# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/errors.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Pydantic models for plugins.
This module implements the pydantic models associated with
the base plugin layer including configurations, and contexts.
"""

# Standard
import math
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Optional, Union

# First-Party
from cpex.framework.models import (
    ControlExecutionRecord,
    PluginErrorModel,
    PluginMode,
    PluginViolation,
)

DenialMetadataValue = Union[bool, int, float]
"""Safe, low-cardinality metadata values allowed on a denial outcome."""


_TELEMETRY_LABEL = re.compile(r"[A-Za-z0-9._-]{1,64}\Z", re.ASCII)


def sanitize_denial_metadata(metadata: Optional[Mapping[str, Any]]) -> dict[str, DenialMetadataValue]:
    """Select an owned, bounded dictionary of explicitly opted-in numeric metrics.

    Producers must use static metric names and non-sensitive values. Numeric
    identifiers must never be supplied: type validation cannot prove privacy.
    Oversized input maps are rejected entirely, before selecting valid entries.
    """
    if not isinstance(metadata, Mapping) or len(metadata) > 16:
        return {}

    safe: dict[str, DenialMetadataValue] = {}
    for key, value in metadata.items():
        if type(key) is not str or _TELEMETRY_LABEL.fullmatch(key) is None:
            continue
        if type(value) is bool:
            safe[key] = value
        elif type(value) is int and -(2**63) <= value <= 2**63 - 1:
            safe[key] = value
        elif type(value) is float and math.isfinite(value):
            safe[key] = value
    return safe


def _safe_label(value: Any) -> Optional[str]:
    """Accept bounded identifier labels, never free-form text."""
    return value if type(value) is str and _TELEMETRY_LABEL.fullmatch(value) else None


def _safe_integer(value: Any, minimum: int, maximum: int) -> Optional[int]:
    """Validate protocol codes without coercing boolean or string values."""
    return value if type(value) is int and minimum <= value <= maximum else None


@dataclass(frozen=True)
class DenialExecutionRecord:
    """Immutable, non-sensitive projection of a trusted execution record."""

    plugin_id: str
    plugin_name: str
    plugin_kind: str
    hook_name: str
    mode: PluginMode
    status: str
    requested_allow: Optional[bool]
    effective_allow: bool
    matched: Optional[bool]
    applied: bool
    payload_modified: bool
    extensions_modified: bool
    duration_ns: int
    error_code: Optional[str]

    @classmethod
    def from_execution(cls, execution: ControlExecutionRecord) -> "DenialExecutionRecord":
        """Snapshot trusted execution fields without the free-form reason/config."""
        return cls(
            plugin_id=execution.plugin_id,
            plugin_name=execution.plugin_name,
            plugin_kind=execution.plugin_kind,
            hook_name=execution.hook_name,
            mode=execution.mode,
            status=execution.status.value,
            requested_allow=execution.requested_allow,
            effective_allow=execution.effective_allow,
            matched=execution.matched,
            applied=execution.applied,
            payload_modified=execution.payload_modified,
            extensions_modified=execution.extensions_modified,
            duration_ns=execution.duration_ns,
            error_code=_safe_label(execution.error_code),
        )


@dataclass(frozen=True)
class DenialOutcome:
    """Safe immutable outcome attached to framework-generated denial errors.

    The outcome deliberately omits payloads, headers, violation details,
    free-form reason text, and arbitrary plugin metadata.
    """

    execution: DenialExecutionRecord
    violation_code: Optional[str]
    mcp_error_code: Optional[int]
    http_status_code: Optional[int]
    metadata: Mapping[str, DenialMetadataValue]

    @classmethod
    def from_execution(
        cls,
        execution: ControlExecutionRecord,
        violation: Optional[PluginViolation],
        metadata: Optional[Mapping[str, DenialMetadataValue]],
    ) -> "DenialOutcome":
        """Build an immutable safe snapshot from trusted executor state."""
        return cls(
            execution=DenialExecutionRecord.from_execution(execution),
            violation_code=_safe_label(violation.code) if violation else None,
            mcp_error_code=_safe_integer(violation.mcp_error_code, -(2**31), 2**31 - 1) if violation else None,
            http_status_code=_safe_integer(violation.http_status_code, 100, 599) if violation else None,
            metadata=MappingProxyType(dict(metadata or {})),
        )


class PluginViolationError(Exception):
    """A plugin violation error.

    Attributes:
        violation (PluginViolation): the plugin violation.
        message (str): the plugin violation reason.
        executions (list[ControlExecutionRecord] | None): execution records collected up to and
            including the denying plugin.  ``None`` when the exception is raised outside of a
            hook chain (e.g. a direct ``execute_plugin`` call, or in unit tests).  Populated by
            the executor before the exception propagates to callers (fix for issue #147).
            Note: fire-and-forget plugins do not run on this path, so their records are absent
            here — unlike ``PluginResult.executions`` on a non-exception halt.
        denial_outcome (DenialOutcome | None): immutable framework-generated
            safe snapshot of the denying control. ``None`` for errors raised
            directly by plugins or callers.
    """

    def __init__(self, message: str, violation: PluginViolation | None = None):
        """Initialize a plugin violation error.

        Args:
            message: the reason for the violation error.
            violation: the plugin violation object details.

        Examples:
            >>> from cpex.framework.errors import PluginViolationError
            >>> from cpex.framework.models import PluginViolation
            >>> v = PluginViolation(reason="r", description="d", code="c")
            >>> err = PluginViolationError("blocked", violation=v)
            >>> (str(err), err.violation.code)
            ('blocked', 'c')
        """
        self.message = message
        self.violation = violation
        self.executions: list[ControlExecutionRecord] | None = None
        self.denial_outcome: DenialOutcome | None = None
        self._denial_metadata: Optional[dict[str, DenialMetadataValue]] = None
        super().__init__(self.message)

    @classmethod
    def _from_framework_denial(
        cls,
        message: str,
        violation: PluginViolation | None,
        denial_metadata: Optional[Mapping[str, Any]],
    ) -> "PluginViolationError":
        """Create the exception used only for a result denied by the executor."""
        error = cls(message, violation)
        error._denial_metadata = sanitize_denial_metadata(denial_metadata)
        return error

    def attach_denial_outcome(self, execution: ControlExecutionRecord) -> None:
        """Attach the framework-generated outcome after the denial is recorded."""
        if self._denial_metadata is None or self.denial_outcome is not None:
            return
        self.denial_outcome = DenialOutcome.from_execution(execution, self.violation, self._denial_metadata)


class PluginError(Exception):
    """A plugin error object for errors internal to the plugin.

    Attributes:
        error (PluginErrorModel): the plugin error object.
    """

    def __init__(self, error: PluginErrorModel):
        """Initialize a plugin violation error.

        Args:
            error: the plugin error details.

        Examples:
            >>> from cpex.framework.errors import PluginError
            >>> from cpex.framework.models import PluginErrorModel
            >>> pe = PluginError(PluginErrorModel(message="boom", plugin_name="p1"))
            >>> (str(pe), pe.error.plugin_name)
            ('boom', 'p1')
        """
        self.error = error
        super().__init__(self.error.message)


def convert_exception_to_error(exception: Exception, plugin_name: str) -> PluginErrorModel:
    """Converts an exception object into a PluginErrorModel. Primarily used for external plugin error handling.

    Args:
        exception: The exception to be converted.
        plugin_name: The name of the plugin on which the exception occurred.

    Returns:
        A plugin error pydantic object that can be sent over HTTP.

    Examples:
        >>> from cpex.framework.errors import convert_exception_to_error
        >>> err = convert_exception_to_error(ValueError("nope"), plugin_name="p1")
        >>> (err.plugin_name, "ValueError('nope')" in err.message)
        ('p1', True)
    """
    return PluginErrorModel(message=repr(exception), plugin_name=plugin_name)
