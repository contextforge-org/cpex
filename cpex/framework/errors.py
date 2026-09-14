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

DenialMetadataValue = Union[bool, str]
"""Safe, low-cardinality metadata values allowed on a denial outcome."""


_DENIAL_METADATA_RULES: dict[str, type[object]] = {
    "allowed": bool,
    "throttled": bool,
    "backend": str,
}
_SAFE_BACKEND_NAMES = frozenset({"memory", "redis", "valkey"})
_FRAMEWORK_DENIAL_MARKER = object()


def sanitize_denial_metadata(metadata: Optional[Mapping[str, Any]]) -> Mapping[str, DenialMetadataValue]:
    """Return the explicitly allowlisted, safe portion of denial metadata.

    Plugin metadata is untrusted.  Only rate-limiter state that Gateway needs for
    telemetry can cross the exception boundary.  In particular, this excludes
    arbitrary strings, nested data, request identifiers, and credentials.
    """
    if not metadata:
        return MappingProxyType({})

    safe: dict[str, DenialMetadataValue] = {}
    for key, expected_type in _DENIAL_METADATA_RULES.items():
        value = metadata.get(key)
        # bool is an int subclass, so require the exact type rather than
        # isinstance() to keep the contract unambiguous.
        if type(value) is bool and expected_type is bool:
            safe[key] = value
        elif key == "backend" and type(value) is str and value in _SAFE_BACKEND_NAMES:
            safe[key] = value
    return MappingProxyType(safe)


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
            error_code=execution.error_code,
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
            violation_code=violation.code if violation else None,
            mcp_error_code=violation.mcp_error_code if violation else None,
            http_status_code=violation.http_status_code if violation else None,
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

    def __init__(
        self,
        message: str,
        violation: PluginViolation | None = None,
        *,
        denial_metadata: Optional[Mapping[str, DenialMetadataValue]] = None,
        _framework_marker: object | None = None,
    ):
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
        self._framework_denial = _framework_marker is _FRAMEWORK_DENIAL_MARKER
        # This is already allowlisted by the executor.  Keep it private until a
        # trusted execution record exists, then create the immutable outcome.
        self._denial_metadata = MappingProxyType(dict(denial_metadata or {}))
        super().__init__(self.message)

    @classmethod
    def _from_framework_denial(
        cls,
        message: str,
        violation: PluginViolation | None,
        denial_metadata: Optional[Mapping[str, DenialMetadataValue]],
    ) -> "PluginViolationError":
        """Create the exception used only for a result denied by the executor."""
        return cls(
            message,
            violation,
            denial_metadata=denial_metadata,
            _framework_marker=_FRAMEWORK_DENIAL_MARKER,
        )

    def attach_denial_outcome(self, execution: ControlExecutionRecord) -> None:
        """Attach the framework-generated outcome after the denial is recorded."""
        if not self._framework_denial:
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
