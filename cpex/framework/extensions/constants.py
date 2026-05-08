# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/constants.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Extension constants.

Single source of truth for slot names and field names used in the
slot registry, filter_extensions(), merge_extensions(), and
validate_tier_constraints(). Using these constants instead of bare
strings prevents typo-induced duplicates.
"""

# Standard
from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Slot Registry Names (dot-notation paths for nested sub-fields)
# ---------------------------------------------------------------------------


class SlotName(str, Enum):
    """Canonical slot names for extension fields and sub-fields.

    Top-level names correspond to Extensions model attributes.
    Dotted names represent nested sub-fields (e.g., security.subject.roles).
    """

    def __str__(self) -> str:
        """Return the enum value as a plain string.

        Overrides the default ``StrEnum.__str__`` which renders as
        ``ClassName.MEMBER`` in Python 3.11+.

        Returns:
            The raw string value of the enum member.
        """
        return self.value

    REQUEST = "request"
    PROVENANCE = "provenance"
    COMPLETION = "completion"
    LLM = "llm"
    FRAMEWORK = "framework"
    MCP = "mcp"
    AGENT = "agent"
    HTTP = "http"
    META = "meta"
    DELEGATION = "delegation"
    CUSTOM = "custom"

    # Security sub-fields
    SECURITY_SUBJECT = "security.subject"
    SECURITY_SUBJECT_ROLES = "security.subject.roles"
    SECURITY_SUBJECT_TEAMS = "security.subject.teams"
    SECURITY_SUBJECT_CLAIMS = "security.subject.claims"
    SECURITY_SUBJECT_PERMISSIONS = "security.subject.permissions"
    SECURITY_OBJECTS = "security.objects"
    SECURITY_DATA = "security.data"
    SECURITY_LABELS = "security.labels"


# ---------------------------------------------------------------------------
# Pydantic Field Name Constants
# ---------------------------------------------------------------------------
# Used as keys in model_copy(update={...}) dicts and Extensions(**fields)
# construction. These match the Pydantic model attribute names exactly.

# Extensions model fields
FIELD_REQUEST: str = "request"
FIELD_PROVENANCE: str = "provenance"
FIELD_COMPLETION: str = "completion"
FIELD_LLM: str = "llm"
FIELD_FRAMEWORK: str = "framework"
FIELD_MCP: str = "mcp"
FIELD_AGENT: str = "agent"
FIELD_HTTP: str = "http"
FIELD_META: str = "meta"
FIELD_DELEGATION: str = "delegation"
FIELD_CUSTOM: str = "custom"
FIELD_SECURITY: str = "security"

# SecurityExtension model fields
FIELD_LABELS: str = "labels"
FIELD_CLASSIFICATION: str = "classification"
FIELD_SUBJECT: str = "subject"
FIELD_OBJECTS: str = "objects"
FIELD_DATA: str = "data"

# SubjectExtension model fields
FIELD_ROLES: str = "roles"
FIELD_TEAMS: str = "teams"
FIELD_CLAIMS: str = "claims"
FIELD_PERMISSIONS: str = "permissions"
