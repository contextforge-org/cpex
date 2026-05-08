# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/provenance.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Provenance extension model.
Carries origin and threading information for lineage tracking
across multi-turn conversations and multi-agent systems.
Immutable tier — shared reference, no modifications allowed.
"""

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class ProvenanceExtension(BaseModel):
    """Origin and threading information for the message.

    Enables lineage tracking across multi-turn conversations and
    multi-agent systems. Immutable — the processing pipeline rejects
    any modifications.

    Attributes:
        source: Source identifier (e.g., "user", "agent:xyz", "mcp-server:abc").
        message_id: Unique message identifier.
        parent_id: Parent message ID (threading/replies).

    Examples:
        >>> ext = ProvenanceExtension(
        ...     source="agent:weather-bot",
        ...     message_id="msg-001",
        ...     parent_id="msg-000",
        ... )
        >>> ext.source
        'agent:weather-bot'
        >>> ext.message_id
        'msg-001'
    """

    model_config = ConfigDict(frozen=True)

    source: str | None = Field(default=None, description="Source identifier.")
    message_id: str | None = Field(default=None, description="Unique message identifier.")
    parent_id: str | None = Field(default=None, description="Parent message ID (threading/replies).")
