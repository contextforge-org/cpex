# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/agent.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Agent extension models.
Carries agent execution context — session tracking, multi-agent lineage,
original user intent, and optional windowed conversation history.
Immutable tier — the user's intent and session identity must not be
modifiable by processing components.
"""

# Standard

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class ConversationContext(BaseModel):
    """Windowed conversation context for agent-aware processing.

    Provides a lightweight view of prior conversation history without
    requiring access to the full message store.

    Attributes:
        history: Windowed message history (recent turns).
        summary: Summarized prior context.
        topics: Extracted topics or intents.

    Examples:
        >>> ctx = ConversationContext(
        ...     summary="User asked about quarterly revenue.",
        ...     topics=["revenue", "Q4"],
        ... )
        >>> ctx.summary
        'User asked about quarterly revenue.'
        >>> ctx.topics
        ['revenue', 'Q4']
    """

    model_config = ConfigDict(frozen=True)

    history: list[BaseModel] = Field(
        default_factory=list,
        description="Windowed message history (recent turns). Each entry is a typed model (e.g., CMF Message).",
        max_length=100,
    )
    summary: str | None = Field(default=None, description="Summarized prior context.")
    topics: list[str] = Field(default_factory=list, description="Extracted topics or intents.")


class AgentExtension(BaseModel):
    """Agent execution context.

    Tracks session identity, multi-agent lineage, and the original
    user intent that triggered the current action. Immutable — the
    processing pipeline rejects any modifications.

    Attributes:
        input: Original user intent that triggered this action.
        session_id: Broad session identifier.
        conversation_id: Specific dialogue/task within a session.
        turn: Position in conversation (0-indexed).
        agent_id: Identifier of the producing agent.
        parent_agent_id: Spawning agent's ID (multi-agent lineage).
        conversation: Windowed conversation context.

    Examples:
        >>> ext = AgentExtension(
        ...     input="What is the weather in London?",
        ...     session_id="sess-001",
        ...     conversation_id="conv-042",
        ...     turn=3,
        ...     agent_id="weather-agent",
        ... )
        >>> ext.input
        'What is the weather in London?'
        >>> ext.turn
        3

        >>> # Multi-agent lineage
        >>> child = AgentExtension(
        ...     agent_id="sub-agent-01",
        ...     parent_agent_id="weather-agent",
        ... )
        >>> child.parent_agent_id
        'weather-agent'
    """

    model_config = ConfigDict(frozen=True)

    input: str | None = Field(default=None, description="Original user intent that triggered this action.")
    session_id: str | None = Field(default=None, description="Broad session identifier.")
    conversation_id: str | None = Field(default=None, description="Specific dialogue/task within a session.")
    turn: int | None = Field(default=None, description="Position in conversation (0-indexed).")
    agent_id: str | None = Field(default=None, description="Identifier of the producing agent.")
    parent_agent_id: str | None = Field(default=None, description="Spawning agent's ID (multi-agent lineage).")
    conversation: ConversationContext | None = Field(default=None, description="Windowed conversation context.")
