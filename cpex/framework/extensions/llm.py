# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/llm.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

LLM extension model.
Carries model identity and capability metadata for routing,
policy evaluation, and audit.
Immutable tier — shared reference, no modifications allowed.
"""

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class LLMExtension(BaseModel):
    """Model identity and capability metadata.

    Used for routing, policy evaluation, and audit when the producing
    model's identity matters independently of the completion itself.
    Immutable — the processing pipeline rejects any modifications.

    Attributes:
        model_id: Model identifier (e.g., gpt-4o, claude-sonnet-4-20250514).
        provider: Provider name (e.g., openai, anthropic, google).
        capabilities: Declared model capabilities (e.g., vision, tool_use, extended_thinking).

    Examples:
        >>> ext = LLMExtension(
        ...     model_id="claude-sonnet-4-20250514",
        ...     provider="anthropic",
        ...     capabilities=["vision", "tool_use", "extended_thinking"],
        ... )
        >>> ext.provider
        'anthropic'
        >>> "tool_use" in ext.capabilities
        True
    """

    model_config = ConfigDict(frozen=True)

    model_id: str | None = Field(default=None, description="Model identifier.")
    provider: str | None = Field(default=None, description="Provider name.")
    capabilities: list[str] = Field(default_factory=list, description="Declared model capabilities.")
