# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/completion.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Completion extension models.
Carries LLM completion information including stop reason, token usage,
model identifier, wire format, and latency.
Immutable tier — shared reference, no modifications allowed.
"""

# Standard
from enum import Enum

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class StopReason(str, Enum):
    """Closed-set enumeration of completion stop reasons.

    Attributes:
        END: Natural end of generation.
        RETURN: Model returned a structured result.
        CALL: Model made a tool call.
        MAX_TOKENS: Generation stopped due to token limit.
        STOP_SEQUENCE: Generation stopped at a stop sequence.

    Examples:
        >>> StopReason.END
        <StopReason.END: 'end'>
        >>> StopReason("max_tokens")
        <StopReason.MAX_TOKENS: 'max_tokens'>
    """

    END = "end"
    RETURN = "return"
    CALL = "call"
    MAX_TOKENS = "max_tokens"
    STOP_SEQUENCE = "stop_sequence"


class TokenUsage(BaseModel):
    """Token consumption metrics for a completion.

    Attributes:
        input_tokens: Tokens consumed by the input.
        output_tokens: Tokens generated in the output.
        total_tokens: Total tokens (input + output).

    Examples:
        >>> usage = TokenUsage(input_tokens=150, output_tokens=50, total_tokens=200)
        >>> usage.total_tokens
        200
    """

    model_config = ConfigDict(frozen=True)

    input_tokens: int = Field(description="Tokens consumed by the input.")
    output_tokens: int = Field(description="Tokens generated in the output.")
    total_tokens: int = Field(description="Total tokens (input + output).")


class CompletionExtension(BaseModel):
    """LLM completion information.

    Fields like model and stop_reason can drive policy decisions
    (e.g., "only allow gpt-4 for financial queries", "flag max_tokens
    responses for review"). Immutable — the processing pipeline rejects
    any modifications.

    Attributes:
        stop_reason: Why the model stopped.
        tokens: Token counts.
        model: Model identifier that generated this response.
        raw_format: Original wire format (chatml, harmony, gemini, anthropic).
        created_at: ISO timestamp when the message was created.
        latency_ms: Response generation time in milliseconds.

    Examples:
        >>> ext = CompletionExtension(
        ...     stop_reason=StopReason.END,
        ...     tokens=TokenUsage(input_tokens=100, output_tokens=50, total_tokens=150),
        ...     model="gpt-4o",
        ...     latency_ms=1200,
        ... )
        >>> ext.stop_reason
        <StopReason.END: 'end'>
        >>> ext.tokens.total_tokens
        150
        >>> ext.latency_ms
        1200
    """

    model_config = ConfigDict(frozen=True)

    stop_reason: StopReason | None = Field(default=None, description="Why the model stopped.")
    tokens: TokenUsage | None = Field(default=None, description="Token counts.")
    model: str | None = Field(default=None, description="Model identifier that generated this response.")
    raw_format: str | None = Field(
        default=None, description="Original wire format (chatml, harmony, gemini, anthropic)."
    )
    created_at: str | None = Field(default=None, description="ISO timestamp when the message was created.")
    latency_ms: int | None = Field(default=None, description="Response generation time in milliseconds.")
