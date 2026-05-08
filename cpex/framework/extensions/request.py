# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/request.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Request extension model.
Carries execution environment and request-level timing/tracing metadata.
Immutable tier — shared reference, no modifications allowed.
"""

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class RequestExtension(BaseModel):
    """Execution environment and request-level timing/tracing.

    Available to all consumers without any capability requirement (base tier).
    Immutable — the processing pipeline rejects any modifications.

    Attributes:
        environment: Execution environment (production, staging, dev).
        request_id: Request correlation ID.
        timestamp: ISO timestamp of the request.
        trace_id: Distributed tracing ID (OpenTelemetry).
        span_id: Distributed tracing span ID.

    Examples:
        >>> ext = RequestExtension(
        ...     environment="production",
        ...     request_id="req-abc-123",
        ...     timestamp="2025-01-15T10:30:00Z",
        ... )
        >>> ext.environment
        'production'
        >>> ext.request_id
        'req-abc-123'

        >>> # Frozen: modifications require model_copy
        >>> updated = ext.model_copy(update={"span_id": "span-456"})
        >>> updated.span_id
        'span-456'
        >>> ext.span_id is None
        True
    """

    model_config = ConfigDict(frozen=True)

    environment: str | None = Field(default=None, description="Execution environment (production, staging, dev).")
    request_id: str | None = Field(default=None, description="Request correlation ID.")
    timestamp: str | None = Field(default=None, description="ISO timestamp of the request.")
    trace_id: str | None = Field(default=None, description="Distributed tracing ID (OpenTelemetry).")
    span_id: str | None = Field(default=None, description="Distributed tracing span ID.")
