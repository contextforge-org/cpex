# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/http.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

HTTP extension model.
Carries HTTP request context with capability-gated access.
Guarded tier — readable with read_headers, writable with write_headers.
"""

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class HttpExtension(BaseModel):
    """HTTP request context.

    Readable with the read_headers capability, writable with
    write_headers. Sensitive headers (Authorization, Cookie, X-API-Key)
    are stripped when serialized for external policy engines.

    Guarded tier — the processing pipeline rejects modifications
    unless the consumer holds the write_headers capability.

    Attributes:
        headers: HTTP headers as key-value pairs.

    Examples:
        >>> ext = HttpExtension(
        ...     headers={"Content-Type": "application/json", "X-Request-ID": "req-123"},
        ... )
        >>> ext.headers["Content-Type"]
        'application/json'

        >>> # Frozen: modifications require model_copy
        >>> updated = ext.model_copy(
        ...     update={"headers": {**ext.headers, "X-Trace-ID": "trace-456"}},
        ... )
        >>> "X-Trace-ID" in updated.headers
        True
    """

    model_config = ConfigDict(frozen=True)

    headers: dict[str, str] = Field(default_factory=dict, description="HTTP headers as key-value pairs.")
