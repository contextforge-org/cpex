# Location: ./bindings/python/python/cpex/_lib.pyi
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Type stubs for the cpex._lib native extension.
#
# Async methods return PyO3 awaitables. Their resolved type is given in the
# `Awaitable[...]` annotation. Underscore-prefixed TypedDicts are
# stub-only: they describe the dicts returned at runtime and cannot be
# imported.

from datetime import datetime
from typing import Any, Awaitable, Optional, TypedDict

class _RefreshFailure(TypedDict):
    secret: str
    provider: str
    kind: str
    message: str

class _RefreshReport(TypedDict):
    updated: list[str]
    unchanged: int
    failed: list[_RefreshFailure]

class PipelineResult:
    @property
    def continue_processing(self) -> bool: ...
    @property
    def modified_payload(self) -> Optional[dict[str, Any]]: ...
    @property
    def payload_modified(self) -> bool: ...
    @property
    def modified_extensions(self) -> Optional[dict[str, Any]]: ...
    @property
    def violation(self) -> Optional[dict[str, Any]]: ...
    @property
    def errors(self) -> list[dict[str, Any]]: ...
    @property
    def metadata(self) -> Optional[dict[str, Any]]: ...
    @property
    def context_table(self) -> dict[str, Any]: ...

class PolicyEngine:
    def __new__(
        cls,
        config_path: str,
        *,
        allow_private_destinations: bool = False,
    ) -> "PolicyEngine": ...
    def initialize(self) -> Awaitable[None]: ...
    def shutdown(self) -> Awaitable[None]: ...
    def invoke_hook(
        self,
        hook_name: str,
        payload: dict[str, Any],
        extensions: Optional[dict[str, Any]] = None,
        context_table: Optional[dict[str, Any]] = None,
    ) -> Awaitable[PipelineResult]: ...
    def refresh_secrets(self) -> Awaitable[_RefreshReport]: ...
    def secrets_last_success(self, provider: str) -> Optional[datetime]: ...
