# Location: ./bindings/python/python/cpex/_lib.pyi
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
# Authors: Ted Habeck
#
# Type stubs for the cpex._lib native extension.
#
# Uncertain awaitable return types are omitted rather than guessed (#5).
# `PluginManager` methods return coroutines; annotated as `Any` since
# the exact coroutine/awaitable type from PyO3 is not stable in stubs.

from typing import Any, Optional

class PipelineResult:
    @property
    def continue_processing(self) -> bool: ...
    @property
    def modified_payload(self) -> Optional[dict]: ...
    @property
    def modified_extensions(self) -> Optional[dict]: ...
    @property
    def violation(self) -> Optional[dict]: ...
    @property
    def errors(self) -> list[dict]: ...
    @property
    def metadata(self) -> Optional[dict]: ...
    @property
    def context_table(self) -> dict: ...

class PluginManager:
    def __new__(cls, config_path: str) -> "PluginManager": ...
    def initialize(self) -> Any: ...
    def shutdown(self) -> Any: ...
    def invoke_hook(
        self,
        hook_name: str,
        payload: dict,
        extensions: Optional[dict] = None,
        context_table: Optional[dict] = None,
    ) -> Any: ...
