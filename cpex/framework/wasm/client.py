# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/wasm/client.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Host-side wrapper for WebAssembly Component Model plugins.

WasmPlugin is a Plugin subclass — the existing PluginManager treats it
identically to any other plugin kind. The wasm-specific behavior is fully
encapsulated here: manifest load, integrity verification, capability-gated
linker setup, fuel/timeout budget per invocation, and JSON marshaling.

Design parallels
----------------
- Wire format mirrors IsolatedVenvPlugin: JSON via model_dump_json on the
  way out, registry.json_to_result on the way back. This means the host
  serializer is shared across plugin kinds with no special-casing.
- Lifecycle (initialize/invoke_hook/cleanup) mirrors ExternalPlugin.
- Capability linking is the new piece — see WasmCapabilityLinker.

Threading
---------
Wasmtime instances are not thread-safe. WasmPlugin owns one Store per
instance, accessed under an asyncio.Lock. The plugin runs invocations
sequentially per instance; the manager handles cross-plugin concurrency
above this layer.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from cpex.framework.base import Plugin
from cpex.framework.errors import PluginError, convert_exception_to_error
from cpex.framework.hooks.registry import get_hook_registry
from cpex.framework.models import (
    PluginConfig,
    PluginContext,
    PluginErrorModel,
    PluginPayload,
    PluginResult,
)
from cpex.framework.wasm.capabilities import check_capabilities_subset
from cpex.framework.wasm.linker import WasmCapabilityLinker
from cpex.framework.wasm.manifest import WasmManifest

logger = logging.getLogger(__name__)

WASM_API_VERSION = "cpex.plugin/v1"


class WasmPlugin(Plugin):
    """A CPEX plugin backed by a WebAssembly Component Model artifact.

    Configuration (from PluginConfig.config):
        manifest_path: str — path to plugin-manifest.yaml (REQUIRED)
        wasi_random_seed: int — optional deterministic seed for tests

    See docs/specs/wasm-plugin-spec.md for the full contract.
    """

    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)
        self.implementation = "WASM"

        if not config.config or "manifest_path" not in config.config:
            raise PluginError(
                error=PluginErrorModel(
                    message="WASM plugin config must include 'manifest_path'",
                    plugin_name=config.name,
                )
            )

        self._manifest_path: str = config.config["manifest_path"]
        self._manifest: Optional[WasmManifest] = None
        self._linker: Optional[WasmCapabilityLinker] = None
        self._lock = asyncio.Lock()
        self._shutdown_called = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Load manifest, verify artifact, link capabilities, call init.

        Any failure here is a hard load-time error: the plugin will not
        be registered with PluginManager.
        """
        try:
            # 1. Parse + validate YAML manifest, verify SHA-256 on disk.
            self._manifest = await asyncio.to_thread(
                WasmManifest.from_path, self._manifest_path
            )
            logger.info(
                "Loaded wasm manifest: name=%s version=%s api=%s",
                self._manifest.name,
                self._manifest.version,
                self._manifest.api_version,
            )

            # 2. Cross-check declared identity against PluginConfig.
            if self._manifest.name != self.config.name:
                raise PluginError(
                    error=PluginErrorModel(
                        message=(
                            f"Manifest name {self._manifest.name!r} does not "
                            f"match PluginConfig.name {self.config.name!r}"
                        ),
                        plugin_name=self.config.name,
                    )
                )

            # 3. Cross-check declared hooks ⊇ PluginConfig.hooks.
            declared = set(self._manifest.hooks)
            requested = {str(h) for h in self.config.hooks}
            if not requested.issubset(declared):
                missing = requested - declared
                raise PluginError(
                    error=PluginErrorModel(
                        message=(
                            f"PluginConfig requests hooks not declared in "
                            f"manifest: {sorted(missing)}"
                        ),
                        plugin_name=self.config.name,
                    )
                )

            # 4. Build the capability-gated linker. This is the security
            #    boundary: only declared capabilities get linked.
            self._linker = WasmCapabilityLinker(
                manifest=self._manifest,
                plugin_name=self.config.name,
            )
            await asyncio.to_thread(self._linker.instantiate)

            # 5. Cross-check component's self-reported manifest.
            component_manifest = await self._call_export("manifest", [])
            await self._verify_component_manifest(component_manifest)

            # 6. Hand the plugin its config and let it validate.
            plugin_config_json = json.dumps(self.config.config or {})
            result = await self._call_export(
                "init", [plugin_config_json], allow_error=True
            )
            if isinstance(result, dict) and "err" in result:
                err = result["err"]
                raise PluginError(
                    error=PluginErrorModel(
                        message=f"Plugin init() failed: {err.get('message')}",
                        plugin_name=self.config.name,
                    )
                )

            logger.info(
                "WASM plugin %r initialized successfully", self.config.name
            )

        except PluginError:
            raise
        except Exception as e:
            logger.exception(
                "WASM plugin %r failed to initialize", self.config.name
            )
            raise PluginError(
                error=convert_exception_to_error(e, plugin_name=self.config.name)
            ) from e

    async def cleanup(self) -> None:
        """Call shutdown() on the component and drop the instance."""
        if self._shutdown_called or self._linker is None:
            return
        self._shutdown_called = True
        try:
            await self._call_export("shutdown", [], allow_error=True)
        except Exception:
            logger.exception(
                "WASM plugin %r shutdown raised; continuing teardown",
                self.config.name,
            )
        finally:
            self._linker.close()
            self._linker = None

    # ------------------------------------------------------------------
    # Hook invocation
    # ------------------------------------------------------------------

    async def invoke_hook(
        self,
        hook_type: str,
        payload: PluginPayload,
        context: PluginContext,
    ) -> PluginResult:
        """Marshal payload + context to JSON, call the wasm component,
        and convert the JSON reply back to a typed PluginResult.

        Per-call resource budgets (fuel, timeout) are taken from the
        manifest's `limits:` block.
        """
        if self._linker is None or self._manifest is None:
            raise PluginError(
                error=PluginErrorModel(
                    message=f"Plugin {self.config.name!r} not initialized",
                    plugin_name=self.config.name,
                )
            )

        registry = get_hook_registry()
        if not registry.get_result_type(hook_type):
            raise PluginError(
                error=PluginErrorModel(
                    message=f"Hook type {hook_type!r} not registered",
                    plugin_name=self.config.name,
                )
            )

        payload_json = payload.model_dump_json() if payload else "null"
        context_json = context.model_dump_json() if context else "null"

        # Host-side size guard before crossing the boundary.
        max_bytes = self._manifest.limits.max_payload_bytes
        if len(payload_json) > max_bytes or len(context_json) > max_bytes:
            raise PluginError(
                error=PluginErrorModel(
                    message=(
                        f"Payload or context exceeds max_payload_bytes "
                        f"({max_bytes})"
                    ),
                    plugin_name=self.config.name,
                )
            )

        try:
            # call_timeout_ms bounds wall-clock; fuel bounds CPU; both apply.
            timeout_s = self._manifest.limits.call_timeout_ms / 1000.0
            result = await asyncio.wait_for(
                self._call_export(
                    "invoke_hook",
                    [hook_type, payload_json, context_json],
                    allow_error=True,
                    refuel=True,
                ),
                timeout=timeout_s,
            )

            if isinstance(result, dict) and "err" in result:
                err = result["err"]
                raise PluginError(
                    error=PluginErrorModel(
                        message=(
                            f"Plugin reported error on {hook_type}: "
                            f"{err.get('code')} — {err.get('message')}"
                        ),
                        plugin_name=self.config.name,
                    )
                )

            reply_json = result if isinstance(result, str) else result.get("ok")
            reply_dict = json.loads(reply_json)
            return registry.json_to_result(hook_type, reply_dict)

        except asyncio.TimeoutError as e:
            logger.warning(
                "WASM plugin %r exceeded call_timeout_ms on hook %s",
                self.config.name,
                hook_type,
            )
            raise PluginError(
                error=PluginErrorModel(
                    message=(
                        f"Hook {hook_type} exceeded call_timeout_ms "
                        f"({self._manifest.limits.call_timeout_ms}ms)"
                    ),
                    plugin_name=self.config.name,
                )
            ) from e
        except PluginError:
            raise
        except Exception as e:
            logger.exception(
                "Unexpected error in WASM plugin %r on hook %s",
                self.config.name,
                hook_type,
            )
            raise PluginError(
                error=convert_exception_to_error(e, plugin_name=self.config.name)
            ) from e

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _call_export(
        self,
        export_name: str,
        args: list[Any],
        *,
        allow_error: bool = False,
        refuel: bool = False,
    ) -> Any:
        """Serialize access to the wasm instance and call an export.

        Wasmtime Stores are not thread-safe, so we serialize with a lock
        and run the (potentially blocking) call in a worker thread.
        """
        assert self._linker is not None

        async with self._lock:
            if refuel:
                # Restore fuel to the manifest budget for this invocation.
                self._linker.refuel(self._manifest.limits.max_fuel)
            return await asyncio.to_thread(
                self._linker.call_export, export_name, args, allow_error
            )

    async def _verify_component_manifest(self, component_manifest: Any) -> None:
        """Cross-check the component's self-reported manifest against the
        YAML manifest. Any mismatch is a fail-closed load-time error.
        """
        assert self._manifest is not None

        # component_manifest is a dict-like decoded by the bindings.
        cm = component_manifest if isinstance(component_manifest, dict) else {
            "name": getattr(component_manifest, "name", None),
            "version": getattr(component_manifest, "version", None),
            "api_version": getattr(component_manifest, "api_version", None),
            "hooks": list(getattr(component_manifest, "hooks", []) or []),
            "required_capabilities": list(
                getattr(component_manifest, "required_capabilities", []) or []
            ),
        }

        errors: list[str] = []

        if cm.get("api_version") != WASM_API_VERSION:
            errors.append(
                f"component api_version={cm.get('api_version')!r}, "
                f"host supports {WASM_API_VERSION!r}"
            )
        if cm.get("name") != self._manifest.name:
            errors.append(
                f"component name={cm.get('name')!r}, "
                f"manifest name={self._manifest.name!r}"
            )
        if cm.get("version") != self._manifest.version:
            errors.append(
                f"component version={cm.get('version')!r}, "
                f"manifest version={self._manifest.version!r}"
            )

        declared_hooks = set(cm.get("hooks") or [])
        yaml_hooks = set(self._manifest.hooks)
        if not yaml_hooks.issubset(declared_hooks):
            errors.append(
                f"component declares hooks={sorted(declared_hooks)}, "
                f"manifest promises {sorted(yaml_hooks)}; "
                f"missing in component: {sorted(yaml_hooks - declared_hooks)}"
            )

        required_caps = list(cm.get("required_capabilities") or [])
        try:
            check_capabilities_subset(required_caps, self._manifest.capabilities)
        except ValueError as e:
            errors.append(str(e))

        if errors:
            raise PluginError(
                error=PluginErrorModel(
                    message=(
                        "WASM component manifest cross-check failed: "
                        + "; ".join(errors)
                    ),
                    plugin_name=self.config.name,
                )
            )
