# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/isolated/worker.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck, Fred Araujo

Isolated plugin server
Module that contains plugin server code to invoke hooks in native plugins.
"""

import asyncio
import hashlib
import importlib.metadata
import json
import logging
import platform
import sys
from pathlib import Path
from types import ModuleType
from typing import List, Type, cast

from cpex.framework.base import HookRef, Plugin, PluginRef
from cpex.framework.constants import HOOK_TYPE
from cpex.framework.loader.plugin import ALLOWED_PLUGIN_DIRS
from cpex.framework.manager import PluginExecutor
from cpex.framework.models import PluginConfig, PluginContext
from cpex.framework.utils import import_module, parse_class_name

logger = logging.getLogger(__name__)


class TaskProcessor:
    """
    A Caching task processor that only reloads the plugin if the config has changed.
    """

    config_hash: str
    module_path_hash: str
    hook_ref: HookRef
    executor: PluginExecutor
    plugin_config: PluginConfig | None = None

    def __init__(self) -> None:
        """Initialize defaults."""
        hasher = hashlib.sha256()
        hasher.update(b"")
        self.config_hash = hasher.hexdigest()
        self.module_path_hash = self.config_hash

    def compute_hash(self, json_config_or_module_path: str):
        """Compute the hash of the supplied string"""
        hasher = hashlib.sha256()
        hasher.update(json_config_or_module_path.encode())
        return hasher.hexdigest()

    def initialize(
        self,
        hook_ref: HookRef,
        executor: PluginExecutor,
        json_config: str,
        module_path: str,
        plugin_config: PluginConfig,
    ):
        """Assign locals, and compute hashes."""
        self.hook_ref = hook_ref
        self.executor = executor
        self.config_hash = self.compute_hash(json_config_or_module_path=json_config)
        self.module_path_hash = self.compute_hash(json_config_or_module_path=module_path)
        self.plugin_config = plugin_config


def get_environment_info():
    """Get information about current Python environment."""
    return {
        "python_version": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "installed_packages": [str(d) for d in importlib.metadata.entry_points()][:10],  # First 10 packages
    }


async def process_task(task_data, tp: TaskProcessor):
    """Process the task received from parent."""
    task_type = task_data.get("task_type")

    if task_type == "info":
        return {
            "status": "success",
            "environment": get_environment_info(),
            "message": "Environment info retrieved successfully",
        }
    # This is essentially emulating the plugin loader's load and instantiate plugin
    if task_type == "load_and_run_hook":
        # relative path from project root.
        json_config = task_data.get("config")
        config_raw = json.loads(json_config)
        module_paths: List[str] = task_data.get("plugin_dirs")
        resolved_paths: List[str] = []
        for module_path in module_paths:
            path = Path(module_path).resolve()
            resolved_module_path = str(path)
            if path.exists():
                resolved_paths.append(resolved_module_path)
                if resolved_module_path not in sys.path:
                    if resolved_module_path.startswith(tuple(ALLOWED_PLUGIN_DIRS)):
                        sys.path.append(resolved_module_path)
                    else:
                        raise RuntimeError(f"plugin module_path '{resolved_module_path}' not in allowed plugin dirs.")
            else:
                raise RuntimeError(f"plugin module_path '{resolved_module_path}' does not exist.")

        if tp.config_hash != tp.compute_hash(json_config):
            # pull the resolved plugin path and only add the module path if it has the same root
            config: PluginConfig = PluginConfig(**config_raw)
            hook_type = task_data.get(HOOK_TYPE)
            cls_name: str = task_data.get("class_name")
            mod_name, n_cls_name = parse_class_name(cls_name)
            module: ModuleType = import_module(mod_name)
            # cool, we found the module, and verified it implemented the hook type.
            class_ = getattr(module, n_cls_name)
            plugin_type = cast(Type[Plugin], class_)
            plugin = plugin_type(config)
            await plugin.initialize()
            # now invoke the hook
            plugin_ref = PluginRef(plugin)
            hook_ref = HookRef(hook_type, plugin_ref)
            executor = PluginExecutor(None, 30)
            tp.initialize(
                hook_ref=hook_ref,
                executor=executor,
                json_config=json_config,
                module_path=json.dumps(resolved_paths),
                plugin_config=config,
            )
        # retrieve the context
        context = task_data.get("context")
        plugin_context = PluginContext(
            state=context.get("state"), global_context=context.get("global_context"), metadata=context.get("metadata")
        )
        result = await tp.executor.execute_plugin(
            hook_ref=tp.hook_ref,
            payload=task_data.get("payload"),
            local_context=plugin_context,
            violations_as_exceptions=False,
        )
        return result
    return {
        "status": "error",
        "message": "task type not supported.",
        "request_id": task_data.get("request_id", "unknown") if "task_data" in locals() else "unknown",
    }


async def main():
    """Main function - continuously read from stdin, process tasks, write to stdout."""
    logger.info("Worker process started, waiting for tasks...")

    try:
        # Cache the plugin so that it only has to be initialized once
        tp = TaskProcessor()
        # Continuously read and process tasks
        while True:
            try:
                # Read one line at a time
                if tp.plugin_config and "max_content_size" in tp.plugin_config:
                    line = sys.stdin.readline(limit=int(tp.plugin_config.max_content_size))
                else:
                    # on the first read, the plugin_config has not yet been initialized so just read.
                    line = sys.stdin.readline()
                # Check for EOF
                if not line:
                    logger.info("EOF received, shutting down worker")
                    break

                # Parse the task
                task_data = json.loads(line.strip())
                request_id = task_data.get("request_id", "unknown")

                # Check for shutdown signal
                if task_data.get("task_type") == "shutdown":
                    logger.info("Shutdown signal received")
                    response = {"status": "success", "message": "Shutting down", "request_id": request_id}
                    print(json.dumps(response), flush=True)
                    break

                # Process the task
                response = await process_task(task_data, tp)

                # Serialize response
                if response:
                    serializable_response = response.model_dump(mode="json")
                else:  # none case should be a failure rather than success.
                    serializable_response = {"status": "success"}

                # Add request_id to response
                serializable_response["request_id"] = request_id

                serialized_response = json.dumps(serializable_response)
                # Send response back to parent (one line per response)
                if tp.plugin_config:
                    # workaround until cpex is updated beyond dev11
                    # cpex is a dependency of the plugin and as such it's PluginConfig does not contain the max_content_size yet.
                    if "max_content_size" in tp.plugin_config:
                        if len(serialized_response) > tp.plugin_config.max_content_size:
                            logger.error("Serialized response exceeds max content size")
                            error_response = {
                                "status": "error",
                                "message": "Serialized response exceeds max content size",
                                "request_id": request_id,
                            }
                            serialized_response = json.dumps(error_response)
                print(serialized_response, flush=True)

            except json.JSONDecodeError as e:
                error_response = {
                    "status": "error",
                    "message": f"Invalid JSON input: {str(e)}",
                    "request_id": "unknown",
                }
                print(json.dumps(error_response), flush=True)

            except Exception as e:
                logger.error("Error processing task: %s", str(e))
                error_response = {
                    "status": "error",
                    "message": f"Unexpected error: {str(e)}",
                    "request_id": "unknown",
                }
                print(json.dumps(error_response), flush=True)

    except KeyboardInterrupt:
        logger.info("Worker interrupted")
    except Exception:
        logger.exception("Fatal error in worker main loop")
    finally:
        logger.info("Worker process shutting down")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
