# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/isolated/client.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Isolated plugin client
Module that contains plugin client code to serve venv isolated plugins.
"""

import asyncio
import functools
import hashlib
import json
import logging
import os
import shutil
import sys
import venv
from pathlib import Path

from typing_extensions import Any, Optional

from cpex.framework.base import Plugin
from cpex.framework.constants import CONTEXT, HOOK_TYPE, PAYLOAD, PLUGIN_NAME
from cpex.framework.errors import PluginError, convert_exception_to_error
from cpex.framework.hooks.registry import get_hook_registry
from cpex.framework.isolated.venv_comm import VenvProcessCommunicator
from cpex.framework.models import PluginConfig, PluginContext, PluginErrorModel, PluginPayload, PluginResult
from cpex.framework.utils import find_package_path

logger = logging.getLogger(__name__)


class IsolatedVenvPlugin(Plugin):
    """IsolatedVenvPlugin class."""

    def __init__(self, config: PluginConfig, plugin_dirs) -> None:
        """Initialize the plugin's venv environment."""
        super().__init__(config)
        self.implementation = "Python"
        self.comm = None
        self.plugin_dirs = plugin_dirs
        # use the first plugin dir specified in the plugin configuration file.
        path = Path(self.plugin_dirs[0]).resolve()
        class_root = self.config.config.get("class_name").split(".")[0]
        cache_root: Path = path / class_root
        self.plugin_path: Path = cache_root
        if not cache_root.exists():
            cache_root.mkdir(parents=True, exist_ok=True)
        self.cache_dir: Path = cache_root / ".cpex" / "venv_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _compute_requirements_hash(self, requirements_file: Optional[str]) -> str:
        """Compute SHA256 hash of requirements file content.

        Args:
            requirements_file: Path to the requirements file, or None when the
                plugin has no requirements file.

        Returns:
            Hexadecimal hash string. An absent or non-existent file hashes to
            the empty-content digest.
        """
        hasher = hashlib.sha256()

        if requirements_file is not None:
            req_path = Path(requirements_file)
            if req_path.exists():
                with open(req_path, "rb") as f:
                    hasher.update(f.read())
            else:
                # If no requirements file, use empty hash
                hasher.update(b"")
        else:
            hasher.update(b"")

        return hasher.hexdigest()

    def _manifest_path(self) -> Path:
        """Path to the plugin's persisted manifest under its plugin directory."""
        return self.plugin_path / "plugin-manifest.yaml"

    def _compute_manifest_hash(self) -> str:
        """Compute SHA256 hash of the persisted plugin-manifest.yaml.

        Returns the empty-content digest when no manifest file is present. This
        gives plugins without a self-referencing requirements file a stable
        change signal for cache invalidation (U5): a version bump or any edit to
        the persisted manifest changes the hash and forces a venv reinstall.
        """
        hasher = hashlib.sha256()
        manifest_path = self._manifest_path()
        if manifest_path.exists():
            with open(manifest_path, "rb") as f:
                hasher.update(f.read())
        else:
            hasher.update(b"")
        return hasher.hexdigest()

    def _get_cache_metadata_path(self, venv_path: str) -> Path:
        """Get the path to the cache metadata file.

        Args:
            venv_path: Path to the virtual environment

        Returns:
            Path to the metadata file
        """
        venv_name = Path(venv_path).name
        return self.cache_dir / f"{venv_name}_metadata.json"

    def _is_venv_cache_valid(self, venv_path: str, requirements_file: Optional[str]) -> bool:
        """Check if cached venv is valid by comparing requirements + manifest signals.

        Args:
            venv_path: Path to the virtual environment
            requirements_file: Path to the requirements file, or None when the
                plugin has no requirements file (manifest version+hash is then
                the sole change signal).

        Returns:
            True if cache is valid, False otherwise
        """
        venv_path_obj = Path(venv_path)
        metadata_path = self._get_cache_metadata_path(venv_path)

        # Check if venv directory exists
        if not venv_path_obj.exists():
            logger.debug("Venv path does not exist: %s", venv_path)
            return False

        # Check if metadata file exists
        if not metadata_path.exists():
            logger.debug("Metadata file does not exist: %s", metadata_path)
            return False

        try:
            # Load metadata
            with open(metadata_path, "r", encoding="utf8") as f:
                metadata = json.load(f)

            # Compute current requirements hash
            current_hash = self._compute_requirements_hash(requirements_file)

            # Compare requirements hash
            cached_hash = metadata.get("requirements_hash")
            if cached_hash != current_hash:
                logger.info("Requirements changed. Cached hash: %s, Current hash: %s", cached_hash, current_hash)
                return False

            # Compare manifest version + hash (U5). Either changing invalidates
            # the cache — this is the sole change signal for plugins with no
            # requirements file (whose requirements hash is a constant).
            current_version = self.config.version
            cached_version = metadata.get("manifest_version")
            if cached_version != current_version:
                logger.info(
                    "Manifest version changed. Cached: %s, Current: %s", cached_version, current_version
                )
                return False

            current_manifest_hash = self._compute_manifest_hash()
            cached_manifest_hash = metadata.get("manifest_hash")
            if cached_manifest_hash != current_manifest_hash:
                logger.info(
                    "Manifest content changed. Cached hash: %s, Current hash: %s",
                    cached_manifest_hash,
                    current_manifest_hash,
                )
                return False

            logger.info("Valid venv cache found for %s", venv_path)
            return True

        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Error reading cache metadata: %s", str(e))
            return False

    def _save_cache_metadata(self, venv_path: str, requirements_file: Optional[str]) -> None:
        """Save cache metadata for the venv.

        Args:
            venv_path: Path to the virtual environment
            requirements_file: Path to the requirements file, or None when the
                plugin has no requirements file.
        """
        metadata_path = self._get_cache_metadata_path(venv_path)
        requirements_hash = self._compute_requirements_hash(requirements_file)

        resolved_requirements = None
        if requirements_file is not None and Path(requirements_file).exists():
            resolved_requirements = str(Path(requirements_file).resolve())

        metadata = {
            "venv_path": str(Path(venv_path).resolve()),
            "requirements_file": resolved_requirements,
            "requirements_hash": requirements_hash,
            "manifest_version": self.config.version,
            "manifest_hash": self._compute_manifest_hash(),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }

        with open(metadata_path, "w", encoding="utf8") as f:
            json.dump(metadata, f, indent=2)

        logger.info("Saved cache metadata to %s", metadata_path)

    async def create_venv(
        self, venv_path: str = ".venv", requirements_file: Optional[str] = None, use_cache: bool = True
    ) -> bool:
        """Create a new venv environment with caching support.

        Args:
            venv_path: Path where the virtual environment should be created
            requirements_file: Path to requirements file for cache validation
            use_cache: Whether to use cached venv if available
        """
        venv_path_obj = Path(venv_path)

        # Check if we can use cached venv. A None requirements_file is valid:
        # for converted FQN plugins the manifest version+hash is the cache signal
        # (U5), so cache validity must be evaluated even without a requirements file.
        if use_cache and self._is_venv_cache_valid(venv_path, requirements_file):
            logger.info("✓ Using cached virtual environment at: %s", venv_path_obj.resolve())
            return False

        # If cache is invalid or not using cache, remove existing venv
        if venv_path_obj.exists():
            logger.info("Removing existing venv at %s", venv_path)
            shutil.rmtree(venv_path_obj)

        # Check Python version
        python_version = sys.version_info
        logger.info(f"Current Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")

        # Create the EnvBuilder with common options
        builder = venv.EnvBuilder(
            system_site_packages=False,  # Don't include system site-packages
            clear=False,  # Don't clear existing venv if it exists
            symlinks=True,  # Use symlinks (recommended on Unix-like systems)
            upgrade=False,  # Don't upgrade existing venv
            with_pip=True,  # Install pip in the venv
            prompt=None,  # Use default prompt (directory name)
        )

        # Create the virtual environment
        logger.info(f"\nCreating virtual environment at: {venv_path_obj.resolve()}")
        try:
            builder.create(venv_path)
            logger.info("✓ Virtual environment created successfully!")
            logger.info("\nTo activate the virtual environment:")
            logger.info(f"  source {venv_path}/bin/activate  # On Unix/macOS")
            logger.info(f"  {venv_path}\\Scripts\\activate  # On Windows")
            return True
        except Exception as e:
            logger.error(f"✗ Error creating virtual environment: {e}")
            raise

    # Called by plugins/framework/loader/plugin.py load_and_instantiate_plugin()
    # The plugins/framework/manager.py class (PluginManager) loads and registers the plugin
    async def initialize(self) -> None:
        """Initialize the plugin's venv environment with caching support."""
        # ensure the config is validated
        if not os.path.exists(self.plugin_path):
            raise FileNotFoundError(f"plugin path not found: {self.plugin_path}")

        venv_path = self.plugin_path / ".venv"

        # requirements_file is optional: converted FQN plugins get their package
        # into the venv via the installer's channel source, not a requirements file.
        requirements_file_input = self.config.config.get("requirements_file")

        requirements_file: Optional[Path] = None
        if requirements_file_input:
            # Try to find the package location where plugin-manifest.yaml resides.
            # Fall back to self.plugin_path if package is not installed (e.g., in tests).
            try:
                package_path = find_package_path(self.config.name)
                logger.debug("Found installed package %s at %s", self.config.name, package_path)
            except RuntimeError:
                # Package not installed (e.g., in test environment), use plugin_path
                package_path = self.plugin_path
                logger.debug("Package %s not installed, using plugin_path: %s", self.config.name, package_path)

            requirements_file = package_path / requirements_file_input

        # Create venv with caching support. create_venv tolerates a None/missing
        # requirements file (empty-hash path).
        new_venv = await self.create_venv(venv_path=venv_path, requirements_file=requirements_file, use_cache=True)

        self.comm = VenvProcessCommunicator(venv_path)

        # Only (re)install when the venv was newly created or the cache was invalid.
        if new_venv:
            if requirements_file is not None and Path(requirements_file).exists():
                logger.info("Installing requirements in venv")
                self.comm.install_requirements(requirements_file)
            else:
                logger.info("No requirements file for %s; skipping requirements install", self.config.name)
            # Save metadata after successful creation (records requirements hash for cache validity).
            self._save_cache_metadata(venv_path, requirements_file)
        else:
            logger.info("Using cached venv, skipping requirements installation")

    async def cleanup(self) -> None:
        """Cleanup resources, including stopping the worker process."""
        if self.comm:
            logger.info("Stopping worker process for plugin '%s'", self.name)
            self.comm.stop_worker()
            self.comm = None

    def _validate_hook_invocation(self, hook_type: str) -> type[PluginResult]:
        """Validate hook type and communication channel.

        Args:
            hook_type: The hook type to validate

        Returns:
            The result type for the hook

        Raises:
            PluginError: If validation fails
        """
        registry = get_hook_registry()
        result_type = registry.get_result_type(hook_type)
        if not result_type:
            raise PluginError(
                error=PluginErrorModel(
                    message=f"Hook type '{hook_type}' not registered in hook registry", plugin_name=self.name
                )
            )

        if not self.comm:
            raise PluginError(error=PluginErrorModel(message="Plugin comm not initialized", plugin_name=self.name))

        return result_type

    def _build_hook_task(self, hook_type: str, payload: PluginPayload, context: PluginContext) -> dict[str, Any]:
        """Build task dictionary for hook invocation.

        Args:
            hook_type: The hook type to invoke
            payload: The payload to send
            context: The context to send

        Returns:
            Task dictionary ready for transmission
        """
        # Cache config lookups
        class_name = self.config.config["class_name"]
        safe_config = self.config.get_safe_config()

        # Serialize payload and context to ensure they are JSON-serializable
        serialized_payload = payload.model_dump(mode="json") if payload is not None else None
        serialized_context = context.model_dump(mode="json") if context is not None else None

        return {
            "task_type": "load_and_run_hook",
            "plugin_dirs": self.plugin_dirs,
            "class_name": class_name,
            "config": safe_config,
            HOOK_TYPE: hook_type,
            PLUGIN_NAME: self.name,
            PAYLOAD: serialized_payload,
            CONTEXT: serialized_context,
        }

    async def invoke_hook(self, hook_type: str, payload: PluginPayload, context: PluginContext) -> PluginResult:
        """Invoke a plugin in the context of the active venv (self.comm)"""
        try:
            # Validate and get result type
            self._validate_hook_invocation(hook_type)

            # Build and send task
            task_data = self._build_hook_task(hook_type, payload, context)
            loop = asyncio.get_event_loop()
            result_dict: dict[str, Any] = await loop.run_in_executor(
                None,
                functools.partial(
                    self.comm.send_task,
                    script_path="cpex/framework/isolated/worker.py",
                    task_data=task_data,
                    max_content_size=self.config.max_content_size,
                ),
            )
            # Convert response to typed result
            registry = get_hook_registry()
            return registry.json_to_result(hook_type, result_dict)

        except PluginError:
            logger.exception("Plugin error invoking hook '%s' for plugin '%s'", hook_type, self.name)
            raise
        except Exception as e:
            logger.exception("Unexpected error invoking hook '%s' for plugin '%s'", hook_type, self.name)
            raise PluginError(error=convert_exception_to_error(e, plugin_name=self.name)) from e

    def remove_venv(self):
        """
        Remove the virtual environment associated with the plugin.
        """
        shutil.rmtree(self.plugin_path.joinpath(".cpex"))
        shutil.rmtree(self.plugin_path.joinpath(".venv"))
