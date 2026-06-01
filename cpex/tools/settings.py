"""Location: ./cpex/tools/settings.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

This module implements the plugin catalog object.
"""

import logging
import os
from pathlib import Path

from dotenv import find_dotenv, load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


load_dotenv(find_dotenv("../../.env"))


class CatalogSettings(BaseSettings):
    """Catalog settings."""

    model_config = SettingsConfigDict(env_prefix="PLUGINS_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    GITHUB_TOKEN: str | None = Field(
        default=None, description="The github token for accessing the plugins repositories"
    )
    GITHUB_API: str | None = Field(default="api.github.com", description="api.github.com")
    REPO_URLS: str = Field(
        default="https://github.com/ibm/cpex-plugins", description="The url of the plugins repositories comma separated"
    )
    REGISTRY_FOLDER: str | None = Field(
        default="data", description="The folder where the plugin registry is located (r/w)"
    )
    CATALOG_FOLDER: str = Field(
        default="plugin-catalog", description="The folder where the plugin catalog is located (r/w)"
    )
    FOLDER: str = Field(default="plugins", description="The folder where the plugins are located (r/w)")
    VERIFY_PACKAGE_INTEGRITY: bool = Field(
        default=True, description="Enable SHA256 hash verification for downloaded packages from PyPI"
    )
    STRICT_INTEGRITY_MODE: bool = Field(
        default=False, description="Fail installation if package hashes are unavailable (strict mode)"
    )


def get_catalog_settings() -> CatalogSettings:
    """Get catalog settings.
    Returns:
        CatalogSettings: Catalog settings.
    """
    return CatalogSettings()


def get_plugin_registry_path() -> Path:
    """Get the plugin registry file path.

    This centralizes the logic for determining where the plugin registry is stored.
    Uses PLUGIN_REGISTRY_FILE env var if set, otherwise falls back to 'data' folder.

    Returns:
        Path: Path to the installed-plugins.json file.
    """
    folder = Path(os.environ.get("PLUGIN_REGISTRY_FILE", "data"))
    return folder / "installed-plugins.json"
