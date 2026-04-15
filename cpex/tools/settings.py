"""Location: ./cpex/tools/settings.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

This module implements the plugin catalog object.
"""

import logging

from dotenv import find_dotenv, load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


load_dotenv(find_dotenv("../../.env"))


class CatalogSettings(BaseSettings):
    """Catalog settings."""

    PLUGINS_GITHUB_TOKEN: str | None = Field(
        default=None, description="The github token for accessing the plugins repositories"
    )
    PLUGINS_GITHUB_API: str | None = Field(default="api.github.com", description="api.github.com")
    PLUGINS_REPO_URLS: str = Field(
        default="https://github.com/ibm/cpex-plugins", description="The url of the plugins repositories comma separated"
    )
    PLUGINS_REGISTRY_FOLDER: str | None = Field(
        default="data", description="The folder where the plugin registry is located (r/w)"
    )
    PLUGINS_CATALOG_FOLDER: str = Field(
        default="plugin-catalog", description="The folder where the plugin catalog is located (r/w)"
    )
    PLUGINS_FOLDER: str = Field(default="plugins", description="The folder where the plugins are located (r/w)")
    model_config = SettingsConfigDict(env_prefix="PLUGINS_", env_file=".env", env_file_encoding="utf-8", extra="ignore")


def get_catalog_settings() -> CatalogSettings:
    """Get catalog settings.
    Returns:
        CatalogSettings: Catalog settings.
    """
    return CatalogSettings()
