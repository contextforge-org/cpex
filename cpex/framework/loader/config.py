# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/loader/config.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor, Mihai Criveti

Configuration loader implementation.
This module loads configurations for plugins.
"""

# Standard
import os

# Third-Party
import jinja2
import yaml
from jinja2.sandbox import SandboxedEnvironment

# First-Party
from cpex.framework.models import Config


class ConfigLoader:
    """A configuration loader.

    Examples:
        >>> import tempfile
        >>> import os
        >>> # Create a temporary config file
        >>> with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        ...     _ = f.write(\"\"\"
        ... plugin_dirs: ['/path/to/plugins']
        ... \"\"\")
        ...     temp_path = f.name
        >>> try:
        ...     config = ConfigLoader.load_config(temp_path, use_jinja=False)
        ...     config.plugin_dirs
        ... finally:
        ...     os.unlink(temp_path)
        ['/path/to/plugins']
    """

    @staticmethod
    def load_config(config: str, use_jinja: bool = True) -> Config:
        """Load the plugin configuration from a file path.

        Args:
            config: the configuration path.
            use_jinja: use jinja to replace env variables if true.

        Returns:
            The plugin configuration object.

        Examples:
            >>> import tempfile
            >>> import os
            >>> with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            ...     _ = f.write(\"\"\"
            ... plugin_dirs: []
            ... \"\"\")
            ...     temp_path = f.name
            >>> try:
            ...     cfg = ConfigLoader.load_config(temp_path, use_jinja=False)
            ...     cfg.plugin_dirs
            ... finally:
            ...     os.unlink(temp_path)
            []
        """
        try:
            with open(os.path.normpath(config), "r", encoding="utf-8") as file:
                template = file.read()
                if use_jinja:
                    # Use DebugUndefined so that ONLY `env.*` references (the values passed to
                    # render()) are substituted; any other ``{{ ... }}`` in the config — e.g. a
                    # plugin's default_template that it renders itself at runtime — is left
                    # verbatim as ``{{ name }}`` instead of being silently blanked to "".
                    # Without this, the default Undefined renders every non-env placeholder to an
                    # empty string at load time, so a plugin that stores a runtime template in its
                    # config (WebhookNotification's default_template) ends up with an all-empty,
                    # invalid body. See issue #81.
                    jinja_env = SandboxedEnvironment(loader=jinja2.BaseLoader(), autoescape=True, undefined=jinja2.DebugUndefined)
                    rendered_template = jinja_env.from_string(template).render(env=os.environ)
                else:
                    rendered_template = template
                config_data = yaml.safe_load(rendered_template) or {}
            return Config(**config_data)
        except FileNotFoundError:
            # Graceful fallback for tests and minimal environments without plugin config
            return Config(plugins=[], plugin_dirs=[])


class ConfigSaver:
    """
    A configuration saver
    """

    @staticmethod
    def save_config(config: Config, config_path: str) -> None:
        """
        Save the supplied configuration data to the filesystem
        """
        try:
            updated_content = yaml.safe_dump(config.model_dump(mode="json"), default_flow_style=False)
            with open(os.path.normpath(config_path), "w", encoding="utf-8") as file:
                file.write(updated_content)
                file.flush()
        except OSError as ose:
            raise RuntimeError(f"Error saving PluginConfig to {config_path}") from ose
