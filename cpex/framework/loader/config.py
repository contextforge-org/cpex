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
import re

# Third-Party
import yaml

# First-Party
from cpex.framework.models import Config

# The ONLY interpolation syntax supported in a plugin configuration: ``{{ env.NAME }}``.
# Deliberately narrow — see ``_interpolate_env`` for why the config is not rendered as a
# general-purpose template.
_ENV_REFERENCE = re.compile(r"{{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*}}")


def _interpolate_env(template: str) -> str:
    """Substitute ``{{ env.NAME }}`` references with their environment values.

    Only that exact syntax is touched. Every other ``{{ ... }}`` or ``{% ... %}`` in the
    configuration is left **byte-for-byte** unchanged, because plugins legitimately store
    templates in their own config that they render themselves at runtime (for example
    ``WebhookNotification.default_template``, which does an exact ``str.replace`` on
    ``{{event}}``). Rendering the whole YAML document as a Jinja template destroyed those:
    unknown names were blanked to ``""``, filters rewrote them, ``{% ... %}`` blocks were
    evaluated away, nested lookups such as ``{{ event.name }}`` raised ``UndefinedError``,
    and ``autoescape`` HTML-escaped every substituted value (``&`` became ``&amp;``).
    See issue #81.

    A reference to an environment variable that is not set is preserved verbatim rather
    than being replaced with an empty string, so a missing variable stays visible instead
    of silently collapsing a value.

    Args:
        template: the raw configuration text.

    Returns:
        The text with ``{{ env.NAME }}`` references resolved.

    Examples:
        >>> import os
        >>> os.environ['CPEX_DOCTEST_VAR'] = 'https://example.test/a?b=1&c=2'
        >>> _interpolate_env('endpoint: "{{ env.CPEX_DOCTEST_VAR }}"')
        'endpoint: "https://example.test/a?b=1&c=2"'
        >>> _interpolate_env('body: "{{event}} {{ ts | upper }}"')
        'body: "{{event}} {{ ts | upper }}"'
        >>> _interpolate_env('endpoint: "{{ env.CPEX_DOCTEST_UNSET }}"')
        'endpoint: "{{ env.CPEX_DOCTEST_UNSET }}"'
        >>> del os.environ['CPEX_DOCTEST_VAR']
    """

    def _replace(match: "re.Match[str]") -> str:
        """Resolve a single matched reference, keeping unset variables verbatim.

        Args:
            match: the matched ``{{ env.NAME }}`` reference.

        Returns:
            The environment value, or the original text when the variable is unset.
        """
        return os.environ.get(match.group(1), match.group(0))

    return _ENV_REFERENCE.sub(_replace, template)


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
            use_jinja: if true, resolve ``{{ env.NAME }}`` environment references in the
                configuration. Only that syntax is interpolated — all other ``{{ ... }}``
                and ``{% ... %}`` text is preserved verbatim (see ``_interpolate_env``).
                The name is kept for backwards compatibility with existing callers; the
                configuration is no longer rendered as a general Jinja template.

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
                    rendered_template = _interpolate_env(template)
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
