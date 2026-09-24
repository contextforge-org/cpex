# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/loader/test_config_loader.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Tao Peng

Regression tests for ConfigLoader's environment interpolation (issue #81).

``ConfigLoader.load_config`` must substitute ``{{ env.NAME }}`` references while leaving
every OTHER ``{{ ... }}`` / ``{% ... %}`` construct byte-for-byte untouched, so a plugin
that stores a runtime template in its config is not corrupted at load time.

The byte-for-byte requirement is not cosmetic: the motivating consumer,
``WebhookNotification``, renders its ``default_template`` with an exact string replace of
``{{event}}`` (no inner spaces), so any whitespace normalisation of the placeholder breaks
it just as thoroughly as blanking it did.
"""

# Standard
import os
import tempfile

# Third-Party
import pytest
import yaml

# First-Party
from cpex.framework.loader.config import ConfigLoader

# The runtime template a plugin stores in its own config, exactly as it must survive load.
_RUNTIME_TEMPLATE = '{ "event": "{{event}}", "timestamp": "{{timestamp}}", "violation": {{violation}} }'

# A config whose plugin carries BOTH an env reference (must be substituted) and a range of
# non-env constructs (must all survive verbatim).
_CONFIG = """plugins:
  - name: "TemplatePlugin"
    kind: "plugins.example.TemplatePlugin"
    hooks: ["prompt_pre_fetch"]
    config:
      endpoint: "{{ env.CPEX_TEST_ENDPOINT }}"
      default_template: '__RUNTIME_TEMPLATE__'
      nested_lookup: "{{ event.name }}"
      filtered: "{{ event | upper }}"
      conditional: "{% if flag %}kept{% endif %}"
      unset_env: "{{ env.CPEX_TEST_DEFINITELY_UNSET }}"
""".replace(
    # Plain token substitution: str.format/%-formatting would mangle the `{{ }}` and `{% %}`.
    "__RUNTIME_TEMPLATE__",
    _RUNTIME_TEMPLATE,
)


def _load(config_text: str, use_jinja: bool = True):
    """Write ``config_text`` to a temp file and load it through ConfigLoader."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as handle:
        handle.write(config_text)
        temp_path = handle.name
    try:
        return ConfigLoader.load_config(temp_path, use_jinja=use_jinja)
    finally:
        os.unlink(temp_path)


@pytest.fixture
def plugin_config(monkeypatch):
    """Load ``_CONFIG`` with the env reference set and the unset one guaranteed absent."""
    monkeypatch.setenv("CPEX_TEST_ENDPOINT", "https://hooks.example.com/abc")
    monkeypatch.delenv("CPEX_TEST_DEFINITELY_UNSET", raising=False)
    return _load(_CONFIG).plugins[0].config


def test_env_reference_is_substituted(plugin_config):
    """An ``{{ env.X }}`` reference is replaced with the environment value."""
    assert plugin_config["endpoint"] == "https://hooks.example.com/abc"


def test_non_env_placeholder_preserved_byte_for_byte(plugin_config):
    """Issue #81: a plugin's runtime template survives load exactly as written.

    Before the fix the whole YAML file was rendered as a Jinja template, so these
    placeholders were blanked to ``""`` (default ``Undefined``) or rewritten with canonical
    spacing as ``{{ event }}`` (``DebugUndefined``). Both break ``WebhookNotification``,
    which replaces the literal ``{{event}}``.
    """
    assert plugin_config["default_template"] == _RUNTIME_TEMPLATE


def test_nested_expression_preserved(plugin_config):
    """A nested lookup survives instead of raising ``UndefinedError`` at load time."""
    assert plugin_config["nested_lookup"] == "{{ event.name }}"


def test_filter_expression_preserved(plugin_config):
    """A filter is not applied to the placeholder (it used to yield ``{{ EVENT }}``)."""
    assert plugin_config["filtered"] == "{{ event | upper }}"


def test_statement_block_preserved(plugin_config):
    """A ``{% ... %}`` block is not evaluated away to an empty string."""
    assert plugin_config["conditional"] == "{% if flag %}kept{% endif %}"


def test_unset_env_reference_preserved_verbatim(plugin_config):
    """An unset environment variable keeps its original text.

    It is neither blanked to ``""`` (the pre-fix behaviour) nor replaced with Jinja
    diagnostic text such as ``{{ no such element: os._Environ object['X'] }}``.
    """
    assert plugin_config["unset_env"] == "{{ env.CPEX_TEST_DEFINITELY_UNSET }}"


def test_env_value_is_not_html_escaped(monkeypatch):
    """Substituted values are inserted literally — the config is YAML, not HTML.

    The previous Jinja pass used ``autoescape=True``, which turned a perfectly valid
    query-string ``&`` into ``&amp;`` inside the loaded configuration.
    """
    url = "https://hooks.example.com/a?b=1&c=2<3"
    monkeypatch.setenv("CPEX_TEST_ENDPOINT", url)
    monkeypatch.delenv("CPEX_TEST_DEFINITELY_UNSET", raising=False)
    config = _load(_CONFIG)
    assert config.plugins[0].config["endpoint"] == url


def test_env_value_breaking_yaml_quoting_fails_loudly(monkeypatch):
    """Boundary: a value that breaks the surrounding YAML quoting raises, it is not silent.

    Substitution happens on the raw text, so an environment value containing a double
    quote terminates the quoted scalar it was substituted into. The previous Jinja pass
    hid this behind ``autoescape``, which rewrote the quote to ``&#34;`` and loaded a
    silently wrong value. Failing to parse is the better of the two, and this test pins
    the behaviour so a future change to escape/quote the value is a deliberate one.
    """
    monkeypatch.setenv("CPEX_TEST_ENDPOINT", 'https://hooks.example.com/"injected')
    monkeypatch.delenv("CPEX_TEST_DEFINITELY_UNSET", raising=False)
    with pytest.raises(yaml.YAMLError):
        _load(_CONFIG)


def test_jinja_disabled_leaves_template_untouched(monkeypatch):
    """With ``use_jinja=False`` nothing is interpolated — env refs stay literal too."""
    monkeypatch.setenv("CPEX_TEST_ENDPOINT", "https://hooks.example.com/abc")
    config = _load(_CONFIG, use_jinja=False)
    plugin_config = config.plugins[0].config
    assert plugin_config["endpoint"] == "{{ env.CPEX_TEST_ENDPOINT }}"
    assert "{{event}}" in plugin_config["default_template"]
