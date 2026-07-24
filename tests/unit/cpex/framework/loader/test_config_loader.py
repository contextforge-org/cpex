# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/loader/test_config_loader.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Tao Peng

Regression tests for ConfigLoader's jinja rendering (issue #81).

The jinja pass in ``ConfigLoader.load_config`` must substitute ``env.*`` references
while leaving any OTHER ``{{ ... }}`` placeholder verbatim — so a plugin that stores
a runtime template in its config (e.g. WebhookNotification's ``default_template``) is
not silently blanked at load time.
"""

# Standard
import os
import tempfile

# First-Party
from cpex.framework.loader.config import ConfigLoader

# A config whose plugin carries BOTH an env reference (must be substituted) and a
# non-env runtime template placeholder (must be preserved, not blanked).
_CONFIG = """plugins:
  - name: "TemplatePlugin"
    kind: "plugins.example.TemplatePlugin"
    hooks: ["prompt_pre_fetch"]
    config:
      endpoint: "{{ env.CPEX_TEST_ENDPOINT }}"
      default_template: '{ "event": "{{event}}", "timestamp": "{{timestamp}}", "violation": "{{violation}}" }'
"""


def _load(config_text: str, use_jinja: bool = True):
    """Write ``config_text`` to a temp file and load it through ConfigLoader."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as handle:
        handle.write(config_text)
        temp_path = handle.name
    try:
        return ConfigLoader.load_config(temp_path, use_jinja=use_jinja)
    finally:
        os.unlink(temp_path)


def test_jinja_substitutes_env_reference(monkeypatch):
    """An ``{{ env.X }}`` reference is substituted with the environment value."""
    monkeypatch.setenv("CPEX_TEST_ENDPOINT", "https://hooks.example.com/abc")
    config = _load(_CONFIG)
    assert config.plugins[0].config["endpoint"] == "https://hooks.example.com/abc"


def test_jinja_preserves_non_env_placeholder(monkeypatch):
    """Issue #81: a non-env ``{{ ... }}`` (a plugin's runtime template) is NOT blanked.

    Before the fix, the default Undefined rendered every non-env placeholder to an
    empty string at load time, leaving ``default_template`` as
    ``{ "event": "", "timestamp": "", "violation": "" }``.
    """
    monkeypatch.setenv("CPEX_TEST_ENDPOINT", "https://hooks.example.com/abc")
    config = _load(_CONFIG)
    template = config.plugins[0].config["default_template"]
    # The runtime placeholders survive load (whitespace is normalized to `{{ name }}`).
    assert "{{ event }}" in template
    assert "{{ timestamp }}" in template
    assert "{{ violation }}" in template
    # And it was NOT blanked.
    assert '"event": ""' not in template


def test_jinja_disabled_leaves_template_untouched():
    """With ``use_jinja=False`` nothing is rendered — env refs stay literal too."""
    config = _load(_CONFIG, use_jinja=False)
    assert config.plugins[0].config["endpoint"] == "{{ env.CPEX_TEST_ENDPOINT }}"
    assert "{{event}}" in config.plugins[0].config["default_template"]
