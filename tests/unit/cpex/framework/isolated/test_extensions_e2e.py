# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/isolated/test_extensions_e2e.py
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

End-to-end tests for the isolated-worker extensions channel.

These drive a *real* worker subprocess over stdin/stdout, the way the Rust host
does, rather than calling ``process_task`` in-process. That matters for reasons
the in-process tests cannot cover:

* **The field really crosses the boundary.** An in-process test constructs the
  ``Extensions`` itself, so it proves the framework forwards an object it was
  handed — not that the worker read a JSON field off stdin and rebuilt the model
  on the far side.
* **A 3-arg hook is really detected.** ``_accepts_extensions`` inspects the hook
  signature at plugin-load time. Only loading the plugin the way the worker does
  exercises that.
* **The return really serializes.** ``modified_extensions`` has to survive
  ``model_dump(mode="json")`` onto the stdout line the host parses. A model that
  is correct in memory but unserializable would pass every in-process test.

The wire contract both surfaces implement is pinned in
``docs/specs/extensions-wire-contract.md``.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[5]
FIXTURE_PLUGIN_DIR = REPO_ROOT / "tests" / "unit" / "cpex" / "fixtures" / "plugins" / "isolated"
EXTENSIONS_PLUGIN_CLASS = "extensions_plugin.plugin.ExtensionsPlugin"

# Kept in step with the fixture plugin's own constant.
APPENDED_LABEL = "SCANNED_BY_FIXTURE"

# A 2-arg fixture, to prove the framework withholds extensions from that shape.
TWO_ARG_PLUGIN_CLASS = "test_plugin.plugin.TestPlugin"


def _build_task(
    extensions,
    request_id,
    plugin_class=EXTENSIONS_PLUGIN_CLASS,
    capabilities=None,
    hook_type="tool_pre_invoke",
):
    """Build a load_and_run_hook task line for the worker.

    Args:
        extensions: the ``extensions`` field, or None to omit it.
        request_id: id the worker must echo back.
        plugin_class: dotted path of the fixture plugin class to load.
        capabilities: capabilities to declare on the plugin config.
        hook_type: hook to invoke.

    Returns:
        The task as a dict.
    """
    config_dict = {
        "name": plugin_class.split(".")[0],
        "kind": "isolated_venv",
        "config": {},
    }
    if capabilities is not None:
        config_dict["capabilities"] = capabilities

    task = {
        "task_type": "load_and_run_hook",
        "config": json.dumps(config_dict),
        "plugin_dirs": [str(FIXTURE_PLUGIN_DIR)],
        "class_name": plugin_class,
        "hook_type": hook_type,
        "payload": {"name": "search", "args": {"q": "hello"}},
        "context": {"state": {}, "global_context": {"request_id": request_id}, "metadata": {}},
        "request_id": request_id,
    }
    if extensions is not None:
        task["extensions"] = extensions
    return task


def _run_worker(tasks, probe_path, extra_env=None):
    """Run the worker as a subprocess, feeding it tasks and collecting output.

    Args:
        tasks: list of task dicts to write to the worker's stdin.
        probe_path: file the fixture plugin records its observations to.
        extra_env: additional environment variables for the worker process.

    Returns:
        A ``(responses, stdout, stderr, observations)`` tuple.
    """
    stdin_data = "".join(json.dumps(task) + "\n" for task in tasks)

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(REPO_ROOT), str(FIXTURE_PLUGIN_DIR)])
    env["CPEX_EXTENSIONS_PROBE"] = str(probe_path)
    # The worker refuses module paths outside the allowed plugin dirs.
    env["CPEX_ALLOWED_PLUGIN_DIRS"] = str(FIXTURE_PLUGIN_DIR)
    if extra_env:
        env.update(extra_env)

    completed = subprocess.run(
        [sys.executable, "-m", "cpex.framework.isolated.worker"],
        input=stdin_data,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
        timeout=120,
    )

    responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    observations = []
    if Path(probe_path).exists():
        observations = [
            json.loads(line) for line in Path(probe_path).read_text(encoding="utf-8").splitlines() if line.strip()
        ]
    return responses, completed.stdout, completed.stderr, observations


def _wire_extensions():
    """An inbound wire dict shaped as the Rust host sends it.

    The three sensitive headers are absent because the host strips them before
    writing the task; what a plugin sees is the already-scrubbed view. The
    fixture asserts on that, so a host-side regression would surface as a leak
    in the probe rather than passing silently.
    """
    return {
        "security": {"labels": ["PII"], "classification": "confidential"},
        "agent": {"agent_id": "agent-e2e-7"},
        "http": {"headers": {"X-Request-Id": "req-ext-e2e"}},
        "custom": {"trace": True},
    }


@pytest.fixture
def probe_path(tmp_path):
    """Path the fixture plugin records hook observations to."""
    return tmp_path / "extensions_probe.jsonl"


class TestExtensionsEndToEnd:
    """Extensions reach a real 3-arg plugin hook through a real worker."""

    def test_three_arg_plugin_observes_inbound_extensions(self, probe_path):
        """A task with an extensions field delivers populated extensions to the hook.

        The acceptance example for the whole channel: before this, the same task
        produced ``extensions=None`` inside the hook.
        """
        task = _build_task(
            _wire_extensions(),
            "req-e2e-ext",
            capabilities=["read_labels", "read_agent", "read_headers"],
        )

        responses, stdout, stderr, observations = _run_worker([task], probe_path)

        assert len(observations) == 1, f"plugin did not run; stdout={stdout!r} stderr={stderr!r}"
        seen = observations[0]
        assert seen["extensions"] == "present", "the hook must receive extensions, not None"
        assert seen["labels"] == ["PII"]
        assert seen["classification"] == "confidential"
        assert seen["agent_id"] == "agent-e2e-7"
        assert seen["custom"] == {"trace": True}
        assert responses[0]["request_id"] == "req-e2e-ext"
        assert responses[0].get("continue_processing") is True

    def test_no_sensitive_header_reaches_the_plugin(self, probe_path):
        """The inbound view carries no credential header.

        The host strips them; this asserts the plugin's own view of what arrived,
        which is the only place that claim can be checked from.
        """
        task = _build_task(
            _wire_extensions(),
            "req-e2e-headers",
            capabilities=["read_labels", "read_headers"],
        )

        _responses, stdout, stderr, observations = _run_worker([task], probe_path)

        assert len(observations) == 1, f"plugin did not run; stdout={stdout!r} stderr={stderr!r}"
        assert observations[0]["leaked_headers"] == [], "no sensitive header may cross the boundary"
        assert "x-request-id" in observations[0]["header_names"], "a benign header still arrives"

    def test_appended_label_rides_back_on_the_response(self, probe_path):
        """The plugin's additive label survives onto the response the host reads.

        This is the return half of the channel. The label has to survive
        ``model_dump(mode="json")`` onto the stdout line, which is what the Rust
        host deserializes and feeds to the tier-validated merge.
        """
        task = _build_task(
            _wire_extensions(),
            "req-e2e-return",
            capabilities=["read_labels", "append_labels"],
        )

        responses, stdout, stderr, _observations = _run_worker([task], probe_path)

        assert responses, f"worker produced no response; stdout={stdout!r} stderr={stderr!r}"
        modified = responses[0].get("modified_extensions")
        assert modified is not None, f"the plugin's extensions must ride back; got {responses[0]!r}"

        labels = modified["security"]["labels"]
        assert APPENDED_LABEL in labels, f"the appended label must survive serialization: {labels}"
        assert "PII" in labels, "and the inbound label must still be there"

    def test_absent_extensions_field_leaves_the_hook_with_none(self, probe_path):
        """Without the field the hook sees None and does not error.

        The backward-compatibility case: every task built before this feature
        existed omits the field, and those plugins must keep working.
        """
        task = _build_task(None, "req-e2e-noext")

        responses, stdout, stderr, observations = _run_worker([task], probe_path)

        assert len(observations) == 1, f"plugin did not run; stdout={stdout!r} stderr={stderr!r}"
        assert observations[0]["extensions"] is None
        assert responses[0].get("continue_processing") is True
        assert responses[0].get("modified_extensions") is None, "nothing to modify means no field"

    def test_two_arg_plugin_still_runs_when_the_task_carries_extensions(self, probe_path):
        """A 2-arg hook is invoked normally and is never handed extensions.

        Every pre-existing isolated plugin is 2-arg. If the worker forced the
        third argument, all of them would break at once — so this is the
        regression guard for the existing fleet.
        """
        task = _build_task(
            _wire_extensions(),
            "req-e2e-twoarg",
            plugin_class=TWO_ARG_PLUGIN_CLASS,
        )

        responses, stdout, stderr, _observations = _run_worker([task], probe_path)

        assert responses, f"worker produced no response; stdout={stdout!r} stderr={stderr!r}"
        assert responses[0].get("status") != "error", f"a 2-arg plugin must still run: {responses[0]!r}"
        assert responses[0]["request_id"] == "req-e2e-twoarg"

    def test_unknown_slot_does_not_break_the_worker(self, probe_path):
        """A slot this Python version does not model is ignored, not fatal.

        The two surfaces version independently. A host that grows a slot ahead of
        the worker must not take every plugin on the channel down.
        """
        wire = _wire_extensions()
        wire["some_future_slot"] = {"whatever": 1}
        task = _build_task(wire, "req-e2e-unknown", capabilities=["read_labels"])

        responses, stdout, stderr, observations = _run_worker([task], probe_path)

        assert len(observations) == 1, f"plugin did not run; stdout={stdout!r} stderr={stderr!r}"
        assert observations[0]["extensions"] == "present", "known slots must survive an unknown one"
        assert observations[0]["labels"] == ["PII"]
        assert responses[0].get("continue_processing") is True
