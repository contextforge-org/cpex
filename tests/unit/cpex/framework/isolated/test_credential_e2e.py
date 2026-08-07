# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/isolated/test_credential_e2e.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

End-to-end tests for the isolated-worker credential path.

These drive a *real* worker subprocess over stdin/stdout, the way the Rust host
does, rather than calling ``process_task`` in-process. That matters for two
reasons the in-process tests cannot cover:

* **Hook registration.** ``cpex.framework.hooks.identity`` registers its hooks as
  an import-time side effect and ``cpex.framework.__init__`` does not import it.
  An in-process test that imports the identity models itself registers them
  incidentally, masking a worker that would fail with "No payload defined for
  hook identity_resolve" in production.
* **stderr.** The reference ``venv_comm.py`` reader drains and logs worker
  stderr, so it is a real leak sink — and only a subprocess has one.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[5]
FIXTURE_PLUGIN_DIR = REPO_ROOT / "tests" / "unit" / "cpex" / "fixtures" / "plugins" / "isolated"
CREDENTIAL_PLUGIN_CLASS = "credential_plugin.plugin.CredentialPlugin"
LEAKY_PLUGIN_CLASS = "leaky_plugin.plugin.LeakyPlugin"


def _build_task(hook_type, payload, credential, request_id, plugin_class=CREDENTIAL_PLUGIN_CLASS):
    """Build a load_and_run_hook task line for the worker.

    Args:
        hook_type: hook to invoke.
        payload: payload dict as the client would serialize it (secrets redacted).
        credential: the credential field, or None to omit it.
        request_id: id the worker must echo back.
        plugin_class: dotted path of the fixture plugin class to load.

    Returns:
        The task as a dict.
    """
    config_dict = {"name": plugin_class.split(".")[0], "kind": "isolated_venv", "config": {}}
    task = {
        "task_type": "load_and_run_hook",
        "config": json.dumps(config_dict),
        "plugin_dirs": [str(FIXTURE_PLUGIN_DIR)],
        "class_name": plugin_class,
        "hook_type": hook_type,
        "payload": payload,
        "context": {"state": {}, "global_context": {"request_id": request_id}, "metadata": {}},
        "request_id": request_id,
    }
    if credential is not None:
        task["credential"] = credential
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
    env["CPEX_CREDENTIAL_PROBE"] = str(probe_path)
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


@pytest.fixture
def probe_path(tmp_path):
    """Path the fixture plugin records hook observations to."""
    return tmp_path / "credential_probe.jsonl"


class TestCredentialEndToEnd:
    """The plaintext token reaches a real plugin hook through a real worker."""

    def test_identity_resolve_plugin_observes_plaintext_token(self, probe_path):
        """An identity_resolve task with a credential field delivers the plaintext.

        The payload on the wire carries only ``"**********"`` — so if the plugin
        records the real token, it can only have come from the credential field.
        """
        token = "e2e.IDENTITY.plaintext-token"
        task = _build_task(
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            {"inbound": {"token": token, "source_header": "Authorization", "kind": "jwt"}},
            "req-e2e-identity",
        )

        responses, stdout, stderr, observations = _run_worker([task], probe_path)

        assert len(observations) == 1, f"plugin did not run; stdout={stdout!r} stderr={stderr!r}"
        assert observations[0]["hook"] == "identity_resolve"
        assert observations[0]["raw_token"] == token
        assert observations[0]["source"] == "bearer"
        # The header name is delivered; its value is not (headers do not redact).
        assert observations[0]["headers"] == {"Authorization": "**********"}
        assert responses[0]["request_id"] == "req-e2e-identity"
        assert responses[0].get("continue_processing") is True

    def test_token_delegate_plugin_observes_plaintext_token(self, probe_path):
        """A token_delegate task with a credential field delivers the plaintext."""
        token = "e2e.DELEGATED.plaintext-token"
        task = _build_task(
            "token_delegate",
            {"target_name": "get_compensation", "target_type": "tool", "bearer_token": "**********"},
            {
                "delegated": {
                    "token": token,
                    "outbound_header": "Authorization",
                    "audience": "hr-service",
                    "scopes": ["read:compensation"],
                }
            },
            "req-e2e-delegate",
        )

        responses, stdout, stderr, observations = _run_worker([task], probe_path)

        assert len(observations) == 1, f"plugin did not run; stdout={stdout!r} stderr={stderr!r}"
        assert observations[0]["hook"] == "token_delegate"
        assert observations[0]["bearer_token"] == token
        assert observations[0]["target_name"] == "get_compensation"
        assert responses[0]["request_id"] == "req-e2e-delegate"

    def test_without_credential_field_plugin_sees_only_redacted_token(self, probe_path):
        """The credential field is the *only* plaintext source.

        Same task minus the credential field: the plugin must see the redacted
        placeholder the payload carried, confirming the plaintext cannot arrive
        by any other route.
        """
        task = _build_task(
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            None,
            "req-e2e-nocred",
        )

        responses, stdout, stderr, observations = _run_worker([task], probe_path)

        assert len(observations) == 1, f"plugin did not run; stdout={stdout!r} stderr={stderr!r}"
        assert observations[0]["raw_token"] == "**********"
        # Not an error — reconstruction is opt-in on the field's presence.
        assert responses[0].get("continue_processing") is True

    def test_no_token_reaches_stdout_or_stderr_on_success(self, probe_path):
        """A successful credential task emits the token to neither sink."""
        token = "e2e-CANARY-no-leak-on-success"
        task = _build_task(
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            {"inbound": {"token": token, "source_header": "Authorization", "kind": "jwt"}},
            "req-e2e-clean",
        )

        _, stdout, stderr, observations = _run_worker([task], probe_path)

        # Guard against a vacuous pass: the token really was delivered.
        assert observations[0]["raw_token"] == token
        assert token not in stdout, "token leaked to worker stdout"
        assert token not in stderr, "token leaked to worker stderr"

    def test_fail_closed_on_empty_token_end_to_end(self, probe_path):
        """An empty token yields an error response and the hook never runs."""
        task = _build_task(
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            {"inbound": {"token": "", "source_header": "Authorization", "kind": "jwt"}},
            "req-e2e-failclosed",
        )

        responses, stdout, stderr, observations = _run_worker([task], probe_path)

        assert observations == [], "hook ran despite unusable credential"
        assert responses[0]["status"] == "error"
        assert "Credential reconstruction failed" in responses[0]["message"]
        assert responses[0]["request_id"] == "req-e2e-failclosed"

    def test_hostile_plugin_leaks_nothing_through_any_sink(self, probe_path):
        """Every exfiltration vector a plugin has is closed, in one worker run.

        The plugin holds the plaintext by design, so it can *try* through any sink.
        Each mode below was confirmed leaking before the scrubbing barrier moved to
        the log-record factory and grew stdout/result containment.
        """
        token = "e2e-HOSTILE-CANARY-abc123"
        modes = [
            "log_exception",
            "log_exc_arg",
            "log_container",
            "log_noprop",
            "raise_embedded",
            "print_stdout",
            "print_stderr",
            "result_metadata",
            "result_claims",
            "result_reason",
            "echo_headers",
        ]

        failures = []
        for mode in modes:
            task = _build_task(
                "identity_resolve",
                {"raw_token": "**********", "source": "bearer", "headers": {}},
                {
                    "inbound": {
                        "token": token,
                        "source_header": "Authorization",
                        "kind": "jwt",
                        # echo_headers copies these into raw_claims; the list value
                        # is the off-type case model_copy does not validate.
                        "headers": {"Authorization": [f"Bearer {token}"], "X-Trace": "abc"},
                    }
                },
                f"req-leak-{mode}",
                plugin_class=LEAKY_PLUGIN_CLASS,
            )
            _, stdout, stderr, _ = _run_worker([task], probe_path, extra_env={"CPEX_LEAK_MODE": mode, "LEAKY": "1"})
            if token in stdout:
                failures.append(f"{mode}: leaked to stdout")
            if token in stderr:
                failures.append(f"{mode}: leaked to stderr")

        assert not failures, "credential leaked:\n" + "\n".join(failures)

    def test_plugin_stdout_write_does_not_corrupt_the_response_channel(self, probe_path):
        """A plugin printing to stdout must not inject a line into the framing channel.

        venv_comm reads stdout line-by-line and demuxes on request_id, so a
        plugin-authored line with a matching id would be delivered to the caller as
        the worker's own response and desync the stream.
        """
        token = "e2e-FRAMING-CANARY-abc123"
        task = _build_task(
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            {"inbound": {"token": token, "source_header": "Authorization", "kind": "jwt"}},
            "req-e2e-leak",
            plugin_class=LEAKY_PLUGIN_CLASS,
        )

        responses, stdout, stderr, _ = _run_worker(
            [task], probe_path, extra_env={"CPEX_LEAK_MODE": "print_stdout", "LEAKY": "1"}
        )

        assert token not in stdout
        assert token not in stderr
        # Exactly one line on the channel — the worker's own response — and it
        # carries no injected field.
        assert len(responses) == 1, f"plugin injected extra response lines: {responses}"
        assert "stolen" not in responses[0]

    @pytest.mark.parametrize("mode", ["result_metadata", "result_claims", "result_reason", "echo_headers"])
    def test_result_echoing_the_credential_fails_closed(self, probe_path, mode):
        """A result carrying the inbound token is refused, not shipped.

        metadata / raw_claims / reject_reason are plain types that main() serializes
        straight to stdout, so the only safe outcome is to fail the task.
        """
        token = "e2e-RESULTECHO-CANARY-abc123"
        task = _build_task(
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            {
                "inbound": {
                    "token": token,
                    "source_header": "Authorization",
                    "kind": "jwt",
                    "headers": {"Authorization": [f"Bearer {token}"]},
                }
            },
            "req-e2e-resultecho",
            plugin_class=LEAKY_PLUGIN_CLASS,
        )

        responses, stdout, stderr, _ = _run_worker([task], probe_path, extra_env={"CPEX_LEAK_MODE": mode, "LEAKY": "1"})

        assert token not in stdout
        assert token not in stderr
        if mode == "echo_headers":
            # The headers the plugin echoed were already scrubbed at
            # reconstruction, so this succeeds rather than failing closed —
            # defense in depth, and the token still never ships.
            assert responses[0].get("continue_processing") is True
        else:
            assert responses[0]["status"] == "error"
            assert "Credential reconstruction failed" in responses[0]["message"]

    def test_non_identity_hook_ignores_credential_field(self, probe_path):
        """A credential field on a non-identity hook triggers no reconstruction.

        The fixture plugin has no ``tool_pre_invoke``, so the hook is a no-op —
        what matters is that the worker does not fail closed, does not touch the
        payload, and does not echo the field.
        """
        token = "e2e-CANARY-wrong-hook"
        task = _build_task(
            "tool_pre_invoke",
            {"name": "web_search", "args": {}},
            {"inbound": {"token": token, "source_header": "Authorization", "kind": "jwt"}},
            "req-e2e-otherhook",
        )

        responses, stdout, stderr, observations = _run_worker([task], probe_path)

        assert observations == []
        # No fail-closed error: the credential field is simply ignored here.
        assert "Credential reconstruction failed" not in json.dumps(responses)
        assert token not in stdout, "ignored credential leaked to stdout"
        assert token not in stderr, "ignored credential leaked to stderr"
