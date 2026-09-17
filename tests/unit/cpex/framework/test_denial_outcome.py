"""Boundary and attribution tests for explicit denial telemetry."""

import inspect
import json
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio

from cpex.framework import (
    ControlExecutionRecord,
    ControlExecutionStatus,
    DenialExecutionRecord,
    DenialOutcome,
    GlobalContext,
    OnError,
    Plugin,
    PluginConfig,
    PluginContext,
    PluginError,
    PluginManager,
    PluginMode,
    PluginResult,
    PluginViolation,
    PluginViolationError,
    PromptHookType,
    PromptPrehookPayload,
)
from cpex.framework.base import HookRef, PluginRef
from cpex.framework.errors import sanitize_denial_metadata


def test_cross_runtime_acceptance_fixtures():
    fixtures = json.loads((Path(__file__).parents[3] / "fixtures/denial_metadata.json").read_text())
    for case in fixtures:
        assert sanitize_denial_metadata(case["input"]) == case["expected"], case["name"]


def record(**changes):
    return ControlExecutionRecord(
        **{
            "plugin_id": "abc",
            "plugin_name": "GenericControl",
            "plugin_kind": "test.Control",
            "hook_name": "prompt_pre_fetch",
            "mode": PluginMode.SEQUENTIAL,
            "status": ControlExecutionStatus.COMPLETED,
            "effective_allow": False,
            "requested_allow": False,
            "matched": True,
            "applied": True,
            "duration_ns": 123,
            "reason": "sensitive request text",
            "error_code": "DENIED",
            "config_keys": ["credential"],
            **changes,
        }
    )


@pytest.mark.parametrize("metadata", [None, {}, {"backend": "postgres"}, {"backend": "valkey"}])
def test_empty_or_string_metadata(metadata):
    assert sanitize_denial_metadata(metadata) == {}


def test_generic_metrics_preserve_primitives_and_numeric_endpoints():
    metrics = {
        "rejected_count": 0,
        "policy.matched": False,
        "minimum": -(2**63),
        "maximum": 2**63 - 1,
        "score": 0.75,
        "zero_float": 0.0,
    }
    result = sanitize_denial_metadata(metrics)
    assert result == metrics
    assert result is not metrics
    assert {key: type(value) for key, value in result.items()} == {key: type(value) for key, value in metrics.items()}


@pytest.mark.parametrize(
    "value",
    ["token", {"nested": 1}, [1], None, object(), float("nan"), float("inf"), float("-inf"), -(2**63) - 1, 2**63],
)
def test_invalid_metric_values_are_dropped(value):
    assert sanitize_denial_metadata({"invalid": value, "retained": False}) == {"retained": False}


@pytest.mark.parametrize("key", ["", "a" * 65, "email@domain", "white space", "é", "newline\n", 123])
def test_invalid_metric_keys_are_dropped(key):
    assert sanitize_denial_metadata({key: 1, "retained": 0}) == {"retained": 0}


def test_map_and_key_bounds():
    metrics = {f"metric_{index}": index for index in range(16)}
    assert sanitize_denial_metadata(metrics) == metrics
    metrics["invalid"] = "discarded"
    assert sanitize_denial_metadata(metrics) == {}
    assert sanitize_denial_metadata({"a" * 64: 1, "A-z_0.9": True}) == {"a" * 64: 1, "A-z_0.9": True}


def test_snapshot_field_parity_and_explicit_projection():
    expected = set(ControlExecutionRecord.model_fields) - {"reason", "config_keys"}
    assert {field.name for field in fields(DenialExecutionRecord)} == expected
    execution = record()
    snapshot = DenialExecutionRecord.from_execution(execution)
    for name in expected:
        assert getattr(snapshot, name) == getattr(execution, name)


@pytest.mark.parametrize("code", ["free form", "a" * 65, "email@domain", "", "é"])
def test_invalid_codes_are_omitted(code):
    outcome = DenialOutcome.from_execution(
        record(error_code=code), PluginViolation(reason="r", description="d", code=code), {}
    )
    assert outcome.execution.error_code is None
    assert outcome.violation_code is None


@pytest.mark.parametrize(
    "http,mcp,expected_http,expected_mcp",
    [
        (100, -(2**31), 100, -(2**31)),
        (599, 2**31 - 1, 599, 2**31 - 1),
        (99, -(2**31) - 1, None, None),
        (600, 2**31, None, None),
        (True, False, None, None),
        ("429", "-32029", None, None),
        (429.0, -32029.0, None, None),
    ],
)
def test_protocol_status_validation(http, mcp, expected_http, expected_mcp):
    violation = PluginViolation.model_construct(
        reason="r", description="d", code="A" * 64, http_status_code=http, mcp_error_code=mcp
    )
    outcome = DenialOutcome.from_execution(record(), violation, {})
    assert outcome.violation_code == "A" * 64
    assert outcome.http_status_code == expected_http
    assert outcome.mcp_error_code == expected_mcp


def test_snapshot_is_frozen_and_isolated_from_sources():
    metrics = {"rejects": 2}
    violation = PluginViolation(reason="sensitive", description="secret", code="DENIED", http_status_code=429)
    error = PluginViolationError._from_framework_denial("blocked", violation, metrics)
    metrics["rejects"] = 900
    execution = record()
    error.attach_denial_outcome(execution)
    outcome = error.denial_outcome
    assert outcome is not None
    execution.plugin_name = "changed"
    execution.duration_ns = 900
    violation.code = "changed"
    violation.http_status_code = 500
    assert outcome.execution.plugin_name == "GenericControl"
    assert outcome.execution.duration_ns == 123
    assert outcome.violation_code == "DENIED"
    assert outcome.http_status_code == 429
    assert dict(outcome.metadata) == {"rejects": 2}
    with pytest.raises(FrozenInstanceError):
        outcome.http_status_code = 500
    with pytest.raises(FrozenInstanceError):
        outcome.execution.plugin_name = "forged"
    with pytest.raises(TypeError):
        outcome.metadata["rejects"] = 999


def test_public_exception_constructor_remains_compatible():
    assert list(inspect.signature(PluginViolationError).parameters) == ["message", "violation"]
    error = PluginViolationError("blocked")
    assert (str(error), error.message, error.violation, error.executions, error.denial_outcome) == (
        "blocked",
        "blocked",
        None,
        None,
        None,
    )


@pytest_asyncio.fixture
async def manager():
    instance = PluginManager("./tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await instance.initialize()
    try:
        yield instance
    finally:
        await instance.shutdown()
        PluginManager.reset()


def control(plugin_type, mode, name="GenericControl"):
    return HookRef(
        PromptHookType.PROMPT_PRE_FETCH,
        PluginRef(
            plugin_type(
                PluginConfig(
                    name=name,
                    description="test",
                    author="test",
                    version="1.0",
                    tags=[],
                    kind="test.Control",
                    hooks=["prompt_pre_fetch"],
                    mode=mode,
                    on_error=OnError.FAIL,
                    config={},
                )
            )
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [PluginMode.SEQUENTIAL, PluginMode.CONCURRENT])
@pytest.mark.parametrize("with_violation", [True, False])
@pytest.mark.parametrize(
    "metrics",
    [
        None,
        {},
        {"score": 0.5, "rejects": 0, "effective_allow": True},
        {"backend": "postgres", "nested": {"token": "secret"}},
    ],
)
async def test_explicit_denial_always_has_trusted_outcome(manager, mode, with_violation, metrics):
    class GenericControl(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            return PluginResult(
                continue_processing=False,
                violation=PluginViolation(reason="sensitive", description="secret", code="DENIED")
                if with_violation
                else None,
                metadata={"ordinary": 42, "plugin_name": "forged"},
                denial_metadata=metrics,
            )

    ref = control(GenericControl, mode)
    with patch.object(manager._registry, "get_hook_refs_for_hook", return_value=[ref]):
        with pytest.raises(PluginViolationError) as raised:
            await manager.invoke_hook(
                PromptHookType.PROMPT_PRE_FETCH,
                PromptPrehookPayload(prompt_id="p", args={}),
                global_context=GlobalContext(request_id="r"),
                violations_as_exceptions=True,
            )
    outcome = raised.value.denial_outcome
    assert outcome is not None
    assert outcome.execution.plugin_id == ref.plugin_ref.uuid
    assert outcome.execution.plugin_name == "GenericControl"
    assert outcome.execution.mode == mode
    assert outcome.execution.effective_allow is False
    assert outcome.execution.hook_name == "prompt_pre_fetch"
    assert dict(outcome.metadata) == sanitize_denial_metadata(metrics)
    assert "ordinary" not in outcome.metadata
    assert outcome.violation_code == ("DENIED" if with_violation else None)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [PluginMode.SEQUENTIAL, PluginMode.CONCURRENT])
async def test_direct_plugin_exception_receives_no_outcome(manager, mode):
    class DirectControl(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            raise PluginViolationError("directly raised")

    with patch.object(manager._registry, "get_hook_refs_for_hook", return_value=[control(DirectControl, mode)]):
        with pytest.raises(PluginViolationError) as raised:
            await manager.invoke_hook(
                PromptHookType.PROMPT_PRE_FETCH,
                PromptPrehookPayload(prompt_id="p", args={}),
                global_context=GlobalContext(request_id="r"),
                violations_as_exceptions=True,
            )
    assert raised.value.denial_outcome is None


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [PluginMode.AUDIT, PluginMode.TRANSFORM, PluginMode.FIRE_AND_FORGET])
async def test_nonblocking_modes_keep_their_semantics(manager, mode):
    class ObservingControl(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            return PluginResult(continue_processing=False, denial_metadata={"rejects": 2})

    with patch.object(manager._registry, "get_hook_refs_for_hook", return_value=[control(ObservingControl, mode)]):
        result, _ = await manager.invoke_hook(
            PromptHookType.PROMPT_PRE_FETCH,
            PromptPrehookPayload(prompt_id="p", args={}),
            global_context=GlobalContext(request_id="r"),
            violations_as_exceptions=True,
        )
        await result.wait_for_background_tasks()
    assert result.continue_processing is True


@pytest.mark.asyncio
async def test_infrastructure_failure_keeps_existing_error_behavior(manager):
    class BrokenControl(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            raise RuntimeError("failed")

    with patch.object(
        manager._registry, "get_hook_refs_for_hook", return_value=[control(BrokenControl, PluginMode.SEQUENTIAL)]
    ):
        with pytest.raises(PluginError):
            await manager.invoke_hook(
                PromptHookType.PROMPT_PRE_FETCH,
                PromptPrehookPayload(prompt_id="p", args={}),
                global_context=GlobalContext(request_id="r"),
                violations_as_exceptions=True,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,metrics",
    [
        ("SQLSanitizer", {"rejected_clauses": 2}),
        ("ContentGuard", {"match_score": 0.75}),
        ("QuotaControl", {"remaining": 0, "throttled": True}),
    ],
)
async def test_generic_metrics_survive_single_plugin_result_for_external_hosts(manager, name, metrics):
    class MetricControl(Plugin):
        async def prompt_pre_fetch(self, payload, context):
            return PluginResult(continue_processing=False, denial_metadata=metrics)

    ref = control(MetricControl, PluginMode.SEQUENTIAL, name=name)
    result = await manager._get_executor().execute_plugin(
        ref,
        PromptPrehookPayload(prompt_id="p", args={}),
        PluginContext(global_context=GlobalContext(request_id="r")),
        False,
    )
    assert result.continue_processing is False
    assert result.denial_metadata == metrics
