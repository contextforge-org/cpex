"""Opt-in denial metrics survive the existing result transport routes."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from cpex.framework import (
    GlobalContext,
    Plugin,
    PluginConfig,
    PluginContext,
    PluginResult,
    PromptPrehookPayload,
)
from cpex.framework.external.mcp.server.server import ExternalPluginServer

METRICS = {"minimum": -(2**63), "maximum": 2**63 - 1, "zero": 0, "matched": False, "score": 0.5}


def native_server(metrics):
    server = ExternalPluginServer("./tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    server._plugin_manager = AsyncMock()
    server._plugin_manager.invoke_hook_for_plugin.return_value = PluginResult(
        continue_processing=False, metadata={"ordinary": "unchanged"}, denial_metadata=metrics
    )
    return server


@pytest.mark.asyncio
@pytest.mark.parametrize("metrics", [None, {}, METRICS])
async def test_mcp_result_route(metrics):
    server = native_server(metrics)
    result = await server.invoke_hook(
        "prompt_pre_fetch",
        "GenericControl",
        {"prompt_id": "p", "args": {}},
        PluginContext(global_context=GlobalContext(request_id="r")).model_dump(),
    )
    plugin = Plugin(PluginConfig(name="GenericControl", kind="test.Control", hooks=["prompt_pre_fetch"]))
    parsed = plugin.json_to_result("prompt_pre_fetch", result["result"])
    assert parsed.denial_metadata == metrics
    assert parsed.metadata == {"ordinary": "unchanged"}


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["grpc", "unix"])
@pytest.mark.parametrize("metrics", [None, {}, METRICS])
async def test_protobuf_server_and_client_routes(transport, metrics, tmp_path):
    pytest.importorskip("grpc")
    from cpex.framework.external.grpc.client import GrpcExternalPlugin
    from cpex.framework.external.grpc.proto import plugin_service_pb2
    from cpex.framework.external.grpc.server.server import GrpcPluginServicer
    from cpex.framework.external.unix.client import UnixSocketExternalPlugin
    from cpex.framework.external.unix.server.server import UnixSocketPluginServer
    from cpex.framework.models import GRPCClientConfig, UnixSocketClientConfig

    server = native_server(metrics)
    context = PluginContext(global_context=GlobalContext(request_id="r"))
    payload = PromptPrehookPayload(prompt_id="p", args={})
    request = plugin_service_pb2.InvokeHookRequest(hook_type="prompt_pre_fetch", plugin_name="GenericControl")
    request.payload.update(payload.model_dump())
    request.context.global_context.request_id = "r"
    if transport == "grpc":
        response = await GrpcPluginServicer(server).InvokeHook(request, MagicMock())
        client = GrpcExternalPlugin(
            PluginConfig(
                name="GenericControl",
                kind="external",
                hooks=["prompt_pre_fetch"],
                grpc=GRPCClientConfig(target="localhost:1234"),
            )
        )
        client._stub = AsyncMock()
        client._stub.InvokeHook.return_value = plugin_service_pb2.InvokeHookResponse.FromString(
            response.SerializeToString()
        )
    else:
        unix_server = UnixSocketPluginServer(
            socket_path=str(tmp_path / "server.sock"),
            config_path="./tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml",
        )
        unix_server._plugin_server = server
        encoded = await unix_server._handle_invoke_hook(request)
        response = plugin_service_pb2.InvokeHookResponse.FromString(encoded)
        client = UnixSocketExternalPlugin(
            PluginConfig(
                name="GenericControl",
                kind="external",
                hooks=["prompt_pre_fetch"],
                unix_socket=UnixSocketClientConfig(path=str(tmp_path / "client.sock")),
            )
        )
        client._send_request = AsyncMock(return_value=response)
    result = await client.invoke_hook("prompt_pre_fetch", payload, context)
    assert result.continue_processing is False
    assert result.denial_metadata == metrics
    if metrics:
        assert {key: type(value) for key, value in result.denial_metadata.items()} == {
            key: type(value) for key, value in metrics.items()
        }
    assert result.metadata == {"ordinary": "unchanged"}


def test_untrusted_protobuf_metrics_are_revalidated():
    pytest.importorskip("grpc")
    from cpex.framework.external.grpc.proto import plugin_service_pb2
    from cpex.framework.external.proto_convert import denial_metadata_from_proto

    metadata = plugin_service_pb2.DenialMetadata()
    metadata.fields["good"].boolean = False
    metadata.fields["nonfinite"].floating = float("inf")
    metadata.fields["bad key"].integer = 1
    metadata.fields["unset"].SetInParent()
    assert denial_metadata_from_proto(metadata) == {"good": False}


def test_proto_base_helpers_preserve_opt_in_metrics():
    pytest.importorskip("grpc")
    from cpex.framework.external.proto_convert import (
        pydantic_result_to_proto_base,
        update_pydantic_result_from_proto_base,
    )

    encoded = pydantic_result_to_proto_base(PluginResult(denial_metadata=METRICS))
    decoded = PluginResult()
    update_pydantic_result_from_proto_base(decoded, encoded)
    assert decoded.denial_metadata == METRICS
