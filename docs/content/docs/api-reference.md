---
title: "API Reference"
weight: 140
---

# API Reference

All public symbols are importable from `cpex.framework`:

```python
from cpex.framework import Plugin, hook, PluginManager, PluginConfig, ...
```

---

## Core

| Symbol | Description |
|--------|-------------|
| `Plugin` | Base class for all plugins |
| `hook` | Decorator to bind a method to one or more hook types |
| `PluginManager` | Orchestrates plugin lifecycle and hook execution |
| `get_plugin_manager` | Get or initialize the singleton plugin manager |

## Configuration

| Symbol | Description |
|--------|-------------|
| `PluginConfig` | Plugin configuration model (frozen) |
| `PluginMode` | Execution mode enum: `SEQUENTIAL`, `TRANSFORM`, `AUDIT`, `CONCURRENT`, `FIRE_AND_FORGET`, `DISABLED` |
| `OnError` | Error handling enum: `FAIL`, `IGNORE`, `DISABLE` |
| `PluginCondition` | Conditions for when a plugin should execute |
| `ConfigLoader` | Loads plugin configuration from YAML files |
| `PluginLoader` | Discovers and instantiates plugin classes |

## Context

| Symbol | Description |
|--------|-------------|
| `GlobalContext` | Shared context across all plugins (request ID, user, tenant, server, state, metadata) |
| `PluginContext` | Per-plugin context that persists across hooks within a request lifecycle |
| `PluginContextTable` | Type alias: `dict[str, PluginContext]` |

## Results & Errors

| Symbol | Description |
|--------|-------------|
| `PluginPayload` | Base class for all hook payloads (frozen) |
| `PluginResult` | Generic result from plugin hook processing |
| `PluginViolation` | Policy violation with reason, description, code, and details |
| `PluginError` | Exception for errors internal to a plugin |
| `PluginViolationError` | Exception wrapping a `PluginViolation` |
| `PluginErrorModel` | Pydantic model for plugin error details |

## Tool Hooks

| Symbol | Description |
|--------|-------------|
| `ToolHookType` | Enum: `TOOL_PRE_INVOKE`, `TOOL_POST_INVOKE` |
| `ToolPreInvokePayload` | Payload for `tool_pre_invoke` (name, args) |
| `ToolPreInvokeResult` | Result type for `tool_pre_invoke` |
| `ToolPostInvokePayload` | Payload for `tool_post_invoke` (name, result) |
| `ToolPostInvokeResult` | Result type for `tool_post_invoke` |

## Prompt Hooks

| Symbol | Description |
|--------|-------------|
| `PromptHookType` | Enum: `PROMPT_PRE_FETCH`, `PROMPT_POST_FETCH` |
| `PromptPrehookPayload` | Payload for `prompt_pre_fetch` (prompt_id, args) |
| `PromptPrehookResult` | Result type for `prompt_pre_fetch` |
| `PromptPosthookPayload` | Payload for `prompt_post_fetch` (prompt_id, result) |
| `PromptPosthookResult` | Result type for `prompt_post_fetch` |

## Resource Hooks

| Symbol | Description |
|--------|-------------|
| `ResourceHookType` | Enum: `RESOURCE_PRE_FETCH`, `RESOURCE_POST_FETCH` |
| `ResourcePreFetchPayload` | Payload for `resource_pre_fetch` (uri, metadata) |
| `ResourcePreFetchResult` | Result type for `resource_pre_fetch` |
| `ResourcePostFetchPayload` | Payload for `resource_post_fetch` (uri, content) |
| `ResourcePostFetchResult` | Result type for `resource_post_fetch` |

## Agent Hooks

| Symbol | Description |
|--------|-------------|
| `AgentHookType` | Enum: `AGENT_PRE_INVOKE`, `AGENT_POST_INVOKE` |
| `AgentPreInvokePayload` | Payload for `agent_pre_invoke` (agent_id, messages, tools, model, system_prompt, parameters) |
| `AgentPreInvokeResult` | Result type for `agent_pre_invoke` |
| `AgentPostInvokePayload` | Payload for `agent_post_invoke` (agent_id, messages, tool_calls) |
| `AgentPostInvokeResult` | Result type for `agent_post_invoke` |

## HTTP Hooks

| Symbol | Description |
|--------|-------------|
| `HttpHookType` | Enum: `HTTP_PRE_REQUEST`, `HTTP_POST_REQUEST`, `HTTP_AUTH_RESOLVE_USER`, `HTTP_AUTH_CHECK_PERMISSION` |
| `HttpPreRequestPayload` | Payload for `http_pre_request` (path, method, client_host, client_port, headers) |
| `HttpPreRequestResult` | Result type for `http_pre_request` |
| `HttpPostRequestPayload` | Payload for `http_post_request` (extends pre-request with response_headers, status_code) |
| `HttpPostRequestResult` | Result type for `http_post_request` |
| `HttpAuthResolveUserPayload` | Payload for `http_auth_resolve_user` (credentials, headers) |
| `HttpAuthResolveUserResult` | Result type for `http_auth_resolve_user` |
| `HttpAuthCheckPermissionPayload` | Payload for `http_auth_check_permission` (user_email, permission, resource_type, ...) |
| `HttpAuthCheckPermissionResult` | Result type for `http_auth_check_permission` |
| `HttpAuthCheckPermissionResultPayload` | Result payload with granted/reason fields |
| `HttpHeaderPayload` | HTTP headers dict wrapper |

## Hook Registry

| Symbol | Description |
|--------|-------------|
| `HookRegistry` | Singleton registry mapping hook types to payload/result classes |
| `get_hook_registry` | Get the global `HookRegistry` instance |
| `HookPayloadPolicy` | Defines which payload fields plugins may modify |

## External Plugins

| Symbol | Description |
|--------|-------------|
| `ExternalPluginServer` | MCP-compatible server for hosting external plugins |
| `MCPClientConfig` | Client-side MCP transport configuration |
| `MCPServerConfig` | Server-side MCP configuration |
| `TransportType` | Enum: `SSE`, `HTTP`, `STDIO`, `STREAMABLEHTTP`, `GRPC` |

## Observability

| Symbol | Description |
|--------|-------------|
| `ObservabilityProvider` | Protocol for injecting tracing into the plugin pipeline |

## Utilities

| Symbol | Description |
|--------|-------------|
| `get_attr` | Safe nested attribute access utility |
