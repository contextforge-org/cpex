---
title: "Hook Types Reference"
weight: 40
---

# Hook Types Reference

CPEX ships with built-in hooks for common AI and application operations. Each hook defines a typed payload (the data your plugin receives) and a result type (what you return). You can also [register custom hooks]({{< relref "/docs/hooks#custom-hooks" >}}).

---

## Tool Hooks

Intercept tool/function calls before execution and inspect results after.

### `tool_pre_invoke`

Fires **before** a tool is executed.

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Tool name |
| `args` | `dict[str, Any]` | Tool arguments |

**Payload:** `ToolPreInvokePayload` | **Result:** `ToolPreInvokeResult`

Use cases: block dangerous tools, sanitize arguments, inject defaults, rate limiting.

### `tool_post_invoke`

Fires **after** a tool returns its result.

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Tool name |
| `result` | `Any` | Tool execution result |

**Payload:** `ToolPostInvokePayload` | **Result:** `ToolPostInvokeResult`

Use cases: redact PII from results, validate output format, log responses.

---

## Prompt Hooks

Intercept prompt template operations before fetching and after rendering.

### `prompt_pre_fetch`

Fires **before** a prompt template is fetched and rendered.

| Field | Type | Description |
|-------|------|-------------|
| `prompt_id` | `str` | Prompt template ID |
| `args` | `dict[str, str]` | Template arguments |

**Payload:** `PromptPrehookPayload` | **Result:** `PromptPrehookResult`

Use cases: validate prompt arguments, inject context, block prompts by ID.

### `prompt_post_fetch`

Fires **after** a prompt template is rendered.

| Field | Type | Description |
|-------|------|-------------|
| `prompt_id` | `str` | Prompt template ID |
| `result` | `Any` | Rendered prompt result (messages, description) |

**Payload:** `PromptPosthookPayload` | **Result:** `PromptPosthookResult`

Use cases: filter rendered content, log completions, modify output messages.

---

## Resource Hooks

Intercept resource access before fetching and after retrieval.

### `resource_pre_fetch`

Fires **before** a resource is fetched.

| Field | Type | Description |
|-------|------|-------------|
| `uri` | `str` | Resource URI |
| `metadata` | `dict[str, Any]` | Request metadata |

**Payload:** `ResourcePreFetchPayload` | **Result:** `ResourcePreFetchResult`

Use cases: validate URIs, enforce access control, log resource access.

### `resource_post_fetch`

Fires **after** a resource is retrieved.

| Field | Type | Description |
|-------|------|-------------|
| `uri` | `str` | Resource URI |
| `content` | `Any` | Fetched resource content |

**Payload:** `ResourcePostFetchPayload` | **Result:** `ResourcePostFetchResult`

Use cases: redact content, validate size limits, scan for sensitive data.

---

## Agent Hooks

Intercept agent invocations and inspect agent responses.

### `agent_pre_invoke`

Fires **before** an agent is invoked.

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | `str` | Agent identifier |
| `messages` | `list[Any]` | Conversation messages |
| `tools` | `list[str] \| None` | Available tools |
| `model` | `str \| None` | Model override |
| `system_prompt` | `str \| None` | System instructions |
| `parameters` | `dict[str, Any]` | LLM parameters (temperature, max_tokens, etc.) |

**Payload:** `AgentPreInvokePayload` | **Result:** `AgentPreInvokeResult`

Use cases: enforce model restrictions, filter messages, inject system instructions, limit available tools.

### `agent_post_invoke`

Fires **after** an agent responds.

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | `str` | Agent identifier |
| `messages` | `list[Any]` | Response messages |
| `tool_calls` | `list[dict] \| None` | Tool invocations made by agent |

**Payload:** `AgentPostInvokePayload` | **Result:** `AgentPostInvokeResult`

Use cases: audit agent outputs, content moderation, log tool call patterns.

---

## HTTP Hooks

Intercept HTTP request processing and implement custom authentication.

### `http_pre_request`

Fires **before** any request processing (middleware layer).

| Field | Type | Description |
|-------|------|-------------|
| `path` | `str` | HTTP path |
| `method` | `str` | HTTP method (GET, POST, etc.) |
| `client_host` | `str \| None` | Client IP address |
| `client_port` | `int \| None` | Client port |
| `headers` | `HttpHeaderPayload` | HTTP headers |

**Payload:** `HttpPreRequestPayload` | **Result:** `HttpPreRequestResult`

Use cases: request logging, rate limiting, IP filtering, header injection.

### `http_post_request`

Fires **after** request processing completes.

Extends `HttpPreRequestPayload` with:

| Field | Type | Description |
|-------|------|-------------|
| `response_headers` | `HttpHeaderPayload \| None` | Response headers |
| `status_code` | `int \| None` | HTTP status code |

**Payload:** `HttpPostRequestPayload` | **Result:** `HttpPostRequestResult`

Use cases: response logging, latency tracking, error rate monitoring.

### `http_auth_resolve_user`

Fires during user authentication (auth layer).

| Field | Type | Description |
|-------|------|-------------|
| `credentials` | `dict \| None` | HTTP authorization credentials |
| `headers` | `HttpHeaderPayload` | Full request headers |
| `client_host` | `str \| None` | Client IP |
| `client_port` | `int \| None` | Client port |

**Payload:** `HttpAuthResolveUserPayload` | **Result:** `HttpAuthResolveUserResult`

Use cases: custom auth (LDAP, mTLS, external IdP, API key validation).

### `http_auth_check_permission`

Fires during RBAC permission checks.

| Field | Type | Description |
|-------|------|-------------|
| `user_email` | `str` | Authenticated user email |
| `permission` | `str` | Required permission (e.g., `tools.read`) |
| `resource_type` | `str \| None` | Resource type being accessed |
| `team_id` | `str \| None` | Team context |
| `is_admin` | `bool` | Whether user has admin privileges |
| `auth_method` | `str \| None` | Authentication method used |
| `client_host` | `str \| None` | Client IP |
| `user_agent` | `str \| None` | User agent string |

**Payload:** `HttpAuthCheckPermissionPayload` | **Result:** `HttpAuthCheckPermissionResult`

Use cases: custom authorization, time-based access, IP-based restrictions.

---

## Identity Hooks

Handle token-based identity resolution and credential delegation for downstream services.

### `identity_resolve`

Fires on inbound requests to decode, verify, and map a token to a subject identity.

| Field | Type | Description |
|-------|------|-------------|
| `raw_token` | `SecretStr` | Raw credential (JWT, API key, etc.) — redacted on serialization |
| `source` | `str` | How the credential was extracted (`bearer`, `mtls`, `api_key`) |
| `headers` | `dict[str, str]` | Full HTTP headers |
| `client_host` | `str \| None` | Client IP |
| `client_port` | `int \| None` | Client port |

**Payload:** `IdentityPayload` | **Result:** `IdentityResolveResult`

The result carries an `IdentityResult` as `modified_payload`, containing the resolved `SubjectExtension` or a rejection.

### `token_delegate`

Fires on outbound calls to exchange or mint a token for a downstream target.

| Field | Type | Description |
|-------|------|-------------|
| `target_name` | `str` | Tool, agent, or resource being called |
| `target_type` | `str` | Entity type (`tool`, `agent`, `resource`, `service`) |
| `target_audience` | `str \| None` | Audience URI for the target |
| `required_permissions` | `list[str]` | Permissions needed by the target |
| `trust_domain` | `str \| None` | Trust domain |
| `auth_enforced_by` | `str` | Who enforces auth (`caller`, `target`, `both`) |
| `bearer_token` | `SecretStr \| None` | Caller's current bearer token |

**Payload:** `DelegationPayload` | **Result:** `TokenDelegateResult`

The result carries a `DelegationResult` as `modified_payload`, containing the delegated token and updated delegation chain.

---

## CMF Message Hooks

Unified hooks that use the [Common Message Format]({{< relref "/docs/cmf" >}}) for cross-cutting policy evaluation. These parallel the typed hooks above but accept a single `MessagePayload` wrapping a CMF `Message`.

| Hook | Fires at |
|------|----------|
| `cmf.tool_pre_invoke` | Before tool execution |
| `cmf.tool_post_invoke` | After tool execution |
| `cmf.llm_input` | Before model/LLM call |
| `cmf.llm_output` | After model/LLM call |
| `cmf.prompt_pre_fetch` | Before prompt fetch |
| `cmf.prompt_post_fetch` | After prompt fetch |
| `cmf.resource_pre_fetch` | Before resource fetch |
| `cmf.resource_post_fetch` | After resource fetch |

**Payload:** `MessagePayload(message: Message, hook: MessageHookType)` | **Result:** `MessageResult`

CMF hooks let you write a single plugin that evaluates content at every interception point using one unified interface. See [Common Message Format]({{< relref "/docs/cmf" >}}) for details.

---

## Summary Table

| Hook | Payload | Category |
|------|---------|----------|
| `tool_pre_invoke` | `ToolPreInvokePayload` | Tool |
| `tool_post_invoke` | `ToolPostInvokePayload` | Tool |
| `prompt_pre_fetch` | `PromptPrehookPayload` | Prompt |
| `prompt_post_fetch` | `PromptPosthookPayload` | Prompt |
| `resource_pre_fetch` | `ResourcePreFetchPayload` | Resource |
| `resource_post_fetch` | `ResourcePostFetchPayload` | Resource |
| `agent_pre_invoke` | `AgentPreInvokePayload` | Agent |
| `agent_post_invoke` | `AgentPostInvokePayload` | Agent |
| `http_pre_request` | `HttpPreRequestPayload` | HTTP |
| `http_post_request` | `HttpPostRequestPayload` | HTTP |
| `http_auth_resolve_user` | `HttpAuthResolveUserPayload` | HTTP |
| `http_auth_check_permission` | `HttpAuthCheckPermissionPayload` | HTTP |
| `identity_resolve` | `IdentityPayload` | Identity |
| `token_delegate` | `DelegationPayload` | Identity |
| `cmf.*` | `MessagePayload` | CMF |

All types are importable from `cpex.framework`.
