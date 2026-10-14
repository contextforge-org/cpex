---
title: "Extensions & Capability-Gating"
weight: 50
---

# Extensions and Capability-Gating

Alongside the message, every operation carries typed **extensions**: the contextual state policy reasons about. Identity is an extension. So are security labels, the delegation chain, request headers, agent session context, and more. Each extension is bridged into the flat attribute bag APL reads, under a well-known namespace. **Capability-gating** controls which plugins may read or write each one.

This is a supporting concern, not the headline. You rarely configure it directly. It matters because it is what makes least privilege real for the plugins that execute policy effects, and because the namespaces below are the exact keys an APL predicate or plugin can read.

## The extensions

Each extension flattens into bag attributes under its namespace, gated by a read capability. A prefix ending in `.` matches any key beneath it (`role.` matches `role.hr`); a bare name is an exact key.

| Extension | Carries | Bag namespace | Read capability |
|-----------|---------|---------------|-----------------|
| Security (subject) | subject id and type, roles, permissions, teams, claims, authentication status | `subject.id`, `subject.type`, `authenticated`, `subject.roles`, `subject.permissions`, `subject.teams`, `role.*`, `perm.*`, `team.*`, `claim.*` | `read_subject`, `read_roles`, `read_permissions`, `read_teams`, `read_claims` |
| Security (client) | OAuth application identity: client id, trust level, roles, permissions, scopes, audiences, teams, claims | `client.*` | `read_client` |
| Security (workload) | attested workload identity (SPIFFE / mTLS) for the inbound caller and for this instance | `caller_workload.*`, `this_workload.*` | `read_workload` |
| Security (labels) | taint / classification labels for information-flow control | `security.labels`, `security.classification` | `read_labels`, `append_labels` |
| Delegation | delegation depth, delegated flag, origin and actor subjects, chain age | `delegation.*`, `delegated` | `read_delegation`, `append_delegation` |
| Agent | session, conversation, turn, and lineage context | `agent.*` | `read_agent` |
| Meta | entity metadata: type, name, tags, scope, properties | `meta.*` | `read_meta` |
| Request | environment, request id, timestamp, trace and span ids | `request.*` | `read_request` |
| HTTP | request line (method, path, host, scheme) and request/response headers (lowercased) | `http.method`, `http.path`, `http.host`, `http.scheme`, `http.request_headers.*`, `http.response_headers.*` | `read_headers`, `write_headers` |
| LLM | model id, provider, capabilities | `llm.*` | `read_llm` |
| LLM request | the host-parsed inference request body | not flattened; OPA, CEL and Cedar read it as `llm.request` | `read_llm_request` |
| MCP | tool, resource, or prompt metadata | `mcp.*` (`mcp.tool.*`, `mcp.resource.*`, `mcp.prompt.*`) | `read_mcp` |
| Completion | stop reason, token counts, model, latency | `completion.*` | `read_completion` |
| Provenance | source, message id, parent id | `provenance.*` | `read_provenance` |
| Framework | agentic framework name and version, node and graph ids, metadata | `framework.*` | `read_framework` |
| Custom | free-form host-defined namespace | `custom.*` | `read_custom` |
| Raw credentials | inbound tokens and minted delegated tokens | flow through plugin payloads, not the bag | `read_inbound_credentials`, `read_delegated_tokens` |
| Candidate constraint | folded backend routing constraint from `restrict` effects | not a bag namespace; read by the host router | `write_candidate_constraint` |

The request arguments and response body are also flattened. An object writes `args.<dotted>` / `result.<dotted>`; a top-level scalar or scalar array writes the bare key `args` / `result`. The route name is available as `route.key`. APL field pipelines (`args:` / `result:`) operate on those. Operator-maintained static attributes are flattened under `data.*`. These come from config files, not the request, and need no capability (see [Static Attributes]({{< relref "/docs/apl/attributes" >}})).

Most extensions are **inputs**: resolved before policy runs and flattened into the bag for predicates to read. The **candidate constraint** is the exception: it is an **output**. APL `restrict` effects fold into it (see [Backend Restriction]({{< relref "/docs/apl/restrict" >}})), it rides the returned extensions the same way minted delegation tokens do, and the host router reads it typed to prune its candidate set.

## Capabilities

A plugin declares the capabilities it needs. CPEX filters the extensions before handing them to the plugin, so a plugin sees only what it declared. The default is no access; capabilities are additive grants.

```yaml
plugins:
  - name: audit-log
    kind: acme/audit
    hooks: [cmf.tool_pre_invoke]
    capabilities:
      - read_subject
      - read_client
      - read_delegation
```

### Read capabilities and the bag keys they unlock

| Capability | Unlocks |
|-----------|---------|
| `read_subject` | `subject.id`, `subject.type`, `authenticated` |
| `read_roles` | `subject.roles` and `role.*` aliases for undotted members (plus the `read_subject` baseline) |
| `read_permissions` | `subject.permissions` and `perm.*` aliases for undotted members (plus baseline) |
| `read_teams` | `subject.teams` and `team.*` aliases for undotted members (plus baseline) |
| `read_claims` | `claim.*` (plus baseline) |
| `read_client` | `client.*` |
| `read_workload` | `caller_workload.*`, `this_workload.*` |
| `read_delegation` | `delegation.*`, `delegated` |
| `read_agent` | `agent.*` |
| `read_meta` | `meta.*` |
| `read_request` | `request.*` |
| `read_headers` | `http.method`, `http.path`, `http.host`, `http.scheme`, `http.request_headers.*`, `http.response_headers.*` |
| `read_llm` | `llm.*` |
| `read_llm_request` | no bag keys; gates the parsed request body on the LLM request extension |
| `read_mcp` | `mcp.*` |
| `read_completion` | `completion.*` |
| `read_provenance` | `provenance.*` |
| `read_framework` | `framework.*` |
| `read_custom` | `custom.*` |
| `read_labels` | the labels on the security extension; a plugin reads them from the extension, while an APL predicate reads `security.labels` from the bag |
| `read_inbound_credentials` | no bag keys; gates raw inbound tokens in the plugin payload |
| `read_delegated_tokens` | no bag keys; gates minted tokens in the plugin payload |

`read_roles`, `read_permissions`, `read_teams`, and `read_claims` each imply the `read_subject` baseline (`subject.id`, `subject.type`, `authenticated`). The last three capabilities widen no plugin's bag view: labels are read from the typed extension, and credential material flows through plugin payloads rather than the bag.

Membership names containing `.` stay atomic in the canonical sets and get no flattened alias. Test a dotted role with `subject.roles contains "admin.readonly"`; there is no `role.admin.readonly` key. The same holds for permissions, teams, and client roles and permissions.

### Write capabilities

Four capabilities grant write tokens rather than read access:

| Capability | Grants |
|-----------|--------|
| `append_labels` | add a taint or classification label (monotonic; cannot remove) |
| `append_delegation` | extend the delegation chain (monotonic) |
| `write_headers` | rewrite request and response headers (implies `read_headers`) |
| `write_candidate_constraint` | narrow the backends the router may select |

### Gating an action: `perform_http`

Every capability above gates a slot of contextual state. `perform_http` gates an action: reaching outside the process at all. It is the one capability where withholding it stops the call rather than degrading it. A plugin denied `read_claims` sees fewer attributes and carries on; a plugin denied its IdP call and carrying on regardless would decide without the answer it needed, which fails open. The engine therefore refuses to start and names the plugin and the capability to add.

Every plugin that fetches JWKS, exchanges a token, dispatches a CIBA prompt, or queries an HTTP key directory must declare it. The host must also have installed an HTTP transport (see [Builtins]({{< relref "/docs/builtins#the-http-transport" >}})).

## Mutability tiers

Extensions differ in how they may change during a request, and the runtime enforces the tier:

- **Immutable**: fixed once resolved. The verified subject identity, client, workload, agent, meta, request, LLM, LLM request, MCP, completion, provenance, and framework extensions. The LLM request is never serialized, so it stays out of extension dumps and session stores.
- **Monotonic**: may only grow. Security labels (added via `append_labels`, never removed) and the delegation chain (extended via `append_delegation`).
- **Mutable**: may be rewritten. HTTP headers (via `write_headers`) and the custom namespace.

So a plugin cannot clear a taint label or rewrite a verified identity even if it holds the corresponding read capability. This is what keeps the state APL depends on trustworthy: the model is untrusted, and so is any plugin beyond the context and mutations it was explicitly granted.

## How it connects to policy

Capability-gating runs at the boundary between the engine and each plugin: the engine decides which extension slots a plugin sees, and the CMF extractors then flatten those slots into the bag. The same filtered, tier-enforced view feeds the attribute bag APL evaluates, so a policy and the plugins it invokes operate on a consistent, least-privilege picture of the request. See [Identity]({{< relref "/docs/apl/identity" >}}) for how the subject is populated and [Session Tainting]({{< relref "/docs/apl/tainting" >}}) for the monotonic label tier in action.
