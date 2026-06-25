---
title: "Extensions & Capability-Gating"
weight: 100
---

# Extensions and Capability-Gating

Alongside the message, every operation carries typed **extensions**: the contextual state policy reasons about. Identity is an extension. So are security labels, the delegation chain, request headers, agent session context, and more. Each extension is bridged into the flat attribute bag APL reads, under a well-known namespace. **Capability-gating** controls which plugins may read or write each one.

This is a supporting concern, not the headline. You rarely configure it directly. It matters because it is what makes least privilege real for the plugins that execute policy effects, and because the namespaces below are the exact keys an APL predicate or plugin can read.

## The extensions

Each extension flattens into bag attributes under its namespace, gated by a read capability. A prefix ending in `.` matches any key beneath it (`role.` matches `role.hr`); a bare name is an exact key.

| Extension | Carries | Bag namespace | Read capability |
|-----------|---------|---------------|-----------------|
| Security (subject) | subject id and type, roles, permissions, teams, claims, authentication status | `subject.id`, `subject.type`, `authenticated`, `role.*`, `perm.*`, `subject.teams`, `team.*`, `claim.*` | `read_subject`, `read_roles`, `read_permissions`, `read_teams`, `read_claims` |
| Security (client) | OAuth application identity: client id, trust level, roles, permissions, scopes, audiences, teams, claims | `client.*` | `read_client` |
| Security (workload) | attested workload identity (SPIFFE / mTLS) for this host and the inbound caller | `workload.*`, `caller_workload.*` | `read_workload` |
| Security (labels) | taint / classification labels for information-flow control | read directly from the extension (not materialized into bag keys) | `read_labels`, `append_labels` |
| Delegation | delegation depth, delegated flag, origin and actor subjects, chain age | `delegation.*`, `delegated` | `read_delegation`, `append_delegation` |
| Agent | session, conversation, turn, and lineage context | `agent.*` | `read_agent` |
| Meta | entity metadata: type, name, tags, scope, properties | `meta.*` | `read_meta` |
| Request | environment, request id, timestamp, trace and span ids | `request.*` | `read_request` |
| HTTP | request and response headers (lowercased) | `http.request_headers.*`, `http.response_headers.*` | `read_headers`, `write_headers` |
| LLM | model id, provider, capabilities | `llm.*` | `read_llm` |
| MCP | tool, resource, or prompt metadata | `mcp.*` (`mcp.tool.*`, `mcp.resource.*`, `mcp.prompt.*`) | `read_mcp` |
| Completion | stop reason, token counts, model, latency | `completion.*` | `read_completion` |
| Provenance | source, message id, parent id | `provenance.*` | `read_provenance` |
| Framework | agentic framework name and version, node and graph ids, metadata | `framework.*` | `read_framework` |
| Custom | free-form host-defined namespace | `custom.*` | `read_custom` |
| Raw credentials | inbound tokens and minted delegated tokens | flow through plugin payloads, not the bag | `read_inbound_credentials`, `read_delegated_tokens` |

The request arguments and response body are also flattened, under `args.*` and `result.*`, and the route name is available as `route.key`. APL field pipelines (`args:` / `result:`) operate on those.

## Capabilities

A plugin declares the capabilities it needs. CPEX filters the extensions before handing them to the plugin, so a plugin sees only what it declared. The default is no access; capabilities are additive grants.

```yaml
plugins:
  - name: audit-log
    kind: audit/logger
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
| `read_roles` | `role.*` (plus the `read_subject` baseline) |
| `read_permissions` | `perm.*` (plus baseline) |
| `read_teams` | `subject.teams` (plus baseline; `team.*` mirrors teams) |
| `read_claims` | `claim.*` (plus baseline) |
| `read_client` | `client.*` |
| `read_workload` | `workload.*`, `caller_workload.*` |
| `read_delegation` | `delegation.*`, `delegated` |
| `read_agent` | `agent.*` |
| `read_meta` | `meta.*` |
| `read_request` | `request.*` |
| `read_headers` | `http.request_headers.*`, `http.response_headers.*` |
| `read_llm` | `llm.*` |
| `read_mcp` | `mcp.*` |
| `read_completion` | `completion.*` |
| `read_provenance` | `provenance.*` |
| `read_framework` | `framework.*` |
| `read_custom` | `custom.*` |
| `read_labels` | no bag keys; the plugin reads labels from the security extension directly |
| `read_inbound_credentials` | no bag keys; gates raw inbound tokens in the plugin payload |
| `read_delegated_tokens` | no bag keys; gates minted tokens in the plugin payload |

`read_roles`, `read_permissions`, `read_teams`, and `read_claims` each imply the `read_subject` baseline (`subject.id`, `subject.type`, `authenticated`). The last three capabilities gate state that is not materialized into bag keys: labels are read from the extension, and credential material flows through plugin payloads rather than the bag, so granting them does not widen what an APL predicate can read.

### Write capabilities

Three capabilities grant write tokens rather than read access:

| Capability | Grants |
|-----------|--------|
| `append_labels` | add a taint label (monotonic; cannot remove) |
| `append_delegation` | extend the delegation chain (monotonic) |
| `write_headers` | rewrite request and response headers (implies `read_headers`) |

## Mutability tiers

Extensions differ in how they may change during a request, and the runtime enforces the tier:

- **Immutable**: fixed once resolved. The verified subject identity, client, workload, agent, meta, request, LLM, MCP, completion, provenance, and framework extensions.
- **Monotonic**: may only grow. Security labels (added via `append_labels`, never removed) and the delegation chain (extended via `append_delegation`).
- **Mutable**: may be rewritten. HTTP headers (via `write_headers`) and the custom namespace.

So a plugin cannot clear a taint label or rewrite a verified identity even if it holds the corresponding read capability. This is what keeps the state APL depends on trustworthy: the model is untrusted, and so is any plugin beyond the context and mutations it was explicitly granted.

## How it connects to policy

Capability-gating runs at the boundary between the manager and each plugin (`filter_extensions` in cpex-core decides which extension slots a plugin sees; the CMF extractors then flatten those slots into the bag). The same filtered, tier-enforced view feeds the attribute bag APL evaluates, so a policy and the plugins it invokes operate on a consistent, least-privilege picture of the request. See [Identity]({{< relref "/docs/identity" >}}) for how the subject is populated and [Session Tainting]({{< relref "/docs/tainting" >}}) for the monotonic label tier in action.
