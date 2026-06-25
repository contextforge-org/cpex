---
title: "Extensions & Capability-Gating"
weight: 100
---

# Extensions and Capability-Gating

Alongside the message, every operation carries typed **extensions**: the contextual state policy reasons about. Identity is an extension. So are security labels, the delegation chain, and request headers. Capability-gating controls which plugins may read or write each one.

This is a supporting concern, not the headline. You rarely configure it directly. It matters because it is what makes least privilege real for the plugins that execute policy effects.

## What extensions carry

| Extension | Holds |
|-----------|-------|
| Security / identity | subject, roles, permissions, claims, client, workload identity |
| Security labels | taint labels for information-flow control |
| Delegation | delegation depth, chain, granted scopes |
| Request | method, headers, transport metadata |

APL reads these through the attribute bag (`subject.id`, `role.hr`, `security.labels`, `delegation.depth`). The extensions are the typed source; the bag is the flat view policy queries.

## Capabilities

A plugin declares the capabilities it needs. CPEX filters the extensions before handing them to the plugin, so a plugin sees only what it declared and nothing more:

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

Common capabilities and what they unlock:

| Capability | Grants read of |
|-----------|----------------|
| `read_subject` | `subject.id`, `subject.type`, `authenticated` |
| `read_roles` | `role.*` |
| `read_permissions` | `perm.*` |
| `read_labels` | security labels |
| `read_delegation` | `delegation.*`, `delegated` |
| `read_headers` | request headers |

A PII scanner that only needs to see content does not get the subject's identity. An audit logger that records who did what gets `read_subject` but cannot append taint labels. The default is no access; capabilities are additive grants.

## Mutability tiers

Extensions differ in how they may change during a request:

- **Immutable**: fixed once resolved (the verified subject identity).
- **Monotonic**: may only grow (taint labels are added, never removed).
- **Mutable**: may be rewritten (request headers a delegator updates).

The runtime enforces these tiers, so a plugin cannot clear a taint label or rewrite a verified identity even if it holds a read capability. This is what keeps the state APL depends on trustworthy: the model is untrusted, and so is any plugin beyond the context and mutations it was explicitly granted.

## How it connects to policy

Capability-gating runs at the boundary between the manager and each plugin. The same filtered, tier-enforced view feeds the attribute bag APL evaluates, so a policy and the plugins it invokes operate on a consistent, least-privilege picture of the request. See [Identity]({{< relref "/docs/identity" >}}) for how the subject is populated and [Session Tainting]({{< relref "/docs/tainting" >}}) for the monotonic label tier in action.
