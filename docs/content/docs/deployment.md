---
title: "Deployment"
weight: 140
---

# Deployment

CPEX is the enforcement point, but where that point sits is your choice. The same APL policy enforces whether CPEX runs as a gateway in front of a tool server, as an egress sidecar beside an agent, or inside an agent framework. You move the boundary; the policy does not change.

## The same policy, two placements

Take the `get_compensation` route. It is identical whether CPEX fronts the backend or guards the agent's egress:

```yaml
routes:
  - tool: get_compensation
    policy:
      - "require(role.hr)"
      - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
      - "taint(secret, session)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

```mermaid
flowchart TB
  subgraph gw["gateway (inbound)"]
    direction LR
    A1["agent"] --> C1["CPEX gateway"] --> T1["hr tool server"]
  end
  subgraph sc["egress sidecar (outbound)"]
    direction LR
    A2["agent + sidecar"] --> C2["CPEX sidecar"] --> T2["hr tool server"]
  end
```

As a **gateway**, CPEX sits in front of the tool server and enforces on inbound calls: every request to the backend passes through it. As an **egress sidecar**, CPEX sits beside the agent and enforces on the agent's outbound calls: the agent's tool invocations leave through the sidecar's proxy. The enforcement point moved from the backend's door to the agent's. The route above runs unchanged in both.

## Route forms

A deployment integration usually expresses routes as a list of `- tool:` entries, with the `policy`, `args`, and `result` blocks directly under each. This is the same policy you would write in the map-keyed form (see [Configuration]({{< relref "/docs/configuration" >}})); the wrapping differs, the rules do not. Pick one form per deployment and keep it consistent.

## Placement guidance

| Placement | Controls | Use when |
|-----------|----------|----------|
| Gateway (inbound) | every call reaching a backend, from any client | you own the tool server and want one chokepoint in front of it |
| Egress sidecar (outbound) | every call an agent makes, to any backend | you own the agent and want to guard what it can reach |
| In-framework | operations as the agent runtime issues them | you control the runtime and want enforcement inline |

The decision is about which boundary you control and trust, not about policy capability. Identity resolution, PDP calls, delegation, redaction, and tainting all work the same at each.

## Inference traffic

When CPEX guards an agent's egress, route inference calls directly to the model provider rather than through the policy path, unless you intend to apply policy to them. Otherwise model traffic is evaluated as if it were a tool call. Reserve the enforced path for the operations you actually want mediated.

## What to read next

- [Configuration]({{< relref "/docs/configuration" >}}): the full config structure for a deployment.
- [Patterns]({{< relref "/docs/patterns" >}}): production patterns for rollout and layered enforcement.
- [Identity]({{< relref "/docs/identity" >}}) and [Delegation]({{< relref "/docs/delegation" >}}): wiring IdP verification and token exchange in a real stack.
