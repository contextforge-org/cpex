---
title: "Vision"
weight: 5
---

# A Reference Monitor for Agents

An agent backed by an LLM acts across trust domains. It calls tools, invokes other agents over A2A (agent-to-agent), runs inference, and fetches prompts and resources. The model deciding which operation to run is untrusted: it can be steered by injected content, confused by tool output, or simply wrong. Authorization, delegation, and information-flow control cannot live inside that model.

CPEX puts them at the boundary. It is a deterministic reference monitor between the untrusted LLM and the capabilities it invokes. Every operation passes through CPEX, which decides what happens using state the model cannot see or forge.

## The state the model cannot forge

A policy decision is only as trustworthy as the state it reads. CPEX evaluates each operation against state it owns, not state the LLM supplies:

- **Identity**: who the caller is, resolved from verified tokens (subject, roles, permissions, claims, workload identity).
- **Delegation chains**: which credentials were minted on whose behalf, and with what scope.
- **Taint labels**: what sensitive data this session has already touched.
- **Audit log**: an append-only record of every decision.

The LLM never sees these and cannot rewrite them. That is what makes CPEX a reference monitor rather than a suggestion.

## Policy is configuration

You do not write enforcement logic in application code. You write **APL** (Authorization Policy Language): the declarative configuration that defines each operation's enforcement pipeline, attaching its conditions and effects to the operation they govern.

```yaml
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
        - "taint(secret, session)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

This route requires the caller to be in the HR role, mints a scoped downstream token for the backend, marks the session as having touched secret data, and redacts the SSN on the wire unless the caller holds the `view_ssn` permission. The decision is the same for every caller; the outcome differs by identity.

## Three layers

Enforcement is three concerns, separated cleanly:

| Layer | Role |
|-------|------|
| **APL** | How you define policy: declarative configuration that sequences the controls in an operation's enforcement pipeline. |
| **CMF** (Common Message Format) | What you evaluate. A protocol-agnostic envelope carrying identity, labels, delegation, and content. |
| **Pipeline** (hooks, plugins, execution) | How effects run. The mechanism that executes a policy's effects at the boundary. |

APL leads. CMF gives policy a uniform thing to evaluate across tools, A2A, inference, prompts, and resources. The pipeline is the supporting execution layer: it is what lets a policy effect call a PDP, mint a token, scan for PII, or write an audit record. You reach for it when you extend the set of effects available to policy, not when you write policy.

## The policy spectrum

Different controls belong at different points. CPEX runs the same way at each of them, so you place a policy where its enforcement point is, not where the framework forces it.

![The policy spectrum: soft prompt-level controls (style, tone, refusals), enforcement-tier tool and A2A authorization (redaction, delegation), and hard infrastructure-boundary controls (identity, info-flow, audit), on an axis from advisory to enforced at the boundary](images/vision_policy_spectrum.png)

A style guardrail at the prompt level and a hard information-flow control at an infrastructure boundary are the same kind of object: an APL policy evaluated by a CPEX reference monitor. Only the placement changes.

## Where CPEX runs

CPEX is direction-agnostic. It enforces the same policy whether it sits in front of a tool server as a gateway, beside an agent as an egress sidecar, or inside an agent framework. See [Deployment]({{< relref "/docs/deployment" >}}) for the placements, the [Threat Model]({{< relref "/docs/threat-model" >}}) for what each placement covers against an untrusted model, and [Overview]({{< relref "/docs/overview" >}}) for the model in motion.
