---
title: "CPEX"
type: docs
weight: 0
---

# CPEX

**A policy and authorization framework for agentic applications.**

CPEX is a deterministic reference monitor between an untrusted agent and the capabilities it invokes. AI agents can be steered by injected content, confused by tool output, or simply make mistakes. CPEX mediates every operation an agent triggers (tool calls, A2A methods, inference calls, prompt and resource fetches) against state the agent cannot see or forge: identity, delegation chains, taint labels, and an append-only audit log.

You write policy in APL (Authorization Policy Language): a declarative, attribute-based rules with explicit effects. CPEX evaluates that policy at the boundary and enforces the result, allowing, denying, redacting, delegating, or tainting before the operation proceeds.

![CPEX mediates every operation an untrusted LLM triggers, evaluating APL policy against identity, delegation, taint, and audit state the model cannot forge](/cpex/images/cpex_overview.png)

The plugin pipeline underneath (hooks, the plugin manager, execution modes) is the mechanism that runs policy effects. It is the supporting layer, not the headline. APL is how you express intent; the pipeline is how that intent executes.

---

{{% columns %}}
- ### Get started

  Stand up CPEX as an enforcement point and run your first policy.

  [Quick Start &rarr;]({{< relref "/docs/quickstart" >}})

- ### Write policy

  Learn APL: predicates, effects, sequencing, PDPs, delegation, and tainting.

  [APL &rarr;]({{< relref "/docs/apl" >}})

- ### Why CPEX

  The reference-monitor model and where CPEX sits in an agent stack.

  [Vision &rarr;]({{< relref "/docs/vision" >}})

{{% /columns %}}
