---
title: "CPEX"
type: docs
weight: 0
---

# CPEX

**A policy enforcement runtime for AI agents.**

CPEX is a deterministic reference monitor between an agent and every capability it invokes: tools, prompts, resources, inference providers, and A2A methods. Every operation is evaluated against security state the model cannot observe or influence, including identity, delegation and escalation chains, information-flow labels, and an audit log.

CPEX composes authorization, delegation, redaction, information-flow tracking, and auditing into a single policy-defined pipeline. Each capability an agent can invoke defines its own enforcement pipeline; APL is the configuration that defines it, executed in two phases: before the operation and after its result.

![CPEX mediates every operation an untrusted LLM triggers, evaluating APL policy against identity, delegation, taint, and audit state the model cannot forge](images/cpex_overview.png)

Existing authorization systems (RBAC, ABAC, Cedar, OPA, AuthZEN) answer whether a request should be allowed. CPEX answers a broader question: what security pipeline should execute for this agent operation. It invokes those engines for the decision and enforces the result.

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
