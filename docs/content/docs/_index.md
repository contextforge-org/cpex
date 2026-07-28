---
title: "Documentation"
weight: 1
bookFlatSection: true
---

# CPEX Documentation

CPEX is a policy enforcement runtime for AI agents: a deterministic reference monitor that mediates every operation an untrusted LLM triggers. Each capability an agent can invoke defines its own enforcement pipeline (authorization, delegation, redaction, information-flow control, audit), configured in APL and run deterministically at the boundary.

Start with the [Vision]({{< relref "/docs/vision" >}}) for the reference-monitor model, the [Threat Model]({{< relref "/docs/threat-model" >}}) for what CPEX defends against at each placement, or the [Use Cases]({{< relref "/docs/use-cases" >}}) for the controls running end-to-end behind a real gateway. Then the [Quick Start]({{< relref "/docs/quickstart" >}}) stands up an enforcement point, and [APL]({{< relref "/docs/apl" >}}) is where you write policy. Prefer to learn by doing? The [Tutorial]({{< relref "/docs/tutorial" >}}) builds a working enforcement point one capability at a time, with runnable code you can edit and re-run.

Using the Python 0.1.x line? Its docs are preserved under [0.1.x (Legacy)]({{< relref "/docs/0.1.x" >}}).
