---
title: "CPEX — ContextForge Plugin Extensibility Framework"
type: docs
---

# CPEX

**A composable enforcement framework for AI agents and toolchains**

CPEX lets you intercept, enforce, and extend application behavior through plugins — without modifying core logic. Define hook points in your application, write plugins that attach to them, and compose enforcement pipelines that run automatically.

```python
from cpex.framework import hook, Plugin, PluginResult, PluginViolation

class RateLimitPlugin(Plugin):
    @hook("tool_pre_invoke")
    async def check_rate_limit(self, payload, context):
        if self.is_over_limit(context):
            return PluginResult(
                continue_processing=False,
                violation=PluginViolation(reason="Rate limit exceeded", code="RATE_LIMIT")
            )
        return PluginResult(continue_processing=True)
```

Register the plugin, and it runs at every hook invocation. No changes to your application logic.

### What you can build with CPEX

- **Security** — access control, prompt injection detection, data loss prevention
- **Observability** — request tracing, audit logging, metrics collection
- **Governance** — policy enforcement, compliance validation, approval workflows
- **Reliability** — rate limiting, circuit breakers, response validation

---

{{% columns %}}

- ### Get Started
  Install CPEX and build your first plugin in five minutes.

  [Quick Start &rarr;]({{< relref "/docs/quickstart" >}})

- ### Learn the Concepts
  Understand hooks, execution modes, and the plugin pipeline.

  [Overview &rarr;]({{< relref "/docs/overview" >}})

- ### Project Vision
  Why hooks, plugins, and policy are the path to agent security.

  [Vision &rarr;]({{< relref "/docs/vision" >}})

{{% /columns %}}
