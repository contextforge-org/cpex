---
title: "Plugins & Pipeline"
weight: 60
---

# Plugins and the Execution Pipeline

APL is the policy surface. The pipeline is what runs underneath it: the mechanism that executes a policy's effects. Most of the time you write APL and never touch the pipeline directly. You reach for it when you extend the set of effects available to policy, by adding a plugin, or when you need to understand exactly how and when effects run.

## Hooks

A **hook** is a named interception point. The host invokes a hook at an operation boundary (before a tool call, after an LLM completion, around a prompt or resource fetch), and the plugin manager runs the plugins registered there. Hooks are where APL routes attach: a route's `policy` phase runs at the pre-invocation hook, its `result` phase at the post-invocation hook.

When an effect says `plugin(pii-scan)` or `delegate(workday-oauth)`, it is naming a plugin registered on the relevant hook. The effect is the policy-level intent; the plugin is the code that runs.

## The plugin manager

The `PluginManager` owns registration, ordering, capability filtering, timeouts, and error isolation. A plugin can:

- **allow** the operation to continue,
- **block** it with a violation (surfaced as a deny), or
- **modify** the payload, using copy-on-write isolation so one plugin's changes are visible to the next without mutating shared state.

This is the substrate APL effects compile down to. A `deny` is a block; a `redact` is a modify; a `plugin(...)` call is a dispatch.

## Execution modes

A plugin runs in a **mode** that fixes whether it can block, whether it can modify, and how it runs relative to others. Modes run in a fixed phase order:

```
sequential -> transform -> audit -> concurrent -> fire_and_forget
```

| Mode | Execution | Can block? | Can modify? | Use |
|------|-----------|:----------:|:-----------:|-----|
| `sequential` | serial, chained | yes | yes | policy enforcement + transformation |
| `transform` | serial, chained | no | yes | redaction, rewriting |
| `audit` | serial | no | no | logging, metrics |
| `concurrent` | parallel, fail-fast | yes | no | independent gates |
| `fire_and_forget` | background, after all phases | no | no | telemetry, async audit |
| `disabled` | not loaded | — | — | plugin off |

Error handling is set separately with `on_error` (`fail`, `ignore`, or `disable`), independent of mode. A `sequential` policy plugin with `on_error: fail` denies the operation if it errors; an `audit` plugin with `on_error: ignore` never blocks the request even if logging fails.

## When to write a plugin

Write a plugin when policy needs an effect the builtins do not provide: a custom validator, a bespoke PDP resolver, an integration with an internal service. Depend on the lean [`cpex-sdk`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-sdk) crate for the `Plugin` and `HookHandler` traits rather than the full runtime. Declare the plugin's capabilities so it receives only the context it needs (see [Extensions & Capability-Gating]({{< relref "/docs/extensions" >}})), register it on a hook, and reference it from APL by its `kind` or name.

The bundled plugins (identity, delegation, PII, audit, PDPs) are catalogued in [Builtins]({{< relref "/docs/builtins" >}}); their wiring is in [Configuration]({{< relref "/docs/configuration" >}}).
