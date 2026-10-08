---
title: "Plugins & Pipeline"
weight: 60
---

# Plugins and the Execution Pipeline

APL is the policy surface. The pipeline is what runs underneath it: the mechanism that executes a policy's effects. Most of the time you write APL and never touch the pipeline directly. You reach for it when you extend the set of effects available to policy, by adding a plugin, or when you need to understand exactly how and when effects run.

## Hooks

A **hook** is a named interception point. The host invokes a hook at an operation boundary (before a tool call, after an LLM completion, around a prompt or resource fetch), and the engine runs the plugins registered there. Hooks are where APL routes attach: a route's `authorization.pre_invocation` phase runs at the pre-invocation hook, its `result` phase at the post-invocation hook.

When an effect says `run(pii-scan)` or `delegate(workday-oauth)`, it is naming a plugin registered on the relevant hook. The effect is the policy-level intent; the plugin is the code that runs.

The hook names a plugin declares in `hooks:` come from a fixed table:

| Family | Hooks |
|---|---|
| CMF | `cmf.tool_pre_invoke`, `cmf.tool_post_invoke`, `cmf.llm_input`, `cmf.llm_output`, `cmf.prompt_pre_invoke`, `cmf.prompt_post_invoke`, `cmf.resource_pre_fetch`, `cmf.resource_post_fetch` |
| HTTP | `http.request`, `http.response` |
| Identity | `identity.resolve` |
| Delegation | `token.delegate` |
| Elicitation | `elicit` |

An unknown name in `hooks:` fails the load and names the nearest valid hook. The unprefixed names from 0.2.x (`tool_pre_invoke`, `identity_resolve`, `prompt_pre_fetch`, ...) are rejected; the [migration guide]({{< relref "/docs/migration-0.3#hook-names" >}}) lists the renames.

A Rust host may declare hooks of its own. The config loader refuses a hook name it has no metadata for, so register the metadata (`praxis_policy_core::hooks::register_hook_metadata`) before loading a config that names it.

## The policy engine

The `PolicyEngine` owns registration, ordering, capability filtering, timeouts, and error isolation. A plugin can:

- **allow** the operation to continue,
- **block** it with a violation (surfaced as a deny), or
- **modify** the payload, using copy-on-write isolation so one plugin's changes are visible to the next without mutating shared state.

This is the substrate APL effects compile down to. A `deny` is a block, a `redact` is a modify, and a `run(...)` step is a dispatch.

A plugin that panics in `sequential` or `transform` mode is contained and reported as a violation with the code `plugin_panic`. A panicking branch of a `parallel:` step is a deny.

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
| `disabled` | not loaded | n/a | n/a | plugin off |

Modes and their ordering apply under `dispatch: hooks`. Under the default `dispatch: policy`, a step names the one plugin to run, so nothing orders a hook's entries and a per-plugin `priority:` is a load error. Order the steps instead.

Error handling is set separately with `on_error` (`fail`, `ignore`, or `disable`), independent of mode. A `sequential` policy plugin with `on_error: fail` denies the operation if it errors; an `audit` plugin with `on_error: ignore` never blocks the request even if logging fails.

## When to write a plugin

Write a plugin when policy needs an effect the builtins do not provide: a custom validator, a bespoke PDP resolver, an integration with an internal service. There is no separate SDK crate. Implement `PluginFactory` against `cpex::prelude`, which carries the `Plugin`, `PluginFactory` and `HookHandler` traits, `TypedHandlerAdapter`, payloads, results and the CMF types. Declare the plugin's capabilities so it receives only the context it needs (see [Extensions & Capability-Gating]({{< relref "/docs/extensions" >}})), register it on a hook, and reference it from APL by name.

Registration names the `kind:` a policy will write, and takes the factory boxed:

```rust
engine.register_factory("validator/my-scan", Box::new(MyScanFactory));
```

An unrecognized `kind` fails the config load, so a factory you forgot to register is caught at startup rather than at the first request that needed it. [Tutorial module 9]({{< relref "/docs/tutorial/09-custom-plugin" >}}) builds one end to end.

Plugins are written in Rust. The Python bindings cannot register a plugin of their own; the Go package can, through a Rust FFI crate it links (see the [Go package README](https://github.com/contextforge-org/cpex/tree/main/go/cpex#writing-plugins-rust-for-go-callers)). Existing Python CPEX plugins run out of process through the [Python plugin host](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-hosts-python).

The bundled plugins and decision points are catalogued in [Builtins]({{< relref "/docs/builtins" >}}); their wiring is in [Configuration]({{< relref "/docs/configuration" >}}).
