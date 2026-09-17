---
title: "Write your own plugin"
weight: 10
---

# Module 9: Write your own plugin

> You are in the [CPEX tutorial]({{< relref "_index" >}}). Runs without the IdP.

**Goal:** write a plugin for a check the builtins do not ship, register it, and reference it from policy by name, exactly like a builtin.

## The problem

The bundled plugins cover common needs, but your domain has its own rules. You need a way to drop custom logic into the pipeline without forking CPEX, and to wire it from policy the same way you wire a builtin.

## Build it

A plugin is a Rust type implementing a hook handler. This one, a business-hours guard, reads the request's `hour` argument and its own open/close config, and denies calls outside the window. From [`examples/m09_custom_plugin.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/examples/m09_custom_plugin.rs):

```rust
impl HookHandler<CmfHook> for BusinessHours {
    async fn handle(&self, payload: &MessagePayload, _ext: &Extensions, _ctx: &mut PluginContext)
        -> PluginResult<MessagePayload>
    {
        let hour = payload.message.get_tool_calls().into_iter().next()
            .and_then(|tc| tc.arguments.get("hour")).and_then(|v| v.as_u64());
        match hour {
            Some(h) if h >= self.open_hour && h < self.close_hour => PluginResult::allow(),
            Some(h) => PluginResult::deny(PluginViolation::new("office.closed",
                format!("requested at hour {h}, outside {}-{}", self.open_hour, self.close_hour))),
            None => PluginResult::deny(PluginViolation::new("office.no_hour", "no `hour` argument")),
        }
    }
}
```

A factory builds it from config and wires the handler onto a hook. You register the factory before loading the policy, then reference the plugin by name. The traits come from `cpex-sdk`; the factory and handler-adapter plumbing come from `cpex-core`, the same pattern every builtin uses.

```rust
mgr.register_factory("business-hours", Box::new(BusinessHoursFactory));
cpex::install_builtins(&mgr);
mgr.load_config_yaml(POLICY).unwrap();
```

The policy references it like any builtin ([`policies/m09.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m09.yaml)):

```yaml
plugins:
  - name: business-hours
    kind: business-hours
    hooks: [cmf.tool_pre_invoke]
    config: { open_hour: 9, close_hour: 17 }
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "run(business-hours)"
```

## Run it

```bash
cargo run -p cpex-tutorial --example m09_custom_plugin
```

```
▸ get_compensation at 10:00 (within 9-17 window)
  ✓ ALLOWED  { ... }

▸ get_compensation at 22:00 (outside the window)
  ✗ DENIED   [office.closed] requested at hour 22, outside business hours 9-17
```

## Try it

1. Change the window. In `examples/tutorial/policies/m09.yaml`, set `close_hour: 23` and re-run. Expect: the 22:00 call now allows. Config feeds the plugin.
2. Change the denial. In `examples/tutorial/examples/m09_custom_plugin.rs`, edit the `PluginViolation::new("office.closed", ...)` call in the `Some(h)` arm, changing the code and reason strings, and re-run at hour 22. Expect: the denial line shows your new code and reason. (The tutorial's `Outcome` surfaces the code and reason; a plugin can also attach `description` and `details` on the violation, which a real host logs even though this harness does not print them.)
3. Gate a different tool. In `policies/m09.yaml`, add a second route so the same plugin guards it:
   ```yaml
   - tool: search_repos
     authorization:
       pre_invocation:
         - "run(business-hours)"
   ```
   Then add a call to it in `m09_custom_plugin.rs` (e.g. `mediate(&mgr, &caller, "search_repos", json!({ "visibility": "public", "hour": 22 }), backends::search_repos)`), re-run, and confirm `search_repos` is denied at hour 22 too. One plugin, many routes.

## Checkpoint

{{< details "How does policy find your plugin?" >}}
You register a factory under a `kind`, and the plugin block in policy names that `kind`. The APL visitor resolves it at load time, so `run(business-hours)` dispatches to your handler.
{{< /details >}}

{{< details "What decides allow vs. deny?" >}}
Your handler returns `PluginResult::allow()` or `PluginResult::deny(violation)`. The violation carries the code and reason the caller sees, just like a builtin.
{{< /details >}}

## Go deeper

- [Plugins & the Execution Pipeline]({{< relref "/docs/pipeline" >}}) and [Extensions & Capability-Gating]({{< relref "/docs/extensions" >}}).

## Next

[Module 10: Testing your policy]({{< relref "10-testing" >}}): write table-driven allow/deny tests that run in CI.
