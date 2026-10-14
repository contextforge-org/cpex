---
title: "Effects & sequencing"
weight: 5
---

# Module 4: Effects & sequencing

> You are in the [CPEX tutorial]({{< relref "_index" >}}). Runs without the IdP.

**Goal:** compose several effects in an ordered pipeline that halts on the first denial, run a side-effecting plugin (audit), and emit your own machine-readable denial code.

## The problem

Real routes do more than one thing. They audit the attempt, apply a business rule, then check authorization, in a specific order, where a denial stops everything after it but not the side effects before it. You need to see and control that ordering.

## Build it

`pre_invocation` is an ordered list. From [`policies/m04.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m04.yaml):

```yaml
plugins:
  - name: audit-log
    kind: tutorial/audit-line
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_subject, read_meta]

routes:
  - tool: send_email
    authorization:
      pre_invocation:
        - "run(audit-log)"
        - "args.external == true: deny('outbound email to external recipients is blocked', 'email.external_blocked')"
        - "require(authenticated)"
```

CPEX ships no audit plugin of its own, because the record's format and destination are what each deployment replaces. The `audit-log` plugin here has `kind: tutorial/audit-line`, a small host plugin in [`src/audit.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/src/audit.rs). It writes one JSON line per call to stderr with the entity, the subject, the tool name, and the argument keys. It leaves argument values out on purpose, since they can carry PII or secrets. The host registers its factory before loading the policy. From [`examples/m04_effects.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/examples/m04_effects.rs):

```rust
let engine = Arc::new(PolicyEngine::default());
cpex::install_builtins(&engine);
cpex_tutorial::install_http_transport(&engine);
cpex_tutorial::audit::register(&engine);
engine
    .load_config_yaml(POLICY)
    .expect("policy m04.yaml should load");
engine.initialize().await.expect("initialize");
```

Policy reaches it by name with `run(audit-log)`, like any other plugin. Module 9 shows how to build one.

Three effects, top to bottom:

1. `run(audit-log)` records the attempt and always allows, so the pipeline continues. This is a side effect.
2. A guard, `<predicate>: deny('<reason>', '<code>')`. `deny(...)` produces a denial with a code you choose, so downstream systems can branch on it.
3. `require(authenticated)` is reached only if the guard passed. Halt-on-deny means a denial at step 2 skips step 3.

## Run it

```bash
cargo run -p cpex-tutorial --example m04_effects
```

```
▸ send_email to an external recipient (custom deny guard halts)
{"ts":1791421465,"plugin":"audit-log","entity":{"type":"tool","name":"send_email"},"tool_call":{"name":"send_email","arg_keys":["external","subject","to"]}}
  ✗ DENIED   [email.external_blocked] outbound email to external recipients is blocked

▸ send_email to an internal recipient (guard passes, auth check halts)
{"ts":1791421465,"plugin":"audit-log","entity":{"type":"tool","name":"send_email"},"tool_call":{"name":"send_email","arg_keys":["external","subject","to"]}}
  ✗ DENIED   [routes.tool:send_email.pre_invocation[2]] access denied
```

The caller is anonymous, so the audit line has no `subject`. The `ts` value is a Unix timestamp and differs on your run. The audit line (stderr) fires on both calls, because it runs before the denials. The external call halts at the custom guard with `email.external_blocked`. The internal call gets past the guard to `require(authenticated)` and halts there. Same route, different stopping point, because the order is policy.

## Try it

1. Reorder. Move `require(authenticated)` to the top and re-run. Expect: both calls deny with the authentication code, and the external-recipient guard never runs. Ordering changed the outcome and the reason.
2. Change the code. Edit the `deny(...)` code string to `email.blocked_v2`. Expect: the external call's reason code changes, nothing else does.
3. Drop audit. Remove the `run(audit-log)` line and re-run. Expect: same allow and deny outcomes, but no audit line on stderr. The side effect is gone.

## Checkpoint

{{< details "Why does the audit line appear even when the call is denied?" >}}
Because `run(audit-log)` sits before the denying effects. Halt-on-deny stops effects after a denial, not before it. Side effects that already ran still happened.
{{< /details >}}

{{< details "What decides the denial's reason code?" >}}
For a hand-written guard, the second argument to `deny('reason', 'code')`. For a `require(...)` that fails, CPEX derives a code from the rule's position. Custom codes let downstream systems branch on why something was denied.
{{< /details >}}

## Go deeper

- [Effects & Sequencing]({{< relref "/docs/apl/effects" >}}) for the full effect set, halt-on-deny, and `on_allow`/`on_deny` reactions.
- [Builtins]({{< relref "/docs/builtins" >}}) for the bundled plugins.
- [Module 9]({{< relref "09-custom-plugin" >}}) for how a host plugin like `tutorial/audit-line` is built.

## Next

[Module 5: Delegating decisions]({{< relref "05-pdp" >}}): hand a decision to CEL or Cedar and let CPEX enforce the verdict.
