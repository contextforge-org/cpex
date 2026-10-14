---
title: "Testing your policy"
weight: 11
---

# Module 10: Testing your policy

> You are in the [CPEX tutorial]({{< relref "_index" >}}). Runs without the IdP.

**Goal:** test policy the way you test code. Load a policy, drive routes with a fake backend, and assert the outcome, so a policy change that breaks a rule fails CI.

## The problem

Policy decides who sees what. A careless edit can silently open a route or over-redact a field. You want the allow and deny matrix pinned by tests that run on every change, without standing up an IdP or a real backend for the cases that do not need one.

## Build it

A test loads a policy into an engine and calls routes through `mediate()` with a fake backend, then asserts. Table-driven cases keep the matrix readable. From [`tests/policy_tests.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/tests/policy_tests.rs):

```rust
/// Load a policy string into a ready-to-use engine.
async fn engine_with(policy: &str) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    cpex::install_builtins(&engine);
    cpex_tutorial::install_http_transport(&engine);
    cpex_tutorial::audit::register(&engine);
    engine.load_config_yaml(policy).expect("policy should load");
    engine.initialize().await.expect("initialize");
    engine
}
```

The setup is the same as a module binary: builtins, the tutorial HTTP transport, and the tutorial's `tutorial/audit-line` plugin that `m04.yaml` declares. Each case is one row:

```rust
#[tokio::test]
async fn module4_external_email_denied_with_custom_code() {
    let engine = engine_with(M04).await;
    let cases = [
        Case {
            tool: "send_email",
            args: json!({ "to": "x@evil.example", "subject": "hi", "external": true }),
            want_allowed: false,
            want_code: Some("email.external_blocked"),
        },
        Case {
            tool: "send_email",
            args: json!({ "to": "x@corp.example", "subject": "hi", "external": false }),
            want_allowed: false, // anonymous, so require(authenticated) halts it
            want_code: None,
        },
    ];
    for c in &cases {
        run_case(&engine, c).await;
    }
}
```

A third test, `every_module_policy_loads`, loads every module's policy without calling `initialize()`. Loading is where the engine checks a policy's shape: unknown keys, plugins no step reaches, steps naming undeclared plugins, and capabilities a plugin needs but does not declare. Skipping `initialize()` keeps it offline, since that is where identity plugins fetch their JWKS.

Anonymous callers exercise structural rules (authentication gates, argument guards, result pipelines) with no Keycloak. For identity-dependent rules, mint tokens the way the module binaries do.

## Run it

```bash
cargo test -p cpex-tutorial
```

```
running 3 tests
test module1_gates_by_authentication ... ok
test module4_external_email_denied_with_custom_code ... ok
test every_module_policy_loads ... ok
```

The example binary runs the same idea in the tutorial's output format:

```bash
cargo run -p cpex-tutorial --example m10_testing
```

```
▸ send_email {"to":"x@evil.example","external":true} → expect DENY
{"ts":1791421466,"plugin":"audit-log","entity":{"type":"tool","name":"send_email"},"tool_call":{"name":"send_email","arg_keys":["external","to"]}}
  ✗ DENIED   [email.external_blocked] outbound email to external recipients is blocked

▸ send_email {"to":"x@corp.example","external":false} → expect DENY
{"ts":1791421466,"plugin":"audit-log","entity":{"type":"tool","name":"send_email"},"tool_call":{"name":"send_email","arg_keys":["external","to"]}}
  ✗ DENIED   [routes.tool:send_email.pre_invocation[2]] access denied
```

The JSON lines are the audit plugin writing to stderr. They list argument keys, never values.

## Try it

1. Break a policy. Edit `examples/tutorial/policies/m04.yaml` to drop the external-recipient guard (the `deny(...)` line), then run `cargo test -p cpex-tutorial`. Expect: `module4_external_email_denied_with_custom_code` fails, catching the regression.
2. Add a case. In `examples/tutorial/tests/policy_tests.rs`, add a row to the `cases` array in `module1_gates_by_authentication`, for example:
   ```rust
   Case {
       tool: "search_repos",
       args: json!({ "visibility": "internal" }),
       want_allowed: true,
       want_code: None,
   },
   ```
   Run `cargo test -p cpex-tutorial`. Expect: it passes (`search_repos` is an unconditional `allow` in `m01.yaml`).
3. Wire it into CI. `make test` runs the whole workspace test suite, including these.

## Checkpoint

{{< details "Do these tests need Keycloak?" >}}
No. They use anonymous callers to exercise structural rules, so they run in plain CI. Identity-dependent tests would mint tokens, which needs the IdP.
{{< /details >}}

{{< details "What does a test actually assert on?" >}}
The `Outcome` from `mediate()`: allowed or denied, and for denials the reason code. That is the same value your host branches on in production.
{{< /details >}}

## Go deeper

- [Testing Policy]({{< relref "/docs/testing" >}}) and [Patterns: shadow rollout with audit mode]({{< relref "/docs/patterns" >}}).

## Next

[Module 11: Organizing policy]({{< relref "11-groups" >}}): factor the setup your routes share into reusable groups.
