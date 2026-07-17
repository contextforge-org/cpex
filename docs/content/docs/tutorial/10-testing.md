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

A test loads a policy into a manager and calls routes through `mediate()` with a fake backend, then asserts. Table-driven cases keep the matrix readable. From [`tests/policy_tests.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/tests/policy_tests.rs):

```rust
async fn manager_with(policy: &str) -> Arc<PluginManager> {
    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(policy).expect("policy should load");
    mgr.initialize().await.expect("initialize");
    mgr
}

#[tokio::test]
async fn module4_external_email_denied_with_custom_code() {
    let mgr = manager_with(M04).await;
    let outcome = mediate(&mgr, &Caller::anonymous(), "send_email",
        json!({ "to": "x@evil.example", "external": true }),
        |a| backends::dispatch("send_email", a)).await;
    assert!(matches!(outcome, Outcome::Denied { code, .. } if code == "email.external_blocked"));
}
```

Anonymous callers exercise structural rules (authentication gates, argument guards, result pipelines) with no Keycloak. For identity-dependent rules, mint tokens the way the module binaries do.

## Run it

```bash
cargo test -p cpex-tutorial
```

```
running 2 tests
test module1_gates_by_authentication ... ok
test module4_external_email_denied_with_custom_code ... ok
```

The example binary runs the same idea in the tutorial's output format:

```bash
cargo run -p cpex-tutorial --example m10_testing
```

## Try it

1. Break a policy. Edit `examples/tutorial/policies/m04.yaml` to drop the external-recipient guard (the `deny(...)` line), then run `cargo test -p cpex-tutorial`. Expect: `module4_external_email_denied_with_custom_code` fails, catching the regression.
2. Add a case. In `examples/tutorial/tests/policy_tests.rs`, add a row to the `cases` array in `module1_gates_by_authentication`, for example:
   ```rust
   Case { tool: "search_repos", args: json!({ "visibility": "internal" }), want_allowed: true, want_code: None },
   ```
   Run `cargo test -p cpex-tutorial`. Expect: it passes (`search_repos` is open in `m01.yaml`).
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

The capstone reassembles the full three-backend scenario. Modules 6, 8, and 9 (delegation, elicitation, custom plugins) round out the set.
