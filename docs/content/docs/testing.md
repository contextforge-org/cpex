---
title: "Testing"
weight: 110
---

# Testing Policy

Policy is code, and it deserves tests. The behaviors worth covering are the ones the scenario demonstrates: a route allows the right callers, denies the wrong ones, redacts the right fields, and carries taint across a session. Because APL is declarative and evaluated by the runtime, you can test a route by loading a policy and driving operations through it, asserting the outcome, without standing up a live backend.

## What to test

For each route, cover the outcomes its policy produces:

- **Allow**: a caller with the required attributes passes and the operation forwards.
- **Deny**: a caller missing a required attribute is rejected, with the expected reason code.
- **Redaction**: a field is present for an entitled caller and redacted for an unentitled one (the "same request, different data" outcomes).
- **Information flow**: a session that acquired a taint label is blocked on a later operation that gates on it.
- **Delegation**: a passing caller mints a token with the requested scope, and a post-check denies when the granted scope is short.

## A table-driven policy test

Load a policy into a manager, drive routes through it with a fake backend, and assert the outcome. The tutorial ships this as a working template you can copy: [`examples/tutorial/tests/policy_tests.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/tests/policy_tests.rs). The setup is a small helper:

```rust
async fn manager_with(policy: &str) -> Arc<PluginManager> {
    let mgr = Arc::new(PluginManager::default());
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(policy).expect("policy should load");
    mgr.initialize().await.expect("initialize");
    mgr
}
```

Then a table keeps the allow/deny matrix readable, one row per case:

```rust
#[tokio::test]
async fn external_email_denied_with_custom_code() {
    let mgr = manager_with(POLICY).await;
    let outcome = mediate(
        &mgr,
        &Caller::anonymous(),
        "send_email",
        json!({ "to": "x@evil.example", "external": true }),
        |args| backends::dispatch("send_email", args),
    )
    .await;
    assert!(matches!(
        outcome,
        Outcome::Denied { code, .. } if code == "email.external_blocked"
    ));
}
```

`mediate()` here is the tutorial's harness wrapper around the host dispatch loop, not a CPEX API; in your own host you would drive the same route through your own loop and assert on the result. Anonymous callers are enough to exercise structural rules (authentication gates, argument guards, `result` pipelines) with no IdP. For identity-dependent rules, mint a token the way the tutorial's `idp` helper does.

A stateful taint test follows the same shape but shares one session id across two calls: read a sensitive route, then assert a later `send_email` on the same session is denied on the taint label. Tutorial [module 7]({{< relref "/docs/tutorial/07-tainting" >}}) is the worked example; [module 10]({{< relref "/docs/tutorial/10-testing" >}}) walks through the test file above.

## Scenario checks

Beyond unit tests, each tutorial module binary supports a `--check` flag that runs its scripted scenario and exits non-zero if the outcome drifts. `make tutorial-check` boots the tutorial IdP, runs every module's check, and tears it down. This is a lightweight way to pin end-to-end behavior (including the identity- and delegation-backed paths) in CI.

## Integration coverage

Unit-evaluating a route proves the policy logic. It does not prove the plugins it dispatches behave correctly end to end. For effects that call out (a PDP resolver, a delegator, a PII scanner), add an integration test that exercises the real plugin through the manager, so the interaction is covered and not just the policy's intent. Test the failure paths too: a PDP that denies, a token exchange that returns a short scope, a scanner that flags content. Those are the branches policy exists to handle.

## Running

```bash
cargo test -p cpex-tutorial     # the policy tests above
cargo test --workspace          # everything, including the runtime and APL suites
```

Copy [`examples/tutorial/tests/policy_tests.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/tests/policy_tests.rs) as the starting point for tests against your own policy.
