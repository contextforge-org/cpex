---
title: "Testing"
weight: 160
---

# Testing Policy

Policy is code, and it deserves tests. The behaviors worth covering are the ones the scenario demonstrates: a route allows the right callers, denies the wrong ones, and redacts the right fields. Because APL is declarative and evaluated by `apl-core`, you can test a route by evaluating it against fixture identities and asserting the outcome, without standing up a live backend.

## What to test

For each route, cover the outcomes its policy produces:

- **Allow**: a caller with the required attributes passes and the operation forwards.
- **Deny**: a caller missing a required attribute is rejected, with the expected reason code.
- **Redaction**: a field is present for an entitled caller and redacted for an unentitled one (the "same request, different data" outcomes).
- **Information flow**: a session that acquired a taint label is blocked on a later operation that gates on it.
- **Delegation**: a passing caller mints a token with the requested scope, and a post-check denies when the granted scope is short.

## Evaluating a route in a test

Compile the config and evaluate a route against an attribute bag standing in for a caller. Assert the decision and the transformed payload. The `apl-core` and `apl-cpex` crates expose the evaluator used by the runtime; their test suites (for example `crates/apl-core/tests`) are the working reference for the exact entry points and fixtures.

A redaction test, in shape:

- build a bag for an HR caller **with** `perm.view_ssn`, evaluate `get_employee`, assert `ssn` is present;
- build a bag for an HR caller **without** `perm.view_ssn`, evaluate the same route, assert `ssn` is redacted;
- build a bag for a non-HR caller, evaluate, assert deny at `require(role.hr)`.

## Integration coverage

Unit-evaluating a route proves the policy logic. It does not prove the plugins it dispatches behave correctly end to end. For effects that call out (a PDP resolver, a delegator, a PII scanner), add an integration test that exercises the real plugin through the manager, so the interaction is covered and not just the policy's intent. Test the failure paths too: a PDP that denies, a token exchange that returns a short scope, a scanner that flags content. Those are the branches policy exists to handle.

## Running

```bash
cargo test --workspace
```

See [`crates/cpex-core/examples`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-core/examples) for runnable programs that load a config and invoke routes, which double as a starting point for integration tests against your own policy.
