# PPE adoption follow-ups

These issue drafts come from [Teryl's review of CPEX #190](https://github.com/contextforge-org/cpex/pull/190). Both were confirmed against the published PPE 0.4.1 sources. Issue publication is pending maintainer approval.

## fix(apl): make install_builtins idempotent per engine

In PPE 0.4.1, `install_builtins` calls `register_apl` on every invocation and discards the returned visitor handle (`praxis-policy/src/lib.rs:269-276`). `PolicyEngine::register_visitor` appends unconditionally (`praxis-policy-core/src/engine.rs:1403-1409`). Calling the helper twice therefore installs two APL visitors on the same engine.

Reproducer:

```rust
let engine = std::sync::Arc::new(praxis_policy::PolicyEngine::default());
praxis_policy::install_builtins(&engine);
praxis_policy::install_builtins(&engine);
// Loading policy sections now walks two APL visitors.
```

Make `install_builtins` idempotent per engine, or reject duplicate APL visitor registration without suppressing unrelated custom visitors. Add a regression test covering two installs, a subsequent policy load, and dispatch with one execution of each configured step. Also cover concurrent installs and an interrupted install if the implementation introduces install state.

CPEX 0.3.0 retains its FFI and Python per-engine guards as defence in depth. Rust embedders must install builtins once until PPE fixes this. If CPEX adopts the fix, release it from the 0.4.1 release branch as a 0.4.x patch, move the exact dependency pin, and rerun parity before tagging 0.3.0.

## feat(http): allow specific private destinations without opening all private networks

PPE 0.4.1 `HyperTransport` exposes only `with_allow_private_destinations` (`praxis-policy/src/http_hyper.rs:216`). It permits private destinations globally for every builtin sharing the transport, including JWKS, OAuth delegation, CIBA and Vault.

A host needing JWKS from localhost must therefore also permit RFC 1918, link-local addresses including cloud metadata, and CGNAT. Add a host-configured allow-list of private hosts or destinations that keeps all other private destinations blocked. Policy documents must not be able to widen that list. Preserve the default denial and check resolved addresses, redirects and IPv4/IPv6 consistently with the existing transport checks.

Acceptance: a permitted localhost JWKS succeeds, another private host and `169.254.169.254` remain blocked, and redirects or DNS resolution cannot escape the allow-list. Include Vault because it shares the host transport.

This is deferred PPE feature work, not a CPEX 0.3.0 release dependency. Meanwhile CPEX's binding startup warns whenever its global opt-in is enabled; Rust hosts can install their own transport with narrower egress rules.
