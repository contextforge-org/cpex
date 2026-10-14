---
date: 2026-10-07
topic: ppe-core-adoption
---

# Adopt PPE as the CPEX Core (CPEX 0.3.0)

## Summary

CPEX 0.3.0 replaces its own engine core and builtins with the published Praxis Policy Engine (PPE) crates. It keeps the surfaces PPE does not have (Python host, C FFI, Python and Go bindings, delegator-biscuit, tutorial, standalone docs) and moves all of them to PPE's API and policy format. A CPEX-side acceptance suite and a parity check against 0.2.3 confirm that operations still work.

---

## Problem Frame

The CPEX Rust core was donated to the Praxis org as PPE. The port was extracted at CPEX commit `aed0f15`, with OPA added from `fa222c4`; both anchors are recorded in PPE's changelog (0.1.0 entry) and `docs/dev/port-provenance.md` in the PPE repo. Since then PPE has moved to 0.4.1. Along the way it renamed the public API (`PluginManager` became `PolicyEngine`, `cpex-*` and `apl-*` crates became `praxis-policy-*`), folded the SDK into a prelude module, required hosts to supply an HTTP transport, changed the policy document (dispatch defaults to `policy`, about ten keys removed, unreached plugins fail the load), merged its extensions into one builtins crate, and turned `pii-scanner` and `audit-logger` into unpublished reference plugins.

CPEX still carries its own copy of everything PPE now owns: core, orchestration, three APL crates, the SDK, the builtins crate, and nine builtin plugins, PDPs and session stores. The two copies drift. Every fix lands twice or not at all, and CPEX users run an engine that is falling behind the one the same maintainers ship upstream. Meanwhile the CPEX-only surfaces (Python host, FFI, Python and Go bindings, tutorial) are what CPEX users actually integrate with, and they are all wired to the old core and the old `PluginManager` name.

---

## Actors

- A1. Rust embedder: depends on the `cpex` crate directly and registers its own plugin factories.
- A2. Python integrator: uses the `cpex` wheel, often through legacy `PluginManager` code.
- A3. Go integrator: uses the `go/cpex` package over the C FFI.
- A4. Operator: writes the policy YAML that CPEX loads.
- A5. Maintainer: maintains both PPE and CPEX and cuts the 0.3.0 release.

---

## Requirements

**Dependency and crate layout**
- R1. CPEX depends on PPE through released crates.io versions only, pinned to an exact release in the 0.4.x line, and this includes PPE's builtins. No path or git dependency on PPE remains in released manifests.
- R2. CPEX removes every crate that PPE replaces: core, orchestration, the three APL crates, the SDK, the builtins crate, and the builtin plugins, PDPs and session store that PPE already has (identity-jwt, delegator-oauth, elicitation-ciba, cedar-direct, cel, opa, valkey).
- R3. CPEX removes its `pii-scanner` and `audit-logger` crates. It does not re-host PPE's reference versions.
- R4. CPEX keeps `delegator-biscuit` as a CPEX-owned plugin, ported to PPE's plugin API, built and tested in the CPEX workspace.
- R5. CPEX keeps the out-of-process Python plugin host and the C FFI, both ported to PPE's API.

**Public API**
- R6. Every CPEX surface uses PPE's names: Rust, Python, Go, FFI-facing docs, examples and the tutorial. `PluginManager` becomes `PolicyEngine`, and the other renames PPE made since the port follow the same way. The Go constructors are renamed to match (for example, `NewPolicyEngine`).
- R7. The Python package keeps `PluginManager` as an alias of `PolicyEngine`. It is the only compatibility alias on any surface.
- R8. No Rust or Go compatibility aliases or shims for the old names.

**Builtins shipped in bindings**
- R9. The Python wheel and the Go FFI library ship every non-experimental builtin PPE publishes. That adds OPA, CIBA, api-key identity and the Vault secret provider to the current set. PPE's experimental quota is not shipped.
- R10. The Python wheel and Go FFI library do not ship `pii-scanner` or `audit-logger`. Using them requires a Rust host.
- R11. Builtins that make outbound HTTP calls (JWT/JWKS, OAuth token exchange, CIBA, Vault) keep working from Python and Go without integrators writing transport code.

**Policy configuration**
- R12. CPEX accepts exactly the policy document PPE accepts. It does no pre-processing, key rewriting or legacy-key acceptance.
- R13. Every config shipped in CPEX (examples, tutorial modules, test fixtures, docs snippets) is ported to the PPE format and loads cleanly, including PPE's load-time checks such as unreached plugins.
- R14. A migration guide maps each removed or changed 0.2.x config key, hook name and behavior to its 0.3.0 form. It also covers the dispatch-mode default, newly required plugin capabilities, and the new load-time failures.

**Documentation**
- R15. CPEX keeps its own complete docs site. Docs are revised for every API and config change, not dropped in favor of PPE's.
- R16. CPEX docs gain the current PPE material that applies to CPEX users (for example HTTP routing, assertions, auditing, identity claim mapping, CMF extensions, and the crate map), adapted to CPEX's audience and surfaces.
- R17. Docs show how a Rust host registers PPE's reference `pii-scanner` and `audit-logger` plugins through the host plugin registration path. They also state that Python and Go builds do not include them.
- R18. The 0.3.0 changelog lists every breaking change across Rust, Python, Go and config, and links the migration guide.

**Verification**
- R19. Existing CPEX suites pass after the port: Rust workspace tests, Python host e2e, FFI tests, Go tests (including race), Python binding tests, and tutorial checks.
- R20. A new CPEX-side acceptance suite drives PPE through CPEX's own surfaces (Python bindings, Go/FFI, Python host) for the key flows: config load, identity, delegation, PDP decisions, session labels, and elicitation where practical. It covers what PPE's own e2e suites cannot reach.
- R25. Python support keeps working end to end after the refactor: the PyO3 wheel builds, imports and runs policies, and the out-of-process Python plugin host (`isolated_venv` plugins) loads and runs plugins on the new engine, with its e2e suites green in CI.
- R21. A parity check runs representative configs against CPEX 0.2.3 and 0.3.0 (after config migration) and confirms the same allow/deny decisions, violation codes and plugin effects. Any difference is documented as intended in the migration guide or fixed.

**Build, CI and release**
- R22. Makefile targets, CI workflows and release workflows are updated for the new crate layout, the PPE dependency, and the new test suites. Targets for removed crates are dropped, the new acceptance and parity checks are wired in, and the Python wheel and Go release builds keep working.
- R23. The release ships as CPEX 0.3.0.

**Contribution hygiene**
- R26. CPEX moves to the same Rust edition as PPE (2024, resolver 3), as its own change separate from the port.
- R24. Commits are signed off (`-s`), use short conventional commit messages, and carry no AI attribution trailers.

---

## Acceptance Examples

- AE1. **Covers R7, R6.** Given Python code that does `from cpex import PluginManager` and builds an engine from a migrated config, when it runs on 0.3.0, it works unchanged. Given Go code calling `NewPluginManager`, it fails to compile and the migration guide names `NewPolicyEngine`.
- AE2. **Covers R12, R14.** Given a 0.2.x config that uses a removed key, when 0.3.0 loads it, the load fails with PPE's unknown-key error. The migration guide has an entry for that key.
- AE3. **Covers R10, R17.** Given a Python config declaring a `pii-scanner` plugin, when it loads, the kind is reported as unknown. The docs explain that pii-scanner needs a Rust host and show how to register it there.
- AE4. **Covers R11.** Given a Go integrator using an identity-jwt plugin with a JWKS URL and no transport setup, when a request arrives, the JWT is validated through PPE's transport, the same as on 0.2.3.
- AE5. **Covers R21.** Given a representative 0.2.3 config and its migrated 0.3.0 form, when both evaluate the same request set, the decisions and violation codes match, or each difference is listed as intended.

---

## Success Criteria

- Python integrators and Python plugin authors keep working on 0.3.0: the wheel and the `isolated_venv` host both pass their suites.
- A CPEX user can upgrade to 0.3.0 by following the migration guide alone, and their policy decisions do not change silently.
- CPEX no longer contains a second copy of engine code. Engine fixes land once, in PPE, and reach CPEX by a version bump.
- A planner can sequence the work without inventing which crates survive, what the bindings ship, how configs are treated, or what "not broken" means.

---

## Scope Boundaries

- No config migration tool, and no acceptance of 0.2.x keys at load time.
- No compatibility aliases on Rust or Go. The Python `PluginManager` alias is the only one.
- No `pii-scanner` or `audit-logger` in Python or Go builds.
- No PPE experimental quota in bindings.
- No new engine features or behavior changes inside PPE, apart from upstreaming fixes CPEX needs (see Key Decisions).
- No moving CPEX docs into PPE, and no retiring CPEX docs in favor of PPE's.
- No Praxis-side consumer changes.

---

## Key Decisions

- Clean break on names everywhere except the Python alias: legacy Python integrations are the most fragile and the brief asked for it. Elsewhere, aliases would keep both names alive indefinitely.
- Config follows PPE exactly, with a guide rather than a tool or shim: a shim would recreate the drift this work removes, and PPE's stricter load checks are a safety gain worth keeping.
- crates.io only, exact 0.4.x pin: CPEX releases depend on what PPE has actually released, so 0.3.0 is reproducible. PPE has shipped breaking changes inside 0.4.x, so the pin is exact. If CPEX needs a PPE change, PPE ships a 0.4.x patch first.
- `cpex` stays as the host-facing facade crate and re-exports PPE's facade, so Rust embedders keep one entry point and CPEX-only features hang off it.
- Bindings install PPE's default HTTP transport on the integrator's behalf, because Python and Go users cannot plug in a Rust transport and identity, delegation and CIBA must keep working.
- Bindings mirror PPE's non-experimental builtin set, which brings OPA and CIBA into Python and Go for the first time, alongside api-key and Vault.
- Post-port CPEX changes are reconciled upstream: CPEX has 13 commits after `aed0f15`. The few that touch core or builtins (for example a CEL resolver change and identity-jwt test changes) are checked against PPE, and anything missing is upstreamed to PPE rather than kept as a CPEX patch.
- `pii-scanner` and `audit-logger` stay out of bindings: they are unpublished in PPE, and shipping them from CPEX would make CPEX their de facto publisher.

---

## Dependencies / Assumptions

- PPE 0.4.x on crates.io exposes everything CPEX's Python host, FFI and biscuit plugin need through its public API. Gaps become PPE changes and releases, which gate CPEX 0.3.0.
- PPE's toolchain floor (edition 2024, its MSRV) becomes CPEX's floor, and CPEX adopts the same edition so both repos share idioms and lint behavior.
- The PPE local clone at `../praxis-policy` is a reference for porting and for upstream fixes, not a build input.
- An older plan, `docs/plans/2026-08-08-001-feat-praxis-policy-engine-port-plan.md`, covered creating PPE. This work is its CPEX-side follow-up.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R6][Technical] Whether C ABI symbol names in the FFI are renamed along with the Go names, or kept stable underneath a renamed Go surface.
- [Affects R5][Technical] Which PPE public APIs the Python host and FFI need that may not be public today, and whether any require a PPE release first.
- [Affects R21][Technical] Which configs make up the representative parity set, and how the parity check runs against 0.2.3 (pinned release artifact vs. tagged build).
- [Affects R20][Needs research] Which acceptance flows are already covered by PPE's own e2e suites, so the CPEX suite only adds coverage for CPEX surfaces.
- [Affects R16][Technical] Which PPE doc pages are adopted as-is, adapted, or summarized with a link.
- [Affects R22][Technical] How removed crates' published crates.io names are handled (final deprecation release or just left at 0.2.3).
