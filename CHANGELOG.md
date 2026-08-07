# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

> **Types of changes:**
>
> - **Added**: for new features.
> - **Changed**: for changes in existing functionality.
> - **Deprecated**: for soon-to-be removed features.
> - **Removed**: for now removed features.
> - **Fixed**: for any bug fixes.
> - **Security**: in case of vulnerabilities.

## [Unreleased]

### Added

- **Out-of-process host for existing Python CPEX plugins.** A new `cpex-hosts-python` crate registers `kind: isolated_venv`, running an unmodified Python CPEX plugin in its own cached virtualenv as a subprocess instead of in-process through the PyO3 bindings. Each plugin gets a venv keyed by a SHA-256 fingerprint of its requirements + manifest (rebuilt when either changes, `rmtree`d rather than upgraded in place so a removed dependency actually disappears), and the host drives the Python framework's `worker.py` over a newline-delimited JSON stdio protocol. Hook payloads, `context`, and the capability-filtered `Extensions` view cross as JSON; returns come back as a serialized `PluginResult`, with `modified_extensions` merged through the executor's existing copy-on-write tier validation — the host implements no tier logic of its own. Failure modes the executor cannot otherwise distinguish (venv build failure, worker death mid-flight, a task over `max_content_size`, per-invocation timeout) map to distinct `PluginError`s carrying a stable `code` and structured `details`, so the executor's configured `on_error` policy applies unchanged. Pure Rust plus a subprocess — no libpython link, so the crate is in `default-members` and a plain `cargo build` does not require a Python dev install. The wire contract is pinned in `docs/specs/extensions-wire-contract.md`; CMF §3 remains normative for the extension slots themselves. (#149)

### Fixed

- **A failed `python3 -m venv` or `pip install` now reports its exit code and stderr as structured `details`.** Both paths returned a `VenvBuild` error whose entire content was a prose string, so an operator's log pipeline had to string-match English to recover pip's own diagnosis. They now build `HostError::VenvCommand`, which carries the failing `step`, the exit code (`null` when the child was killed by a signal), and a bounded stderr excerpt into `PluginError::Execution.details`. The stable `code` is unchanged (`venv_build_failed`), and the pip *timeout* path is deliberately still message-only — nothing exited, so there is no exit code to report. (#149)

### Security

- **The host now verifies the worker understands what it is about to be sent, and fails closed at startup when it does not.** An older `worker.py` does not reject a wire field it predates — it ignores it, so a plugin declaring `read_inbound_credentials` against one started cleanly and then ran with **no credential at all**, silently, which is precisely what fail-closed rule 2 exists to prevent. Version strings cannot distinguish the two cases: two framework builds shipped as `0.1.2` with different worker protocols. `initialize()` therefore probes the worker with a new `capabilities` task before any plugin code loads, and the worker answers with the feature names it actually implements. A worker predating the handshake replies `task type not supported.`, which the host reads as "no features" — the conservative answer — while a timeout or a dead worker stays an error, since those mean the probe never completed. Enforcement is per plugin rather than a blanket version gate: a credential capability requires the `credential` feature, an extensions capability requires `extensions`, and a plugin declaring nothing gated still starts on any worker. A mismatch fails that plugin at startup with an error naming the missing feature and what the worker did report, rather than deferring the discovery to a live request; the respawn path re-verifies, because the replacement resolves `worker.py` from a venv that may have been rebuilt since. (#149)

- **Raw credential material can now reach an out-of-process worker.** `RawInboundToken.token` and `RawDelegatedToken.token` are `#[serde(skip)]`, and the "raw credentials never leave the host process" invariant has held because nothing read those fields directly. The `isolated_venv` host narrowly reverses that for two hooks — `identity_resolve` and `token_delegate`, the only ones whose Python payload models a raw token at all — by reading the in-memory field and sending the plaintext in a dedicated `credential` DTO. This is opt-in twice over and fails closed: a plugin receives nothing unless it declares `read_inbound_credentials` or `read_delegated_tokens`, and a plugin that declares one but cannot be served (no extension, empty token) causes the dispatch to error rather than silently sending no credential — an empty bearer would otherwise read as "no authentication required". The `raw_credentials` extension slot itself is never carried, so no hollow token slot invites a plugin to misread "not on this channel" as "no credential present", and the sensitive-header strip (`Authorization` / `Cookie` / `Set-Cookie` / `X-API-Key`, case-insensitive, both directions) keeps credential headers out of the `http` slot regardless. The FFI, Python-bindings, and audit paths are untouched, and the in-process hosts are unaffected.

  **Operators should note the residual exposure the capability gate does not close.** Once the plaintext is resident in the worker process it is readable by every transitively-installed dependency in that plugin's venv — a materially larger and less audited trust boundary than the in-process host, which neither the gate nor the transport can constrain. Grant these two capabilities only to plugins whose venv contents you control, and treat a plugin's requirements file as credential-adjacent supply chain. (#149)
## [0.2.3] - unreleased

### Added

- **Multi-principal delegation.** A `delegate(...)` step can now name **whose** identity the minted token speaks for (`subject: user | client | caller_workload | this_workload`) and **who** is acting (`actor: user | client | caller_workload`, an RFC 8693 `actor_token` recording `act` alongside `sub`). The mode is *derived* from the subject, never declared, so a route can't claim on-behalf-of-user while handing over a workload SVID. Adds SPIFFE JWT-SVID workload ingress (`role: caller_workload`, validated into `caller_workload.*` and stashed as `TokenKind::SpiffeJwt`) and, for `subject: caller_workload`, a two-leg OAuth delegator (SVID as an RFC 7523 `client_assertion` → base token → RFC 8693 exchange). (#131)
- **Top-level `groups:` config section.** Reusable policy bundles (authentication + authorization + plugins) now live at a canonical top-level `groups:`, and a route joins one with a first-class `groups:` field (string-or-list). `groups:` is sugar over tags — it folds into the route's tag set at resolution, so host-injected runtime tags still join groups the same way. A route naming an undefined group is rejected at load. (#131)

### Changed

- **BREAKING: `TokenRole::Workload` renamed to `TokenRole::CallerWorkload`.** A serde `alias = "workload"` keeps existing serialized config loading, but the Rust symbol is renamed — downstream Rust code must update. (#131)
- **BREAKING: `DelegationMode::AsGateway` renamed to `AsThisWorkload`.** A serde `alias = "as_gateway"` keeps persisted values deserializing. (#131)
- **BREAKING: `DelegationKey` is now `#[non_exhaustive]`** and gained a `client_id` field (partitioning the delegated-token cache per calling OAuth client, mirroring `workload_id`). Construct it via `DelegationKey::new(mode, audience, scopes)` + the `with_subject_id` / `with_workload_id` / `with_client_id` setters rather than a struct literal. (#131)
- **BREAKING: `PipelineResult` is now `#[non_exhaustive]`** and gained a `payload_modified` field. `modified_payload` is `Some` on every allowed pipeline, carrying the final payload whether or not a plugin touched it, so it never answered "did anything change?" — read the new flag for that. Construct via `allowed_with` / `denied` plus the `with_errors` / `with_payload_modified` builders rather than a struct literal; exhaustive destructuring must gain a `..` arm. (#151)
- **`payload_modified` is carried across the FFI to the Python and Go bindings.** `FfiPipelineResult`, `PyPipelineResult` (as a `payload_modified` property), and Go's `PipelineResult` / `TypedPipelineResult` all expose it, so non-Rust hosts can distinguish an accepted mutation from a payload the pipeline merely carried. Additive on the MessagePack wire, so the FFI ABI version is unchanged. The Go `Invoke` doc example no longer presents `ModifiedPayload != nil` as a mutation test — it is true on every allowed pipeline. (#151)
- **BREAKING: a pipeline field name reported to a plugin is now root-relative everywhere.** A `do:`-block field op passed `args.city` where the `args:` / `result:` sections passed `city`; both now pass `city`, with the phase selecting the root. The type of `PluginInvocation::Field.name` is unchanged, so this is a silent semantic change: any out-of-tree `PluginInvoker` that stripped an `args.` / `result.` prefix must drop that handling or it will mis-resolve the field. (#151)
- **A pipeline stage plugin that rewrites a field to the value it already held is treated as no change.** Previously any returned payload marked the field replaced. (#151)
- **`payload_modified` errs toward reporting a change.** It records that the executor *accepted* an edit, not that the bytes differ, so it trips on a plugin returning an untouched clone and on a field pipeline writing a field the value it already held. Both previously reported no change. Operators sizing this: inside the engine it costs a `Value` clone and a `Message` clone with no serialization, but a host that keys its wire re-encode off "did the payload change?" will now re-encode on somewhat more routes, and for FFI hosts the MessagePack step rides along. The direction is deliberate. A false positive costs one redundant re-encode; the false negative was the vulnerability fixed in this release, so a modest throughput shift on mutating routes is expected rather than a regression. (#151)

### Deprecated

- The reserved `all` group and the `global.policies:` bundle location, in favor of the top-level `groups:` section. Both still load. (#131)

### Fixed

- **Plugin payload mutations are no longer silently discarded.** A plugin that rewrote anything other than a message's text — a tool result, a tool call's arguments, a thinking block, an attachment — had its mutation dropped by the APL route handler, which decided "was this modified?" by comparing concatenated text content. Redaction and sanitisation plugins are precisely the ones that rewrite tool results, so the failure was fail-open on the path that matters most: the plugin reported a successful redaction and the host forwarded the original secret. Mutation is now reported by the executor at the point it accepts a plugin's payload (`PipelineResult.payload_modified`) and read from there, so it no longer depends on which part of the message changed. Plugins that appended a throwaway text part to force the old check to fire can drop that workaround. (#151)
- **A field pipeline no longer clobbers a plugin's edit to the same content part.** Folding an `args:` or `result:` pipeline's rewrite back into the message replaced the whole argument map / result content, discarding edits a plugin had made to other fields of it. Only the paths the pipeline actually changed are applied now, so a pipeline redacting one argument and a plugin scrubbing another both survive. (#151)
- **A plugin invoked as a pipeline stage now reports a value for the field it was pointed at.** It previously reported the message's concatenated text as the field's new value, which for a structured tool call meant an unrelated argument was overwritten with chat text. A plugin that rewrote some other part of the payload now reports no field change, and its mutation travels with the payload instead. The reported value is compared against the field as the payload held it before the plugin ran, so a `plugin(...)` stage that leaves the field alone can no longer undo an earlier `mask` / `redact` / `hash` stage in the same chain — those interim edits live only in the pipeline, never in the payload, and comparing against them handed the pre-redaction value back as if the plugin had produced it. (#151)
- **A field pipeline that conflicts with a plugin on the same path now logs the tie-break.** `args:` / `result:` pipeline edits take precedence over a plugin's edit to the same field (config-author-wins), a key the plugin removed comes back if the pipeline rewrote it, and a key the pipeline omitted goes even if the plugin had rewritten it. Every case warns with the field name instead of resolving silently. (#151)

## [0.2.2] - 2026-07-15

### Added

- **Human-in-the-loop (HIL) elicitation for APL.** A policy can pause an operation to ask a human — manager approval, a confirm, a step-up re-auth, an attestation — and resume once the human responds, without blocking the request path. Sugar verbs (`require_approval` / `confirm` / `require_step_up` / `require_attestation` / `request_info` / `require_review`) desugar to one `Step::Elicit`, resolved by name to an `ElicitationHandler` plugin exactly like `delegate(...)`. While the human hasn't answered, the phase *suspends* (`Decision` stays `Allow` with a pending bundle) and the host emits JSON-RPC `-32120` so the agent retries by echoing the elicitation id; expiry, channel error, denial, or a failed validation fail closed (default `on_error: deny`). The approval is bound to the live request args via an APL `scope:` expression (`args.amount <= 25000`) the runtime checks at resolution — never an LLM summary. Ships a working Keycloak **CIBA** channel plugin (`kind: elicitation/ciba`, in `cpex-builtins` default features). See [Elicitation]({{< relref "/docs/apl/elicitation" >}}). (#115)

### Changed

- **`read_headers` granted to every synthetic policy handler.** The entity-less HTTP catch-all, per-entity routes (tool/prompt/resource), and defaults are now all granted the `read_headers` capability at install time, so `http.*` request attributes (`http.method` / `http.path` / `http.host` / `http.scheme` / `http.request_headers.*`) are available to policy evaluation wherever the host attaches an `HttpExtension`. Previously only the `global` HTTP catch-all had it, so a per-entity rule could not read the HTTP request line. This lets one policy combine `http.*` with entity/`args.*` predicates in a single evaluation (e.g. an MCP tool route that also gates on `http.method`). It is a no-op for hosts that never populate the HTTP extension — there is nothing to read — and `http.host` continues to be sourced from a validated request authority, never a raw client `Host` header.
- **APL order comparisons now coerce numeric-looking strings.** `numeric_compare` parses string operands as `f64` for order operators (`>`, `>=`, `<`, `<=`), so `args.amount > 10000` fires when the arg arrives as the string `"25000"` — as LLM tool arguments routinely do. This affects **all** order comparisons in the engine, not just elicitation `scope:` bindings: a comparison that previously returned `false` because one side was a numeric string may now evaluate numerically. Equality (`==`) is unchanged, and genuinely non-numeric strings still don't order-compare (they yield `false`, per spec §2.3). (#115)

## [0.2.1] - 2026-07-14

### Added

- **HTTP request-line attributes.** `HttpExtension` now carries optional `method` / `path` / `host` / `scheme`, surfaced in the APL attribute bag as `http.method` / `http.path` / `http.host` / `http.scheme` so CEL/APL predicates can reason over the HTTP request line. They ride the existing `read_headers` capability (the `http` extension slot is gated as a whole). `http.host` must be populated from a validated request authority (e.g. HTTP/2 `:authority`), never a raw client `Host` header, so host-based policy cannot be spoofed.
- **Custom denial response (`response:` block).** A route — or `global` — may declare a custom HTTP `status` / `body` / `headers` for its denials via a `response:` block (a sibling of `authorization:`). On a deny, these are carried on `PluginViolation.details` (`http.status` / `http.body` / `http.headers`) for the host to render; absent, the host default is unchanged. No new APL grammar and no new `PluginViolation` fields. It is scope-local: a `global` response is not inherited by entity routes, and the block warns (inert) at `defaults` / policy-bundle scope.
- **Entity-less HTTP authorization.** The catch-all `global` policy now authorizes generic (non-MCP/A2A) HTTP requests that carry no entity, via new reserved coordinates (`http` / `*`) and the `cmf.http_request` hook. A host fires `cmf.http_request` with those coordinates; the global `authorization` (or `args`) block is evaluated with `read_headers` granted, and a global `response:` decorates the denial. Fail-closed session-store denials carry the response too.
- **Python bindings (PyO3).** Native `cpex` Python package wrapping the cpex-core `PluginManager`, built with maturin/PyO3. ([#70](https://github.com/contextforge-org/cpex/pull/70))

### Changed

- **BREAKING — APL authz/authn config keys renamed** for clarity. The old key names no longer parse; a config using them fails to load with an error naming the replacement (a dropped authorization or authentication block would otherwise fail open, so the rejection is deliberate). Migration:
  - `identity:` → `authentication:` (at `global`, per-route, and policy-group scope)
  - `policy:` → `authorization.pre_invocation:` (or flat `pre_invocation:`)
  - `post_policy:` → `authorization.post_invocation:` (or flat `post_invocation:`)

  The two authorization phases may be written either nested under an `authorization:` block or flat directly on the section; the forms are equivalent. The field-pipeline keys `args:` / `result:` are unchanged (they stay aligned with the `args.*` / `result.*` attribute namespaces that predicates and interpolation read). Internal APL IR is unchanged. (#105)

- **Canonical APL config shape in docs.** All documentation, the README, and the bundled examples now use one canonical shape — no `apl:` wrapper, with `authentication:` and `authorization:` as sibling blocks (`pre_invocation:` / `post_invocation:` nested under `authorization:`; `args:` / `result:` / `pdp:` / `session_store:` / `response:` as siblings). Both the `apl:` wrapper and the wrapper-free form remain accepted by the parser; this only standardizes the examples authors copy from.

## [0.2.0] - 2026-06-26

### Added

- CPEX redesign as a Rust framework with Go bindings
- APL (Authorization Policy Language) governance is now bundled into `libcpex_ffi.a`. New `cpex_apl_install` extern C entry point registers the standard APL plugin/PDP factories (`validator/pii-scan`, `audit/logger`, `identity/jwt`, `delegator/oauth`, `cedar-direct`) and installs the APL config visitor on a manager. Call it after `cpex_manager_new_default` and before `cpex_load_config`. Go hosts use `PluginManager.EnableAPL()`. (#60)
- Publish `libcpex_ffi.a` as signed GitHub Release artifacts on every semver tag push (`linux-amd64-gnu`, `linux-arm64-gnu`, `linux-amd64-musl`, `linux-arm64-musl`, `darwin-arm64`). Cosign keyless signatures + SHA256 checksums; see `crates/cpex-ffi/RELEASE.md` for the schema and the verify-and-consume recipe. (#60)
- FFI ABI versioning: `cpex_ffi_abi_version()` extern C accessor exposes `FFI_ABI_VERSION`. The Go binding checks this in `init()` and panics on mismatch. Other language bindings must replicate the check. (#60)
- CEL (Common Expression Language) policy decision backend. A new `apl-pdp-cel` crate registers `kind: cel`, letting authors write inline boolean predicates (`cel: { expr: ... }`) over the common attribute vocabulary (`subject.id`, `delegation.depth`, `session.labels`, ...), evaluated through the existing `PdpResolver` seam alongside Cedar, OPA, and AuthZen. Expressions compile once and cache by source; compile errors, undeclared-variable references, and non-boolean results fail closed (deny), overridable with `on_error: allow`. No change to APL evaluation semantics. (#68)
- APL authoring ergonomics (backwards-compatible). The `apl:` wrapper is now optional — recognized APL terms (`policy`, `post_policy`, `args`, `result`, `pdp`, `session_store`) written directly on a section are honored, with the explicit `apl:` form still taking precedence. `run(name)` is accepted as an alias for `plugin(name)` in both policy steps and field pipelines. Unconditional `deny('reason')` / `deny('reason', 'code')` now parses as a bare action (e.g. in `on_deny:` lists), so a reason/code can be attached without a conditional. (#71)
- Valkey-backed `SessionStore` for cross-node and cross-restart session label propagation. Selectable via a `kind: valkey` block under `global.apl.session_store` (factory pattern mirroring `pdp`), shipped in the `apl-session-valkey` crate and wired into `cpex-ffi` behind the optional `valkey` cargo feature (the default build and `.a` artifact are unaffected). Labels live in a Redis SET so appends are an atomic server-side union (`SADD`); the store is fail-closed (a load/append error denies the request rather than under-labeling), serves primary-only reads, supports an optional sliding TTL, requires TLS for non-localhost endpoints, and SHA-256s session ids out of the keyspace. When no block is configured the default remains the in-process memory store. See the operator runbook at `docs/operations/valkey-session-store.md`. (#74)
- `cpex` host facade crate: a single dependency that re-exports the host runtime (`PluginManager`, `AplOptions`, `register_apl`) and the bundled plugin factories, each behind a cargo feature (`jwt`, `oauth`, `pii`, `audit`, `cedar`, `cel`, `valkey`). Hosts depend on `cpex` and enable the plugins they want instead of pinning `apl-cmf` / `apl-cpex` / `apl-pdp-*` / `apl-session-*` individually. `install_builtins(&mgr)` registers every enabled factory and installs the APL config visitor in one call; `register_builtin_plugins`, `builtin_pdp_factories`, and `builtin_session_store_factories` expose the pieces for hosts that assemble `AplOptions` themselves. (#77)
- `cpex-builtins` aggregator crate: the bundled extension set (plugins, PDPs, session stores) behind a 1:1 cargo-feature map, with a declarative `register_builtins!` macro that expands to explicit, `#[cfg]`-gated `register_factory` calls (kept explicit rather than `inventory`/`linkme` so factory symbols survive the linker GC inside `libcpex_ffi.a`). `register_builtins`, `builtin_pdps`, `builtin_session_store_factories`, and `install_builtins` are the single source of truth that both the `cpex` facade and `cpex-ffi` now delegate to. (#72)

### Changed

- The `cpex` facade is now **engine-only by default**: `cpex = "0.2"` compiles no builtin plugins. The bundled set is opt-in via the new `builtins` feature (the common in-process set) or `full` (everything, incl. Valkey), with the granular plugin features (`jwt`, `oauth`, `pii`, `audit`, `cedar`, `cel`, `valkey`) preserved as passthroughs. The registration helpers and concrete factory types are re-exported from `cpex-builtins` and appear only when a builtins feature is enabled. `cpex-ffi` keeps its prior bundled set (four hook plugins + `cedar-direct`) by selecting that exact `cpex-builtins` feature subset. No FFI ABI change. (#72)
- `PluginFactoryRegistry::register` now logs a `tracing::warn!` when a registration overwrites an existing `kind` (last-writer-wins is unchanged, but silent override was a footgun). (#72)
- Builtin extension crates moved out of the flat `crates/` directory into a `builtins/` tree (`builtins/plugins/`, `builtins/pdps/`, `builtins/session/`, `builtins/cedarling/`) and renamed off the `apl-` prefix, since they are CPEX plugins that *use* APL hooks rather than APL itself: `apl-pii-scanner` → `cpex-plugin-pii-scanner`, `apl-audit-logger` → `cpex-plugin-audit-logger`, `apl-identity-jwt` → `cpex-plugin-identity-jwt`, `apl-delegator-oauth` → `cpex-plugin-delegator-oauth`, `apl-delegator-biscuit` → `cpex-plugin-delegator-biscuit`, `apl-pdp-cedar-direct` → `cpex-pdp-cedar-direct`, `apl-pdp-cel` → `cpex-pdp-cel`, `apl-session-valkey` → `cpex-session-valkey`, `apl-cedarling` → `cpex-cedarling`. The policy crates (`apl-core`, `apl-cmf`, `apl-cpex`) keep their names. Config-facing `kind:` strings and the FFI C ABI are unchanged. (#72)
- FFI `FFI_ABI_VERSION` bumped `1 → 2`: added the `cpex_apl_install` extern C function and changed `cpex_load_config` to run registered config visitors (it now calls `load_config_yaml` internally so `apl:` blocks are walked). The Go binding's `expectedFFIABIVersion` is bumped in lockstep. (#60)
- Size-first `[profile.release]`: `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `strip = true`. `libcpex_ffi.a` is linked statically into host binaries, so this flows straight into their image size — a representative statically-linked consumer shrank ~21%. `panic = "abort"` is intentionally not set (the FFI relies on `catch_unwind` at its `#[no_mangle]` boundary). No API or ABI change. (#69)
- Trimmed the workspace `tokio` feature floor from `["full"]` to `["rt", "rt-multi-thread", "sync", "time", "macros"]` — the union of what the crates actually use; `reqwest`/`hyper` still pull `net`/`io` where they need them via feature unification. Drops the unused `fs`/`process`/`signal` surface (and the `signal-hook-registry` dependency). (#69)
- `SessionStore` trait methods (`load_labels` / `append_labels`) now return `Result` so backend failures propagate to callers — the error channel fail-closed requires. `MemorySessionStore` is infallible and adapts trivially; the CMF invoker (`for_request` / `persist_session`) and the route handler propagate the error and fail the request closed on a load/append failure. This is part of the shared `SessionStore` contract that future bridges inherit. (#74)

### Removed

- Removed the `cpex-cedarling` crate (a Sub-step A stub with no real Cedarling calls), its `cpex-ffi` optional dependency + `cedarling` cargo feature, and the `cedarling` PDP dialect from the APL grammar (`PdpDialect::Cedarling` and `cedarling:` step recognition). This drops the only `git` dependency in the workspace (the Janssen `cedarling` crate, ~200 transitive deps), making every crate publishable to crates.io. Cedarling was wired nowhere — no config, host, or Go binding referenced it — so there is no functional change; the remaining PDP `kind:` strings (`cedar-direct`, `cel`) and the FFI C ABI are unchanged. A `cedarling`-backed PDP can still be supplied out-of-tree (it degrades to `PdpDialect::Custom`, alongside the resolver-less `opa` / `authzen` / `nemo` dialects).

### Fixed

- Cedar evaluation no longer fails with "recursion limit reached" on hosts that give the FFI a small thread stack (notably musl, whose default is 128 KiB). `cedar-policy` aborts when `stacker::remaining_stack()` is below its 100 KiB floor; the cedar dispatch in `apl-pdp-cedar-direct` is now wrapped in `stacker::maybe_grow`, so it runs on an adequately sized stack regardless of the host (a no-op when there is already headroom, e.g. glibc's 8 MiB threads). Regression test exercises a real evaluation on a 128 KiB stack. (#69)

## [0.1.1] - 2026-06-04

### Added

- Plugin bundling, catalog, installation and versioning ([#31](https://github.com/contextforge-org/cpex/pull/31))

### Fixed

- Implement `__eq__` and `__ne__` for CopyOnWriteDict ([#55](https://github.com/contextforge-org/cpex/pull/55))
- Respect `PLUGINS_LOG_LEVEL` environment variable in all runtime.py files ([#48](https://github.com/contextforge-org/cpex/pull/48))

## [0.1.0] - 2026-05-05

### Added

- Initial release

[Unreleased]: https://github.com/contextforge-org/cpex/compare/0.2.2...HEAD
[0.2.2]: https://github.com/contextforge-org/cpex/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/contextforge-org/cpex/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/contextforge-org/cpex/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/contextforge-org/cpex/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/contextforge-org/cpex/releases/tag/0.1.0
