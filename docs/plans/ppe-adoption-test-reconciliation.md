# PPE adoption test reconciliation

Reconstructed on 2026-10-13 from successful executions, including doctests. The 0.2.3 tag has the same engine and builtin sources as the snapshot engine commit. This records the current post-port branch, rather than inventing historical counts for the intermediate cut-over commit where kept surfaces were not yet ported.

Environment: macOS, rustc 1.96.0, default workspace features. Before: `cargo test --workspace --locked --offline` on immutable `v0.2.3` (`e3a2b30`). After: `cargo test --workspace --offline -- --test-threads=4` on `8b3cbb9` plus the Teryl review fixes, with `PARITY_VALKEY_URL` pointing to a disposable Valkey 8 database. Four test threads avoid contention between Python subprocess timing tests. One existing worker-death timing assertion failed in a concurrent run; it passed in isolation and in the recorded run.

**Before: 1434 executed, 39 ignored. After: 408 executed, 17 ignored. Both runs had zero failures.** PPE dependency tests are not executed by the CPEX workspace command. A smaller CPEX count therefore does not establish coverage parity by itself.

The [machine-readable inventory](ppe-adoption-test-counts.json) records counts per executable and every ignored test with its reason. Default-feature counts exclude optional-feature-only tests; the retained baseline harness is run separately against the old engine.

| Package | Before executed | Before ignored | After executed | After ignored |
|---|---:|---:|---:|---:|
| `apl-cmf` | 61 | 1 | 0 | 0 |
| `apl-core` | 307 | 0 | 0 | 0 |
| `apl-cpex` | 212 | 1 | 0 | 0 |
| `cpex` | 2 | 2 | 13 | 1 |
| `cpex-builtins` | 3 | 0 | 0 | 0 |
| `cpex-core` | 374 | 15 | 0 | 0 |
| `cpex-demo-ffi` | 0 | 0 | 1 | 0 |
| `cpex-ffi` | 10 | 0 | 32 | 0 |
| `cpex-hosts-python` | 219 | 13 | 328 | 16 |
| `cpex-orchestration` | 7 | 0 | 0 | 0 |
| `cpex-parity-harness` | 0 | 0 | 12 | 0 |
| `cpex-pdp-cedar-direct` | 17 | 0 | 0 | 0 |
| `cpex-pdp-cel` | 32 | 1 | 0 | 0 |
| `cpex-pdp-opa` | 74 | 0 | 0 | 0 |
| `cpex-plugin-audit-logger` | 1 | 0 | 0 | 0 |
| `cpex-plugin-delegator-biscuit` | 10 | 0 | 12 | 0 |
| `cpex-plugin-delegator-oauth` | 27 | 0 | 0 | 0 |
| `cpex-plugin-elicitation-ciba` | 15 | 1 | 0 | 0 |
| `cpex-plugin-identity-jwt` | 40 | 0 | 0 | 0 |
| `cpex-plugin-pii-scanner` | 6 | 0 | 0 | 0 |
| `cpex-python` | 2 | 0 | 7 | 0 |
| `cpex-sdk` | 0 | 0 | 0 | 0 |
| `cpex-session-valkey` | 13 | 5 | 0 | 0 |
| `cpex-tutorial` | 2 | 0 | 3 | 0 |

## Deleted suite ownership

The following locations were checked in PPE `v0.4.1`. They identify the upstream maintenance owner, not an assertion that every old test has an identical upstream copy or was run here. Core and builtin behavior is also checked through the 68-request CPEX parity fixture set; surface acceptance covers the binding boundary.

| Deleted CPEX package | PPE 0.4.1 owner / disposition |
|---|---|
| `cpex-core` | `crates/ppe-core/src` unit tests and `crates/ppe-core/tests` integration suites |
| `cpex-orchestration` | `crates/ppe-orchestration` |
| `cpex-sdk` | Public authoring API is in `praxis-policy-core` and the PPE facade prelude; no separately maintained SDK crate |
| `cpex-builtins` | `crates/builtins` registration and builtin tests |
| `apl-core` | `crates/ppe-apl-core` |
| `apl-cmf` | `crates/ppe-apl-cmf` |
| `apl-cpex` | `crates/ppe-apl-runtime` |
| `cpex-plugin-identity-jwt` | `crates/builtins/src/plugins/identity_jwt` and `crates/builtins/tests/jwt` |
| `cpex-plugin-delegator-oauth` | `crates/builtins/src/plugins/delegator_oauth` and `crates/builtins/tests/oauth` |
| `cpex-plugin-elicitation-ciba` | `crates/builtins/src/plugins/elicitation_ciba` and `crates/builtins/tests/ciba` |
| `cpex-pdp-cedar-direct` | `crates/builtins/src/pdps/cedar_direct` and `crates/builtins/tests/cedar` |
| `cpex-pdp-cel` | `crates/builtins/src/pdps/cel` and `crates/builtins/tests/cel` |
| `cpex-pdp-opa` | `crates/builtins/src/pdps/opa` and `crates/builtins/tests/opa` |
| `cpex-session-valkey` | `crates/builtins/src/session/valkey` and `crates/builtins/tests/valkey` |
| `cpex-plugin-pii-scanner` | Intentionally removed from CPEX; PPE keeps `reference/plugins/pii-scanner` outside its shipped builtins |
| `cpex-plugin-audit-logger` | Intentionally removed from CPEX; PPE keeps `reference/plugins/audit-logger` outside its shipped builtins |

The imported engine/APL suites remain an upstream PPE CI responsibility. JWT, OAuth, CIBA, PDP and session behavior retain CPEX parity coverage; the Valkey read-back test explicitly seeds data written by 0.2.3. PII and audit are intentional product removals, so their deleted CPEX tests are not silently counted as passing.

## Ignored tests

Every ignored test is listed below. The supported legacy-worker release gate separately executed the four `make test-python-e2e` suites against SDK commit `6a38e0eb2ac399fdbce3f3ac9fcf695c5bd4518e`: 14 passed, zero ignored, zero skips. The two `config_e2e` tests still require a separately installed `cpex-test-plugin` fixture and are explicitly outside that target. The old live-Keycloak and Valkey integration tests remain upstream integration responsibilities; CPEX parity used a real disposable Valkey.

### Before (0.2.3)

- `cpex-hosts-python / tests/config_e2e.rs / config_yaml_dispatches_identity_resolve_and_token_delegate_to_the_installed_plugin`: requires cpex-test-plugin installed under plugins/ with a built venv.
- `cpex-hosts-python / tests/config_e2e.rs / config_yaml_dispatches_tool_pre_invoke_to_the_installed_plugin`: requires cpex-test-plugin installed under plugins/ with a built venv.
- `cpex-hosts-python / tests/credential_e2e.rs / a_capable_plugin_reads_the_raw_token_end_to_end`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/credential_e2e.rs / a_declared_capability_that_cannot_be_honored_fails_closed_end_to_end`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/credential_e2e.rs / a_non_capable_plugin_on_the_same_hook_receives_no_token`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/credential_e2e.rs / the_credential_never_reaches_a_log_sink_the_host_controls`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/credential_e2e.rs / the_real_worker_answers_the_capabilities_handshake`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/extensions_merge_e2e.rs / an_appended_label_is_dropped_without_the_capability`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/extensions_merge_e2e.rs / an_appended_label_survives_the_merge_when_the_capability_is_declared`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/isolated_venv_e2e.rs / a_cmf_hook_is_rejected_cleanly_by_a_framework_that_has_no_cmf_hooks`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/isolated_venv_e2e.rs / a_real_plugin_deny_surfaces_as_a_deny_result`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/isolated_venv_e2e.rs / a_second_run_reuses_the_cached_venv`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/isolated_venv_e2e.rs / legacy_tool_pre_invoke_round_trips_through_the_real_worker`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-plugin-elicitation-ciba / tests/live_keycloak.rs / live_dispatch_then_pending`: requires a live Keycloak.
- `cpex-session-valkey / tests/valkey_store_integration.rs / cross_node_concurrent_append_unions`: marked #[ignore].
- `cpex-session-valkey / tests/valkey_store_integration.rs / ttl_set_on_append_and_refreshed_on_load`: marked #[ignore].
- `cpex-session-valkey / tests/valkey_store_integration.rs / unknown_session_returns_empty_ok`: marked #[ignore].
- `cpex-session-valkey / tests/valkey_store_integration.rs / unreachable_endpoint_fails_closed`: marked #[ignore].
- `cpex-session-valkey / tests/valkey_store_integration.rs / wrongtype_reply_fails_closed`: marked #[ignore].
- `apl-cmf / doctests / crates/apl-cmf/src/lib.rs - BagBuilder (line 84)`: marked #[ignore].
- `apl-cpex / doctests / crates/apl-cpex/src/register.rs - register::register_apl (line 133)`: marked #[ignore].
- `cpex / doctests / crates/cpex/src/lib.rs - (line 46)`: marked #[ignore].
- `cpex / doctests / crates/cpex/src/lib.rs - (line 75)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/delegation/hook.rs - delegation::hook::TokenDelegateHook (line 55)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/elicitation/hook.rs - elicitation::hook::ElicitationHook (line 50)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/extensions/container.rs - extensions::container::Extensions::cow_copy (line 162)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/factory.rs - factory::PluginFactory (line 39)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/factory.rs - factory::PluginFactoryRegistry (line 85)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/hooks/macros.rs - hooks::macros::define_hook (line 21)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/hooks/macros.rs - hooks::macros::define_hook (line 38)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/hooks/trait_def.rs - hooks::trait_def::HookHandler (line 102)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/identity/hook.rs - identity::hook::IdentityHook (line 65)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/manager.rs - manager::PluginManager::invoke_named (line 1086)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/manager.rs - manager::PluginManager::load_config_file (line 464)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/manager.rs - manager::PluginManager::register_factory (line 438)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/manager.rs - manager::PluginManager::register_handler (line 740)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/manager.rs - manager::PluginManager::register_handler_for_names (line 771)`: marked #[ignore].
- `cpex-core / doctests / crates/cpex-core/src/plugin.rs - plugin::Plugin (line 47)`: marked #[ignore].
- `cpex-pdp-cel / doctests / builtins/pdps/cel/src/resolver.rs - resolver::CelResolver::with_functions (line 152)`: marked #[ignore].

### After (0.3.0)

- `cpex-hosts-python / tests/acceptance_e2e.rs / a_rejected_credential_denies_and_an_unauthenticated_route_call_is_refused`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/acceptance_e2e.rs / python_identity_and_delegation_plugins_serve_a_ppe_route`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/config_e2e.rs / config_yaml_dispatches_identity_resolve_and_token_delegate_to_the_installed_plugin`: requires cpex-test-plugin installed under plugins/ with a built venv.
- `cpex-hosts-python / tests/config_e2e.rs / config_yaml_dispatches_tool_pre_invoke_to_the_installed_plugin`: requires cpex-test-plugin installed under plugins/ with a built venv.
- `cpex-hosts-python / tests/credential_e2e.rs / a_capable_plugin_reads_the_raw_token_end_to_end`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/credential_e2e.rs / a_declared_capability_that_cannot_be_honored_fails_closed_end_to_end`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/credential_e2e.rs / a_non_capable_plugin_on_the_same_hook_receives_no_token`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/credential_e2e.rs / the_credential_never_reaches_a_log_sink_the_host_controls`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/credential_e2e.rs / the_real_worker_answers_the_capabilities_handshake`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/extensions_merge_e2e.rs / an_appended_label_is_dropped_without_the_capability`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/extensions_merge_e2e.rs / an_appended_label_survives_the_merge_when_the_capability_is_declared`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/isolated_venv_e2e.rs / a_cmf_message_the_shim_cannot_represent_fails_closed`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/isolated_venv_e2e.rs / a_real_plugin_deny_surfaces_as_a_deny_result`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/isolated_venv_e2e.rs / a_second_run_reuses_the_cached_venv`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/isolated_venv_e2e.rs / legacy_plugins_on_cmf_tool_pre_invoke_rewrite_and_deny_through_the_engine`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex-hosts-python / tests/isolated_venv_e2e.rs / legacy_tool_pre_invoke_round_trips_through_the_real_worker`: requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`.
- `cpex / doctests / crates/cpex/src/lib.rs - (line 66)`: marked #[ignore].
