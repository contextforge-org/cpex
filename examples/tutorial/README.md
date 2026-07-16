# CPEX Tutorial: runnable code

This crate is the runnable companion to the [CPEX tutorial docs](../../docs/content/docs/tutorial). Each tutorial module is one binary under `examples/`; they all share the harness in `src/`.

```bash
# From the workspace root:
cargo run -p cpex-tutorial --example m01_hello            # run a module
cargo run -p cpex-tutorial --example m01_hello -- --check # scripted assertions (used by CI)
```

## Layout

| Path | What it is |
|------|-----------|
| `src/mediate.rs` | `mediate()`, the enforcement loop a host owns, wrapped in one call. **Harness code, not a CPEX API** (see the note at the top of the file). |
| `src/backends.rs` | Fake HR / repo / email tools. They hold data and do no enforcement; policy in front of them decides who sees what. |
| `src/idp.rs` | Mint a token from the tutorial Keycloak realm; wait for it to be ready. |
| `src/approvals.rs` | A tiny `curl`-driven approval channel for the elicitation module. |
| `src/ui.rs` | Shared console formatting and the `--check` assertion helpers. |
| `examples/mNN_*.rs` | One binary per tutorial module. |
| `policies/mNN.yaml` | The APL each module loads. **These are yours to edit**; that is the point. Reset with `git checkout -- examples/tutorial/policies`. |
| `idp/` | `docker-compose.yml` + `realm-export.json` for the tutorial Keycloak. |

## The IdP

Modules 0–1 need no IdP. Module 2 onward resolve real tokens, so start Keycloak first:

```bash
docker compose -f examples/tutorial/idp/docker-compose.yml up -d   # ~30s first boot
docker compose -f examples/tutorial/idp/docker-compose.yml down    # resets everything
```

See [`idp/README.md`](idp/README.md) for the personas and how to mint a token by hand.

## Editing policy

For modules 2–8 you change `policies/*.yaml`, not Rust. Each policy file has a header explaining what to try. The harness reloads the file on each run (`cargo run ...`), so edit, re-run, observe.
