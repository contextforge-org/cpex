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
| `src/audit.rs` | A one-line audit plugin (`kind: tutorial/audit-line`) used by module 4 and the capstone. It prints the tool name and argument keys, never argument values. |
| `src/approvals.rs` | A tiny `curl`-driven approval channel for the elicitation module. |
| `src/ui.rs` | Shared console formatting and the `--check` assertion helpers. |
| `src/lib.rs` | `install_http_transport()`, the HTTP transport every module installs. It allows private destinations so the builtins can reach the IdP on `localhost`. **Not a production setting.** |
| `examples/mNN_*.rs` | One binary per tutorial module. |
| `policies/mNN.yaml` | The APL each module loads. **These are yours to edit**; that is the point. Reset with `git checkout -- examples/tutorial/policies`. |
| `idp/` | `docker-compose.yml` + `realm-export.json` for the tutorial Keycloak. |

## The IdP

Modules 0–1 need no IdP. Module 2 onward resolve real tokens, so start Keycloak first:

```bash
docker compose -f examples/tutorial/idp/docker-compose.yml up -d   # ~30s first boot
docker compose -f examples/tutorial/idp/docker-compose.yml down    # resets everything
```

The identity, delegation and approval builtins reach Keycloak through the HTTP transport the host installs, and each of those plugins declares the `perform_http` capability in its policy. The tutorial transport allows private and loopback destinations because the IdP runs on `localhost`; a production host keeps the default (`cpex::install_default_http_transport`) or brings its own.

The realm takes a few seconds to import. Wait for it before running an IdP-backed module (a call returning `auth.jwks_unavailable` means it was still booting):

```bash
cargo run -p cpex-tutorial --example wait_for_idp   # blocks until the realm is serving
```

`make tutorial-check` runs this probe automatically before the IdP modules. Module 16 additionally needs the SPIRE overlay, which `make tutorial-check-spire` brings up. See [`idp/README.md`](idp/README.md) for the personas and how to mint a token by hand.

## Editing policy

From module 2 on you change `policies/*.yaml`, not Rust. Each policy file has a header explaining what to try. The harness reloads the file on each run (`cargo run ...`), so edit, re-run, observe.
