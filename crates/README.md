# CPEX Rust crates

CPEX runs on the praxis-policy engine (PPE), consumed from crates.io at an
exact version pin. The engine, its APL layer and the bundled builtins are PPE
crates; this directory holds only what CPEX adds on top.

- `cpex`: host facade. Re-exports the public surface of `praxis-policy`
  (`PolicyEngine`, `install_builtins`, `prelude`, `AplOptions`, the builtin
  factories, `HyperTransport`), built with every stable builtin and the
  bundled hyper HTTP transport. The `python-host` feature adds the Python
  plugin host.
- `cpex-hosts-python`: runs existing Python plugins out-of-process, each in
  its own cached virtualenv, under the `isolated_venv` kind
  ([README](cpex-hosts-python/README.md)).
- `cpex-ffi`: C ABI over the engine, used by the Go package and the Go demo.

The Biscuit delegator lives in `builtins/plugins/delegator-biscuit`, and the
PyO3 bindings in `bindings/python`.

## Build and test

Requires the toolchain pinned in `rust-toolchain.toml`. From the repository
root:

```bash
cargo build -p cpex
cargo test -p cpex
```

## Quick example

```rust
use std::sync::Arc;
use cpex::PolicyEngine;

let engine = Arc::new(PolicyEngine::default());
cpex::install_builtins(&engine);
cpex::install_default_http_transport(&engine);
engine.load_config_yaml(yaml)?;
engine.initialize().await?;
```

`install_default_http_transport` refuses private and loopback destinations.
For a local IdP during development, install
`HyperTransport::new().with_allow_private_destinations()` with
`engine.set_http_transport(...)` instead; it opens every private address to
every outbound builtin, so keep it out of production.

Hook names, config keys and the plugin API follow PPE. See the PPE crate docs
for `praxis-policy` and `praxis-policy-core` for the full reference, the
[crate map](https://contextforge-org.github.io/cpex/docs/crates/) for what each
crate holds, and the
[migration guide](https://contextforge-org.github.io/cpex/docs/migration-0.3/)
for changes from 0.2.x.
