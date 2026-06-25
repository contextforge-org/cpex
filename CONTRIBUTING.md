# Contributing to CPEX

CPEX welcomes external contributions. If you have an itch, please feel free to
scratch it.

To contribute code or documentation, submit a [pull request](https://github.com/contextforge-org/cpex/pulls).
A good way to get familiar with the codebase is to tackle low-hanging fruit in
the [issue tracker](https://github.com/contextforge-org/cpex/issues). Before a
more ambitious contribution, please [open an issue](https://github.com/contextforge-org/cpex/issues)
first so the approach can be discussed — we want to avoid a situation where a
contribution requires extensive rework or cannot be accepted.

> **Note:** This branch (`0.2`+) is the **Rust** substrate. The legacy Python
> package is maintained on the [`0.1.x` branch](https://github.com/contextforge-org/cpex/tree/0.1.x);
> send Python fixes there.

## Prerequisites

- **Rust 1.96** — pinned in [`rust-toolchain.toml`](rust-toolchain.toml); `rustup`
  installs it (with `clippy`, `rustfmt`, `llvm-tools-preview`) automatically.
- **Go 1.25+** — only needed to build/test the Go bindings (`go/cpex`) and the
  Go demo (`examples/go-demo`).

## Development workflow

The [`Makefile`](Makefile) mirrors CI — a green `make ci` locally means a green
pipeline:

```bash
make lint            # rustfmt --check + clippy -D warnings
make test            # cargo test --workspace
make audit           # cargo deny check (advisories, licenses, bans, sources)
make coverage        # coverage summary (report only, no gate)
make examples-build  # build all Rust + Go examples — cheapest stale-API guard
make ci              # the full gate: lint + test + examples
```

Before submitting a PR, make sure `make ci` passes.

## Coding standards

- **Edition 2021**, MSRV **1.96**. Keep the toolchain, `clippy.toml` `msrv`, and
  `rust-version` in sync when bumping.
- **Formatting:** `cargo fmt` (config in [`rustfmt.toml`](rustfmt.toml)). CI runs
  `cargo fmt --all -- --check`.
- **Lints:** the workspace lint policy lives in `[workspace.lints]` in the root
  [`Cargo.toml`](Cargo.toml); each crate opts in with `[lints] workspace = true`.
  CI enforces it via `cargo clippy --workspace --all-targets -- -D warnings`.
  - Prefer `#[expect(..., reason = "…")]` over `#[allow(...)]` where practical.
  - Use `thiserror` for error types and `tracing` for runtime logging.
  - Use workspace dependencies (`x = { workspace = true }`) to keep versions
    consistent.
- **Lint ratchet:** many high-value lints (e.g. `missing_docs`, `doc_markdown`,
  `unwrap_used`, `uninlined_format_args`) are currently parked at `allow` with a
  `ratchet:` note because the pre-existing tree doesn't yet satisfy them. New
  code is encouraged to meet the higher bar; tightening a parked lint to `deny`
  (often a one-shot `cargo clippy --fix`) is a welcome focused PR.

### Source file headers

Each source file should carry an Apache-2.0 SPDX header. For Rust:

```rust
// Location: ./path/to/file.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Your Name
```

## crates.io publishing

The library crates publish to crates.io from the `release.yaml` workflow on a
`vX.Y.Z` tag, in dependency order. Internal dependencies carry both a `path`
and a `version`; when adding a new internal dependency, include the `version` so
the crate remains publishable. `cpex-ffi` is `publish = false` (distributed as
signed prebuilt artifacts).

## Legal — Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of Origin (DCO) 1.1](https://developercertificate.org/).
Sign off every commit to certify you wrote the patch or otherwise have the right
to submit it under the project's license:

```bash
git commit -s
```

This adds a `Signed-off-by` trailer:

```text
Signed-off-by: Jane Doe <jane.doe@example.com>
```

## Security

Do not report security vulnerabilities through public issues or PRs. See
[SECURITY.md](SECURITY.md) for private disclosure via GitHub's vulnerability
reporting.

## Communication

Connect with us through the [issue tracker](https://github.com/contextforge-org/cpex/issues).
