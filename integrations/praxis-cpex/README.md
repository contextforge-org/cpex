# praxis-cpex — Praxis HttpFilter that embeds CPEX/APL

In-process Praxis filter (`cpex`) that runs the CPEX/APL policy stack
on selected request paths. Ships as a separate workspace under
`integrations/` so the Praxis dep tree (Pingora, rustls, etc.) doesn't
slow down core CPEX iteration.

## Status

**Slice A: identity-only.** The filter:

1. Reads a bearer token from `Authorization` (configurable).
2. Resolves identity via the embedded `PluginManager` (today: JWT via
   `apl-identity-jwt`'s `identity/jwt` factory).
3. Continues on success; rejects with HTTP 401 + violation reason on
   failure.

Coming in later slices: APL policy evaluation (B), MCP body parsing
(C), delegation token attach (D), body rewriting (F), turnkey demo
(E). See `docs/praxis-cpex-filter-design.md` at the repo root.

## Prerequisites

- Rust toolchain (matches the parent CPEX workspace)
- **CMake** — required by `libz-ng-sys`, pulled transitively by Pingora
  via Praxis. On macOS: `brew install cmake`. On Debian/Ubuntu:
  `apt install cmake`.
- A C/C++ toolchain (Xcode CLT on macOS / `build-essential` on Linux)

## Layout

```
integrations/praxis-cpex/
├── Cargo.toml            # standalone workspace
├── filter/               # CpexFilter (impl HttpFilter)
├── bin/                  # praxis-cpex binary
└── examples/             # praxis.yaml + cpex.yaml + curl scenarios
```

## Build & run

```
cd integrations/praxis-cpex
cargo build --release -p praxis-cpex-bin

./target/release/praxis-cpex -c examples/praxis.yaml
```

## Praxis dep pin

Praxis is pinned to a known-good git rev (see workspace root
`Cargo.toml`). Praxis is pre-1.0 and uses a custom Pingora fork — no
crates.io release we can target by version today. Bump deliberately.
