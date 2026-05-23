# cpex-dynamic-plugin

Load Rust CPEX plugins at runtime from `.so` / `.dylib` / `.dll`
files. Plugin authors write the same `async fn handle(...)` code
they would for an in-tree plugin; the only difference is the
plugin compiles as a `cdylib` and the host loads it via `libloading`.

**No serialization across the FFI boundary.** Payloads and
extensions cross as pointers through `Arc<dyn AnyHookHandler>` —
same in-memory representation in plugin and host. All immutability
guarantees, capability gating, monotonic-set protections, and
panic isolation from in-tree plugins apply identically. See
[`docs/specs/cpex-rust-spec.md` §17][spec-§17] for the architecture
rationale.

[spec-§17]: ../../docs/specs/cpex-rust-spec.md

---

## Quick start

### 1. Project layout

```
my-plugin/
├── Cargo.toml
└── src/
    └── lib.rs
```

A dynamic plugin is just a regular Cargo crate with `crate-type =
["cdylib"]`. Most plugins are a single source file plus the
manifest.

### 2. `Cargo.toml`

```toml
[package]
name = "my-rate-limiter"
version = "0.1.0"
edition = "2021"

[lib]
# `cdylib` is what the host dlopens. Add `rlib` too if other Rust
# crates need to depend on this plugin as a normal library (rare;
# usually only needed for the workspace-internal pattern where
# tests dev-depend on a plugin to trigger the cdylib build).
crate-type = ["cdylib"]

[dependencies]
# Both deps MUST be pinned to the same versions the HOST is built
# against. Same-version-only Rust ABI is the load-bearing constraint
# (see "ABI versioning" below).
cpex-core = "..."              # whatever your host uses
cpex-dynamic-plugin = "..."    # same
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
```

### 3. `src/lib.rs`

```rust
use std::sync::Arc;
use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::AnyHookHandler;

use cpex_dynamic_plugin::{cpex_dynamic_plugin, PluginRegistration};

/// Typed *view* of the same fields the operator put under
/// `config:` in their YAML — i.e. of `cfg.config`. We deserialize
/// once at construction so `handle()` doesn't re-parse JSON on
/// the hot path AND so structural mismatches surface as a
/// startup-time `InitializationError` instead of at first invoke.
///
/// This is **not** a separate config source. The operator only
/// ever writes one `config:` block per plugin; `ParsedConfig` is
/// just how this plugin chooses to materialize that block in
/// memory.
#[derive(serde::Deserialize)]
struct ParsedConfig {
    max_per_second: u32,
    #[serde(default = "default_burst")]
    burst: u32,
}

fn default_burst() -> u32 { 10 }

struct MyRateLimiter {
    /// The operator's `PluginConfig` as received. Kept around
    /// because the `Plugin::config()` trait method returns
    /// `&PluginConfig` — the executor needs it for capability
    /// gating, on_error policy, etc.
    cfg: PluginConfig,
    /// Cached typed view of `cfg.config`. Built once in `new()`.
    parsed: ParsedConfig,
    // ... any other runtime state: counters, expiry trackers, etc.
}

impl MyRateLimiter {
    /// Single constructor entry point. Follows the framework
    /// convention: plugin takes ONLY `PluginConfig` and derives
    /// all internal state from `cfg.config`. Operators never pass
    /// pre-built typed pieces; everything flows through the
    /// unified config pipeline.
    fn new(cfg: PluginConfig) -> Result<Self, String> {
        let raw = cfg
            .config
            .as_ref()
            .ok_or_else(|| "rate-limit plugin requires a `config:` block".to_string())?;
        // Deserialize cfg.config into the typed view. This is the
        // ONLY config materialization — operators don't supply
        // settings any other way.
        let parsed: ParsedConfig = serde_json::from_value(raw.clone())
            .map_err(|e| format!("invalid rate-limit config: {e}"))?;
        Ok(Self { cfg, parsed })
    }
}

#[async_trait]
impl Plugin for MyRateLimiter {
    fn config(&self) -> &PluginConfig { &self.cfg }
}

impl HookHandler<CmfHook> for MyRateLimiter {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // self.parsed.max_per_second is the same value the operator
        // wrote at `config.max_per_second` in YAML — just typed
        // and cached. No JSON parsing on the hot path.
        let _budget = self.parsed.max_per_second;
        // ... rate-limit logic ...
        PluginResult::allow()
    }
}

// The macro generates the `#[no_mangle] pub unsafe extern "C" fn
// cpex_plugin_create(...)` entry point. ABI handshake, config
// parsing, catch_unwind, and ownership transfer of the
// PluginRegistration are all handled inside the macro expansion.
cpex_dynamic_plugin! {
    |cfg: PluginConfig| -> Result<PluginRegistration, String> {
        let plugin = Arc::new(MyRateLimiter::new(cfg)?);
        let adapter: Arc<dyn AnyHookHandler> = Arc::new(
            TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)),
        );
        Ok(PluginRegistration::new(
            "my-rate-limiter",
            env!("CARGO_PKG_VERSION"),
            plugin as Arc<dyn Plugin>,
            vec![("cmf.tool_pre_invoke".to_string(), adapter)],
        ))
    }
}
```

### 4. Build

```sh
cargo build --release
```

Output lands at `target/release/libmy_rate_limiter.{so,dylib,dll}`
(Cargo converts hyphens to underscores in the artifact filename;
`lib` prefix appears on Unix, not Windows).

### 5. Use it

The operator references the plugin in unified-config YAML by its
absolute path:

```yaml
plugins:
  - name: rate-limit                # operator's name for the plugin
    kind: "lib:/opt/plugins/libmy_rate_limiter.so"
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_headers]
    config:
      max_per_second: 200            # ← the plugin reads these from cfg.config
      burst: 50                       # ← (deserialized once into ParsedConfig)
```

The host wires the factory once at startup:

```rust
mgr.register_factory_scheme(
    "lib",
    Box::new(cpex_dynamic_plugin::DynamicPluginFactory::new()),
);
mgr.load_config_file(Path::new("plugins.yaml"))?;
mgr.initialize().await?;
```

---

## Names and identifiers

Two `name` fields show up around a dynamic plugin, and they
serve different purposes. They can be the same string if you
want — but they don't have to be.

| Where | Set by | Used for |
|---|---|---|
| YAML `plugins[i].name:` (→ `PluginConfig.name`) | **Operator** | Operational identifier. Hook registration keys, per-plugin context state, error messages (`"plugin 'rate-limit' denied: ..."`), audit logs. The framework treats this as authoritative. |
| `PluginRegistration::new(name, ...)` (→ `PluginRegistration.name`) | **Plugin author** | Diagnostic-only self-report. Surfaces in the loader's `tracing::info!` line as `plugin_reported_name = "..."` so operators can sanity-check that the cdylib they loaded is the one they expected. The framework doesn't route on this. |

In Quick Start §3 / §5 the operator writes `name: rate-limit` in
YAML while the plugin author writes `"my-rate-limiter"` in
`PluginRegistration::new`. Both are fine — they're different
identifiers serving different concerns. Setting them to the same
string is also fine; many operators do exactly that for clarity.

**Two scenarios where keeping them distinct is useful:**

1. **Multiple operator-instances of the same plugin code.** An
   operator can load the same cdylib twice with different
   settings, each under its own operator name:

   ```yaml
   plugins:
     - name: rate-limit-api           # operator's name #1
       kind: "lib:/opt/plugins/libmy_rate_limiter.so"
       config: { max_per_second: 200 }

     - name: rate-limit-admin          # operator's name #2
       kind: "lib:/opt/plugins/libmy_rate_limiter.so"
       config: { max_per_second: 10 }
   ```

   Both load the same cdylib, both report
   `plugin_reported_name = "my-rate-limiter"`, but the
   operational identifiers stay distinct. Audit logs and
   per-plugin context state correctly attribute work to the
   right instance.

2. **Sanity-check at load time.** If the wrong `.so` got dropped
   into the plugins directory, the operator's name says
   "innocent-rate-limit" but the load log surfaces
   `plugin_reported_name = "evil-keylogger"`. Mismatch between
   the operator's expectation and the plugin's self-report is
   visible without grepping through binaries.

If those don't apply to you, just use the same string in both
places.

---

## Plugin construction convention

Plugins follow a single rule: **the constructor takes only
`PluginConfig`.** All runtime state is derived from `cfg.config`
inside `new()`. No alternate constructors that accept already-
built typed pieces.

**Why:** consistent instantiation via the unified-config pipeline.
The operator writes one YAML block; the host's factory
deserializes the `PluginConfig`; the plugin's `new()` extracts
and validates the typed config. Tests follow the same path —
construct a `PluginConfig` with the right `config:` value and
exercise `new()` like production code does. This catches
config-parsing regressions automatically.

**Don't do this:**
```rust
// ✗ separate typed parameters bypass the config-driven path
MyRateLimiter::new(cfg, max_per_second, claim_mapper)
```

**Do this:**
```rust
// ✓ everything flows through cfg.config
MyRateLimiter::new(cfg)
```

---

## Multiple handlers per plugin

A single plugin crate can register more than one handler. There
are two common patterns:

### Pattern A — one struct, multiple hook names (same `HookTypeDef`)

Most common for plugins that participate in multiple CMF phases
(pre + post, args + result). The same struct implements
`HookHandler<CmfHook>` once and is wired under multiple hook
names:

```rust
let plugin = Arc::new(MyPlugin::new(cfg)?);

let pre_adapter: Arc<dyn AnyHookHandler> = Arc::new(
    TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)),
);
let post_adapter: Arc<dyn AnyHookHandler> = Arc::new(
    TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)),
);

Ok(PluginRegistration::new(
    "my-plugin",
    env!("CARGO_PKG_VERSION"),
    plugin as Arc<dyn Plugin>,
    vec![
        ("cmf.tool_pre_invoke".to_string(), pre_adapter),
        ("cmf.tool_post_invoke".to_string(), post_adapter),
    ],
))
```

The operator's `hooks:` array in YAML lists which of the
registered hooks should actually fire for that plugin instance.

### Pattern B — multiple structs / multiple `HookTypeDef`s

If the plugin does conceptually different things at different
hooks (e.g., identity resolution AND CMF policy), wire each
behavior as its own struct + adapter. Each sub-struct still gets
the full `PluginConfig` and derives its own state from it:

```rust
let identity = Arc::new(MyIdentityResolver::new(cfg.clone())?);
let policy = Arc::new(MyPolicyGate::new(cfg.clone())?);

let id_adapter: Arc<dyn AnyHookHandler> = Arc::new(
    TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(&identity)),
);
let policy_adapter: Arc<dyn AnyHookHandler> = Arc::new(
    TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&policy)),
);

// Pick which one becomes the plugin's "primary" representation —
// usually the higher-level / authoritative one. PluginRegistration
// only carries a single Plugin handle; for plugins with multiple
// distinct components, use whichever you'd want surfaced in
// diagnostics.
Ok(PluginRegistration::new(
    "auth-bundle",
    env!("CARGO_PKG_VERSION"),
    identity as Arc<dyn Plugin>,
    vec![
        ("identity.resolve".to_string(), id_adapter),
        ("cmf.tool_pre_invoke".to_string(), policy_adapter),
    ],
))
```

### Selecting a specific handler from YAML

When a single cdylib registers multiple handlers but the operator
only wants one of them active for a given plugin entry, add a
fragment to the `kind:` string:

```yaml
plugins:
  # Same cdylib, two YAML entries, two handlers selected.
  - name: id
    kind: "lib:/opt/plugins/libauth_bundle.so#identity.resolve"
    hooks: [identity.resolve]
  - name: policy
    kind: "lib:/opt/plugins/libauth_bundle.so#cmf.tool_pre_invoke"
    hooks: [cmf.tool_pre_invoke]
```

The `#` fragment names the hook the operator wants kept; all
other handlers from the registration are filtered out. Without a
fragment, every registered handler is wired.

---

## Multiple plugins per cdylib

The `cpex_dynamic_plugin!` macro (singular) emits one plugin per
shared library. If you want to ship several unrelated plugins in
one binary — different code, different identities, different
versions — use the `cpex_dynamic_plugins!` macro (plural) instead.

### Why pick this over multi-handler?

The two shapes solve different problems:

| Shape | Macro | One PluginRegistration per | When |
|-------|-------|---------------------------|------|
| **Multi-handler** | `cpex_dynamic_plugin!` | cdylib (with many `(hook, handler)` pairs inside) | One plugin that participates in several lifecycle hooks. |
| **Multi-plugin** | `cpex_dynamic_plugins!` | `?entry=<name>` selector | Several genuinely distinct plugins packaged together for deployment convenience. |

Use multi-handler unless you specifically need multiple
*independent* plugins. The two shapes are not mutually exclusive —
each entry in a multi-plugin cdylib can itself register multiple
handlers.

### Plugin author side

```rust
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_dynamic_plugin::{cpex_dynamic_plugins, PluginRegistration};

fn build_rate_limiter(cfg: PluginConfig) -> Result<PluginRegistration, String> {
    // ... build and return PluginRegistration ...
#   unimplemented!()
}

fn build_audit(cfg: PluginConfig) -> Result<PluginRegistration, String> {
    // ... build and return PluginRegistration ...
#   unimplemented!()
}

cpex_dynamic_plugins! {
    rate_limiter => {
        name: "Rate Limiter",
        version: "1.0.0",
        description: "Token-bucket rate limiter",
        create: build_rate_limiter,
    },
    audit => {
        name: "Audit Logger",
        version: "0.5.0",
        description: "Writes hook events to disk",
        create: build_audit,
    },
}
```

The macro generates:

* One `cpex_plugin_create_<entry>` symbol per entry (the ident
  before `=>`). The host resolves these by composing the entry
  name from the operator's `?entry=<name>` URL.
* A `cpex_plugin_list` discovery symbol. Hosts read it to validate
  the operator's `?entry=` against the available entries up-front,
  so unknown entries get a friendly "available: [rate_limiter,
  audit]" error instead of a raw "symbol not found" from dlsym.

The entry name (`rate_limiter`, `audit`) MUST be a valid Rust
identifier — the macro requires that. It also has to be a valid C
identifier so the generated symbol name is well-formed; the host
validates the operator's `?entry=<value>` against
`[a-zA-Z_][a-zA-Z0-9_]*` before any symbol lookup.

### Operator side

Each entry is addressable from YAML via `?entry=<name>`:

```yaml
plugins:
  - name: edge-rate-limit
    kind: "lib:/opt/plugins/libmulti.so?entry=rate_limiter"
    hooks: [cmf.tool_pre_invoke]
    config:
      max_per_second: 100
  - name: audit-trail
    kind: "lib:/opt/plugins/libmulti.so?entry=audit"
    hooks: [cmf.tool_post_invoke]
    config:
      log_path: /var/log/cpex-audit.log
```

The shared library is `dlopen`'d once (the OS dedupes), but each
entry produces an independent `PluginInstance` with its own
config, name, and handler set.

URL component order is `<scheme>:<path>[?entry=<name>][#handler]`,
so `?entry=` and `#handler` can be combined for a multi-plugin
cdylib whose entries themselves register multiple handlers:

```yaml
kind: "lib:/opt/plugins/libmulti.so?entry=audit#cmf.tool_post_invoke"
```

### Single-plugin migration is opt-in

Cdylibs built with the singular `cpex_dynamic_plugin!` keep
working exactly as before — they export `cpex_plugin_create` with
no entry suffix, no manifest, and YAML keeps using
`kind: "lib:/path/foo.so"` with no `?entry=`. Nothing changes
unless you migrate to `cpex_dynamic_plugins!`. The two macros are
independent; pick one per cdylib based on whether you're shipping
one plugin or several.

---

## Plugin configuration

Plugins read their settings from `cfg.config` — the
`Option<serde_json::Value>` field on `PluginConfig`. Operators
populate it from the unified-config YAML's `config:` block:

```yaml
plugins:
  - name: rate-limit
    kind: "lib:/opt/plugins/librate_limit.so"
    config:                           # ← this is cfg.config
      max_per_second: 200
      burst: 50
      whitelist: ["10.0.0.0/8"]
```

There is only ever one place a plugin's settings live: `cfg.config`.
The pattern shown in Quick Start §3 (define `ParsedConfig`,
deserialize once in `new()`, store the typed view on `self`) is a
performance/ergonomics optimization — `ParsedConfig` is a *cached
typed view* of `cfg.config`, not a separate config channel.
Initialization errors (missing required fields, unparseable
values, etc.) — return `Err(String)` from `new()`. The
`cpex_dynamic_plugin!` macro propagates that into
`EntryPointResult::InitializationError`, which the host surfaces
via `PluginError::Config` with the cdylib path included in the
diagnostic.

---

## What does NOT go in `config:`

The operator's `kind:` string is the right place for loader
concerns, not the plugin's `config:` block. Specifically:

| Loader concern | Goes in `kind:` |
|---|---|
| Library path | `lib:/opt/plugins/foo.so` |
| Handler filter | `...#cmf.tool_pre_invoke` |

The reason: `config:` is plugin-specific config the plugin's own
typed view deserializes from. Mixing loader fields into it would
force plugins to know about the loader's reserved keys, and
operators would lose the natural separation between "where does
this plugin come from" (a deployment concern) and "how does this
plugin behave" (a runtime concern).

---

## ABI versioning and the same-version constraint

The Rust ABI is unstable across compiler versions and across
patch versions of dependencies. **The plugin's cdylib and the
host MUST be compiled against the same versions of:**

  * `cpex-core`
  * `cpex-dynamic-plugin`
  * The Rust compiler (`rustc --version`)

Mismatches are checked at load time via the
`cpex_dynamic_plugin::ABI_VERSION` constant. When the host's
`DynamicPluginFactory` calls into the plugin's entry point, the
plugin compares the host's reported `ABI_VERSION` to its own
compiled-against value and returns `EntryPointResult::AbiMismatch`
on disagreement. The host surfaces this as a `PluginError::Config`
with the actionable text: *"Rebuild the plugin against the same
cpex-core / cpex-dynamic-plugin versions the host is using."*

`ABI_VERSION` is bumped on any breaking change to:

  * the entry-point function signature
  * `PluginRegistration` field layout
  * `AnyHookHandler` trait shape
  * `Extensions` / `MessagePayload` layout

In practice this means a plugin built against `cpex-core 0.2.0`
won't load into a host running `cpex-core 0.3.0`. Operators
should rebuild plugins whenever they upgrade the host.

### Why no abi_stable

We considered `abi_stable` for true cross-version compatibility.
It adds significant surface (every trait needs `#[sabi_trait]`
wrappers, every type needs `StableAbi` derives) and changes the
plugin-author API. Same-version-only is the simpler default; we
can revisit if multi-vendor plugin marketplaces become a real
need.

---

## Error diagnostics

When a plugin fails to load, the host reports a `PluginError::Config`
with a human-readable message embedding the failure mode. Common
ones:

| Symptom | Cause | Fix |
|---|---|---|
| `failed to dlopen '<path>'` | File doesn't exist, wrong permissions, or wrong arch (e.g., x86_64 plugin on arm64 host). | Verify path, file mode, and `lipo -info <path>`. |
| `cdylib does not export 'cpex_plugin_create'` | Plugin doesn't use the `cpex_dynamic_plugin!` macro, or it's declared without `#[no_mangle] pub extern "C"`. | Use the macro; don't write the entry point by hand. |
| `cdylib was compiled against a different cpex-dynamic-plugin ABI version` | Plugin built against a different `cpex-core` / `cpex-dynamic-plugin` version than the host. | Rebuild the plugin against the host's exact dep versions. |
| `cdylib rejected its PluginConfig` | Operator's YAML has a structural mismatch with the plugin's expected config schema. | Check the plugin's documented config schema. |
| `cdylib failed to initialize` | Plugin's `new()` returned `Err(_)` (config validation, key load, network probe, etc.). | Check the cdylib's logs / stderr for the underlying error. |
| `cdylib panicked during construction` | Plugin code unwound inside `new()` or the macro closure. Caught at the FFI boundary, didn't crash the host. | Check the cdylib's logs / stderr for the panic backtrace. |
| `returned no handler named '<x>'` | The `#<name>` fragment in the kind selected a handler that the plugin didn't register. | Check the cdylib's documentation for which handler names it exposes, or omit the fragment to take all handlers. |

All errors include the operator-supplied plugin `name` and the
absolute library path for ops debugging.

---

## Limitations and trade-offs

* **Load-at-startup only.** No hot reload. Loaded libraries are
  leaked (`Box::leak`) and stay mapped until process exit. This
  is the standard Rust plugin-loader pattern (Bevy and others
  follow it). Hot reload requires reference-counting the library
  alongside all derived `Arc<dyn Plugin>` / `Arc<dyn
  AnyHookHandler>` references — out of scope for v0.
* **No sandbox.** Loaded plugins run in-process with full host
  privileges (file system, network, memory, syscalls). Operators
  vet plugins before deploying them. Capability gating still
  applies to extension access (just like in-tree plugins), but
  it does not stop a malicious plugin from making arbitrary
  syscalls.
* **Allocator.** Plugin and host must share an allocator. Both
  use `std::alloc::System` by default — don't override the
  allocator in your plugin (`#[global_allocator]`) unless the
  host uses the same one.
* **No nested `block_on`.** Async handlers must not `block_on`
  inside `handle()` — the future is already running on a tokio
  task, and nested blocking will panic. Same rule as in-tree
  plugins, but easier to forget when the plugin lives in another
  repo.
* **Same-version-only** (see "ABI versioning" above). Rebuild
  plugins on host upgrades.

---

## Reference examples

All under [`examples/`](./examples), each a standalone cdylib
crate built alongside this crate's integration tests:

* **[`single-plugin/`](./examples/single-plugin)** — minimal
  allow-everything plugin. The simplest possible `cpex_dynamic_plugin!`
  (singular) shape; ~50 lines. Start here.
* **[`multi-handler/`](./examples/multi-handler)** — one plugin
  with two handlers wired to different hooks (pre-invoke allow,
  post-invoke deny). Demonstrates Pattern A from the multi-handler
  section above.
* **[`multi-plugin/`](./examples/multi-plugin)** — two distinct
  plugins (allow + deny) packaged in one cdylib via
  `cpex_dynamic_plugins!` (plural). Operator selects via
  `?entry=allow` or `?entry=deny`.

## Tests

* `cargo test -p cpex-dynamic-plugin` — unit tests for the
  plugin-side ABI helpers and the kind-string parser (no
  dlopen involved).
* `cargo test -p cpex-dynamic-plugin --features host` — full
  suite including the dlopen integration tests that load every
  reference example above at runtime.
