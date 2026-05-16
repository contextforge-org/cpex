# CPEX × AuthBridge Integration

This integration embeds CPEX as a plugin runtime inside Kagenti's
[AuthBridge](https://github.com/kagenti/kagenti-extensions/tree/main/authbridge)
sidecar. AuthBridge sees one Go plugin (`cpex-runtime`); inside that plugin,
CPEX runs its own configurable chain of Rust plugins. Each CPEX sub-plugin
surfaces in AuthBridge's `abctl` Pipeline pane as if it were a native
AuthBridge plugin.

## Why this exists

AuthBridge has a Go plugin pipeline (`authlib/pipeline`) that runs at request
admission and at upstream-response time. Adding a new guardrail today requires
writing a Go plugin, rebuilding the sidecar image, and redeploying. This
integration lets a CPEX user drop in **Rust plugins, configured via YAML**,
inside the same pipeline — without rebuilding the sidecar after a CPEX plugin
is added (assuming dynamic loading; see "Future work" below).

For the v0 workshop demo:
- CPEX runtime is **statically linked** into a custom `cpex-authbridge-envoy`
  binary that replaces the standard `authbridge-envoy`.
- Two CPEX plugins ship in the image: `scope-tool-gate` and `llm-pii-redactor`.
- Plugin **selection and configuration** is YAML-driven via AuthBridge's
  `authbridge-runtime-config` ConfigMap. Image is rebuilt only when a new
  CPEX plugin is added.

## Layout

```
integrations/authbridge/
├── README.md                            # this file
├── ffi/                                 # Rust crate → libkagenti_cpex_ffi.a
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                       # kagenti_cpex_register_factories() entry
│       ├── scope_tool_gate.rs           # CPEX plugin: scope-based tool gating
│       └── llm_pii_redactor.rs          # CPEX plugin: regex PII redaction over LLM body
├── cpex-runtime/                        # Go module — AuthBridge plugin + custom binary
│   ├── go.mod
│   ├── plugin.go                        # implements pipeline.Plugin
│   ├── plugin_test.go
│   ├── bridge.go                        # pctx ↔ CPEX MessagePayload translation
│   ├── config.go                        # YAML config decode
│   └── cmd/cpex-authbridge-envoy/       # custom main that forks upstream main.go
│       └── main.go                      # +1 anonymous import for cpex-runtime
└── deploy/
    ├── Dockerfile                       # multi-stage build (Rust .a + Go binary)
    ├── plugins.yaml                     # sample chain configuration
    └── README.md                        # workshop deploy steps
```

## How it slots into AuthBridge

AuthBridge plugins register via Go's `init()` pattern — each plugin package's
init function calls `plugins.Register(name, factory)`, and the runtime looks
up plugins by name from the YAML config. There is no dynamic loading; the
plugin set is determined at compile time by which packages the binary
anonymously imports.

Our `cpex-runtime` package follows the same convention. To make AuthBridge
include it, we ship a **custom main.go** at
`cmd/cpex-authbridge-envoy/main.go` that's nearly identical to the upstream
`cmd/authbridge-envoy/main.go` — same listener, same lifecycle, same hot-
reload, same session API — with one extra anonymous import:

```go
_ "github.com/contextforge-org/contextforge-plugins-framework/integrations/authbridge/cpex-runtime"
```

The custom binary ends up containing **all** the standard AuthBridge plugins
*plus* `cpex-runtime`. Whether `cpex-runtime` actually fires for a request is
determined by the YAML config.

## YAML config shape

Add `cpex-runtime` to the appropriate AuthBridge pipeline direction (typically
outbound, since the demo redacts LLM prompt bodies):

```yaml
pipeline:
  outbound:
    plugins:
      - name: token-exchange
      - name: mcp-parser
      - name: inference-parser
      - name: cpex-runtime
        config:
          chain:
            - name: llm-pii-redactor
              config:
                patterns:
                  email: '\b[\w.+-]+@[\w-]+\.[\w.-]+\b'
                  ssn: '\b\d{3}-\d{2}-\d{4}\b'
            - name: scope-tool-gate
              config:
                tool_scopes:
                  get_weather: weather:read
```

The `chain:` array names CPEX sub-plugins. `cpex-runtime` walks the chain on
every request and emits one AuthBridge `Invocation` per sub-plugin — so
`abctl` shows each CPEX plugin as a Pipeline row with the standard action
verbs (`allow`/`deny`/`skip`/`modify`/`observe`).

## Build

See `deploy/Dockerfile`. Multi-stage:

1. **Rust stage:** `cargo build --release -p kagenti-cpex-ffi` →
   `libkagenti_cpex_ffi.a`
2. **Go stage:** `go build -o cpex-authbridge-envoy ./cmd/cpex-authbridge-envoy`
   with `CGO_LDFLAGS` pointed at the .a from stage 1
3. **Runtime stage:** copy the binary into AuthBridge's base image, keep the
   same entrypoint so the image is a drop-in replacement

## Deploy on Kind

```bash
docker build -t cpex-authbridge-envoy:demo -f integrations/authbridge/deploy/Dockerfile .
kind load docker-image cpex-authbridge-envoy:demo --name kagenti

# Patch the agent's envoy-proxy image to our custom build:
kubectl set image deployment/weather-service -n team1 envoy-proxy=cpex-authbridge-envoy:demo

# Edit AuthBridge config to enable cpex-runtime — see deploy/plugins.yaml for a sample.
```

The operator may reconcile the image reference back; in that case the image
needs to be set at the chart-value layer rather than via `kubectl set image`.
See `deploy/README.md` for the operator-friendly path.

## Future work

- **Dynamic CPEX plugin loading.** Replace the static-linking model with
  runtime `dlopen` of CPEX plugin shared objects. `cpex-runtime` would scan a
  configured directory (e.g. `/etc/cpex/plugins/*.so`) at boot, registering
  each via the FFI. Adding a guardrail then becomes "drop a .so file into a
  volume" — no image rebuild, no main.go fork. Out of scope for v0 because
  cgo + plugin loading + Kind image baking is a separate workstream.
- **Generic AuthBridge integration package.** If multiple host integrations
  want to embed CPEX (e.g. a langgraph runtime, a crewai runtime), promote
  the bridge translation out of `cpex-runtime` into a shared
  `cpex-go-integrations` helper crate.
- **Capability gating at the plugin boundary.** CPEX capability declarations
  (`read_subject`, `append_labels`, etc.) should drive Extension filtering
  when invoking sub-plugins. This needs the apl-cpex layer that's not yet
  built in the contextforge-plugins-framework workspace; tracked in the APL
  implementation memory.
