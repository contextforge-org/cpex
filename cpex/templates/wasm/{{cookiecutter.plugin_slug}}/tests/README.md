# {{ cookiecutter.plugin_name }}

{{ cookiecutter.description }}

A CPEX plugin compiled to a **WebAssembly Component Model** artifact.
Capability-sandboxed by default — the plugin can only do what its
manifest grants.

## What you get

```
{{ cookiecutter.plugin_slug }}/
├── plugin-manifest.yaml    # the deployment contract (sha256-pinned wasm)
├── config.yaml             # the cpex-side plugin entry that references it
├── wit/cpex-plugin.wit     # frozen WIT world — DO NOT EDIT
├── src/lib.rs              # your plugin logic
├── Cargo.toml              # cargo-component build config
├── Makefile                # build / sha-update / sign / test
├── tests/test_plugin.py    # host-side integration test
└── build/                  # output: .wasm artifact lives here
```

## Build

One-time toolchain setup:

```bash
make install-deps
```

Build the artifact and refresh the manifest hash:

```bash
make build manifest-sha
```

That produces `build/{{ cookiecutter.plugin_slug }}.wasm` and updates
`plugin-manifest.yaml`'s `artifact.sha256` so the host will accept it.

## Test

```bash
make test
```

This loads the built `.wasm` through cpex's `WasmPlugin` exactly the way
production would and exercises the hooks. Passing means the plugin
satisfies the `contextforge:cpex@0.1.0` contract end to end.

## Use in your application

Add this to your application's plugin config (or merge `config.yaml`):

```yaml
plugins:
  - name: "{{ cookiecutter.plugin_slug }}"
    kind: "wasm"
    hooks: ["tool_pre_invoke", "tool_post_invoke"]
    mode: sequential
    priority: 150
    config:
      manifest_path: "/path/to/{{ cookiecutter.plugin_slug }}/plugin-manifest.yaml"
      blocked_tools: ["rm", "sudo"]
```

That's it — the cpex `PluginManager` handles loading, registration,
sandboxing, and hook dispatch just like any other plugin kind.

## The contract

Two files together define what this plugin is:

1. **`wit/cpex-plugin.wit`** — the function-level interface the wasm
   component implements. This is the same file across every CPEX wasm
   plugin and MUST NOT be modified.

2. **`plugin-manifest.yaml`** — what this specific plugin does, which
   hooks it handles, and which host capabilities it needs.

Full spec: see `docs/specs/wasm-plugin-spec.md` in the cpex repo.

## Security model in one paragraph

The manifest's `capabilities:` list controls what the wasm runtime links
into the instance. A capability not listed is not linked. A function not
linked is not callable. There is no runtime permission check to bypass —
the host imports for ungranted capabilities physically do not exist in
the instance's address space. Zero-trust by construction.

## Editing this plugin

You edit:
- `src/lib.rs` — the plugin logic
- `plugin-manifest.yaml` — hooks, capabilities, limits, config schema
- `config.yaml` — deployment-time config

You do NOT edit:
- `wit/cpex-plugin.wit` — the frozen contract (replace with newer versions
  only when bumping `api_version`)

## License

{{ cookiecutter.author }} — pick an SPDX-compatible license.
