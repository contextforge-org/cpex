# CPEX Core Examples

## plugin_demo

A complete end-to-end example showing how to build plugins, load config, and invoke hooks with the CPEX runtime.

### What it demonstrates

- **Defining hook types and payloads** — `ToolPreInvoke` and `ToolPostInvoke` hooks with a shared `ToolInvokePayload`
- **Building plugins** — three plugins (`IdentityResolver`, `PiiGuard`, `AuditLogger`) implementing `Plugin` + `HookHandler<H>` for different hook types
- **Multi-hook registration** — a single plugin instance (e.g., `IdentityResolver`) registered for multiple hooks (`tool_pre_invoke` and `tool_post_invoke`) via the factory pattern
- **Plugin factories** — `PluginFactory` implementations that create plugin instances and wire up typed handler adapters
- **YAML config loading** — `plugin_demo.yaml` declares plugins, policy groups, and routing rules
- **Policy groups and tag-based routing** — the `pii` policy group activates `PiiGuard` only for tools tagged with `pii`
- **Route resolution** — exact tool matches, wildcard catch-all, tag-driven plugin selection
- **PluginContext** — `global_state` used to pass PII clearance between hooks, `local_state` for per-plugin scratch data
- **BackgroundTasks** — fire-and-forget plugins (`AuditLogger`) spawn background tasks; `wait_for_background_tasks()` awaits them
- **PluginContextTable** — context table threaded from pre-invoke to post-invoke to preserve plugin state

### Running

From the workspace root:

```
cargo run --example plugin_demo
```

### Scenarios

The demo runs five scenarios against three registered plugins:

| Scenario | Tool | User | Outcome |
|----------|------|------|---------|
| 1 | get_compensation | alice (no clearance) | DENIED by pii-guard |
| 2 | get_compensation | alice (with clearance) | ALLOWED, then post-invoke fires |
| 3 | list_departments | bob | ALLOWED (no PII tag, pii-guard skipped) |
| 4 | some_other_tool | charlie | ALLOWED (wildcard route) |
| 5 | list_departments | (empty) | DENIED by identity-resolver |

### Files

- `plugin_demo.rs` — Rust source with plugins, factories, and main
- `plugin_demo.yaml` — YAML config with plugins, policy groups, and routes
