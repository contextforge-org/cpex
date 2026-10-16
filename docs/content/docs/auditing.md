---
title: "Auditing"
weight: 65
---

# Auditing

CPEX decides who may call which tool and what comes back. Auditing is the record of those decisions, and of the irreversible acts plugins perform to carry them out.

There are two records, and they answer different questions:

- A **decision** says how the pipeline ruled on one request: which plugins ran, what each did, and whether the request was allowed or blocked.
- An **effect** says what a plugin did to the outside world, such as minting a token at an IdP. Effects outlive the request and cannot be undone, so they are recorded separately and before the act.

Both are off until you configure them. A plugin behaves the same either way: turning auditing off loses the record, not the behavior.

## What each surface supports

| Feature | Rust | Python | Go |
|---|---|---|---|
| Effect log (`engine_settings.effect_log_path`) and recovery at `initialize` | yes | yes | yes |
| Content provenance digests, stream namespace | yes | yes | yes |
| Audit sinks (plugins that receive every decision and effect) | yes, see the note below | no | only through a Rust factory registered with `RegisterFactories` |
| Custom reconciler (`recover_effects_with`) | yes | no | no |

Engine settings are part of the policy document, so every surface reads them. Sinks are Rust plugins, and CPEX ships none: PPE's `audit/logger` is a reference plugin, not a builtin. A Rust host that wants it copies its source from the PPE repository into its own workspace, builds it against the `praxis-policy` facade, and registers it under a `kind` of its choosing.

**Sinks and routes in this release.** Under the default `dispatch: policy`, PPE 0.5.0 fails the load for any declared plugin that no step names, and that check includes sinks. A sink naming no hooks next to APL `routes:` fails with "no step names `<sink>`, so it can never run". Naming it with `run(<sink>)` does not help: the step has no handler to call, so the request is denied with `plugin:<sink>`. Until PPE changes this, a document with routes cannot attach a sink through `plugins:`. To log each call from policy, use a hook plugin that a step names, as the tutorial's [`tutorial/audit-line`]({{< relref "/docs/tutorial/04-effects" >}}) plugin does. Hosts on every surface can also log the `PipelineResult` each invocation returns, which carries the verdict and violation code.

## What the engine promises

A verdict that was reached is emitted once per invocation, at the engine's return points, and the record says what the caller was told. That includes requests the `assertions:` contract refused after the pipeline allowed them, and requests denied before the pipeline started because no route resolved.

When an effect log is configured, every completed act has a durable record of its intent. The intent is written and `fsync`ed before the act. If it cannot be written, the act does not happen. After a crash, an intent with no outcome means the act may or may not have happened, and the external system it was performed against (the participant, such as the IdP) is the one to ask.

Durable means written to the local filesystem and `fsync`ed, with the parent directory synced when the log is created. It does not mean replicated, and it is only as good as the storage under it.

A sink only observes. The extensions it receives are filtered against the capabilities its own `plugins:` entry declares, the same as any plugin. It never gets the HTTP transport without `perform_http`, and it cannot write effects.

## The effect log

```yaml
engine_settings:
  effect_log_path: /var/lib/cpex/effects.ndjson
  effect_log_compaction_threshold: 1024   # optional; 0 disables auto-compaction
```

With a path set, intent is recorded before a plugin acts. The file holds one JSON record per line. Once an effect has both an intent and an outcome, the pair is compacted away, so the file tracks what is in flight.

A crash can leave a final line cut short. Recovery discards that one line, since the act it guarded never proceeded. A bad line anywhere else is corruption, and recovery refuses to continue rather than drop a record of an irreversible act.

A Rust host that wires plugins in code can call `PolicyEngine::set_effect_log` before `initialize`. That does not survive `load_config`, so a log that must outlive a reload belongs in the document.

### Effect states

| State | Meaning |
|---|---|
| `prepared` | Intent recorded. Nothing external has happened yet. |
| `confirmed` | The act completed. |
| `rejected` | The act provably did not happen. |
| `unknown` | Nobody can say. Reconcile it. |

The OAuth delegator records every failed mint as `unknown`, including a 4xx with an OAuth error body: the transport cannot prove the authorization server sent it, and a timed-out call may still have landed. Only a check against an authoritative participant can record `rejected`.

### Which modes may act

Only `sequential` and `transform`. A plugin in any other mode that tries to perform an effect is refused with a violation naming the plugin, the mode and the key to change. Concurrent branches can be cancelled, `audit` is read-only, and `fire_and_forget` runs after the verdict, so an act there would happen for work the pipeline threw away. A plugin also cannot perform an effect on a clone of its extensions.

### Recovery

`initialize` sweeps the log once, before traffic. Completed effects are compacted away and the rest go to the reconciler. The default reconciler connects to nothing: it leaves each orphaned effect `unknown` and reports it at startup with its key and plugin. OAuth has no standard endpoint to ask whether a token was issued, so for the OAuth delegator that is usually the end of it. Its `idempotency_header:` setting names a vendor header for an IdP that supports one.

A Rust host with an authoritative issuance ledger implements `EffectReconciler` and calls `PolicyEngine::recover_effects_with`. Calling `recover_effects` again while serving is safe: the engine skips keys it has an act open on.

## Content provenance

A decision record says which plugins ran, not whether they changed the request. A content hash answers that without the record holding either version: a keyed digest of the payload at entry and again at emission. Equal digests mean nothing changed the content.

The digest is HMAC-SHA256 under a secret you declare, because a plain hash of short content can be guessed:

```yaml
engine_settings:
  capture_content_provenance: true
  content_provenance_key: provenance_key
secrets:
  providers:
    local: { kind: file, base_dir: /etc/cpex }
  values:
    provenance_key: { provider: local, ref: provenance.key }
```

```sh
openssl rand -base64 48 > /etc/cpex/provenance.key
```

The key must be at least 32 bytes. Digests read `hmac-sha256:<key_id>:<hex>`, and two digests compare only when their key ids match. A `file` key rotates when the host refreshes secrets (`refresh_secrets` in Python, `RefreshSecrets` in Go, `PolicyEngine::refresh_secrets` in Rust); an `env` key rotates only with a restart. Engines writing into one audit stream should share a key.

The Python and Go bindings install the `env`, `file` and `vault` secret providers for you. A Rust host installs a registry with `PolicyEngine::set_secret_providers` before `initialize`, for example `SecretProviderRegistry::with_builtin_backends()`. Without one, `initialize` fails naming the missing kind.

For development, `content_provenance_key: unkeyed` records plain SHA-256 and warns at every load. Turning provenance on with no key fails to load. Only CMF `MessagePayload`s are digested.

## Stream position

```yaml
engine_settings:
  audit_stream_namespace: gw-1
```

Stream ids become `gw-1:decision` and `gw-1:effect`, so one collector can tell processes apart. Each record carries `epoch`, `stream_id`, `stream_seq` and `emission_seq`. Use `stream_seq` to detect loss within one `(epoch, stream_id)`, and `emission_seq` to merge the two streams in order. A smaller `stream_seq` under a larger `epoch` is a restart, not a gap.

## Writing a sink in Rust

Any plugin becomes a sink by overriding `Plugin::as_audit_handler`. `handle` receives every decision; `on_effect` receives every effect transition and defaults to ignoring them.

```rust
use std::sync::Arc;

use async_trait::async_trait;
use cpex::praxis_policy_core::audit::AuditHandler;
use cpex::praxis_policy_core::decision::{DecisionLog, Verdict};
use cpex::praxis_policy_core::effect::EffectRecord;
use cpex::praxis_policy_core::hooks::payload::{Extensions, PluginPayload};
use cpex::prelude::{Plugin, PluginConfig};

struct DecisionSink {
    cfg: PluginConfig,
}

#[async_trait]
impl AuditHandler for DecisionSink {
    async fn handle(
        &self,
        _payload: &dyn PluginPayload,
        _extensions: &Extensions,
        decisions: &DecisionLog,
    ) {
        let blocked = matches!(decisions.verdict(), Some(Verdict::Deny(_)));
        eprintln!("{} blocked={blocked}", self.cfg.name);
    }

    // Optional. Effects only reach a sink that wants them.
    async fn on_effect(&self, _effect: &EffectRecord, _extensions: &Extensions) {}

    fn name(&self) -> &str {
        &self.cfg.name
    }
}

#[async_trait]
impl Plugin for DecisionSink {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }

    fn as_audit_handler(self: Arc<Self>) -> Option<Arc<dyn AuditHandler>> {
        Some(self)
    }
}
```

Its factory returns a `PluginInstance` with no handlers. A sink fires for every hook family, so `payload` is not always a CMF `MessagePayload`: downcast and handle the other case.

The engine awaits every sink before it returns, so sink latency is request latency. A sink that writes to the network should queue the record and return. Each call is bounded by `engine_settings.audit_timeout_milliseconds` (100 ms by default), and a sink that fails or panics is logged and skipped.

Grant a sink exactly the capabilities for what it records (`read_subject`, `read_client`, `read_labels`, `read_delegated_tokens` and so on). A sink with none still emits a record per invocation, with the gated fields missing, and a reader cannot tell "no delegation happened" from "the sink could not see it".

## Troubleshooting

- `delegation.effects_not_permitted` or `effect_phase_not_permitted`: the plugin's mode cannot perform irreversible acts. Set `mode:` to `sequential` or `transform`.
- `effect_extensions_detached`: the plugin called `perform_effect` on a copy of its extensions.
- `delegation.effect_log_failed`: the intent could not be written. Check that the path is writable. The delegation is denied rather than minting a credential nothing accounts for.
- Unresolved effects at startup: expected with the default reconciler. Each names its key and plugin.

## Go deeper

- PPE's [auditing guide](https://github.com/praxis-proxy/policy/blob/v0.5.0/docs/content/auditing.md), the source for this page, with the full record schemas and the effect protocol for plugin authors (`perform_effect`, `begin_effect`, `complete_effect`).
- [Header Assertions]({{< relref "/docs/assertions" >}}): the contract that can refuse a request after the pipeline.
- [Configuration]({{< relref "/docs/configuration" >}}): the `secrets:` block.
