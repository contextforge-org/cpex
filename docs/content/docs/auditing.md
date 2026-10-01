---
title: "Auditing"
weight: 65
---

# Auditing

CPEX can audit its own enforcement — every allow, deny, and modify — plus the
irreversible effects (token mints, approval grants) that plugins cause. This is
the operator and developer guide: how to turn auditing on, what the records look
like, and how to write your own audit sink.

## What you get

- **Decision auditing** — one record per invocation with the verdict
  (allow / deny / modify), the ordered plugin steps, the request's trace span,
  and the taint labels. Unlike a plain observer plugin, this sees **denials**.
- **Effect auditing** — a separate, crash-safe record per irreversible external
  action (a token mint, an approval grant), written *ahead* of the act.
- **Provenance** (opt-in) — a content hash of the payload for tamper-evident,
  content-addressed lineage without storing the content itself.

Everything is opt-in: nothing changes until you declare a sink and (optionally)
turn on the effect log and content provenance.

## Quick start — a decision-audit sink

Declare the `audit-logger` builtin **with no `hooks:`**. That is what makes it a
decision-audit sink rather than a legacy post-hook observer:

```yaml
plugins:
  - name: audit-logger
    kind: audit/logger          # the builtin's registered kind
    # no hooks: → auto-attaches to the executor's verdict path
    config:
      destination: stderr       # stderr (default) | tracing  (target "apl.audit")
      source: "prod-gateway-1"  # optional label stamped on every record
```

That is the whole setup for decision auditing. The sink receives the finalized
decision record and the final extensions directly, so it needs no `read_*`
capabilities.

> **The one rule that trips people up.** The plugin auto-attaches as a sink
> *only when its `hooks:` list is empty*. If you list hooks on an audit plugin,
> it silently reverts to the **legacy** post-hook mode, which sees only
> *allowed* traffic and **misses every denial** — the exact gap this feature
> closes. **No hooks = sink.**

## Effect auditing

To record irreversible effects crash-safely, do two things: turn on the durable
write-ahead log, and grant the *causing* plugin the `emit_effect` capability.

```yaml
plugin_settings:
  effect_log_path: /var/lib/cpex/effects.wal   # turns on the write-ahead log (fail-closed)
  effect_log_compaction_threshold: 1024        # optional; default 1024, 0 disables

plugins:
  - name: audit-logger
    kind: audit/logger
    config: { destination: stderr }

  - name: oauth-delegator
    kind: delegator/oauth
    hooks: [token_delegate]
    capabilities: [emit_effect]                # ← lets its mints be audited write-ahead
    config: { token_endpoint: "https://idp…/token", client_id: "…" }
```

- **Without `effect_log_path`**, effect auditing is *ordering-only*: records
  still reach the sink, but are not crash-safe and the write-ahead is not
  fail-closed. This is the "basic logging" mode.
- **Without `emit_effect`** on the causing plugin, its effect calls are no-ops —
  its mints are not audited.

### Effect lifecycle

An effect moves through `prepared → confirmed | rejected | unknown`:

- `prepared` — intent durably recorded *before* the act (fail-closed: no durable
  record, no act).
- `confirmed` / `rejected` — the act completed / provably did not.
- `unknown` — the process crashed after the act, before recording the outcome.
  A failed call is recorded `unknown`, not `rejected` — it may still have landed
  at the participant.

### Recovery at startup

When an effect log is configured, the host runs recovery once at boot. It
compacts completed effects and surfaces any that crashed mid-flight, returning
the ones it could not resolve:

```rust
// Default: logs unresolved effects and leaves them `unknown`.
let unresolved = manager.recover_effects().await?;

// Or supply a reconciler that can confirm a mint against an issuance ledger
// by its key:
let unresolved = manager.recover_effects_with(&my_reconciler).await?;
```

Today an OAuth IdP offers no lookup by mint key, so the default reconciler logs
unresolved mints and leaves them `unknown` for an operator to investigate.

## Content provenance

```yaml
plugin_settings:
  capture_content_provenance: true   # executor hashes the payload at entry (sha256:…)
```

Opt-in, because hashing is on the request path. The executor hashes the payload
at pipeline entry; the sink hashes the output. **Only digests are kept, never
the content** — you get lineage and tamper-evidence without re-spilling the data
a PII scanner exists to redact. A payload type opts in to being hashable (the
CMF message payload does); others emit no hash.

## What a record looks like

With `destination: stderr` you get one JSON line per decision, and a separate
line per effect:

```jsonc
// decision
{
  "ts": "2026-08-14T…", "plugin": "audit-logger", "source": "prod-gateway-1",
  "subject": { "id": "alice@corp.com", "roles": ["hr"] },
  "verdict": { "deny": { "code": "missing_permission", "reason": "…" } },
  "decision_steps": [
    { "plugin": "pii-scanner", "phase": "Transform",  "action": "ModifiedPayload" },
    { "plugin": "cedar-pdp",   "phase": "Sequential", "action": "Denied" }
  ],
  "span":    { "trace_id": "…", "span_id": "…", "parent_span_id": "…" },
  "taint":   { "input": ["PII"], "final": ["PII", "secret"] },
  "content": { "input_hash": "sha256:…", "output_hash": "sha256:…" },
  "epoch": 1723680000000000000, "stream_id": "decision", "stream_seq": 413, "emission_seq": 913
}

// effect
{
  "ts": "2026-08-14T…",
  "effect": {
    "kind": "token_mint", "state": "confirmed", "key": "…",
    "caused_by": "oauth-delegator",
    "details": { "audience": "workday-api", "scope": "read_compensation" },
    "epoch": 1723680000000000000, "stream_id": "effect", "stream_seq": 7, "emission_seq": 912
  }
}
```

Fields appear only when present: `span` always; `taint` when labels exist;
`content` only when content provenance is enabled; `subject` when a subject is
resolved.

### Sequence numbers — completeness vs. order

Four fields — `epoch`, `stream_id`, `stream_seq`, `emission_seq` — let a
downstream store prove properties about the stream it received. Two are
**claims** a verifier checks; two **scope** those claims. Don't use one claim
for the other's job:

- `stream_seq` is a **completeness** claim. It is dense (gap-free) within its
  `(epoch, stream_id)`. **A gap means a record was dropped** — a consumer of one
  stream can prove nothing was silently lost.
- `emission_seq` is an **ordering** claim only. It is monotonic across *both*
  streams within an epoch, so a consumer that merges decisions and effects can
  reconstruct their interleave (an effect emits during a request, so it carries
  a lower `emission_seq` than the decision that closed the request). **A
  single-stream consumer sees it sparse by design — the gaps are the other
  stream's records, not a loss.** Do not detect loss from `emission_seq`.
- `stream_id` scopes `stream_seq` — it names the per-type stream, `"decision"`
  or `"effect"` (the entry-type a merged consumer keys on). Decisions and
  effects each get their own dense counter, so a consumer of just one still has
  gap-free completeness.
- `epoch` scopes both counters. It is the executor's boot time (Unix
  nanoseconds), so a *new, larger* value marks a restart: `stream_seq` proves
  completeness within an epoch, and across a restart the epoch changes, so a
  verifier tells a **counter reset from records lost** — and `(epoch,
  emission_seq)` is a total order across restarts. Detecting loss of the *tail*
  of a previous epoch (a crash between emit and persist) is not possible from
  the counters alone — that is what a durable sink (an append-only ledger) is
  for. **Assumption:** the host clock does not step backward across a restart
  (an NTP correction or VM snapshot restore). Because `epoch` is boot-time,
  a non-increasing value would make two boots share one chain scope; if you
  need strict monotonicity regardless of the clock, back it with a persisted
  counter or a ULID instead.

### Destinations

| `destination` | Behaviour |
|---|---|
| `stderr` (default) | One JSON line per record to stderr — grep / `jq` / forward. |
| `tracing` | Emitted via `tracing::info!` at target `apl.audit`; the host's subscriber routes it wherever traces go. |

## Writing a custom audit sink

The `audit-logger` is one implementation of the `AuditHandler` trait. Write your
own to forward audit to a SIEM, a schema like OCSF, or an internal event bus.
Depend on `cpex-core` for the traits.

An audit handler is **observation-only** — it is handed the finalized decision
and cannot influence it (its methods return nothing):

```rust
use std::sync::Arc;
use cpex_core::audit::AuditHandler;
use cpex_core::decision::DecisionLog;
use cpex_core::effect::EffectRecord;
use cpex_core::hooks::payload::{Extensions, PluginPayload};

struct MyAuditSink { /* destination handle, config, … */ }

#[async_trait::async_trait]
impl AuditHandler for MyAuditSink {
    // Called once per invocation, at the verdict — for allows, denies, and
    // modifies alike.
    async fn handle(&self, _payload: &dyn PluginPayload, ext: &Extensions, decisions: &DecisionLog) {
        let verdict = decisions.verdict();      // Allow | Deny(violation)
        let steps   = decisions.steps();        // what each plugin did
        let span    = decisions.span();         // trace_id / span_id / parent_span_id
        let labels  = decisions.input_labels(); // taint the request arrived with
        let hash    = decisions.input_hash();   // Some(..) when provenance is on
        let _ = (verdict, steps, span, labels, hash, ext);
        // build your event and ship it — do not block or mutate
    }

    // Optional: called per irreversible effect (token mint, approval grant).
    // Omit it if your sink only cares about decisions.
    async fn on_effect(&self, effect: &EffectRecord, _ext: &Extensions) {
        let _ = (&effect.kind, &effect.state, &effect.key, &effect.details);
        // e.g. emit a token mint as its own event
    }

    // Names the sink in error logs if it panics or times out.
    fn name(&self) -> &str { "my-audit-sink" }
}
```

Attach it in one of two ways:

**As a builtin plugin (config-driven).** Implement `Plugin` and return the sink
from `as_audit_handler` so the manager auto-attaches it when it is declared with
no hooks (exactly like `audit-logger`):

```rust
impl cpex_core::plugin::Plugin for MyAuditSink {
    fn config(&self) -> &cpex_core::plugin::PluginConfig { &self.cfg }

    fn as_audit_handler(self: Arc<Self>) -> Option<Arc<dyn AuditHandler>> {
        Some(self) // declare with no hooks → auto-attaches as a decision-audit sink
    }
}
```

Register a `PluginFactory` for it under a `kind`, and it configures like any
other builtin (see [Builtins]({{< relref "/docs/builtins" >}}) and
[Configuration]({{< relref "/docs/configuration" >}})).

**Programmatically (embedding).** Attach it directly to a running manager:

```rust
manager.register_audit_handler(Arc::new(MyAuditSink { /* … */ }));
```

Two rules the framework enforces so a sink can never harm a request: it receives
the decision record but it is **never on the plugin context** (a sink cannot see
or change another plugin's state through it), and a sink that panics or exceeds
its timeout is contained and logged — the request, whose verdict is already
decided, proceeds regardless.

### Sinks run on the request path — keep them cheap

`handle` and `on_effect` are **awaited** where the verdict (or effect) is
emitted, *before* the request returns — they are **not** fire-and-forget. That
is deliberate, and it is the property that makes the record trustworthy: a crash
cannot lose a verdict that was emitted, so a downstream evidence chain needs no
drop-detection for the steady state and can rely on this ordering. It is a
stable contract — changing it to fire-and-forget would silently break consumers
built on it.

The cost of that guarantee is that **sink latency is on the request path**
(bounded per sink by the plugin timeout, and sinks run one at a time). So keep
the work in a sink cheap — serialize, hash, append. A sink that does something
slow — a network call to a SIEM, a write to a remote ledger — should hand the
record to an **internal queue and return immediately**, doing the slow work on
its own side of the boundary rather than blocking the request.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Denials never appear in the log | The audit plugin has `hooks:` listed → legacy post-hook mode. Remove the hooks. |
| Effect records appear but aren't crash-safe | No `effect_log_path` set → ordering-only mode. |
| A plugin's mints aren't audited at all | The plugin is missing the `emit_effect` capability. |
| No `content` field | `capture_content_provenance` is off, or the payload type isn't hashable. |
| Mints stuck `unknown` after a restart | Expected with the default reconciler — no ledger to confirm them. Investigate, or wire a reconciler. |

## See also

- [Builtins]({{< relref "/docs/builtins" >}}) — the `audit/logger` builtin and the others.
- [Configuration]({{< relref "/docs/configuration" >}}) — the full config structure.
- [Extensions & Capability-Gating]({{< relref "/docs/extensions" >}}) — capabilities like `emit_effect`.
