// Location: ./crates/cpex-core/src/effect.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// EffectRecord — an irreversible external effect a plugin *causes* (a token
// mint, an approval grant), audited as its own event, distinct from a
// pipeline decision.
//
// Effects follow a small transaction lifecycle:
//
//     prepared -> confirmed | rejected | unknown
//
// `prepared` means CPEX has *durably recorded the intent* to attempt the
// action and nothing external has happened yet; the terminal states record
// the outcome, or `unknown` after a crash (resolved later by reconciling
// against the participant — e.g. the IdP — via the record's `key`). This is
// the write-ahead model in docs/step5-effect-audit-options.md (Option C).
//
// This module holds the effect types and lifecycle (`EffectRecord`,
// `EffectState`), the `EffectEmitter` / `DurableEffectLog` traits, and the
// file-backed write-ahead log (`FileEffectLog`). Framework-mediated effect
// primitives (v2) are a later slice.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::PluginError;
use crate::hooks::payload::Extensions;

/// Where an effect is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EffectState {
    /// Intent durably recorded; nothing external has happened yet.
    Prepared,
    /// The external act completed.
    Confirmed,
    /// The external act provably did not happen.
    Rejected,
    /// Crashed after acting, before the outcome was recorded. Resolved by
    /// reconciling against the participant via `EffectRecord::key`.
    Unknown,
}

/// A record of an irreversible external effect — emitted to audit sinks as
/// its own event. The causing plugin fills the descriptive fields; the
/// framework stamps `plugin_name`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EffectRecord {
    /// Machine-readable kind, e.g. `"token_mint"`, `"approval_grant"`.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// Idempotency / reconciliation key threaded into the external call, so
    /// an `unknown` outcome can be resolved against the participant later.
    /// Must be **unique per attempt** — recovery resolves keys across the
    /// whole WAL, so a key reused across retries would let an earlier
    /// attempt's terminal record mask a later attempt's orphan (see
    /// [`FileEffectLog::recover`]).
    pub key: String,
    /// Where in its lifecycle this record is.
    pub state: EffectState,
    /// Structured, effect-specific detail (audience, scopes, ttl, …).
    pub details: HashMap<String, serde_json::Value>,
    /// Which plugin caused the effect. Set by the framework, not self-reported.
    pub plugin_name: Option<String>,
    /// The executor's boot time (Unix nanoseconds), scoping the sequences so a
    /// verifier tells a counter reset (new, larger epoch) from records lost.
    /// Ordered, so `(epoch, emission_seq)` totally orders records across
    /// restarts. Stamped at emission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// The per-type stream this record belongs to (`"effect"`). Stamped at
    /// emission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    /// **Completeness** counter — dense within `(epoch, stream_id)`; a gap means
    /// an effect record was dropped. Stamped at emission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_seq: Option<u64>,
    /// **Ordering** counter — monotonic across decisions and effects within the
    /// epoch, for interleaved order. Sparse for an effects-only consumer by
    /// design; not a loss signal. Stamped at emission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emission_seq: Option<u64>,
}

impl EffectRecord {
    /// A fresh `prepared` record — the intent, before the act. `key` is the
    /// idempotency/reconciliation key that will ride into the external call.
    pub fn prepared(
        kind: impl Into<String>,
        description: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
            key: key.into(),
            state: EffectState::Prepared,
            details: HashMap::new(),
            plugin_name: None,
            epoch: None,
            stream_id: None,
            stream_seq: None,
            emission_seq: None,
        }
    }

    /// Attach a structured detail (builder-style).
    pub fn with_detail(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Move to a terminal state (`Confirmed` / `Rejected` / `Unknown`).
    pub fn into_state(mut self, state: EffectState) -> Self {
        self.state = state;
        self
    }
}

/// A per-invocation capability handle for emitting effects, granted to
/// plugins with the `emit_effect` capability. It rides on `Extensions`
/// exactly like the write tokens: `filter_extensions` never sets it; the
/// executor does, for capable plugins, right before `handle`. Calling it
/// fans the record out to the auto-attached audit sinks' `on_effect`.
///
/// Slice 2 emits (write-ahead *ordering*); it is not yet *durable* — the WAL
/// and fail-closed prepare are a later slice.
#[async_trait]
pub trait EffectEmitter: Send + Sync + std::fmt::Debug {
    /// Durably record `effect`, then fan it out to the audit sinks. `ext`
    /// supplies ambient context (identity, delegation, correlation).
    ///
    /// **Fail-closed:** an `Err` means the record could not be durably
    /// persisted, so the caller must **not** perform the irreversible act.
    /// (With no durable log configured, this is ordering-only and returns
    /// `Ok` after emitting — slice 3b installs the real WAL.)
    async fn emit(&self, effect: &EffectRecord, ext: &Extensions) -> Result<(), Box<PluginError>>;
}

/// The slot on `Extensions` that holds the per-invocation effect-emitter
/// capability handle.
///
/// This is a newtype around `Option<Arc<dyn EffectEmitter>>` for one reason:
/// the inner `Arc` must be *unextractable* by plugins. A bare public field would
/// let a capable plugin (a delegator, say) stash the `Arc` and later call
/// `emit` **outside any invocation, with a fabricated `Extensions`** — forging
/// the identity/correlation the emitter trusts for provenance. For a log whose
/// purpose is reconstructing a causal graph, a forged record is worse than a
/// missing one: a gap is visible, a forgery is not.
///
/// So the field stays `pub` (functional-update `..` construction at the many
/// `Extensions` build sites still compiles), but the payload is private. The
/// only ways to *reach* the emitter are the crate-internal [`Self::emitter`]
/// accessor — used exclusively by `Extensions::begin_effect` /
/// `complete_effect`, which always pass the real `self` — so a plugin can
/// trigger `emit` only against the genuine, current `Extensions`, never a
/// handcrafted one. This gives the emitter the same *isolation by construction*
/// the `DecisionLog` gets by type, rather than the weaker isolation-by-capability
/// a retainable handle would give.
///
/// The slot is deliberately **not** `Clone`: with the field `pub`, a `Clone`
/// slot could be cloned out of the `&Extensions` a plugin receives in `handle`,
/// stashed, and replayed later on a handcrafted `Extensions` — the private inner
/// `Arc` rides along in the clone, so hiding it behind the newtype is not enough
/// on its own. That is exactly the forgery this type exists to prevent, so the
/// clone path must not exist. `handle` only ever holds `&Extensions`, and
/// `Extensions::clone` resets the slot to empty, so nothing legitimate needs to
/// clone it. The `compile_fail` test below pins the property against regression.
///
/// ```compile_fail
/// use cpex_core::effect::EffectEmitterSlot;
/// use cpex_core::extensions::Extensions;
/// let ext = Extensions::default();
/// let _stashed: EffectEmitterSlot = ext.effect_emitter.clone();
/// ```
#[derive(Debug, Default)]
pub struct EffectEmitterSlot(Option<Arc<dyn EffectEmitter>>);

impl EffectEmitterSlot {
    /// An empty slot — the plugin was not granted the `emit_effect` capability.
    pub fn empty() -> Self {
        Self(None)
    }

    /// A slot holding a live emitter, installed by the executor for a capable
    /// plugin right before `handle`.
    pub fn installed(emitter: Arc<dyn EffectEmitter>) -> Self {
        Self(Some(emitter))
    }

    /// Whether a capability handle is present (i.e. the plugin may emit).
    pub fn is_available(&self) -> bool {
        self.0.is_some()
    }

    /// Crate-internal access to the emitter. Deliberately not `pub`: the whole
    /// point of the newtype is that no plugin can extract the `Arc`.
    pub(crate) fn emitter(&self) -> Option<&Arc<dyn EffectEmitter>> {
        self.0.as_ref()
    }
}

/// Resolves an effect left `unknown` after a crash by asking an authoritative
/// issuance ledger whether the act identified by `EffectRecord::key` actually
/// happened. The `EffectRecord` is self-describing (kind, key, details), so a
/// reconciler just reads those fields and performs a keyed lookup — it needs no
/// knowledge of which plugin caused the effect. Returns a terminal state, or
/// `Unknown` when the ledger can't say, so the record is retried on a later
/// sweep.
///
/// Most effects have no queryable ledger (an OAuth IdP, for instance, exposes
/// no lookup by mint key), so [`LogUnknownsReconciler`] is the default.
#[async_trait]
pub trait EffectReconciler: Send + Sync {
    async fn reconcile(&self, effect: &EffectRecord) -> EffectState;
}

/// The default [`EffectReconciler`]: there is no ledger to query, so it logs
/// each unresolved effect and leaves it `unknown` for an operator to
/// investigate. This is the honest, correct behavior for every effect whose
/// participant exposes no keyed lookup — which today is all of them. A real
/// reconciler (e.g. against a mandate server that owns issuance) queries the
/// ledger by `EffectRecord::key`; nothing about it is plugin-specific.
#[derive(Debug, Default)]
pub struct LogUnknownsReconciler;

#[async_trait]
impl EffectReconciler for LogUnknownsReconciler {
    async fn reconcile(&self, effect: &EffectRecord) -> EffectState {
        tracing::warn!(
            effect_key = %effect.key,
            kind = %effect.kind,
            plugin = effect.plugin_name.as_deref().unwrap_or("?"),
            "effect left unresolved after a crash; no ledger to reconcile it — \
             leaving `unknown` for investigation"
        );
        EffectState::Unknown
    }
}

/// A durable, append-only sink for effect records — the write-ahead log.
/// `append` must not return `Ok` until the record is durably persisted; an
/// `Err` means the caller must **not** perform the irreversible act
/// (fail-closed). `FileEffectLog` is the file-backed implementation.
#[async_trait]
pub trait DurableEffectLog: Send + Sync {
    async fn append(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>>;

    /// Recover after a restart: compact completed effects and reconcile the
    /// unresolved ones against `reconciler`, recording each confirmed/rejected
    /// outcome durably. Returns the effects still `unknown` (the participant
    /// couldn't say) for a later sweep. Default: a no-op — for logs with no
    /// recoverable on-disk state.
    async fn recover_and_reconcile(
        &self,
        _reconciler: &dyn EffectReconciler,
    ) -> Result<Vec<EffectRecord>, Box<PluginError>> {
        Ok(Vec::new())
    }
}

/// A file-backed, append-only write-ahead log for effect records — the
/// durable sink behind `ext.begin_effect`. Each record is appended as one
/// JSON line and `fsync`'d before `append` returns, so a `prepared` intent is
/// on stable storage *before* the irreversible act. `append` returns `Err`
/// (fail-closed) whenever the record cannot be durably persisted, which is
/// what stops the act from proceeding.
///
/// The append + `fsync` run on a blocking thread (`spawn_blocking`): tokio's
/// `fs` feature is not enabled, and a synchronous `fsync` must never stall an
/// async worker. Concurrent appends are safe — `O_APPEND` makes each write
/// land atomically at the end of the file. v1 opens the file per append;
/// effects are rare (token mints, approval grants), so the open cost is not a
/// hot path, and a pooled handle can be a later optimization.
/// Default number of appends between automatic compactions. Effects are rare,
/// so this bounds the file to roughly this many records between compactions
/// without paying a rewrite on every write.
const DEFAULT_COMPACTION_THRESHOLD: usize = 1024;

#[derive(Debug, Clone)]
pub struct FileEffectLog {
    path: Arc<std::path::PathBuf>,
    /// Serializes appends. `O_APPEND` already makes each write's *positioning*
    /// atomic, but `write_all`'s partial-write loop leaves a narrow window
    /// where two concurrent writers could interleave a record. One writer at a
    /// time closes it and gives a deterministic on-disk order (what the
    /// recovery sweep reads back). Effects are rare, so contention is
    /// negligible. Cloned handles share the lock, since they share the file.
    write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Appends since the last compaction. Shared across cloned handles (they
    /// share the file). When it crosses `compaction_threshold`, `append`
    /// triggers a compact-only `recover()` to bound the file.
    appends_since_compaction: Arc<AtomicUsize>,
    /// Auto-compaction fires after this many appends. `0` disables it —
    /// compaction then happens only on an explicit `recover()`.
    compaction_threshold: usize,
}

impl FileEffectLog {
    /// A WAL that appends to `path`, creating the file if it does not exist.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            appends_since_compaction: Arc::new(AtomicUsize::new(0)),
            compaction_threshold: DEFAULT_COMPACTION_THRESHOLD,
        }
    }

    /// Override the append count that triggers automatic compaction. `0`
    /// disables auto-compaction (compaction then happens only on an explicit
    /// `recover()`).
    pub fn with_compaction_threshold(mut self, threshold: usize) -> Self {
        self.compaction_threshold = threshold;
        self
    }
}

#[async_trait]
impl DurableEffectLog for FileEffectLog {
    async fn append(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>> {
        // Serialize on the async thread (cheap, no I/O); do the blocking
        // append + fsync off the async worker pool.
        let mut line = serde_json::to_vec(effect)
            .map_err(|e| wal_error("serialize effect record", Some(Box::new(e))))?;
        line.push(b'\n');

        let path = Arc::clone(&self.path);
        // Write under the lock, then release it *before* any compaction:
        // `recover()` re-acquires this same lock, so holding it here would
        // deadlock. Serialized so records never interleave.
        {
            let _guard = self.write_lock.lock().await;
            tokio::task::spawn_blocking(move || -> Result<(), Box<PluginError>> {
                use std::io::Write as _;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path.as_ref())
                    .map_err(|e| wal_error("open WAL", Some(Box::new(e))))?;
                file.write_all(&line)
                    .map_err(|e| wal_error("write WAL record", Some(Box::new(e))))?;
                // The durability barrier: the record is on stable storage
                // before this returns Ok — and therefore before the caller acts.
                file.sync_all()
                    .map_err(|e| wal_error("fsync WAL", Some(Box::new(e))))?;
                Ok(())
            })
            .await
            .map_err(|e| wal_error("WAL append task failed", Some(Box::new(e))))??;
        }

        // Auto-compaction: once appends since the last compaction cross the
        // threshold, run compact-only `recover()` — safe at runtime, since it
        // keeps in-flight `prepared` records and only drops matched pairs — to
        // bound the file. Threshold 0 disables it. A compaction failure is
        // logged, never fatal: the record above is already durable, so the
        // append itself succeeded and must not report fail-closed.
        if self.compaction_threshold != 0 {
            let n = self
                .appends_since_compaction
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            if n >= self.compaction_threshold {
                self.appends_since_compaction.store(0, Ordering::Relaxed);
                if let Err(e) = self.recover().await {
                    tracing::warn!("effect WAL auto-compaction failed: {e}");
                }
            }
        }

        Ok(())
    }

    async fn recover_and_reconcile(
        &self,
        reconciler: &dyn EffectReconciler,
    ) -> Result<Vec<EffectRecord>, Box<PluginError>> {
        // Compact completed effects, then ask the participant about each
        // survivor. A confirmed/rejected answer is recorded so the following
        // compaction drops the pair; an `unknown` answer is left for later.
        let summary = self.recover().await?;
        let mut resolved_any = false;
        let mut still_unknown = Vec::new();
        for rec in summary.unresolved {
            match reconciler.reconcile(&rec).await {
                state @ (EffectState::Confirmed | EffectState::Rejected) => {
                    self.append(&rec.clone().into_state(state)).await?;
                    resolved_any = true;
                },
                // Still `unknown` (or `prepared`) — keep it for the next sweep.
                _ => still_unknown.push(rec),
            }
        }
        if resolved_any {
            // A second pass compacts the just-resolved matched pairs out.
            self.recover().await?;
        }
        Ok(still_unknown)
    }
}

/// Build the `PluginError` a durable-write failure surfaces. `begin_effect`
/// treats any `Err` from the WAL as fail-closed, so this is the error that
/// prevents an irreversible act from proceeding.
fn wal_error(
    what: &str,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
) -> Box<PluginError> {
    PluginError::Execution {
        plugin_name: "effect-wal".into(),
        message: format!("effect WAL: {what}"),
        source,
        code: Some("effect_wal_failed".into()),
        details: HashMap::new(),
        proto_error_code: None,
    }
    .boxed()
}

/// The result of a recovery sweep over a [`FileEffectLog`].
#[derive(Debug, Default)]
pub struct RecoverySummary {
    /// Number of effects that completed — a `prepared` matched by a terminal
    /// (`confirmed`/`rejected`) record — and were compacted out of the log.
    pub compacted: usize,
    /// Effects with no terminal record: `prepared`-without-outcome (an act that
    /// may or may not have happened before a crash) or an explicit `unknown`.
    /// Each needs reconciliation against the participant (the IdP) via its
    /// `key`. They are retained in the rewritten log.
    pub unresolved: Vec<EffectRecord>,
}

impl FileEffectLog {
    /// Recover after a restart: read the WAL, drop completed effects (a
    /// `prepared` matched by a terminal record), and atomically rewrite the
    /// file with only the unresolved records — `prepared`-without-terminal or
    /// `unknown`. Returns those unresolved records so the caller can reconcile
    /// them against the participant (the IdP) via each record's `key`. This is
    /// the compaction that bounds WAL growth (design §6.1) and the entry point
    /// for crash recovery. Idempotent; a missing file is a no-op.
    pub async fn recover(&self) -> Result<RecoverySummary, Box<PluginError>> {
        let path = Arc::clone(&self.path);
        // Serialize against appends while we read + rewrite the log.
        let _guard = self.write_lock.lock().await;
        tokio::task::spawn_blocking(move || -> Result<RecoverySummary, Box<PluginError>> {
            // A missing log means nothing to recover.
            let data = match std::fs::read_to_string(path.as_ref()) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RecoverySummary::default())
                },
                Err(e) => return Err(wal_error("read WAL for recovery", Some(Box::new(e)))),
            };

            // Parse every record in append order.
            let mut records: Vec<EffectRecord> = Vec::new();
            for (i, line) in data.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let rec = serde_json::from_str(line).map_err(|e| {
                    wal_error(&format!("parse WAL line {}", i + 1), Some(Box::new(e)))
                })?;
                records.push(rec);
            }

            // A key is resolved iff some record for it reached a terminal
            // state. Everything else (prepared-only, unknown) is unresolved.
            //
            // INVARIANT: a `key` is a unique per-attempt id, not a reused
            // idempotency key. Resolution matches across the whole file, so a
            // plugin that reused one stable key across retries would let a
            // terminal record from an earlier attempt mask a later attempt's
            // orphaned `prepared` as resolved. The OAuth delegator satisfies
            // this with a fresh UUID per mint; a future plugin that wants
            // stable idempotency keys must add per-attempt scoping here (e.g.
            // an attempt counter alongside the key) before relying on recovery.
            let resolved: std::collections::HashSet<&str> = records
                .iter()
                .filter(|r| matches!(r.state, EffectState::Confirmed | EffectState::Rejected))
                .map(|r| r.key.as_str())
                .collect();

            // Keep the latest record per unresolved key, in first-seen order.
            let mut unresolved: Vec<EffectRecord> = Vec::new();
            let mut pos: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for r in &records {
                if resolved.contains(r.key.as_str()) {
                    continue;
                }
                match pos.get(&r.key) {
                    Some(&i) => unresolved[i] = r.clone(),
                    None => {
                        pos.insert(r.key.clone(), unresolved.len());
                        unresolved.push(r.clone());
                    },
                }
            }
            let compacted = resolved.len();

            // Atomic rewrite: write the survivors to a temp file, fsync, then
            // rename over the original. rename is atomic on POSIX, so a crash
            // mid-compaction leaves either the old log or the new one — never
            // a truncated one.
            let tmp = path.with_extension("recover.tmp");
            {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&tmp)
                    .map_err(|e| wal_error("open WAL temp", Some(Box::new(e))))?;
                for r in &unresolved {
                    let mut line = serde_json::to_vec(r)
                        .map_err(|e| wal_error("serialize during compaction", Some(Box::new(e))))?;
                    line.push(b'\n');
                    f.write_all(&line)
                        .map_err(|e| wal_error("write WAL temp", Some(Box::new(e))))?;
                }
                f.sync_all()
                    .map_err(|e| wal_error("fsync WAL temp", Some(Box::new(e))))?;
            }
            std::fs::rename(&tmp, path.as_ref())
                .map_err(|e| wal_error("rename WAL temp", Some(Box::new(e))))?;

            Ok(RecoverySummary {
                compacted,
                unresolved,
            })
        })
        .await
        .map_err(|e| wal_error("WAL recovery task failed", Some(Box::new(e))))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Debug)]
    struct NoopEmitter;

    #[async_trait]
    impl EffectEmitter for NoopEmitter {
        async fn emit(
            &self,
            _effect: &EffectRecord,
            _ext: &Extensions,
        ) -> Result<(), Box<PluginError>> {
            Ok(())
        }
    }

    #[test]
    fn effect_emitter_slot_defaults_to_empty_and_unavailable() {
        // The empty slot (default, and what `filter_extensions`/Clone leave
        // behind) reports no capability. `installed` flips that. The point of
        // the newtype is that no `emitter()` — hence no `Arc` — is reachable
        // outside this crate, which is a compile-time property, not a runtime
        // one; here we only pin the observable availability contract.
        let empty = EffectEmitterSlot::default();
        assert!(!empty.is_available());
        assert!(empty.emitter().is_none());

        let filled = EffectEmitterSlot::installed(Arc::new(NoopEmitter));
        assert!(filled.is_available());
        assert!(filled.emitter().is_some());
    }

    #[test]
    fn prepared_starts_in_prepared_with_details() {
        let e = EffectRecord::prepared("token_mint", "exchange for workday-api", "k-1")
            .with_detail("audience", "workday-api")
            .with_detail("scopes", json!(["read_compensation"]));

        assert_eq!(e.kind, "token_mint");
        assert_eq!(e.key, "k-1");
        assert_eq!(e.state, EffectState::Prepared);
        assert_eq!(e.details["audience"], "workday-api");
        assert_eq!(e.details["scopes"][0], "read_compensation");
        assert!(e.plugin_name.is_none());
    }

    #[test]
    fn into_state_transitions_to_terminal() {
        let e = EffectRecord::prepared("token_mint", "…", "k-2").into_state(EffectState::Confirmed);
        assert_eq!(e.state, EffectState::Confirmed);
    }

    /// A temp path unique per (process, call) so parallel tests don't collide,
    /// without pulling in a `tempfile` dev-dependency.
    fn unique_temp_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("cpex_{tag}_{}_{n}.ndjson", std::process::id()))
    }

    #[tokio::test]
    async fn file_log_appends_one_json_line_per_record() {
        let path = unique_temp_path("append");
        let log = FileEffectLog::new(&path);

        let e1 = EffectRecord::prepared("token_mint", "mint A", "k-1")
            .with_detail("audience", "workday-api");
        let e2 = EffectRecord::prepared("approval_grant", "grant B", "k-2");
        log.append(&e1).await.expect("append e1");
        log.append(&e2).await.expect("append e2");

        let contents = std::fs::read_to_string(&path).expect("read WAL");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "one line per appended record");

        // Each line round-trips back into an EffectRecord (this is what the
        // 3b-iii recovery sweep will rely on).
        let r1: EffectRecord = serde_json::from_str(lines[0]).expect("parse line 1");
        assert_eq!(r1.kind, "token_mint");
        assert_eq!(r1.key, "k-1");
        assert_eq!(r1.state, EffectState::Prepared);
        assert_eq!(r1.details["audience"], "workday-api");

        let r2: EffectRecord = serde_json::from_str(lines[1]).expect("parse line 2");
        assert_eq!(r2.kind, "approval_grant");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn file_log_persists_across_reopen() {
        // A fresh log over the same path sees prior records — the WAL is real
        // on-disk state, not per-instance memory. Recovery depends on this.
        let path = unique_temp_path("reopen");
        FileEffectLog::new(&path)
            .append(&EffectRecord::prepared("token_mint", "x", "k-a"))
            .await
            .unwrap();
        FileEffectLog::new(&path)
            .append(&EffectRecord::prepared("token_mint", "y", "k-b"))
            .await
            .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents.lines().count(),
            2,
            "second instance appends, does not truncate"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_log_concurrent_appends_stay_intact() {
        // N tasks append to one shared log across multiple worker threads. The
        // serialization lock must yield exactly N whole, parseable records —
        // no split or interleaved lines.
        let path = unique_temp_path("concurrent");
        let log = FileEffectLog::new(&path);
        const N: usize = 64;

        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let log = log.clone();
            handles.push(tokio::spawn(async move {
                let e = EffectRecord::prepared("token_mint", format!("mint {i}"), format!("k-{i}"));
                log.append(&e).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let contents = std::fs::read_to_string(&path).expect("read WAL");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), N, "one line per concurrent append");

        // Every line is a complete record, and all N distinct keys are present
        // (nothing was corrupted or lost).
        let mut keys = std::collections::HashSet::new();
        for line in lines {
            let rec: EffectRecord =
                serde_json::from_str(line).expect("each line is one intact record");
            keys.insert(rec.key);
        }
        assert_eq!(keys.len(), N, "all N records present and distinct");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn recover_compacts_completed_and_keeps_orphans() {
        let path = unique_temp_path("recover");
        let log = FileEffectLog::new(&path);

        // Completed: prepared + confirmed (same key).
        let done = EffectRecord::prepared("token_mint", "done", "k-done");
        log.append(&done).await.unwrap();
        log.append(&done.clone().into_state(EffectState::Confirmed))
            .await
            .unwrap();
        // Orphan: prepared with no terminal (the crash case).
        log.append(&EffectRecord::prepared("token_mint", "orphan", "k-orphan"))
            .await
            .unwrap();
        // Completed: prepared + rejected.
        let rej = EffectRecord::prepared("approval_grant", "rej", "k-rej");
        log.append(&rej).await.unwrap();
        log.append(&rej.clone().into_state(EffectState::Rejected))
            .await
            .unwrap();

        let summary = log.recover().await.unwrap();
        assert_eq!(
            summary.compacted, 2,
            "confirmed + rejected effects compacted out"
        );
        assert_eq!(summary.unresolved.len(), 1, "only the orphan is unresolved");
        assert_eq!(summary.unresolved[0].key, "k-orphan");

        // The rewritten log holds only the orphan.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        let rec: EffectRecord = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(rec.key, "k-orphan");

        // Idempotent: a second sweep with no new terminals keeps the orphan.
        let again = log.recover().await.unwrap();
        assert_eq!(again.compacted, 0);
        assert_eq!(again.unresolved.len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn recover_on_missing_file_is_noop() {
        let path = unique_temp_path("recover_missing");
        let _ = std::fs::remove_file(&path);
        let summary = FileEffectLog::new(&path).recover().await.unwrap();
        assert_eq!(summary.compacted, 0);
        assert!(summary.unresolved.is_empty());
    }

    #[tokio::test]
    async fn recover_and_reconcile_resolves_via_participant() {
        // A stand-in IdP: confirms one key, rejects another, can't resolve a third.
        struct MockIdp;
        #[async_trait]
        impl EffectReconciler for MockIdp {
            async fn reconcile(&self, effect: &EffectRecord) -> EffectState {
                match effect.key.as_str() {
                    "k-confirm" => EffectState::Confirmed,
                    "k-reject" => EffectState::Rejected,
                    _ => EffectState::Unknown,
                }
            }
        }

        let path = unique_temp_path("reconcile");
        let log = FileEffectLog::new(&path);
        for key in ["k-confirm", "k-reject", "k-unknown"] {
            log.append(&EffectRecord::prepared("token_mint", "orphan", key))
                .await
                .unwrap();
        }

        let still = log.recover_and_reconcile(&MockIdp).await.unwrap();
        assert_eq!(still.len(), 1, "only the un-resolvable effect remains");
        assert_eq!(still[0].key, "k-unknown");

        // The WAL now holds only the still-unknown record; the resolved pair
        // for k-confirm and k-reject was compacted out.
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        let rec: EffectRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(rec.key, "k-unknown");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn auto_compaction_bounds_the_wal() {
        let path = unique_temp_path("autocompact");
        // Low threshold so completed effects trigger compaction quickly.
        let log = FileEffectLog::new(&path).with_compaction_threshold(4);

        // 20 completed effects = 40 appends. Without compaction the file would
        // grow to 40 lines; auto-compaction drops each matched pair, so it
        // stays bounded near the number of in-flight (here: zero) records.
        for i in 0..20 {
            let e = EffectRecord::prepared("token_mint", "x", format!("k-{i}"));
            log.append(&e).await.unwrap();
            log.append(&e.clone().into_state(EffectState::Confirmed))
                .await
                .unwrap();
        }

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        let lines = contents.lines().count();
        assert!(
            lines < 8,
            "auto-compaction bounded the WAL (got {lines} lines, not 40)"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn compaction_threshold_zero_disables_auto_compaction() {
        let path = unique_temp_path("nocompact");
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);

        // Two completed effects (4 appends). With auto-compaction off, every
        // line stays — nothing is compacted until an explicit recover().
        for i in 0..2 {
            let e = EffectRecord::prepared("token_mint", "x", format!("k-{i}"));
            log.append(&e).await.unwrap();
            log.append(&e.clone().into_state(EffectState::Confirmed))
                .await
                .unwrap();
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents.lines().count(),
            4,
            "no auto-compaction when threshold is 0"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn default_reconciler_leaves_effects_unknown() {
        let effect = EffectRecord::prepared("token_mint", "no ledger", "k-x");
        assert_eq!(
            LogUnknownsReconciler.reconcile(&effect).await,
            EffectState::Unknown
        );
    }
}
