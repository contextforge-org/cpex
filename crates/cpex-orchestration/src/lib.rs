// Location: ./crates/cpex-orchestration/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Async concurrency primitives shared by the CPEX runtime.
//
// Two callers today, both running "N async branches concurrently with
// optional short-circuit on first deny":
//
//   * `cpex-core::executor::run_concurrent_phase` — fans out concurrent
//     plugins for one hook event
//   * `apl-core::evaluator::dispatch_parallel` — fans out the effects
//     inside an APL `parallel:` block
//
// Both want the same mechanics — `tokio::task::JoinSet` keyed by task
// id, react-to-results-as-they-arrive, optional `abort_all` on first
// deny, per-branch timeout. Without a shared primitive, both would
// reinvent the pattern (slightly differently) and drift.
//
// This crate exposes a single generic function `run_branches`. It
// speaks `Future<Output = T>` + an `is_deny` predicate — no domain
// concepts. Each caller adapts its types (HookEntry, EffectOutcome,
// Decision, …) at the boundary.

#![deny(rust_2018_idioms)]

use std::collections::HashMap;
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::task::{Id, JoinSet};
use tokio::time::timeout;

/// Configuration knobs for [`run_branches`].
#[derive(Debug, Clone, Copy)]
pub struct BranchConfig {
    /// Maximum time each individual branch is allowed to run before
    /// being recorded as `BranchOutcome::TimedOut`. `None` disables
    /// the per-branch timeout (relies on cancellation from
    /// `short_circuit_on_deny` and the outer caller).
    pub timeout_per_branch: Option<Duration>,

    /// When `true`, abort the remaining branches as soon as the first
    /// branch returns a result satisfying the `is_deny` predicate.
    /// Aborted branches are returned as `BranchOutcome::Aborted`.
    pub short_circuit_on_deny: bool,
}

impl Default for BranchConfig {
    fn default() -> Self {
        Self {
            timeout_per_branch: None,
            short_circuit_on_deny: true,
        }
    }
}

/// What happened to one branch in [`run_branches`].
///
/// Branches always return results in the **input order** (index 0
/// first, even if it physically finished last). Callers that care
/// about wall-clock completion order need to add their own
/// timestamping inside the branch future.
#[derive(Debug)]
pub enum BranchOutcome<T> {
    /// Branch ran to completion within its timeout and produced `T`.
    Completed(T),
    /// Branch exceeded its `timeout_per_branch`. Callers typically
    /// treat this as a deny / failure depending on policy.
    TimedOut,
    /// Branch was cancelled before completion because an earlier
    /// branch tripped `short_circuit_on_deny`. Distinguishable from
    /// `TimedOut` so audit/logging can tell whether the framework
    /// or the caller's own time budget killed the task.
    Aborted,
    /// Branch's spawned task panicked. Carries the panic payload's
    /// `Display` representation for logging — the typed payload is
    /// dropped (JoinError doesn't preserve it across boxing).
    Panicked(String),
}

impl<T> BranchOutcome<T> {
    /// Get a reference to the completed value if the branch succeeded.
    /// `None` for timeouts, aborts, and panics.
    pub fn completed(&self) -> Option<&T> {
        match self {
            BranchOutcome::Completed(v) => Some(v),
            _ => None,
        }
    }

    /// Consume the outcome, returning the completed value if any.
    pub fn into_completed(self) -> Option<T> {
        match self {
            BranchOutcome::Completed(v) => Some(v),
            _ => None,
        }
    }
}

/// Run `branches` concurrently, returning one [`BranchOutcome`] per
/// branch in **input order**.
///
/// # Behaviour
///
/// * Each branch is spawned onto the current tokio runtime via
///   `JoinSet::spawn`. The runtime must be `rt-multi-thread` for the
///   branches to actually run in parallel; single-threaded runtimes
///   will run them concurrently (interleaved) but on one OS thread.
/// * If `config.short_circuit_on_deny` is set, the moment any branch
///   completes with a result satisfying `is_deny`, all remaining
///   branches are aborted via `JoinSet::abort_all`. They surface as
///   `BranchOutcome::Aborted`.
/// * If `config.timeout_per_branch` is set, each branch is wrapped in
///   `tokio::time::timeout`. Timeouts surface as `BranchOutcome::TimedOut`.
/// * Panics inside a branch are caught (tokio's `JoinSet` returns
///   them via `JoinError::is_panic`) and surfaced as
///   `BranchOutcome::Panicked` rather than re-panicking — the
///   intent is that one misbehaving branch shouldn't take down the
///   whole orchestrator.
///
/// # Cost notes
///
/// * `tokio::task::spawn` has ~1 µs overhead per spawn — fine for
///   the workload sizes this is designed for (typically 2-20
///   branches). If you need 1000+ branches, profile first.
/// * Each branch's future is `Send + 'static` (it's spawned onto a
///   task) — captured state must satisfy those bounds. Most callers
///   handle this by cloning state per branch before constructing the
///   future.
pub async fn run_branches<T, F, P>(
    branches: Vec<F>,
    config: BranchConfig,
    is_deny: P,
) -> Vec<BranchOutcome<T>>
where
    T: Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
    P: Fn(&T) -> bool + Send + Sync,
{
    let n = branches.len();
    if n == 0 {
        return Vec::new();
    }

    // Spawn each branch onto the JoinSet. The spawn handle's `Id` is
    // captured into `id_to_idx` so a panicked task — which surfaces as
    // a `JoinError` carrying only its `Id`, not the return value — can
    // still be mapped back to its input index.
    let mut set: JoinSet<(usize, BranchOutcome<T>)> = JoinSet::new();
    let mut id_to_idx: HashMap<Id, usize> = HashMap::with_capacity(n);
    for (idx, fut) in branches.into_iter().enumerate() {
        let to = config.timeout_per_branch;
        let handle = set.spawn(async move {
            let result = match to {
                None => Ok(fut.await),
                Some(d) => timeout(d, fut).await,
            };
            let outcome = match result {
                Ok(v) => BranchOutcome::Completed(v),
                Err(_) => BranchOutcome::TimedOut,
            };
            (idx, outcome)
        });
        id_to_idx.insert(handle.id(), idx);
    }

    // Collect outcomes into a position-indexed Vec so the return order
    // matches input order regardless of physical completion order.
    // `None` slots get filled as branches finish; remaining `None`s
    // after all completions get replaced with `Aborted` (only
    // possible when short-circuit fired).
    let mut slots: Vec<Option<BranchOutcome<T>>> = (0..n).map(|_| None).collect();
    let mut aborted = false;

    while let Some(joined) = set.join_next_with_id().await {
        match joined {
            Ok((_id, (idx, outcome))) => {
                let halts = matches!(&outcome, BranchOutcome::Completed(v) if is_deny(v));
                slots[idx] = Some(outcome);
                if halts && config.short_circuit_on_deny && !aborted {
                    set.abort_all();
                    aborted = true;
                    // Don't break — we still need to drain whatever
                    // tasks already completed before we asked for the
                    // abort, so their outcomes land in their slots
                    // (vs. being silently lost). The drain loop
                    // continues until JoinSet is empty.
                }
            },
            Err(e) => {
                // A task either panicked or was cancelled by
                // `abort_all`. JoinError exposes the task `Id`, which
                // we look up in `id_to_idx` to recover the original
                // input index. Panicked branches land in their own
                // slot; cancelled ones get left as `None` and filled
                // with `Aborted` post-loop.
                if e.is_panic() {
                    let payload = format!("{:?}", e);
                    if let Some(&idx) = id_to_idx.get(&e.id()) {
                        slots[idx] = Some(BranchOutcome::Panicked(payload));
                    }
                }
            },
        }
    }

    // Anything still unset was aborted by `short_circuit_on_deny`.
    slots
        .into_iter()
        .map(|s| s.unwrap_or(BranchOutcome::Aborted))
        .collect()
}

// Implementation note on the generic signature:
//
// `P` is the closure type for `is_deny`. We declare it as a generic
// type parameter rather than `impl Fn(...)` so the function works
// uniformly across async runtimes and callers that need to use
// boxed predicates (`Box<dyn Fn(...)>`) for runtime polymorphism.
//
// The `BoxFuture` import isn't strictly needed for the public API
// but is re-exported below for callers that want to build
// homogeneous branch vectors out of differently-typed futures (the
// common case in apl-core's `Effect::Parallel` dispatch, where each
// effect's future has a unique inferred type).

/// Convenience alias re-exported from `futures` for callers building
/// type-erased branch vectors. `apl-core`'s `Effect::Parallel`
/// dispatch uses this because the per-effect futures have different
/// inferred types and need erasure to fit in a single `Vec`.
pub type ErasedBranch<T> = BoxFuture<'static, T>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn no_deny<T>(_: &T) -> bool {
        false
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn all_complete_in_input_order() {
        // Branches finish in REVERSE wall-clock order — sleep more
        // for earlier indices. The output Vec must still be in input
        // order: branch[0] → first slot, branch[2] → last slot.
        let branches: Vec<_> = (0usize..3)
            .map(|idx| {
                Box::pin(async move {
                    let delay = Duration::from_millis(30 - 10 * idx as u64);
                    tokio::time::sleep(delay).await;
                    idx
                }) as BoxFuture<'static, usize>
            })
            .collect();

        let out = run_branches(
            branches,
            BranchConfig {
                timeout_per_branch: None,
                short_circuit_on_deny: false,
            },
            no_deny::<usize>,
        )
        .await;

        assert_eq!(out.len(), 3);
        for (i, outcome) in out.into_iter().enumerate() {
            match outcome {
                BranchOutcome::Completed(v) => assert_eq!(v, i, "input order preserved"),
                other => panic!("expected Completed({}), got {:?}", i, other),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timeout_marks_branch_as_timed_out() {
        let branches: Vec<_> = vec![
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                "should not see this"
            }) as BoxFuture<'static, &str>,
            Box::pin(async { "quick" }) as BoxFuture<'static, &str>,
        ];

        let out = run_branches(
            branches,
            BranchConfig {
                timeout_per_branch: Some(Duration::from_millis(50)),
                short_circuit_on_deny: false,
            },
            no_deny::<&str>,
        )
        .await;

        assert!(matches!(out[0], BranchOutcome::TimedOut));
        assert!(matches!(out[1], BranchOutcome::Completed("quick")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn short_circuit_on_deny_aborts_remaining() {
        // Branch 0 returns Deny quickly; branches 1 and 2 are slow.
        // With short_circuit, the slow ones should be Aborted.
        let counter = Arc::new(AtomicUsize::new(0));
        let c0 = counter.clone();
        let c1 = counter.clone();
        let c2 = counter.clone();

        let branches: Vec<BoxFuture<'static, bool>> = vec![
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(5)).await;
                c0.fetch_add(1, Ordering::SeqCst);
                true // deny
            }),
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                c1.fetch_add(1, Ordering::SeqCst);
                false
            }),
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                c2.fetch_add(1, Ordering::SeqCst);
                false
            }),
        ];

        let out = run_branches(
            branches,
            BranchConfig {
                timeout_per_branch: None,
                short_circuit_on_deny: true,
            },
            |v: &bool| *v,
        )
        .await;

        assert!(matches!(out[0], BranchOutcome::Completed(true)));
        assert!(matches!(out[1], BranchOutcome::Aborted));
        assert!(matches!(out[2], BranchOutcome::Aborted));
        // Only the first branch should have incremented; the slow
        // ones were aborted before they got past their sleeps.
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn short_circuit_disabled_keeps_all_running() {
        // Same shape as above but with short_circuit OFF — all three
        // should run to completion despite branch 0 denying.
        let branches: Vec<BoxFuture<'static, bool>> = vec![
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                true
            }),
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                false
            }),
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                false
            }),
        ];

        let out = run_branches(
            branches,
            BranchConfig {
                timeout_per_branch: None,
                short_circuit_on_deny: false,
            },
            |v: &bool| *v,
        )
        .await;

        assert!(matches!(out[0], BranchOutcome::Completed(true)));
        assert!(matches!(out[1], BranchOutcome::Completed(false)));
        assert!(matches!(out[2], BranchOutcome::Completed(false)));
    }

    #[tokio::test]
    async fn empty_input_returns_empty_output() {
        let out: Vec<BranchOutcome<()>> = run_branches(
            Vec::<BoxFuture<'static, ()>>::new(),
            BranchConfig::default(),
            no_deny::<()>,
        )
        .await;
        assert!(out.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn panic_inside_branch_does_not_take_down_orchestrator() {
        let branches: Vec<BoxFuture<'static, i32>> =
            vec![Box::pin(async { panic!("boom") }), Box::pin(async { 42 })];
        let out = run_branches(
            branches,
            BranchConfig {
                timeout_per_branch: None,
                short_circuit_on_deny: false,
            },
            no_deny::<i32>,
        )
        .await;
        // Branch 1 must complete despite branch 0's panic.
        assert!(out
            .iter()
            .any(|o| matches!(o, BranchOutcome::Completed(42))));
        assert!(out.iter().any(|o| matches!(o, BranchOutcome::Panicked(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn panic_lands_in_correct_input_slot() {
        // Branch 1 panics; branches 0 and 2 succeed. The panicked
        // outcome must land at index 1, not "the first empty slot."
        // This guards executor consumers that key per-entry
        // `on_error` policy off the branch index.
        let branches: Vec<BoxFuture<'static, i32>> = vec![
            Box::pin(async { 10 }),
            Box::pin(async { panic!("middle branch boom") }),
            Box::pin(async { 30 }),
        ];
        let out = run_branches(
            branches,
            BranchConfig {
                timeout_per_branch: None,
                short_circuit_on_deny: false,
            },
            no_deny::<i32>,
        )
        .await;
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], BranchOutcome::Completed(10)));
        assert!(
            matches!(out[1], BranchOutcome::Panicked(_)),
            "panic must land at index 1, got {:?}",
            out[1]
        );
        assert!(matches!(out[2], BranchOutcome::Completed(30)));
    }
}
