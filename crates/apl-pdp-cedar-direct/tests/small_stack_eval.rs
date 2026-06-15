// Location: ./crates/apl-pdp-cedar-direct/tests/small_stack_eval.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Regression test for the musl small-stack / cedar "recursion limit" trap.
//
// cedar-policy-core guards evaluation against stack exhaustion by checking
// `stacker::remaining_stack()` against a 100 KiB floor (REQUIRED_STACK_SPACE).
// An FFI host chooses the thread stack the evaluation runs on: glibc defaults
// threads to 8 MiB (clears the floor), but musl defaults to 128 KiB, so once
// the call chain has descended into evaluation the floor trips and cedar
// returns "recursion limit reached" on inputs that decide fine on glibc.
//
// `CedarDirectResolver::evaluate` wraps the cedar work in `stacker::maybe_grow`,
// which runs it on a fresh, generously-sized segment when the current stack is
// low — making cedar host-stack-agnostic. This test pins that behavior by
// evaluating on a 128 KiB OS thread (musl's default):
//
//   * with the guard  -> grows onto a large segment -> Allow
//   * without it      -> cedar trips its floor       -> Err("recursion limit reached")
//
// We use `futures::executor::block_on` rather than tokio: `evaluate` has no
// real await points (cedar is synchronous), and the lighter executor keeps the
// pre-`maybe_grow` footprint small so the 128 KiB proves the grow path, not the
// runtime.

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::step::{PdpCall, PdpDialect, PdpResolver};
use apl_pdp_cedar_direct::CedarDirectResolver;

/// musl's default thread stack size — below cedar's 100 KiB remaining-stack
/// floor once evaluation is underway.
const MUSL_DEFAULT_STACK: usize = 128 * 1024;

#[test]
fn evaluate_succeeds_on_musl_sized_thread_stack() {
    let decision = std::thread::Builder::new()
        .name("musl-stack-sim".into())
        .stack_size(MUSL_DEFAULT_STACK)
        .spawn(|| {
            const POLICY: &str = r#"
                @id("allow-all")
                permit(principal, action, resource);
            "#;
            let resolver =
                CedarDirectResolver::from_policy_text(POLICY).expect("policy parses");

            let call = PdpCall {
                dialect: PdpDialect::Cedar,
                args: serde_yaml::from_str(
                    "action: 'Action::\"read\"'\nresource:\n  type: Document\n  id: doc-1\n",
                )
                .expect("call args parse"),
            };
            let mut bag = AttributeBag::new();
            bag.set("subject.id", "alice");
            bag.set("subject.type", "User");

            futures::executor::block_on(resolver.evaluate(&call, &bag))
        })
        .expect("spawn 128 KiB thread")
        .join()
        .expect("evaluation thread must not overflow/panic")
        .expect("cedar must evaluate on a musl-sized stack (maybe_grow guard)");

    assert_eq!(
        decision.decision,
        Decision::Allow,
        "an unconditional permit must Allow even on a 128 KiB thread stack",
    );
}
