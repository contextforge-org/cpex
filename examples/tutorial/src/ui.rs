// Location: ./examples/tutorial/src/ui.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Console formatting shared by every tutorial module, so the output, and
// the terminal recordings made from it, look consistent. Nothing here is
// CPEX-specific; it just prints scenarios and outcomes tidily.

use crate::mediate::Outcome;

/// Print a module title banner.
pub fn module_banner(title: &str) {
    println!("\n\x1b[1;36m=== {title} ===\x1b[0m\n");
}

/// Print a scenario sub-header (one per distinct call in a module).
pub fn scenario(label: &str) {
    println!("\x1b[1m▸ {label}\x1b[0m");
}

/// Print an outcome with a colored ✓ / ✗ and, for allows, a compact
/// rendering of the (possibly redacted) result.
pub fn print_outcome(outcome: &Outcome) {
    match outcome {
        Outcome::Allowed { result } => {
            let rendered =
                serde_json::to_string(result).unwrap_or_else(|_| "<unserializable>".into());
            println!("  \x1b[32m✓ ALLOWED\x1b[0m  {rendered}");
        },
        Outcome::Denied { code, reason } => {
            println!("  \x1b[31m✗ DENIED\x1b[0m   [{code}] {reason}");
        },
        Outcome::Pending {
            elicitation_id,
            approver,
        } => {
            println!(
                "  \x1b[33m⏸ PENDING\x1b[0m  awaiting {approver}'s approval (id {elicitation_id})"
            );
        },
    }
    println!();
}

/// Assert an outcome matches what a scenario expects, for `--check` mode.
/// Returns `true` on match. The mismatch line is printed only under
/// `--check`: an interactive run (the "Try it" flow, where you deliberately
/// change outcomes) stays quiet and just shows the scenario and its result.
pub fn expect(outcome: &Outcome, want_allowed: bool) -> bool {
    let ok = outcome.is_allowed() == want_allowed;
    if !ok && check_mode() {
        let want = if want_allowed { "ALLOWED" } else { "DENIED" };
        println!("  \x1b[33m! CHECK FAILED\x1b[0m expected {want}, got {outcome:?}");
    }
    ok
}

/// Whether the module was run with `--check` (scripted assertion mode,
/// used by CI) rather than interactively.
pub fn check_mode() -> bool {
    std::env::args().any(|a| a == "--check")
}

/// Exit helper for `--check` runs: 0 if every assertion passed, 1 if any
/// failed. No-op in interactive mode.
pub fn finish_check(all_passed: bool) {
    if check_mode() {
        if all_passed {
            println!("\x1b[32mAll checks passed.\x1b[0m");
        } else {
            println!("\x1b[31mSome checks failed.\x1b[0m");
            std::process::exit(1);
        }
    }
}
