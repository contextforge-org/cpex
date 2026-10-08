// Location: ./tests/parity/harness/tests/parity.rs
// SPDX-License-Identifier: Apache-2.0
//
// Parity with the 0.2.3 baseline. Every scenario is replayed through the
// current engine with its migrated config and the hook rename table, then
// diffed against the recorded snapshot. The test fails on a difference that
// intended-differences.yaml does not list, and on a listed entry that no
// longer matches anything.
//
// The Valkey read-back test seeds a database from the keyspace 0.2.3 left
// behind and checks that the current engine reads those labels back: it
// replays only requests that read labels, so every taint they see comes
// from the seed. Valkey tests run only when PARITY_VALKEY_URL is set.

use std::path::Path;

use serde_json::Value;

use cpex_parity_harness::parity::{diff_scenario, to_allow_list_yaml};
use cpex_parity_harness::spec::HookRenames;
use cpex_parity_harness::{check_parity, default_root, replay, Options, Replay, Replayed, Status};

/// Both tests flush and fill the same Valkey database and scratch
/// directories, so they take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn valkey_url() -> Option<String> {
    std::env::var("PARITY_VALKEY_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn options() -> Options {
    let root = default_root();
    Options {
        out: root.join("unused"),
        root,
        only: Vec::new(),
        valkey_url: valkey_url(),
    }
}

fn read_json(path: &Path) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_matches_snapshots_except_intended_differences() {
    let _turn = SERIAL.lock().await;
    let (report, statuses) = check_parity(&options()).await.expect("parity check");
    for (name, status) in &statuses {
        if let Status::Skipped(why) = status {
            eprintln!("SKIPPED {name}: {why}");
        }
    }
    assert!(
        statuses.iter().any(|(_, s)| *s == Status::Written),
        "no scenario was checked"
    );
    let mut problems = String::new();
    if !report.unexpected.is_empty() {
        problems.push_str(&format!(
            "{} differences are not in intended-differences.yaml. Investigate each; \
             list it with its cause only if it is intended:\n{}",
            report.unexpected.len(),
            to_allow_list_yaml(&report.unexpected)
        ));
    }
    for e in &report.stale {
        problems.push_str(&format!(
            "stale allow-list entry, matches no difference: {} / {} / {}\n",
            e.scenario, e.request, e.field
        ));
    }
    assert!(problems.is_empty(), "{problems}");
}

/// Requests in the Valkey scenario that read session labels and do not
/// write any. Replayed alone, whatever taint they see was seeded.
const LABEL_READERS: &[&str] = &[
    "email-after-taint-denied",
    "fresh-session-allowed",
    "other-subject-same-session-id",
    "email-without-session-id",
];

#[tokio::test(flavor = "multi_thread")]
async fn valkey_labels_written_by_0_2_3_read_back_unchanged() {
    if valkey_url().is_none() {
        eprintln!("SKIPPED valkey read-back: set PARITY_VALKEY_URL");
        return;
    }
    let _turn = SERIAL.lock().await;
    let root = default_root();
    let seed = read_json(&root.join("snapshots/valkey/session-valkey.keyspace.json"));
    let baseline = read_json(&root.join("snapshots/session-valkey.json"));

    let plan = Replay {
        valkey_seed: Some(seed.clone()),
        only_requests: LABEL_READERS.iter().map(|s| s.to_string()).collect(),
    };
    let Replayed::Done { snapshot, keyspace } = replay(&options(), "session-valkey", &plan)
        .await
        .expect("replay")
    else {
        panic!("session-valkey was skipped with a Valkey URL set");
    };

    // The seed is the only source of taint, so the denial proves the
    // labels were read back under the same key.
    let ids: Vec<&str> = snapshot["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    assert_eq!(ids, LABEL_READERS, "replayed requests");

    // Each replayed request matches its record from the full 0.2.3 run.
    let renames = HookRenames::default();
    let mut expected = baseline.clone();
    expected["requests"] = Value::Array(
        baseline["requests"]
            .as_array()
            .expect("requests")
            .iter()
            .filter(|r| LABEL_READERS.contains(&r["id"].as_str().unwrap_or_default()))
            .cloned()
            .collect(),
    );
    let differences: Vec<_> = diff_scenario("session-valkey", &expected, &snapshot, &renames)
        .into_iter()
        // The load block and description are covered by the parity test.
        .filter(|d| !d.request.starts_with('<'))
        .collect();
    assert!(
        differences.is_empty(),
        "labels seeded from 0.2.3 read back differently:\n{}",
        to_allow_list_yaml(&differences)
    );
    let denied = &snapshot["requests"][0];
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["code"], "session_tainted");

    // Reading changed nothing in the store: same keys, members and TTLs.
    assert_eq!(
        keyspace.expect("keyspace export"),
        seed,
        "the replay changed the seeded keyspace"
    );
}
