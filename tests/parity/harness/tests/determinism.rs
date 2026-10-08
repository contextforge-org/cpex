// Location: ./tests/parity/harness/tests/determinism.rs
// SPDX-License-Identifier: Apache-2.0
//
// Two captures through the current engine produce byte-identical output,
// so a parity difference is never a run-to-run artifact. (Matching the
// committed 0.2.3 snapshots is the parity test's job.) Valkey scenarios run
// only when PARITY_VALKEY_URL is set; without it they are skipped and
// reported on stderr.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cpex_parity_harness::{capture, default_root, Options, Status};

fn valkey_url() -> Option<String> {
    std::env::var("PARITY_VALKEY_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cpex-parity-test-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Every file under `dir`, keyed by its path relative to `dir`.
fn tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().to_path_buf();
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

async fn run(out: PathBuf) -> Vec<(String, Status)> {
    let opts = Options {
        root: default_root(),
        out,
        only: Vec::new(),
        valkey_url: valkey_url(),
    };
    let results = capture(&opts).await.expect("capture");
    for (name, status) in &results {
        if let Status::Skipped(why) = status {
            eprintln!("SKIPPED {name}: {why}");
        }
    }
    results
}

#[tokio::test(flavor = "multi_thread")]
async fn two_captures_are_byte_identical() {
    let a = scratch("a");
    let b = scratch("b");
    let results = run(a.clone()).await;
    run(b.clone()).await;

    let ta = tree(&a);
    let tb = tree(&b);
    assert!(!ta.is_empty(), "capture wrote nothing");
    assert_eq!(
        ta.keys().collect::<Vec<_>>(),
        tb.keys().collect::<Vec<_>>(),
        "the two runs wrote different file sets"
    );
    for (path, bytes) in &ta {
        assert!(
            tb[path] == *bytes,
            "{} differs between two runs",
            path.display()
        );
    }

    let written = results
        .iter()
        .filter(|(_, s)| *s == Status::Written)
        .count();
    assert!(written > 0, "no scenario was captured");

    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
}
