// Location: ./tests/parity/harness/src/main.rs
// SPDX-License-Identifier: Apache-2.0
//
//   parity-capture [--root DIR] [--out DIR] [--valkey-url URL] [SCENARIO...]
//   parity-capture --diff [--root DIR] [--valkey-url URL] [SCENARIO...]
//
// The first form replays the scenarios through the current engine and
// writes normalized snapshots to --out (default: target/parity under the
// workspace). It never writes to <root>/snapshots, which holds the 0.2.3
// baseline. The second form diffs a fresh replay against that baseline and
// prints every difference, marking the ones the allow-list does not cover.
//
// The root defaults to tests/parity and the Valkey URL to PARITY_VALKEY_URL.
// Scenarios that need Valkey are skipped when no URL is given.

use std::path::PathBuf;
use std::process::ExitCode;

use cpex_parity_harness::parity::to_allow_list_yaml;
use cpex_parity_harness::{Options, Status, capture, check_parity, default_out, default_root};

fn usage() -> ExitCode {
    eprintln!(
        "usage: parity-capture [--diff] [--root DIR] [--out DIR] [--valkey-url URL] [SCENARIO...]"
    );
    ExitCode::from(2)
}

fn print_statuses(results: &[(String, Status)], done: &str) {
    for (name, status) in results {
        match status {
            Status::Written => println!("{done:<8} {name}"),
            Status::Skipped(why) => println!("SKIPPED  {name}: {why}"),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut root: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut diff = false;
    let mut valkey_url = std::env::var("PARITY_VALKEY_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let mut only = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => root = args.next().map(PathBuf::from),
            "--out" => out = args.next().map(PathBuf::from),
            "--valkey-url" => valkey_url = args.next(),
            "--diff" => diff = true,
            "-h" | "--help" => return usage(),
            s if s.starts_with('-') => return usage(),
            s => only.push(s.to_string()),
        }
    }
    let root = root.unwrap_or_else(default_root);
    let out = out.unwrap_or_else(default_out);
    if out.starts_with(root.join("snapshots")) {
        eprintln!("error: --out must not point at the 0.2.3 baseline in <root>/snapshots");
        return ExitCode::FAILURE;
    }
    let opts = Options {
        root,
        out,
        only,
        valkey_url,
    };

    if diff {
        return match check_parity(&opts).await {
            Ok((report, results)) => {
                print_statuses(&results, "checked");
                for d in &report.differences {
                    let mark = if report.unexpected.contains(d) {
                        "UNEXPECTED"
                    } else {
                        "intended"
                    };
                    println!("{mark:<10} {d}");
                }
                for e in &report.stale {
                    println!(
                        "STALE      {} / {} / {}: allow-list entry matches nothing",
                        e.scenario, e.request, e.field
                    );
                }
                if report.is_clean() {
                    println!("parity: {} intended differences", report.differences.len());
                    ExitCode::SUCCESS
                } else {
                    println!("\nunexpected differences as allow-list entries:\n");
                    print!("{}", to_allow_list_yaml(&report.unexpected));
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            },
        };
    }

    match capture(&opts).await {
        Ok(results) => {
            print_statuses(&results, "wrote");
            ExitCode::SUCCESS
        },
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        },
    }
}
