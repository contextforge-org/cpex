// Location: ./tests/parity/harness/src/main.rs
// SPDX-License-Identifier: Apache-2.0
//
//   parity-capture [--root DIR] [--out DIR] [--valkey-url URL] [SCENARIO...]
//
// Defaults: root is tests/parity, out is <root>/snapshots, the Valkey URL
// comes from PARITY_VALKEY_URL. Scenarios that need Valkey are skipped
// (and their snapshots left untouched) when no URL is given.

use std::path::PathBuf;
use std::process::ExitCode;

use cpex_parity_harness::{capture, default_root, Options, Status};

fn usage() -> ExitCode {
    eprintln!("usage: parity-capture [--root DIR] [--out DIR] [--valkey-url URL] [SCENARIO...]");
    ExitCode::from(2)
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut root: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
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
            "-h" | "--help" => return usage(),
            s if s.starts_with('-') => return usage(),
            s => only.push(s.to_string()),
        }
    }
    let root = root.unwrap_or_else(default_root);
    let out = out.unwrap_or_else(|| root.join("snapshots"));
    let opts = Options {
        root,
        out,
        only,
        valkey_url,
    };

    match capture(&opts).await {
        Ok(results) => {
            for (name, status) in results {
                match status {
                    Status::Written => println!("wrote    {name}"),
                    Status::Skipped(why) => println!("SKIPPED  {name}: {why}"),
                }
            }
            ExitCode::SUCCESS
        },
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        },
    }
}
