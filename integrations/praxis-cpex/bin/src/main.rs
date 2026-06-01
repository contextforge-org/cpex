// Location: ./integrations/praxis-cpex/bin/src/main.rs
// SPDX-License-Identifier: Apache-2.0
//
// `praxis-cpex` — a drop-in replacement for the stock `praxis` binary
// that registers the `cpex` HttpFilter (from `cpex-praxis-filter`) so
// operators can declare `filter: cpex` in their YAML.
//
// Usage:
//   praxis-cpex -c examples/praxis.yaml
//
// Everything else is vanilla Praxis behavior: listeners, routing,
// other built-in filters, admin endpoints, hot reload. We only add
// one filter name to the registry.

#![deny(unsafe_code)]

use praxis_filter::register_filters;
use tracing::info;

use cpex_praxis_filter::CpexFilter;

// -----------------------------------------------------------------------------
// Filter Registration
// -----------------------------------------------------------------------------

register_filters! {
    http "cpex" => CpexFilter::from_config,
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

#[allow(clippy::print_stderr)]
fn main() {
    let explicit = parse_config_arg();

    let config_path = praxis::resolve_config_path(explicit.as_deref());
    let config = praxis::load_config(explicit.as_deref()).unwrap_or_else(|e| praxis::fatal(&e));
    praxis::init_tracing(&config).unwrap_or_else(|e| praxis::fatal(&e));
    info!("starting praxis-cpex");
    praxis::run_server_with_registry(config, custom_registry(), config_path)
}

/// Parse `-c <path>` / `--config <path>` from argv. Falls back to
/// `PRAXIS_CONFIG` env var. Kept minimal; we don't need the full
/// stock CLI surface for Slice A.
fn parse_config_arg() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => return args.next(),
            other if other.starts_with("--config=") => {
                return Some(other.trim_start_matches("--config=").to_string());
            }
            _ => {}
        }
    }
    std::env::var("PRAXIS_CONFIG").ok()
}
