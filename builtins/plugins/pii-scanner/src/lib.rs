// Location: ./builtins/plugins/pii-scanner/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// cpex-plugin-pii-scanner — CMF `HookHandler` that walks the message's
// ToolCall / PromptRequest argument map and tests each string value
// against configured PII patterns. Modes:
//
//   * `deny`   — return `pii.detected` violation; gateway 403s
//   * `taint`  — emit a session taint label (downstream policy can
//                gate via `session.labels contains 'PII'`)
//   * `redact` — replace matching values with `[PII]` and continue
//
// Operators wire it as a `policy:` step:
//
//   policy:
//     - "require(perm.email_send)"
//     - "plugin(pii-scan)"
//
// The plugin registers on whichever CMF pre-invoke hooks the
// operator declares in YAML (tool / prompt / llm / resource).

pub mod config;
pub mod factory;
pub mod scanner;

pub use config::{PiiPattern, PiiScanMode, PiiScannerConfig};
pub use factory::{PiiScannerFactory, KIND};
pub use scanner::PiiScanner;
