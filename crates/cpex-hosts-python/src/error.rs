// Location: ./crates/cpex-hosts-python/src/error.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Host-internal errors and their mapping to `cpex_core::error::PluginError`.
//
// The host distinguishes failure modes the executor cannot see — a venv that
// would not build, a worker that died mid-flight, a task over the size cap —
// so operators get an actionable reason. At the trait boundary each maps to a
// `PluginError`, and the *executor* applies the configured error policy
// (fail / ignore / disable). The host never implements that policy itself.

use std::collections::HashMap;
use std::fmt;

use cpex_core::error::PluginError;

/// Cap on the stderr excerpt carried in `PluginError::Execution.details`.
///
/// pip failures are verbose (resolver backtracking can run to hundreds of
/// lines) and the tail holds the actual error, so `stderr_excerpt` keeps the
/// last `STDERR_EXCERPT_BYTES` rather than the first.
const STDERR_EXCERPT_BYTES: usize = 4096;

/// Structured detail keys. Stable — operators and tests match on these.
const DETAIL_EXIT_CODE: &str = "exit_code";
const DETAIL_STDERR: &str = "stderr_excerpt";
const DETAIL_STDERR_TRUNCATED: &str = "stderr_truncated";
const DETAIL_TIMEOUT_SECS: &str = "timeout_secs";
const DETAIL_SIZE: &str = "size_bytes";
const DETAIL_LIMIT: &str = "limit_bytes";

/// Output of a failed child process, in the structured form the error carries.
///
/// # Redaction
///
/// This is a diagnostic channel that reaches logs, so it must never carry
/// credential material. It is safe for the two producers that build it today —
/// `python3 -m venv` and `pip install -r`, neither of which is passed a token
/// or a credentialed URL — and it is *not* safe to reuse for a process whose
/// argv, environment, or index URL embeds a secret. `pip`'s own output already
/// redacts the userinfo component of an index URL, but a caller that puts a
/// token somewhere else on the command line would defeat that; such a caller
/// must scrub before constructing this.
#[derive(Debug, Clone, Default)]
pub struct ProcessOutput {
    /// The child's exit status code, or `None` if it was killed by a signal.
    pub exit_code: Option<i32>,

    /// The child's stderr, already decoded lossily and trimmed.
    pub stderr: String,
}

impl ProcessOutput {
    /// Build from a `std::process::Output`, decoding stderr lossily.
    ///
    /// See the type-level redaction note: only use this for a child whose
    /// output cannot contain credential material.
    pub fn from_output(output: &std::process::Output) -> Self {
        Self {
            exit_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }
    }

    /// The trailing `STDERR_EXCERPT_BYTES` of stderr, and whether it was cut.
    ///
    /// Splits on a `char` boundary so the excerpt stays valid UTF-8.
    fn stderr_excerpt(&self) -> (&str, bool) {
        if self.stderr.len() <= STDERR_EXCERPT_BYTES {
            return (self.stderr.as_str(), false);
        }
        let mut start = self.stderr.len() - STDERR_EXCERPT_BYTES;
        while start < self.stderr.len() && !self.stderr.is_char_boundary(start) {
            start += 1;
        }
        (&self.stderr[start..], true)
    }

    /// Render as `exited <code>: <stderr>` for the `Display` message.
    fn describe(&self) -> String {
        let status = match self.exit_code {
            Some(code) => format!("exited {code}"),
            None => "was killed by a signal".to_string(),
        };
        let (excerpt, _) = self.stderr_excerpt();
        if excerpt.is_empty() {
            status
        } else {
            format!("{status}: {excerpt}")
        }
    }

    /// Insert `exit_code` / `stderr_excerpt` into a details map.
    fn write_details(&self, details: &mut HashMap<String, serde_json::Value>) {
        details.insert(
            DETAIL_EXIT_CODE.to_string(),
            match self.exit_code {
                Some(code) => serde_json::Value::from(code),
                None => serde_json::Value::Null,
            },
        );
        let (excerpt, truncated) = self.stderr_excerpt();
        details.insert(DETAIL_STDERR.to_string(), serde_json::Value::from(excerpt));
        if truncated {
            details.insert(
                DETAIL_STDERR_TRUNCATED.to_string(),
                serde_json::Value::Bool(true),
            );
        }
    }
}

/// A failure inside the host, before or around the plugin's own logic.
#[derive(Debug)]
pub enum HostError {
    /// The plugin's configuration cannot support a venv (no plugin dirs, an
    /// unusable class name).
    Config { message: String },

    /// Building the virtualenv or installing its requirements failed.
    VenvBuild { message: String },

    /// A venv build step that ran a child process and got a non-zero exit.
    ///
    /// Split out from `Self::VenvBuild` so the exit code and stderr survive as
    /// structured `details` on the `PluginError` instead of being flattened
    /// into prose a caller has to string-match. `step` names the command that
    /// failed ("python3 -m venv", "pip install") and `context` the thing it
    /// was acting on (the venv path, the requirements file).
    ///
    /// Carries process output — see the redaction note on `ProcessOutput`.
    VenvCommand {
        step: &'static str,
        context: String,
        output: ProcessOutput,
    },

    /// The worker subprocess could not be launched.
    WorkerStart { message: String },

    /// The worker process is gone — reader EOF, or a non-zero exit — while a
    /// request was outstanding. Distinct from a timeout: there is nothing
    /// left to wait for.
    WorkerDied { message: String },

    /// No response arrived within the per-invocation timeout.
    Timeout { timeout_secs: u64 },

    /// The serialized task exceeded the configured `max_content_size`. Caught
    /// before the write, so nothing was sent.
    TaskTooLarge { size: usize, limit: usize },

    /// A worker response frame exceeded the configured `max_content_size`.
    /// Detected mid-read, so the frame was discarded rather than buffered.
    ResponseTooLarge { size: usize, limit: usize },

    /// The worker returned a structured error response for this request.
    WorkerError { message: String },

    /// A payload or response could not be serialized or parsed.
    ///
    /// The message must never carry payload *values* — only the shape of the
    /// failure (which field, which type), since it reaches logs.
    Protocol { message: String },

    /// A credential-bearing hook could not be served safely, so the host
    /// failed closed rather than dispatching without the token.
    ///
    /// The message never contains token material.
    Credential { message: String },
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config { message } => write!(f, "configuration error: {message}"),
            Self::VenvBuild { message } => write!(f, "venv build failed: {message}"),
            Self::VenvCommand {
                step,
                context,
                output,
            } => write!(
                f,
                "venv build failed: `{step}` on {context} {}",
                output.describe()
            ),
            Self::WorkerStart { message } => write!(f, "worker failed to start: {message}"),
            Self::WorkerDied { message } => write!(f, "worker process died: {message}"),
            Self::Timeout { timeout_secs } => {
                write!(f, "worker did not respond within {timeout_secs}s")
            },
            Self::TaskTooLarge { size, limit } => write!(
                f,
                "serialized task is {size} bytes, over the {limit}-byte max_content_size"
            ),
            Self::ResponseTooLarge { size, limit } => write!(
                f,
                "worker response frame is at least {size} bytes, over the \
                 {limit}-byte max_content_size; the frame was discarded rather \
                 than buffered"
            ),
            Self::WorkerError { message } => write!(f, "worker returned an error: {message}"),
            Self::Protocol { message } => write!(f, "protocol error: {message}"),
            Self::Credential { message } => write!(f, "credential error: {message}"),
        }
    }
}

impl std::error::Error for HostError {}

impl HostError {
    /// Short, stable code for the `PluginError::Execution.code` field, so a
    /// host can branch on the failure mode without string-matching messages.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config { .. } => "config",
            Self::VenvBuild { .. } | Self::VenvCommand { .. } => "venv_build_failed",
            Self::WorkerStart { .. } => "worker_start_failed",
            Self::WorkerDied { .. } => "worker_died",
            Self::Timeout { .. } => "timeout",
            Self::TaskTooLarge { .. } => "task_too_large",
            Self::ResponseTooLarge { .. } => "response_too_large",
            Self::WorkerError { .. } => "worker_error",
            Self::Protocol { .. } => "protocol_error",
            Self::Credential { .. } => "credential_error",
        }
    }

    /// Machine-readable diagnostics for `PluginError::Execution.details`.
    ///
    /// The `Display` message is prose for a human; this is the same facts in a
    /// form an operator's log pipeline or a test can match on without parsing
    /// English. A failed `pip install` is the motivating case: its exit code
    /// and stderr tail land here rather than only inside the message string.
    ///
    /// Variants whose fields are already fully described by the message (and
    /// carry no structured facts beyond it) contribute nothing, so the map is
    /// empty for them rather than padded with a duplicate of the message.
    ///
    /// Every value here reaches logs, so nothing that could hold credential
    /// material — payload values, token bytes — is admitted. The one variant
    /// carrying child-process output is gated by the redaction note on
    /// `ProcessOutput`.
    pub fn details(&self) -> HashMap<String, serde_json::Value> {
        let mut details = HashMap::new();
        match self {
            Self::VenvCommand { step, output, .. } => {
                details.insert("step".to_string(), serde_json::Value::from(*step));
                output.write_details(&mut details);
            },
            Self::Timeout { timeout_secs } => {
                details.insert(
                    DETAIL_TIMEOUT_SECS.to_string(),
                    serde_json::Value::from(*timeout_secs),
                );
            },
            Self::TaskTooLarge { size, limit } | Self::ResponseTooLarge { size, limit } => {
                details.insert(DETAIL_SIZE.to_string(), serde_json::Value::from(*size));
                details.insert(DETAIL_LIMIT.to_string(), serde_json::Value::from(*limit));
            },
            // Message-only variants: nothing structured to add.
            Self::Config { .. }
            | Self::VenvBuild { .. }
            | Self::WorkerStart { .. }
            | Self::WorkerDied { .. }
            | Self::WorkerError { .. }
            | Self::Protocol { .. }
            | Self::Credential { .. } => {},
        }
        details
    }

    /// Convert to the framework error type for a named plugin.
    ///
    /// A timeout becomes `PluginError::Timeout` so the executor's existing
    /// timeout accounting applies; a config fault becomes
    /// `PluginError::Config`; everything else is an `Execution` error the
    /// executor routes through the plugin's `on_error` policy.
    pub fn into_plugin_error(self, plugin_name: &str) -> Box<PluginError> {
        match self {
            Self::Timeout { timeout_secs } => PluginError::Timeout {
                plugin_name: plugin_name.to_string(),
                timeout_ms: timeout_secs.saturating_mul(1000),
                proto_error_code: None,
            }
            .boxed(),

            Self::Config { ref message } => PluginError::Config {
                message: format!("plugin '{plugin_name}' (isolated_venv): {message}"),
            }
            .boxed(),

            other => {
                let code = other.code();
                PluginError::Execution {
                    plugin_name: plugin_name.to_string(),
                    message: other.to_string(),
                    source: None,
                    code: Some(code.to_string()),
                    details: other.details(),
                    proto_error_code: None,
                }
                .boxed()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The details map for a message-only variant.
    fn details_of(err: HostError) -> HashMap<String, serde_json::Value> {
        err.details()
    }

    /// Extract `details` from the `Execution` arm, failing on any other arm.
    fn execution_details(err: HostError) -> HashMap<String, serde_json::Value> {
        match *err.into_plugin_error("p") {
            PluginError::Execution { details, .. } => details,
            other => panic!("expected Execution, got {other:?}"),
        }
    }

    fn pip_failure(stderr: &str, exit_code: Option<i32>) -> HostError {
        HostError::VenvCommand {
            step: "pip install",
            context: "requirements.txt".to_string(),
            output: ProcessOutput {
                exit_code,
                stderr: stderr.to_string(),
            },
        }
    }

    /// The regression this variant exists for: a failed pip install used to
    /// convert to an `Execution` error with an empty details map, so the exit
    /// code and stderr were only recoverable by parsing the message prose.
    #[test]
    fn a_failed_pip_install_carries_its_exit_code_and_stderr_in_details() {
        let details = execution_details(pip_failure("ERROR: No matching distribution", Some(1)));

        assert_eq!(details[DETAIL_EXIT_CODE], serde_json::Value::from(1));
        assert_eq!(
            details[DETAIL_STDERR],
            serde_json::Value::from("ERROR: No matching distribution")
        );
        assert_eq!(details["step"], serde_json::Value::from("pip install"));
        assert!(!details.contains_key(DETAIL_STDERR_TRUNCATED));
    }

    /// The code stays `venv_build_failed` so existing branching still works.
    #[test]
    fn the_new_variant_shares_the_venv_build_failed_code() {
        assert_eq!(pip_failure("boom", Some(1)).code(), "venv_build_failed");
        assert_eq!(
            HostError::VenvBuild {
                message: "boom".into()
            }
            .code(),
            "venv_build_failed"
        );
    }

    /// A signal-killed child has no exit code; the slot is explicitly null
    /// rather than absent, so a consumer can tell "killed" from "not a
    /// process failure at all".
    #[test]
    fn a_signal_killed_child_reports_a_null_exit_code() {
        let details = execution_details(pip_failure("", None));

        assert_eq!(details[DETAIL_EXIT_CODE], serde_json::Value::Null);
        assert!(pip_failure("", None)
            .to_string()
            .contains("was killed by a signal"));
    }

    /// Long pip output is cut to the tail, where the actual error lives, and
    /// flagged so a reader knows they are not seeing the whole thing.
    #[test]
    fn an_oversized_stderr_is_truncated_to_its_tail_and_flagged() {
        let stderr = format!("{}TAIL-MARKER", "x".repeat(STDERR_EXCERPT_BYTES * 2));
        let details = execution_details(pip_failure(&stderr, Some(2)));

        let excerpt = details[DETAIL_STDERR].as_str().unwrap();
        assert!(excerpt.len() <= STDERR_EXCERPT_BYTES);
        assert!(
            excerpt.ends_with("TAIL-MARKER"),
            "the tail holds the real error, so it must survive truncation"
        );
        assert_eq!(
            details[DETAIL_STDERR_TRUNCATED],
            serde_json::Value::Bool(true)
        );
    }

    /// Truncation must not split a multi-byte char and produce invalid UTF-8.
    #[test]
    fn truncation_respects_char_boundaries() {
        // "é" is two bytes, so a naive byte split lands mid-character.
        let stderr = "é".repeat(STDERR_EXCERPT_BYTES);
        let details = execution_details(pip_failure(&stderr, Some(1)));

        let excerpt = details[DETAIL_STDERR].as_str().unwrap();
        assert!(excerpt.chars().all(|c| c == 'é'));
        assert!(excerpt.len() <= STDERR_EXCERPT_BYTES);
    }

    /// A timeout keeps its dedicated `PluginError::Timeout` mapping, so it
    /// must not be diverted into the `Execution` arm by the details work.
    #[test]
    fn a_timeout_still_maps_to_the_timeout_variant() {
        let err = HostError::Timeout { timeout_secs: 30 };
        match *err.into_plugin_error("p") {
            PluginError::Timeout { timeout_ms, .. } => assert_eq!(timeout_ms, 30_000),
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn a_size_cap_breach_reports_both_the_size_and_the_limit() {
        let details = execution_details(HostError::TaskTooLarge {
            size: 2048,
            limit: 1024,
        });

        assert_eq!(details[DETAIL_SIZE], serde_json::Value::from(2048));
        assert_eq!(details[DETAIL_LIMIT], serde_json::Value::from(1024));
    }

    /// Message-only variants stay empty rather than duplicating the message
    /// into a details key.
    #[test]
    fn message_only_variants_contribute_no_details() {
        for err in [
            HostError::VenvBuild {
                message: "m".into(),
            },
            HostError::WorkerStart {
                message: "m".into(),
            },
            HostError::WorkerDied {
                message: "m".into(),
            },
            HostError::WorkerError {
                message: "m".into(),
            },
            HostError::Protocol {
                message: "m".into(),
            },
            HostError::Credential {
                message: "m".into(),
            },
        ] {
            assert!(details_of(err).is_empty());
        }
    }

    /// The `Display` message keeps the exit code and stderr too — the details
    /// map is an addition, not a relocation, so existing log lines that only
    /// render the message do not regress.
    #[test]
    fn the_display_message_still_names_the_step_context_and_failure() {
        let message = pip_failure("ERROR: could not build wheel", Some(1)).to_string();

        assert!(message.contains("pip install"));
        assert!(message.contains("requirements.txt"));
        assert!(message.contains("exited 1"));
        assert!(message.contains("ERROR: could not build wheel"));
    }
}
