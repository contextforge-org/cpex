// Location: ./crates/cpex-hosts-python/src/worker.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Worker client — launches `worker.py` in the plugin's venv and speaks the
// newline-delimited JSON protocol to it.
//
// The async analog of `cpex/framework/isolated/venv_comm.py`. Where that uses
// two threads and a `Queue` per request, this uses two tokio tasks and a
// one-shot channel per request:
//
// ```text
//   send_task ──> outbound channel ──> writer task ──> child stdin
//                      registers a one-shot in `pending`
//   child stdout ──> reader task ──> demux on request_id ──> that one-shot
// ```
//
// Demuxing on `request_id` rather than assuming request/response ordering is
// what lets several hook invocations be in flight against one worker at once —
// the executor dispatches parallel-phase plugins concurrently, and a
// FIFO-coupled client would serialize them.
//
// # Failure modes, kept distinct
//
// A hung worker (`Timeout`) and a dead worker (`WorkerDied`) call for different
// operator responses, so they do not collapse into one error. Process death is
// detected by reader EOF, at which point every pending one-shot is dropped —
// each in-flight `send_task` then resolves to `WorkerDied` instead of waiting
// out a timeout that can never be satisfied.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::error::HostError;

/// How long to wait for a worker to exit after a `shutdown` task before
/// killing it. Matches `venv_comm.py`'s `stop_worker` grace window.
const SHUTDOWN_GRACE_SECS: u64 = 5;

/// Task type for a hook invocation, as `worker.py` dispatches on it.
pub const TASK_LOAD_AND_RUN_HOOK: &str = "load_and_run_hook";

/// Task type that asks the worker to exit.
pub const TASK_SHUTDOWN: &str = "shutdown";

/// Map of in-flight request ids to the channel awaiting each response.
///
/// Carries a `Result` rather than a bare `Value` so the reader task can hand a
/// waiting caller a typed failure — an oversized response frame is a real
/// answer to that request ("it cannot be delivered"), and reporting it beats
/// letting the caller sit out the full timeout for a response that was already
/// discarded.
type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value, HostError>>>>>;

/// How many recent stderr lines to retain for diagnosis.
///
/// A worker that dies at import time (a bad dependency pin, a missing module)
/// says so on stderr and nowhere else. Without this, the host reports only
/// "worker process died" and the actual cause is lost — the tail is small
/// enough to be cheap and long enough to hold a Python traceback.
const STDERR_RETAIN_LINES: usize = 40;

/// Ring buffer of the worker's most recent stderr lines.
type StderrTail = Arc<Mutex<std::collections::VecDeque<String>>>;

/// Cap on one retained stderr line, independent of `max_content_size`.
///
/// Stderr is diagnostic, so an over-long line is truncated rather than treated
/// as a protocol violation — but the retained copy still has to be bounded, or
/// a worker that writes one enormous line drives host memory on its own.
/// Sized to hold a Python traceback frame comfortably.
const STDERR_MAX_LINE_BYTES: usize = 8 * 1024;

/// Appended to a stderr line that was cut at `STDERR_MAX_LINE_BYTES`, so an
/// operator reading the tail can tell truncation from a worker that really
/// stopped mid-sentence.
const TRUNCATION_MARKER: &str = "… [truncated by host]";

/// Outcome of one bounded line read.
enum BoundedLine {
    /// A complete line, within the limit.
    Line(String),

    /// The line exceeded the limit. Carries the bytes read up to the cap, for
    /// the diagnostic paths that want a prefix; the rest was discarded as it
    /// arrived, so nothing beyond the cap was ever buffered.
    Oversized { prefix: String, scanned: usize },

    /// Stream closed.
    Eof,
}

/// Read one `\n`-delimited line, refusing to buffer more than `limit` bytes.
///
/// `AsyncBufReadExt::lines` grows its `String` without bound, which is what
/// makes an unbounded inbound stream a host memory problem regardless of the
/// outbound `max_content_size` check. This reads through the `BufRead` fill
/// buffer instead: once `limit` bytes have accumulated without a newline, the
/// remainder of the line is consumed and dropped rather than retained, so the
/// stream stays framed (the next read starts at a real line boundary) while
/// peak memory stays at `limit` plus one fill buffer.
async fn read_bounded_line<R>(reader: &mut R, limit: usize) -> std::io::Result<BoundedLine>
where
    R: AsyncBufRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut scanned = 0usize;
    let mut over = false;

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // EOF. A trailing fragment with no newline is still a line.
            if scanned == 0 {
                return Ok(BoundedLine::Eof);
            }
            break;
        }

        let (chunk, consumed, done) = match available.iter().position(|b| *b == b'\n') {
            Some(index) => (&available[..index], index + 1, true),
            None => {
                let all = available.len();
                (available, all, false)
            },
        };

        scanned += chunk.len();
        if !over {
            // Only retain up to the cap; everything past it is consumed and
            // dropped, which is what keeps this bounded.
            let room = limit.saturating_sub(buffer.len());
            let keep = chunk.len().min(room);
            buffer.extend_from_slice(&chunk[..keep]);
            if scanned > limit {
                over = true;
            }
        }

        reader.consume(consumed);
        if done {
            break;
        }
    }

    // Trim a `\r` from CRLF, matching what `lines()` does.
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }

    let text = String::from_utf8_lossy(&buffer).into_owned();
    if over {
        Ok(BoundedLine::Oversized {
            prefix: text,
            scanned,
        })
    } else {
        Ok(BoundedLine::Line(text))
    }
}

/// Set once the reader task observes that the worker's stdout has closed.
///
/// Needed because clearing `pending` only rescues requests that were *already*
/// registered when the worker died. A send issued afterwards would otherwise
/// register a fresh one-shot into a map nobody is reading, succeed at writing
/// into an mpsc channel whose consumer has exited, and then wait out the full
/// timeout for a response that can never arrive. Checking this flag turns that
/// into an immediate `WorkerDied`.
type Alive = Arc<std::sync::atomic::AtomicBool>;

/// A live `worker.py` subprocess and the plumbing that talks to it.
pub struct WorkerClient {
    /// Outbound task lines, drained by the writer task.
    outbound: mpsc::UnboundedSender<String>,

    /// Response channels keyed by request id.
    pending: Pending,

    /// False once the reader task has seen the worker's stdout close.
    alive: Alive,

    /// Recent stderr, for explaining a death.
    stderr_tail: StderrTail,

    /// The child handle, kept so shutdown can wait on and kill it. `None`
    /// once shutdown has consumed it.
    child: Mutex<Option<Child>>,

    /// Cap on one serialized task, enforced before the write.
    max_content_size: usize,

    /// Per-invocation response timeout.
    timeout_secs: u64,
}

/// Manual rather than derived: the outbound channel carries serialized task
/// lines, which on a credential-bearing hook include the plaintext token. A
/// derive would put those in any debug dump of the client.
impl std::fmt::Debug for WorkerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerClient")
            .field("max_content_size", &self.max_content_size)
            .field("timeout_secs", &self.timeout_secs)
            .finish_non_exhaustive()
    }
}

impl WorkerClient {
    /// Launch `worker.py` with the venv's interpreter and start the I/O tasks.
    ///
    /// `cwd` becomes the child's working directory, which is where a plugin's
    /// relative-path side effects land.
    pub async fn spawn(
        python: &Path,
        script_path: &Path,
        cwd: Option<&Path>,
        max_content_size: usize,
        timeout_secs: u64,
    ) -> Result<Self, HostError> {
        if !python.exists() {
            return Err(HostError::WorkerStart {
                message: format!("venv interpreter not found at {}", python.display()),
            });
        }

        let mut command = Command::new(python);
        command
            .arg(script_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Without this, a killed host leaves orphaned workers behind.
            .kill_on_drop(true);

        if let Some(dir) = cwd {
            command.current_dir(dir);
        }

        let mut child = command.spawn().map_err(|e| HostError::WorkerStart {
            message: format!(
                "could not spawn {} {}: {e}",
                python.display(),
                script_path.display()
            ),
        })?;

        let stdin = child.stdin.take().ok_or_else(|| HostError::WorkerStart {
            message: "worker stdin was not piped".into(),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| HostError::WorkerStart {
            message: "worker stdout was not piped".into(),
        })?;
        let stderr = child.stderr.take().ok_or_else(|| HostError::WorkerStart {
            message: "worker stderr was not piped".into(),
        })?;

        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let alive: Alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let stderr_tail: StderrTail = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let (outbound, outbound_rx) = mpsc::unbounded_channel::<String>();

        tokio::spawn(writer_loop(stdin, outbound_rx));
        // The inbound cap is the same `max_content_size` the outbound path
        // enforces: one configured limit on the size of a protocol frame,
        // applied in both directions.
        tokio::spawn(reader_loop(
            stdout,
            Arc::clone(&pending),
            Arc::clone(&alive),
            max_content_size,
        ));
        tokio::spawn(stderr_loop(stderr, Arc::clone(&stderr_tail)));

        Ok(Self {
            outbound,
            pending,
            alive,
            stderr_tail,
            child: Mutex::new(Some(child)),
            max_content_size,
            timeout_secs,
        })
    }

    /// Build a `WorkerDied` error, appending recent stderr when there is any.
    ///
    /// The stderr tail is what turns "worker process died" into something
    /// actionable — an import error, a missing dependency, a traceback.
    async fn died(&self, context: &str) -> HostError {
        let tail = self.stderr_tail.lock().await;
        if tail.is_empty() {
            return HostError::WorkerDied {
                message: context.to_string(),
            };
        }

        let recent: Vec<&str> = tail.iter().map(String::as_str).collect();
        HostError::WorkerDied {
            message: format!("{context}; recent worker stderr: {}", recent.join(" | ")),
        }
    }

    /// The worker's retained stderr lines, oldest first.
    ///
    /// Exposed so a test can assert the credential channel never surfaces here:
    /// this buffer is the one place the host copies worker stderr, and the one
    /// place it is echoed onward (into a `WorkerDied` message).
    pub async fn stderr_lines(&self) -> Vec<String> {
        self.stderr_tail.lock().await.iter().cloned().collect()
    }

    /// Whether the worker's stdout is still open.
    ///
    /// A `false` here is definitive — the process has closed its output. A
    /// `true` is only as fresh as the reader task's last observation, so a
    /// send can still race a death; that path is covered by the dropped-sender
    /// branch in `send_task`.
    pub fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Send a task and await its response.
    ///
    /// The caller supplies the task body; this method injects the `request_id`
    /// and handles registration, the size check, the write, and the timeout.
    pub async fn send_task(&self, mut task: Value) -> Result<Value, HostError> {
        // Checked up front: once the worker is known dead, waiting out the
        // timeout tells the caller nothing it does not already know.
        if !self.is_alive() {
            return Err(self.died("worker process is no longer running").await);
        }

        let request_id = uuid::Uuid::new_v4().to_string();

        {
            let obj = task.as_object_mut().ok_or_else(|| HostError::Protocol {
                message: "task must be a JSON object".into(),
            })?;
            obj.insert("request_id".into(), Value::String(request_id.clone()));
        }

        let line = serde_json::to_string(&task).map_err(|e| HostError::Protocol {
            message: format!("could not serialize task: {e}"),
        })?;

        // Checked before registering or writing, so an oversized task costs
        // nothing and cannot desync the worker's line-oriented reader.
        if line.len() > self.max_content_size {
            return Err(HostError::TaskTooLarge {
                size: line.len(),
                limit: self.max_content_size,
            });
        }

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id.clone(), tx);

        // Registration happens before the write so a fast response cannot
        // arrive before there is anywhere to route it.
        if self.outbound.send(format!("{line}\n")).is_err() {
            self.pending.lock().await.remove(&request_id);
            return Err(self
                .died("writer task is gone — the worker is no longer accepting tasks")
                .await);
        }

        let response =
            match tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx).await
            {
                Ok(Ok(Ok(response))) => response,
                // The reader task delivered a typed failure for this request —
                // an over-limit response frame it had to discard.
                Ok(Ok(Err(e))) => return Err(e),
                // The sender was dropped without a value: the reader task saw EOF
                // and cleared `pending`, so the worker is gone.
                Ok(Err(_)) => {
                    return Err(self
                        .died("worker exited while the request was in flight")
                        .await)
                },
                Err(_) => {
                    self.pending.lock().await.remove(&request_id);
                    return Err(HostError::Timeout {
                        timeout_secs: self.timeout_secs,
                    });
                },
            };

        interpret_response(response)
    }

    /// Ask the worker to exit, then wait out the grace window and kill it.
    ///
    /// Idempotent: a second call after the child has been reaped is a no-op,
    /// which matters because `shutdown` may run from both the plugin lifecycle
    /// and a drop path.
    pub async fn shutdown(&self) -> Result<(), HostError> {
        let Some(mut child) = self.child.lock().await.take() else {
            return Ok(());
        };

        // `venv_comm.py` sends a fixed "shutdown" request id rather than a
        // UUID, and the worker echoes it back; nothing awaits the reply.
        let task = serde_json::json!({ "task_type": TASK_SHUTDOWN, "request_id": TASK_SHUTDOWN });
        if let Ok(line) = serde_json::to_string(&task) {
            let _ = self.outbound.send(format!("{line}\n"));
        }

        match tokio::time::timeout(
            std::time::Duration::from_secs(SHUTDOWN_GRACE_SECS),
            child.wait(),
        )
        .await
        {
            Ok(Ok(_status)) => Ok(()),
            Ok(Err(e)) => Err(HostError::WorkerDied {
                message: format!("could not wait on the worker process: {e}"),
            }),
            Err(_) => {
                // A worker that ignores the shutdown task (or is wedged inside
                // plugin code) must not hold teardown open.
                tracing::warn!("worker did not exit within {SHUTDOWN_GRACE_SECS}s; killing it");
                child.kill().await.map_err(|e| HostError::WorkerDied {
                    message: format!("could not kill the unresponsive worker: {e}"),
                })?;
                Ok(())
            },
        }
    }
}

/// Turn a worker response envelope into a result.
///
/// The worker signals failure with `{"status": "error", "message": ...}`; any
/// other envelope is the hook result. `request_id` is stripped — it is
/// transport bookkeeping, and `venv_comm.py` removes it too before returning.
fn interpret_response(mut response: Value) -> Result<Value, HostError> {
    if let Some(obj) = response.as_object_mut() {
        obj.remove("request_id");

        if obj.get("status").and_then(Value::as_str) == Some("error") {
            let message = obj
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("worker reported an error with no message")
                .to_string();
            return Err(HostError::WorkerError { message });
        }
    }
    Ok(response)
}

/// Drain outbound task lines into the child's stdin.
///
/// Ends when the channel closes (client dropped) or the pipe breaks (worker
/// gone). Either way the reader loop is what surfaces the failure to callers.
async fn writer_loop(
    mut stdin: tokio::process::ChildStdin,
    mut outbound: mpsc::UnboundedReceiver<String>,
) {
    while let Some(line) = outbound.recv().await {
        if stdin.write_all(line.as_bytes()).await.is_err() {
            tracing::debug!("worker stdin closed; writer stopping");
            break;
        }
        if stdin.flush().await.is_err() {
            tracing::debug!("worker stdin flush failed; writer stopping");
            break;
        }
    }
}

/// Read response lines and route each to the one-shot for its request id.
///
/// Each frame is read under `limit` (the configured `max_content_size`), so a
/// hostile or runaway worker cannot grow host memory by never emitting a
/// newline. An over-limit frame is dropped rather than buffered: the waiting
/// caller gets a typed `ResponseTooLarge`, and because the rest of the line is
/// consumed to its newline the stream stays framed for the next response.
///
/// On EOF, `pending` is drained and every sender dropped, which resolves each
/// in-flight `send_task` to `WorkerDied` rather than leaving it to time out.
async fn reader_loop(
    stdout: tokio::process::ChildStdout,
    pending: Pending,
    alive: Alive,
    limit: usize,
) {
    let mut reader = BufReader::new(stdout);

    loop {
        match read_bounded_line(&mut reader, limit).await {
            Ok(BoundedLine::Line(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let Ok(response) = serde_json::from_str::<Value>(line) else {
                    // A plugin that printed to stdout lands here. Skipping the
                    // line keeps the stream in sync; the request still times
                    // out or gets its real response later.
                    tracing::warn!("worker emitted a non-JSON stdout line; ignoring it");
                    continue;
                };

                let Some(request_id) = response.get("request_id").and_then(Value::as_str) else {
                    tracing::warn!("worker response had no request_id; dropping it");
                    continue;
                };

                match pending.lock().await.remove(request_id) {
                    Some(tx) => {
                        // Receiver gone means the caller already timed out.
                        let _ = tx.send(Ok(response));
                    },
                    None => {
                        // The fixed "shutdown" id lands here by design, as does
                        // any late response whose caller has given up.
                        tracing::debug!(request_id, "response for an unknown request id");
                    },
                }
            },
            Ok(BoundedLine::Oversized { prefix, scanned }) => {
                // The frame is gone — only `limit` bytes of it were ever kept.
                // Recovering the request id from that prefix is best-effort
                // (JSON field order is not guaranteed), so the fallback is to
                // fail every in-flight request: something the worker sent could
                // not be delivered, and guessing which caller it belonged to
                // would be worse than telling all of them.
                tracing::error!(
                    scanned,
                    limit,
                    "worker response frame exceeded max_content_size; \
                     the frame was discarded rather than buffered"
                );

                let request_id = request_id_from_prefix(&prefix);
                let mut pending = pending.lock().await;
                match request_id.and_then(|id| pending.remove(&id).map(|tx| (id, tx))) {
                    Some((id, tx)) => {
                        tracing::warn!(
                            request_id = %id,
                            "failing the request whose response was over the size limit"
                        );
                        let _ = tx.send(Err(response_too_large(scanned, limit)));
                    },
                    None => {
                        // No recoverable id. Fail everyone rather than leave a
                        // caller waiting on a response that no longer exists.
                        for (id, tx) in pending.drain() {
                            tracing::warn!(
                                request_id = %id,
                                "failing an in-flight request: an over-limit response frame was \
                                 discarded and its owner could not be identified"
                            );
                            let _ = tx.send(Err(response_too_large(scanned, limit)));
                        }
                    },
                }
            },
            Ok(BoundedLine::Eof) => {
                tracing::debug!("worker stdout closed");
                break;
            },
            Err(e) => {
                tracing::warn!("error reading worker stdout: {e}");
                break;
            },
        }
    }

    // Order matters: mark dead *before* clearing, so a send that races this
    // teardown either sees the flag and fails fast, or finds its sender
    // dropped. Either way it does not wait out the timeout.
    alive.store(false, std::sync::atomic::Ordering::Release);

    // Dropping the senders is what converts a dead worker into an immediate
    // error for everyone still waiting.
    pending.lock().await.clear();
}

/// The error a caller gets when its response frame was over the inbound cap.
///
/// A dedicated constructor because the failure needs one stable shape and one
/// stable wording wherever the reader raises it. `HostError::TaskTooLarge` is
/// deliberately not reused: its `Display` says "serialized task", which would
/// point an operator at the *outbound* check and at their own payload rather
/// than at the worker's reply.
fn response_too_large(size: usize, limit: usize) -> HostError {
    HostError::ResponseTooLarge { size, limit }
}

/// Best-effort recovery of a `request_id` from a truncated response frame.
///
/// The frame is not parseable JSON — it was cut mid-value — so this scans for
/// the `"request_id"` key textually. `worker.py` emits the id early enough that
/// this usually succeeds, which lets the reader fail exactly the one caller
/// whose response was dropped instead of every in-flight request. A miss is
/// expected and handled by the caller, not an error.
fn request_id_from_prefix(prefix: &str) -> Option<String> {
    const KEY: &str = "\"request_id\"";
    let after_key = &prefix[prefix.find(KEY)? + KEY.len()..];
    let after_colon = &after_key[after_key.find(':')? + 1..];
    let opening = after_colon.find('"')?;
    let rest = &after_colon[opening + 1..];
    // A truncated frame can end mid-id; without a closing quote there is no
    // way to know the value is complete, so treat it as unrecoverable.
    let closing = rest.find('"')?;
    Some(rest[..closing].to_string())
}

/// Log the worker's stderr and retain a bounded tail for diagnosis.
///
/// Logged at debug: the worker's own logging goes here, and a credential-bearing
/// hook must never surface token material through it. `worker.py` scrubs its
/// side (it holds the plaintext only to scrub it back out of anything the
/// plugin logs, raises, or returns); this side never parses these lines or
/// echoes them anywhere except into a `WorkerDied` message, which is the one
/// place an operator genuinely needs them.
///
/// # Bounding
///
/// Stderr gets a *softer* policy than stdout. It carries no framing and no
/// request routing — it is the channel that explains a death, so discarding it
/// or killing the worker over it would destroy the diagnostic the operator
/// needs precisely when things are going wrong. Each line is therefore
/// truncated at `STDERR_MAX_LINE_BYTES` with an explicit marker (so an operator
/// can tell a host cut from a worker that stopped mid-sentence) rather than
/// raising an error, and the `STDERR_RETAIN_LINES` ring already caps the total.
/// Together those give a hard ceiling of roughly
/// `STDERR_RETAIN_LINES * STDERR_MAX_LINE_BYTES` on retained stderr, with peak
/// read memory bounded per line — so a worker that spews stderr forever, in
/// however few newlines, cannot grow the host.
async fn stderr_loop(stderr: tokio::process::ChildStderr, tail: StderrTail) {
    let mut reader = BufReader::new(stderr);

    loop {
        let line = match read_bounded_line(&mut reader, STDERR_MAX_LINE_BYTES).await {
            Ok(BoundedLine::Line(line)) => line,
            Ok(BoundedLine::Oversized { prefix, scanned }) => {
                tracing::warn!(
                    scanned,
                    limit = STDERR_MAX_LINE_BYTES,
                    "worker stderr line exceeded the per-line limit; retaining a truncated prefix"
                );
                format!("{prefix}{TRUNCATION_MARKER}")
            },
            Ok(BoundedLine::Eof) => break,
            Err(e) => {
                tracing::debug!("error reading worker stderr: {e}");
                break;
            },
        };

        tracing::debug!(target: "cpex_hosts_python::worker_stderr", "{line}");

        let mut tail = tail.lock().await;
        if tail.len() == STDERR_RETAIN_LINES {
            tail.pop_front();
        }
        tail.push_back(line);
    }
}

/// Resolve `worker.py` inside a venv's site-packages.
///
/// The worker ships with the `cpex` framework, which the plugin's requirements
/// pull into the venv — so the host does not carry its own copy. Both
/// `lib/pythonX.Y/site-packages` (Unix) and `Lib/site-packages` (Windows) are
/// searched because the interpreter version is not known up front.
pub fn resolve_worker_script(venv_path: &Path, relative: &str) -> Result<PathBuf, HostError> {
    // An absolute override (used by tests and by hosts that vendor a worker)
    // bypasses venv resolution entirely.
    let relative_path = Path::new(relative);
    if relative_path.is_absolute() {
        return Ok(relative_path.to_path_buf());
    }

    let mut candidates = Vec::new();

    let unix_lib = venv_path.join("lib");
    if let Ok(entries) = std::fs::read_dir(&unix_lib) {
        for entry in entries.flatten() {
            candidates.push(entry.path().join("site-packages").join(relative_path));
        }
    }
    candidates.push(
        venv_path
            .join("Lib")
            .join("site-packages")
            .join(relative_path),
    );
    // Last resort: a worker sitting directly under the venv.
    candidates.push(venv_path.join(relative_path));

    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .ok_or_else(|| HostError::WorkerStart {
            message: format!(
                "could not find '{relative}' in the venv at {} — is `cpex` installed in it? \
                 (a plugin's requirements file must pull in the framework that ships worker.py)",
                venv_path.display()
            ),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{skip_without_python3, TempDir};

    /// A stub worker that speaks the same protocol as `worker.py`.
    ///
    /// Deterministic stand-in for the real thing: no venv, no framework
    /// import, and each behavior selectable per task so the failure modes are
    /// reachable without contriving a real plugin to misbehave.
    ///
    /// Recognized `task_type` values:
    ///   - `echo`      — reply with `{"status":"success","echo":<payload>}`
    ///   - `slow`      — sleep `delay` seconds, then echo (drives the timeout)
    ///   - `fail`      — reply `{"status":"error","message":<message>}`
    ///   - `die`       — exit immediately without replying
    ///   - `noisy`     — print a non-JSON line first, then reply
    ///   - `huge`      — reply with a padded response of `size` bytes
    ///   - `unframed`  — stream `size` bytes with no newline at all, then reply
    ///   - `loud`      — write a `size`-byte stderr line, then reply
    ///   - `deaf`      — ignore `shutdown` and keep running (drives the kill)
    ///   - `shutdown`  — reply and exit, unless previously put in `deaf` mode
    const STUB_WORKER: &str = r#"
import json, sys, time

deaf = False
while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if not line:
        continue
    task = json.loads(line)
    kind = task.get("task_type")
    rid = task.get("request_id", "unknown")

    if kind == "shutdown":
        if deaf:
            # Acknowledge but refuse to exit, so the host must kill us.
            print(json.dumps({"status": "success", "request_id": rid}), flush=True)
            while True:
                time.sleep(0.05)
        print(json.dumps({"status": "success", "message": "Shutting down", "request_id": rid}), flush=True)
        break
    if kind == "deaf":
        deaf = True
        print(json.dumps({"status": "success", "request_id": rid}), flush=True)
        continue
    if kind == "die":
        sys.exit(3)
    if kind == "slow":
        time.sleep(float(task.get("delay", 1.0)))
        print(json.dumps({"status": "success", "echo": task.get("payload"), "request_id": rid}), flush=True)
        continue
    if kind == "fail":
        print(json.dumps({"status": "error", "message": task.get("message", "stub failure"), "request_id": rid}), flush=True)
        continue
    if kind == "noisy":
        print("this is not JSON and must not desync the stream", flush=True)
        print(json.dumps({"status": "success", "echo": task.get("payload"), "request_id": rid}), flush=True)
        continue
    if kind == "huge":
        # request_id first, so the host can still name the caller from the
        # truncated prefix it kept.
        size = int(task.get("size", 1024))
        print(json.dumps({"request_id": rid, "status": "success", "pad": "P" * size}), flush=True)
        continue
    if kind == "unframed":
        # No newline at all: the pathological case for a line reader.
        size = int(task.get("size", 1024))
        sys.stdout.write("U" * size)
        sys.stdout.flush()
        print(json.dumps({"request_id": rid, "status": "success"}), flush=True)
        continue
    if kind == "loud":
        size = int(task.get("size", 1024))
        sys.stderr.write("L" * size + "\n")
        sys.stderr.flush()
        print(json.dumps({"status": "success", "echo": task.get("payload"), "request_id": rid}), flush=True)
        continue

    print(json.dumps({"status": "success", "echo": task.get("payload"), "request_id": rid}), flush=True)
"#;

    /// Write the stub to disk and spawn a client against it.
    async fn stub_client(
        dir: &TempDir,
        max_content_size: usize,
        timeout_secs: u64,
    ) -> WorkerClient {
        let script = dir.path().join("stub_worker.py");
        std::fs::write(&script, STUB_WORKER).unwrap();

        let python = which_python3();
        WorkerClient::spawn(
            &python,
            &script,
            Some(dir.path()),
            max_content_size,
            timeout_secs,
        )
        .await
        .expect("stub worker spawns")
    }

    /// Absolute path to python3, since `WorkerClient::spawn` requires an
    /// existing interpreter path rather than a PATH lookup.
    fn which_python3() -> PathBuf {
        let out = std::process::Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()
            .expect("run command -v");
        PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
    }

    #[tokio::test]
    async fn a_task_round_trips_to_its_response() {
        if skip_without_python3("a_task_round_trips_to_its_response") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 10).await;

        let response = client
            .send_task(serde_json::json!({ "task_type": "echo", "payload": {"tool": "search"} }))
            .await
            .expect("the stub replies");

        assert_eq!(response["echo"]["tool"], "search");
        assert!(
            response.get("request_id").is_none(),
            "request_id is transport bookkeeping and must be stripped"
        );
    }

    #[tokio::test]
    async fn concurrent_sends_each_receive_their_own_response() {
        // Demux correctness. The stub answers the slower task second, so a
        // client that assumed FIFO ordering would hand each caller the other's
        // response — this test fails loudly on that.
        if skip_without_python3("concurrent_sends_each_receive_their_own_response") {
            return;
        }
        let dir = TempDir::new();
        let client = Arc::new(stub_client(&dir, 1_000_000, 10).await);

        let slow = {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                client
                    .send_task(serde_json::json!({
                        "task_type": "slow", "delay": 0.4, "payload": "slow-one"
                    }))
                    .await
            })
        };

        // Give the slow task a head start so it is genuinely outstanding.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let fast = client
            .send_task(serde_json::json!({ "task_type": "echo", "payload": "fast-one" }))
            .await
            .expect("the fast task replies");

        let slow = slow.await.unwrap().expect("the slow task replies");

        assert_eq!(fast["echo"], "fast-one");
        assert_eq!(slow["echo"], "slow-one");
    }

    #[tokio::test]
    async fn many_concurrent_sends_all_resolve_correctly() {
        // Scales the demux check past two, where an off-by-one in the pending
        // map would still look fine.
        if skip_without_python3("many_concurrent_sends_all_resolve_correctly") {
            return;
        }
        let dir = TempDir::new();
        let client = Arc::new(stub_client(&dir, 1_000_000, 20).await);

        let mut handles = Vec::with_capacity(16);
        for i in 0..16 {
            let client = Arc::clone(&client);
            handles.push(tokio::spawn(async move {
                let response = client
                    .send_task(serde_json::json!({ "task_type": "echo", "payload": i }))
                    .await
                    .expect("each task replies");
                (i, response["echo"].as_i64().unwrap())
            }));
        }

        for handle in handles {
            let (sent, echoed) = handle.await.unwrap();
            assert_eq!(
                sent, echoed,
                "response {echoed} was delivered to the caller that sent {sent}"
            );
        }
    }

    #[tokio::test]
    async fn an_oversized_task_is_rejected_before_it_is_sent() {
        if skip_without_python3("an_oversized_task_is_rejected_before_it_is_sent") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 256, 10).await;

        let err = client
            .send_task(serde_json::json!({ "task_type": "echo", "payload": "x".repeat(1024) }))
            .await
            .expect_err("a task over the cap must be rejected");

        match err {
            HostError::TaskTooLarge { size, limit } => {
                assert!(size > limit);
                assert_eq!(limit, 256);
            },
            other => panic!("expected TaskTooLarge, got {other:?}"),
        }

        // The client must still be usable — rejecting a task locally neither
        // wrote to the pipe nor desynced the worker.
        let response = client
            .send_task(serde_json::json!({ "task_type": "echo", "payload": "small" }))
            .await
            .expect("the client survives a rejected task");
        assert_eq!(response["echo"], "small");
    }

    // --- inbound bounds ------------------------------------------------------

    #[tokio::test]
    async fn an_oversized_response_frame_is_rejected_rather_than_buffered() {
        // The reviewer's finding: `max_content_size` was enforced only outbound,
        // so a worker could return a frame of any size and the host would grow
        // its heap to hold it. Before the fix this test hangs to the timeout
        // (the giant frame is buffered, parsed, and delivered as a success);
        // after it, the caller gets a prompt protocol error.
        if skip_without_python3("an_oversized_response_frame_is_rejected_rather_than_buffered") {
            return;
        }
        let dir = TempDir::new();
        // Big enough for the outbound task, far smaller than the reply.
        let client = stub_client(&dir, 4096, 10).await;

        let err = client
            .send_task(serde_json::json!({ "task_type": "huge", "size": 300_000 }))
            .await
            .expect_err("a response over the cap cannot be delivered");

        match err {
            HostError::ResponseTooLarge { size, limit } => {
                assert_eq!(limit, 4096, "the error carries the configured cap");
                assert!(
                    size >= limit,
                    "the reported size must be at least the cap it broke: {size}"
                );
                let message = err.to_string();
                assert!(
                    message.contains("4096") && message.contains("discarded"),
                    "the error should name the limit and say the frame was dropped: {message}"
                );
                assert!(
                    !message.contains("PPPP"),
                    "the error must not echo the frame it refused: {message}"
                );
            },
            other => panic!("expected a ResponseTooLarge error, got {other:?}"),
        }

        // Framing survived: the discarded frame was consumed to its newline, so
        // the next response lands on a real line boundary.
        let response = client
            .send_task(serde_json::json!({ "task_type": "echo", "payload": "still-framed" }))
            .await
            .expect("the stream is still in sync after a dropped frame");
        assert_eq!(response["echo"], "still-framed");
    }

    #[tokio::test]
    async fn an_unterminated_response_stream_does_not_grow_without_bound() {
        // The worst case for a line reader: bytes with no newline in sight.
        // `lines()` would buffer all of them; `read_bounded_line` stops
        // retaining at the cap and discards the rest as it arrives.
        if skip_without_python3("an_unterminated_response_stream_does_not_grow_without_bound") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 4096, 10).await;

        let err = client
            .send_task(serde_json::json!({ "task_type": "unframed", "size": 500_000 }))
            .await
            .expect_err("an unframed flood cannot answer the request");
        assert!(
            matches!(err, HostError::ResponseTooLarge { .. }),
            "got {err:?}"
        );

        // The stub appended a real response after the flood; the reader must
        // have resynced on that newline rather than staying wedged.
        let response = client
            .send_task(serde_json::json!({ "task_type": "echo", "payload": "resynced" }))
            .await
            .expect("the reader recovers at the next newline");
        assert_eq!(response["echo"], "resynced");
    }

    #[tokio::test]
    async fn oversized_stderr_is_truncated_rather_than_killing_the_worker() {
        // Stderr is diagnostic, so the policy differs from stdout: bound it and
        // mark the cut, but keep the worker alive — this is the channel that
        // explains a failure, and losing the worker over a verbose traceback
        // would trade a diagnostic for an outage.
        if skip_without_python3("oversized_stderr_is_truncated_rather_than_killing_the_worker") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 10).await;

        let response = client
            .send_task(serde_json::json!({
                "task_type": "loud", "size": 200_000, "payload": "survived"
            }))
            .await
            .expect("a loud worker is still a working worker");
        assert_eq!(response["echo"], "survived");
        assert!(client.is_alive());

        let lines = client.stderr_lines().await;
        let loud = lines
            .iter()
            .find(|line| line.starts_with("LLL"))
            .expect("the loud line was retained");

        assert!(
            loud.ends_with(TRUNCATION_MARKER),
            "a cut line must say so, or an operator reads it as the worker stopping mid-sentence"
        );
        assert!(
            loud.len() <= STDERR_MAX_LINE_BYTES + TRUNCATION_MARKER.len(),
            "the retained line is bounded: {} bytes",
            loud.len()
        );
        // And the prefix is genuinely useful, not an empty stub.
        assert!(loud.len() > STDERR_MAX_LINE_BYTES / 2);
    }

    #[tokio::test]
    async fn total_retained_stderr_stays_bounded_under_a_flood() {
        // Per-line truncation alone is not enough: many long lines must also be
        // capped, which is what the retain ring does. Together they put a hard
        // ceiling on stderr memory.
        if skip_without_python3("total_retained_stderr_stays_bounded_under_a_flood") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 20).await;

        for _ in 0..(STDERR_RETAIN_LINES * 2) {
            client
                .send_task(serde_json::json!({
                    "task_type": "loud", "size": 20_000, "payload": "ok"
                }))
                .await
                .expect("the worker keeps serving");
        }

        let lines = client.stderr_lines().await;
        assert!(
            lines.len() <= STDERR_RETAIN_LINES,
            "the ring must cap line count: {}",
            lines.len()
        );
        let total: usize = lines.iter().map(String::len).sum();
        assert!(
            total <= STDERR_RETAIN_LINES * (STDERR_MAX_LINE_BYTES + TRUNCATION_MARKER.len()),
            "retained stderr must have a hard ceiling: {total} bytes"
        );
    }

    // --- bounded line reading (no subprocess needed) -------------------------

    #[tokio::test]
    async fn a_bounded_read_returns_whole_lines_under_the_limit() {
        let mut reader = BufReader::new(&b"first\nsecond\n"[..]);

        for expected in ["first", "second"] {
            match read_bounded_line(&mut reader, 64).await.unwrap() {
                BoundedLine::Line(line) => assert_eq!(line, expected),
                other => panic!("expected a line, got {}", describe(&other)),
            }
        }
        assert!(matches!(
            read_bounded_line(&mut reader, 64).await.unwrap(),
            BoundedLine::Eof
        ));
    }

    #[tokio::test]
    async fn a_bounded_read_reports_the_scanned_size_and_keeps_only_the_cap() {
        let input = format!("{}\nafter\n", "x".repeat(500));
        let mut reader = BufReader::new(input.as_bytes());

        match read_bounded_line(&mut reader, 100).await.unwrap() {
            BoundedLine::Oversized { prefix, scanned } => {
                assert_eq!(prefix.len(), 100, "nothing past the cap is retained");
                assert_eq!(scanned, 500, "the true size is still reported");
            },
            other => panic!("expected Oversized, got {}", describe(&other)),
        }

        // Resync: the oversized line was consumed through its newline.
        match read_bounded_line(&mut reader, 100).await.unwrap() {
            BoundedLine::Line(line) => assert_eq!(line, "after"),
            other => panic!("expected the next line, got {}", describe(&other)),
        }
    }

    #[tokio::test]
    async fn a_line_exactly_at_the_limit_is_not_oversized() {
        // Off-by-one guard: the cap is the largest *acceptable* size, matching
        // the outbound `line.len() > max_content_size` comparison.
        let input = "xxxxx\n";
        let mut reader = BufReader::new(input.as_bytes());
        match read_bounded_line(&mut reader, 5).await.unwrap() {
            BoundedLine::Line(line) => assert_eq!(line, "xxxxx"),
            other => panic!(
                "5 bytes under a 5-byte cap is fine, got {}",
                describe(&other)
            ),
        }
    }

    #[tokio::test]
    async fn a_trailing_fragment_without_a_newline_is_still_a_line() {
        let mut reader = BufReader::new(&b"no trailing newline"[..]);
        match read_bounded_line(&mut reader, 64).await.unwrap() {
            BoundedLine::Line(line) => assert_eq!(line, "no trailing newline"),
            other => panic!("expected a line, got {}", describe(&other)),
        }
    }

    #[tokio::test]
    async fn a_bounded_read_trims_crlf_like_lines_does() {
        let mut reader = BufReader::new(&b"windows\r\n"[..]);
        match read_bounded_line(&mut reader, 64).await.unwrap() {
            BoundedLine::Line(line) => assert_eq!(line, "windows"),
            other => panic!("expected a line, got {}", describe(&other)),
        }
    }

    /// Name a `BoundedLine` for a panic message, since it has no `Debug`.
    fn describe(line: &BoundedLine) -> &'static str {
        match line {
            BoundedLine::Line(_) => "Line",
            BoundedLine::Oversized { .. } => "Oversized",
            BoundedLine::Eof => "Eof",
        }
    }

    #[test]
    fn a_request_id_is_recovered_from_a_truncated_frame() {
        // What lets the reader fail exactly the one caller whose response was
        // dropped instead of every in-flight request.
        assert_eq!(
            request_id_from_prefix(r#"{"request_id": "abc-123", "status": "succ"#),
            Some("abc-123".to_string())
        );
        assert_eq!(
            request_id_from_prefix(r#"{"status":"success","request_id":"xyz","pad":"PPP"#),
            Some("xyz".to_string())
        );
    }

    #[test]
    fn an_unrecoverable_request_id_is_reported_as_absent() {
        // Each of these must be a clean `None` — a wrong guess would fail the
        // wrong caller, which is worse than failing all of them.
        for prefix in [
            r#"{"status":"success","pad":"PPPP"#, // id not in the prefix
            r#"{"request_id": "cut-off-mid-val"#, // no closing quote
            r#"{"request_id""#,                   // no colon
            "",                                   // nothing at all
        ] {
            assert_eq!(
                request_id_from_prefix(prefix),
                None,
                "should not guess an id from {prefix:?}"
            );
        }
    }

    #[test]
    fn the_over_limit_error_names_the_response_not_the_task() {
        // Reusing `TaskTooLarge` would point an operator at their own outbound
        // payload for a fault in the worker's reply.
        let err = response_too_large(9_000, 4_096);
        let message = err.to_string();
        assert!(matches!(
            err,
            HostError::ResponseTooLarge {
                size: 9_000,
                limit: 4_096
            }
        ));
        assert_eq!(err.code(), "response_too_large");
        assert!(message.contains("response"), "{message}");
        assert!(!message.contains("serialized task"), "{message}");
        assert!(
            message.contains("9000") && message.contains("4096"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn no_response_within_the_timeout_yields_a_timeout_error() {
        if skip_without_python3("no_response_within_the_timeout_yields_a_timeout_error") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 1).await;

        let err = client
            .send_task(serde_json::json!({ "task_type": "slow", "delay": 5.0 }))
            .await
            .expect_err("a task that outruns the timeout must error");

        assert!(
            matches!(err, HostError::Timeout { timeout_secs: 1 }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_worker_error_response_becomes_a_worker_error() {
        if skip_without_python3("a_worker_error_response_becomes_a_worker_error") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 10).await;

        let err = client
            .send_task(serde_json::json!({ "task_type": "fail", "message": "plugin blew up" }))
            .await
            .expect_err("status=error must not be returned as success");

        match err {
            HostError::WorkerError { message } => assert!(message.contains("plugin blew up")),
            other => panic!("expected WorkerError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn worker_death_mid_flight_resolves_rather_than_hangs() {
        // The important one: a dead worker must not leave a caller waiting out
        // a timeout that can never be satisfied. The generous 30s client
        // timeout means a hang here would show up as a test that runs for 30s
        // and then reports Timeout instead of WorkerDied.
        if skip_without_python3("worker_death_mid_flight_resolves_rather_than_hangs") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 30).await;

        let started = std::time::Instant::now();
        let err = client
            .send_task(serde_json::json!({ "task_type": "die" }))
            .await
            .expect_err("a worker that exits without replying must error");

        assert!(
            matches!(err, HostError::WorkerDied { .. }),
            "expected WorkerDied (not Timeout), got {err:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the error must arrive on worker death, not on timeout expiry"
        );
    }

    #[tokio::test]
    async fn sends_after_worker_death_fail_fast() {
        if skip_without_python3("sends_after_worker_death_fail_fast") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 30).await;

        let _ = client
            .send_task(serde_json::json!({ "task_type": "die" }))
            .await;

        // A send issued *after* the death must also fail fast. Clearing
        // `pending` on EOF only rescues already-registered requests; without an
        // explicit liveness flag this send would register into an unwatched map
        // and wait out the full 30s timeout.
        let started = std::time::Instant::now();
        let err = client
            .send_task(serde_json::json!({ "task_type": "echo", "payload": "anyone home?" }))
            .await
            .expect_err("a send to a dead worker cannot succeed");

        assert!(
            matches!(err, HostError::WorkerDied { .. }),
            "expected WorkerDied, got {err:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "a send to a known-dead worker must fail immediately, not on timeout: {:?}",
            started.elapsed()
        );
        assert!(!client.is_alive());
    }

    #[tokio::test]
    async fn a_non_json_stdout_line_does_not_desync_the_stream() {
        // Plugins print. A stray line must be skipped, not consumed as if it
        // were the response to the pending request.
        if skip_without_python3("a_non_json_stdout_line_does_not_desync_the_stream") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 10).await;

        let response = client
            .send_task(serde_json::json!({ "task_type": "noisy", "payload": "after-the-noise" }))
            .await
            .expect("the real response still arrives");
        assert_eq!(response["echo"], "after-the-noise");
    }

    #[tokio::test]
    async fn shutdown_terminates_a_live_worker() {
        if skip_without_python3("shutdown_terminates_a_live_worker") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 10).await;

        client
            .send_task(serde_json::json!({ "task_type": "echo", "payload": "alive" }))
            .await
            .expect("worker is up");

        client.shutdown().await.expect("a cooperative worker exits");
        // Idempotent: teardown can be reached more than once.
        client
            .shutdown()
            .await
            .expect("a second shutdown is a no-op");
    }

    #[tokio::test]
    async fn a_worker_that_ignores_shutdown_is_killed_after_the_grace_window() {
        if skip_without_python3("a_worker_that_ignores_shutdown_is_killed_after_the_grace_window") {
            return;
        }
        let dir = TempDir::new();
        let client = stub_client(&dir, 1_000_000, 10).await;

        // Put the stub into a mode where it acknowledges shutdown and then
        // spins forever.
        client
            .send_task(serde_json::json!({ "task_type": "deaf" }))
            .await
            .expect("stub accepts deaf mode");

        let started = std::time::Instant::now();
        client
            .shutdown()
            .await
            .expect("an unresponsive worker is killed, not waited on forever");

        let elapsed = started.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_secs(SHUTDOWN_GRACE_SECS),
            "the grace window should be honored before killing: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(SHUTDOWN_GRACE_SECS + 5),
            "the kill must happen promptly once the window expires: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_death_error_carries_the_workers_stderr() {
        // A worker that dies during startup — a bad dependency pin, a missing
        // module — explains itself on stderr and nowhere else. Without the
        // tail, the host reports a bare "worker process died" and the operator
        // has nothing to act on.
        if skip_without_python3("a_death_error_carries_the_workers_stderr") {
            return;
        }
        let dir = TempDir::new();
        let script = dir.path().join("import_error.py");
        std::fs::write(
            &script,
            "import sys\nprint('ImportError: cannot import name McpError', file=sys.stderr, flush=True)\nsys.exit(1)\n",
        )
        .unwrap();

        let client =
            WorkerClient::spawn(&which_python3(), &script, Some(dir.path()), 1_000_000, 30)
                .await
                .expect("the process starts, then exits");

        let err = client
            .send_task(serde_json::json!({ "task_type": "echo" }))
            .await
            .expect_err("a dead worker cannot answer");

        let message = err.to_string();
        assert!(matches!(err, HostError::WorkerDied { .. }), "got {err:?}");
        assert!(
            message.contains("McpError"),
            "the death error should carry the stderr that explains it: {message}"
        );
    }

    #[tokio::test]
    async fn spawning_against_a_missing_interpreter_errors() {
        let err = WorkerClient::spawn(
            Path::new("/nonexistent/bin/python"),
            Path::new("/tmp/worker.py"),
            None,
            1024,
            5,
        )
        .await
        .expect_err("a missing interpreter cannot be launched");

        assert!(matches!(err, HostError::WorkerStart { .. }), "got {err:?}");
    }

    // --- response interpretation (no subprocess needed) ---------------------

    #[test]
    fn an_error_envelope_becomes_a_worker_error() {
        let err = interpret_response(serde_json::json!({
            "status": "error", "message": "boom", "request_id": "abc"
        }))
        .expect_err("status=error is a failure");
        match err {
            HostError::WorkerError { message } => assert_eq!(message, "boom"),
            other => panic!("expected WorkerError, got {other:?}"),
        }
    }

    #[test]
    fn an_error_envelope_without_a_message_still_errors() {
        let err = interpret_response(serde_json::json!({ "status": "error" }))
            .expect_err("a message-less error is still an error");
        assert!(matches!(err, HostError::WorkerError { .. }));
    }

    #[test]
    fn a_success_envelope_is_returned_without_its_request_id() {
        let response = interpret_response(serde_json::json!({
            "status": "success", "continue_processing": true, "request_id": "abc"
        }))
        .expect("success passes through");
        assert!(response.get("request_id").is_none());
        assert_eq!(response["continue_processing"], true);
    }

    #[test]
    fn a_result_envelope_with_no_status_field_is_success() {
        // The hook path returns `model_dump()` of a result model, which has no
        // `status` key at all — treating "no status" as an error would fail
        // every successful invocation.
        let response = interpret_response(serde_json::json!({
            "continue_processing": false, "violation": {"code": "pii"}
        }))
        .expect("a bare result model is not an error");
        assert_eq!(response["violation"]["code"], "pii");
    }

    // --- worker script resolution ------------------------------------------

    #[test]
    fn an_absolute_script_path_bypasses_venv_resolution() {
        let resolved = resolve_worker_script(Path::new("/venv"), "/opt/custom/worker.py").unwrap();
        assert_eq!(resolved, PathBuf::from("/opt/custom/worker.py"));
    }

    #[test]
    fn the_worker_script_is_found_in_unix_site_packages() {
        let dir = TempDir::new();
        let site = dir
            .path()
            .join("lib")
            .join("python3.12")
            .join("site-packages");
        let worker = site.join("cpex").join("framework").join("isolated");
        std::fs::create_dir_all(&worker).unwrap();
        std::fs::write(worker.join("worker.py"), "# stub").unwrap();

        let resolved =
            resolve_worker_script(dir.path(), "cpex/framework/isolated/worker.py").unwrap();
        assert_eq!(resolved, worker.join("worker.py"));
    }

    #[test]
    fn a_missing_worker_script_names_the_venv_and_the_likely_cause() {
        let dir = TempDir::new();
        let err = resolve_worker_script(dir.path(), "cpex/framework/isolated/worker.py")
            .expect_err("an empty venv has no worker");

        let message = err.to_string();
        assert!(message.contains("worker.py"));
        assert!(
            message.contains("cpex"),
            "the message should point at the missing framework: {message}"
        );
    }
}
