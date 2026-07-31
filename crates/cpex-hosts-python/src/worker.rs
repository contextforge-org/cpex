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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Value>>>>;

/// How many recent stderr lines to retain for diagnosis.
///
/// A worker that dies at import time (a bad dependency pin, a missing module)
/// says so on stderr and nowhere else. Without this, the host reports only
/// "worker process died" and the actual cause is lost — the tail is small
/// enough to be cheap and long enough to hold a Python traceback.
const STDERR_RETAIN_LINES: usize = 40;

/// Ring buffer of the worker's most recent stderr lines.
type StderrTail = Arc<Mutex<std::collections::VecDeque<String>>>;

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
        tokio::spawn(reader_loop(
            stdout,
            Arc::clone(&pending),
            Arc::clone(&alive),
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
                Ok(Ok(response)) => response,
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
/// On EOF, `pending` is drained and every sender dropped, which resolves each
/// in-flight `send_task` to `WorkerDied` rather than leaving it to time out.
async fn reader_loop(stdout: tokio::process::ChildStdout, pending: Pending, alive: Alive) {
    let mut lines = BufReader::new(stdout).lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
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
                        let _ = tx.send(response);
                    },
                    None => {
                        // The fixed "shutdown" id lands here by design, as does
                        // any late response whose caller has given up.
                        tracing::debug!(request_id, "response for an unknown request id");
                    },
                }
            },
            Ok(None) => {
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

/// Log the worker's stderr and retain a bounded tail for diagnosis.
///
/// Logged at debug: the worker's own logging goes here, and a credential-bearing
/// hook must never surface token material through it. `worker.py` scrubs its
/// side (it holds the plaintext only to scrub it back out of anything the
/// plugin logs, raises, or returns); this side never parses these lines or
/// echoes them anywhere except into a `WorkerDied` message, which is the one
/// place an operator genuinely needs them.
async fn stderr_loop(stderr: tokio::process::ChildStderr, tail: StderrTail) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
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
