// Location: ./crates/cpex-hosts-python/src/isolated/subprocess.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// WorkerProcess — long-running worker.py subprocess lifecycle.
//
// Mirrors Python's VenvProcessCommunicator (venv_comm.py):
//   - spawn: tokio::process::Command with stdin/stdout/stderr piped
//   - send_task: write JSON-lines task + request_id, await oneshot response
//   - shutdown: send {"task_type":"shutdown"}, wait, then kill
//   - Drop: synchronously kills the child to prevent subprocess orphans

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("task timed out after {0:?}")]
    Timeout(Duration),
    #[error("worker process died or channel closed")]
    ProcessDied,
    #[error("worker returned error: {0}")]
    WorkerError(String),
}

type ResponseSender = oneshot::Sender<Result<serde_json::Value, WorkerError>>;

/// Message sent to the background I/O task.
struct WorkerTask {
    request_id: String,
    task_data: serde_json::Value,
    reply_tx: ResponseSender,
}

/// Long-running worker.py subprocess with JSON-lines I/O.
pub struct WorkerProcess {
    /// Sender to the background I/O task. `None` after shutdown.
    task_tx: Arc<Mutex<Option<tokio::sync::mpsc::Sender<WorkerTask>>>>,
    /// Handle for the background I/O task.
    _io_task: tokio::task::JoinHandle<()>,
    /// The child process handle — kept for kill() in Drop.
    ///
    /// Wrapped in Arc<Mutex> so we can share it between the Drop impl
    /// and the background I/O task (which needs to signal process death).
    child_pid: Arc<Mutex<Option<u32>>>,
    /// Raw kill handle — we keep a separate `std::process::Child`-level
    /// kill path because `tokio::process::Child::kill()` is async and
    /// unavailable in Drop. We use a raw kill(pid, SIGKILL) instead.
    raw_child: Arc<Mutex<Option<Child>>>,
}

impl WorkerProcess {
    /// Spawn the worker.py subprocess and start the background I/O task.
    pub async fn spawn(python_exe: &Path, script_path: &Path, cwd: &Path) -> Result<Self, WorkerError> {
        let mut child = Command::new(python_exe)
            .arg(script_path)
            .current_dir(cwd)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let pid = child.id();
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let (task_tx, mut task_rx) = tokio::sync::mpsc::channel::<WorkerTask>(64);
        let task_tx = Arc::new(Mutex::new(Some(task_tx)));

        let raw_child = Arc::new(Mutex::new(Some(child)));
        let raw_child_for_io = Arc::clone(&raw_child);

        // Background task: owns stdin writer + stdout reader, routes responses.
        let io_task = tokio::spawn(async move {
            let mut writer = tokio::io::BufWriter::new(stdin);
            let mut reader = BufReader::new(stdout);
            let mut stderr_reader = BufReader::new(stderr);

            // Pending requests waiting for their response.
            let mut pending: HashMap<String, ResponseSender> = HashMap::new();
            let mut line_buf = String::new();
            let mut stderr_buf = String::new();

            loop {
                tokio::select! {
                    // New task to send.
                    maybe_task = task_rx.recv() => {
                        let Some(task) = maybe_task else {
                            // Sender dropped — shut down.
                            break;
                        };
                        let mut obj = task.task_data.clone();
                        if let Some(map) = obj.as_object_mut() {
                            map.insert("request_id".to_string(), serde_json::json!(task.request_id.clone()));
                        }
                        let line = match serde_json::to_string(&obj) {
                            Ok(s) => s,
                            Err(e) => {
                                let _ = task.reply_tx.send(Err(WorkerError::Json(e)));
                                continue;
                            }
                        };
                        pending.insert(task.request_id, task.reply_tx);
                        if let Err(e) = writer.write_all(format!("{}\n", line).as_bytes()).await {
                            error!("failed to write to worker stdin: {}", e);
                            break;
                        }
                        if let Err(e) = writer.flush().await {
                            error!("failed to flush worker stdin: {}", e);
                            break;
                        }
                    }
                    // Response line from worker stdout.
                    n = reader.read_line(&mut line_buf) => {
                        match n {
                            Ok(0) => {
                                // EOF — worker exited.
                                info!("worker stdout EOF");
                                break;
                            }
                            Ok(_) => {
                                let trimmed = line_buf.trim();
                                if !trimmed.is_empty() {
                                    match serde_json::from_str::<serde_json::Value>(trimmed) {
                                        Ok(resp) => {
                                            let rid = resp.get("request_id")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("")
                                                .to_string();
                                            if let Some(tx) = pending.remove(&rid) {
                                                // Check for worker-level error.
                                                if resp.get("status").and_then(|v| v.as_str()) == Some("error") {
                                                    let msg = resp.get("message")
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("worker error")
                                                        .to_string();
                                                    let _ = tx.send(Err(WorkerError::WorkerError(msg)));
                                                } else {
                                                    let _ = tx.send(Ok(resp));
                                                }
                                            } else {
                                                debug!("no pending request for request_id={:?}", rid);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("could not parse worker response: {} — {:?}", e, trimmed);
                                        }
                                    }
                                }
                                line_buf.clear();
                            }
                            Err(e) => {
                                error!("error reading worker stdout: {}", e);
                                break;
                            }
                        }
                    }
                    // Drain stderr to logs.
                    n = stderr_reader.read_line(&mut stderr_buf) => {
                        match n {
                            Ok(0) | Err(_) => {}
                            Ok(_) => {
                                let trimmed = stderr_buf.trim();
                                if !trimmed.is_empty() {
                                    debug!("[worker stderr] {}", trimmed);
                                }
                                stderr_buf.clear();
                            }
                        }
                    }
                }
            }

            // Drain any remaining pending requests with ProcessDied.
            for (_, tx) in pending.drain() {
                let _ = tx.send(Err(WorkerError::ProcessDied));
            }

            // Wait for child to exit.
            let mut guard = raw_child_for_io.lock().await;
            if let Some(mut child) = guard.take() {
                if let Err(e) = child.wait().await {
                    debug!("worker wait() error: {}", e);
                }
            }
        });

        Ok(Self {
            task_tx,
            _io_task: io_task,
            child_pid: Arc::new(Mutex::new(pid)),
            raw_child,
        })
    }

    /// Send a task dict and await the response, with a timeout.
    pub async fn send_task(
        &self,
        task_data: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, WorkerError> {
        let request_id = Uuid::new_v4().to_string();
        let (reply_tx, reply_rx) = oneshot::channel();

        {
            let guard = self.task_tx.lock().await;
            let sender = guard.as_ref().ok_or(WorkerError::ProcessDied)?;
            sender
                .send(WorkerTask {
                    request_id,
                    task_data,
                    reply_tx,
                })
                .await
                .map_err(|_| WorkerError::ProcessDied)?;
        }

        tokio::time::timeout(timeout, reply_rx)
            .await
            .map_err(|_| WorkerError::Timeout(timeout))?
            .map_err(|_| WorkerError::ProcessDied)?
    }

    /// Graceful shutdown: send shutdown task, wait up to `timeout_secs`, then kill.
    pub async fn shutdown(&self, timeout_secs: u64) {
        let shutdown_data = serde_json::json!({
            "task_type": "shutdown",
        });
        let timeout = Duration::from_secs(timeout_secs);
        match self.send_task(shutdown_data, timeout).await {
            Ok(_) => {
                info!("worker shutdown acknowledged");
            }
            Err(WorkerError::Timeout(_)) => {
                warn!("worker shutdown timed out — killing");
                self.kill().await;
            }
            Err(e) => {
                debug!("worker shutdown send error: {} — likely already dead", e);
            }
        }
        // Close the sender so the I/O task can finish.
        *self.task_tx.lock().await = None;
    }

    async fn kill(&self) {
        let mut guard = self.raw_child.lock().await;
        if let Some(ref mut child) = *guard {
            if let Err(e) = child.kill().await {
                debug!("kill() error: {}", e);
            }
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        // Best-effort synchronous kill to prevent orphan subprocesses.
        // We send SIGKILL via the OS directly since we can't await here.
        if let Ok(guard) = self.child_pid.try_lock() {
            if let Some(pid) = *guard {
                #[cfg(unix)]
                {
                    unsafe {
                        libc_kill(pid as i32, 9); // SIGKILL
                    }
                }
                #[cfg(windows)]
                {
                    // On Windows, TerminateProcess would be the equivalent.
                    // For now we rely on the OS cleaning up when this process exits.
                    let _ = pid;
                }
            }
        }
    }
}

#[cfg(unix)]
unsafe fn libc_kill(pid: i32, sig: i32) {
    // Use the libc kill(2) syscall directly.
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    kill(pid, sig);
}
