// Location: ./crates/cpex-ffi/tests/common/mod.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Shared helpers for the FFI integration tests: a tiny scripted HTTP
// server on loopback, a warning-capturing tracing subscriber, and thin
// wrappers over the C entry points.

#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};

use cpex_ffi::{
    cpex_apl_install, cpex_engine_new_default, cpex_free_background, cpex_free_bytes,
    cpex_free_context_table, cpex_initialize, cpex_invoke, cpex_load_config,
    CpexBackgroundTasksInner, CpexContextTableInner, CpexEngineInner, RC_OK,
};

// ---------------------------------------------------------------------
// Scripted HTTP server
// ---------------------------------------------------------------------

type Routes = Arc<Mutex<HashMap<String, (u16, String)>>>;

/// A loopback HTTP/1.1 server answering each path with a scripted status
/// and JSON body. One thread per connection, `Connection: close` on every
/// response. Unscripted paths answer 404.
pub struct MockServer {
    port: u16,
    routes: Routes,
    hits: Arc<Mutex<HashMap<String, usize>>>,
}

impl MockServer {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let routes: Routes = Arc::default();
        let hits: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let (r, h) = (Arc::clone(&routes), Arc::clone(&hits));
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (r, h) = (Arc::clone(&r), Arc::clone(&h));
                std::thread::spawn(move || serve(stream, &r, &h));
            }
        });
        Self { port, routes, hits }
    }

    pub fn set(&self, path: &str, status: u16, body: &str) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_owned(), (status, body.to_owned()));
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    pub fn hits(&self, path: &str) -> usize {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }
}

fn serve(stream: TcpStream, routes: &Routes, hits: &Mutex<HashMap<String, usize>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let target = request_line.split_whitespace().nth(1).unwrap_or("/");
    let path = target.split('?').next().unwrap_or("/").to_owned();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    let _ = reader.read_exact(&mut body);

    *hits.lock().unwrap().entry(path.clone()).or_insert(0) += 1;
    let (status, payload) = routes
        .lock()
        .unwrap()
        .get(&path)
        .cloned()
        .unwrap_or_else(|| (404, r#"{"errors":["not found"]}"#.to_owned()));
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{payload}",
        payload.len()
    );
    let mut stream = stream;
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

// ---------------------------------------------------------------------
// Warning capture
// ---------------------------------------------------------------------

static LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={:?} ", field.name(), value);
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        LOGS.lock().unwrap().push(fields.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Install the process-wide warning capture. Safe to call from every test.
pub fn capture_warnings() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = tracing::subscriber::set_global_default(Capture);
    });
}

/// Every captured warning or error line containing all of `needles`.
pub fn warnings_containing(needles: &[&str]) -> Vec<String> {
    LOGS.lock()
        .unwrap()
        .iter()
        .filter(|line| needles.iter().all(|n| line.contains(n)))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------
// FFI wrappers
// ---------------------------------------------------------------------

/// Owns an engine handle and shuts it down on drop.
pub struct Engine(pub *mut CpexEngineInner);

impl Engine {
    /// `cpex_engine_new_default` then `cpex_apl_install(flags)`.
    pub fn installed(flags: u32) -> Self {
        let handle = cpex_engine_new_default();
        assert!(!handle.is_null());
        assert_eq!(unsafe { cpex_apl_install(handle, flags) }, RC_OK);
        Self(handle)
    }

    pub fn inner(&self) -> &CpexEngineInner {
        unsafe { &*self.0 }
    }

    pub fn load(&self, yaml: &str) -> c_int {
        unsafe { cpex_load_config(self.0, yaml.as_ptr() as *const c_char, yaml.len() as c_int) }
    }

    pub fn initialize(&self) -> c_int {
        unsafe { cpex_initialize(self.0) }
    }

    /// `cpex_invoke` without a context table; returns the rc and, on
    /// `RC_OK`, the decoded result.
    pub fn invoke(
        &self,
        hook: &str,
        payload_type: u8,
        payload: &[u8],
    ) -> (c_int, Option<FfiResult>) {
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: c_int = 0;
        let mut ct: *mut CpexContextTableInner = ptr::null_mut();
        let mut bg: *mut CpexBackgroundTasksInner = ptr::null_mut();
        unsafe {
            let rc = cpex_invoke(
                self.0,
                hook.as_ptr() as *const c_char,
                hook.len() as c_int,
                payload_type,
                payload.as_ptr(),
                payload.len() as c_int,
                ptr::null(),
                0,
                ptr::null_mut(),
                &mut out,
                &mut out_len,
                &mut ct,
                &mut bg,
            );
            let mut decoded = None;
            if !out.is_null() {
                let bytes = std::slice::from_raw_parts(out, out_len as usize);
                decoded = Some(rmp_serde::from_slice(bytes).expect("decode FFI result"));
                cpex_free_bytes(out, out_len);
            }
            if !ct.is_null() {
                cpex_free_context_table(ct);
            }
            if !bg.is_null() {
                cpex_free_background(bg);
            }
            (rc, decoded)
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { cpex_ffi::cpex_shutdown(self.0) };
    }
}

/// The FFI pipeline result as a host decodes it.
#[derive(Debug, serde::Deserialize)]
pub struct FfiResult {
    pub continue_processing: bool,
    #[serde(default)]
    pub violation: Option<serde_json::Value>,
    #[serde(default)]
    pub payload_type: u8,
    #[serde(default)]
    pub modified_payload: Option<serde_bytes::ByteBuf>,
}

impl FfiResult {
    pub fn violation_code(&self) -> Option<&str> {
        self.violation.as_ref()?.get("code")?.as_str()
    }
}

/// Run a future to completion on a private current-thread runtime.
pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(fut)
}
