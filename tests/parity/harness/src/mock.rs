// Location: ./tests/parity/harness/src/mock.rs
// SPDX-License-Identifier: Apache-2.0
//
// Mock upstream for the IdP JWKS, OAuth token exchange and CIBA endpoints.
// Routes come from the scenario file; every call is logged (credential
// form fields dropped) so snapshots show which upstream calls a request
// caused.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde_json::{Value, json};

use crate::keys::KeyRing;
use crate::spec::MockRoute;

/// Form fields never written to a snapshot.
const SECRET_FIELDS: &[&str] = &[
    "subject_token",
    "actor_token",
    "client_secret",
    "client_assertion",
    "password",
    "refresh_token",
];

pub struct MockServer {
    url: String,
    server: Arc<tiny_http::Server>,
    calls: Arc<Mutex<Vec<Value>>>,
    worker: Option<JoinHandle<()>>,
}

impl MockServer {
    pub fn start(routes: Vec<MockRoute>, keys: &KeyRing) -> Result<Self, String> {
        let server = Arc::new(
            tiny_http::Server::http("127.0.0.1:0").map_err(|e| format!("mock bind: {e}"))?,
        );
        let port = server
            .server_addr()
            .to_ip()
            .map(|a| a.port())
            .ok_or("mock server has no IP address")?;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let jwks = keys.jwks().to_string();

        let worker = {
            let server = server.clone();
            let calls = calls.clone();
            std::thread::spawn(move || {
                let mut hits = vec![0u32; routes.len()];
                for mut req in server.incoming_requests() {
                    let method = req.method().as_str().to_ascii_uppercase();
                    let path = req.url().split('?').next().unwrap_or("").to_string();
                    let mut body = String::new();
                    let _ = req.as_reader().read_to_string(&mut body);
                    let form: BTreeMap<String, String> = form_urlencoded::parse(body.as_bytes())
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                        .collect();

                    let logged: BTreeMap<&String, &String> = form
                        .iter()
                        .filter(|(k, _)| !SECRET_FIELDS.contains(&k.as_str()))
                        .collect();
                    calls
                        .lock()
                        .unwrap()
                        .push(json!({ "method": method, "path": path, "form": logged }));

                    let idx = routes.iter().enumerate().position(|(i, r)| {
                        r.method.eq_ignore_ascii_case(&method)
                            && r.path == path
                            && r.form.iter().all(|(k, v)| form.get(k) == Some(v))
                            && r.max_hits.is_none_or(|max| hits[i] < max)
                    });
                    if let Some(i) = idx {
                        hits[i] += 1;
                    }
                    let route = idx.map(|i| &routes[i]);
                    let (status, body) = match route {
                        Some(r) => {
                            let body = match (r.builtin.as_deref(), &r.json) {
                                (Some("jwks"), _) => jwks.clone(),
                                (_, Some(v)) => v.to_string(),
                                _ => String::new(),
                            };
                            (r.status, body)
                        },
                        None => (404, json!({ "error": "no_mock_route" }).to_string()),
                    };
                    let header = tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"application/json"[..],
                    )
                    .expect("static header");
                    let _ = req.respond(
                        tiny_http::Response::from_string(body)
                            .with_status_code(status)
                            .with_header(header),
                    );
                }
            })
        };

        Ok(Self {
            url: format!("http://127.0.0.1:{port}"),
            server,
            calls,
            worker: Some(worker),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Calls received since the last drain, in arrival order.
    pub fn drain_calls(&self) -> Vec<Value> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
