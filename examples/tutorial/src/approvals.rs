// Location: ./examples/tutorial/src/approvals.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// A deliberately tiny human-approval channel for the elicitation module
// (module 8). When policy suspends an operation awaiting a human, the
// request lands here as "pending"; a human approves or denies it out of
// band, in the tutorial, with a `curl` from a second terminal:
//
//   curl localhost:8090/approvals                     # list pending
//   curl -X POST localhost:8090/approvals/<id>/approve
//   curl -X POST localhost:8090/approvals/<id>/deny
//
// This stands in for what a production deployment does with a real
// out-of-band channel (a push notification to an approver's phone, an
// OIDC CIBA backchannel, a Slack action). The point of module 8 is CPEX's
// suspend/resume model, not the transport, so we keep the transport a
// one-screen HTTP server. The "Go deeper" link points at the full
// Keycloak-CIBA channel for readers who want the real backchannel.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Status of a pending approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Approved,
    Denied,
}

/// One approval request tracked by the channel.
#[derive(Debug, Clone)]
pub struct Request {
    pub id: String,
    pub approver: String,
    pub purpose: String,
    pub status: Status,
}

/// Shared, thread-safe store of approval requests. Cloneable handle, the
/// HTTP server thread and the policy path share one store.
#[derive(Clone, Default)]
pub struct ApprovalChannel {
    inner: Arc<Mutex<HashMap<String, Request>>>,
}

impl ApprovalChannel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new pending request (called when policy suspends).
    pub fn open(&self, id: &str, approver: &str, purpose: &str) {
        let mut map = self.inner.lock().unwrap();
        map.entry(id.to_string()).or_insert_with(|| Request {
            id: id.to_string(),
            approver: approver.to_string(),
            purpose: purpose.to_string(),
            status: Status::Pending,
        });
    }

    /// Current status of a request (`None` if unknown).
    pub fn status(&self, id: &str) -> Option<Status> {
        self.inner.lock().unwrap().get(id).map(|r| r.status)
    }

    /// Approve or deny a request. Returns `true` if the id was found.
    pub fn resolve(&self, id: &str, approved: bool) -> bool {
        let mut map = self.inner.lock().unwrap();
        if let Some(req) = map.get_mut(id) {
            req.status = if approved {
                Status::Approved
            } else {
                Status::Denied
            };
            true
        } else {
            false
        }
    }

    /// Snapshot of all requests, for the `GET /approvals` listing.
    pub fn list(&self) -> Vec<Request> {
        self.inner.lock().unwrap().values().cloned().collect()
    }

    /// Start the HTTP server on `port` in a background thread. Returns the
    /// join handle; the server runs until the process exits.
    pub fn serve(&self, port: u16) -> std::thread::JoinHandle<()> {
        let channel = self.clone();
        std::thread::spawn(move || {
            let server = match tiny_http::Server::http(("127.0.0.1", port)) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("approval channel failed to bind port {port}: {e}");
                    return;
                },
            };
            for request in server.incoming_requests() {
                let (status, body) = route(&channel, request.method(), request.url());
                let response = tiny_http::Response::from_string(body).with_status_code(status);
                let _ = request.respond(response);
            }
        })
    }
}

/// Route one HTTP request to a (status, body) pair. Split out so it can be
/// unit-tested without a live socket.
fn route(channel: &ApprovalChannel, method: &tiny_http::Method, url: &str) -> (u16, String) {
    let path = url.trim_end_matches('/');
    match (method, path) {
        (tiny_http::Method::Get, "/approvals") => {
            let lines: Vec<String> = channel
                .list()
                .iter()
                .map(|r| {
                    format!(
                        "{}\t{:?}\tapprover={}\t{}",
                        r.id, r.status, r.approver, r.purpose
                    )
                })
                .collect();
            let body = if lines.is_empty() {
                "no pending approvals\n".to_string()
            } else {
                format!("{}\n", lines.join("\n"))
            };
            (200, body)
        },
        (tiny_http::Method::Post, p) if p.ends_with("/approve") || p.ends_with("/deny") => {
            let approved = p.ends_with("/approve");
            let id = p
                .trim_start_matches("/approvals/")
                .trim_end_matches("/approve")
                .trim_end_matches("/deny");
            if channel.resolve(id, approved) {
                let verb = if approved { "approved" } else { "denied" };
                (200, format!("{id} {verb}\n"))
            } else {
                (404, format!("no pending approval '{id}'\n"))
            }
        },
        _ => (404, "not found\n".to_string()),
    }
}
