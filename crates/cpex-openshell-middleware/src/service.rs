// Location: ./crates/cpex-openshell-middleware/src/service.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Xiaokui Shu
//
// The `SupervisorMiddleware` gRPC server: OpenShell's request-only egress hook
// backed by CPEX. `Describe` advertises the single V1 binding
// (HTTP_REQUEST / PRE_CREDENTIALS). `ValidateConfig` checks the REST tool map.
// `EvaluateHttpRequest` runs CPEX pre-invocation and returns allow/deny.
//
// Enforcement contract (matches the integration proposal's invariants):
// - CPEX is consulted only after OpenShell's L4 + baseline gates admit the
//   request, and can only narrow — it returns ALLOW (proceed) or DENY, never a
//   credential write or body mutation. Deny wins; CPEX never widens.
// - Every error path (parse, identity, PDP, JWKS, session-store, runtime) maps
//   to DENY. The service never returns ALLOW on error. OpenShell's binding is
//   additionally configured `fail_closed`, so an unreachable service also denies.
// - The `Pending` (elicitation) outcome cannot be expressed on the request-only
//   contract, so it maps to a DENY with a distinct reason code rather than a
//   silent allow.

use std::sync::Arc;

use cpex::embed::{CpexAuthorizer, Outcome};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::adapter::{self, MappedOperation};
use crate::config::RestToolMap;
use crate::proto::supervisor_middleware_server::SupervisorMiddleware;
use crate::proto::{
    Decision, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding, MiddlewareManifest,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
    ValidateConfigResponse,
};

/// The CMF tool pre-invoke hook every egress operation is mapped onto. Only the
/// pre phase is used (the request-only contract carries no post phase).
const HOOK_TOOL_PRE_INVOKE: &str = "cmf.tool_pre_invoke";

/// Reason code returned when an `engine: cpex` request maps to no tool. Fail
/// closed — no unevaluated bytes are forwarded.
const REASON_NO_TOOL: &str = "cpex_no_tool_mapping";
/// Reason code for any internal evaluation error (parse/identity/PDP/runtime).
/// Fail closed.
const REASON_ERROR: &str = "cpex_evaluation_error";
/// Reason code for a `Pending` (CIBA) outcome, which the request-only contract
/// cannot suspend/resume; denied here rather than silently allowed.
const REASON_ELICITATION_UNSUPPORTED: &str = "cpex_elicitation_unsupported";

/// The maximum request body this binding accepts (advertised in `Describe`).
/// The demo bodies (JSON-RPC `tools/call`) are tiny; 256 KiB is generous.
const MAX_BODY_BYTES: u64 = 262_144;

/// gRPC message-size ceiling the server accepts, matching OpenShell's client
/// (`MIDDLEWARE_GRPC_MESSAGE_BYTES` ≈ 4 MiB + envelope).
pub const GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024 + 300 * 1024;

/// The CPEX-backed supervisor middleware.
pub struct CpexMiddlewareService {
    authorizer: Arc<CpexAuthorizer>,
    /// Human-readable service name reported in the manifest (diagnostic only).
    service_name: String,
}

impl CpexMiddlewareService {
    pub fn new(authorizer: Arc<CpexAuthorizer>) -> Self {
        Self {
            authorizer,
            service_name: "cpex-openshell-middleware".to_string(),
        }
    }

    /// Core evaluation, factored out of the tonic wrapper so it is directly
    /// unit-testable. Returns a fully-formed `HttpRequestResult`; never errors
    /// out of band (every failure is a DENY result), so OpenShell always gets a
    /// definite decision on a successful RPC.
    pub async fn evaluate(&self, eval: HttpRequestEvaluation) -> HttpRequestResult {
        // Parse the per-binding REST tool map. A malformed config is a
        // fail-closed deny (it should have been rejected at ValidateConfig).
        let rest_map = match eval
            .config
            .as_ref()
            .map(struct_to_json)
            .map(|json| RestToolMap::from_config_json(&json))
        {
            Some(Ok(map)) => map,
            Some(Err(reason)) => {
                warn!(%reason, "rejecting request: bad middleware config");
                return deny(REASON_ERROR);
            },
            None => RestToolMap::default(),
        };

        // Map the egress request to a CMF tool operation. Unmapped → fail closed.
        let Some(MappedOperation {
            tool,
            payload,
            mut extensions,
        }) = adapter::map_operation(&eval, &rest_map)
        else {
            info!("denying: request maps to no CPEX tool");
            return deny(REASON_NO_TOOL);
        };

        // Resolve identity from the dedicated header only (never Authorization).
        // Absence yields no subject; identity-gated routes then deny. A failed
        // resolution (bad signature / issuer / audience / expiry) is a deny.
        if let Some(token) = adapter::identity_token(&eval) {
            match self.authorizer.resolve_identity(&token, extensions.clone()).await {
                Ok(enriched) => extensions = enriched,
                Err(outcome) => return outcome_to_result(outcome),
            }
        }

        // Pre-invocation: `require`/`taint` steps run here. Deny-wins is enforced
        // by the CPEX pipeline; a taint label committed now (e.g. in
        // get_compensation) is durable before this returns (the embed API awaits
        // background tasks), so a later send_email on the same session sees it.
        let outcome = self
            .authorizer
            .invoke(HOOK_TOOL_PRE_INVOKE, payload, extensions)
            .await;
        info!(tool = %tool, decision = ?discriminant(&outcome), "cpex pre-invocation");
        outcome_to_result(outcome)
    }

    fn manifest(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: self.service_name.clone(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            // The single V1 binding: request-phase, pre-credentials. This is the
            // whole contract — no response or suspend phase exists to advertise.
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_body_bytes: MAX_BODY_BYTES,
                timeout: String::new(),
            }],
        }
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for CpexMiddlewareService {
    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(self.manifest()))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let req = request.into_inner();
        let json = req.config.as_ref().map(struct_to_json).unwrap_or(serde_json::Value::Null);
        let response = match RestToolMap::from_config_json(&json).and_then(|m| m.validate()) {
            Ok(()) => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Err(reason) => ValidateConfigResponse { valid: false, reason },
        };
        Ok(Response::new(response))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        Ok(Response::new(self.evaluate(request.into_inner()).await))
    }
}

/// Map a CPEX [`Outcome`] to an OpenShell [`HttpRequestResult`].
///
/// The request is never mutated: an allow proceeds unchanged (OpenShell then
/// injects its own credentials and forwards), a deny stops the request before
/// credentials/egress. `Pending` cannot be honored on the request-only contract
/// and is denied with a distinct code.
fn outcome_to_result(outcome: Outcome) -> HttpRequestResult {
    match outcome {
        Outcome::Allow { .. } => HttpRequestResult {
            decision: Decision::Allow as i32,
            reason: String::new(),
            body: Vec::new(),
            has_body: false,
            header_mutations: Vec::new(),
            findings: Vec::new(),
            metadata: Default::default(),
            reason_code: String::new(),
        },
        // `reason` is a free-form diagnostic OpenShell does NOT relay to the
        // caller or logs; `reason_code` is the stable machine code it may return.
        // Neither carries a secret (the CPEX code/reason are non-secret by
        // construction).
        Outcome::Deny { code, reason } => HttpRequestResult {
            decision: Decision::Deny as i32,
            reason,
            body: Vec::new(),
            has_body: false,
            header_mutations: Vec::new(),
            findings: Vec::new(),
            metadata: Default::default(),
            reason_code: sanitize_reason_code(&code),
        },
        Outcome::Pending { approver, .. } => {
            warn!(%approver, "denying pending elicitation: unsupported on request-only path");
            deny(REASON_ELICITATION_UNSUPPORTED)
        },
    }
}

/// A DENY result carrying only a non-secret reason code.
fn deny(reason_code: &str) -> HttpRequestResult {
    HttpRequestResult {
        decision: Decision::Deny as i32,
        reason: String::new(),
        body: Vec::new(),
        has_body: false,
        header_mutations: Vec::new(),
        findings: Vec::new(),
        metadata: Default::default(),
        reason_code: reason_code.to_string(),
    }
}

/// OpenShell requires reason codes to be `[a-z][a-z0-9_]*`, ≤64 bytes. CPEX
/// violation codes use dots (`session_tainted`, `policy.deny`); normalize dots
/// to underscores and drop anything else so a valid code is always returned.
fn sanitize_reason_code(code: &str) -> String {
    let mut out: String = code
        .chars()
        .map(|c| if c == '.' || c == '-' { '_' } else { c })
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
        .take(64)
        .collect();
    // Must start with a lowercase letter.
    if !out.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        out = format!("cpex_{out}");
        out.truncate(64);
    }
    out
}

/// A stable, non-secret label for an outcome (for logging only).
fn discriminant(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Allow { .. } => "allow",
        Outcome::Deny { .. } => "deny",
        Outcome::Pending { .. } => "pending",
    }
}

/// Convert a `google.protobuf.Struct` (prost) into a `serde_json::Value`.
fn struct_to_json(s: &prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(
        s.fields
            .iter()
            .map(|(k, v)| (k.clone(), prost_value_to_json(v)))
            .collect(),
    )
}

fn prost_value_to_json(v: &prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    match &v.kind {
        None | Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::NumberValue(n)) => serde_json::Number::from_f64(*n)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::StructValue(s)) => struct_to_json(s),
        Some(Kind::ListValue(l)) => {
            serde_json::Value::Array(l.values.iter().map(prost_value_to_json).collect())
        },
    }
}
