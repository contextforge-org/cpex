// Location: ./tests/parity/harness/src/engine.rs
// SPDX-License-Identifier: Apache-2.0
//
// Engine adapter. The only file that names engine types: it loads a config,
// dispatches hooks, and projects each pipeline result into the
// engine-neutral outcome shape the snapshots record. Retargeting the
// harness to another engine means rewriting this file and keeping the
// projection shape stable.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use serde_json::{Map, Value, json};

use cpex::{HyperTransport, PolicyEngine};
use praxis_policy_core::cmf::content::{ToolCall, ToolResult};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload};
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::extensions::{
    AgentExtension, Extensions, HttpExtension, MetaExtension, SecurityExtension, SubjectExtension,
    SubjectType,
};
use praxis_policy_core::identity::{IdentityHook, IdentityPayload, TokenSource};

use crate::normalize::{SCRUBBED_TOKEN, sorted};
use crate::spec::{ExtensionsSpec, InvokeRequest, MediateHooks};

// The go-demo CMF plugins (tool policy + header injector), compiled from
// the demo's own source so the scenario tracks that file.
#[path = "../../../../examples/go-demo/ffi/src/cmf_plugins.rs"]
#[allow(dead_code)]
mod go_demo_cmf;

/// Request header an agent echoes to resume a suspended elicitation.
const ELICITATION_ID_HEADER: &str = "X-Policy-Elicitation-Id";

/// Credential-bearing request headers whose values are never recorded.
const CREDENTIAL_HEADERS: &[&str] = &["authorization", "x-user-token", "x-workload-token"];

pub struct Engine {
    mgr: Arc<PolicyEngine>,
}

/// A caller with its credentials already minted.
#[derive(Default)]
pub struct ResolvedCaller {
    pub bearer: Option<String>,
    pub credentials: BTreeMap<String, String>,
    pub session: Option<String>,
    pub elicitation_id: Option<String>,
}

pub struct MediateOutcome {
    pub stages: Vec<Value>,
    pub decision: &'static str,
    pub code: Option<String>,
    /// What the caller sees: the backend result after the post phase.
    pub result: Option<Value>,
    pub elicitation_id: Option<String>,
}

impl Engine {
    pub async fn load(yaml: &str, host_plugins: &[String]) -> Result<Self, String> {
        let mgr = Arc::new(PolicyEngine::default());
        cpex::install_builtins(&mgr);
        // The mock upstream listens on 127.0.0.1, which the bundled
        // transport refuses unless private destinations are allowed.
        mgr.set_http_transport(Arc::new(
            HyperTransport::new().with_allow_private_destinations(),
        ));
        for set in host_plugins {
            match set.as_str() {
                "go-demo-cmf" => go_demo_cmf::register_cmf_factories(&mgr),
                other => return Err(format!("unknown host plugin set '{other}'")),
            }
        }
        mgr.load_config_yaml(yaml)
            .map_err(|e| format!("load: {e}"))?;
        mgr.initialize()
            .await
            .map_err(|e| format!("initialize: {e}"))?;
        Ok(Self { mgr })
    }

    pub async fn shutdown(&self) {
        self.mgr.shutdown().await;
    }

    /// One explicit hook invocation.
    pub async fn invoke(&self, req: &InvokeRequest) -> Result<Value, String> {
        let payload: MessagePayload = serde_json::from_value(req.payload.clone())
            .map_err(|e| format!("{}: payload is not a CMF MessagePayload: {e}", req.id))?;
        let ext = build_extensions(&req.extensions);
        let (result, bg) = self
            .mgr
            .invoke_named::<CmfHook>(&req.hook, payload, ext, None)
            .await;
        bg.wait_for_background_tasks().await;
        Ok(project_stage(&req.hook, &result))
    }

    /// The host loop the tutorial's `mediate()` runs: identity, pre, backend,
    /// post. Halts at the first stage that does not continue.
    pub async fn mediate(
        &self,
        hooks: &MediateHooks,
        caller: &ResolvedCaller,
        tool: &str,
        args: &Value,
        backend: &Value,
    ) -> MediateOutcome {
        let mut stages = Vec::new();
        let mut ext = Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some(tool.into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        if let Some(sid) = &caller.session {
            ext.agent = Some(Arc::new(AgentExtension {
                session_id: Some(sid.clone()),
                ..Default::default()
            }));
        }
        if let Some(eid) = &caller.elicitation_id {
            let mut http = HttpExtension::default();
            http.set_request_header(ELICITATION_ID_HEADER, eid);
            ext.http = Some(Arc::new(http));
        }

        // Identity: one credential is passed bare; several go as a header map.
        if caller.bearer.is_some() || !caller.credentials.is_empty() {
            let payload = match (&caller.bearer, caller.credentials.is_empty()) {
                (Some(t), true) => IdentityPayload::new(t.clone(), TokenSource::Bearer),
                _ => {
                    let mut headers = std::collections::HashMap::new();
                    if let Some(t) = &caller.bearer {
                        headers.insert("authorization".to_string(), t.clone());
                    }
                    for (h, t) in &caller.credentials {
                        headers.insert(h.to_ascii_lowercase(), t.clone());
                    }
                    IdentityPayload::new(String::new(), TokenSource::Bearer).with_headers(headers)
                },
            };
            let (res, bg) = self
                .mgr
                .invoke_named::<IdentityHook>(&hooks.identity, payload, ext.clone(), None)
                .await;
            bg.wait_for_background_tasks().await;
            stages.push(project_stage(&hooks.identity, &res));
            if !res.continue_processing {
                return halted(stages, &res);
            }
            if let Some(identity) = IdentityPayload::from_pipeline_result(&res) {
                ext = identity.apply_to_extensions(ext);
            }
        }

        let pre_payload = MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "parity-call".into(),
                        name: tool.into(),
                        arguments: object_to_map(args),
                        namespace: None,
                    },
                }],
            ),
        };
        let (pre, bg) = self
            .mgr
            .invoke_named::<CmfHook>(&hooks.pre, pre_payload, ext.clone(), None)
            .await;
        bg.wait_for_background_tasks().await;
        stages.push(project_stage(&hooks.pre, &pre));
        if !pre.continue_processing {
            return halted(stages, &pre);
        }
        let post_ext = pre.modified_extensions.clone().unwrap_or(ext);

        let post_payload = MessagePayload {
            message: Message::with_content(
                Role::Tool,
                vec![ContentPart::ToolResult {
                    content: ToolResult {
                        tool_call_id: "parity-call".into(),
                        tool_name: tool.into(),
                        content: backend.clone(),
                        is_error: false,
                    },
                }],
            ),
        };
        let (post, bg) = self
            .mgr
            .invoke_named::<CmfHook>(&hooks.post, post_payload, post_ext, None)
            .await;
        bg.wait_for_background_tasks().await;
        stages.push(project_stage(&hooks.post, &post));
        if !post.continue_processing {
            return halted(stages, &post);
        }

        let result = post
            .modified_payload
            .as_ref()
            .and_then(|p| p.as_any().downcast_ref::<MessagePayload>())
            .and_then(|mp| mp.message.get_tool_results().into_iter().next())
            .map(|tr| tr.content.clone())
            .unwrap_or_else(|| backend.clone());

        MediateOutcome {
            stages,
            decision: "allow",
            code: None,
            result: Some(result),
            elicitation_id: None,
        }
    }
}

fn halted(stages: Vec<Value>, res: &PipelineResult) -> MediateOutcome {
    let code = res.violation.as_ref().map(|v| v.code.clone());
    let pending = code.as_deref() == Some("elicitation.pending");
    let elicitation_id = res
        .violation
        .as_ref()
        .and_then(|v| v.details.get("elicitation_id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    MediateOutcome {
        stages,
        decision: if pending { "pending" } else { "deny" },
        code,
        result: None,
        elicitation_id,
    }
}

fn object_to_map(v: &Value) -> std::collections::HashMap<String, Value> {
    match v {
        Value::Object(m) => m.clone().into_iter().collect(),
        Value::Null => Default::default(),
        other => [("value".to_string(), other.clone())].into_iter().collect(),
    }
}

fn build_extensions(spec: &ExtensionsSpec) -> Extensions {
    let mut ext = Extensions::default();
    if let Some(m) = &spec.meta {
        ext.meta = Some(Arc::new(MetaExtension {
            entity_type: m.entity_type.clone(),
            entity_name: m.entity_name.clone(),
            tags: m.tags.iter().cloned().collect(),
            ..Default::default()
        }));
    }
    if let Some(s) = &spec.security {
        let mut sec = SecurityExtension::default();
        for l in &s.labels {
            sec.labels.add_label(l.clone());
        }
        if let Some(subj) = &s.subject {
            sec.subject = Some(SubjectExtension {
                id: subj.id.clone(),
                subject_type: Some(SubjectType::User),
                roles: subj.roles.iter().cloned().collect::<HashSet<_>>(),
                permissions: subj.permissions.iter().cloned().collect::<HashSet<_>>(),
                ..Default::default()
            });
        }
        ext.security = Some(Arc::new(sec));
    }
    if let Some(h) = &spec.http {
        let mut http = HttpExtension::default();
        for (k, v) in &h.request_headers {
            http.set_request_header(k.clone(), v.clone());
        }
        ext.http = Some(Arc::new(http));
    }
    if let Some(a) = &spec.agent {
        ext.agent = Some(Arc::new(AgentExtension {
            session_id: a.session_id.clone(),
            agent_id: a.agent_id.clone(),
            ..Default::default()
        }));
    }
    ext
}

// ---------------------------------------------------------------------
// Projection into the snapshot shape
// ---------------------------------------------------------------------

/// Keys whose values are sets: their string arrays are sorted.
const SET_KEYS: &[&str] = &[
    "roles",
    "permissions",
    "teams",
    "labels",
    "tags",
    "scopes",
    "scopes_granted",
    "authorized_scopes",
    "authorized_audiences",
    "selectors",
];

fn sort_sets(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                let v = match v {
                    Value::Array(a)
                        if SET_KEYS.contains(&k.as_str()) && a.iter().all(Value::is_string) =>
                    {
                        Value::Array(
                            sorted(a.into_iter().filter_map(|x| x.as_str().map(str::to_string)))
                                .into_iter()
                                .map(Value::String)
                                .collect(),
                        )
                    },
                    other => sort_sets(other),
                };
                out.insert(k, v);
            }
            Value::Object(out)
        },
        Value::Array(a) => Value::Array(a.into_iter().map(sort_sets).collect()),
        other => other,
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> Value {
    sort_sets(serde_json::to_value(v).unwrap_or(Value::Null))
}

fn project_stage(hook: &str, res: &PipelineResult) -> Value {
    let violation = res.violation.as_ref().map(|v| {
        json!({
            "code": v.code,
            "reason": v.reason,
            "description": v.description,
            "plugin": v.plugin_name,
            "proto_error_code": v.proto_error_code,
            "details": sort_sets(Value::Object(v.details.clone().into_iter().collect())),
        })
    });
    let payload = if res.payload_modified {
        res.modified_payload.as_ref().map(|p| {
            if let Some(mp) = p.as_any().downcast_ref::<MessagePayload>() {
                json!({ "cmf": to_json(mp) })
            } else if let Some(ip) = p.as_any().downcast_ref::<IdentityPayload>() {
                json!({ "identity": project_identity(ip) })
            } else {
                json!({ "unknown": true })
            }
        })
    } else {
        None
    };
    let mut errors: Vec<Value> = res
        .errors
        .iter()
        .map(|e| json!({ "plugin": e.plugin_name, "code": e.code, "message": e.message }))
        .collect();
    errors.sort_by_key(|e| e.to_string());

    json!({
        "hook": hook,
        "continue": res.continue_processing,
        "violation": violation,
        "payload_modified": res.payload_modified,
        "payload": payload,
        "extensions": res.modified_extensions.as_ref().map(project_extensions),
        "errors": errors,
    })
}

fn project_identity(p: &IdentityPayload) -> Value {
    json!({
        "subject": p.subject.as_ref().map(to_json),
        "client": p.client.as_ref().map(to_json),
        "caller_workload": p.caller_workload.as_ref().map(to_json),
        "delegation": p.delegation.as_ref().map(to_json),
        "raw_credentials": p.raw_credentials.as_ref().map(project_raw_credentials),
        "raw_claims": sort_sets(Value::Object(p.raw_claims.clone().into_iter().collect())),
    })
}

fn project_raw_credentials(rc: &praxis_policy_core::extensions::RawCredentialsExtension) -> Value {
    let mut inbound: Vec<Value> = rc
        .inbound_tokens
        .iter()
        .map(|(role, t)| {
            json!({
                "role": to_json(role),
                "source_header": t.source_header,
                "kind": to_json(&t.kind),
                "token": if t.token.is_empty() { Value::Null } else { json!(SCRUBBED_TOKEN) },
            })
        })
        .collect();
    inbound.sort_by_key(|v| v.to_string());
    let mut delegated: Vec<Value> = rc
        .delegated_tokens
        .iter()
        .map(|(key, t)| {
            json!({
                "key": to_json(key),
                "outbound_header": t.outbound_header,
                "audience": t.audience,
                "scopes": sorted(t.scopes.iter().cloned()),
                "token": if t.token.is_empty() { Value::Null } else { json!(SCRUBBED_TOKEN) },
            })
        })
        .collect();
    delegated.sort_by_key(|v| v.to_string());
    json!({ "inbound_tokens": inbound, "delegated_tokens": delegated })
}

fn project_extensions(ext: &Extensions) -> Value {
    let http = ext.http.as_ref().map(|h| {
        let req: BTreeMap<String, String> = h
            .request_headers
            .iter()
            .map(|(k, v)| {
                let v = if CREDENTIAL_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
                    SCRUBBED_TOKEN.to_string()
                } else {
                    v.clone()
                };
                (k.clone(), v)
            })
            .collect();
        let resp: BTreeMap<&String, &String> = h.response_headers.iter().collect();
        json!({ "request_headers": req, "response_headers": resp })
    });
    let security = ext.security.as_ref().map(|s| {
        json!({
            "labels": sorted(s.labels.iter().cloned()),
            "classification": s.classification,
            "subject": s.subject.as_ref().map(to_json),
            "client": s.client.as_ref().map(to_json),
            "caller_workload": s.caller_workload.as_ref().map(to_json),
            "auth_method": s.auth_method,
        })
    });
    json!({
        "meta": ext.meta.as_ref().map(|m| json!({
            "entity_type": m.entity_type,
            "entity_name": m.entity_name,
            "tags": sorted(m.tags.iter().cloned()),
        })),
        "agent": ext.agent.as_ref().map(|a| json!({ "session_id": a.session_id })),
        "http": http,
        "security": security,
        "delegation": ext.delegation.as_ref().map(|d| to_json(&**d)),
        "raw_credentials": ext.raw_credentials.as_ref().map(|rc| project_raw_credentials(rc)),
    })
}
