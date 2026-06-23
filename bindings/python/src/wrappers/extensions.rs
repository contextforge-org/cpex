// Location: ./bindings/python/src/wrappers/extensions.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Typed wrappers for the Extensions container and every slot. SecurityExtension
// and SubjectExtension are bespoke (monotonic labels, typed identity sets); the
// remaining slots are serde-bridge wrappers.

use std::sync::Arc;

use cpex_core::extensions::{
    AgentExtension, AuthorizationDetail, ClientExtension, CompletionExtension, ConversationContext,
    DelegationExtension, DelegationHop, Extensions, FrameworkExtension, HttpExtension, LLMExtension,
    MCPExtension, MetaExtension, PromptMetadata, ProvenanceExtension, RequestExtension,
    ResourceMetadata, SecurityExtension, SubjectExtension, SubjectType, TokenUsage, ToolMetadata,
    WorkloadIdentity,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyFrozenSet;

use super::enum_from_str;

// ---------------------------------------------------------------------------
// Serde-bridge slot wrappers (kwargs ctor + to_dict)
// ---------------------------------------------------------------------------

serde_wrapper!(PyRequestExtension, "RequestExtension", RequestExtension,
    native: [environment, request_id, timestamp, trace_id, span_id], convert: []);
serde_wrapper!(PyAgentExtension, "AgentExtension", AgentExtension,
    native: [input, session_id, conversation_id, turn, agent_id, parent_agent_id],
    convert: []); // `conversation` is a handle getter below
serde_wrapper!(PyHttpExtension, "HttpExtension", HttpExtension,
    native: [request_headers, response_headers], convert: []);
serde_wrapper!(PyMCPExtension, "MCPExtension", MCPExtension,
    native: [], convert: []); // tool/resource/prompt are handle getters below
serde_wrapper!(PyCompletionExtension, "CompletionExtension", CompletionExtension,
    native: [model, raw_format, created_at, latency_ms],
    convert: [stop_reason]); // `tokens` is a handle getter below

// Nested wrappers used as handle return types.
serde_wrapper!(PyConversationContext, "ConversationContext", ConversationContext,
    native: [summary, topics], convert: [history]);
serde_wrapper!(PyToolMetadata, "ToolMetadata", ToolMetadata,
    native: [name, title, description, server_id, namespace],
    convert: [input_schema, output_schema, annotations]);
serde_wrapper!(PyResourceMetadata, "ResourceMetadata", ResourceMetadata,
    native: [uri, name, description, mime_type, server_id],
    convert: [annotations]);
serde_wrapper!(PyPromptMetadata, "PromptMetadata", PromptMetadata,
    native: [name, description, server_id],
    convert: [arguments, annotations]);
serde_wrapper!(PyTokenUsage, "TokenUsage", TokenUsage,
    native: [input_tokens, output_tokens, total_tokens], convert: []);
serde_wrapper!(PyAuthorizationDetail, "AuthorizationDetail", AuthorizationDetail,
    native: [detail_type, locations, actions, datatypes, identifier, privileges],
    convert: [extra]);

// Handle getters — return nested objects as live typed wrappers, not dicts.
#[pymethods]
impl PyAgentExtension {
    #[getter]
    fn conversation(&self) -> Option<PyConversationContext> {
        self.inner
            .conversation
            .as_ref()
            .map(|c| PyConversationContext { inner: c.clone() })
    }
}

#[pymethods]
impl PyMCPExtension {
    #[getter]
    fn tool(&self) -> Option<PyToolMetadata> {
        self.inner.tool.as_ref().map(|t| PyToolMetadata { inner: t.clone() })
    }
    #[getter]
    fn resource(&self) -> Option<PyResourceMetadata> {
        self.inner
            .resource
            .as_ref()
            .map(|r| PyResourceMetadata { inner: r.clone() })
    }
    #[getter]
    fn prompt(&self) -> Option<PyPromptMetadata> {
        self.inner
            .prompt
            .as_ref()
            .map(|p| PyPromptMetadata { inner: p.clone() })
    }
}

#[pymethods]
impl PyCompletionExtension {
    #[getter]
    fn tokens(&self) -> Option<PyTokenUsage> {
        self.inner.tokens.as_ref().map(|t| PyTokenUsage { inner: t.clone() })
    }
}
serde_wrapper!(PyProvenanceExtension, "ProvenanceExtension", ProvenanceExtension,
    native: [source, message_id, parent_id], convert: []);
serde_wrapper!(PyLLMExtension, "LLMExtension", LLMExtension,
    native: [model_id, provider, capabilities], convert: []);
serde_wrapper!(PyFrameworkExtension, "FrameworkExtension", FrameworkExtension,
    native: [framework, framework_version, node_id, graph_id],
    convert: [metadata]);
serde_wrapper!(PyMetaExtension, "MetaExtension", MetaExtension,
    native: [entity_type, entity_name, tags, scope, properties], convert: []);
serde_wrapper!(PyClientExtension, "ClientExtension", ClientExtension,
    native: [client_id, client_name, authorized_scopes, authorized_audiences,
             roles, permissions, teams],
    convert: [trust_level, claims]);
serde_wrapper!(PyWorkloadIdentity, "WorkloadIdentity", WorkloadIdentity,
    native: [spiffe_id, trust_domain, attestor, selectors, client_id],
    convert: [attested_at]);
serde_wrapper!(PyDelegationExtension, "DelegationExtension", DelegationExtension,
    native: [depth, origin_subject_id, actor_subject_id, delegated, age_seconds],
    convert: []); // `chain` is a handle getter below
serde_wrapper!(PyDelegationHop, "DelegationHop", DelegationHop,
    native: [subject_id, audience, scopes_granted, ttl_seconds, from_cache],
    convert: [subject_type, timestamp, strategy]); // `authorization_details` handle below

#[pymethods]
impl PyDelegationExtension {
    #[getter]
    fn chain(&self) -> Vec<PyDelegationHop> {
        self.inner
            .chain
            .iter()
            .map(|h| PyDelegationHop { inner: h.clone() })
            .collect()
    }
}

#[pymethods]
impl PyDelegationHop {
    #[getter]
    fn authorization_details(&self) -> Vec<PyAuthorizationDetail> {
        self.inner
            .authorization_details
            .iter()
            .map(|a| PyAuthorizationDetail { inner: a.clone() })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// SubjectExtension — bespoke (typed identity sets)
// ---------------------------------------------------------------------------

/// Authenticated subject (who is calling). Immutable.
#[pyclass(name = "SubjectExtension", frozen)]
pub struct PySubjectExtension {
    pub(crate) inner: SubjectExtension,
}

#[pymethods]
impl PySubjectExtension {
    #[new]
    #[pyo3(signature = (id=None, subject_type=None, roles=None, permissions=None, teams=None))]
    fn new(
        id: Option<String>,
        subject_type: Option<&str>,
        roles: Option<Vec<String>>,
        permissions: Option<Vec<String>>,
        teams: Option<Vec<String>>,
    ) -> PyResult<Self> {
        let subject_type: Option<SubjectType> = match subject_type {
            None => None,
            Some(s) => Some(enum_from_str(s, "SubjectType")?),
        };
        Ok(Self {
            inner: SubjectExtension {
                id,
                subject_type,
                roles: roles.unwrap_or_default().into_iter().collect(),
                permissions: permissions.unwrap_or_default().into_iter().collect(),
                teams: teams.unwrap_or_default().into_iter().collect(),
                claims: Default::default(),
            },
        })
    }

    #[getter]
    fn id(&self) -> Option<String> {
        self.inner.id.clone()
    }

    #[getter]
    fn roles<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyFrozenSet>> {
        PyFrozenSet::new(py, self.inner.roles.iter())
    }

    #[getter]
    fn permissions<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyFrozenSet>> {
        PyFrozenSet::new(py, self.inner.permissions.iter())
    }

    #[getter]
    fn teams<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyFrozenSet>> {
        PyFrozenSet::new(py, self.inner.teams.iter())
    }
}

// ---------------------------------------------------------------------------
// SecurityExtension — monotonic labels (add-only, no remove)
// ---------------------------------------------------------------------------

/// Security context. Labels are **monotonic**: `add_label` exists but there is
/// deliberately no `remove_label` — backed by `MonotonicSet`.
#[pyclass(name = "SecurityExtension")]
pub struct PySecurityExtension {
    pub(crate) inner: SecurityExtension,
}

#[pymethods]
impl PySecurityExtension {
    #[new]
    #[pyo3(signature = (labels=None, classification=None, subject=None, client=None))]
    fn new(
        labels: Option<Vec<String>>,
        classification: Option<String>,
        subject: Option<PyRef<PySubjectExtension>>,
        client: Option<PyRef<PyClientExtension>>,
    ) -> Self {
        let mut inner = SecurityExtension {
            classification,
            subject: subject.map(|s| s.inner.clone()),
            client: client.map(|c| c.inner.clone()),
            ..Default::default()
        };
        for l in labels.unwrap_or_default() {
            inner.add_label(l);
        }
        Self { inner }
    }

    /// Add a security label. Monotonic — there is no counterpart remove.
    fn add_label(&mut self, label: &str) {
        self.inner.add_label(label);
    }

    fn has_label(&self, label: &str) -> bool {
        self.inner.has_label(label)
    }

    #[getter]
    fn labels<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyFrozenSet>> {
        PyFrozenSet::new(py, self.inner.labels.iter())
    }

    #[getter]
    fn classification(&self) -> Option<String> {
        self.inner.classification.clone()
    }

    #[getter]
    fn subject(&self) -> Option<PySubjectExtension> {
        self.inner
            .subject
            .as_ref()
            .map(|s| PySubjectExtension { inner: s.clone() })
    }

    fn __repr__(&self) -> String {
        format!(
            "SecurityExtension(labels={}, classification={:?})",
            self.inner.labels.len(),
            self.inner.classification
        )
    }
}

// ---------------------------------------------------------------------------
// Extensions container — assembles typed slot handles
// ---------------------------------------------------------------------------

/// The CMF extensions container. Construct from typed slot handles; each slot
/// is stored frozen (Arc) in the Rust core.
#[pyclass(name = "Extensions")]
pub struct PyExtensions {
    pub(crate) inner: Extensions,
}

#[pymethods]
impl PyExtensions {
    #[new]
    #[pyo3(signature = (
        security=None, request=None, agent=None, http=None, delegation=None,
        mcp=None, completion=None, provenance=None, llm=None, framework=None, meta=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        security: Option<PyRef<PySecurityExtension>>,
        request: Option<PyRef<PyRequestExtension>>,
        agent: Option<PyRef<PyAgentExtension>>,
        http: Option<PyRef<PyHttpExtension>>,
        delegation: Option<PyRef<PyDelegationExtension>>,
        mcp: Option<PyRef<PyMCPExtension>>,
        completion: Option<PyRef<PyCompletionExtension>>,
        provenance: Option<PyRef<PyProvenanceExtension>>,
        llm: Option<PyRef<PyLLMExtension>>,
        framework: Option<PyRef<PyFrameworkExtension>>,
        meta: Option<PyRef<PyMetaExtension>>,
    ) -> Self {
        Self {
            inner: Extensions {
                security: security.map(|s| Arc::new(s.inner.clone())),
                request: request.map(|r| Arc::new(r.inner.clone())),
                agent: agent.map(|a| Arc::new(a.inner.clone())),
                http: http.map(|h| Arc::new(h.inner.clone())),
                delegation: delegation.map(|d| Arc::new(d.inner.clone())),
                mcp: mcp.map(|m| Arc::new(m.inner.clone())),
                completion: completion.map(|c| Arc::new(c.inner.clone())),
                provenance: provenance.map(|p| Arc::new(p.inner.clone())),
                llm: llm.map(|l| Arc::new(l.inner.clone())),
                framework: framework.map(|f| Arc::new(f.inner.clone())),
                meta: meta.map(|m| Arc::new(m.inner.clone())),
                ..Default::default()
            },
        }
    }

    #[getter]
    fn security(&self) -> Option<PySecurityExtension> {
        self.inner
            .security
            .as_ref()
            .map(|a| PySecurityExtension { inner: (**a).clone() })
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let v = serde_json::to_value(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("cpex: {e}")))?;
        crate::conversions::json_value_to_pyobj(py, &v)
    }
}
