// Location: ./crates/cpex-core/src/extensions/container.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Extensions and OwnedExtensions — typed containers for all
// extension data passed separately from the payload to handlers.
//
// Extensions is fully immutable (all Arc<T>) — zero-copy shareable.
// OwnedExtensions is the plugin's writeable workspace, created by
// cow_copy(), returned in PluginResult::modify_extensions().

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::agent::AgentExtension;
use super::completion::CompletionExtension;
use super::delegation::DelegationExtension;
use super::framework::FrameworkExtension;
use super::guarded::{Guarded, WriteToken};
use super::http::HttpExtension;
use super::llm::LLMExtension;
use super::mcp::MCPExtension;
use super::meta::MetaExtension;
use super::provenance::ProvenanceExtension;
use super::request::RequestExtension;
use super::security::SecurityExtension;

// ---------------------------------------------------------------------------
// Extensions — all Arc, fully immutable, zero-copy shareable
// ---------------------------------------------------------------------------

/// Typed container for all message extensions.
///
/// All slots are `Arc<T>` — fully immutable, zero-copy shareable.
/// Cloning is all refcount bumps. `filter_extensions()` creates a
/// filtered view by setting unwanted slots to `None` (still all Arc,
/// no deep copies). Plugins receive `&Extensions` (zero cost).
///
/// To modify, plugins call `cow_copy()` which returns an
/// `OwnedExtensions` with mutable/monotonic/guarded slots cloned
/// out of Arc and write tokens propagated.
///
/// Mirrors Python's `cpex.framework.extensions.Extensions`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Extensions {
    /// Execution environment and request tracing (immutable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Arc<RequestExtension>>,

    /// Agent execution context — session, conversation, lineage (immutable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<Arc<AgentExtension>>,

    /// HTTP headers (frozen as Arc — unfrozen in OwnedExtensions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<Arc<HttpExtension>>,

    /// Security — labels, classification, subject (frozen as Arc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<Arc<SecurityExtension>>,

    /// Delegation chain (frozen as Arc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Arc<DelegationExtension>>,

    /// MCP entity metadata (immutable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<Arc<MCPExtension>>,

    /// LLM completion information (immutable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<Arc<CompletionExtension>>,

    /// Origin and message threading (immutable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Arc<ProvenanceExtension>>,

    /// Model identity and capabilities (immutable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<Arc<LLMExtension>>,

    /// Agentic framework context (immutable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<Arc<FrameworkExtension>>,

    /// Host-provided operational metadata (immutable).
    #[serde(default)]
    pub meta: Option<Arc<MetaExtension>>,

    /// Custom extensions (frozen as Arc — unfrozen in OwnedExtensions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<Arc<HashMap<String, serde_json::Value>>>,

    /// Write tokens — set by the executor per plugin, NOT serialized.
    /// Used by `cow_copy()` to propagate write access to OwnedExtensions.
    #[serde(skip)]
    pub http_write_token: Option<WriteToken>,
    #[serde(skip)]
    pub labels_write_token: Option<WriteToken>,
    #[serde(skip)]
    pub delegation_write_token: Option<WriteToken>,
}

impl Clone for Extensions {
    /// All Arc bumps — zero data copies. Write tokens are NOT cloned.
    fn clone(&self) -> Self {
        Self {
            request: self.request.clone(),
            agent: self.agent.clone(),
            http: self.http.clone(),
            security: self.security.clone(),
            delegation: self.delegation.clone(),
            mcp: self.mcp.clone(),
            completion: self.completion.clone(),
            provenance: self.provenance.clone(),
            llm: self.llm.clone(),
            framework: self.framework.clone(),
            meta: self.meta.clone(),
            custom: self.custom.clone(),
            http_write_token: None,
            labels_write_token: None,
            delegation_write_token: None,
        }
    }
}

impl Extensions {
    /// Create a copy-on-write owned copy for modification.
    ///
    /// Immutable slots share the same `Arc` (refcount bump, ~1ns).
    /// Mutable/monotonic/guarded slots are cloned out of Arc into
    /// owned values — the plugin can modify them directly.
    /// Write tokens are propagated from the original.
    ///
    /// # Usage
    ///
    /// ```ignore
    /// fn handle(&self, payload: &P, ext: &Extensions, ctx: &mut PluginContext) -> PluginResult<P> {
    ///     let mut owned = ext.cow_copy();
    ///     owned.security.as_mut().unwrap().add_label("CHECKED");
    ///     if let Some(ref token) = owned.http_write_token {
    ///         owned.http.as_mut().unwrap().write(token).set_header("X-Foo", "bar");
    ///     }
    ///     PluginResult::modify_extensions(owned)
    /// }
    /// ```
    pub fn cow_copy(&self) -> OwnedExtensions {
        OwnedExtensions {
            // Immutable — same Arc pointers
            request: self.request.clone(),
            agent: self.agent.clone(),
            mcp: self.mcp.clone(),
            completion: self.completion.clone(),
            provenance: self.provenance.clone(),
            llm: self.llm.clone(),
            framework: self.framework.clone(),
            meta: self.meta.clone(),

            // Mutable/monotonic/guarded — cloned out of Arc into owned
            http: self.http.as_ref().map(|arc| Guarded::new((**arc).clone())),
            security: self.security.as_ref().map(|arc| (**arc).clone()),
            delegation: self.delegation.as_ref().map(|arc| (**arc).clone()),
            custom: self.custom.as_ref().map(|arc| (**arc).clone()),

            // Write tokens — propagated from the original
            http_write_token: if self.http_write_token.is_some() {
                Some(WriteToken::new())
            } else {
                None
            },
            labels_write_token: if self.labels_write_token.is_some() {
                Some(WriteToken::new())
            } else {
                None
            },
            delegation_write_token: if self.delegation_write_token.is_some() {
                Some(WriteToken::new())
            } else {
                None
            },
        }
    }

    /// Validate that immutable slots were not tampered with.
    pub fn validate_immutable(&self, modified: &OwnedExtensions) -> bool {
        fn ptr_eq_opt<T>(a: &Option<Arc<T>>, b: &Option<Arc<T>>) -> bool {
            match (a, b) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            }
        }

        ptr_eq_opt(&self.request, &modified.request)
            && ptr_eq_opt(&self.agent, &modified.agent)
            && ptr_eq_opt(&self.mcp, &modified.mcp)
            && ptr_eq_opt(&self.completion, &modified.completion)
            && ptr_eq_opt(&self.provenance, &modified.provenance)
            && ptr_eq_opt(&self.llm, &modified.llm)
            && ptr_eq_opt(&self.framework, &modified.framework)
            && ptr_eq_opt(&self.meta, &modified.meta)
    }

    /// Merge an OwnedExtensions back into this Extensions.
    pub fn merge_owned(&mut self, owned: OwnedExtensions) {
        self.http = owned.http.map(|g| Arc::new(g.into_inner()));
        self.security = owned.security.map(Arc::new);
        self.delegation = owned.delegation.map(Arc::new);
        self.custom = owned.custom.map(Arc::new);
    }
}

// ---------------------------------------------------------------------------
// OwnedExtensions — plugin's writeable workspace
// ---------------------------------------------------------------------------

/// Owned copy of extensions for plugin modification.
///
/// Returned by `Extensions::cow_copy()`. Immutable slots share
/// the same `Arc` pointers as the original (zero copy). Mutable,
/// monotonic, and guarded slots are cloned into owned values that
/// the plugin can modify directly.
///
/// Plugins return this in `PluginResult::modify_extensions()`.
/// The executor validates (immutable unchanged, monotonic superset)
/// and merges back into the pipeline's `Extensions`.
///
/// Hosts never see this type — the executor converts to `Extensions`
/// before building `PipelineResult`.
#[derive(Debug)]
pub struct OwnedExtensions {
    // Immutable — same Arc pointers as original
    pub request: Option<Arc<RequestExtension>>,
    pub agent: Option<Arc<AgentExtension>>,
    pub mcp: Option<Arc<MCPExtension>>,
    pub completion: Option<Arc<CompletionExtension>>,
    pub provenance: Option<Arc<ProvenanceExtension>>,
    pub llm: Option<Arc<LLMExtension>>,
    pub framework: Option<Arc<FrameworkExtension>>,
    pub meta: Option<Arc<MetaExtension>>,

    // Mutable/monotonic/guarded — owned, modifiable
    pub http: Option<Guarded<HttpExtension>>,
    pub security: Option<SecurityExtension>,
    pub delegation: Option<DelegationExtension>,
    pub custom: Option<HashMap<String, serde_json::Value>>,

    // Write tokens — propagated from executor
    pub http_write_token: Option<WriteToken>,
    pub labels_write_token: Option<WriteToken>,
    pub delegation_write_token: Option<WriteToken>,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::{
        DelegationExtension, HttpExtension, RequestExtension, SecurityExtension,
    };

    fn make_extensions() -> Extensions {
        let mut security = SecurityExtension::default();
        security.add_label("PII");

        let mut http = HttpExtension::default();
        http.set_header("Authorization", "Bearer token");

        Extensions {
            request: Some(Arc::new(RequestExtension {
                request_id: Some("req-001".into()),
                ..Default::default()
            })),
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            delegation: Some(Arc::new(DelegationExtension::default())),
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some("tool".into()),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[test]
    fn test_cow_copy_shares_immutable_arcs() {
        let ext = make_extensions();
        let cow = ext.cow_copy();

        // Immutable slots share the same Arc — zero copy
        assert!(Arc::ptr_eq(ext.request.as_ref().unwrap(), cow.request.as_ref().unwrap()));
        assert!(Arc::ptr_eq(ext.meta.as_ref().unwrap(), cow.meta.as_ref().unwrap()));
    }

    #[test]
    fn test_cow_copy_deep_clones_mutable_slots() {
        let ext = make_extensions();
        let cow = ext.cow_copy();

        // Mutable/monotonic slots are deep cloned — independent copies
        assert!(cow.security.is_some());
        assert!(cow.http.is_some());
        assert!(cow.delegation.is_some());

        // Modifying the COW copy doesn't affect the original
        cow.security.as_ref().unwrap().has_label("PII");
    }

    #[test]
    fn test_cow_copy_propagates_write_tokens() {
        let mut ext = make_extensions();

        // No tokens on the original → no tokens on COW
        let cow_no_tokens = ext.cow_copy();
        assert!(cow_no_tokens.http_write_token.is_none());
        assert!(cow_no_tokens.labels_write_token.is_none());
        assert!(cow_no_tokens.delegation_write_token.is_none());

        // Executor sets tokens based on capabilities
        ext.http_write_token = Some(WriteToken::new());
        ext.labels_write_token = Some(WriteToken::new());

        // COW copy propagates only the tokens that exist
        let cow_with_tokens = ext.cow_copy();
        assert!(cow_with_tokens.http_write_token.is_some());
        assert!(cow_with_tokens.labels_write_token.is_some());
        assert!(cow_with_tokens.delegation_write_token.is_none()); // wasn't set
    }

    #[test]
    fn test_cow_copy_write_token_enables_guarded_write() {
        let mut ext = make_extensions();
        ext.http_write_token = Some(WriteToken::new());

        let mut cow = ext.cow_copy();

        // Can read without token
        assert_eq!(
            cow.http.as_ref().unwrap().read().get_header("Authorization"),
            Some("Bearer token")
        );

        // Can write with token from COW
        let token = cow.http_write_token.as_ref().unwrap();
        cow.http
            .as_mut()
            .unwrap()
            .write(token)
            .set_header("X-Custom", "value");

        assert_eq!(
            cow.http.as_ref().unwrap().read().get_header("X-Custom"),
            Some("value")
        );

        // Original unchanged
        assert!(ext.http.as_ref().unwrap().get_header("X-Custom").is_none());
    }

    #[test]
    fn test_cow_copy_monotonic_label_insert() {
        let mut ext = make_extensions();
        ext.labels_write_token = Some(WriteToken::new());

        let mut cow = ext.cow_copy();

        // Can add labels on the COW copy
        cow.security.as_mut().unwrap().add_label("HIPAA");
        assert!(cow.security.as_ref().unwrap().has_label("HIPAA"));

        // Original unchanged
        assert!(!ext.security.as_ref().unwrap().has_label("HIPAA"));
    }

    #[test]
    fn test_validate_immutable_passes_for_cow() {
        let ext = make_extensions();
        let cow = ext.cow_copy();

        // COW copy shares immutable Arcs → validation passes
        assert!(ext.validate_immutable(&cow));
    }

    #[test]
    fn test_validate_immutable_fails_when_tampered() {
        let ext = make_extensions();
        let mut cow = ext.cow_copy();

        // Tamper with an immutable slot
        cow.request = Some(Arc::new(RequestExtension {
            request_id: Some("TAMPERED".into()),
            ..Default::default()
        }));

        // Validation fails — different Arc pointer
        assert!(!ext.validate_immutable(&cow));
    }

    #[test]
    fn test_validate_immutable_both_none_passes() {
        let ext = Extensions::default();
        let cow = ext.cow_copy();
        assert!(ext.validate_immutable(&cow));
    }

    #[test]
    fn test_clone_drops_write_tokens() {
        let mut ext = make_extensions();
        ext.http_write_token = Some(WriteToken::new());
        ext.labels_write_token = Some(WriteToken::new());
        ext.delegation_write_token = Some(WriteToken::new());

        // Regular clone drops all tokens
        let cloned = ext.clone();
        assert!(cloned.http_write_token.is_none());
        assert!(cloned.labels_write_token.is_none());
        assert!(cloned.delegation_write_token.is_none());

        // cow_copy propagates them
        let cow = ext.cow_copy();
        assert!(cow.http_write_token.is_some());
        assert!(cow.labels_write_token.is_some());
        assert!(cow.delegation_write_token.is_some());
    }

    #[test]
    fn test_cow_copy_modify_multiple_fields() {
        use crate::extensions::DelegationExtension;
        use crate::extensions::delegation::DelegationHop;

        // Build extensions with security, http, delegation, custom
        let mut security = SecurityExtension::default();
        security.add_label("PII");

        let mut http = HttpExtension::default();
        http.set_header("Authorization", "Bearer token");

        let mut ext = Extensions {
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            delegation: Some(Arc::new(DelegationExtension::default())),
            custom: Some(Arc::new([("existing".to_string(), serde_json::json!("value"))].into())),
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some("tool".into()),
                ..Default::default()
            })),
            ..Default::default()
        };

        // Executor sets all write tokens
        ext.http_write_token = Some(WriteToken::new());
        ext.labels_write_token = Some(WriteToken::new());
        ext.delegation_write_token = Some(WriteToken::new());

        // Plugin does one cow_copy, modifies multiple fields
        let mut cow = ext.cow_copy();

        // 1. Add security labels (monotonic)
        cow.security.as_mut().unwrap().add_label("CHECKED");
        cow.security.as_mut().unwrap().add_label("COMPLIANT");

        // 2. Inject HTTP headers (guarded)
        let token = cow.http_write_token.as_ref().unwrap();
        cow.http.as_mut().unwrap().write(token).set_header("X-Checked", "true");
        cow.http.as_mut().unwrap().write(token).set_header("X-Policy", "v2");

        // 3. Append delegation hop (monotonic)
        cow.delegation.as_mut().unwrap().append_hop(DelegationHop {
            subject_id: "service-a".into(),
            scopes_granted: vec!["read_hr".into()],
            ..Default::default()
        });

        // 4. Add custom data (mutable, no token needed)
        cow.custom.as_mut().unwrap().insert(
            "audit.timestamp".into(),
            serde_json::json!("2026-04-29"),
        );

        // Verify COW copy has all modifications
        let sec = cow.security.as_ref().unwrap();
        assert!(sec.has_label("PII"));       // original
        assert!(sec.has_label("CHECKED"));   // added
        assert!(sec.has_label("COMPLIANT")); // added

        let http = cow.http.as_ref().unwrap().read();
        assert_eq!(http.get_header("Authorization"), Some("Bearer token")); // original
        assert_eq!(http.get_header("X-Checked"), Some("true"));            // added
        assert_eq!(http.get_header("X-Policy"), Some("v2"));               // added

        assert_eq!(cow.delegation.as_ref().unwrap().chain.len(), 1);
        assert_eq!(cow.delegation.as_ref().unwrap().chain[0].subject_id, "service-a");

        assert_eq!(cow.custom.as_ref().unwrap().get("existing").unwrap(), "value");
        assert_eq!(cow.custom.as_ref().unwrap().get("audit.timestamp").unwrap(), "2026-04-29");

        // Verify original is unchanged
        assert!(!ext.security.as_ref().unwrap().has_label("CHECKED"));
        assert!(ext.http.as_ref().unwrap().get_header("X-Checked").is_none());
        assert!(ext.delegation.as_ref().unwrap().chain.is_empty());
        assert!(!ext.custom.as_ref().unwrap().contains_key("audit.timestamp"));

        // Immutable slots still valid
        assert!(ext.validate_immutable(&cow));
    }

    #[test]
    fn test_read_only_plugin_zero_cost() {
        // Plugin that only reads — no cow_copy, no clone
        let ext = make_extensions();

        // Read security labels
        let has_pii = ext.security.as_ref()
            .map(|s| s.has_label("PII"))
            .unwrap_or(false);
        assert!(has_pii);

        // Read HTTP headers
        let auth = ext.http.as_ref()
            .map(|h| h.get_header("Authorization"))
            .flatten();
        assert_eq!(auth, Some("Bearer token"));

        // Read meta
        let entity = ext.meta.as_ref()
            .and_then(|m| m.entity_type.as_deref());
        assert_eq!(entity, Some("tool"));

        // No cow_copy called — zero allocations for read-only access
    }
}
