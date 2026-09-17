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

use std::collections::{HashMap, HashSet};
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
use super::raw_credentials::RawCredentialsExtension;
use super::request::RequestExtension;
use super::routing::{CandidateConstraintExtension, CAP_WRITE_CANDIDATE_CONSTRAINT};
use super::security::SecurityExtension;

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

    /// Backend candidate constraint emitted by APL `restrict` effects
    /// (frozen as Arc — cloned out in OwnedExtensions). The policy
    /// engine writes it; the host router reads it typed to narrow its
    /// candidate set. A routing directive, never an access decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_constraint: Option<Arc<CandidateConstraintExtension>>,

    /// Delegation chain (frozen as Arc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Arc<DelegationExtension>>,

    /// Raw credential material — Layer 3 of the credential storage
    /// model (see `RawCredentialsExtension` docs). Capability-gated;
    /// `filter_extensions` strips this slot for plugins without
    /// `read_inbound_credentials` / `read_delegated_tokens`. Token
    /// fields inside this extension are `#[serde(skip)]`, so any
    /// serialization (logs, audit dumps, hot-reload snapshots) drops
    /// secret material even when the slot itself survives — so no
    /// out-of-process plugin sees token bytes over the generic
    /// `extensions` channel. Plaintext can still reach a worker over a
    /// host's purpose-built, capability-gated side channel; see
    /// `RawCredentialsExtension` for the conditions and the residual
    /// exposure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_credentials: Option<Arc<RawCredentialsExtension>>,

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
            candidate_constraint: self.candidate_constraint.clone(),
            delegation: self.delegation.clone(),
            raw_credentials: self.raw_credentials.clone(),
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
            raw_credentials: self.raw_credentials.clone(),

            // Mutable/monotonic/guarded — cloned out of Arc into owned
            http: self.http.as_ref().map(|arc| Guarded::new((**arc).clone())),
            security: self.security.as_ref().map(|arc| (**arc).clone()),
            candidate_constraint: self
                .candidate_constraint
                .as_ref()
                .map(|arc| (**arc).clone()),
            delegation: self.delegation.as_ref().map(|arc| (**arc).clone()),
            custom: self.custom.as_ref().map(|arc| (**arc).clone()),

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
    ///
    /// A slot that is `None` in modified (because capability filtering
    /// hid it from the plugin) is always valid — the plugin never saw
    /// it. Only flag as tampering when both are `Some` with different
    /// Arc pointers, or when the original is `None` but modified is
    /// `Some` (the plugin fabricated a slot it shouldn't have).
    pub fn validate_immutable(&self, modified: &OwnedExtensions) -> bool {
        fn ptr_eq_opt<T>(a: &Option<Arc<T>>, b: &Option<Arc<T>>) -> bool {
            match (a, b) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                (_, None) => true,        // plugin never saw it — not tampering
                (None, Some(_)) => false, // plugin fabricated a slot
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
        // NOTE: `raw_credentials` is INTENTIONALLY excluded from the
        // immutable check. Framework orchestrators (apl-cpex's
        // DelegationPluginInvoker) legitimately write
        // `delegated_tokens.*` via the shared Mutex during route
        // evaluation, producing a new Arc by the time the synthetic
        // handler returns. Per-plugin write authority is enforced at
        // the capability layer (`write_delegated_tokens` /
        // `write_inbound_credentials`), not at this pointer-equality
        // gate. Until cap-tier-aware merge lands, treat raw_credentials
        // as merge-able like `security` and `delegation`.
    }

    /// Whether `modified` may write the `candidate_constraint` slot, given
    /// the plugin's `capabilities`.
    ///
    /// The routing constraint is the policy engine's *output*: only a holder
    /// of [`CAP_WRITE_CANDIDATE_CONSTRAINT`] may create, change, or remove it.
    /// A plugin that leaves the slot at its original value (or holds the cap)
    /// passes; any other plugin that alters it by value is rejected, so a
    /// downstream plugin cannot overwrite, drop, or forge the constraint.
    /// Compared by value (not `Arc` pointer) because the slot legitimately
    /// round-trips through a fresh `Arc` on every merge.
    pub fn candidate_constraint_write_ok(
        &self,
        modified: &OwnedExtensions,
        capabilities: &HashSet<String>,
    ) -> bool {
        capabilities.contains(CAP_WRITE_CANDIDATE_CONSTRAINT)
            || modified.candidate_constraint.as_ref() == self.candidate_constraint.as_deref()
    }

    /// Merge an OwnedExtensions back into this Extensions, field by field.
    ///
    /// # Why per-field and not per-slot
    ///
    /// `owned` derives from `cow_copy()` of a **capability-filtered** view, so
    /// every sub-field the plugin could not read is *empty* in it, not merely
    /// unchanged. `filter_extensions` blanks `security.labels`, `.subject`,
    /// `.client`, `.caller_workload`, and `.this_workload` for a plugin without
    /// the matching read capability. A whole-slot swap therefore writes those
    /// blanks over canonical state: a plugin with no security capability at all
    /// could wipe the pipeline's security labels just by returning a `custom`
    /// value, because the swap took its empty-labels view along for the ride.
    ///
    /// So each writable field is merged individually and only when the matching
    /// write token is present on `owned`. The token is minted by the executor
    /// from the plugin's declared capabilities (`WriteToken::new()` is
    /// `pub(crate)`), so it is the authority for *this* field, not for the slot
    /// it happens to live in. Fields with no write capability in the tier model
    /// — `security.subject`, `.auth_method`, `.client`, the workload identities
    /// — are never taken from `owned` no matter which token it carries.
    ///
    /// Ambiguity fails closed: an absent token, an absent slot, or a
    /// non-monotonic edit leaves the canonical value standing.
    pub fn merge_owned(&mut self, owned: OwnedExtensions) {
        self.merge_http(owned.http, owned.http_write_token.as_ref());
        self.merge_security(owned.security, owned.labels_write_token.as_ref());
        self.candidate_constraint = owned.candidate_constraint.map(Arc::new);
        self.merge_delegation(owned.delegation, owned.delegation_write_token.as_ref());

        // `custom` is the Mutable tier with `AccessPolicy::Unrestricted` — no
        // capability gates it, so it merges without a token. It is also the
        // only slot in that position, which is why it must not be able to drag
        // a gated slot along with it.
        self.custom = owned.custom.map(Arc::new);
        // `raw_credentials` is shared by Arc in `OwnedExtensions` —
        // plugins don't mutate it directly. But framework orchestrators
        // (apl-cpex's DelegationPluginInvoker) DO write delegated_tokens
        // / inbound_tokens through the shared `Arc<Mutex<Extensions>>`
        // before the synthetic handler returns. We must propagate
        // those writes back so callers of `invoke_named` see the
        // minted tokens in `PipelineResult.modified_extensions`.
        // Without this, `delegate(...)` steps silently lose their
        // results at the executor merge boundary.
        if owned.raw_credentials.is_some() {
            self.raw_credentials = owned.raw_credentials;
        }
    }

    /// Merge the guarded `http` slot — header maps and the request line.
    ///
    /// `write_headers` authorizes *headers*, which is what the capability is
    /// named for. The request line (`method`, `path`, `host`, `scheme`) is
    /// host-populated request identity that policies gate on, so it is always
    /// preserved from canonical state and never taken from `owned`. `host` in
    /// particular must come from a validated authority (see `HttpExtension`),
    /// which a plugin's return value is not.
    fn merge_http(&mut self, owned: Option<Guarded<HttpExtension>>, token: Option<&WriteToken>) {
        let Some(owned) = owned else { return };
        if token.is_none() {
            return;
        }
        let owned = owned.into_inner();

        let mut merged = match self.http.as_ref() {
            Some(canonical) => (**canonical).clone(),
            // No canonical http slot: there is no request line to preserve, so
            // the returned headers stand on their own.
            None => HttpExtension::default(),
        };
        merged.request_headers = owned.request_headers;
        merged.response_headers = owned.response_headers;
        self.http = Some(Arc::new(merged));
    }

    /// Merge the `security` slot — labels only, and only as an append.
    ///
    /// Labels are the Monotonic tier: `append_labels` permits growing the set
    /// and nothing else. A returned set that is not a superset of canonical is a
    /// removal attempt and is dropped whole rather than partially applied — a
    /// laundered declassification is the exact attack this gate exists for, and
    /// removal requires a `DeclassifierToken` no plugin can construct.
    ///
    /// Every other field on the slot is Immutable in the tier model with
    /// `write_cap: None` — `subject`, `auth_method`, `client`, `caller_workload`,
    /// `this_workload`, `classification`, `objects`, `data`. A labels token does
    /// not reach them, so they are preserved from canonical state. Without this,
    /// `append_labels` alone would let a plugin rewrite the authenticated
    /// subject and the auth method it was authenticated by.
    fn merge_security(&mut self, owned: Option<SecurityExtension>, token: Option<&WriteToken>) {
        let Some(owned) = owned else { return };
        if token.is_none() {
            return;
        }

        let mut merged = match self.security.as_ref() {
            Some(canonical) => (**canonical).clone(),
            None => SecurityExtension::default(),
        };

        // Monotonic: fold in the additions, never assign the returned set.
        // Assignment would drop any canonical label the plugin could not see,
        // and folding makes a filtered-away label unremovable by construction.
        if !owned.labels.is_superset(&merged.labels) {
            // Not a superset of what the plugin was shown either — an explicit
            // removal attempt. Drop the whole edit; the canonical set stands.
            return;
        }
        for label in owned.labels.iter() {
            merged.labels.add_label(label.clone());
        }

        self.security = Some(Arc::new(merged));
    }

    /// Merge the `delegation` slot — append-only chain growth, validated.
    ///
    /// The chain is the Monotonic tier: `append_delegation` permits appending
    /// hops. A returned chain must therefore *extend* the canonical one — same
    /// length-or-longer, with every existing hop unchanged. A shortened or
    /// rewritten chain is a forged lineage (dropping the hop that recorded a
    /// scope narrowing widens effective authority) and is dropped whole.
    ///
    /// `depth` and `delegated` are recomputed from the merged chain rather than
    /// taken from the wire, so a plugin cannot claim a depth its chain does not
    /// have. `origin_subject_id` is the chain's root identity and is preserved
    /// once canonical state has one.
    fn merge_delegation(&mut self, owned: Option<DelegationExtension>, token: Option<&WriteToken>) {
        let Some(owned) = owned else { return };
        if token.is_none() {
            return;
        }

        let canonical = self.delegation.as_ref().map(|arc| (**arc).clone());
        let mut merged = canonical.clone().unwrap_or_default();

        if let Some(canonical) = canonical.as_ref() {
            if !chain_extends(&canonical.chain, &owned.chain) {
                return;
            }
        }
        merged.chain = owned.chain;

        // Derived from the chain, not asserted by the plugin.
        // Cast is safe: a chain with > u32::MAX hops would have failed
        // allocation long ago.
        merged.depth = merged.chain.len() as u32;
        merged.delegated = !merged.chain.is_empty();

        // The root of the chain cannot be re-pointed once established; the
        // current actor legitimately advances with each appended hop.
        if merged.origin_subject_id.is_none() {
            merged.origin_subject_id = owned.origin_subject_id;
        }
        merged.actor_subject_id = owned.actor_subject_id;
        merged.age_seconds = owned.age_seconds;

        self.delegation = Some(Arc::new(merged));
    }
}

/// True when `returned` is `canonical` plus zero or more appended hops.
///
/// Hops are compared on the fields that carry authority — subject, audience,
/// granted scopes, and strategy. A rewrite of any of those on an existing hop is
/// not an append, so the whole edit is refused.
///
/// Public so out-of-process hosts can apply the same validation to a chain
/// arriving over the wire before it reaches the merge, instead of reimplementing
/// the definition of "append-only" and drifting from it.
pub fn chain_extends(
    canonical: &[super::delegation::DelegationHop],
    returned: &[super::delegation::DelegationHop],
) -> bool {
    if returned.len() < canonical.len() {
        return false;
    }
    canonical
        .iter()
        .zip(returned.iter())
        .all(|(before, after)| {
            before.subject_id == after.subject_id
                && before.subject_type == after.subject_type
                && before.audience == after.audience
                && before.scopes_granted == after.scopes_granted
                && before.strategy == after.strategy
        })
}

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
    /// Raw credentials are shared by Arc here too — write tokens for
    /// `inbound_tokens` and `delegated_tokens` mutation paths land with
    /// the IdentityResolve and TokenDelegate hooks. Until
    /// then, no plugin writes through `OwnedExtensions.raw_credentials`.
    pub raw_credentials: Option<Arc<RawCredentialsExtension>>,

    // Mutable/monotonic/guarded — owned, modifiable
    pub http: Option<Guarded<HttpExtension>>,
    pub security: Option<SecurityExtension>,
    pub candidate_constraint: Option<CandidateConstraintExtension>,
    pub delegation: Option<DelegationExtension>,
    pub custom: Option<HashMap<String, serde_json::Value>>,

    pub http_write_token: Option<WriteToken>,
    pub labels_write_token: Option<WriteToken>,
    pub delegation_write_token: Option<WriteToken>,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::security::SubjectExtension;
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
        assert!(Arc::ptr_eq(
            ext.request.as_ref().unwrap(),
            cow.request.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            ext.meta.as_ref().unwrap(),
            cow.meta.as_ref().unwrap()
        ));
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
            cow.http
                .as_ref()
                .unwrap()
                .read()
                .get_header("Authorization"),
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

    // ----- candidate_constraint write authority -----

    fn a_constraint(region: &str) -> CandidateConstraintExtension {
        CandidateConstraintExtension {
            allow_regions: Some(vec![region.to_string()]),
            ..Default::default()
        }
    }

    fn caps(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn candidate_constraint_unchanged_passes_without_cap() {
        // A plugin that leaves the slot at its original value is fine even
        // without the write cap — the common case for every plugin.
        let mut ext = Extensions::default();
        ext.candidate_constraint = Some(Arc::new(a_constraint("eu")));
        let owned = ext.cow_copy(); // carries the same constraint value
        assert!(ext.candidate_constraint_write_ok(&owned, &caps(&[])));
    }

    #[test]
    fn candidate_constraint_overwrite_rejected_without_cap() {
        let mut ext = Extensions::default();
        ext.candidate_constraint = Some(Arc::new(a_constraint("eu")));
        let mut owned = ext.cow_copy();
        owned.candidate_constraint = Some(a_constraint("us")); // weakened/changed
        assert!(!ext.candidate_constraint_write_ok(&owned, &caps(&[])));
        // ...but a cap-holder (the APL engine) may overwrite.
        assert!(ext.candidate_constraint_write_ok(&owned, &caps(&[CAP_WRITE_CANDIDATE_CONSTRAINT])));
    }

    #[test]
    fn candidate_constraint_removal_rejected_without_cap() {
        let mut ext = Extensions::default();
        ext.candidate_constraint = Some(Arc::new(a_constraint("eu")));
        let mut owned = ext.cow_copy();
        owned.candidate_constraint = None; // dropped the policy engine's constraint
        assert!(!ext.candidate_constraint_write_ok(&owned, &caps(&[])));
    }

    #[test]
    fn candidate_constraint_fabricate_rejected_without_cap() {
        let ext = Extensions::default(); // no constraint originally
        let mut owned = ext.cow_copy();
        owned.candidate_constraint = Some(a_constraint("eu")); // forged
        assert!(!ext.candidate_constraint_write_ok(&owned, &caps(&[])));
        // The APL engine, holding the cap, legitimately creates it.
        assert!(ext.candidate_constraint_write_ok(&owned, &caps(&[CAP_WRITE_CANDIDATE_CONSTRAINT])));
    }

    #[test]
    fn candidate_constraint_both_none_passes_without_cap() {
        let ext = Extensions::default();
        let owned = ext.cow_copy();
        assert!(ext.candidate_constraint_write_ok(&owned, &caps(&[])));
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
        use crate::extensions::delegation::DelegationHop;
        use crate::extensions::DelegationExtension;

        let mut security = SecurityExtension::default();
        security.add_label("PII");

        let mut http = HttpExtension::default();
        http.set_header("Authorization", "Bearer token");

        let mut ext = Extensions {
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            delegation: Some(Arc::new(DelegationExtension::default())),
            custom: Some(Arc::new(
                [("existing".to_string(), serde_json::json!("value"))].into(),
            )),
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
        cow.http
            .as_mut()
            .unwrap()
            .write(token)
            .set_header("X-Checked", "true");
        cow.http
            .as_mut()
            .unwrap()
            .write(token)
            .set_header("X-Policy", "v2");

        // 3. Append delegation hop (monotonic)
        cow.delegation.as_mut().unwrap().append_hop(DelegationHop {
            subject_id: "service-a".into(),
            scopes_granted: vec!["read_hr".into()],
            ..Default::default()
        });

        // 4. Add custom data (mutable, no token needed)
        cow.custom
            .as_mut()
            .unwrap()
            .insert("audit.timestamp".into(), serde_json::json!("2026-04-29"));

        // Verify COW copy has all modifications
        let sec = cow.security.as_ref().unwrap();
        assert!(sec.has_label("PII")); // original
        assert!(sec.has_label("CHECKED")); // added
        assert!(sec.has_label("COMPLIANT")); // added

        let http = cow.http.as_ref().unwrap().read();
        assert_eq!(http.get_header("Authorization"), Some("Bearer token")); // original
        assert_eq!(http.get_header("X-Checked"), Some("true")); // added
        assert_eq!(http.get_header("X-Policy"), Some("v2")); // added

        assert_eq!(cow.delegation.as_ref().unwrap().chain.len(), 1);
        assert_eq!(
            cow.delegation.as_ref().unwrap().chain[0].subject_id,
            "service-a"
        );

        assert_eq!(
            cow.custom.as_ref().unwrap().get("existing").unwrap(),
            "value"
        );
        assert_eq!(
            cow.custom.as_ref().unwrap().get("audit.timestamp").unwrap(),
            "2026-04-29"
        );

        // Verify original is unchanged
        assert!(!ext.security.as_ref().unwrap().has_label("CHECKED"));
        assert!(ext.http.as_ref().unwrap().get_header("X-Checked").is_none());
        assert!(ext.delegation.as_ref().unwrap().chain.is_empty());
        assert!(!ext.custom.as_ref().unwrap().contains_key("audit.timestamp"));

        // Immutable slots still valid
        assert!(ext.validate_immutable(&cow));
    }

    #[test]
    fn test_validate_immutable_passes_when_slot_filtered_out() {
        // Bug fix regression: when capability filtering hides a slot
        // from the plugin (e.g., agent=None in owned because plugin
        // lacks read_agent), validate_immutable must NOT treat that
        // as tampering.
        let ext = make_extensions();
        let mut cow = ext.cow_copy();

        // Simulate capability filtering hiding the agent slot
        cow.agent = None;

        // Validation should pass — plugin never saw the slot
        assert!(ext.validate_immutable(&cow));
    }

    #[test]
    fn test_validate_immutable_fails_when_slot_fabricated() {
        // If the original has no agent but the plugin returns one,
        // that's fabrication — should fail.
        let ext = Extensions::default(); // no agent
        let mut cow = ext.cow_copy();

        cow.agent = Some(Arc::new(AgentExtension {
            agent_id: Some("fabricated".into()),
            ..Default::default()
        }));

        assert!(!ext.validate_immutable(&cow));
    }

    #[test]
    fn test_validate_immutable_passes_multiple_slots_filtered() {
        // Multiple immutable slots filtered out — all should pass
        let ext = make_extensions();
        let mut cow = ext.cow_copy();

        cow.agent = None;
        cow.mcp = None;
        cow.completion = None;
        cow.framework = None;

        assert!(ext.validate_immutable(&cow));
    }

    #[test]
    fn test_merge_owned_preserves_http_response_headers() {
        // Bug fix regression: merge_owned must preserve response
        // headers written by a plugin through Guarded write access.
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer tok");

        let mut ext = Extensions {
            http: Some(Arc::new(http)),
            ..Default::default()
        };
        ext.http_write_token = Some(WriteToken::new());

        let mut cow = ext.cow_copy();

        // Plugin writes response headers through the guard
        let token = cow.http_write_token.as_ref().unwrap();
        let h = cow.http.as_mut().unwrap().write(token);
        h.set_response_header("X-Tool-Name", "get_compensation");
        h.set_response_header("X-Status", "success");

        // Merge back
        ext.merge_owned(cow);

        // Response headers must be present after merge
        let merged_http = ext.http.as_ref().unwrap();
        assert_eq!(
            merged_http.get_response_header("X-Tool-Name"),
            Some("get_compensation")
        );
        assert_eq!(merged_http.get_response_header("X-Status"), Some("success"));
        // Original request headers preserved
        assert_eq!(
            merged_http.get_request_header("Authorization"),
            Some("Bearer tok")
        );
    }

    #[test]
    fn test_merge_owned_with_filtered_security_preserves_labels() {
        // A plugin without read_labels gets empty labels in its filtered
        // view. merge_owned must not write that blank over canonical state.
        //
        // This asserted the opposite before the per-field merge landed — it
        // encoded the slot-swap bug as expected behavior.
        let mut security = SecurityExtension::default();
        security.add_label("PII");
        security.add_label("HR");

        let mut ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };
        // Even *with* the append capability, an empty returned set must not
        // subtract. Without the token it would not merge at all, which would
        // make the test pass for the wrong reason.
        ext.labels_write_token = Some(WriteToken::new());

        let mut cow = ext.cow_copy();
        // Simulate the filtered view: no read_labels → empty label set.
        cow.security.as_mut().unwrap().labels = crate::extensions::MonotonicSet::new();

        ext.merge_owned(cow);

        let merged_sec = ext.security.as_ref().unwrap();
        assert!(
            merged_sec.has_label("PII"),
            "a label the plugin could not see must survive the merge"
        );
        assert!(merged_sec.has_label("HR"));
    }

    #[test]
    fn test_merge_owned_none_http_preserves_pipeline() {
        // If owned.http is None (plugin had no read_headers capability),
        // the canonical slot must stand — there is no edit to apply.
        let mut http = HttpExtension::default();
        http.set_request_header("X-Original", "value");

        let mut ext = Extensions {
            http: Some(Arc::new(http)),
            ..Default::default()
        };
        ext.http_write_token = Some(WriteToken::new());

        let mut cow = ext.cow_copy();
        cow.http = None; // simulate filtered-out HTTP

        ext.merge_owned(cow);

        assert_eq!(
            ext.http
                .as_ref()
                .and_then(|h| h.get_request_header("X-Original")),
            Some("value"),
            "an absent slot in the return is not an instruction to clear it"
        );
    }

    // -- Per-field merge gating (review finding A) --
    //
    // Each test below fails against the previous whole-slot `merge_owned`,
    // which assigned `self.security = owned.security` (and likewise for http
    // and delegation) regardless of which token `owned` carried.

    #[test]
    fn test_custom_write_cannot_wipe_security_labels() {
        // The headline finding: a plugin with NO security capability returns a
        // `custom` value. Its filtered view has empty labels, and the old slot
        // swap took that view along — wiping the pipeline's labels via a slot
        // the plugin was never gated on.
        let mut security = SecurityExtension::default();
        security.add_label("PII");

        let mut ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };
        // No tokens at all — this plugin declared no security capability.

        let mut cow = ext.cow_copy();
        cow.security.as_mut().unwrap().labels = crate::extensions::MonotonicSet::new();
        cow.custom = Some([("verdict".to_string(), serde_json::json!("clean"))].into());

        ext.merge_owned(cow);

        assert!(
            ext.security.as_ref().unwrap().has_label("PII"),
            "a capability-less custom write must not wipe security labels"
        );
        assert_eq!(
            ext.custom.as_ref().unwrap().get("verdict").unwrap(),
            "clean",
            "the legitimate custom write still lands"
        );
    }

    #[test]
    fn test_labels_token_cannot_rewrite_subject_or_auth_method() {
        // `append_labels` is Monotonic on *labels*. `subject` and `auth_method`
        // are Immutable with `write_cap: None`, so a labels token must not
        // reach them — otherwise appending a label buys a plugin the ability to
        // rewrite the principal it authenticated as.
        let mut security = SecurityExtension::default();
        security.add_label("PII");
        security.subject = Some(SubjectExtension {
            id: Some("real-user".into()),
            ..Default::default()
        });
        security.auth_method = Some("mtls".into());

        let mut ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };
        ext.labels_write_token = Some(WriteToken::new());

        let mut cow = ext.cow_copy();
        let owned_sec = cow.security.as_mut().unwrap();
        owned_sec.add_label("SCANNED"); // legitimate
        owned_sec.subject = Some(SubjectExtension {
            id: Some("attacker".into()),
            ..Default::default()
        });
        owned_sec.auth_method = Some("anonymous".into());

        ext.merge_owned(cow);

        let merged = ext.security.as_ref().unwrap();
        assert!(merged.has_label("SCANNED"), "the label append is honored");
        assert!(merged.has_label("PII"), "and does not subtract");
        assert_eq!(
            merged.subject.as_ref().unwrap().id.as_deref(),
            Some("real-user"),
            "a labels token must not rewrite the authenticated subject"
        );
        assert_eq!(
            merged.auth_method.as_deref(),
            Some("mtls"),
            "nor the auth method"
        );
    }

    #[test]
    fn test_label_removal_is_dropped_whole() {
        let mut security = SecurityExtension::default();
        security.add_label("PII");
        security.add_label("HIPAA");

        let mut ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };
        ext.labels_write_token = Some(WriteToken::new());

        let mut cow = ext.cow_copy();
        // Drop HIPAA and add something — a laundered declassification.
        let mut shrunk = std::collections::HashSet::new();
        shrunk.insert("PII".to_string());
        shrunk.insert("CLEAN".to_string());
        cow.security.as_mut().unwrap().labels = crate::extensions::MonotonicSet::from_set(shrunk);

        ext.merge_owned(cow);

        let merged = ext.security.as_ref().unwrap();
        assert!(merged.has_label("HIPAA"), "the removal is refused");
        assert!(
            !merged.has_label("CLEAN"),
            "and the edit is dropped whole, not partially applied"
        );
    }

    #[test]
    fn test_security_merge_needs_the_labels_token() {
        let mut security = SecurityExtension::default();
        security.add_label("PII");

        let mut ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };
        // No labels token.

        let mut cow = ext.cow_copy();
        cow.security.as_mut().unwrap().add_label("FORGED");

        ext.merge_owned(cow);

        assert!(
            !ext.security.as_ref().unwrap().has_label("FORGED"),
            "an append without the capability is dropped"
        );
    }

    #[test]
    fn test_http_merge_preserves_request_line() {
        // Policies gate on method/path/host/scheme (CHANGELOG 0.2.2), and
        // `write_headers` does not authorize rewriting request identity.
        let mut http = HttpExtension::default();
        http.method = Some("POST".into());
        http.path = Some("/api/v1/transfer".into());
        http.host = Some("bank.internal".into());
        http.scheme = Some("https".into());

        let mut ext = Extensions {
            http: Some(Arc::new(http)),
            ..Default::default()
        };
        ext.http_write_token = Some(WriteToken::new());

        let mut cow = ext.cow_copy();
        let token = cow.http_write_token.take().expect("token propagated");
        {
            let h = cow.http.as_mut().unwrap().write(&token);
            h.set_request_header("X-Scanned", "1");
            // A worker round trip loses these; a hostile one rewrites them.
            h.method = Some("GET".into());
            h.path = Some("/api/v1/healthz".into());
            h.host = Some("evil.example".into());
            h.scheme = None;
        }
        cow.http_write_token = Some(token);

        ext.merge_owned(cow);

        let merged = ext.http.as_ref().unwrap();
        assert_eq!(merged.method.as_deref(), Some("POST"));
        assert_eq!(merged.path.as_deref(), Some("/api/v1/transfer"));
        assert_eq!(merged.host.as_deref(), Some("bank.internal"));
        assert_eq!(merged.scheme.as_deref(), Some("https"));
        assert_eq!(
            merged.get_request_header("X-Scanned"),
            Some("1"),
            "the header write it was authorized for still lands"
        );
    }

    #[test]
    fn test_delegation_chain_cannot_be_shortened_or_rewritten() {
        use crate::extensions::delegation::DelegationHop;

        let mut delegation = DelegationExtension::default();
        delegation.append_hop(DelegationHop {
            subject_id: "user-1".into(),
            scopes_granted: vec!["read_hr".into()],
            ..Default::default()
        });
        delegation.append_hop(DelegationHop {
            subject_id: "svc-a".into(),
            scopes_granted: vec!["read_hr".into()],
            ..Default::default()
        });
        delegation.origin_subject_id = Some("user-1".into());

        let mut ext = Extensions {
            delegation: Some(Arc::new(delegation)),
            ..Default::default()
        };
        ext.delegation_write_token = Some(WriteToken::new());

        // Truncate to one hop, dropping the narrowing that hop recorded.
        let mut cow = ext.cow_copy();
        let owned_del = cow.delegation.as_mut().unwrap();
        owned_del.chain.truncate(1);
        owned_del.depth = 1;

        ext.merge_owned(cow);
        assert_eq!(
            ext.delegation.as_ref().unwrap().chain.len(),
            2,
            "a truncated chain is not an append — refused whole"
        );

        // Rewriting the scopes on an existing hop is likewise not an append.
        let mut cow = ext.cow_copy();
        cow.delegation.as_mut().unwrap().chain[0].scopes_granted = vec!["admin".into()];

        ext.merge_owned(cow);
        assert_eq!(
            ext.delegation.as_ref().unwrap().chain[0].scopes_granted,
            vec!["read_hr".to_string()],
            "an existing hop's granted scopes cannot be widened"
        );
    }

    #[test]
    fn test_delegation_append_is_honored_and_depth_recomputed() {
        use crate::extensions::delegation::DelegationHop;

        let mut delegation = DelegationExtension::default();
        delegation.append_hop(DelegationHop {
            subject_id: "user-1".into(),
            scopes_granted: vec!["read_hr".into()],
            ..Default::default()
        });
        delegation.origin_subject_id = Some("user-1".into());

        let mut ext = Extensions {
            delegation: Some(Arc::new(delegation)),
            ..Default::default()
        };
        ext.delegation_write_token = Some(WriteToken::new());

        let mut cow = ext.cow_copy();
        let owned_del = cow.delegation.as_mut().unwrap();
        owned_del.chain.push(DelegationHop {
            subject_id: "svc-b".into(),
            scopes_granted: vec!["read_hr".into()],
            ..Default::default()
        });
        // Claim a depth the chain does not have, and try to re-point the root.
        owned_del.depth = 99;
        owned_del.origin_subject_id = Some("attacker".into());

        ext.merge_owned(cow);

        let merged = ext.delegation.as_ref().unwrap();
        assert_eq!(merged.chain.len(), 2, "the append is honored");
        assert_eq!(merged.depth, 2, "depth is recomputed, not trusted");
        assert!(merged.delegated);
        assert_eq!(
            merged.origin_subject_id.as_deref(),
            Some("user-1"),
            "the chain root cannot be re-pointed once established"
        );
    }

    #[test]
    fn test_delegation_merge_needs_the_token() {
        use crate::extensions::delegation::DelegationHop;

        let mut ext = Extensions {
            delegation: Some(Arc::new(DelegationExtension::default())),
            ..Default::default()
        };
        // No delegation token.

        let mut cow = ext.cow_copy();
        cow.delegation.as_mut().unwrap().append_hop(DelegationHop {
            subject_id: "forged".into(),
            ..Default::default()
        });

        ext.merge_owned(cow);

        assert!(
            ext.delegation.as_ref().unwrap().chain.is_empty(),
            "appending a hop without the capability is dropped"
        );
    }

    #[test]
    fn test_read_only_plugin_zero_cost() {
        // Plugin that only reads — no cow_copy, no clone
        let ext = make_extensions();

        // Read security labels
        let has_pii = ext
            .security
            .as_ref()
            .map(|s| s.has_label("PII"))
            .unwrap_or(false);
        assert!(has_pii);

        // Read HTTP headers
        let auth = ext
            .http
            .as_ref()
            .and_then(|h| h.get_header("Authorization"));
        assert_eq!(auth, Some("Bearer token"));

        // Read meta
        let entity = ext.meta.as_ref().and_then(|m| m.entity_type.as_deref());
        assert_eq!(entity, Some("tool"));

        // No cow_copy called — zero allocations for read-only access
    }
}
