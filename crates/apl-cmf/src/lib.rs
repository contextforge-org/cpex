// Location: ./crates/apl-cmf/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// apl-cmf — bridges typed cpex-core extensions into apl-core's flat
// AttributeBag. This is where the *attribute vocabulary* APL policy
// authors write against gets defined.
//
// Layering (see docs/specs/apl-design.md §4):
//
//   cpex-core  : typed extension data (SecurityExtension, …)
//   apl-cmf    : ←── this crate, flat-key bridge
//   apl-core   : language IR + evaluator (AttributeBag, predicates, pipelines)
//   apl-cpex   : runtime adapter (hooks, PluginInvoker, PdpResolver)
//
// The crate is intentionally simple: each bridge is a pure function that
// reads its typed source and writes flat keys into a borrowed bag. No
// async, no I/O. Composition is via the convenience `BagBuilder`.
//
// Attribute namespace contract (each module owns the detail comment):
//   SecurityExtension.subject         → subject.*, role.*, perm.*, claim.*, authenticated
//   SecurityExtension.client          → client.*, client.role.*, client.perm.*, client.claim.*
//   SecurityExtension.caller_workload → caller_workload.*   (inbound attested peer)
//   SecurityExtension.this_workload   → this_workload.*     (our own attested identity —
//                                         not `agent.*`, which is `AgentExtension`)
//   SecurityExtension                  → security.labels, security.classification, auth_method
//   DelegationExtension           → delegation.*, delegated
//   AgentExtension                 → agent.*       (session, conversation, lineage)
//   MetaExtension                  → meta.*
//   RequestExtension               → request.*
//   HttpExtension                  → http.method, http.path, http.host, http.scheme,
//                                     http.request_headers.*, http.response_headers.*
//   LLMExtension                   → llm.*
//   MCPExtension                   → mcp.tool.*, mcp.resource.*, mcp.prompt.*
//   CompletionExtension            → completion.*
//   ProvenanceExtension            → provenance.*
//   FrameworkExtension             → framework.*  (incl. framework.metadata.*)
//   Extensions.custom              → custom.*
//   Request args object            → args.*
//   Response result object         → result.*

pub mod agent;
pub mod capability_namespaces;
pub mod completion;
pub mod constants;
pub mod custom;
pub mod delegation;
pub mod extensions_bridge;
pub mod framework;
pub mod http;
pub mod llm;
pub mod mcp;
pub mod meta;
pub mod payload;
pub mod provenance;
pub mod request;
pub mod security;

pub use agent::extract_agent;
pub use capability_namespaces::{
    capability_namespaces, known_read_capabilities, unlocked_bag_prefixes,
};
pub use completion::extract_completion;
pub use custom::extract_custom;
pub use delegation::extract_delegation;
pub use extensions_bridge::extract_extensions;
pub use framework::extract_framework;
pub use http::extract_http;
pub use llm::extract_llm;
pub use mcp::extract_mcp;
pub use meta::extract_meta;
pub use payload::{extract_args, extract_result};
pub use provenance::extract_provenance;
pub use request::extract_request;
pub use security::{extract_client, extract_security, extract_workload};

use apl_core::AttributeBag;
use cpex_core::extensions::{DelegationExtension, Extensions, SecurityExtension};

/// Fluent builder that composes the typed sources into a single bag.
///
/// Lets the host (apl-cpex) write:
/// ```ignore
/// let bag = BagBuilder::new()
///     .with_security(&sec)
///     .with_delegation(&del)
///     .with_args(&payload.args)
///     .build();
/// ```
///
/// Order of `with_*` calls is irrelevant — keys live in disjoint namespaces.
#[derive(Default)]
pub struct BagBuilder {
    bag: AttributeBag,
}

impl BagBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_security(mut self, sec: &SecurityExtension) -> Self {
        extract_security(sec, &mut self.bag);
        self
    }

    pub fn with_delegation(mut self, del: &DelegationExtension) -> Self {
        extract_delegation(del, &mut self.bag);
        self
    }

    /// Bridge every present slot in an `Extensions` container at once —
    /// security, delegation, agent, meta, request, http, llm, mcp,
    /// completion, provenance, framework, custom.
    pub fn with_extensions(mut self, ext: &Extensions) -> Self {
        extract_extensions(ext, &mut self.bag);
        self
    }

    pub fn with_args(mut self, args: &serde_json::Value) -> Self {
        extract_args(args, &mut self.bag);
        self
    }

    pub fn with_result(mut self, result: &serde_json::Value) -> Self {
        extract_result(result, &mut self.bag);
        self
    }

    /// Set the route key under `route.key` for policy predicates that
    /// branch on which route is running (mostly useful in default/policy
    /// bundles applied across routes).
    pub fn with_route_key(mut self, route_key: impl Into<String>) -> Self {
        self.bag.set("route.key", route_key.into());
        self
    }

    pub fn build(self) -> AttributeBag {
        self.bag
    }
}
