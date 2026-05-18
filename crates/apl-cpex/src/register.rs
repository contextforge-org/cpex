// Location: ./crates/apl-cpex/src/register.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `register_apl` — sugar function that bundles "construct
// `AplConfigVisitor` + register it with the manager" into one call.
//
// Hosts that just want APL governance with sensible defaults call this
// instead of building the visitor by hand. The lower-level
// `PluginManager::register_visitor` API stays available for custom
// orchestrators (future Rego, Cedar-direct, hand-rolled audit visitors)
// that don't fit the APL setup.
//
// # Why one PDP slot but a `Vec` of resolvers
//
// `AplConfigVisitor` carries a single `Arc<dyn PdpResolver>` so that
// any resolver (direct Cedar, direct OPA, or a `PdpRouter` carrying
// many) plugs in uniformly. When the caller passes more than one
// resolver via `AplOptions.pdps`, this function wraps them in a
// `PdpRouter` so each `pdp(...)` step dispatches by dialect. Passing
// zero resolvers is fine — APL routes that don't use `pdp(...)` steps
// won't notice.

use std::collections::HashSet;
use std::sync::Arc;

use cpex_core::manager::PluginManager;
use cpex_core::visitor::ConfigVisitor;

use apl_core::step::PdpResolver;

use crate::dispatch_plan::DispatchCache;
use crate::pdp_router::PdpRouter;
use crate::session_store::SessionStore;
use crate::visitor::AplConfigVisitor;

/// Configuration for [`register_apl`]. All runtime collaborators APL
/// needs to do its work are funneled through here so the call site
/// reads as a single block instead of a multi-step builder.
pub struct AplOptions {
    /// Shared dispatch-plan cache. One `Arc<DispatchCache>` per host
    /// instance — clones are cheap (refcount bump) and the cache is
    /// internally synchronized.
    pub dispatch_cache: Arc<DispatchCache>,

    /// Pluggable session-scoped state. `MemorySessionStore` is the
    /// default in-process backend; production hosts swap in Redis /
    /// DynamoDB-backed impls.
    pub session_store: Arc<dyn SessionStore>,

    /// Zero or more PDP resolvers. Wrapped in a [`PdpRouter`] under
    /// the hood so `pdp(...)` steps dispatch by dialect. An empty
    /// list means no PDP is wired — routes that call `pdp(...)`
    /// surface `PdpError::NoResolver` at evaluation time, which is the
    /// correct behavior for "you forgot to configure your policy
    /// decision point."
    pub pdps: Vec<Arc<dyn PdpResolver>>,

    /// Override the visitor's baseline capabilities for installed
    /// `AplRouteHandler`s. `None` uses the visitor's default
    /// (read-only across the common attribute namespaces); `Some(set)`
    /// replaces it entirely. The per-route plugin capability union is
    /// added on top regardless — this only controls the baseline.
    ///
    /// Set to `Some(HashSet::new())` for strict deployments where
    /// only plugin-declared caps should be granted.
    pub base_capabilities: Option<HashSet<String>>,
}

impl AplOptions {
    /// Minimal options — in-process dispatch cache + memory session
    /// store, no PDP, default baseline capabilities. Useful for tests
    /// and single-process demos.
    pub fn in_process() -> Self {
        Self {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(crate::session_store::MemorySessionStore::new()),
            pdps: Vec::new(),
            base_capabilities: None,
        }
    }
}

/// Build an [`AplConfigVisitor`] from the supplied options and register
/// it on the manager. Returns the `Arc<AplConfigVisitor>` so the caller
/// can stash it for later inspection (e.g. for a custom `with_pdp`
/// extension) — but in the typical case the return value is dropped
/// and the visitor lives inside the manager's visitor list.
///
/// After this call, the next `mgr.load_config_yaml(yaml)` invocation
/// will walk the visitor: cpex-core's [`visit_plugins`][vp] populates
/// the APL plugin registry from `&[PluginConfig]`; the hierarchy walk
/// stacks `global.apl` / `defaults.<entity>.apl` / `policies.<tag>.apl`
/// / route-level `apl:` into compiled routes; one `AplRouteHandler` is
/// installed per route per phase via
/// [`PluginManager::annotate_route`][ar].
///
/// [vp]: cpex_core::visitor::ConfigVisitor::visit_plugins
/// [ar]: cpex_core::manager::PluginManager::annotate_route
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use cpex_core::manager::PluginManager;
/// use apl_cpex::{register_apl, AplOptions};
///
/// let mgr = Arc::new(PluginManager::default());
/// mgr.register_factory("scope-gate", Box::new(ScopeGateFactory));
///
/// apl_cpex::register_apl(&mgr, AplOptions {
///     dispatch_cache: dispatch_cache.clone(),
///     session_store: session_store.clone(),
///     pdps: vec![cedar, opa],   // wrapped in PdpRouter internally
/// });
///
/// mgr.load_config_yaml(&yaml_string)?;
/// mgr.initialize().await?;
/// ```
pub fn register_apl(
    mgr: &Arc<PluginManager>,
    opts: AplOptions,
) -> Arc<AplConfigVisitor> {
    let AplOptions {
        dispatch_cache,
        session_store,
        pdps,
        base_capabilities,
    } = opts;

    let mut visitor = AplConfigVisitor::new(
        dispatch_cache,
        session_store,
        Arc::downgrade(mgr),
    );

    // Compose 0 / 1 / N PDP resolvers under a single `Arc<dyn PdpResolver>`.
    // The router itself is a `PdpResolver` whose `evaluate` dispatches by
    // dialect, so any number of resolvers folds into the same shape.
    if !pdps.is_empty() {
        let mut router = PdpRouter::new();
        for pdp in pdps {
            router.register(pdp);
        }
        visitor = visitor.with_pdp(Arc::new(router));
    }

    if let Some(caps) = base_capabilities {
        visitor = visitor.with_base_capabilities(caps);
    }

    let arc = Arc::new(visitor);
    mgr.register_visitor(Arc::clone(&arc) as Arc<dyn ConfigVisitor>);
    arc
}
