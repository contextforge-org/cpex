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
// # Two ways to supply PDPs
//
// PDP resolvers can reach the visitor's internal `PdpRouter` via two
// channels, and `AplOptions` exposes both:
//
//   * `pdps`           — code-supplied resolvers. The host built them
//                        in Rust (e.g. a hand-rolled audit resolver,
//                        a test fake) and hands them in directly.
//   * `pdp_factories`  — factories the visitor consults when it sees a
//                        `global.apl.pdp[]` entry in the unified
//                        config. Each factory advertises a `kind()`
//                        string that matches the YAML block's `kind:`
//                        field.
//
// Both channels feed the same `PdpRouter` inside the visitor, so a
// host can mix the two freely — code-supplied Cedar for tests plus a
// config-declared OPA in prod, say.

use std::collections::HashSet;
use std::sync::Arc;

use cpex_core::manager::PluginManager;
use cpex_core::visitor::ConfigVisitor;

use apl_core::step::{PdpFactory, PdpResolver};

use crate::dispatch_plan::DispatchCache;
use crate::session_store::{SessionStore, SessionStoreFactory};
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

    /// Zero or more code-supplied PDP resolvers. Each is registered
    /// into the visitor's internal `PdpRouter`, so `pdp(...)` steps
    /// dispatch by dialect across this list **and** any resolvers the
    /// visitor builds from `global.apl.pdp[]` config entries. An empty
    /// list combined with empty `pdp_factories` means no PDP is wired
    /// — routes that call `pdp(...)` surface `PdpError::NoResolver` at
    /// evaluation time, which is the correct behavior for "you forgot
    /// to configure your policy decision point."
    pub pdps: Vec<Arc<dyn PdpResolver>>,

    /// PDP factories the visitor consults when it encounters a
    /// `global.apl.pdp[]` entry. Each factory advertises a `kind()`
    /// string that matches the YAML block's `kind:` field — e.g.
    /// `cedar-direct`, `opa`. An empty list disables
    /// config-driven PDP wiring; hosts can still supply resolvers via
    /// `pdps`.
    pub pdp_factories: Vec<Arc<dyn PdpFactory>>,

    /// Session-store factories the visitor consults when it encounters a
    /// `global.apl.session_store` block. Each factory advertises a
    /// `kind()` string matching the block's `kind:` field — e.g.
    /// `valkey`. An empty list keeps the constructor-supplied
    /// `session_store` (the `MemorySessionStore` default) active, so
    /// existing deployments are unaffected.
    pub session_store_factories: Vec<Arc<dyn SessionStoreFactory>>,

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
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: None,
        }
    }
}

/// Build an [`AplConfigVisitor`] from the supplied options and register
/// it on the manager. Returns the `Arc<AplConfigVisitor>` so the caller
/// can stash it for later inspection (or call `register_pdp` on it
/// after the fact for late-bound resolvers) — but in the typical case
/// the return value is dropped and the visitor lives inside the
/// manager's visitor list.
///
/// After this call, the next `mgr.load_config_yaml(yaml)` invocation
/// will walk the visitor: cpex-core's [`visit_plugins`][vp] populates
/// the APL plugin registry from `&[PluginConfig]`; `visit_global`
/// processes any `global.apl.pdp[]` entries by dispatching to the
/// registered `pdp_factories`; the hierarchy walk stacks `global.apl`
/// / `defaults.<entity>.apl` / `policies.<tag>.apl` / route-level
/// `apl:` into compiled routes; one `AplRouteHandler` is installed
/// per route per phase via [`PluginManager::annotate_route`][ar].
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
/// use cpex_pdp_cedar_direct::CedarDirectPdpFactory;
///
/// let mgr = Arc::new(PluginManager::default());
/// mgr.register_factory("scope-gate", Box::new(ScopeGateFactory));
///
/// apl_cpex::register_apl(&mgr, AplOptions {
///     dispatch_cache: dispatch_cache.clone(),
///     session_store: session_store.clone(),
///     pdps: vec![],                                       // none code-supplied
///     pdp_factories: vec![Arc::new(CedarDirectPdpFactory::new())],
///     base_capabilities: None,
/// });
///
/// mgr.load_config_yaml(&yaml_string)?;
/// mgr.initialize().await?;
/// ```
pub fn register_apl(mgr: &Arc<PluginManager>, opts: AplOptions) -> Arc<AplConfigVisitor> {
    let AplOptions {
        dispatch_cache,
        session_store,
        pdps,
        pdp_factories,
        session_store_factories,
        base_capabilities,
    } = opts;

    // Build the visitor and apply consuming builders first (these take
    // `self` by value), then mutating registrations (`&mut self` for
    // factories), and finally wrap in `Arc` so we can hand the shared
    // handle to the manager. Code-supplied PDPs go through
    // `register_pdp(&self, ...)` which uses interior mutability, so
    // they're registered after the `Arc` wrap.
    let mut visitor = AplConfigVisitor::new(dispatch_cache, session_store, Arc::downgrade(mgr));

    if let Some(caps) = base_capabilities {
        visitor = visitor.with_base_capabilities(caps);
    }

    for factory in pdp_factories {
        visitor.register_pdp_factory(factory);
    }

    for factory in session_store_factories {
        visitor.register_session_store_factory(factory);
    }

    let arc = Arc::new(visitor);

    for pdp in pdps {
        arc.register_pdp(pdp);
    }

    mgr.register_visitor(Arc::clone(&arc) as Arc<dyn ConfigVisitor>);
    arc
}
