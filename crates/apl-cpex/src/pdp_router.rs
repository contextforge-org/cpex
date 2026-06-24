// Location: ./crates/apl-cpex/src/pdp_router.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `PdpRouter` — composite `PdpResolver` that dispatches each call to the
// resolver matching the requested `PdpDialect`. Lets a single host (or a
// single `AplRouteHandler`) carry resolvers for several backends at the
// same time without having to pick one at construction.
//
// The PDP backends that ship in this workspace, each its own crate
// registered here by dialect:
//
//   - **cedar** (`cpex-pdp-cedar-direct`) — in-process Cedar policy-set
//     evaluation.
//   - **opa** — Open Policy Agent / Rego.
//   - **authzen** — AuthZen-protocol external decision point.
//   - **nemo** — NeMo reasoning backend.
//   - **cel** (`cpex-pdp-cel`) — inline CEL boolean predicates authored in
//     the route YAML (`cel: { expr: "..." }`); smallest dep tree, no
//     external policy store.
//
// Routing is by dialect equality. The first registered resolver for a
// given dialect wins on duplicate registration — registering Cedar twice
// keeps the original and logs a warning. Unknown-dialect calls return
// `PdpError::NoResolver(dialect)`.
//
// `PdpRouter` is itself a `PdpResolver`, so it slots straight into
// `AplRouteHandler::with_pdp`. Its own `dialect()` method returns
// `PdpDialect::Custom("router")` — a sentinel the evaluator doesn't
// branch on; only inner resolvers' dialects matter.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use apl_core::attributes::AttributeBag;
use apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};

/// Dispatches PDP calls to the right resolver based on
/// `Step::Pdp.call.dialect`. Construct with `new()`, add resolvers via
/// `register`, then hand the router to a route handler.
///
/// Cloning is cheap (refcount bumps on each resolver `Arc`) — the
/// `AplConfigVisitor` snapshots its accumulated router into an `Arc`
/// for every installed route handler so a config reload that mutates
/// the visitor state doesn't tear in-flight handlers.
#[derive(Clone)]
pub struct PdpRouter {
    resolvers: HashMap<PdpDialect, Arc<dyn PdpResolver>>,
}

impl PdpRouter {
    pub fn new() -> Self {
        Self {
            resolvers: HashMap::new(),
        }
    }

    /// Register a resolver for its declared dialect. If a resolver is
    /// already registered for that dialect the new one is dropped and a
    /// warning is logged — explicit replacement should go through
    /// `replace` instead so the intent is visible at call sites.
    pub fn register(&mut self, resolver: Arc<dyn PdpResolver>) -> &mut Self {
        let dialect = resolver.dialect();
        if self.resolvers.contains_key(&dialect) {
            tracing::warn!(
                dialect = ?dialect,
                "PdpRouter: resolver for dialect already registered — keeping existing",
            );
            return self;
        }
        self.resolvers.insert(dialect, resolver);
        self
    }

    /// Replace any existing resolver for the new resolver's dialect.
    /// Use this when the host genuinely wants to swap in a different
    /// implementation (testing, A/B rollout).
    pub fn replace(&mut self, resolver: Arc<dyn PdpResolver>) -> &mut Self {
        let dialect = resolver.dialect();
        self.resolvers.insert(dialect, resolver);
        self
    }

    /// Number of registered resolvers. Useful for tests.
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

impl Default for PdpRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PdpResolver for PdpRouter {
    fn dialect(&self) -> PdpDialect {
        // Sentinel — evaluator routes per `Step::Pdp.call.dialect`, not
        // the resolver's own declared dialect. The router never claims to
        // be one of the real dialects so a stray equality check can't
        // accidentally pick it.
        PdpDialect::Custom("router".to_string())
    }

    async fn evaluate(&self, call: &PdpCall, bag: &AttributeBag) -> Result<PdpDecision, PdpError> {
        let resolver = self
            .resolvers
            .get(&call.dialect)
            .ok_or_else(|| PdpError::NoResolver(call.dialect.clone()))?;
        resolver.evaluate(call, bag).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apl_core::evaluator::Decision;

    struct FakePdp {
        dialect: PdpDialect,
        decision: Decision,
    }

    #[async_trait]
    impl PdpResolver for FakePdp {
        fn dialect(&self) -> PdpDialect {
            self.dialect.clone()
        }

        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            Ok(PdpDecision {
                decision: self.decision.clone(),
                diagnostics: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn routes_by_dialect() {
        let mut router = PdpRouter::new();
        router.register(Arc::new(FakePdp {
            dialect: PdpDialect::Cedar,
            decision: Decision::Allow,
        }));
        router.register(Arc::new(FakePdp {
            dialect: PdpDialect::Opa,
            decision: Decision::Deny {
                reason: Some("opa says no".into()),
                rule_source: "opa".into(),
            },
        }));

        let bag = AttributeBag::default();
        let cedar_call = PdpCall {
            dialect: PdpDialect::Cedar,
            args: serde_yaml::Value::Null,
        };
        let opa_call = PdpCall {
            dialect: PdpDialect::Opa,
            args: serde_yaml::Value::Null,
        };

        let cedar_res = router.evaluate(&cedar_call, &bag).await.unwrap();
        assert!(matches!(cedar_res.decision, Decision::Allow));

        let opa_res = router.evaluate(&opa_call, &bag).await.unwrap();
        assert!(matches!(opa_res.decision, Decision::Deny { .. }));
    }

    #[tokio::test]
    async fn missing_dialect_returns_no_resolver() {
        let router = PdpRouter::new();
        let bag = AttributeBag::default();
        let call = PdpCall {
            dialect: PdpDialect::Cedar,
            args: serde_yaml::Value::Null,
        };
        let err = router.evaluate(&call, &bag).await.unwrap_err();
        assert!(matches!(err, PdpError::NoResolver(_)));
    }

    #[tokio::test]
    async fn duplicate_register_keeps_first() {
        let mut router = PdpRouter::new();
        router.register(Arc::new(FakePdp {
            dialect: PdpDialect::Cedar,
            decision: Decision::Allow,
        }));
        router.register(Arc::new(FakePdp {
            dialect: PdpDialect::Cedar,
            decision: Decision::Deny {
                reason: Some("shouldn't fire".into()),
                rule_source: "test".into(),
            },
        }));
        let call = PdpCall {
            dialect: PdpDialect::Cedar,
            args: serde_yaml::Value::Null,
        };
        let res = router
            .evaluate(&call, &AttributeBag::default())
            .await
            .unwrap();
        assert!(matches!(res.decision, Decision::Allow));
    }
}
