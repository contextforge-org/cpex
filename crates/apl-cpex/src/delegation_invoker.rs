// Location: ./crates/apl-cpex/src/delegation_invoker.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `DelegationPluginInvoker` — `apl-core::DelegationInvoker` impl
// bound to the `TokenDelegateHook` family. Drives dispatch off a
// pre-resolved [`RouteDispatchPlan::delegation_entries`] and forwards
// to `PluginManager::invoke_entries::<TokenDelegateHook>(...)`.
//
// # When this runs
//
// The apl-core evaluator calls
// `DelegationInvoker::delegate(&DelegateStep)` once per `Step::Delegate`
// it encounters in a `pre_invocation:` / `post_invocation:` block. The invoker:
//
//   1. Looks up the resolved `token.delegate` entry for the step's
//      plugin name in the dispatch plan.
//   2. Constructs a `cpex_core::delegation::DelegationPayload` from
//      the inbound bearer token (from
//      `Extensions.raw_credentials.inbound_tokens[User]`) plus the
//      step's `config_override` (target / audience / permissions /
//      attenuation — schema is plugin-defined; we map a few
//      well-known keys onto the typed payload builders and stash
//      everything else as metadata for plugin-specific consumption).
//   3. Calls `mgr.invoke_entries::<TokenDelegateHook>(&[entry], ...)`.
//   4. Pulls the resulting `DelegationPayload` from the
//      `PipelineResult`, applies it to the shared `Extensions` (via
//      `apply_to_extensions`), and returns a `DelegationOutcome` with
//      the granted_* fields extracted from the minted token.
//
// # Shared extensions
//
// This invoker shares the same `Arc<Mutex<Extensions>>` as
// `CmfPluginInvoker` for the same request. That means when
// `delegate(...)` writes `raw_credentials.delegated_tokens.*`, the
// next CMF plugin in the chain (or downstream evaluator phases) sees
// it. Get the shared handle via `CmfPluginInvoker::extensions_arc()`.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::SecondsFormat;
use tokio::sync::Mutex;

use cpex_core::delegation::{
    payload::{AuthEnforcedBy, TargetType},
    DelegationPayload, TokenDelegateHook,
};
use cpex_core::extensions::raw_credentials::TokenRole;
use cpex_core::hooks::payload::Extensions;
use cpex_core::manager::PluginManager;

use apl_core::evaluator::Decision;
use apl_core::step::{DelegateStep, DelegationError, DelegationInvoker, DelegationOutcome};

use crate::dispatch_plan::RouteDispatchPlan;

/// Bridges APL `delegate(...)` step dispatch to CPEX
/// `TokenDelegateHook` plugins.
///
/// Carries the request's shared `Extensions` so mutations from a
/// `delegate(...)` step (minted token, updated delegation chain)
/// land in the same `Extensions` the CMF invoker is reading.
pub struct DelegationPluginInvoker {
    manager: Arc<PluginManager>,
    /// Same `Arc<Mutex<Extensions>>` as the CMF invoker for this
    /// request — sharing this handle is what makes minted tokens
    /// visible to downstream CMF plugins.
    extensions: Arc<Mutex<Extensions>>,
    /// Pre-resolved per-route delegation lineup. Built at request
    /// start by the host (or fetched from a shared `DispatchCache`).
    plan: Arc<RouteDispatchPlan>,
}

impl DelegationPluginInvoker {
    /// Construct an invoker bound to the request's shared extensions
    /// and the route's pre-resolved dispatch plan. Take the
    /// extensions Arc from `CmfPluginInvoker::extensions_arc()` so
    /// the two invokers see the same mutable Extensions.
    pub fn new(
        manager: Arc<PluginManager>,
        extensions: Arc<Mutex<Extensions>>,
        plan: Arc<RouteDispatchPlan>,
    ) -> Self {
        Self {
            manager,
            extensions,
            plan,
        }
    }
}

#[async_trait]
impl DelegationInvoker for DelegationPluginInvoker {
    async fn delegate(&self, step: &DelegateStep) -> Result<DelegationOutcome, DelegationError> {
        // Resolve the plugin's token.delegate entry out of
        // `self.plan.delegation_entries`. Routes that don't reference this
        // plugin in `pre_invocation:` / `post_invocation:` at compile time
        // won't have an entry there — surface that as NotFound so the
        // evaluator's on_error semantics kick in.
        let entry = self
            .plan
            .delegation_entries
            .get(&step.plugin_name)
            .ok_or_else(|| DelegationError::NotFound(step.plugin_name.clone()))?
            .clone();

        // Snapshot extensions to construct the payload and pass into
        // invoke_entries. The canonical copy stays under the Mutex; this
        // snapshot is the per-call working copy.
        let current_extensions = self.extensions.lock().await.clone();

        // Pull the inbound bearer token from raw_credentials. Looks for
        // the User-role token; future iterations can surface multi-token
        // selection (Client / Workload) via step config.
        let bearer_token = current_extensions
            .raw_credentials
            .as_ref()
            .and_then(|rc| rc.inbound_tokens.get(&TokenRole::User))
            .map(|tok| (*tok.token).clone())
            .unwrap_or_default();

        // Read step args. Step `config_override` is a yaml map per the IR
        // — extract a few well-known keys onto the typed DelegationPayload
        // builders. Unknown keys still flow through to the plugin via the
        // per-call config-override pathway (plugins consume them from
        // their `cfg.config`). `target` is required (delegation needs to
        // know who the downstream call is for); `audience`, `permissions`,
        // `mode`, `auth_enforced_by` are recognized; everything else stays
        // opaque.
        let cfg = step.config_override.as_ref().and_then(|v| v.as_mapping());

        let target_name: String = cfg
            .and_then(|m| m.get(serde_yaml::Value::String("target".into())))
            .and_then(|v| v.as_str())
            .unwrap_or(&step.plugin_name)
            .to_string();

        let mut payload = DelegationPayload::new(bearer_token, target_name);

        if let Some(audience) = cfg
            .and_then(|m| m.get(serde_yaml::Value::String("audience".into())))
            .and_then(|v| v.as_str())
        {
            payload = payload.with_target_audience(audience);
        }
        if let Some(perms) = cfg
            .and_then(|m| m.get(serde_yaml::Value::String("permissions".into())))
            .and_then(|v| v.as_sequence())
        {
            let list: Vec<String> = perms
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            if !list.is_empty() {
                payload = payload.with_required_permissions(list);
            }
        }
        if let Some(t_kind) = cfg
            .and_then(|m| m.get(serde_yaml::Value::String("target_type".into())))
            .and_then(|v| v.as_str())
        {
            payload = payload.with_target_type(target_type_from_str(t_kind));
        }
        if let Some(enforcer) = cfg
            .and_then(|m| m.get(serde_yaml::Value::String("auth_enforced_by".into())))
            .and_then(|v| v.as_str())
        {
            payload = payload.with_auth_enforced_by(auth_enforced_by_from_str(enforcer));
        }

        // 5. Dispatch. The plan's pre-resolved entry already has any
        //    per-route config override merged into the plugin's
        //    instance config; what we're passing on this call is the
        //    typed payload (target / audience / permissions / etc.).
        let (result, _bg) = self
            .manager
            .invoke_entries::<TokenDelegateHook>(
                std::slice::from_ref(&entry),
                payload,
                current_extensions,
                None,
            )
            .await;

        // 6. Translate the result.
        if !result.continue_processing {
            // Plugin denied (IdP refusal, validation failure, etc.).
            let decision = match result.violation {
                Some(v) => Decision::Deny {
                    reason: Some(v.reason),
                    rule_source: v.code,
                },
                None => Decision::Deny {
                    reason: Some(format!(
                        "delegate `{}` denied without violation detail",
                        step.plugin_name
                    )),
                    rule_source: step.source.clone(),
                },
            };
            return Ok(DelegationOutcome::deny(decision));
        }

        // 7. Pull the resolved DelegationPayload and apply to shared
        //    extensions so downstream code sees the minted token /
        //    updated chain.
        let resolved = DelegationPayload::from_pipeline_result(&result).ok_or_else(|| {
            DelegationError::Dispatch(format!(
                "plugin `{}` returned allow but no DelegationPayload",
                step.plugin_name,
            ))
        })?;

        {
            let mut ext_lock = self.extensions.lock().await;
            let merged = resolved.clone().apply_to_extensions(ext_lock.clone());
            *ext_lock = merged;
        }

        // 8. Extract granted_* for the evaluator to surface into the bag.
        let (granted_permissions, granted_audience, granted_expires_at) =
            match resolved.delegated_token {
                Some(tok) => (
                    tok.scopes,
                    Some(tok.audience),
                    Some(tok.expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
                ),
                None => (Vec::new(), None, None),
            };

        Ok(DelegationOutcome {
            decision: Decision::Allow,
            granted_permissions,
            granted_audience,
            granted_expires_at,
        })
    }
}

fn target_type_from_str(s: &str) -> TargetType {
    match s.to_ascii_lowercase().as_str() {
        "tool" => TargetType::Tool,
        "agent" => TargetType::Agent,
        "resource" => TargetType::Resource,
        "service" => TargetType::Service,
        other => TargetType::Custom(other.to_string()),
    }
}

fn auth_enforced_by_from_str(s: &str) -> AuthEnforcedBy {
    match s.to_ascii_lowercase().as_str() {
        "caller" => AuthEnforcedBy::Caller,
        "target" => AuthEnforcedBy::Target,
        // Unknown values default to Caller — matches DelegationPayload::new's default.
        _ => AuthEnforcedBy::Caller,
    }
}
