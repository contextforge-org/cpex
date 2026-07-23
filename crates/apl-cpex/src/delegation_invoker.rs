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
    DelegationPayload, DelegationSubject, TokenDelegateHook,
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

        // Read step args first — the subject / actor role selection below
        // reads from them. Step `config_override` is a yaml map per the IR;
        // extract a few well-known keys onto the typed DelegationPayload
        // builders. Unknown keys still flow through to the plugin via the
        // per-call config-override pathway (plugins consume them from their
        // `cfg.config`). Recognized keys: `target` (required), `subject`,
        // `actor`, `audience`, `permissions`, `target_type`,
        // `auth_enforced_by`; everything else stays opaque.
        //
        // There is deliberately no `mode` key: the delegation mode is
        // *derived* from `subject` by the handler rather than declared, so a
        // route can't claim on-behalf-of-user while handing over a workload
        // SVID.
        let cfg = step.config_override.as_ref().and_then(|v| v.as_mapping());

        // Resolve who the exchange is *for*. Defaults to the user
        // (on-behalf-of); `subject: caller_workload` selects the
        // caller's SVID for the no-user, agent-acting-autonomously
        // exchange, `subject: client` the OAuth client token, and
        // `subject: gateway` means *we* are the principal.
        //
        // Gateway is the one subject with no inbound credential to
        // read — the gateway proves who it is with its own
        // credentials, not with anything the caller sent. So
        // `inbound_role()` returns None and the bearer token stays
        // empty *by design*; the handler must not treat that as the
        // "missing credential" error it is for every other subject.
        let subject = cfg
            .and_then(|m| m.get(serde_yaml::Value::String("subject".into())))
            .and_then(|v| v.as_str())
            .and_then(DelegationSubject::from_config_str)
            .unwrap_or_default();
        let bearer_token = subject
            .inbound_role()
            .and_then(|role| {
                current_extensions
                    .raw_credentials
                    .as_ref()
                    .and_then(|rc| rc.inbound_tokens.get(&role))
                    .map(|tok| (*tok.token).clone())
            })
            .unwrap_or_default();

        let target_name: String = cfg
            .and_then(|m| m.get(serde_yaml::Value::String("target".into())))
            .and_then(|v| v.as_str())
            .unwrap_or(&step.plugin_name)
            .to_string();

        // Carry the subject onto the payload. The delegator sees only
        // opaque token bytes, so this is the only way it can tell an
        // agent-acting-autonomously exchange from an on-behalf-of-user
        // one — and that decides how the minted token gets attributed.
        let mut payload = DelegationPayload::new(bearer_token, target_name).with_subject(subject);

        // Optional RFC 8693 actor. When the step opts in with e.g.
        // `actor: caller_workload`, attach that inbound credential as
        // the actor_token so the minted token records `act` = actor
        // alongside `sub` = subject. Pairs naturally with
        // `subject: gateway`: the gateway is the principal the backend
        // trusts, while `act` records which agent caused the call.
        // An absent credential leaves the exchange single-token.
        if let Some(actor_role) = role_from_cfg(cfg, "actor") {
            let actor_token = current_extensions
                .raw_credentials
                .as_ref()
                .and_then(|rc| rc.inbound_tokens.get(&actor_role))
                .map(|tok| (*tok.token).clone())
                .unwrap_or_default();
            if !actor_token.is_empty() {
                payload = payload.with_actor(actor_role, actor_token);
            }
        }

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

        // Dispatch. The plan's pre-resolved entry already has any
        // per-route config override merged into the plugin's
        // instance config; what we're passing on this call is the
        // typed payload (target / audience / permissions / etc.).
        let (result, _bg) = self
            .manager
            .invoke_entries::<TokenDelegateHook>(
                std::slice::from_ref(&entry),
                payload,
                current_extensions,
                None,
            )
            .await;

        // Translate the result.
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

        // Pull the resolved DelegationPayload and apply to shared
        // extensions so downstream code sees the minted token /
        // updated chain.
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

        // Extract granted_* for the evaluator to surface into the bag.
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

/// Resolve a `TokenRole` from the `actor` step-config key, whose
/// value names an *inbound* credential. Returns `None` when the key
/// is absent or unrecognized, so the actor is simply omitted and the
/// exchange stays single-token — never silently substituted for a
/// typo'd role.
///
/// Unlike `subject`, an actor is always an inbound credential: the
/// actor is by definition a party that presented itself to us. That's
/// why this returns `TokenRole` while the subject resolves to a
/// [`DelegationSubject`], which additionally admits `gateway`.
///
/// `"workload"` is accepted as a legacy spelling of `caller_workload`.
fn role_from_cfg(cfg: Option<&serde_yaml::Mapping>, key: &str) -> Option<TokenRole> {
    match cfg
        .and_then(|m| m.get(serde_yaml::Value::String(key.into())))
        .and_then(|v| v.as_str())
    {
        Some("user") => Some(TokenRole::User),
        Some("client") => Some(TokenRole::Client),
        Some("caller_workload") | Some("workload") => Some(TokenRole::CallerWorkload),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a YAML fragment into the step `config_override` mapping
    /// shape the invoker receives (`step.config_override.as_mapping()`).
    fn cfg(yaml: &str) -> serde_yaml::Mapping {
        serde_yaml::from_str::<serde_yaml::Value>(yaml)
            .expect("valid yaml")
            .as_mapping()
            .expect("yaml is a mapping")
            .clone()
    }

    // --- subject selection (which credential is the exchange subject) ---

    #[test]
    fn subject_workload_selects_svid_role() {
        // Mode A: `subject: workload` routes the caller's SVID in as
        // the subject_token of the exchange.
        let m = cfg("subject: workload");
        assert_eq!(
            role_from_cfg(Some(&m), "subject"),
            Some(TokenRole::CallerWorkload)
        );
    }

    #[test]
    fn subject_user_selects_user_role() {
        let m = cfg("subject: user");
        assert_eq!(role_from_cfg(Some(&m), "subject"), Some(TokenRole::User));
    }

    #[test]
    fn subject_client_selects_client_role() {
        let m = cfg("subject: client");
        assert_eq!(role_from_cfg(Some(&m), "subject"), Some(TokenRole::Client));
    }

    #[test]
    fn subject_absent_returns_none_so_caller_defaults_to_user() {
        // The helper does NOT bake in the User default — the caller
        // (`.unwrap_or(TokenRole::User)`) does. An absent key must
        // return None so on-behalf-of stays the default.
        let m = cfg("target: hr-service");
        assert_eq!(role_from_cfg(Some(&m), "subject"), None);
    }

    #[test]
    fn unknown_role_returns_none_rather_than_guessing() {
        // A typo'd role is not silently mapped to some default role —
        // it returns None so the caller applies its own policy.
        let m = cfg("subject: workloadd");
        assert_eq!(role_from_cfg(Some(&m), "subject"), None);
    }

    // --- actor selection (RFC 8693 actor_token, Mode B) ---

    #[test]
    fn actor_workload_selects_svid_role() {
        // Mode B: `actor: workload` records the SVID as the act party
        // alongside the user subject.
        let m = cfg("actor: workload");
        assert_eq!(
            role_from_cfg(Some(&m), "actor"),
            Some(TokenRole::CallerWorkload)
        );
    }

    #[test]
    fn actor_absent_returns_none_so_exchange_stays_single_token() {
        let m = cfg("subject: user");
        assert_eq!(role_from_cfg(Some(&m), "actor"), None);
    }

    #[test]
    fn missing_mapping_returns_none() {
        assert_eq!(role_from_cfg(None, "subject"), None);
        assert_eq!(role_from_cfg(None, "actor"), None);
    }

    // --- both keys coexist (Mode B: user subject + workload actor) ---

    #[test]
    fn subject_and_actor_resolve_independently() {
        let m = cfg("subject: user\nactor: workload");
        assert_eq!(role_from_cfg(Some(&m), "subject"), Some(TokenRole::User));
        assert_eq!(
            role_from_cfg(Some(&m), "actor"),
            Some(TokenRole::CallerWorkload)
        );
    }
}
