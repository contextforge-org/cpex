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
        // `subject: this_workload` means *we* are the principal.
        //
        // this_workload is the one subject with no inbound credential to
        // read — this instance proves who it is with its own
        // credentials, not with anything the caller sent. So
        // `inbound_role()` returns None and the bearer token stays
        // empty *by design*; the handler must not treat that as the
        // "missing credential" error it is for every other subject.
        let subject = subject_from_cfg(cfg)?;
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

        // Optional RFC 8693 actor. When the step opts in with e.g.
        // `actor: client`, attach that inbound credential as the
        // actor_token so the minted token records `act` = actor alongside
        // `sub` = subject. This is the on-behalf-of shape: `subject: user`
        // (or `client`) with the acting party recorded as `act`. An absent
        // credential leaves the exchange single-token. Parse + validate it
        // before `subject` is consumed by the payload below.
        let actor_role = role_from_cfg(cfg, "actor")?;
        reject_unsupported_actor_combo(&subject, actor_role.as_ref())?;

        // Carry the subject onto the payload. The delegator sees only
        // opaque token bytes, so this is the only way it can tell an
        // agent-acting-autonomously exchange from an on-behalf-of-user
        // one — and that decides how the minted token gets attributed.
        let mut payload = DelegationPayload::new(bearer_token, target_name).with_subject(subject);

        if let Some(actor_role) = actor_role {
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
/// [`DelegationSubject`], which additionally admits `this_workload`.
///
/// `"workload"` is accepted as a legacy spelling of `caller_workload`.
/// Parse the `subject:` step key into a [`DelegationSubject`], on the
/// production path (`DelegationSubject::from_config_str`). Distinguishes:
/// - **absent** → the documented default (`user`);
/// - **present but not a string / unrecognized** → `Err` — a typo'd
///   subject must fail rather than silently exchange a different
///   credential shape.
fn subject_from_cfg(
    cfg: Option<&serde_yaml::Mapping>,
) -> Result<DelegationSubject, DelegationError> {
    let Some(v) = cfg.and_then(|m| m.get(serde_yaml::Value::String("subject".into()))) else {
        return Ok(DelegationSubject::default());
    };
    let s = v
        .as_str()
        .ok_or_else(|| DelegationError::InvalidConfig("`subject:` must be a string".into()))?;
    DelegationSubject::from_config_str(s).ok_or_else(|| {
        DelegationError::InvalidConfig(format!(
            "unknown `subject: {s}` (expected user | client | caller_workload | this_workload)"
        ))
    })
}

/// Parse an actor-style role key (`actor:`) into a [`TokenRole`].
/// - `Ok(None)` — key absent (documented default: no actor);
/// - `Ok(Some(role))` — present and recognized;
/// - `Err(..)` — present but invalid, which must fail rather than
///   silently drop the actor.
fn role_from_cfg(
    cfg: Option<&serde_yaml::Mapping>,
    key: &str,
) -> Result<Option<TokenRole>, DelegationError> {
    let Some(v) = cfg.and_then(|m| m.get(serde_yaml::Value::String(key.into()))) else {
        return Ok(None);
    };
    let s = v
        .as_str()
        .ok_or_else(|| DelegationError::InvalidConfig(format!("`{key}:` must be a string")))?;
    match s {
        "user" => Ok(Some(TokenRole::User)),
        "client" => Ok(Some(TokenRole::Client)),
        "caller_workload" | "workload" => Ok(Some(TokenRole::CallerWorkload)),
        other => Err(DelegationError::InvalidConfig(format!(
            "unknown `{key}: {other}` (expected user | client | caller_workload)"
        ))),
    }
}

/// Reject `actor:` combined with a subject the OAuth delegator can't attach
/// an actor to: `caller_workload` is itself the subject (via the leg-1 base
/// token — no separate actor slot), and `this_workload` uses a
/// `client_credentials` grant, where `actor_token` has no meaning (RFC 6749
/// §4.4). The delegator omits the actor in both cases, so accepting the key
/// would silently mislead — fail instead.
fn reject_unsupported_actor_combo(
    subject: &DelegationSubject,
    actor: Option<&TokenRole>,
) -> Result<(), DelegationError> {
    if actor.is_some()
        && matches!(
            subject,
            DelegationSubject::CallerWorkload | DelegationSubject::ThisWorkload
        )
    {
        return Err(DelegationError::InvalidConfig(
            "`actor:` is not supported with `subject: caller_workload` or \
             `subject: this_workload` — the actor would be silently ignored"
                .into(),
        ));
    }
    Ok(())
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

    // --- subject selection (production path: subject_from_cfg -> DelegationSubject) ---

    #[test]
    fn subject_variants_parse() {
        let s = |y| subject_from_cfg(Some(&cfg(y))).unwrap();
        assert_eq!(s("subject: user"), DelegationSubject::User);
        assert_eq!(s("subject: client"), DelegationSubject::Client);
        assert_eq!(
            s("subject: caller_workload"),
            DelegationSubject::CallerWorkload
        );
        assert_eq!(s("subject: workload"), DelegationSubject::CallerWorkload); // legacy alias
        assert_eq!(s("subject: this_workload"), DelegationSubject::ThisWorkload);
    }

    #[test]
    fn subject_absent_defaults_to_user() {
        // An absent `subject:` is the documented default (on-behalf-of user).
        assert_eq!(
            subject_from_cfg(Some(&cfg("target: hr-service"))).unwrap(),
            DelegationSubject::User
        );
        assert_eq!(subject_from_cfg(None).unwrap(), DelegationSubject::User);
    }

    #[test]
    fn subject_typo_is_rejected_not_defaulted_to_user() {
        // A present-but-invalid subject must FAIL, not silently become user
        // (which would exchange a different credential than the author asked).
        let err = subject_from_cfg(Some(&cfg("subject: workloadd"))).unwrap_err();
        assert!(matches!(err, DelegationError::InvalidConfig(_)), "{err:?}");
    }

    #[test]
    fn subject_non_string_is_rejected() {
        let err = subject_from_cfg(Some(&cfg("subject: [a, b]"))).unwrap_err();
        assert!(matches!(err, DelegationError::InvalidConfig(_)), "{err:?}");
    }

    // --- actor selection (production path: role_from_cfg -> Result<Option<TokenRole>>) ---

    #[test]
    fn actor_variants_parse() {
        let a = |y| role_from_cfg(Some(&cfg(y)), "actor").unwrap();
        assert_eq!(a("actor: user"), Some(TokenRole::User));
        assert_eq!(a("actor: client"), Some(TokenRole::Client));
        assert_eq!(a("actor: workload"), Some(TokenRole::CallerWorkload));
    }

    #[test]
    fn actor_absent_is_ok_none() {
        // Absent actor → single-token exchange (no error).
        assert_eq!(
            role_from_cfg(Some(&cfg("subject: user")), "actor").unwrap(),
            None
        );
        assert_eq!(role_from_cfg(None, "actor").unwrap(), None);
    }

    #[test]
    fn actor_typo_is_rejected_not_silently_dropped() {
        // A present-but-invalid actor must FAIL, not silently drop the actor.
        let err = role_from_cfg(Some(&cfg("actor: workloadd")), "actor").unwrap_err();
        assert!(matches!(err, DelegationError::InvalidConfig(_)), "{err:?}");
    }

    // --- both keys coexist (user subject + workload actor) ---

    #[test]
    fn subject_and_actor_resolve_independently() {
        let m = cfg("subject: user\nactor: workload");
        assert_eq!(subject_from_cfg(Some(&m)).unwrap(), DelegationSubject::User);
        assert_eq!(
            role_from_cfg(Some(&m), "actor").unwrap(),
            Some(TokenRole::CallerWorkload)
        );
    }

    // --- actor is rejected with subjects that have no actor slot ---

    #[test]
    fn actor_with_user_or_client_subject_is_allowed() {
        for s in [DelegationSubject::User, DelegationSubject::Client] {
            assert!(reject_unsupported_actor_combo(&s, Some(&TokenRole::Client)).is_ok());
        }
        // No actor at all is always fine.
        assert!(reject_unsupported_actor_combo(&DelegationSubject::CallerWorkload, None).is_ok());
    }

    #[test]
    fn actor_with_workload_or_this_workload_subject_is_rejected() {
        // These subjects have no actor slot — the delegator would silently
        // drop the actor, so the combo must fail rather than mislead.
        for s in [
            DelegationSubject::CallerWorkload,
            DelegationSubject::ThisWorkload,
        ] {
            let err =
                reject_unsupported_actor_combo(&s, Some(&TokenRole::CallerWorkload)).unwrap_err();
            assert!(matches!(err, DelegationError::InvalidConfig(_)), "{err:?}");
        }
    }
}
