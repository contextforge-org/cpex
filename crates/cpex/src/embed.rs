// Location: ./crates/cpex/src/embed.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Host embedding API: a supported entry point a host (e.g. an egress proxy)
// uses to construct the CPEX runtime once and mediate operations against it.
//
// This is deliberately HOOK-AGNOSTIC. CPEX mediates whatever hooks a host
// defines — CMF tool pre/post-invoke, `cmf.http_request`, LLM input/output,
// resource fetch, or a host's own custom hook. So the core surface is
// `invoke(hook_name, payload, extensions) -> Outcome`; the host decides which
// hook and payload shape fit its protocol. (An OpenShell-style egress proxy,
// for instance, maps its operations onto the CMF *tool* hooks so it can run a
// post phase for response redaction and reuse tool-shaped policy — but that
// is the host adapter's choice, not something this API bakes in.)
//
// Compared to the tutorial's `examples/tutorial/src/mediate.rs` harness, this
// API adds two things a real host needs: a construct-once lifecycle with a
// host-owned session store, and honest allow/deny/pending mapping that never
// fabricates a result. In particular `Outcome::Allow` carries the *modified*
// payload or `None` — it never falls back to echoing the input payload as if
// it were transformed (the `…unwrap_or(raw_result)` fail-open in `mediate()`).
// A host that ran a redaction-eligible operation and gets `payload: None`
// therefore fails closed rather than releasing an unredacted body.
//
// Requires the `cpex-builtins` feature: the constructor wires the bundled
// plugin factories (identity/jwt, delegator/oauth, audit, pii, ciba) and PDP
// factories (cedar-direct, cel) so a bundle can reference them by `kind`.

use std::sync::Arc;

use apl_cpex::{register_apl, AplOptions, SessionStore};
use cpex_core::extensions::Extensions;
use cpex_core::hooks::payload::PluginPayload;
use cpex_core::identity::{IdentityHook, IdentityPayload, TokenSource, HOOK_IDENTITY_RESOLVE};
use cpex_core::manager::PluginManager;

use crate::{builtin_pdp_factories, builtin_session_store_factories, register_builtin_plugins};

/// Violation code a suspended (human-in-the-loop) elicitation surfaces under.
const ELICITATION_PENDING_CODE: &str = "elicitation.pending";

/// Construction / initialization failure for [`CpexAuthorizer::from_bundle_yaml`].
#[derive(Debug)]
pub enum EmbedError {
    /// The APL bundle YAML failed to parse or install.
    Config(String),
    /// Runtime initialization failed.
    Init(String),
}

impl std::fmt::Display for EmbedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmbedError::Config(m) => write!(f, "cpex bundle config error: {m}"),
            EmbedError::Init(m) => write!(f, "cpex runtime init error: {m}"),
        }
    }
}

impl std::error::Error for EmbedError {}

/// The result of mediating one hook invocation. Hook-agnostic: `payload` is
/// whatever payload type the invoked hook produces (a `MessagePayload`, an
/// HTTP payload, a custom host payload), downcast by the host.
pub enum Outcome {
    /// The pipeline allowed the operation.
    ///
    /// - `extensions` carries any pipeline modifications (a delegated-token
    ///   intent, appended session labels) the host threads onward.
    /// - `payload` is the pipeline's resulting payload: transformed when a
    ///   rule fired (e.g. redaction), otherwise the input carried through the
    ///   pipeline. It is the pipeline's own output, never a fabricated copy of
    ///   the input substituted by this API. `None` only in the degenerate case
    ///   where the pipeline yielded no payload — a host expecting a transform
    ///   (a redaction-eligible route) should fail closed on `None` rather than
    ///   release an untransformed body.
    Allow {
        extensions: Extensions,
        payload: Option<Box<dyn PluginPayload>>,
    },
    /// The pipeline denied the operation before/at this hook. Non-secret.
    Deny { code: String, reason: String },
    /// The pipeline suspended the operation pending an out-of-band human
    /// approval. Resume by echoing `elicitation_id` on a later invocation
    /// (the host carries it however its protocol allows).
    Pending {
        elicitation_id: String,
        approver: String,
    },
}

impl Outcome {
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Outcome::Allow { .. })
    }
}

// Manual Debug: the `payload` is a `Box<dyn PluginPayload>` (not Debug), so we
// report only whether a transformed payload is present, never its contents.
impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Allow { payload, .. } => f
                .debug_struct("Allow")
                .field("payload_present", &payload.is_some())
                .finish(),
            Outcome::Deny { code, reason } => f
                .debug_struct("Deny")
                .field("code", code)
                .field("reason", reason)
                .finish(),
            Outcome::Pending {
                elicitation_id,
                approver,
            } => f
                .debug_struct("Pending")
                .field("elicitation_id", elicitation_id)
                .field("approver", approver)
                .finish(),
        }
    }
}

/// A supported in-process CPEX embedding. Construct once at policy-load time
/// (never per request), then mediate operations.
pub struct CpexAuthorizer {
    mgr: Arc<PluginManager>,
}

impl CpexAuthorizer {
    /// Build the runtime from an APL bundle, wiring the bundled plugin and
    /// PDP factories and a host-supplied, process-lifetime session store.
    ///
    /// The store is injected (not created internally) so the host controls
    /// its lifetime — taint labels must outlive individual operations.
    pub async fn from_bundle_yaml(
        yaml: &str,
        session_store: Arc<dyn SessionStore>,
    ) -> Result<Self, EmbedError> {
        let mgr = Arc::new(PluginManager::default());

        // Register bundled plugin factories by `kind` (identity/jwt,
        // delegator/oauth, audit, pii, ciba) so the config can name them.
        register_builtin_plugins(&mgr);

        // Install the APL config visitor with in-process defaults, then
        // override the session store with the host's and wire the bundled
        // PDP / session-store factories the config may reference.
        let mut opts = AplOptions::in_process();
        opts.session_store = session_store;
        opts.pdp_factories = builtin_pdp_factories();
        opts.session_store_factories = builtin_session_store_factories();
        register_apl(&mgr, opts);

        // `load_config_yaml` (not `load_config`) runs the config visitors
        // that walk `apl:` blocks and install per-route handlers.
        mgr.load_config_yaml(yaml)
            .map_err(|e| EmbedError::Config(e.to_string()))?;
        mgr.initialize()
            .await
            .map_err(|e| EmbedError::Init(e.to_string()))?;

        Ok(Self { mgr })
    }

    /// Mediate one operation against `hook_name`. This is the core,
    /// hook-agnostic surface: the host builds the payload its hook expects
    /// (a CMF message, an HTTP payload, a custom payload) and gets back an
    /// [`Outcome`]. Background tasks (e.g. session-label persistence for
    /// taint) are awaited before returning, so any state a policy committed
    /// during this hook is durable once the host sees `Allow`.
    ///
    /// Deny-wins: the first denying step in the pipeline halts it.
    pub async fn invoke(
        &self,
        hook_name: &str,
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
    ) -> Outcome {
        let (result, bg) = self
            .mgr
            .invoke_by_name(hook_name, payload, extensions.clone(), None)
            .await;
        bg.wait_for_background_tasks().await;

        if !result.continue_processing {
            if let Some(v) = &result.violation {
                if v.code == ELICITATION_PENDING_CODE {
                    let elicitation_id = v
                        .details
                        .get("elicitation_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let approver = v
                        .details
                        .get("approver")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("the approver")
                        .to_string();
                    return Outcome::Pending {
                        elicitation_id,
                        approver,
                    };
                }
            }
            return deny(&result);
        }

        Outcome::Allow {
            extensions: result.modified_extensions.unwrap_or(extensions),
            payload: result.modified_payload,
        }
    }

    /// Resolve a verified-identity token into a subject and fold it into the
    /// extensions, using the standard `identity.resolve` hook. Returns the
    /// enriched extensions on success, or the denying/pending [`Outcome`] if
    /// identity resolution itself failed (bad signature, wrong issuer, etc.).
    ///
    /// This is a convenience over [`Self::invoke`] for the near-universal
    /// identity step; hosts with a bespoke identity hook can call `invoke`
    /// directly instead.
    pub async fn resolve_identity(
        &self,
        token: &str,
        extensions: Extensions,
    ) -> Result<Extensions, Outcome> {
        let (result, bg) = self
            .mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                IdentityPayload::new(token.to_owned(), TokenSource::Bearer),
                extensions.clone(),
                None,
            )
            .await;
        bg.wait_for_background_tasks().await;

        if !result.continue_processing {
            return Err(deny(&result));
        }
        Ok(match IdentityPayload::from_pipeline_result(&result) {
            Some(identity) => identity.apply_to_extensions(extensions),
            None => extensions,
        })
    }

    /// Escape hatch for advanced hosts: the underlying manager, for
    /// `invoke_named`, custom hook types, or lifecycle control.
    #[must_use]
    pub fn manager(&self) -> &Arc<PluginManager> {
        &self.mgr
    }
}

/// Map a denying pipeline result to [`Outcome::Deny`], with sane fallbacks
/// when a phase halts without a violation.
fn deny(result: &cpex_core::executor::PipelineResult) -> Outcome {
    match &result.violation {
        Some(v) => Outcome::Deny {
            code: v.code.clone(),
            reason: v.reason.clone(),
        },
        None => Outcome::Deny {
            code: "policy.deny".into(),
            reason: "denied without a violation".into(),
        },
    }
}
