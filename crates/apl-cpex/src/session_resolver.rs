// Location: ./crates/apl-cpex/src/session_resolver.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// 3-tier session-id resolver. The Python apl-plugins `SessionResolver`
// (cpex/framework/session.py) shipped a 4-tier version including a
// client-supplied `X-CPEX-Session-Id` header tier. **That tier is
// excluded by design here**: an authenticated client can set the
// header to another subject's known session id and inherit their
// accumulated taint labels, or to a new value and escape their own
// tainted session — defeating `session.labels`-based deny policies
// entirely. The Python comment framed the header as a feature ("lets
// a smart client maintain its own session boundary"); under threat
// modeling it is a privilege-escalation channel with no surviving
// use case the other tiers don't cover. If a future deployment needs
// client-supplied session grouping, the right shape is a subject-
// bound hash (`sha256(subject_id : client_value)`), not the raw
// header value.
//
// The resolver walks these tiers in order, returning the first hit:
//
//   0. `agent`      — `AgentExtension.session_id`. A *pre-resolved*
//      value: an upstream plugin or middleware decided what the
//      session is and wrote it here. Highest priority because it
//      represents authority, not derivation — overriding this with a
//      derived value would discard that upstream decision. Plugins
//      that need bespoke session resolution (e.g., reading from a
//      separate session-management service) write here and let the
//      resolver pick it up.
//
//   1. `token_claim` — explicit `session_id` claim in the inbound JWT.
//      Strongest binding among the *derived* tiers: the auth issuer
//      chose this session and signed it into the token. Read from
//      `SecurityExtension.subject.claims["session_id"]`.
//
//   2. `identity`   — derived: sha256(sub : caller_workload : this_workload)[:16].
//      No special infrastructure needed; the triple is already populated
//      by `apl-identity-jwt`'s claim mapping. Same user + same agent +
//      same gateway = same session, stable across token refresh (the
//      claims are stable even when the token string isn't).
//
//   3. `none`       — no usable identifier; caller (CmfPluginInvoker)
//      skips hydration / persistence. Returns `Ok(None)` so the caller
//      can distinguish "no session" from "resolver error" if we ever
//      add an error variant.
//
// Each tier reads from a typed `Extensions` field, not raw JWT/HTTP
// payloads — those have already been mapped by upstream identity
// plugins (apl-identity-jwt). The resolver stays free of crypto /
// parsing logic.

use cpex_core::extensions::Extensions;
use sha2::{Digest, Sha256};

/// Which tier produced the session id. Useful for diagnostics / audit
/// and to let downstream code branch on binding strength (e.g., only
/// trust `token_claim`-derived sessions for the highest-stakes
/// operations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSource {
    /// Pre-resolved by an upstream plugin via `AgentExtension.session_id`.
    /// Highest priority — represents an authoritative decision.
    Agent,
    /// JWT `session_id` claim — strongest binding among derived tiers.
    TokenClaim,
    /// Derived from the identity triple. Stable across token refresh.
    Identity,
}

impl SessionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionSource::Agent => "agent",
            SessionSource::TokenClaim => "token_claim",
            SessionSource::Identity => "identity",
        }
    }
}

/// Resolve a session id from the request's `Extensions`. Returns
/// `Some((id, source))` on the first tier that hits, or `None` when
/// every tier comes up empty (anonymous request, no claims, no
/// header, no identity).
///
/// Identity-tier (2) requires at minimum `security.subject.id` to be
/// populated — without an end-user identifier there's no meaningful
/// session boundary to hash against. The other two identity-triple
/// components (caller_workload, this_workload) fall back to the
/// `"-"` sentinel when absent, which keeps the hash defined but
/// degrades to a (sub, *, *) session — usually fine for demos with
/// a single gateway and single agent.
pub fn resolve_session(ext: &Extensions) -> Option<(String, SessionSource)> {
    // Tier 0: pre-resolved by an upstream plugin. Authoritative —
    // wins over every derived tier so plugin-supplied custom session
    // resolution isn't silently overridden by a derived hash.
    if let Some(agent) = ext.agent.as_deref() {
        if let Some(sid) = agent.session_id.as_deref() {
            if !sid.is_empty() {
                return Some((sid.to_string(), SessionSource::Agent));
            }
        }
    }

    // Tier 1: explicit JWT claim.
    if let Some(sec) = ext.security.as_deref() {
        if let Some(subj) = sec.subject.as_ref() {
            if let Some(sid) = subj.claims.get("session_id") {
                if !sid.is_empty() {
                    return Some((sid.clone(), SessionSource::TokenClaim));
                }
            }
        }
    }

    // Tier 2: identity-derived. Hash the triple
    // (end-user : calling agent : our gateway) — stable across token
    // refresh because all three components survive token rotation.
    if let Some(sec) = ext.security.as_deref() {
        let sub = sec.subject.as_ref().and_then(|s| s.id.as_deref());
        if let Some(sub) = sub {
            // Fall back to `-` so a missing component degrades the
            // session to (sub, *, *) rather than the resolver silently
            // returning None. Important for demos where the gateway
            // hasn't yet attested its own `this_workload` identity.
            let actor = sec
                .caller_workload
                .as_ref()
                .and_then(|w| w.client_id.as_deref())
                .unwrap_or("-");
            let aud = sec
                .this_workload
                .as_ref()
                .and_then(|w| w.client_id.as_deref())
                .unwrap_or("-");
            let raw = format!("{}:{}:{}", sub, actor, aud);
            let mut hasher = Sha256::new();
            hasher.update(raw.as_bytes());
            // 16 hex chars = 64 bits — plenty for the workload sizes
            // CPEX targets, matches the Python implementation's
            // `hexdigest()[:16]`.
            let digest = hasher.finalize();
            let hex: String = digest
                .iter()
                .take(8)
                .map(|b| format!("{:02x}", b))
                .collect();
            return Some((hex, SessionSource::Identity));
        }
    }

    // Tier 3: no session.
    None
}

// =====================================================================
// Tests — one scenario per tier, plus tier-priority assertions.
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::extensions::{
        AgentExtension, Extensions, HttpExtension, SecurityExtension, SubjectExtension,
        WorkloadIdentity,
    };
    use std::sync::Arc;

    fn extensions_with_security(sec: SecurityExtension) -> Extensions {
        Extensions {
            security: Some(Arc::new(sec)),
            ..Default::default()
        }
    }

    fn subject_with_claims(id: Option<&str>, claims: &[(&str, &str)]) -> SubjectExtension {
        SubjectExtension {
            id: id.map(String::from),
            claims: claims
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    // --- Tier 0: agent (pre-resolved) ---

    #[test]
    fn tier0_agent_session_id_hits_first() {
        let mut agent = AgentExtension::default();
        agent.session_id = Some("sess-upstream".into());
        let ext = Extensions {
            agent: Some(Arc::new(agent)),
            ..Default::default()
        };

        let (sid, src) = resolve_session(&ext).expect("should resolve");
        assert_eq!(sid, "sess-upstream");
        assert_eq!(src, SessionSource::Agent);
    }

    #[test]
    fn tier0_skips_empty_agent_session_id() {
        // Empty agent.session_id should fall through, otherwise an
        // upstream that accidentally cleared the slot aliases every
        // such request to "".
        let mut agent = AgentExtension::default();
        agent.session_id = Some("".into());
        let ext = Extensions {
            agent: Some(Arc::new(agent)),
            ..Default::default()
        };
        assert!(resolve_session(&ext).is_none());
    }

    #[test]
    fn tier0_wins_over_token_claim() {
        // Pre-resolved value beats a JWT claim — upstream authority.
        let mut agent = AgentExtension::default();
        agent.session_id = Some("from-agent".into());
        let sec = SecurityExtension {
            subject: Some(subject_with_claims(
                Some("alice"),
                &[("session_id", "from-token")],
            )),
            ..Default::default()
        };
        let ext = Extensions {
            agent: Some(Arc::new(agent)),
            security: Some(Arc::new(sec)),
            ..Default::default()
        };

        let (sid, src) = resolve_session(&ext).unwrap();
        assert_eq!(sid, "from-agent");
        assert_eq!(src, SessionSource::Agent);
    }

    // --- Tier 1: token_claim ---

    #[test]
    fn tier1_token_claim_hits_when_session_id_claim_present() {
        let sec = SecurityExtension {
            subject: Some(subject_with_claims(
                Some("alice@corp.com"),
                &[("session_id", "sess-from-token-789")],
            )),
            ..Default::default()
        };
        let ext = extensions_with_security(sec);

        let (sid, src) = resolve_session(&ext).expect("should resolve");
        assert_eq!(sid, "sess-from-token-789");
        assert_eq!(src, SessionSource::TokenClaim);
    }

    #[test]
    fn tier1_skips_empty_session_id_claim() {
        // Empty claim values should NOT win tier 1 — they degrade to
        // identity-derived. Otherwise an issuer accidentally putting
        // an empty string in the claim would yield "" as the session
        // key, which would alias every such request.
        let sec = SecurityExtension {
            subject: Some(subject_with_claims(
                Some("alice"),
                &[("session_id", "")],
            )),
            ..Default::default()
        };
        let ext = extensions_with_security(sec);

        let (_, src) = resolve_session(&ext).expect("should fall through to identity");
        assert_eq!(src, SessionSource::Identity);
    }

    // --- Tier 2 (`X-CPEX-Session-Id` header) is intentionally absent ---
    //
    // The Python `SessionResolver` included a header tier; cpex Rust
    // does not. See the module-level doc comment for the threat model.
    // A spoofing-regression guard lives below in
    // `header_x_cpex_session_id_is_ignored`.

    // --- Tier 2: identity ---

    #[test]
    fn tier2_identity_derived_when_no_claim() {
        let sec = SecurityExtension {
            subject: Some(subject_with_claims(Some("alice@corp.com"), &[])),
            caller_workload: Some(WorkloadIdentity {
                client_id: Some("agent-007".into()),
                ..Default::default()
            }),
            this_workload: Some(WorkloadIdentity {
                client_id: Some("praxis-gateway".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ext = extensions_with_security(sec);

        let (sid, src) = resolve_session(&ext).expect("should resolve");
        assert_eq!(src, SessionSource::Identity);
        // 16 hex chars (matches Python `sha256(...)[:16]`).
        assert_eq!(sid.len(), 16);
        assert!(sid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tier2_identity_is_stable_across_calls() {
        // Same triple → same session id. Property guarantees that
        // a token refresh (which doesn't change sub/caller/this) keeps
        // the session intact.
        let mk = || -> SecurityExtension {
            SecurityExtension {
                subject: Some(subject_with_claims(Some("alice@corp.com"), &[])),
                caller_workload: Some(WorkloadIdentity {
                    client_id: Some("agent-007".into()),
                    ..Default::default()
                }),
                this_workload: Some(WorkloadIdentity {
                    client_id: Some("praxis-gateway".into()),
                    ..Default::default()
                }),
                ..Default::default()
            }
        };
        let ext1 = extensions_with_security(mk());
        let ext2 = extensions_with_security(mk());
        let (sid1, _) = resolve_session(&ext1).unwrap();
        let (sid2, _) = resolve_session(&ext2).unwrap();
        assert_eq!(sid1, sid2);
    }

    #[test]
    fn tier2_distinguishes_different_users() {
        let alice = SecurityExtension {
            subject: Some(subject_with_claims(Some("alice"), &[])),
            ..Default::default()
        };
        let bob = SecurityExtension {
            subject: Some(subject_with_claims(Some("bob"), &[])),
            ..Default::default()
        };
        let (sid_a, _) = resolve_session(&extensions_with_security(alice)).unwrap();
        let (sid_b, _) = resolve_session(&extensions_with_security(bob)).unwrap();
        assert_ne!(sid_a, sid_b);
    }

    #[test]
    fn tier2_distinguishes_different_agents() {
        // Same user, two different agents → different sessions.
        // Important so a malicious agent's accumulated taints don't
        // affect a different agent that user runs.
        let mk = |agent: &str| -> SecurityExtension {
            SecurityExtension {
                subject: Some(subject_with_claims(Some("alice"), &[])),
                caller_workload: Some(WorkloadIdentity {
                    client_id: Some(agent.into()),
                    ..Default::default()
                }),
                ..Default::default()
            }
        };
        let (sid1, _) = resolve_session(&extensions_with_security(mk("agent-a"))).unwrap();
        let (sid2, _) = resolve_session(&extensions_with_security(mk("agent-b"))).unwrap();
        assert_ne!(sid1, sid2);
    }

    // --- Tier 3: none ---

    #[test]
    fn tier3_no_session_when_no_data() {
        let ext = Extensions::default();
        assert!(resolve_session(&ext).is_none());
    }

    #[test]
    fn tier3_no_session_when_no_subject_id() {
        // Security exists but no subject id → identity can't hash.
        // Claim is absent too. Should be None.
        let sec = SecurityExtension {
            subject: Some(SubjectExtension::default()), // id = None
            ..Default::default()
        };
        let ext = extensions_with_security(sec);
        assert!(resolve_session(&ext).is_none());
    }

    // --- Spoofing guard (regression test for P0-2) ---

    #[test]
    fn header_x_cpex_session_id_is_ignored() {
        // The Python apl-plugins resolver honored an `X-CPEX-Session-Id`
        // header tier between token_claim and identity. We deliberately
        // dropped it: an authenticated client could set the header to
        // another subject's session id and inherit their accumulated
        // taints, or to a random unused value and escape their own
        // tainted session. This test pins that behaviour: the header is
        // present, no token claim exists, and the resolver still falls
        // through to identity-derived (or none) rather than honoring
        // the header. If a future PR adds a header tier without
        // subject binding, this test fails.
        let sec = SecurityExtension {
            subject: Some(subject_with_claims(Some("alice"), &[])),
            caller_workload: Some(WorkloadIdentity {
                client_id: Some("agent-007".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut http = HttpExtension::default();
        http.request_headers
            .insert("X-CPEX-Session-Id".into(), "sess-bob-stolen".into());
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            http: Some(Arc::new(http)),
            ..Default::default()
        };

        let (sid, src) = resolve_session(&ext).expect("identity should still hit");
        assert_eq!(
            src,
            SessionSource::Identity,
            "header tier was removed; resolver must NOT honor X-CPEX-Session-Id",
        );
        assert_ne!(
            sid, "sess-bob-stolen",
            "header value must never become the session id",
        );
    }
}
