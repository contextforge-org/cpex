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
//      session is and wrote it here (for the FFI/AuthBridge path this
//      is the client `X-Session-Id` header / A2A contextId). Highest
//      priority among sources, but **subject-bound** before use
//      (`sha256(subject_id : value)`): the raw value is attacker-chosen,
//      so it must only scope state WITHIN the authenticated subject,
//      never across principals. Falls through when no subject is present.
//
//   1. `token_claim` — explicit `session_id` claim in the inbound JWT.
//      Strongest binding among the *derived* tiers: the auth issuer
//      chose this session and signed it into the token. Read from
//      `SecurityExtension.subject.claims["session_id"]` and **subject-
//      bound** the same way (a signed claim is per-issuer and may repeat
//      across principals, so the key must still include the subject).
//
//   2. `identity`   — derived: sha256(sub : caller_workload : this_workload)[:16].
//      No special infrastructure needed; the triple is already populated
//      by `cpex-plugin-identity-jwt`'s claim mapping. Same user + same agent +
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
// plugins (cpex-plugin-identity-jwt). The resolver stays free of crypto /
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

/// 16 hex chars (64 bits) of `sha256(raw)`. Shared by the identity tier
/// and the subject-binding of the Agent/TokenClaim tiers so all derived
/// session ids have one keying scheme. Matches the Python implementation's
/// `hexdigest()[:16]`.
fn short_hash(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Bind a client/upstream-supplied raw session value to the authenticated
/// subject: `sha256(subject_id : raw)`. This is the subject-bound shape the
/// module doc prescribes for the (previously raw) Agent and TokenClaim tiers,
/// so a session id chosen by one principal cannot address another principal's
/// session bucket. Returns `None` when there is no authenticated subject — a
/// bare client value has no safe scope, consistent with Tiers 2/3, which also
/// require a subject.
fn subject_scoped(subject_id: Option<&str>, raw: &str) -> Option<String> {
    let sub = subject_id?;
    Some(short_hash(&format!("{}:{}", sub, raw)))
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
    // The authenticated subject, populated by the identity resolvers
    // (cpex-plugin-identity-jwt) before this runs. Every client/upstream-supplied
    // session value below is bound to it so one principal can't address
    // another's session bucket.
    let subject_id = ext
        .security
        .as_deref()
        .and_then(|s| s.subject.as_ref())
        .and_then(|s| s.id.as_deref());

    // Tier 0: pre-resolved by an upstream plugin (for the FFI/AuthBridge
    // path this is `X-Session-Id` / the A2A contextId). Authoritative among
    // sources, but subject-bound here rather than trusted raw: the raw value
    // is attacker-chosen, so it only ever scopes state WITHIN the
    // authenticated subject. Falls through when no subject is present.
    if let Some(agent) = ext.agent.as_deref() {
        if let Some(sid) = agent.session_id.as_deref() {
            if !sid.is_empty() {
                if let Some(bound) = subject_scoped(subject_id, sid) {
                    return Some((bound, SessionSource::Agent));
                }
            }
        }
    }

    // Tier 1: explicit JWT `session_id` claim — also subject-bound. Even a
    // signed claim is per-issuer and could repeat across principals, so the
    // store key must still incorporate the subject.
    if let Some(sec) = ext.security.as_deref() {
        if let Some(subj) = sec.subject.as_ref() {
            if let Some(sid) = subj.claims.get("session_id") {
                if !sid.is_empty() {
                    if let Some(bound) = subject_scoped(subject_id, sid) {
                        return Some((bound, SessionSource::TokenClaim));
                    }
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
            return Some((short_hash(&raw), SessionSource::Identity));
        }
    }

    // Tier 3: no session.
    None
}

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

    // Build Extensions carrying both an agent.session_id and a subject id.
    fn extensions_with_agent_and_subject(session_id: &str, subject_id: &str) -> Extensions {
        let mut agent = AgentExtension::default();
        agent.session_id = Some(session_id.into());
        Extensions {
            agent: Some(Arc::new(agent)),
            security: Some(Arc::new(SecurityExtension {
                subject: Some(subject_with_claims(Some(subject_id), &[])),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[test]
    fn tier0_agent_session_id_is_subject_bound() {
        // A pre-resolved (client-supplied) session id is hashed together
        // with the authenticated subject, never returned raw.
        let ext = extensions_with_agent_and_subject("sess-upstream", "alice");
        let (sid, src) = resolve_session(&ext).expect("should resolve");
        assert_eq!(src, SessionSource::Agent);
        assert_eq!(sid, subject_scoped(Some("alice"), "sess-upstream").unwrap());
        assert_ne!(sid, "sess-upstream", "raw client value must not be the key");
    }

    #[test]
    fn tier0_same_session_id_different_subjects_are_distinct() {
        // Guarantee: principal A reusing principal B's
        // session id must NOT land in B's session bucket.
        let alice = extensions_with_agent_and_subject("shared-sid", "alice");
        let bob = extensions_with_agent_and_subject("shared-sid", "bob");
        let (sid_a, _) = resolve_session(&alice).unwrap();
        let (sid_b, _) = resolve_session(&bob).unwrap();
        assert_ne!(
            sid_a, sid_b,
            "same client session id under different subjects must not collide",
        );
    }

    #[test]
    fn tier0_stable_for_same_subject_and_session_id() {
        // Same subject + same client session id → same key, so a legit
        // user's taint persists across their own request/response cycles.
        let (sid1, _) = resolve_session(&extensions_with_agent_and_subject("s1", "bob")).unwrap();
        let (sid2, _) = resolve_session(&extensions_with_agent_and_subject("s1", "bob")).unwrap();
        assert_eq!(sid1, sid2);
    }

    #[test]
    fn tier0_no_subject_falls_through() {
        // A client session id with no authenticated subject has no safe
        // scope: do not honor it (no anonymous cross-readable bucket).
        let mut agent = AgentExtension::default();
        agent.session_id = Some("sess-upstream".into());
        let ext = Extensions {
            agent: Some(Arc::new(agent)),
            ..Default::default()
        };
        assert!(resolve_session(&ext).is_none());
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
            security: Some(Arc::new(SecurityExtension {
                subject: Some(subject_with_claims(Some("alice"), &[])),
                ..Default::default()
            })),
            ..Default::default()
        };
        // Empty Tier 0 falls through; identity tier (subject present) hits.
        let (_, src) = resolve_session(&ext).expect("should fall through to identity");
        assert_eq!(src, SessionSource::Identity);
    }

    #[test]
    fn tier0_wins_over_token_claim() {
        // Pre-resolved value beats a JWT claim — upstream authority — and is
        // subject-bound rather than returned raw.
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
        assert_eq!(src, SessionSource::Agent);
        assert_eq!(sid, subject_scoped(Some("alice"), "from-agent").unwrap());
    }

    #[test]
    fn tier0_wins_over_identity() {
        // T0 (agent.session_id) must win over T2 (identity triple) when
        // both are available. Pins the tier priority explicitly so a
        // future refactor of the resolver's walk order regresses loudly.
        let mut agent = AgentExtension::default();
        agent.session_id = Some("from-agent".into());
        let sec = SecurityExtension {
            subject: Some(subject_with_claims(Some("alice"), &[])),
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
        let ext = Extensions {
            agent: Some(Arc::new(agent)),
            security: Some(Arc::new(sec)),
            ..Default::default()
        };

        let (sid, src) = resolve_session(&ext).unwrap();
        assert_eq!(
            src,
            SessionSource::Agent,
            "T0 must win over T2 when both are available",
        );
        assert_eq!(sid, subject_scoped(Some("alice"), "from-agent").unwrap());
    }

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
        assert_eq!(src, SessionSource::TokenClaim);
        // Subject-bound, not the raw claim value.
        assert_eq!(
            sid,
            subject_scoped(Some("alice@corp.com"), "sess-from-token-789").unwrap()
        );
        assert_ne!(sid, "sess-from-token-789");
    }

    #[test]
    fn tier1_skips_empty_session_id_claim() {
        // Empty claim values should NOT win tier 1 — they degrade to
        // identity-derived. Otherwise an issuer accidentally putting
        // an empty string in the claim would yield "" as the session
        // key, which would alias every such request.
        let sec = SecurityExtension {
            subject: Some(subject_with_claims(Some("alice"), &[("session_id", "")])),
            ..Default::default()
        };
        let ext = extensions_with_security(sec);

        let (_, src) = resolve_session(&ext).expect("should fall through to identity");
        assert_eq!(src, SessionSource::Identity);
    }

    #[test]
    fn tier1_same_session_id_claim_different_subjects_are_distinct() {
        // The Finding 2 guarantee for T1. An issuer that reuses a
        // session_id value across multiple principals (multi-tenant
        // naming conventions, counters that don't carry the subject,
        // etc.) must NOT let one principal land in another's session
        // bucket. Direct mirror of the T0 cross-principal test.
        let mk = |sub: &str| -> SecurityExtension {
            SecurityExtension {
                subject: Some(subject_with_claims(
                    Some(sub),
                    &[("session_id", "issuer-shared-sid")],
                )),
                ..Default::default()
            }
        };
        let (sid_a, _) = resolve_session(&extensions_with_security(mk("alice"))).unwrap();
        let (sid_b, _) = resolve_session(&extensions_with_security(mk("bob"))).unwrap();
        assert_ne!(
            sid_a, sid_b,
            "same JWT session_id claim under different subjects must not collide",
        );
    }

    #[test]
    fn tier1_stable_for_same_subject_and_session_id_claim() {
        // Same subject + same claim value → same key. A legit user's
        // session stays consistent across requests carrying the same
        // claim, so accumulated taint persists where it should.
        let mk = || -> Extensions {
            extensions_with_security(SecurityExtension {
                subject: Some(subject_with_claims(
                    Some("alice"),
                    &[("session_id", "claim-value-42")],
                )),
                ..Default::default()
            })
        };
        let (sid1, _) = resolve_session(&mk()).unwrap();
        let (sid2, _) = resolve_session(&mk()).unwrap();
        assert_eq!(sid1, sid2);
    }

    #[test]
    fn tier1_no_subject_id_falls_through() {
        // A JWT carries a `session_id` claim but has no `sub` (subject
        // present but `id == None`). T1 has no safe scope without a
        // subject — must fall through. T2 also requires a subject and
        // therefore returns None overall.
        let sec = SecurityExtension {
            subject: Some(SubjectExtension {
                id: None,
                claims: [("session_id".to_string(), "claim-value".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ext = extensions_with_security(sec);
        assert!(
            resolve_session(&ext).is_none(),
            "claim with no subject id has no safe scope; must not honor",
        );
    }

    #[test]
    fn tier1_wins_over_identity() {
        // Both a JWT session_id claim AND a full identity triple are
        // present. T1 must win over T2. Pins the tier priority
        // explicitly — the existing happy-path test happens to omit
        // T2 inputs, so without this T1>T2 priority is only implicit.
        let sec = SecurityExtension {
            subject: Some(subject_with_claims(
                Some("alice"),
                &[("session_id", "from-claim")],
            )),
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

        let (sid, src) = resolve_session(&ext).unwrap();
        assert_eq!(
            src,
            SessionSource::TokenClaim,
            "T1 must win over T2 when both are available",
        );
        assert_eq!(sid, subject_scoped(Some("alice"), "from-claim").unwrap());
    }

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

    #[test]
    fn separator_format_collides_when_subject_contains_colon() {
        // Document — but do not silently ignore — the colon-separator
        // format's known ambiguity. A colon inside subject_id collides
        // with one inside the raw value: both
        //   subject="alice:foo", raw="bar"
        // and
        //   subject="alice",     raw="foo:bar"
        // hash the same string "alice:foo:bar" and thus produce the
        // same session key.
        //
        // JWT `sub` claims are conventionally opaque URNs or emails,
        // which in practice don't carry colons. This test asserts the
        // collision exists so a future migration that introduces
        // colon-bearing subject IDs (or changes the separator format
        // unilaterally) breaks the build and forces a deliberate
        // re-design — most likely a length-prefixed format like
        // `{sub_len}:{sub}:{raw}`.
        let a = subject_scoped(Some("alice:foo"), "bar").unwrap();
        let b = subject_scoped(Some("alice"), "foo:bar").unwrap();
        assert_eq!(
            a, b,
            "current format collides; if subject IDs can contain colons, switch to length-prefix",
        );
    }

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
