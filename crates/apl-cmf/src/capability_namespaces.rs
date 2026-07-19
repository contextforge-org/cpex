// Location: ./crates/apl-cmf/src/capability_namespaces.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Capability → bag-namespace mapping for operator visibility.
//
// cpex-core's `filter_extensions(&ext, &caps)` decides which
// `Extensions` slots a plugin sees based on its declared
// `capabilities:` list. The CMF extractors then flatten those slots
// into bag attributes under well-known prefixes. This module is the
// bridge: given a capability name, return the bag-attribute prefixes
// it unlocks. Lets operators answer "what bag keys does this plugin
// see?" without reading source.
//
// # Scope
//
// Covers the `read_*` capabilities — those map to bag namespaces
// because the corresponding Extensions slots become bag attributes
// after extraction. Write capabilities (`append_labels`,
// `append_delegation`, `write_headers`) gate WRITE tokens, not
// readable state, so they don't appear here.
//
// # Source of truth
//
// All hard-coded strings — both capability names and bag-attribute
// prefixes — live in [`crate::constants`]. The table below
// references the constants rather than inlining strings, so a typo
// surfaces at compile time and the constants file is the single
// place to update names.

use std::collections::HashSet;

use crate::constants::*;

/// Prefix mapping entry. `prefixes` lists the bag-attribute
/// namespace roots this capability unlocks. A prefix ending in `.`
/// means "any key starting with that root" (e.g. `role.` matches
/// `role.hr`). A prefix without a trailing `.` means an exact-match
/// key (e.g. `authenticated`).
struct CapabilityEntry {
    name: &'static str,
    prefixes: &'static [&'static str],
}

/// The mapping table — single source of truth for which bag
/// namespaces a capability unlocks. Keep in sync with cpex-core's
/// `filter_extensions` rules and the per-extension extractor
/// modules (`security.rs`, `delegation.rs`, etc.).
const TABLE: &[CapabilityEntry] = &[
    CapabilityEntry {
        name: CAP_READ_SUBJECT,
        // `read_subject` exposes id + type only; `authenticated` is
        // derived from those being present.
        prefixes: &[BAG_SUBJECT_ID, BAG_SUBJECT_TYPE, BAG_AUTHENTICATED],
    },
    CapabilityEntry {
        name: CAP_READ_ROLES,
        // Implies the read_subject baseline + role.* prefix.
        prefixes: &[
            BAG_ROLE_PREFIX,
            BAG_SUBJECT_ID,
            BAG_SUBJECT_TYPE,
            BAG_AUTHENTICATED,
        ],
    },
    CapabilityEntry {
        name: CAP_READ_PERMISSIONS,
        prefixes: &[
            BAG_PERM_PREFIX,
            BAG_SUBJECT_ID,
            BAG_SUBJECT_TYPE,
            BAG_AUTHENTICATED,
        ],
    },
    CapabilityEntry {
        name: CAP_READ_TEAMS,
        prefixes: &[
            BAG_SUBJECT_TEAMS,
            BAG_SUBJECT_ID,
            BAG_SUBJECT_TYPE,
            BAG_AUTHENTICATED,
        ],
    },
    CapabilityEntry {
        name: CAP_READ_CLAIMS,
        prefixes: &[
            BAG_CLAIM_PREFIX,
            BAG_SUBJECT_ID,
            BAG_SUBJECT_TYPE,
            BAG_AUTHENTICATED,
        ],
    },
    CapabilityEntry {
        // Labels are not extracted into discrete bag keys today —
        // they live on `Extensions.security.labels` and plugins
        // read them directly. APL's BagBuilder doesn't materialize
        // a bag-readable label namespace yet; if it does, add the
        // prefix constant + reference here.
        name: CAP_READ_LABELS,
        prefixes: &[],
    },
    CapabilityEntry {
        name: CAP_READ_CLIENT,
        prefixes: &[BAG_CLIENT_PREFIX],
    },
    CapabilityEntry {
        name: CAP_READ_WORKLOAD,
        // Exposes both inbound caller workload AND this-host workload.
        prefixes: &[BAG_WORKLOAD_PREFIX, BAG_CALLER_WORKLOAD_PREFIX],
    },
    CapabilityEntry {
        // Gates `Extensions.raw_credentials.inbound_tokens` — those
        // tokens flow through plugin payloads (IdentityPayload,
        // DelegationPayload), not into the bag.
        name: CAP_READ_INBOUND_CREDENTIALS,
        prefixes: &[],
    },
    CapabilityEntry {
        name: CAP_READ_DELEGATED_TOKENS,
        prefixes: &[],
    },
    CapabilityEntry {
        name: CAP_READ_DELEGATION,
        prefixes: &[BAG_DELEGATION_PREFIX, BAG_DELEGATED],
    },
    CapabilityEntry {
        name: CAP_READ_AGENT,
        prefixes: &[BAG_AGENT_PREFIX],
    },
    CapabilityEntry {
        name: CAP_READ_META,
        prefixes: &[BAG_META_PREFIX],
    },
    CapabilityEntry {
        name: CAP_READ_REQUEST,
        prefixes: &[BAG_REQUEST_PREFIX],
    },
    CapabilityEntry {
        name: CAP_READ_HEADERS,
        prefixes: &[
            BAG_HTTP_REQUEST_HEADERS_PREFIX,
            BAG_HTTP_RESPONSE_HEADERS_PREFIX,
            // The request line rides the same capability as headers.
            BAG_HTTP_METHOD,
            BAG_HTTP_PATH,
            BAG_HTTP_HOST,
            BAG_HTTP_SCHEME,
        ],
    },
    CapabilityEntry {
        name: CAP_READ_LLM,
        prefixes: &[BAG_LLM_PREFIX],
    },
    CapabilityEntry {
        name: CAP_READ_MCP,
        prefixes: &[BAG_MCP_PREFIX],
    },
    CapabilityEntry {
        name: CAP_READ_COMPLETION,
        prefixes: &[BAG_COMPLETION_PREFIX],
    },
    CapabilityEntry {
        name: CAP_READ_PROVENANCE,
        prefixes: &[BAG_PROVENANCE_PREFIX],
    },
    CapabilityEntry {
        name: CAP_READ_FRAMEWORK,
        prefixes: &[BAG_FRAMEWORK_PREFIX],
    },
    CapabilityEntry {
        name: CAP_READ_CUSTOM,
        prefixes: &[BAG_CUSTOM_PREFIX],
    },
];

/// Bag-attribute prefixes a single capability unlocks. Returns an
/// empty slice for capabilities that don't expose bag-readable
/// state (write capabilities, or read capabilities for slots that
/// aren't extracted into the bag). Unknown capability names also
/// return empty — operators may declare custom caps the framework
/// doesn't recognize, and we don't want to imply they unlock
/// nothing in some "official" sense.
///
/// A prefix ending in `.` matches any bag key starting with it
/// (e.g. `"role."` matches `"role.hr"`, `"role.admin"`).
/// A prefix without a trailing `.` matches the exact bag key
/// (e.g. `"authenticated"` matches only that bag key).
pub fn capability_namespaces(cap: &str) -> &'static [&'static str] {
    TABLE
        .iter()
        .find(|e| e.name == cap)
        .map(|e| e.prefixes)
        .unwrap_or(&[])
}

/// Union of all bag-attribute prefixes unlocked by a set of
/// capabilities. Useful for operators answering "what can this
/// plugin see in the bag, given its declared caps?" without walking
/// the table per cap themselves.
pub fn unlocked_bag_prefixes(caps: &[String]) -> HashSet<&'static str> {
    caps.iter()
        .flat_map(|c| capability_namespaces(c).iter().copied())
        .collect()
}

/// Every capability the framework recognizes for bag-namespace
/// purposes (excludes write caps and unknown ones). Useful for
/// completion / docs / config validation.
pub fn known_read_capabilities() -> impl Iterator<Item = &'static str> {
    TABLE.iter().map(|e| e.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_subject_exposes_id_type_authenticated() {
        let prefixes = capability_namespaces(CAP_READ_SUBJECT);
        assert!(prefixes.contains(&BAG_SUBJECT_ID));
        assert!(prefixes.contains(&BAG_SUBJECT_TYPE));
        assert!(prefixes.contains(&BAG_AUTHENTICATED));
    }

    #[test]
    fn read_roles_implies_subject_baseline_plus_role_prefix() {
        let prefixes = capability_namespaces(CAP_READ_ROLES);
        assert!(prefixes.contains(&BAG_ROLE_PREFIX));
        // Implied subject baseline.
        assert!(prefixes.contains(&BAG_SUBJECT_ID));
        assert!(prefixes.contains(&BAG_AUTHENTICATED));
    }

    #[test]
    fn read_delegation_exposes_delegation_namespace_and_delegated_flag() {
        let prefixes = capability_namespaces(CAP_READ_DELEGATION);
        assert!(prefixes.contains(&BAG_DELEGATION_PREFIX));
        assert!(prefixes.contains(&BAG_DELEGATED));
    }

    #[test]
    fn read_headers_exposes_both_request_and_response_header_namespaces() {
        let prefixes = capability_namespaces(CAP_READ_HEADERS);
        assert!(prefixes.contains(&BAG_HTTP_REQUEST_HEADERS_PREFIX));
        assert!(prefixes.contains(&BAG_HTTP_RESPONSE_HEADERS_PREFIX));
    }

    #[test]
    fn unknown_capability_returns_empty() {
        assert!(capability_namespaces("read_nonsense").is_empty());
    }

    #[test]
    fn write_capability_returns_empty() {
        // Write caps don't expose bag-readable state.
        assert!(capability_namespaces(CAP_APPEND_LABELS).is_empty());
        assert!(capability_namespaces(CAP_APPEND_DELEGATION).is_empty());
        assert!(capability_namespaces(CAP_WRITE_HEADERS).is_empty());
    }

    #[test]
    fn payload_only_credential_caps_return_empty() {
        // These caps gate Extensions slots that flow through plugin
        // payloads, not bag attributes.
        assert!(capability_namespaces(CAP_READ_INBOUND_CREDENTIALS).is_empty());
        assert!(capability_namespaces(CAP_READ_DELEGATED_TOKENS).is_empty());
        // read_labels too — labels aren't materialized into bag keys.
        assert!(capability_namespaces(CAP_READ_LABELS).is_empty());
    }

    #[test]
    fn unlocked_bag_prefixes_unions_multiple_caps() {
        let caps = vec![CAP_READ_SUBJECT.to_string(), CAP_READ_ROLES.to_string()];
        let union = unlocked_bag_prefixes(&caps);
        assert!(union.contains(BAG_SUBJECT_ID));
        assert!(union.contains(BAG_ROLE_PREFIX));
        // Deduplicates the shared subject baseline — only ONE
        // entry for the common BAG_SUBJECT_ID even though both
        // caps include it.
        let baseline_count = union.iter().filter(|p| **p == BAG_SUBJECT_ID).count();
        assert_eq!(baseline_count, 1);
    }

    #[test]
    fn unlocked_bag_prefixes_skips_unknown_caps() {
        let caps = vec![CAP_READ_SUBJECT.to_string(), "read_made_up".to_string()];
        let union = unlocked_bag_prefixes(&caps);
        assert!(union.contains(BAG_SUBJECT_ID));
        // Unknown cap contributes nothing — no panic, no surprise key.
        // read_subject contributes 3 entries; that's the total.
        assert_eq!(union.len(), 3);
    }

    #[test]
    fn known_read_capabilities_returns_every_table_entry() {
        let count = known_read_capabilities().count();
        // Sanity: substantial but bounded — table bloat would be
        // a maintenance signal.
        assert!(count > 10, "expected >10 known caps, got {count}");
        assert!(count < 50, "table grew unexpectedly to {count} entries");
        // Spot-check canonical names are present.
        let names: HashSet<&str> = known_read_capabilities().collect();
        assert!(names.contains(CAP_READ_SUBJECT));
        assert!(names.contains(CAP_READ_META));
        assert!(names.contains(CAP_READ_DELEGATION));
    }
}
