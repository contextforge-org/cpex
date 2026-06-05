// Location: ./crates/apl-cmf/src/delegation.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// DelegationExtension → AttributeBag.
//
// Namespace map:
//
//   del.depth                  → delegation.depth                : Int
//   del.delegated              → delegation.delegated, delegated : Bool
//   del.origin_subject_id      → delegation.origin_subject_id    : String
//   del.actor_subject_id       → delegation.actor_subject_id     : String
//   del.age_seconds            → delegation.age_seconds          : Float
//
// Per-hop fields (scopes, audience, strategy) are not flattened into the
// bag. Policies that need that depth call out to a plugin or PDP; the
// bag stays scalar.

use apl_core::AttributeBag;
use cpex_core::extensions::DelegationExtension;

/// Flatten a `DelegationExtension` into the bag.
pub fn extract_delegation(del: &DelegationExtension, bag: &mut AttributeBag) {
    bag.set("delegation.depth", del.depth as i64);
    bag.set("delegation.delegated", del.delegated);
    // Top-level alias — DSL idiom is `require(!delegated)`, unprefixed.
    bag.set("delegated", del.delegated);

    if let Some(origin) = &del.origin_subject_id {
        bag.set("delegation.origin_subject_id", origin.clone());
    }
    if let Some(actor) = &del.actor_subject_id {
        bag.set("delegation.actor_subject_id", actor.clone());
    }
    bag.set("delegation.age_seconds", del.age_seconds);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::extensions::{DelegationHop, DelegationStrategy};

    #[test]
    fn empty_delegation_sets_zero_depth_and_delegated_false() {
        let del = DelegationExtension::default();
        let mut bag = AttributeBag::new();
        extract_delegation(&del, &mut bag);
        assert_eq!(bag.get_int("delegation.depth"), Some(0));
        assert_eq!(bag.get_bool("delegation.delegated"), Some(false));
        assert_eq!(bag.get_bool("delegated"), Some(false));
        // Optional fields stay absent.
        assert!(!bag.contains("delegation.origin_subject_id"));
        assert!(!bag.contains("delegation.actor_subject_id"));
    }

    #[test]
    fn populated_chain_produces_attributes() {
        let mut del = DelegationExtension {
            origin_subject_id: Some("alice".into()),
            actor_subject_id: Some("service-b".into()),
            age_seconds: 12.5,
            ..Default::default()
        };
        del.append_hop(DelegationHop {
            subject_id: "alice".into(),
            audience: Some("service-b".into()),
            scopes_granted: vec!["read".into()],
            strategy: Some(DelegationStrategy::TokenExchange),
            ..Default::default()
        });
        del.append_hop(DelegationHop {
            subject_id: "service-b".into(),
            audience: Some("service-c".into()),
            scopes_granted: vec!["read".into()],
            ..Default::default()
        });

        let mut bag = AttributeBag::new();
        extract_delegation(&del, &mut bag);
        assert_eq!(bag.get_int("delegation.depth"), Some(2));
        assert_eq!(bag.get_bool("delegation.delegated"), Some(true));
        assert_eq!(bag.get_bool("delegated"), Some(true));
        assert_eq!(bag.get_string("delegation.origin_subject_id"), Some("alice"));
        assert_eq!(bag.get_string("delegation.actor_subject_id"), Some("service-b"));
        assert_eq!(bag.get_float("delegation.age_seconds"), Some(12.5));
    }
}
