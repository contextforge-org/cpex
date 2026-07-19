// Location: ./builtins/pdps/cedar-direct/src/cedar_attrs.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Canonical Cedar entity attribute names.
//
// Cedar policy authors write `principal.roles.contains("hr")`,
// `principal.permissions.contains("view_ssn")`, etc. — the strings on
// the right side of `principal.` are *Cedar entity attribute names*
// that this crate produces when it builds the principal entity from the
// `AttributeBag`. Author-facing vocabulary, distinct from the
// `apl-cmf::constants::BAG_*` bag-key vocabulary even when the words
// happen to match.
//
// Keeping these constants in one module means a rename ripples to a
// single file. The entity builder in `entities.rs` and any future
// schema generator both reference them by symbol.
//
// Pair this list with the schema published to Cedar authors — every
// constant here should appear in any official entity schema.

/// `id` — the entity's identifier attribute (we emit it inside `attrs`
/// for legibility even though Cedar also has it in the `uid` slot).
pub const ATTR_ID: &str = "id";

/// `type` — the entity's type name as a string, for policies that
/// branch on subject kind (`principal.type == "agent"` etc.).
pub const ATTR_TYPE: &str = "type";

/// `roles` — `Set<String>` of role names the principal holds.
/// Filled from `apl-cmf`'s `role.*` bag keys.
pub const ATTR_ROLES: &str = "roles";

/// `permissions` — `Set<String>` of permission names.
/// Filled from `apl-cmf`'s `perm.*` bag keys.
pub const ATTR_PERMISSIONS: &str = "permissions";

/// `teams` — `Set<String>` of team / group memberships.
/// Filled from `apl-cmf`'s `subject.teams` bag key.
pub const ATTR_TEAMS: &str = "teams";

/// `claims` — `Record` of arbitrary JWT-style claims. Filled from
/// `apl-cmf`'s `claim.*` bag keys.
pub const ATTR_CLAIMS: &str = "claims";

/// `uid` — the {type, id} envelope at the top of an entity JSON.
pub const KEY_UID: &str = "uid";

/// `attrs` — the attribute bag inside an entity JSON.
pub const KEY_ATTRS: &str = "attrs";

/// `parents` — the optional parents list inside an entity JSON.
pub const KEY_PARENTS: &str = "parents";
