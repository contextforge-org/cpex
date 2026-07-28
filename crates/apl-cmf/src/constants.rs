// Location: ./crates/apl-cmf/src/constants.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// String constants used across apl-cmf — capability names cpex-core
// recognizes for `filter_extensions`, plus the bag-attribute
// prefixes APL extractors write under. Centralizing both makes the
// capability → bag namespace mapping in `capability_namespaces` a
// straight reference rather than a soup of inline strings, and
// gives operators / docs / tools one canonical place to read them
// from.
//
// # Source-of-truth invariants
//
// * `CAP_*` names match `cpex_core::extensions::filter::filter_extensions`
//   verbatim. cpex-core is authoritative — if it changes a cap name,
//   bump here and update the mapping table.
// * `BAG_*` prefixes match what the per-extension extractor modules
//   (`security.rs`, `delegation.rs`, etc.) actually write into the
//   bag. The extractor files still use string literals today; a
//   future cleanup can refactor them to consume these constants to
//   prevent drift. Tests in `capability_namespaces` flag the
//   contract.

pub const CAP_READ_SUBJECT: &str = "read_subject";
pub const CAP_READ_ROLES: &str = "read_roles";
pub const CAP_READ_PERMISSIONS: &str = "read_permissions";
pub const CAP_READ_TEAMS: &str = "read_teams";
pub const CAP_READ_CLAIMS: &str = "read_claims";

pub const CAP_READ_LABELS: &str = "read_labels";
pub const CAP_READ_CLIENT: &str = "read_client";
pub const CAP_READ_WORKLOAD: &str = "read_workload";

pub const CAP_READ_INBOUND_CREDENTIALS: &str = "read_inbound_credentials";
pub const CAP_READ_DELEGATED_TOKENS: &str = "read_delegated_tokens";

pub const CAP_READ_DELEGATION: &str = "read_delegation";
pub const CAP_READ_AGENT: &str = "read_agent";
pub const CAP_READ_META: &str = "read_meta";
pub const CAP_READ_REQUEST: &str = "read_request";
pub const CAP_READ_HEADERS: &str = "read_headers";
pub const CAP_READ_LLM: &str = "read_llm";
pub const CAP_READ_MCP: &str = "read_mcp";
pub const CAP_READ_COMPLETION: &str = "read_completion";
pub const CAP_READ_PROVENANCE: &str = "read_provenance";
pub const CAP_READ_FRAMEWORK: &str = "read_framework";
pub const CAP_READ_CUSTOM: &str = "read_custom";

pub const CAP_APPEND_LABELS: &str = "append_labels";
pub const CAP_APPEND_DELEGATION: &str = "append_delegation";
pub const CAP_WRITE_HEADERS: &str = "write_headers";

// Bag-attribute prefixes (and exact-match keys) — must match what
// the apl-cmf extractor modules write.
//
// Prefixes ending in `.` match any key starting with them
// (e.g. `BAG_ROLE_PREFIX` matches `role.hr`, `role.admin`).
// Prefixes WITHOUT a trailing `.` match the exact bag key
// (e.g. `BAG_AUTHENTICATED` matches only `authenticated`).
pub const BAG_SUBJECT_ID: &str = "subject.id";
pub const BAG_SUBJECT_TYPE: &str = "subject.type";
pub const BAG_SUBJECT_TEAMS: &str = "subject.teams";
pub const BAG_AUTHENTICATED: &str = "authenticated";
pub const BAG_ROLE_PREFIX: &str = "role.";
pub const BAG_PERM_PREFIX: &str = "perm.";
pub const BAG_TEAM_PREFIX: &str = "team.";
pub const BAG_CLAIM_PREFIX: &str = "claim.";

// Payload (args / result).
//
// These are the dotted-prefix forms used when apl-cmf::payload flattens
// the request's args object and the upstream's result object into the
// bag. APL predicates / Cedar `${args.X}` substitutions / OPA `input.X`
// paths all resolve through these.
pub const BAG_ARGS_PREFIX: &str = "args.";
pub const BAG_RESULT_PREFIX: &str = "result.";

pub const BAG_CLIENT_PREFIX: &str = "client.";
pub const BAG_WORKLOAD_PREFIX: &str = "workload.";
pub const BAG_CALLER_WORKLOAD_PREFIX: &str = "caller_workload.";

pub const BAG_DELEGATION_PREFIX: &str = "delegation.";
pub const BAG_DELEGATED: &str = "delegated";

pub const BAG_AGENT_PREFIX: &str = "agent.";
pub const BAG_META_PREFIX: &str = "meta.";
pub const BAG_REQUEST_PREFIX: &str = "request.";
pub const BAG_HTTP_REQUEST_HEADERS_PREFIX: &str = "http.request_headers.";
pub const BAG_HTTP_RESPONSE_HEADERS_PREFIX: &str = "http.response_headers.";
// HTTP request line — exact keys. These ride the same `read_headers`
// capability as headers (the whole `http` slot is gated together in
// `cpex-core::extensions::filter`).
pub const BAG_HTTP_METHOD: &str = "http.method";
pub const BAG_HTTP_PATH: &str = "http.path";
pub const BAG_HTTP_HOST: &str = "http.host";
pub const BAG_HTTP_SCHEME: &str = "http.scheme";
// Violation `details` keys carrying a transpiled `denyWith` (custom HTTP
// denial response). Shared between the producer (apl-cpex route handler)
// and any consumer (host renderer / tests) so the stringly-typed contract
// stays coupled to one definition.
pub const DETAIL_HTTP_STATUS: &str = "http.status";
pub const DETAIL_HTTP_BODY: &str = "http.body";
pub const DETAIL_HTTP_HEADERS: &str = "http.headers";
pub const BAG_LLM_PREFIX: &str = "llm.";
pub const BAG_MCP_PREFIX: &str = "mcp.";
pub const BAG_COMPLETION_PREFIX: &str = "completion.";
pub const BAG_PROVENANCE_PREFIX: &str = "provenance.";
pub const BAG_FRAMEWORK_PREFIX: &str = "framework.";
pub const BAG_CUSTOM_PREFIX: &str = "custom.";
