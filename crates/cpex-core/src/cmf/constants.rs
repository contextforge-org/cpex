// Location: ./crates/cpex-core/src/cmf/constants.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CMF constants — schema version, serialization field names, and defaults.

/// Current CMF message schema version.
pub const SCHEMA_VERSION: &str = "2.0";

// ---------------------------------------------------------------------------
// Serialization field names for MessageView::to_dict() / to_opa_input()
// ---------------------------------------------------------------------------

// Core view fields
pub const FIELD_KIND: &str = "kind";
pub const FIELD_ROLE: &str = "role";
pub const FIELD_IS_PRE: &str = "is_pre";
pub const FIELD_IS_POST: &str = "is_post";
pub const FIELD_ACTION: &str = "action";
pub const FIELD_HOOK: &str = "hook";
pub const FIELD_URI: &str = "uri";
pub const FIELD_NAME: &str = "name";
pub const FIELD_CONTENT: &str = "content";
pub const FIELD_SIZE_BYTES: &str = "size_bytes";
pub const FIELD_MIME_TYPE: &str = "mime_type";
pub const FIELD_ARGUMENTS: &str = "arguments";

// Extensions container
pub const FIELD_EXTENSIONS: &str = "extensions";

// Subject fields
pub const FIELD_SUBJECT: &str = "subject";
pub const FIELD_ID: &str = "id";
pub const FIELD_TYPE: &str = "type";
pub const FIELD_ROLES: &str = "roles";
pub const FIELD_PERMISSIONS: &str = "permissions";
pub const FIELD_TEAMS: &str = "teams";

// Security fields
pub const FIELD_LABELS: &str = "labels";

// Request fields
pub const FIELD_ENVIRONMENT: &str = "environment";

// HTTP fields
pub const FIELD_HEADERS: &str = "headers";

// Agent fields
pub const FIELD_AGENT: &str = "agent";
pub const FIELD_INPUT: &str = "input";
pub const FIELD_SESSION_ID: &str = "session_id";
pub const FIELD_CONVERSATION_ID: &str = "conversation_id";
pub const FIELD_TURN: &str = "turn";
pub const FIELD_AGENT_ID: &str = "agent_id";
pub const FIELD_PARENT_AGENT_ID: &str = "parent_agent_id";

// Meta fields
pub const FIELD_META: &str = "meta";
pub const FIELD_ENTITY_TYPE: &str = "entity_type";
pub const FIELD_ENTITY_NAME: &str = "entity_name";
pub const FIELD_TAGS: &str = "tags";

// OPA envelope
pub const FIELD_OPA_INPUT: &str = "input";
