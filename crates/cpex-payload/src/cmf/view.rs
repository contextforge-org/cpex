// Location: ./crates/cpex-core/src/cmf/view.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// MessageView — read-only projection for policy evaluation.
//
// Decomposes a Message into individually addressable views with a
// uniform interface regardless of content type. Zero-copy design —
// properties are computed on-demand by borrowing the underlying
// content part and extensions directly.
//
// Mirrors the Python MessageView in cpex/framework/cmf/view.py.

use serde::{Deserialize, Serialize};

use super::content::*;
use super::enums::{ContentType, Role};
use super::message::Message;
use crate::hooks::payload::Extensions;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Type of content a view represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    Text,
    Thinking,
    ToolCall,
    ToolResult,
    Resource,
    ResourceRef,
    PromptRequest,
    PromptResult,
    Image,
    Video,
    Audio,
    Document,
}

/// The action this content represents in the data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewAction {
    Read,
    Write,
    Execute,
    Invoke,
    Send,
    Receive,
    Generate,
}

impl ViewKind {
    /// Map ContentType to ViewKind.
    pub fn from_content_type(ct: ContentType) -> Self {
        match ct {
            ContentType::Text => ViewKind::Text,
            ContentType::Thinking => ViewKind::Thinking,
            ContentType::ToolCall => ViewKind::ToolCall,
            ContentType::ToolResult => ViewKind::ToolResult,
            ContentType::Resource => ViewKind::Resource,
            ContentType::ResourceRef => ViewKind::ResourceRef,
            ContentType::PromptRequest => ViewKind::PromptRequest,
            ContentType::PromptResult => ViewKind::PromptResult,
            ContentType::Image => ViewKind::Image,
            ContentType::Video => ViewKind::Video,
            ContentType::Audio => ViewKind::Audio,
            ContentType::Document => ViewKind::Document,
        }
    }

    /// The default action for this kind of content.
    pub fn default_action(&self, role: Role) -> ViewAction {
        match self {
            ViewKind::ToolCall => ViewAction::Execute,
            ViewKind::ToolResult => ViewAction::Receive,
            ViewKind::Resource | ViewKind::ResourceRef => ViewAction::Read,
            ViewKind::PromptRequest => ViewAction::Invoke,
            ViewKind::PromptResult => ViewAction::Receive,
            // Direction-dependent kinds
            ViewKind::Text
            | ViewKind::Thinking
            | ViewKind::Image
            | ViewKind::Video
            | ViewKind::Audio
            | ViewKind::Document => match role {
                Role::User => ViewAction::Send,
                Role::Assistant => ViewAction::Generate,
                Role::Tool => ViewAction::Receive,
                Role::System | Role::Developer => ViewAction::Write,
            },
        }
    }

    /// Whether this is a tool-related kind.
    pub fn is_tool(&self) -> bool {
        matches!(self, ViewKind::ToolCall | ViewKind::ToolResult)
    }

    /// Whether this is a resource-related kind.
    pub fn is_resource(&self) -> bool {
        matches!(self, ViewKind::Resource | ViewKind::ResourceRef)
    }

    /// Whether this is a prompt-related kind.
    pub fn is_prompt(&self) -> bool {
        matches!(self, ViewKind::PromptRequest | ViewKind::PromptResult)
    }

    /// Whether this is a media kind (image, video, audio, document).
    pub fn is_media(&self) -> bool {
        matches!(
            self,
            ViewKind::Image | ViewKind::Video | ViewKind::Audio | ViewKind::Document
        )
    }

    /// Whether this is a text kind (text or thinking).
    pub fn is_text(&self) -> bool {
        matches!(self, ViewKind::Text | ViewKind::Thinking)
    }
}

// ---------------------------------------------------------------------------
// MessageView
// ---------------------------------------------------------------------------

/// Read-only, zero-copy view over a single content part.
///
/// Provides a uniform interface for policy evaluation regardless
/// of content type. Properties are computed on-demand by borrowing
/// the underlying content part and extensions.
///
/// Produced by `Message::iter_views()` or the standalone `iter_views()`.
pub struct MessageView<'a> {
    /// The underlying content part.
    part: &'a ContentPart,
    /// The kind of content.
    kind: ViewKind,
    /// The parent message role.
    role: Role,
    /// Optional hook location (e.g., "tool_pre_invoke").
    hook: Option<&'a str>,
    /// Optional extensions (for security/http context).
    extensions: Option<&'a Extensions>,
}

impl<'a> MessageView<'a> {
    /// Create a new view over a content part.
    pub fn new(
        part: &'a ContentPart,
        role: Role,
        hook: Option<&'a str>,
        extensions: Option<&'a Extensions>,
    ) -> Self {
        let kind = match part {
            ContentPart::Text { .. } => ViewKind::Text,
            ContentPart::Thinking { .. } => ViewKind::Thinking,
            ContentPart::ToolCall { .. } => ViewKind::ToolCall,
            ContentPart::ToolResult { .. } => ViewKind::ToolResult,
            ContentPart::Resource { .. } => ViewKind::Resource,
            ContentPart::ResourceRef { .. } => ViewKind::ResourceRef,
            ContentPart::PromptRequest { .. } => ViewKind::PromptRequest,
            ContentPart::PromptResult { .. } => ViewKind::PromptResult,
            ContentPart::Image { .. } => ViewKind::Image,
            ContentPart::Video { .. } => ViewKind::Video,
            ContentPart::Audio { .. } => ViewKind::Audio,
            ContentPart::Document { .. } => ViewKind::Document,
        };

        Self {
            part,
            kind,
            role,
            hook,
            extensions,
        }
    }

    // -- Core properties --

    /// The kind of content this view represents.
    pub fn kind(&self) -> ViewKind {
        self.kind
    }

    /// The role of the parent message.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The underlying content part.
    pub fn raw(&self) -> &'a ContentPart {
        self.part
    }

    /// The hook location, if set.
    pub fn hook(&self) -> Option<&str> {
        self.hook
    }

    /// The action this content represents.
    pub fn action(&self) -> ViewAction {
        self.kind.default_action(self.role)
    }

    // -- Phase helpers --

    /// Whether this is a pre-execution hook (tool_pre_invoke, prompt_pre_fetch, etc.).
    pub fn is_pre(&self) -> bool {
        self.hook.is_some_and(|h| h.contains("pre"))
    }

    /// Whether this is a post-execution hook.
    pub fn is_post(&self) -> bool {
        self.hook.is_some_and(|h| h.contains("post"))
    }

    // -- Universal properties --

    /// Text content (for text, thinking, tool result content).
    pub fn content(&self) -> Option<&str> {
        match self.part {
            ContentPart::Text { text } | ContentPart::Thinking { text } => Some(text),
            ContentPart::ToolResult { content: tr } => {
                tr.content.as_str().map(Some).unwrap_or(None)
            }
            ContentPart::Resource { content: r } => r.content.as_deref(),
            ContentPart::PromptResult { content: pr } => pr.content.as_deref(),
            _ => None,
        }
    }

    /// Entity name (tool name, resource URI, prompt name).
    pub fn name(&self) -> Option<&str> {
        match self.part {
            ContentPart::ToolCall { content: tc } => Some(&tc.name),
            ContentPart::ToolResult { content: tr } => Some(&tr.tool_name),
            ContentPart::Resource { content: r } => r.name.as_deref().or(Some(&r.uri)),
            ContentPart::ResourceRef { content: rr } => rr.name.as_deref().or(Some(&rr.uri)),
            ContentPart::PromptRequest { content: pr } => Some(&pr.name),
            ContentPart::PromptResult { content: pr } => Some(&pr.prompt_name),
            _ => None,
        }
    }

    /// URI for the entity.
    pub fn uri(&self) -> Option<String> {
        match self.part {
            ContentPart::ToolCall { content: tc } => Some(format!("tool://_/{}", tc.name)),
            ContentPart::Resource { content: r } => Some(r.uri.clone()),
            ContentPart::ResourceRef { content: rr } => Some(rr.uri.clone()),
            ContentPart::PromptRequest { content: pr } => Some(format!("prompt://_/{}", pr.name)),
            _ => None,
        }
    }

    /// Arguments (for tool calls and prompt requests).
    pub fn args(&self) -> Option<&std::collections::HashMap<String, serde_json::Value>> {
        match self.part {
            ContentPart::ToolCall { content: tc } => Some(&tc.arguments),
            ContentPart::PromptRequest { content: pr } => Some(&pr.arguments),
            _ => None,
        }
    }

    /// Get a specific argument by name.
    pub fn get_arg(&self, name: &str) -> Option<&serde_json::Value> {
        self.args().and_then(|a| a.get(name))
    }

    /// Whether this content has arguments.
    pub fn has_arg(&self, name: &str) -> bool {
        self.get_arg(name).is_some()
    }

    /// MIME type (for resources, media).
    pub fn mime_type(&self) -> Option<&str> {
        match self.part {
            ContentPart::Resource { content: r } => r.mime_type.as_deref(),
            ContentPart::Image { content: img } => img.media_type.as_deref(),
            ContentPart::Video { content: vid } => vid.media_type.as_deref(),
            ContentPart::Audio { content: aud } => aud.media_type.as_deref(),
            ContentPart::Document { content: doc } => doc.media_type.as_deref(),
            _ => None,
        }
    }

    /// Whether the result is an error (tool results, prompt results).
    pub fn is_error(&self) -> bool {
        match self.part {
            ContentPart::ToolResult { content: tr } => tr.is_error,
            ContentPart::PromptResult { content: pr } => pr.is_error,
            _ => false,
        }
    }

    // -- Type helpers --

    pub fn is_tool(&self) -> bool {
        self.kind.is_tool()
    }
    pub fn is_resource(&self) -> bool {
        self.kind.is_resource()
    }
    pub fn is_prompt(&self) -> bool {
        self.kind.is_prompt()
    }
    pub fn is_media(&self) -> bool {
        self.kind.is_media()
    }
    pub fn is_text(&self) -> bool {
        self.kind.is_text()
    }

    // -- Extension accessors --

    /// Get the extensions, if provided.
    pub fn extensions(&self) -> Option<&'a Extensions> {
        self.extensions
    }

    /// Check if a security label exists.
    pub fn has_label(&self, label: &str) -> bool {
        self.extensions
            .and_then(|e| e.security.as_ref())
            .map(|s| s.has_label(label))
            .unwrap_or(false)
    }

    /// Get an HTTP header value.
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.extensions
            .and_then(|e| e.http.as_ref())
            .and_then(|h| h.get_header(name))
    }

    // -- Serialization --

    /// Sensitive headers stripped during serialization.
    const SENSITIVE_HEADERS: &'static [&'static str] = &["authorization", "cookie", "x-api-key"];

    /// Serialize the view to a JSON-compatible map.
    ///
    /// Includes the view's properties, arguments, and optionally
    /// text content and extension context. Sensitive headers
    /// (Authorization, Cookie, X-API-Key) are stripped.
    pub fn to_dict(&self, include_content: bool, include_context: bool) -> serde_json::Value {
        use super::constants::*;

        let mut result = serde_json::Map::new();

        // Core fields
        result.insert(FIELD_KIND.into(), serde_json::json!(self.kind));
        result.insert(FIELD_ROLE.into(), serde_json::json!(self.role));
        result.insert(FIELD_IS_PRE.into(), serde_json::json!(self.is_pre()));
        result.insert(FIELD_IS_POST.into(), serde_json::json!(self.is_post()));
        result.insert(FIELD_ACTION.into(), serde_json::json!(self.action()));

        if let Some(hook) = self.hook {
            result.insert(FIELD_HOOK.into(), serde_json::json!(hook));
        }

        if let Some(uri) = self.uri() {
            result.insert(FIELD_URI.into(), serde_json::json!(uri));
        }

        if let Some(name) = self.name() {
            result.insert(FIELD_NAME.into(), serde_json::json!(name));
        }

        // Content
        if include_content {
            if let Some(text) = self.content() {
                result.insert(FIELD_SIZE_BYTES.into(), serde_json::json!(text.len()));
                result.insert(FIELD_CONTENT.into(), serde_json::json!(text));
            }
        }

        if let Some(mime) = self.mime_type() {
            result.insert(FIELD_MIME_TYPE.into(), serde_json::json!(mime));
        }

        // Arguments
        if let Some(args) = self.args() {
            result.insert(FIELD_ARGUMENTS.into(), serde_json::json!(args));
        }

        // Extensions context
        if include_context {
            if let Some(ext) = self.extensions {
                let mut ext_map = serde_json::Map::new();

                // Subject
                if let Some(ref sec) = ext.security {
                    if let Some(ref subject) = sec.subject {
                        let mut sub_map = serde_json::Map::new();
                        if let Some(ref id) = subject.id {
                            sub_map.insert(FIELD_ID.into(), serde_json::json!(id));
                        }
                        if let Some(ref st) = subject.subject_type {
                            sub_map.insert(FIELD_TYPE.into(), serde_json::json!(st));
                        }
                        if !subject.roles.is_empty() {
                            let mut roles: Vec<&String> = subject.roles.iter().collect();
                            roles.sort();
                            sub_map.insert(FIELD_ROLES.into(), serde_json::json!(roles));
                        }
                        if !subject.permissions.is_empty() {
                            let mut perms: Vec<&String> = subject.permissions.iter().collect();
                            perms.sort();
                            sub_map.insert(FIELD_PERMISSIONS.into(), serde_json::json!(perms));
                        }
                        if !subject.teams.is_empty() {
                            let mut teams: Vec<&String> = subject.teams.iter().collect();
                            teams.sort();
                            sub_map.insert(FIELD_TEAMS.into(), serde_json::json!(teams));
                        }
                        if !sub_map.is_empty() {
                            ext_map
                                .insert(FIELD_SUBJECT.into(), serde_json::Value::Object(sub_map));
                        }
                    }

                    // Labels
                    if !sec.labels.is_empty() {
                        let mut labels: Vec<&String> = sec.labels.iter().collect();
                        labels.sort();
                        ext_map.insert(FIELD_LABELS.into(), serde_json::json!(labels));
                    }
                }

                // Environment
                if let Some(ref req) = ext.request {
                    if let Some(ref env) = req.environment {
                        ext_map.insert(FIELD_ENVIRONMENT.into(), serde_json::json!(env));
                    }
                }

                // Request headers (strip sensitive)
                if let Some(ref http) = ext.http {
                    let safe: std::collections::HashMap<&String, &String> = http
                        .request_headers
                        .iter()
                        .filter(|(k, _)| {
                            !Self::SENSITIVE_HEADERS.contains(&k.to_lowercase().as_str())
                        })
                        .collect();
                    if !safe.is_empty() {
                        ext_map.insert(FIELD_HEADERS.into(), serde_json::json!(safe));
                    }
                }

                // Agent context
                if let Some(ref agent) = ext.agent {
                    let mut agent_map = serde_json::Map::new();
                    if let Some(ref input) = agent.input {
                        agent_map.insert(FIELD_INPUT.into(), serde_json::json!(input));
                    }
                    if let Some(ref sid) = agent.session_id {
                        agent_map.insert(FIELD_SESSION_ID.into(), serde_json::json!(sid));
                    }
                    if let Some(ref cid) = agent.conversation_id {
                        agent_map.insert(FIELD_CONVERSATION_ID.into(), serde_json::json!(cid));
                    }
                    if let Some(turn) = agent.turn {
                        agent_map.insert(FIELD_TURN.into(), serde_json::json!(turn));
                    }
                    if let Some(ref aid) = agent.agent_id {
                        agent_map.insert(FIELD_AGENT_ID.into(), serde_json::json!(aid));
                    }
                    if let Some(ref paid) = agent.parent_agent_id {
                        agent_map.insert(FIELD_PARENT_AGENT_ID.into(), serde_json::json!(paid));
                    }
                    if !agent_map.is_empty() {
                        ext_map.insert(FIELD_AGENT.into(), serde_json::Value::Object(agent_map));
                    }
                }

                // Meta
                if let Some(ref meta) = ext.meta {
                    let mut meta_map = serde_json::Map::new();
                    if let Some(ref et) = meta.entity_type {
                        meta_map.insert(FIELD_ENTITY_TYPE.into(), serde_json::json!(et));
                    }
                    if let Some(ref en) = meta.entity_name {
                        meta_map.insert(FIELD_ENTITY_NAME.into(), serde_json::json!(en));
                    }
                    if !meta.tags.is_empty() {
                        let mut tags: Vec<&String> = meta.tags.iter().collect();
                        tags.sort();
                        meta_map.insert(FIELD_TAGS.into(), serde_json::json!(tags));
                    }
                    if !meta_map.is_empty() {
                        ext_map.insert(FIELD_META.into(), serde_json::Value::Object(meta_map));
                    }
                }

                if !ext_map.is_empty() {
                    result.insert(FIELD_EXTENSIONS.into(), serde_json::Value::Object(ext_map));
                }
            }
        }

        serde_json::Value::Object(result)
    }

    /// Serialize to OPA-compatible input format.
    ///
    /// Wraps the view in the standard OPA input envelope:
    /// `{"input": {...view data...}}`.
    pub fn to_opa_input(&self, include_content: bool) -> serde_json::Value {
        use super::constants::FIELD_OPA_INPUT;
        serde_json::json!({
            FIELD_OPA_INPUT: self.to_dict(include_content, true)
        })
    }
}

impl<'a> std::fmt::Debug for MessageView<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageView")
            .field("kind", &self.kind)
            .field("role", &self.role)
            .field("name", &self.name())
            .field("hook", &self.hook)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// iter_views — decompose a Message into views
// ---------------------------------------------------------------------------

/// Decompose a Message into individually addressable MessageViews.
///
/// Yields one view per content part. Each view provides a uniform
/// interface for policy evaluation regardless of content type.
pub fn iter_views<'a>(
    message: &'a Message,
    hook: Option<&'a str>,
    extensions: Option<&'a Extensions>,
) -> impl Iterator<Item = MessageView<'a>> {
    message
        .content
        .iter()
        .map(move |part| MessageView::new(part, message.role, hook, extensions))
}

// Also add iter_views to Message
impl Message {
    /// Decompose this message into individually addressable MessageViews.
    ///
    /// Yields one view per content part. Each view provides a uniform
    /// interface for policy evaluation regardless of content type.
    pub fn iter_views<'a>(
        &'a self,
        hook: Option<&'a str>,
        extensions: Option<&'a Extensions>,
    ) -> impl Iterator<Item = MessageView<'a>> {
        iter_views(self, hook, extensions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmf::enums::Role;
    use crate::hooks::payload::MetaExtension;

    fn make_test_message() -> Message {
        Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Thinking {
                    text: "Let me think...".into(),
                },
                ContentPart::Text {
                    text: "Here's the answer.".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "get_weather".into(),
                        arguments: [("city".to_string(), serde_json::json!("London"))].into(),
                        namespace: None,
                    },
                },
                ContentPart::Resource {
                    content: Resource {
                        resource_request_id: "rr_001".into(),
                        uri: "file:///data.csv".into(),
                        name: Some("Data File".into()),
                        resource_type: crate::cmf::enums::ResourceType::File,
                        content: Some("col1,col2".into()),
                        mime_type: Some("text/csv".into()),
                        ..Default::default()
                    },
                },
            ],
            channel: None,
        }
    }

    #[test]
    fn test_iter_views_count() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views.len(), 4);
    }

    #[test]
    fn test_view_kinds() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[0].kind(), ViewKind::Thinking);
        assert_eq!(views[1].kind(), ViewKind::Text);
        assert_eq!(views[2].kind(), ViewKind::ToolCall);
        assert_eq!(views[3].kind(), ViewKind::Resource);
    }

    #[test]
    fn test_view_content() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[0].content(), Some("Let me think..."));
        assert_eq!(views[1].content(), Some("Here's the answer."));
        assert!(views[2].content().is_none()); // tool call has no text content
        assert_eq!(views[3].content(), Some("col1,col2")); // resource has text content
    }

    #[test]
    fn test_view_name() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert!(views[0].name().is_none()); // thinking has no name
        assert!(views[1].name().is_none()); // text has no name
        assert_eq!(views[2].name(), Some("get_weather"));
        assert_eq!(views[3].name(), Some("Data File"));
    }

    #[test]
    fn test_view_uri() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[2].uri(), Some("tool://_/get_weather".to_string()));
        assert_eq!(views[3].uri(), Some("file:///data.csv".to_string()));
    }

    #[test]
    fn test_view_args() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        let tool_view = &views[2];
        assert!(tool_view.has_arg("city"));
        assert_eq!(tool_view.get_arg("city").unwrap(), "London");
        assert!(!tool_view.has_arg("nonexistent"));
    }

    #[test]
    fn test_view_action() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[0].action(), ViewAction::Generate); // thinking from assistant
        assert_eq!(views[1].action(), ViewAction::Generate); // text from assistant
        assert_eq!(views[2].action(), ViewAction::Execute); // tool call
        assert_eq!(views[3].action(), ViewAction::Read); // resource
    }

    #[test]
    fn test_view_action_user_role() {
        let msg = Message::text(Role::User, "Hello");
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[0].action(), ViewAction::Send); // text from user
    }

    #[test]
    fn test_view_hook_pre_post() {
        let msg = make_test_message();
        let pre_views: Vec<_> = msg.iter_views(Some("tool_pre_invoke"), None).collect();
        assert!(pre_views[0].is_pre());
        assert!(!pre_views[0].is_post());

        let post_views: Vec<_> = msg.iter_views(Some("tool_post_invoke"), None).collect();
        assert!(post_views[0].is_post());
        assert!(!post_views[0].is_pre());
    }

    #[test]
    fn test_view_type_helpers() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert!(views[0].is_text()); // thinking
        assert!(views[1].is_text()); // text
        assert!(views[2].is_tool()); // tool call
        assert!(views[3].is_resource()); // resource
    }

    #[test]
    fn test_view_mime_type() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[3].mime_type(), Some("text/csv"));
    }

    #[test]
    fn test_view_with_extensions() {
        use crate::extensions::{HttpExtension, SecurityExtension};
        use std::sync::Arc;

        let mut security = SecurityExtension::default();
        security.add_label("PII");

        let mut http = HttpExtension::default();
        http.set_header("Authorization", "Bearer tok");

        let ext = Extensions {
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            ..Default::default()
        };

        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, Some(&ext)).collect();

        assert!(views[0].has_label("PII"));
        assert!(!views[0].has_label("HIPAA"));
        assert_eq!(views[0].get_header("Authorization"), Some("Bearer tok"));
    }

    #[test]
    fn test_to_dict_basic() {
        let msg = Message::text(Role::User, "Hello world");
        let views: Vec<_> = msg.iter_views(Some("llm_input"), None).collect();
        let dict = views[0].to_dict(true, false);

        assert_eq!(dict["kind"], "text");
        assert_eq!(dict["role"], "user");
        assert_eq!(dict["action"], "send");
        assert_eq!(dict["hook"], "llm_input");
        assert_eq!(dict["content"], "Hello world");
        assert_eq!(dict["size_bytes"], 11);
        assert_eq!(dict["is_pre"], false);
        assert_eq!(dict["is_post"], false);
    }

    #[test]
    fn test_to_dict_tool_call() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(Some("tool_pre_invoke"), None).collect();
        let dict = views[2].to_dict(true, false); // tool call

        assert_eq!(dict["kind"], "tool_call");
        assert_eq!(dict["name"], "get_weather");
        assert_eq!(dict["uri"], "tool://_/get_weather");
        assert_eq!(dict["action"], "execute");
        assert_eq!(dict["is_pre"], true);
        assert!(dict["arguments"].is_object());
        assert_eq!(dict["arguments"]["city"], "London");
    }

    #[test]
    fn test_to_dict_without_content() {
        let msg = Message::text(Role::User, "Secret message");
        let views: Vec<_> = msg.iter_views(None, None).collect();
        let dict = views[0].to_dict(false, false);

        assert!(dict.get("content").is_none());
        assert!(dict.get("size_bytes").is_none());
    }

    #[test]
    fn test_to_dict_with_extensions() {
        use crate::extensions::{
            AgentExtension, HttpExtension, RequestExtension, SecurityExtension,
        };
        use std::sync::Arc;

        let mut security = SecurityExtension::default();
        security.add_label("PII");
        security.subject = Some(crate::extensions::security::SubjectExtension {
            id: Some("alice".into()),
            subject_type: Some(crate::extensions::security::SubjectType::User),
            roles: ["admin".to_string()].into(),
            ..Default::default()
        });

        let mut http = HttpExtension::default();
        http.set_header("Authorization", "Bearer secret");
        http.set_header("X-Request-ID", "req-123");

        let ext = Extensions {
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            request: Some(Arc::new(RequestExtension {
                environment: Some("production".into()),
                ..Default::default()
            })),
            agent: Some(Arc::new(AgentExtension {
                session_id: Some("sess-001".into()),
                agent_id: Some("agent-x".into()),
                ..Default::default()
            })),
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                tags: ["pii".to_string()].into(),
                ..Default::default()
            })),
            ..Default::default()
        };

        let msg = Message::text(Role::User, "test");
        let views: Vec<_> = msg.iter_views(None, Some(&ext)).collect();
        let dict = views[0].to_dict(true, true);

        let extensions = &dict["extensions"];

        // Subject visible
        assert_eq!(extensions["subject"]["id"], "alice");
        assert!(extensions["subject"]["roles"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("admin")));

        // Labels visible
        assert!(extensions["labels"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("PII")));

        // Environment visible
        assert_eq!(extensions["environment"], "production");

        // Headers visible — but Authorization stripped (sensitive)
        assert!(extensions["headers"].get("Authorization").is_none());
        assert_eq!(extensions["headers"]["X-Request-ID"], "req-123");

        // Agent context visible
        assert_eq!(extensions["agent"]["session_id"], "sess-001");
        assert_eq!(extensions["agent"]["agent_id"], "agent-x");

        // Meta visible
        assert_eq!(extensions["meta"]["entity_type"], "tool");
        assert_eq!(extensions["meta"]["entity_name"], "get_compensation");
    }

    #[test]
    fn test_to_opa_input() {
        let msg = Message::text(Role::User, "Hello");
        let views: Vec<_> = msg.iter_views(None, None).collect();
        let opa = views[0].to_opa_input(true);

        assert!(opa.get("input").is_some());
        assert_eq!(opa["input"]["kind"], "text");
        assert_eq!(opa["input"]["role"], "user");
        assert_eq!(opa["input"]["content"], "Hello");
    }
}
