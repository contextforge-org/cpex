use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cpex_payload::cmf::content as native_content;
use cpex_payload::cmf::enums as native_enums;
use cpex_payload::cmf::message as native_msg;
use cpex_payload::error::PluginViolation as NativePluginViolation;
use cpex_payload::extensions::container::Extensions as NativeExtensions;
use cpex_payload::extensions::http::HttpExtension as NativeHttpExtension;
use cpex_payload::extensions::meta::MetaExtension as NativeMetaExtension;
use cpex_payload::extensions::monotonic::MonotonicSet;
use cpex_payload::extensions::request::RequestExtension as NativeRequestExtension;
use cpex_payload::extensions::security::{
    SecurityExtension as NativeSecurityExtension, SubjectExtension as NativeSubjectExtension,
    SubjectType as NativeSubjectType,
};
use cpex_payload::context::PluginContext as NativePluginContext;
use cpex_payload::hooks::PluginResult as NativePluginResult;

use crate::cpex::plugin::types::*;

// ---------------------------------------------------------------------------
// WIT → Native: MessagePayload
// ---------------------------------------------------------------------------

pub fn wit_payload_to_native(payload: MessagePayload) -> native_msg::MessagePayload {
    native_msg::MessagePayload {
        message: wit_message_to_native(payload.message),
    }
}

fn wit_message_to_native(msg: Message) -> native_msg::Message {
    native_msg::Message {
        schema_version: msg.schema_version,
        role: wit_role_to_native(msg.role),
        content: msg.content.into_iter().map(wit_content_part_to_native).collect(),
        channel: msg.channel.map(wit_channel_to_native),
    }
}

fn wit_role_to_native(role: Role) -> native_enums::Role {
    match role {
        Role::System => native_enums::Role::System,
        Role::Developer => native_enums::Role::Developer,
        Role::User => native_enums::Role::User,
        Role::Assistant => native_enums::Role::Assistant,
        Role::Tool => native_enums::Role::Tool,
    }
}

fn wit_channel_to_native(channel: Channel) -> native_enums::Channel {
    match channel {
        Channel::Analysis => native_enums::Channel::Analysis,
        Channel::Commentary => native_enums::Channel::Commentary,
        Channel::Final => native_enums::Channel::Final,
    }
}

fn wit_content_part_to_native(part: ContentPart) -> native_content::ContentPart {
    match part {
        ContentPart::Text(text) => native_content::ContentPart::Text { text },
        ContentPart::Thinking(text) => native_content::ContentPart::Thinking { text },
        ContentPart::ToolCall(tc) => native_content::ContentPart::ToolCall {
            content: wit_tool_call_to_native(tc),
        },
        ContentPart::ToolResult(tr) => native_content::ContentPart::ToolResult {
            content: wit_tool_result_to_native(tr),
        },
        ContentPart::CmfResource(r) => native_content::ContentPart::Resource {
            content: wit_resource_to_native(r),
        },
        ContentPart::ResourceRef(rr) => native_content::ContentPart::ResourceRef {
            content: wit_resource_ref_to_native(rr),
        },
        ContentPart::PromptRequest(pr) => native_content::ContentPart::PromptRequest {
            content: wit_prompt_request_to_native(pr),
        },
        ContentPart::PromptResult(pr) => native_content::ContentPart::PromptResult {
            content: wit_prompt_result_to_native(pr),
        },
        ContentPart::Image(img) => native_content::ContentPart::Image {
            content: native_content::ImageSource {
                source_type: img.source_type,
                data: img.data,
                media_type: img.media_type,
            },
        },
        ContentPart::Video(v) => native_content::ContentPart::Video {
            content: native_content::VideoSource {
                source_type: v.source_type,
                data: v.data,
                media_type: v.media_type,
                duration_ms: v.duration_ms,
            },
        },
        ContentPart::Audio(a) => native_content::ContentPart::Audio {
            content: native_content::AudioSource {
                source_type: a.source_type,
                data: a.data,
                media_type: a.media_type,
                duration_ms: a.duration_ms,
            },
        },
        ContentPart::Document(d) => native_content::ContentPart::Document {
            content: native_content::DocumentSource {
                source_type: d.source_type,
                data: d.data,
                media_type: d.media_type,
                title: d.title,
            },
        },
    }
}

fn wit_tool_call_to_native(tc: ToolCall) -> native_content::ToolCall {
    let arguments: HashMap<String, serde_json::Value> =
        serde_json::from_str(&tc.arguments).unwrap_or_default();
    native_content::ToolCall {
        tool_call_id: tc.tool_call_id,
        name: tc.name,
        arguments,
        namespace: tc.namespace,
    }
}

fn wit_tool_result_to_native(tr: ToolResult) -> native_content::ToolResult {
    let content: serde_json::Value =
        serde_json::from_str(&tr.content).unwrap_or(serde_json::Value::String(tr.content.clone()));
    native_content::ToolResult {
        tool_call_id: tr.tool_call_id,
        tool_name: tr.tool_name,
        content,
        is_error: tr.is_error,
    }
}

fn wit_resource_to_native(r: CmfResource) -> native_content::Resource {
    let annotations: HashMap<String, serde_json::Value> =
        serde_json::from_str(&r.annotations).unwrap_or_default();
    native_content::Resource {
        resource_request_id: r.resource_request_id,
        uri: r.uri,
        name: r.name,
        description: r.description,
        resource_type: wit_resource_type_to_native(r.resource_type),
        content: r.content,
        blob: r.blob,
        mime_type: r.mime_type,
        size_bytes: r.size_bytes,
        annotations,
        version: r.version,
    }
}

fn wit_resource_type_to_native(rt: ResourceType) -> native_enums::ResourceType {
    match rt {
        ResourceType::File => native_enums::ResourceType::File,
        ResourceType::Blob => native_enums::ResourceType::Blob,
        ResourceType::Uri => native_enums::ResourceType::Uri,
        ResourceType::Database => native_enums::ResourceType::Database,
        ResourceType::Api => native_enums::ResourceType::Api,
        ResourceType::Memory => native_enums::ResourceType::Memory,
        ResourceType::Artifact => native_enums::ResourceType::Artifact,
    }
}

fn wit_resource_ref_to_native(rr: ResourceReference) -> native_content::ResourceReference {
    native_content::ResourceReference {
        resource_request_id: rr.resource_request_id,
        uri: rr.uri,
        name: rr.name,
        resource_type: wit_resource_type_to_native(rr.resource_type),
        range_start: rr.range_start,
        range_end: rr.range_end,
        selector: rr.selector,
    }
}

fn wit_prompt_request_to_native(pr: PromptRequest) -> native_content::PromptRequest {
    let arguments: HashMap<String, serde_json::Value> =
        serde_json::from_str(&pr.arguments).unwrap_or_default();
    native_content::PromptRequest {
        prompt_request_id: pr.prompt_request_id,
        name: pr.name,
        arguments,
        server_id: pr.server_id,
    }
}

fn wit_prompt_result_to_native(pr: PromptResult) -> native_content::PromptResult {
    let messages: Vec<native_msg::Message> =
        serde_json::from_str(&pr.messages).unwrap_or_default();
    native_content::PromptResult {
        prompt_request_id: pr.prompt_request_id,
        prompt_name: pr.prompt_name,
        messages,
        content: pr.content,
        is_error: pr.is_error,
        error_message: pr.error_message,
    }
}

// ---------------------------------------------------------------------------
// WIT → Native: Extensions
// ---------------------------------------------------------------------------

pub fn wit_extensions_to_native(ext: Extensions) -> NativeExtensions {
    NativeExtensions {
        request: ext.request.map(|r| Arc::new(wit_request_to_native(r))),
        security: ext.security.map(|s| Arc::new(wit_security_to_native(s))),
        http: ext.http.map(|h| Arc::new(wit_http_to_native(h))),
        meta: ext.meta.map(|m| Arc::new(wit_meta_to_native(m))),
        ..Default::default()
    }
}

fn wit_request_to_native(r: RequestExtension) -> NativeRequestExtension {
    NativeRequestExtension {
        environment: r.environment,
        request_id: r.request_id,
        timestamp: r.timestamp,
        trace_id: r.trace_id,
        span_id: r.span_id,
    }
}

fn wit_security_to_native(s: SecurityExtension) -> NativeSecurityExtension {
    NativeSecurityExtension {
        labels: MonotonicSet::from_set(s.labels.into_iter().collect()),
        classification: s.classification,
        subject: s.subject.map(wit_subject_to_native),
        auth_method: s.auth_method,
        ..Default::default()
    }
}

fn wit_subject_to_native(s: SubjectExtension) -> NativeSubjectExtension {
    NativeSubjectExtension {
        id: s.id,
        subject_type: s.subject_type.map(wit_subject_type_to_native),
        roles: s.roles.into_iter().collect::<HashSet<_>>(),
        permissions: s.permissions.into_iter().collect::<HashSet<_>>(),
        teams: s.teams.into_iter().collect::<HashSet<_>>(),
        claims: s.claims.into_iter().collect::<HashMap<_, _>>(),
    }
}

fn wit_subject_type_to_native(st: SubjectType) -> NativeSubjectType {
    match st {
        SubjectType::User => NativeSubjectType::User,
        SubjectType::Agent => NativeSubjectType::Agent,
        SubjectType::Service => NativeSubjectType::Service,
        SubjectType::System => NativeSubjectType::System,
    }
}

fn wit_http_to_native(h: HttpExtension) -> NativeHttpExtension {
    NativeHttpExtension {
        request_headers: h.request_headers.into_iter().collect::<HashMap<_, _>>(),
        response_headers: h.response_headers.into_iter().collect::<HashMap<_, _>>(),
    }
}

fn wit_meta_to_native(m: MetaExtension) -> NativeMetaExtension {
    NativeMetaExtension {
        entity_type: m.entity_type,
        entity_name: m.entity_name,
        tags: m.tags.into_iter().collect::<HashSet<_>>(),
        scope: m.scope,
        properties: m.properties.into_iter().collect::<HashMap<_, _>>(),
    }
}

// ---------------------------------------------------------------------------
// WIT → Native: PluginContext
// ---------------------------------------------------------------------------

pub fn wit_context_to_native(ctx: PluginContext) -> NativePluginContext {
    let local_state = serde_json::from_str(&ctx.local_state).unwrap_or_default();
    let global_state = serde_json::from_str(&ctx.global_state).unwrap_or_default();
    NativePluginContext {
        local_state,
        global_state,
    }
}

// ---------------------------------------------------------------------------
// Native → WIT: PluginResult<MessagePayload> → PluginResult (record)
// ---------------------------------------------------------------------------

pub fn native_result_to_wit(result: NativePluginResult<native_msg::MessagePayload>) -> PluginResult {
    PluginResult {
        continue_processing: result.continue_processing,
        modified_payload: result.modified_payload.map(native_payload_to_wit),
        modified_extensions: result.modified_extensions.map(|ext| native_owned_extensions_to_wit(&ext)),
        violation: result.violation.map(native_violation_to_wit),
        metadata: result.metadata.map(|v| serde_json::to_string(&v).unwrap_or_default()),
    }
}

fn native_violation_to_wit(v: NativePluginViolation) -> PluginViolation {
    PluginViolation {
        code: v.code,
        reason: v.reason,
        description: v.description,
        details: serde_json::to_string(&v.details).unwrap_or_else(|_| "{}".to_string()),
        proto_error_code: v.proto_error_code,
    }
}

// ---------------------------------------------------------------------------
// Native → WIT: MessagePayload
// ---------------------------------------------------------------------------

fn native_payload_to_wit(payload: native_msg::MessagePayload) -> MessagePayload {
    MessagePayload {
        message: native_message_to_wit(payload.message),
    }
}

fn native_message_to_wit(msg: native_msg::Message) -> Message {
    Message {
        schema_version: msg.schema_version,
        role: native_role_to_wit(msg.role),
        content: msg.content.into_iter().map(native_content_part_to_wit).collect(),
        channel: msg.channel.map(native_channel_to_wit),
    }
}

fn native_role_to_wit(role: native_enums::Role) -> Role {
    match role {
        native_enums::Role::System => Role::System,
        native_enums::Role::Developer => Role::Developer,
        native_enums::Role::User => Role::User,
        native_enums::Role::Assistant => Role::Assistant,
        native_enums::Role::Tool => Role::Tool,
    }
}

fn native_channel_to_wit(channel: native_enums::Channel) -> Channel {
    match channel {
        native_enums::Channel::Analysis => Channel::Analysis,
        native_enums::Channel::Commentary => Channel::Commentary,
        native_enums::Channel::Final => Channel::Final,
    }
}

fn native_content_part_to_wit(part: native_content::ContentPart) -> ContentPart {
    match part {
        native_content::ContentPart::Text { text } => ContentPart::Text(text),
        native_content::ContentPart::Thinking { text } => ContentPart::Thinking(text),
        native_content::ContentPart::ToolCall { content } => {
            ContentPart::ToolCall(native_tool_call_to_wit(content))
        }
        native_content::ContentPart::ToolResult { content } => {
            ContentPart::ToolResult(native_tool_result_to_wit(content))
        }
        native_content::ContentPart::Resource { content } => {
            ContentPart::CmfResource(native_resource_to_wit(content))
        }
        native_content::ContentPart::ResourceRef { content } => {
            ContentPart::ResourceRef(native_resource_ref_to_wit(content))
        }
        native_content::ContentPart::PromptRequest { content } => {
            ContentPart::PromptRequest(native_prompt_request_to_wit(content))
        }
        native_content::ContentPart::PromptResult { content } => {
            ContentPart::PromptResult(native_prompt_result_to_wit(content))
        }
        native_content::ContentPart::Image { content } => ContentPart::Image(ImageSource {
            source_type: content.source_type,
            data: content.data,
            media_type: content.media_type,
        }),
        native_content::ContentPart::Video { content } => ContentPart::Video(VideoSource {
            source_type: content.source_type,
            data: content.data,
            media_type: content.media_type,
            duration_ms: content.duration_ms,
        }),
        native_content::ContentPart::Audio { content } => ContentPart::Audio(AudioSource {
            source_type: content.source_type,
            data: content.data,
            media_type: content.media_type,
            duration_ms: content.duration_ms,
        }),
        native_content::ContentPart::Document { content } => {
            ContentPart::Document(DocumentSource {
                source_type: content.source_type,
                data: content.data,
                media_type: content.media_type,
                title: content.title,
            })
        }
    }
}

fn native_tool_call_to_wit(tc: native_content::ToolCall) -> ToolCall {
    ToolCall {
        tool_call_id: tc.tool_call_id,
        name: tc.name,
        arguments: serde_json::to_string(&tc.arguments).unwrap_or_else(|_| "{}".to_string()),
        namespace: tc.namespace,
    }
}

fn native_tool_result_to_wit(tr: native_content::ToolResult) -> ToolResult {
    ToolResult {
        tool_call_id: tr.tool_call_id,
        tool_name: tr.tool_name,
        content: serde_json::to_string(&tr.content).unwrap_or_default(),
        is_error: tr.is_error,
    }
}

fn native_resource_to_wit(r: native_content::Resource) -> CmfResource {
    CmfResource {
        resource_request_id: r.resource_request_id,
        uri: r.uri,
        name: r.name,
        description: r.description,
        resource_type: native_resource_type_to_wit(r.resource_type),
        content: r.content,
        blob: r.blob,
        mime_type: r.mime_type,
        size_bytes: r.size_bytes,
        annotations: serde_json::to_string(&r.annotations).unwrap_or_else(|_| "{}".to_string()),
        version: r.version,
    }
}

fn native_resource_type_to_wit(rt: native_enums::ResourceType) -> ResourceType {
    match rt {
        native_enums::ResourceType::File => ResourceType::File,
        native_enums::ResourceType::Blob => ResourceType::Blob,
        native_enums::ResourceType::Uri => ResourceType::Uri,
        native_enums::ResourceType::Database => ResourceType::Database,
        native_enums::ResourceType::Api => ResourceType::Api,
        native_enums::ResourceType::Memory => ResourceType::Memory,
        native_enums::ResourceType::Artifact => ResourceType::Artifact,
    }
}

fn native_resource_ref_to_wit(rr: native_content::ResourceReference) -> ResourceReference {
    ResourceReference {
        resource_request_id: rr.resource_request_id,
        uri: rr.uri,
        name: rr.name,
        resource_type: native_resource_type_to_wit(rr.resource_type),
        range_start: rr.range_start,
        range_end: rr.range_end,
        selector: rr.selector,
    }
}

fn native_prompt_request_to_wit(pr: native_content::PromptRequest) -> PromptRequest {
    PromptRequest {
        prompt_request_id: pr.prompt_request_id,
        name: pr.name,
        arguments: serde_json::to_string(&pr.arguments).unwrap_or_else(|_| "{}".to_string()),
        server_id: pr.server_id,
    }
}

fn native_prompt_result_to_wit(pr: native_content::PromptResult) -> PromptResult {
    PromptResult {
        prompt_request_id: pr.prompt_request_id,
        prompt_name: pr.prompt_name,
        messages: serde_json::to_string(&pr.messages).unwrap_or_else(|_| "[]".to_string()),
        content: pr.content,
        is_error: pr.is_error,
        error_message: pr.error_message,
    }
}

// ---------------------------------------------------------------------------
// Native → WIT: OwnedExtensions → Extensions
// ---------------------------------------------------------------------------

fn native_owned_extensions_to_wit(
    ext: &cpex_payload::extensions::container::OwnedExtensions,
) -> Extensions {
    Extensions {
        request: ext.request.as_ref().map(|r| native_request_to_wit(r)),
        security: ext.security.as_ref().map(|s| native_security_to_wit(s)),
        http: ext.http.as_ref().map(|h| native_http_to_wit(h.read())),
        meta: ext.meta.as_ref().map(|m| native_meta_to_wit(m)),
    }
}

fn native_request_to_wit(r: &NativeRequestExtension) -> RequestExtension {
    RequestExtension {
        environment: r.environment.clone(),
        request_id: r.request_id.clone(),
        timestamp: r.timestamp.clone(),
        trace_id: r.trace_id.clone(),
        span_id: r.span_id.clone(),
    }
}

fn native_security_to_wit(s: &NativeSecurityExtension) -> SecurityExtension {
    SecurityExtension {
        labels: s.labels.iter().cloned().collect(),
        classification: s.classification.clone(),
        subject: s.subject.as_ref().map(native_subject_to_wit),
        auth_method: s.auth_method.clone(),
    }
}

fn native_subject_to_wit(s: &NativeSubjectExtension) -> SubjectExtension {
    SubjectExtension {
        id: s.id.clone(),
        subject_type: s.subject_type.as_ref().map(native_subject_type_to_wit),
        roles: s.roles.iter().cloned().collect(),
        permissions: s.permissions.iter().cloned().collect(),
        teams: s.teams.iter().cloned().collect(),
        claims: s.claims.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    }
}

fn native_subject_type_to_wit(st: &NativeSubjectType) -> SubjectType {
    match st {
        NativeSubjectType::User => SubjectType::User,
        NativeSubjectType::Agent => SubjectType::Agent,
        NativeSubjectType::Service => SubjectType::Service,
        NativeSubjectType::System => SubjectType::System,
    }
}

fn native_http_to_wit(h: &NativeHttpExtension) -> HttpExtension {
    HttpExtension {
        request_headers: h.request_headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        response_headers: h.response_headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    }
}

fn native_meta_to_wit(m: &NativeMetaExtension) -> MetaExtension {
    MetaExtension {
        entity_type: m.entity_type.clone(),
        entity_name: m.entity_name.clone(),
        tags: m.tags.iter().cloned().collect(),
        scope: m.scope.clone(),
        properties: m.properties.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    }
}
