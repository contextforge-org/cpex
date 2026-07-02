// Location: ./crates/cpex-wasm-host/src/conversions.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Host-side type conversions: native cpex-core types ↔ WIT types.
// Used by WasmBridgeHandler to translate between the PluginManager's native
// types and the WIT types that the WASM sandbox expects.

use std::sync::Arc;

use chrono::DateTime;

use cpex_core::cmf::content as native_content;
use cpex_core::cmf::enums as native_enums;
use cpex_core::cmf::message as native_msg;
use cpex_core::context::PluginContext as NativePluginContext;
use cpex_core::error::PluginViolation as NativePluginViolation;
use cpex_core::extensions::agent::AgentExtension as NativeAgentExtension;
use cpex_core::extensions::authorization::AuthorizationDetail as NativeAuthDetail;
use cpex_core::extensions::completion::{
    CompletionExtension as NativeCompletionExtension, StopReason as NativeStopReason,
    TokenUsage as NativeTokenUsage,
};
use cpex_core::extensions::container::{
    Extensions as NativeExtensions, OwnedExtensions as NativeOwnedExtensions,
};
use cpex_core::extensions::delegation::{
    DelegationExtension as NativeDelegationExtension, DelegationHop as NativeDelegationHop,
    DelegationStrategy as NativeDelegationStrategy,
};
use cpex_core::extensions::framework::FrameworkExtension as NativeFrameworkExtension;
use cpex_core::extensions::http::HttpExtension as NativeHttpExtension;
use cpex_core::extensions::llm::LLMExtension as NativeLLMExtension;
use cpex_core::extensions::mcp::{
    MCPExtension as NativeMCPExtension, PromptMetadata as NativePromptMetadata,
    ResourceMetadata as NativeResourceMetadata, ToolMetadata as NativeToolMetadata,
};
use cpex_core::extensions::meta::MetaExtension as NativeMetaExtension;
use cpex_core::extensions::provenance::ProvenanceExtension as NativeProvenanceExtension;
use cpex_core::extensions::request::RequestExtension as NativeRequestExtension;
use cpex_core::extensions::security::{
    ClientExtension as NativeClientExtension, ClientTrustLevel as NativeClientTrustLevel,
    DataPolicy as NativeDataPolicy, ObjectSecurityProfile as NativeObjectSecurityProfile,
    RetentionPolicy as NativeRetentionPolicy, SecurityExtension as NativeSecurityExtension,
    SubjectExtension as NativeSubjectExtension, SubjectType as NativeSubjectType,
    WorkloadIdentity as NativeWorkloadIdentity,
};
use cpex_core::hooks::trait_def::PluginResult as NativePluginResult;

use crate::payload_registry::PayloadSerializerRegistry;
use crate::sandbox_manager::types::*;

// ---------------------------------------------------------------------------
// Native → WIT: MessagePayload
// ---------------------------------------------------------------------------

pub fn native_payload_to_wit(payload: &native_msg::MessagePayload) -> MessagePayload {
    MessagePayload { message: native_message_to_wit(&payload.message) }
}

fn native_message_to_wit(msg: &native_msg::Message) -> Message {
    Message {
        schema_version: msg.schema_version.clone(),
        role: native_role_to_wit(msg.role),
        content: msg.content.iter().map(native_content_part_to_wit).collect(),
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

fn native_content_part_to_wit(part: &native_content::ContentPart) -> ContentPart {
    match part {
        native_content::ContentPart::Text { text } => ContentPart::Text(text.clone()),
        native_content::ContentPart::Thinking { text } => ContentPart::Thinking(text.clone()),
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
            source_type: content.source_type.clone(),
            data: content.data.clone(),
            media_type: content.media_type.clone(),
        }),
        native_content::ContentPart::Video { content } => ContentPart::Video(VideoSource {
            source_type: content.source_type.clone(),
            data: content.data.clone(),
            media_type: content.media_type.clone(),
            duration_ms: content.duration_ms,
        }),
        native_content::ContentPart::Audio { content } => ContentPart::Audio(AudioSource {
            source_type: content.source_type.clone(),
            data: content.data.clone(),
            media_type: content.media_type.clone(),
            duration_ms: content.duration_ms,
        }),
        native_content::ContentPart::Document { content } => {
            ContentPart::Document(DocumentSource {
                source_type: content.source_type.clone(),
                data: content.data.clone(),
                media_type: content.media_type.clone(),
                title: content.title.clone(),
            })
        }
    }
}

fn native_tool_call_to_wit(tc: &native_content::ToolCall) -> ToolCall {
    ToolCall {
        tool_call_id: tc.tool_call_id.clone(),
        name: tc.name.clone(),
        arguments: serde_json::to_string(&tc.arguments).unwrap_or_else(|_| "{}".to_string()),
        namespace: tc.namespace.clone(),
    }
}

fn native_tool_result_to_wit(tr: &native_content::ToolResult) -> ToolResult {
    ToolResult {
        tool_call_id: tr.tool_call_id.clone(),
        tool_name: tr.tool_name.clone(),
        content: serde_json::to_string(&tr.content).unwrap_or_default(),
        is_error: tr.is_error,
    }
}

fn native_resource_to_wit(r: &native_content::Resource) -> CmfResource {
    CmfResource {
        resource_request_id: r.resource_request_id.clone(),
        uri: r.uri.clone(),
        name: r.name.clone(),
        description: r.description.clone(),
        resource_type: native_resource_type_to_wit(r.resource_type),
        content: r.content.clone(),
        blob: r.blob.clone(),
        mime_type: r.mime_type.clone(),
        size_bytes: r.size_bytes,
        annotations: serde_json::to_string(&r.annotations).unwrap_or_else(|_| "{}".to_string()),
        version: r.version.clone(),
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

fn native_resource_ref_to_wit(rr: &native_content::ResourceReference) -> ResourceReference {
    ResourceReference {
        resource_request_id: rr.resource_request_id.clone(),
        uri: rr.uri.clone(),
        name: rr.name.clone(),
        resource_type: native_resource_type_to_wit(rr.resource_type),
        range_start: rr.range_start,
        range_end: rr.range_end,
        selector: rr.selector.clone(),
    }
}

fn native_prompt_request_to_wit(pr: &native_content::PromptRequest) -> PromptRequest {
    PromptRequest {
        prompt_request_id: pr.prompt_request_id.clone(),
        name: pr.name.clone(),
        arguments: serde_json::to_string(&pr.arguments).unwrap_or_else(|_| "{}".to_string()),
        server_id: pr.server_id.clone(),
    }
}

fn native_prompt_result_to_wit(pr: &native_content::PromptResult) -> PromptResult {
    PromptResult {
        prompt_request_id: pr.prompt_request_id.clone(),
        prompt_name: pr.prompt_name.clone(),
        messages: serde_json::to_string(&pr.messages).unwrap_or_else(|_| "[]".to_string()),
        content: pr.content.clone(),
        is_error: pr.is_error,
        error_message: pr.error_message.clone(),
    }
}

// ---------------------------------------------------------------------------
// Native → WIT: Extensions
// ---------------------------------------------------------------------------

pub fn native_extensions_to_wit(ext: &NativeExtensions) -> Extensions {
    Extensions {
        request: ext.request.as_ref().map(|r| native_request_to_wit(r)),
        security: ext.security.as_ref().map(|s| native_security_to_wit(s)),
        http: ext.http.as_ref().map(|h| native_http_to_wit(h)),
        meta: ext.meta.as_ref().map(|m| native_meta_to_wit(m)),
        agent: ext.agent.as_ref().map(|a| native_agent_to_wit(a)),
        mcp: ext.mcp.as_ref().map(|m| native_mcp_to_wit(m)),
        completion: ext.completion.as_ref().map(|c| native_completion_to_wit(c)),
        provenance: ext.provenance.as_ref().map(|p| native_provenance_to_wit(p)),
        llm: ext.llm.as_ref().map(|l| native_llm_to_wit(l)),
        framework: ext.framework.as_ref().map(|f| native_framework_to_wit(f)),
        delegation: ext.delegation.as_ref().map(|d| native_delegation_to_wit(d)),
        custom: ext.custom.as_ref().and_then(|c| serde_json::to_string(c.as_ref()).ok()),
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
        client: s.client.as_ref().map(native_client_to_wit),
        caller_workload: s.caller_workload.as_ref().map(native_workload_to_wit),
        this_workload: s.this_workload.as_ref().map(native_workload_to_wit),
        auth_method: s.auth_method.clone(),
        objects: s.objects.iter()
            .map(|(k, v)| (k.clone(), native_object_profile_to_wit(v)))
            .collect(),
        data: s.data.iter()
            .map(|(k, v)| (k.clone(), native_data_policy_to_wit(v)))
            .collect(),
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

fn native_client_to_wit(c: &NativeClientExtension) -> ClientExtension {
    let (trust_level, trust_level_custom) = match &c.trust_level {
        NativeClientTrustLevel::FirstParty => (ClientTrustLevel::FirstParty, None),
        NativeClientTrustLevel::ThirdParty => (ClientTrustLevel::ThirdParty, None),
        NativeClientTrustLevel::Internal => (ClientTrustLevel::Internal, None),
        NativeClientTrustLevel::Custom(s) => (ClientTrustLevel::ThirdParty, Some(s.clone())),
        _ => (ClientTrustLevel::ThirdParty, None),
    };
    ClientExtension {
        client_id: c.client_id.clone(),
        client_name: c.client_name.clone(),
        trust_level,
        trust_level_custom,
        authorized_scopes: c.authorized_scopes.clone(),
        authorized_audiences: c.authorized_audiences.clone(),
        roles: c.roles.clone(),
        permissions: c.permissions.clone(),
        teams: c.teams.clone(),
        claims: c.claims.iter()
            .map(|(k, v)| (k.clone(), serde_json::to_string(v).unwrap_or_default()))
            .collect(),
    }
}

fn native_workload_to_wit(w: &NativeWorkloadIdentity) -> WorkloadIdentity {
    WorkloadIdentity {
        spiffe_id: w.spiffe_id.clone(),
        trust_domain: w.trust_domain.clone(),
        attested_at: w.attested_at.map(|dt| dt.to_rfc3339()),
        attestor: w.attestor.clone(),
        selectors: w.selectors.clone(),
        client_id: w.client_id.clone(),
    }
}

fn native_object_profile_to_wit(o: &NativeObjectSecurityProfile) -> ObjectSecurityProfile {
    ObjectSecurityProfile {
        managed_by: o.managed_by.clone(),
        permissions: o.permissions.clone(),
        trust_domain: o.trust_domain.clone(),
        data_scope: o.data_scope.clone(),
    }
}

fn native_data_policy_to_wit(d: &NativeDataPolicy) -> DataPolicy {
    DataPolicy {
        apply_labels: d.apply_labels.clone(),
        allowed_actions: d.allowed_actions.clone(),
        denied_actions: d.denied_actions.clone(),
        retention: d.retention.as_ref().map(|r| RetentionPolicy {
            max_age_seconds: r.max_age_seconds,
            policy: r.policy.clone(),
            delete_after: r.delete_after.clone(),
        }),
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

fn native_agent_to_wit(a: &NativeAgentExtension) -> AgentExtension {
    AgentExtension {
        input: a.input.clone(),
        session_id: a.session_id.clone(),
        conversation_id: a.conversation_id.clone(),
        turn: a.turn,
        agent_id: a.agent_id.clone(),
        parent_agent_id: a.parent_agent_id.clone(),
        conversation: a.conversation.as_ref().map(|c| ConversationContext {
            history: c.history.iter()
                .map(|v| serde_json::to_string(v).unwrap_or_default())
                .collect(),
            summary: c.summary.clone(),
            topics: c.topics.clone(),
        }),
    }
}

fn native_mcp_to_wit(m: &NativeMCPExtension) -> McpExtension {
    McpExtension {
        tool: m.tool.as_ref().map(native_tool_metadata_to_wit),
        resource_info: m.resource.as_ref().map(native_resource_metadata_to_wit),
        prompt: m.prompt.as_ref().map(native_prompt_metadata_to_wit),
    }
}

fn native_tool_metadata_to_wit(t: &NativeToolMetadata) -> ToolMetadata {
    ToolMetadata {
        name: t.name.clone(),
        title: t.title.clone(),
        description: t.description.clone(),
        input_schema: t.input_schema.as_ref().and_then(|v| serde_json::to_string(v).ok()),
        output_schema: t.output_schema.as_ref().and_then(|v| serde_json::to_string(v).ok()),
        server_id: t.server_id.clone(),
        namespace: t.namespace.clone(),
        annotations: t.annotations.iter()
            .map(|(k, v)| (k.clone(), serde_json::to_string(v).unwrap_or_default()))
            .collect(),
    }
}

fn native_resource_metadata_to_wit(r: &NativeResourceMetadata) -> ResourceMetadata {
    ResourceMetadata {
        uri: r.uri.clone(),
        name: r.name.clone(),
        description: r.description.clone(),
        mime_type: r.mime_type.clone(),
        server_id: r.server_id.clone(),
        annotations: r.annotations.iter()
            .map(|(k, v)| (k.clone(), serde_json::to_string(v).unwrap_or_default()))
            .collect(),
    }
}

fn native_prompt_metadata_to_wit(p: &NativePromptMetadata) -> PromptMetadata {
    PromptMetadata {
        name: p.name.clone(),
        description: p.description.clone(),
        arguments: p.arguments.as_ref().and_then(|v| serde_json::to_string(v).ok()),
        server_id: p.server_id.clone(),
        annotations: p.annotations.iter()
            .map(|(k, v)| (k.clone(), serde_json::to_string(v).unwrap_or_default()))
            .collect(),
    }
}

fn native_completion_to_wit(c: &NativeCompletionExtension) -> CompletionExtension {
    CompletionExtension {
        stop_reason: c.stop_reason.map(|r| match r {
            NativeStopReason::End => StopReason::End,
            NativeStopReason::Return => StopReason::ReturnComplete,
            NativeStopReason::Call => StopReason::Call,
            NativeStopReason::MaxTokens => StopReason::MaxTokens,
            NativeStopReason::StopSequence => StopReason::StopSequence,
        }),
        tokens: c.tokens.as_ref().map(|t| TokenUsage {
            input_tokens: t.input_tokens,
            output_tokens: t.output_tokens,
            total_tokens: t.total_tokens,
        }),
        model: c.model.clone(),
        raw_format: c.raw_format.clone(),
        created_at: c.created_at.clone(),
        latency_ms: c.latency_ms,
    }
}

fn native_provenance_to_wit(p: &NativeProvenanceExtension) -> ProvenanceExtension {
    ProvenanceExtension {
        source: p.source.clone(),
        message_id: p.message_id.clone(),
        parent_id: p.parent_id.clone(),
    }
}

fn native_llm_to_wit(l: &NativeLLMExtension) -> LlmExtension {
    LlmExtension {
        model_id: l.model_id.clone(),
        provider: l.provider.clone(),
        capabilities: l.capabilities.clone(),
    }
}

fn native_framework_to_wit(f: &NativeFrameworkExtension) -> FrameworkExtension {
    FrameworkExtension {
        framework: f.framework.clone(),
        framework_version: f.framework_version.clone(),
        node_id: f.node_id.clone(),
        graph_id: f.graph_id.clone(),
        metadata: if f.metadata.is_empty() {
            None
        } else {
            serde_json::to_string(&f.metadata).ok()
        },
    }
}

fn native_delegation_to_wit(d: &NativeDelegationExtension) -> DelegationExtension {
    DelegationExtension {
        chain: d.chain.iter().map(native_delegation_hop_to_wit).collect(),
        depth: d.depth,
        origin_subject_id: d.origin_subject_id.clone(),
        actor_subject_id: d.actor_subject_id.clone(),
        delegated: d.delegated,
        age_seconds: d.age_seconds.to_string(),
    }
}

fn native_delegation_hop_to_wit(hop: &NativeDelegationHop) -> DelegationHop {
    let (strategy, strategy_custom) = match &hop.strategy {
        None => (None, None),
        Some(NativeDelegationStrategy::TokenExchange) => (Some(DelegationStrategy::TokenExchange), None),
        Some(NativeDelegationStrategy::ClientCredentials) => (Some(DelegationStrategy::ClientCredentials), None),
        Some(NativeDelegationStrategy::SpiffeSvid) => (Some(DelegationStrategy::SpiffeSvid), None),
        Some(NativeDelegationStrategy::Passthrough) => (Some(DelegationStrategy::Passthrough), None),
        Some(NativeDelegationStrategy::Ucan) => (Some(DelegationStrategy::Ucan), None),
        Some(NativeDelegationStrategy::TransactionToken) => (Some(DelegationStrategy::TransactionToken), None),
        Some(NativeDelegationStrategy::Custom(s)) => (None, Some(s.clone())),
        Some(_) => (None, None),
    };
    DelegationHop {
        subject_id: hop.subject_id.clone(),
        subject_type: hop.subject_type.as_ref().map(native_subject_type_to_wit),
        audience: hop.audience.clone(),
        scopes_granted: hop.scopes_granted.clone(),
        authorization_details: hop.authorization_details.iter()
            .map(native_auth_detail_to_wit)
            .collect(),
        timestamp: hop.timestamp.to_rfc3339(),
        ttl_seconds: hop.ttl_seconds,
        strategy,
        strategy_custom,
        from_cache: hop.from_cache,
    }
}

fn native_auth_detail_to_wit(a: &NativeAuthDetail) -> AuthorizationDetail {
    AuthorizationDetail {
        detail_type: a.detail_type.clone(),
        locations: a.locations.clone(),
        actions: a.actions.clone(),
        datatypes: a.datatypes.clone(),
        identifier: a.identifier.clone(),
        privileges: a.privileges.clone(),
        extra: if a.extra.is_empty() {
            None
        } else {
            serde_json::to_string(&a.extra).ok()
        },
    }
}

// ---------------------------------------------------------------------------
// Native → WIT: PluginContext
// ---------------------------------------------------------------------------

pub fn native_context_to_wit(ctx: &NativePluginContext) -> PluginContext {
    PluginContext {
        local_state: ctx.local_state.iter()
            .map(|(k, v)| ContextEntry {
                key: k.clone(),
                value: serde_json::to_string(v).unwrap_or_default(),
            })
            .collect(),
        global_state: ctx.global_state.iter()
            .map(|(k, v)| ContextEntry {
                key: k.clone(),
                value: serde_json::to_string(v).unwrap_or_default(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// WIT → Native: HookResult
// ---------------------------------------------------------------------------

pub fn wit_hook_result_to_native(
    result: crate::sandbox_manager::types::HookResult,
    registry: &PayloadSerializerRegistry,
) -> (NativePluginResult<native_msg::MessagePayload>, Option<NativePluginContext>) {
    let modified_payload = result.modified_payload.and_then(|hp| match hp {
        HookPayload::Cmf(mp) => Some(wit_cmf_payload_to_native(mp)),
        HookPayload::Generic(gp) => {
            match registry.deserialize(&gp.payload_type, &gp.payload_data) {
                Ok(boxed) => boxed.as_any().downcast_ref::<native_msg::MessagePayload>().cloned(),
                Err(e) => {
                    eprintln!("[HOST] generic payload writeback failed for '{}': {}", gp.payload_type, e);
                    None
                }
            }
        }
    });

    let modified_extensions = result.modified_extensions.map(wit_extensions_to_owned);

    let native_result = NativePluginResult {
        continue_processing: result.continue_processing,
        modified_payload,
        modified_extensions,
        violation: result.violation.map(wit_violation_to_native),
        metadata: result.metadata.and_then(|s| serde_json::from_str(&s).ok()),
    };

    let modified_ctx = result.modified_context.map(wit_context_to_native);
    (native_result, modified_ctx)
}

fn wit_violation_to_native(v: PluginViolation) -> NativePluginViolation {
    NativePluginViolation {
        code: v.code,
        reason: v.reason,
        description: v.description,
        details: serde_json::from_str(&v.details).unwrap_or_default(),
        plugin_name: v.plugin_name,
        proto_error_code: v.proto_error_code,
    }
}

pub fn wit_context_to_native(ctx: PluginContext) -> NativePluginContext {
    NativePluginContext {
        local_state: ctx.local_state.into_iter()
            .map(|e| (e.key, serde_json::from_str(&e.value).unwrap_or(serde_json::Value::String(e.value))))
            .collect(),
        global_state: ctx.global_state.into_iter()
            .map(|e| (e.key, serde_json::from_str(&e.value).unwrap_or(serde_json::Value::String(e.value))))
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// WIT → Native: MessagePayload (for modified_payload in results)
// ---------------------------------------------------------------------------

pub fn wit_cmf_payload_to_native(payload: MessagePayload) -> native_msg::MessagePayload {
    native_msg::MessagePayload { message: wit_message_to_native(payload.message) }
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
            content: native_content::ToolCall {
                tool_call_id: tc.tool_call_id,
                name: tc.name,
                arguments: serde_json::from_str(&tc.arguments).unwrap_or_default(),
                namespace: tc.namespace,
            },
        },
        ContentPart::ToolResult(tr) => native_content::ContentPart::ToolResult {
            content: native_content::ToolResult {
                tool_call_id: tr.tool_call_id,
                tool_name: tr.tool_name,
                content: serde_json::from_str(&tr.content)
                    .unwrap_or(serde_json::Value::String(tr.content)),
                is_error: tr.is_error,
            },
        },
        ContentPart::CmfResource(r) => native_content::ContentPart::Resource {
            content: native_content::Resource {
                resource_request_id: r.resource_request_id,
                uri: r.uri,
                name: r.name,
                description: r.description,
                resource_type: wit_resource_type_to_native(r.resource_type),
                content: r.content,
                blob: r.blob,
                mime_type: r.mime_type,
                size_bytes: r.size_bytes,
                annotations: serde_json::from_str(&r.annotations).unwrap_or_default(),
                version: r.version,
            },
        },
        ContentPart::ResourceRef(rr) => native_content::ContentPart::ResourceRef {
            content: native_content::ResourceReference {
                resource_request_id: rr.resource_request_id,
                uri: rr.uri,
                name: rr.name,
                resource_type: wit_resource_type_to_native(rr.resource_type),
                range_start: rr.range_start,
                range_end: rr.range_end,
                selector: rr.selector,
            },
        },
        ContentPart::PromptRequest(pr) => native_content::ContentPart::PromptRequest {
            content: native_content::PromptRequest {
                prompt_request_id: pr.prompt_request_id,
                name: pr.name,
                arguments: serde_json::from_str(&pr.arguments).unwrap_or_default(),
                server_id: pr.server_id,
            },
        },
        ContentPart::PromptResult(pr) => native_content::ContentPart::PromptResult {
            content: native_content::PromptResult {
                prompt_request_id: pr.prompt_request_id,
                prompt_name: pr.prompt_name,
                messages: serde_json::from_str(&pr.messages).unwrap_or_default(),
                content: pr.content,
                is_error: pr.is_error,
                error_message: pr.error_message,
            },
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

// ---------------------------------------------------------------------------
// WIT → Native: Extensions (writeback from guest)
// ---------------------------------------------------------------------------

fn wit_extensions_to_owned(ext: Extensions) -> NativeOwnedExtensions {
    use cpex_core::extensions::guarded::Guarded;

    let request = ext.request.map(|r| Arc::new(NativeRequestExtension {
        environment: r.environment,
        request_id: r.request_id,
        timestamp: r.timestamp,
        trace_id: r.trace_id,
        span_id: r.span_id,
    }));

    let security = ext.security.map(|s| wit_security_to_native(s));
    let http = ext.http.map(|h| Guarded::new(NativeHttpExtension {
        request_headers: h.request_headers.into_iter().collect(),
        response_headers: h.response_headers.into_iter().collect(),
    }));
    let meta = ext.meta.map(|m| Arc::new(NativeMetaExtension {
        entity_type: m.entity_type,
        entity_name: m.entity_name,
        tags: m.tags.into_iter().collect(),
        scope: m.scope,
        properties: m.properties.into_iter().collect(),
    }));
    let agent = ext.agent.map(|a| Arc::new(wit_agent_to_native(a)));
    let mcp = ext.mcp.map(|m| Arc::new(wit_mcp_to_native(m)));
    let completion = ext.completion.map(|c| Arc::new(wit_completion_to_native(c)));
    let provenance = ext.provenance.map(|p| Arc::new(NativeProvenanceExtension {
        source: p.source,
        message_id: p.message_id,
        parent_id: p.parent_id,
    }));
    let llm = ext.llm.map(|l| Arc::new(NativeLLMExtension {
        model_id: l.model_id,
        provider: l.provider,
        capabilities: l.capabilities,
    }));
    let framework = ext.framework.map(|f| Arc::new(wit_framework_to_native(f)));
    let delegation = ext.delegation.map(wit_delegation_to_native);
    let custom = ext.custom.and_then(|s| serde_json::from_str(&s).ok());

    NativeOwnedExtensions {
        request,
        agent,
        mcp,
        completion,
        provenance,
        llm,
        framework,
        meta,
        raw_credentials: None,
        http,
        security,
        delegation,
        custom,
        http_write_token: None,
        labels_write_token: None,
        delegation_write_token: None,
    }
}

fn wit_security_to_native(s: SecurityExtension) -> NativeSecurityExtension {
    NativeSecurityExtension {
        labels: cpex_core::extensions::monotonic::MonotonicSet::from_set(
            s.labels.into_iter().collect(),
        ),
        classification: s.classification,
        subject: s.subject.map(|sub| NativeSubjectExtension {
            id: sub.id,
            subject_type: sub.subject_type.map(|st| match st {
                SubjectType::User => NativeSubjectType::User,
                SubjectType::Agent => NativeSubjectType::Agent,
                SubjectType::Service => NativeSubjectType::Service,
                SubjectType::System => NativeSubjectType::System,
            }),
            roles: sub.roles.into_iter().collect(),
            permissions: sub.permissions.into_iter().collect(),
            teams: sub.teams.into_iter().collect(),
            claims: sub.claims.into_iter().collect(),
        }),
        client: s.client.map(|c| wit_client_to_native(c)),
        caller_workload: s.caller_workload.map(|w| wit_workload_to_native(w)),
        this_workload: s.this_workload.map(|w| wit_workload_to_native(w)),
        auth_method: s.auth_method,
        objects: s.objects.into_iter()
            .map(|(k, v)| (k, NativeObjectSecurityProfile {
                managed_by: v.managed_by,
                permissions: v.permissions,
                trust_domain: v.trust_domain,
                data_scope: v.data_scope,
            }))
            .collect(),
        data: s.data.into_iter()
            .map(|(k, v)| (k, NativeDataPolicy {
                apply_labels: v.apply_labels,
                allowed_actions: v.allowed_actions,
                denied_actions: v.denied_actions,
                retention: v.retention.map(|r| NativeRetentionPolicy {
                    max_age_seconds: r.max_age_seconds,
                    policy: r.policy,
                    delete_after: r.delete_after,
                }),
            }))
            .collect(),
    }
}

fn wit_client_to_native(c: ClientExtension) -> NativeClientExtension {
    let trust_level = match c.trust_level_custom {
        Some(s) => NativeClientTrustLevel::Custom(s),
        None => match c.trust_level {
            ClientTrustLevel::FirstParty => NativeClientTrustLevel::FirstParty,
            ClientTrustLevel::ThirdParty => NativeClientTrustLevel::ThirdParty,
            ClientTrustLevel::Internal => NativeClientTrustLevel::Internal,
        },
    };
    NativeClientExtension {
        client_id: c.client_id,
        client_name: c.client_name,
        trust_level,
        authorized_scopes: c.authorized_scopes,
        authorized_audiences: c.authorized_audiences,
        roles: c.roles,
        permissions: c.permissions,
        teams: c.teams,
        claims: c.claims.into_iter()
            .map(|(k, v)| (k, serde_json::from_str(&v).unwrap_or(serde_json::Value::String(v))))
            .collect(),
    }
}

fn wit_workload_to_native(w: WorkloadIdentity) -> NativeWorkloadIdentity {
    NativeWorkloadIdentity {
        spiffe_id: w.spiffe_id,
        trust_domain: w.trust_domain,
        attested_at: w.attested_at.as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
        attestor: w.attestor,
        selectors: w.selectors,
        client_id: w.client_id,
    }
}

fn wit_agent_to_native(a: AgentExtension) -> NativeAgentExtension {
    use cpex_core::extensions::agent::ConversationContext;
    NativeAgentExtension {
        input: a.input,
        session_id: a.session_id,
        conversation_id: a.conversation_id,
        turn: a.turn,
        agent_id: a.agent_id,
        parent_agent_id: a.parent_agent_id,
        conversation: a.conversation.map(|c| ConversationContext {
            history: c.history.iter()
                .map(|s| serde_json::from_str(s).unwrap_or(serde_json::Value::String(s.clone())))
                .collect(),
            summary: c.summary,
            topics: c.topics,
        }),
    }
}

fn wit_mcp_to_native(m: McpExtension) -> NativeMCPExtension {
    NativeMCPExtension {
        tool: m.tool.map(|t| NativeToolMetadata {
            name: t.name,
            title: t.title,
            description: t.description,
            input_schema: t.input_schema.and_then(|s| serde_json::from_str(&s).ok()),
            output_schema: t.output_schema.and_then(|s| serde_json::from_str(&s).ok()),
            server_id: t.server_id,
            namespace: t.namespace,
            annotations: t.annotations.into_iter()
                .map(|(k, v)| (k, serde_json::from_str(&v).unwrap_or(serde_json::Value::String(v))))
                .collect(),
        }),
        resource: m.resource_info.map(|r| NativeResourceMetadata {
            uri: r.uri,
            name: r.name,
            description: r.description,
            mime_type: r.mime_type,
            server_id: r.server_id,
            annotations: r.annotations.into_iter()
                .map(|(k, v)| (k, serde_json::from_str(&v).unwrap_or(serde_json::Value::String(v))))
                .collect(),
        }),
        prompt: m.prompt.map(|p| NativePromptMetadata {
            name: p.name,
            description: p.description,
            arguments: p.arguments.and_then(|s| serde_json::from_str(&s).ok()),
            server_id: p.server_id,
            annotations: p.annotations.into_iter()
                .map(|(k, v)| (k, serde_json::from_str(&v).unwrap_or(serde_json::Value::String(v))))
                .collect(),
        }),
    }
}

fn wit_completion_to_native(c: CompletionExtension) -> NativeCompletionExtension {
    NativeCompletionExtension {
        stop_reason: c.stop_reason.map(|r| match r {
            StopReason::End => NativeStopReason::End,
            StopReason::ReturnComplete => NativeStopReason::Return,
            StopReason::Call => NativeStopReason::Call,
            StopReason::MaxTokens => NativeStopReason::MaxTokens,
            StopReason::StopSequence => NativeStopReason::StopSequence,
        }),
        tokens: c.tokens.map(|t| NativeTokenUsage {
            input_tokens: t.input_tokens,
            output_tokens: t.output_tokens,
            total_tokens: t.total_tokens,
        }),
        model: c.model,
        raw_format: c.raw_format,
        created_at: c.created_at,
        latency_ms: c.latency_ms,
    }
}

fn wit_framework_to_native(f: FrameworkExtension) -> NativeFrameworkExtension {
    NativeFrameworkExtension {
        framework: f.framework,
        framework_version: f.framework_version,
        node_id: f.node_id,
        graph_id: f.graph_id,
        metadata: f.metadata.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
    }
}

fn wit_delegation_to_native(d: DelegationExtension) -> NativeDelegationExtension {
    NativeDelegationExtension {
        chain: d.chain.into_iter().map(|hop| {
            let strategy = match (hop.strategy, hop.strategy_custom) {
                (Some(DelegationStrategy::TokenExchange), _) => Some(NativeDelegationStrategy::TokenExchange),
                (Some(DelegationStrategy::ClientCredentials), _) => Some(NativeDelegationStrategy::ClientCredentials),
                (Some(DelegationStrategy::SpiffeSvid), _) => Some(NativeDelegationStrategy::SpiffeSvid),
                (Some(DelegationStrategy::Passthrough), _) => Some(NativeDelegationStrategy::Passthrough),
                (Some(DelegationStrategy::Ucan), _) => Some(NativeDelegationStrategy::Ucan),
                (Some(DelegationStrategy::TransactionToken), _) => Some(NativeDelegationStrategy::TransactionToken),
                (None, Some(s)) => Some(NativeDelegationStrategy::Custom(s)),
                (None, None) => None,
            };
            NativeDelegationHop {
                subject_id: hop.subject_id,
                subject_type: hop.subject_type.map(|st| match st {
                    SubjectType::User => NativeSubjectType::User,
                    SubjectType::Agent => NativeSubjectType::Agent,
                    SubjectType::Service => NativeSubjectType::Service,
                    SubjectType::System => NativeSubjectType::System,
                }),
                audience: hop.audience,
                scopes_granted: hop.scopes_granted,
                authorization_details: hop.authorization_details.into_iter()
                    .map(|a| NativeAuthDetail {
                        detail_type: a.detail_type,
                        locations: a.locations,
                        actions: a.actions,
                        datatypes: a.datatypes,
                        identifier: a.identifier,
                        privileges: a.privileges,
                        extra: a.extra
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default(),
                    })
                    .collect(),
                timestamp: DateTime::parse_from_rfc3339(&hop.timestamp)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                ttl_seconds: hop.ttl_seconds,
                strategy,
                from_cache: hop.from_cache,
            }
        }).collect(),
        depth: d.depth,
        origin_subject_id: d.origin_subject_id,
        actor_subject_id: d.actor_subject_id,
        delegated: d.delegated,
        age_seconds: d.age_seconds.parse().unwrap_or(0.0),
    }
}
