// Location: ./crates/cpex-wasm-plugin/src/conversions.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Bidirectional type conversions between WIT-generated types and cpex-core native types.
// WIT types are flat/serialized (e.g., JSON strings for maps); native types use
// proper Rust collections (HashMap, HashSet, Vec).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::DateTime;

use cpex_core::cmf::content as native_content;
use cpex_core::cmf::enums as native_enums;
use cpex_core::cmf::message as native_msg;
use cpex_core::context::PluginContext as NativePluginContext;
use cpex_core::extensions::agent::AgentExtension as NativeAgentExtension;
use cpex_core::extensions::authorization::AuthorizationDetail as NativeAuthDetail;
use cpex_core::extensions::completion::{
    CompletionExtension as NativeCompletionExtension, StopReason as NativeStopReason,
    TokenUsage as NativeTokenUsage,
};
use cpex_core::extensions::container::Extensions as NativeExtensions;
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

use crate::cpex::plugin::types::*;

// ---------------------------------------------------------------------------
// WIT → Native: MessagePayload
// ---------------------------------------------------------------------------

pub fn wit_payload_to_native(payload: MessagePayload) -> native_msg::MessagePayload {
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
// WIT → Native: Extensions (full coverage)
// ---------------------------------------------------------------------------

pub fn wit_extensions_to_native(ext: Extensions) -> NativeExtensions {
    NativeExtensions {
        request: ext.request.map(|r| Arc::new(NativeRequestExtension {
            environment: r.environment,
            request_id: r.request_id,
            timestamp: r.timestamp,
            trace_id: r.trace_id,
            span_id: r.span_id,
        })),
        security: ext.security.map(|s| Arc::new(wit_security_to_native(s))),
        http: ext.http.map(|h| Arc::new(NativeHttpExtension {
            request_headers: h.request_headers.into_iter().collect(),
            response_headers: h.response_headers.into_iter().collect(),
        })),
        meta: ext.meta.map(|m| Arc::new(NativeMetaExtension {
            entity_type: m.entity_type,
            entity_name: m.entity_name,
            tags: m.tags.into_iter().collect::<HashSet<_>>(),
            scope: m.scope,
            properties: m.properties.into_iter().collect::<HashMap<_, _>>(),
        })),
        agent: ext.agent.map(|a| Arc::new(wit_agent_to_native(a))),
        mcp: ext.mcp.map(|m| Arc::new(wit_mcp_to_native(m))),
        completion: ext.completion.map(|c| Arc::new(wit_completion_to_native(c))),
        provenance: ext.provenance.map(|p| Arc::new(NativeProvenanceExtension {
            source: p.source,
            message_id: p.message_id,
            parent_id: p.parent_id,
        })),
        llm: ext.llm.map(|l| Arc::new(NativeLLMExtension {
            model_id: l.model_id,
            provider: l.provider,
            capabilities: l.capabilities,
        })),
        framework: ext.framework.map(|f| Arc::new(wit_framework_to_native(f))),
        delegation: ext.delegation.map(|d| Arc::new(wit_delegation_to_native(d))),
        custom: ext.custom.and_then(|s| serde_json::from_str(&s).ok()).map(Arc::new),
        ..Default::default()
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
            subject_type: sub.subject_type.map(wit_subject_type_to_native),
            roles: sub.roles.into_iter().collect(),
            permissions: sub.permissions.into_iter().collect(),
            teams: sub.teams.into_iter().collect(),
            claims: sub.claims.into_iter().collect(),
        }),
        client: s.client.map(|c| {
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
        }),
        caller_workload: s.caller_workload.map(wit_workload_to_native),
        this_workload: s.this_workload.map(wit_workload_to_native),
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

fn wit_subject_type_to_native(st: SubjectType) -> NativeSubjectType {
    match st {
        SubjectType::User => NativeSubjectType::User,
        SubjectType::Agent => NativeSubjectType::Agent,
        SubjectType::Service => NativeSubjectType::Service,
        SubjectType::System => NativeSubjectType::System,
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
                subject_type: hop.subject_type.map(wit_subject_type_to_native),
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

// ---------------------------------------------------------------------------
// WIT → Native: PluginContext
// ---------------------------------------------------------------------------

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
// Native → WIT: PluginResult → HookResult
// ---------------------------------------------------------------------------

pub fn native_result_to_hook_result(
    result: NativePluginResult<native_msg::MessagePayload>,
    ctx: &NativePluginContext,
) -> HookResult {
    native_result_to_hook_result_generic(result, ctx)
}

/// Converts a typed `PluginResult<P>` to a WIT HookResult for any payload
/// type that can cross the WASM boundary. A modified `MessagePayload` goes
/// back structured (cmf variant); every other payload type is serialized
/// into the custom variant with its type discriminator, which the host's
/// PayloadSerializerRegistry uses to reconstruct the concrete type.
pub fn native_result_to_hook_result_generic<P>(
    result: NativePluginResult<P>,
    ctx: &NativePluginContext,
) -> HookResult
where
    P: cpex_core::hooks::payload::WasmSerializablePayload + 'static,
{
    let modified_payload = result.modified_payload.and_then(|p| {
        let any: &dyn std::any::Any = &p;
        if let Some(mp) = any.downcast_ref::<native_msg::MessagePayload>() {
            Some(HookPayload::Cmf(native_payload_to_wit(mp.clone())))
        } else {
            match p.to_wasm_bytes() {
                Ok(bytes) => Some(HookPayload::Custom(CustomPayload {
                    payload_type: P::payload_type_name().to_string(),
                    payload_data: bytes,
                })),
                Err(e) => {
                    eprintln!(
                        "[WASM] failed to serialize modified payload '{}': {}",
                        P::payload_type_name(),
                        e
                    );
                    None
                }
            }
        }
    });
    HookResult {
        continue_processing: result.continue_processing,
        modified_payload,
        modified_extensions: result.modified_extensions.as_ref().map(native_owned_extensions_to_wit),
        modified_context: Some(native_context_to_wit(ctx)),
        violation: result.violation.map(|v| PluginViolation {
            code: v.code,
            reason: v.reason,
            description: v.description,
            details: serde_json::to_string(&v.details).unwrap_or_else(|_| "{}".to_string()),
            plugin_name: v.plugin_name,
            proto_error_code: v.proto_error_code,
        }),
        metadata: result.metadata.map(|v| serde_json::to_string(&v).unwrap_or_default()),
    }
}

pub(crate) fn native_context_to_wit(ctx: &NativePluginContext) -> PluginContext {
    PluginContext {
        local_state: ctx.local_state.iter()
            .map(|(k, v)| ContextEntry { key: k.clone(), value: serde_json::to_string(v).unwrap_or_default() })
            .collect(),
        global_state: ctx.global_state.iter()
            .map(|(k, v)| ContextEntry { key: k.clone(), value: serde_json::to_string(v).unwrap_or_default() })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Native → WIT: MessagePayload
// ---------------------------------------------------------------------------

pub fn native_payload_to_wit(payload: native_msg::MessagePayload) -> MessagePayload {
    MessagePayload { message: native_message_to_wit(payload.message) }
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
        native_content::ContentPart::ToolCall { content } => ContentPart::ToolCall(ToolCall {
            tool_call_id: content.tool_call_id,
            name: content.name,
            arguments: serde_json::to_string(&content.arguments).unwrap_or_else(|_| "{}".to_string()),
            namespace: content.namespace,
        }),
        native_content::ContentPart::ToolResult { content } => ContentPart::ToolResult(ToolResult {
            tool_call_id: content.tool_call_id,
            tool_name: content.tool_name,
            content: serde_json::to_string(&content.content).unwrap_or_default(),
            is_error: content.is_error,
        }),
        native_content::ContentPart::Resource { content } => ContentPart::CmfResource(CmfResource {
            resource_request_id: content.resource_request_id,
            uri: content.uri,
            name: content.name,
            description: content.description,
            resource_type: native_resource_type_to_wit(content.resource_type),
            content: content.content,
            blob: content.blob,
            mime_type: content.mime_type,
            size_bytes: content.size_bytes,
            annotations: serde_json::to_string(&content.annotations).unwrap_or_else(|_| "{}".to_string()),
            version: content.version,
        }),
        native_content::ContentPart::ResourceRef { content } => ContentPart::ResourceRef(ResourceReference {
            resource_request_id: content.resource_request_id,
            uri: content.uri,
            name: content.name,
            resource_type: native_resource_type_to_wit(content.resource_type),
            range_start: content.range_start,
            range_end: content.range_end,
            selector: content.selector,
        }),
        native_content::ContentPart::PromptRequest { content } => ContentPart::PromptRequest(PromptRequest {
            prompt_request_id: content.prompt_request_id,
            name: content.name,
            arguments: serde_json::to_string(&content.arguments).unwrap_or_else(|_| "{}".to_string()),
            server_id: content.server_id,
        }),
        native_content::ContentPart::PromptResult { content } => ContentPart::PromptResult(PromptResult {
            prompt_request_id: content.prompt_request_id,
            prompt_name: content.prompt_name,
            messages: serde_json::to_string(&content.messages).unwrap_or_else(|_| "[]".to_string()),
            content: content.content,
            is_error: content.is_error,
            error_message: content.error_message,
        }),
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
        native_content::ContentPart::Document { content } => ContentPart::Document(DocumentSource {
            source_type: content.source_type,
            data: content.data,
            media_type: content.media_type,
            title: content.title,
        }),
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

// ---------------------------------------------------------------------------
// Native → WIT: OwnedExtensions (from PluginResult::modified_extensions)
// ---------------------------------------------------------------------------

fn native_owned_extensions_to_wit(
    ext: &cpex_core::extensions::container::OwnedExtensions,
) -> Extensions {
    Extensions {
        request: ext.request.as_ref().map(|r| RequestExtension {
            environment: r.environment.clone(),
            request_id: r.request_id.clone(),
            timestamp: r.timestamp.clone(),
            trace_id: r.trace_id.clone(),
            span_id: r.span_id.clone(),
        }),
        security: ext.security.as_ref().map(|s| SecurityExtension {
            labels: s.labels.iter().cloned().collect(),
            classification: s.classification.clone(),
            subject: s.subject.as_ref().map(|sub| SubjectExtension {
                id: sub.id.clone(),
                subject_type: sub.subject_type.as_ref().map(|st| match st {
                    NativeSubjectType::User => SubjectType::User,
                    NativeSubjectType::Agent => SubjectType::Agent,
                    NativeSubjectType::Service => SubjectType::Service,
                    NativeSubjectType::System => SubjectType::System,
                }),
                roles: sub.roles.iter().cloned().collect(),
                permissions: sub.permissions.iter().cloned().collect(),
                teams: sub.teams.iter().cloned().collect(),
                claims: sub.claims.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            }),
            client: None,
            caller_workload: None,
            this_workload: None,
            auth_method: s.auth_method.clone(),
            objects: vec![],
            data: vec![],
        }),
        http: ext.http.as_ref().map(|h| HttpExtension {
            request_headers: h.read().request_headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            response_headers: h.read().response_headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }),
        meta: ext.meta.as_ref().map(|m| MetaExtension {
            entity_type: m.entity_type.clone(),
            entity_name: m.entity_name.clone(),
            tags: m.tags.iter().cloned().collect(),
            scope: m.scope.clone(),
            properties: m.properties.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }),
        agent: None,
        mcp: None,
        completion: None,
        provenance: None,
        llm: None,
        framework: None,
        delegation: None,
        custom: None,
    }
}
