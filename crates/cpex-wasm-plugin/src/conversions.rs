// Location: ./crates/cpex-wasm-plugin/src/conversions.rs
// Copyright 2026
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
use cpex_core::delegation::{
    AttenuationConfig as NativeAttenuationConfig, AuthEnforcedBy as NativeAuthEnforcedBy,
    DelegationPayload as NativeDelegationPayload, TargetType as NativeTargetType,
};
use cpex_core::extensions::raw_credentials::{
    DelegationMode as NativeDelegationMode, RawDelegatedToken as NativeRawDelegatedToken,
};
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
use cpex_core::identity::{IdentityPayload as NativeIdentityPayload, TokenSource as NativeTokenSource};

use crate::cpex::plugin::types::*;

// ---------------------------------------------------------------------------
// WIT → Native: MessagePayload
// ---------------------------------------------------------------------------

/// Convert a WIT MessagePayload to a native cpex-core MessagePayload.
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

/// Convert WIT Extensions to native cpex-core Extensions (Arc-wrapped fields).
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
            method: h.method,
            path: h.path,
            host: h.host,
            scheme: h.scheme,
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
        client: s.client.map(wit_client_to_native),
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
                    .unwrap_or_else(|e| {
                        eprintln!(
                            "[WASM] failed to parse delegation timestamp '{}': {} — substituting Utc::now()",
                            hop.timestamp, e
                        );
                        chrono::Utc::now()
                    }),
                ttl_seconds: hop.ttl_seconds,
                strategy,
                from_cache: hop.from_cache,
            }
        }).collect(),
        depth: d.depth,
        origin_subject_id: d.origin_subject_id,
        actor_subject_id: d.actor_subject_id,
        delegated: d.delegated,
        age_seconds: d.age_seconds.parse().unwrap_or_else(|e| {
            eprintln!(
                "[WASM] failed to parse delegation age_seconds '{}': {} — defaulting to 0.0",
                d.age_seconds, e
            );
            0.0
        }),
    }
}

// ---------------------------------------------------------------------------
// WIT → Native: IdentityPayload
// ---------------------------------------------------------------------------

/// Convert a WIT IdentityPayload to a native cpex-core IdentityPayload.
pub fn wit_identity_payload_to_native(p: IdentityPayload) -> NativeIdentityPayload {
    let source = match p.source {
        TokenSource::Bearer => NativeTokenSource::Bearer,
        TokenSource::UserToken => NativeTokenSource::UserToken,
        TokenSource::Mtls => NativeTokenSource::Mtls,
        TokenSource::SpiffeJwtSvid => NativeTokenSource::SpiffeJwtSvid,
        TokenSource::ApiKey => NativeTokenSource::ApiKey,
        TokenSource::Custom => NativeTokenSource::Custom(p.source_custom.unwrap_or_default()),
    };
    let mut out = NativeIdentityPayload::new("", source);
    if let Some(h) = p.source_header {
        out = out.with_source_header(h);
    }
    out = out.with_headers(p.headers.into_iter().collect());
    if let Some(h) = p.client_host {
        out = out.with_client_host(h);
    }
    if let Some(port) = p.client_port {
        out = out.with_client_port(port);
    }
    out.subject = p.subject.map(|s| NativeSubjectExtension {
        id: s.id,
        subject_type: s.subject_type.map(wit_subject_type_to_native),
        roles: s.roles.into_iter().collect(),
        permissions: s.permissions.into_iter().collect(),
        teams: s.teams.into_iter().collect(),
        claims: s.claims.into_iter().collect(),
    });
    out.client = p.client.map(wit_client_to_native);
    out.caller_workload = p.caller_workload.map(wit_workload_to_native);
    out.delegation = p.delegation.map(wit_delegation_to_native);
    out.resolved_at = p
        .resolved_at
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    out.raw_claims = p
        .raw_claims
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    out
}

// ---------------------------------------------------------------------------
// WIT → Native: DelegationPayload
// ---------------------------------------------------------------------------

/// Convert a WIT DelegationPayload to a native cpex-core DelegationPayload.
pub fn wit_delegation_payload_to_native(p: DelegationPayload) -> NativeDelegationPayload {
    let target_type = match p.target_type {
        TargetType::Tool => NativeTargetType::Tool,
        TargetType::Agent => NativeTargetType::Agent,
        TargetType::Resource => NativeTargetType::Resource,
        TargetType::Service => NativeTargetType::Service,
        TargetType::Custom => NativeTargetType::Custom(p.target_type_custom.unwrap_or_default()),
    };
    let auth_enforced_by = match p.auth_enforced_by {
        AuthEnforcedBy::Caller => NativeAuthEnforcedBy::Caller,
        AuthEnforcedBy::Target => NativeAuthEnforcedBy::Target,
        AuthEnforcedBy::Both => NativeAuthEnforcedBy::Both,
    };
    let mut out = NativeDelegationPayload::new("", p.target_name)
        .with_target_type(target_type)
        .with_auth_enforced_by(auth_enforced_by);
    if let Some(aud) = p.target_audience {
        out = out.with_target_audience(aud);
    }
    if !p.required_permissions.is_empty() {
        out = out.with_required_permissions(p.required_permissions);
    }
    if let Some(td) = p.trust_domain {
        out = out.with_trust_domain(td);
    }
    if let Some(att) = p.route_attenuation {
        out = out.with_route_attenuation(NativeAttenuationConfig {
            capabilities: att.capabilities,
            resource_template: att.resource_template,
            actions: att.actions,
            ttl_seconds: att.ttl_seconds,
        });
    }
    out.delegated_token = p.delegated_token.map(|t| {
        let expires_at = DateTime::parse_from_rfc3339(&t.expires_at)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());
        NativeRawDelegatedToken::new("", t.outbound_header, t.audience, t.scopes, expires_at)
    });
    out.delegation_update = p.delegation_update.map(wit_delegation_to_native);
    out.delegation_mode = p.delegation_mode.map(|m| match m {
        DelegationMode::OnBehalfOfUser => NativeDelegationMode::OnBehalfOfUser,
        DelegationMode::AsGateway => NativeDelegationMode::AsGateway,
    });
    out.minted_at = p
        .minted_at
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    out.metadata = p
        .metadata
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    out
}

// ---------------------------------------------------------------------------
// WIT → Native: PluginContext
// ---------------------------------------------------------------------------

/// Convert a WIT PluginContext to a native cpex-core PluginContext.
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
        } else if let Some(ip) = any.downcast_ref::<NativeIdentityPayload>() {
            Some(HookPayload::Identity(native_identity_payload_to_wit(ip)))
        } else if let Some(dp) = any.downcast_ref::<NativeDelegationPayload>() {
            Some(HookPayload::Delegation(native_delegation_payload_to_wit(dp)))
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

/// Convert a native cpex-core MessagePayload to a WIT MessagePayload.
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

/// Convert plugin-modified extensions back to WIT for the host.
///
/// Mutable slots (persisted by the host via `merge_owned`):
///   - security (full: labels, classification, subject, client, workloads, objects, data, auth_method)
///   - http (request_headers, response_headers, method, path, host, scheme)
///   - delegation (full chain, hops, strategies)
///   - custom (arbitrary key-value map)
///
/// Immutable slots (host discards guest changes by design, validated via Arc pointer equality):
///   - request, agent, mcp, completion, provenance, llm, framework, meta
///
/// The immutable slots are still serialized for completeness (the host uses
/// the original Arc pointers regardless), matching cpex-core native behavior.
// ---------------------------------------------------------------------------
// Native → WIT: IdentityPayload
// ---------------------------------------------------------------------------

pub fn native_identity_payload_to_wit(p: &NativeIdentityPayload) -> IdentityPayload {
    let (source, source_custom) = match p.source() {
        NativeTokenSource::Bearer => (TokenSource::Bearer, None),
        NativeTokenSource::UserToken => (TokenSource::UserToken, None),
        NativeTokenSource::Mtls => (TokenSource::Mtls, None),
        NativeTokenSource::SpiffeJwtSvid => (TokenSource::SpiffeJwtSvid, None),
        NativeTokenSource::ApiKey => (TokenSource::ApiKey, None),
        NativeTokenSource::Custom(s) => (TokenSource::Custom, Some(s.clone())),
        other => {
            eprintln!("[cpex-wasm-plugin] unhandled TokenSource variant {:?}, falling back to Bearer", other);
            (TokenSource::Bearer, None)
        }
    };
    IdentityPayload {
        source,
        source_custom,
        source_header: p.source_header().map(str::to_owned),
        headers: p.headers().iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        client_host: p.client_host().map(str::to_owned),
        client_port: p.client_port(),
        subject: p.subject.as_ref().map(native_subject_to_wit),
        client: p.client.as_ref().map(native_client_to_wit),
        caller_workload: p.caller_workload.as_ref().map(native_workload_to_wit),
        delegation: p.delegation.as_ref().map(native_delegation_ext_to_wit),
        resolved_at: p.resolved_at.map(|dt| dt.to_rfc3339()),
        raw_claims: if p.raw_claims.is_empty() {
            None
        } else {
            serde_json::to_string(&p.raw_claims).ok()
        },
    }
}

// ---------------------------------------------------------------------------
// Native → WIT: DelegationPayload
// ---------------------------------------------------------------------------

pub fn native_delegation_payload_to_wit(p: &NativeDelegationPayload) -> DelegationPayload {
    let (target_type, target_type_custom) = match p.target_type() {
        NativeTargetType::Tool => (TargetType::Tool, None),
        NativeTargetType::Agent => (TargetType::Agent, None),
        NativeTargetType::Resource => (TargetType::Resource, None),
        NativeTargetType::Service => (TargetType::Service, None),
        NativeTargetType::Custom(s) => (TargetType::Custom, Some(s.clone())),
        other => {
            eprintln!("[cpex-wasm-plugin] unhandled TargetType variant {:?}, falling back to Tool", other);
            (TargetType::Tool, None)
        }
    };
    let auth_enforced_by = match p.auth_enforced_by() {
        NativeAuthEnforcedBy::Caller => AuthEnforcedBy::Caller,
        NativeAuthEnforcedBy::Target => AuthEnforcedBy::Target,
        NativeAuthEnforcedBy::Both => AuthEnforcedBy::Both,
        other => {
            eprintln!("[cpex-wasm-plugin] unhandled AuthEnforcedBy variant {:?}, falling back to Caller", other);
            AuthEnforcedBy::Caller
        }
    };
    DelegationPayload {
        target_name: p.target_name().to_owned(),
        target_type,
        target_type_custom,
        target_audience: p.target_audience().map(str::to_owned),
        required_permissions: p.required_permissions().to_vec(),
        trust_domain: p.trust_domain().map(str::to_owned),
        auth_enforced_by,
        route_attenuation: p.route_attenuation().map(|a| AttenuationConfig {
            capabilities: a.capabilities.clone(),
            resource_template: a.resource_template.clone(),
            actions: a.actions.clone(),
            ttl_seconds: a.ttl_seconds,
        }),
        delegated_token: p.delegated_token.as_ref().map(|t| RawDelegatedToken {
            outbound_header: t.outbound_header.clone(),
            audience: t.audience.clone(),
            scopes: t.scopes.clone(),
            expires_at: t.expires_at.to_rfc3339(),
        }),
        delegation_update: p.delegation_update.as_ref().map(native_delegation_ext_to_wit),
        delegation_mode: p.delegation_mode.as_ref().map(|m| match m {
            NativeDelegationMode::OnBehalfOfUser => DelegationMode::OnBehalfOfUser,
            NativeDelegationMode::AsGateway => DelegationMode::AsGateway,
            other => {
                eprintln!("[cpex-wasm-plugin] unhandled DelegationMode variant {:?}, falling back to OnBehalfOfUser", other);
                DelegationMode::OnBehalfOfUser
            }
        }),
        minted_at: p.minted_at.map(|dt| dt.to_rfc3339()),
        metadata: if p.metadata.is_empty() {
            None
        } else {
            serde_json::to_string(&p.metadata).ok()
        },
    }
}

// ---------------------------------------------------------------------------
// Native → WIT: shared helpers for payload conversions
// ---------------------------------------------------------------------------

fn native_subject_to_wit(s: &NativeSubjectExtension) -> SubjectExtension {
    SubjectExtension {
        id: s.id.clone(),
        subject_type: s.subject_type.as_ref().map(|st| match st {
            NativeSubjectType::User => SubjectType::User,
            NativeSubjectType::Agent => SubjectType::Agent,
            NativeSubjectType::Service => SubjectType::Service,
            NativeSubjectType::System => SubjectType::System,
        }),
        roles: s.roles.iter().cloned().collect(),
        permissions: s.permissions.iter().cloned().collect(),
        teams: s.teams.iter().cloned().collect(),
        claims: s.claims.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    }
}

fn native_client_to_wit(c: &NativeClientExtension) -> ClientExtension {
    let (trust_level, trust_level_custom) = match &c.trust_level {
        NativeClientTrustLevel::FirstParty => (ClientTrustLevel::FirstParty, None),
        NativeClientTrustLevel::ThirdParty => (ClientTrustLevel::ThirdParty, None),
        NativeClientTrustLevel::Internal => (ClientTrustLevel::Internal, None),
        NativeClientTrustLevel::Custom(s) => (ClientTrustLevel::ThirdParty, Some(s.clone())),
        other => {
            eprintln!("[cpex-wasm-plugin] unhandled ClientTrustLevel variant {:?}, falling back to ThirdParty", other);
            (ClientTrustLevel::ThirdParty, None)
        }
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

fn native_delegation_ext_to_wit(d: &NativeDelegationExtension) -> DelegationExtension {
    use cpex_core::extensions::delegation::DelegationStrategy as NDS;
    DelegationExtension {
        chain: d.chain.iter().map(|hop| {
            let (strategy, strategy_custom) = match &hop.strategy {
                None => (None, None),
                Some(NDS::TokenExchange) => (Some(DelegationStrategy::TokenExchange), None),
                Some(NDS::ClientCredentials) => (Some(DelegationStrategy::ClientCredentials), None),
                Some(NDS::SpiffeSvid) => (Some(DelegationStrategy::SpiffeSvid), None),
                Some(NDS::Passthrough) => (Some(DelegationStrategy::Passthrough), None),
                Some(NDS::Ucan) => (Some(DelegationStrategy::Ucan), None),
                Some(NDS::TransactionToken) => (Some(DelegationStrategy::TransactionToken), None),
                Some(NDS::Custom(s)) => (None, Some(s.clone())),
                Some(other) => {
                    eprintln!("[cpex-wasm-plugin] unhandled DelegationStrategy variant {:?}, falling back to None", other);
                    (None, None)
                }
            };
            DelegationHop {
                subject_id: hop.subject_id.clone(),
                subject_type: hop.subject_type.as_ref().map(|st| match st {
                    NativeSubjectType::User => SubjectType::User,
                    NativeSubjectType::Agent => SubjectType::Agent,
                    NativeSubjectType::Service => SubjectType::Service,
                    NativeSubjectType::System => SubjectType::System,
                }),
                audience: hop.audience.clone(),
                scopes_granted: hop.scopes_granted.clone(),
                authorization_details: hop.authorization_details.iter().map(|a| AuthorizationDetail {
                    detail_type: a.detail_type.clone(),
                    locations: a.locations.clone(),
                    actions: a.actions.clone(),
                    datatypes: a.datatypes.clone(),
                    identifier: a.identifier.clone(),
                    privileges: a.privileges.clone(),
                    extra: if a.extra.is_empty() { None } else { serde_json::to_string(&a.extra).ok() },
                }).collect(),
                timestamp: hop.timestamp.to_rfc3339(),
                ttl_seconds: hop.ttl_seconds,
                strategy,
                strategy_custom,
                from_cache: hop.from_cache,
            }
        }).collect(),
        depth: d.depth,
        origin_subject_id: d.origin_subject_id.clone(),
        actor_subject_id: d.actor_subject_id.clone(),
        delegated: d.delegated,
        age_seconds: d.age_seconds.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Native → WIT: OwnedExtensions (for result writeback)
// ---------------------------------------------------------------------------

pub(crate) fn native_owned_extensions_to_wit(
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
            subject: s.subject.as_ref().map(|sub| native_subject_to_wit(sub)),
            client: s.client.as_ref().map(|c| native_client_to_wit(c)),
            caller_workload: s.caller_workload.as_ref().map(|w| native_workload_to_wit(w)),
            this_workload: s.this_workload.as_ref().map(|w| native_workload_to_wit(w)),
            auth_method: s.auth_method.clone(),
            objects: s.objects.iter()
                .map(|(k, v)| (k.clone(), native_object_profile_to_wit(v)))
                .collect(),
            data: s.data.iter()
                .map(|(k, v)| (k.clone(), native_data_policy_to_wit(v)))
                .collect(),
        }),
        http: ext.http.as_ref().map(|h| HttpExtension {
            request_headers: h.read().request_headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            response_headers: h.read().response_headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            method: h.read().method.clone(),
            path: h.read().path.clone(),
            host: h.read().host.clone(),
            scheme: h.read().scheme.clone(),
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
        delegation: ext.delegation.as_ref().map(|d| native_delegation_ext_to_wit(d)),
        custom: ext.custom.as_ref().and_then(|c| serde_json::to_string(c).ok()),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::cmf::constants::SCHEMA_VERSION;

    // ── MessagePayload roundtrip ─────────────────────────────────────────────

    #[test]
    fn test_payload_roundtrip_text_message() {
        let native = native_msg::MessagePayload {
            message: native_msg::Message {
                schema_version: SCHEMA_VERSION.into(),
                role: native_enums::Role::User,
                content: vec![native_content::ContentPart::Text {
                    text: "hello world".into(),
                }],
                channel: None,
            },
        };

        let wit = native_payload_to_wit(native.clone());
        let back = wit_payload_to_native(wit);

        assert_eq!(back.message.schema_version, native.message.schema_version);
        assert_eq!(back.message.content.len(), 1);
        match &back.message.content[0] {
            native_content::ContentPart::Text { text } => assert_eq!(text, "hello world"),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn test_payload_roundtrip_tool_call() {
        let mut args = HashMap::new();
        args.insert("key".to_string(), serde_json::json!("value"));
        args.insert("num".to_string(), serde_json::json!(42));

        let native = native_msg::MessagePayload {
            message: native_msg::Message {
                schema_version: SCHEMA_VERSION.into(),
                role: native_enums::Role::Assistant,
                content: vec![native_content::ContentPart::ToolCall {
                    content: native_content::ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "get_data".into(),
                        arguments: args.clone(),
                        namespace: Some("mcp".into()),
                    },
                }],
                channel: Some(native_enums::Channel::Final),
            },
        };

        let wit = native_payload_to_wit(native);
        let back = wit_payload_to_native(wit);

        assert_eq!(back.message.channel, Some(native_enums::Channel::Final));
        match &back.message.content[0] {
            native_content::ContentPart::ToolCall { content } => {
                assert_eq!(content.tool_call_id, "tc_001");
                assert_eq!(content.name, "get_data");
                assert_eq!(content.arguments, args);
                assert_eq!(content.namespace, Some("mcp".into()));
            }
            _ => panic!("expected ToolCall"),
        }
    }

    #[test]
    fn test_payload_roundtrip_tool_result() {
        let native = native_msg::MessagePayload {
            message: native_msg::Message {
                schema_version: SCHEMA_VERSION.into(),
                role: native_enums::Role::Tool,
                content: vec![native_content::ContentPart::ToolResult {
                    content: native_content::ToolResult {
                        tool_call_id: "tc_001".into(),
                        tool_name: "get_data".into(),
                        content: serde_json::json!({"result": "ok"}),
                        is_error: false,
                    },
                }],
                channel: None,
            },
        };

        let wit = native_payload_to_wit(native);
        let back = wit_payload_to_native(wit);

        match &back.message.content[0] {
            native_content::ContentPart::ToolResult { content } => {
                assert_eq!(content.tool_call_id, "tc_001");
                assert_eq!(content.tool_name, "get_data");
                assert_eq!(content.content, serde_json::json!({"result": "ok"}));
                assert!(!content.is_error);
            }
            _ => panic!("expected ToolResult"),
        }
    }

    #[test]
    fn test_payload_roundtrip_all_roles() {
        let roles = vec![
            (native_enums::Role::System, Role::System),
            (native_enums::Role::Developer, Role::Developer),
            (native_enums::Role::User, Role::User),
            (native_enums::Role::Assistant, Role::Assistant),
            (native_enums::Role::Tool, Role::Tool),
        ];

        for (native_role, _) in roles {
            let native = native_msg::MessagePayload {
                message: native_msg::Message {
                    schema_version: SCHEMA_VERSION.into(),
                    role: native_role,
                    content: vec![],
                    channel: None,
                },
            };
            let wit = native_payload_to_wit(native.clone());
            let back = wit_payload_to_native(wit);
            assert_eq!(back.message.role, native.message.role);
        }
    }

    // ── PluginContext roundtrip ──────────────────────────────────────────────

    #[test]
    fn test_context_roundtrip_empty() {
        let native = NativePluginContext::default();
        let wit = native_context_to_wit(&native);
        let back = wit_context_to_native(wit);

        assert!(back.local_state.is_empty());
        assert!(back.global_state.is_empty());
    }

    #[test]
    fn test_context_roundtrip_with_state() {
        let mut native = NativePluginContext::default();
        native.set_local("key1", serde_json::json!("value1"));
        native.set_local("key2", serde_json::json!(42));
        native.set_global("global_key", serde_json::json!({"nested": true}));

        let wit = native_context_to_wit(&native);
        let back = wit_context_to_native(wit);

        assert_eq!(back.get_local("key1").unwrap(), &serde_json::json!("value1"));
        assert_eq!(back.get_local("key2").unwrap(), &serde_json::json!(42));
        assert_eq!(
            back.get_global("global_key").unwrap(),
            &serde_json::json!({"nested": true})
        );
    }

    // ── Extensions: WIT → Native ─────────────────────────────────────────────

    #[test]
    fn test_extensions_empty() {
        let wit = Extensions {
            request: None,
            security: None,
            http: None,
            meta: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        assert!(native.request.is_none());
        assert!(native.security.is_none());
        assert!(native.http.is_none());
    }

    #[test]
    fn test_extensions_security_labels() {
        let wit = Extensions {
            security: Some(SecurityExtension {
                labels: vec!["PII".into(), "SENSITIVE".into()],
                classification: Some("confidential".into()),
                subject: None,
                client: None,
                caller_workload: None,
                this_workload: None,
                auth_method: Some("jwt".into()),
                objects: vec![],
                data: vec![],
            }),
            request: None,
            http: None,
            meta: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        let sec = native.security.unwrap();
        assert!(sec.has_label("PII"));
        assert!(sec.has_label("SENSITIVE"));
        assert_eq!(sec.classification, Some("confidential".into()));
        assert_eq!(sec.auth_method, Some("jwt".into()));
    }

    #[test]
    fn test_extensions_security_subject() {
        let wit = Extensions {
            security: Some(SecurityExtension {
                labels: vec![],
                classification: None,
                subject: Some(SubjectExtension {
                    id: Some("user-123".into()),
                    subject_type: Some(SubjectType::User),
                    roles: vec!["admin".into(), "reader".into()],
                    permissions: vec!["read".into(), "write".into()],
                    teams: vec!["engineering".into()],
                    claims: vec![("org".into(), "acme".into())],
                }),
                client: None,
                caller_workload: None,
                this_workload: None,
                auth_method: None,
                objects: vec![],
                data: vec![],
            }),
            request: None,
            http: None,
            meta: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        let sec = native.security.unwrap();
        let sub = sec.subject.as_ref().unwrap();
        assert_eq!(sub.id, Some("user-123".into()));
        assert_eq!(sub.subject_type, Some(NativeSubjectType::User));
        assert!(sub.roles.contains("admin"));
        assert!(sub.roles.contains("reader"));
        assert!(sub.permissions.contains("write"));
        assert!(sub.teams.contains("engineering"));
        assert_eq!(sub.claims.get("org").unwrap(), "acme");
    }

    #[test]
    fn test_extensions_http_headers() {
        let wit = Extensions {
            http: Some(HttpExtension {
                request_headers: vec![
                    ("Authorization".into(), "Bearer tok".into()),
                    ("X-Request-ID".into(), "req-1".into()),
                ],
                response_headers: vec![("X-Powered-By".into(), "cpex".into())],
                method: Some("POST".into()),
                path: Some("/api/v1/tools".into()),
                host: Some("example.com".into()),
                scheme: Some("https".into()),
            }),
            request: None,
            security: None,
            meta: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        let http = native.http.unwrap();
        assert_eq!(
            http.request_headers.get("Authorization").unwrap(),
            "Bearer tok"
        );
        assert_eq!(http.request_headers.get("X-Request-ID").unwrap(), "req-1");
        assert_eq!(
            http.response_headers.get("X-Powered-By").unwrap(),
            "cpex"
        );
        assert_eq!(http.method, Some("POST".into()));
        assert_eq!(http.path, Some("/api/v1/tools".into()));
    }

    #[test]
    fn test_extensions_request_metadata() {
        let wit = Extensions {
            request: Some(RequestExtension {
                environment: Some("production".into()),
                request_id: Some("req-abc".into()),
                timestamp: Some("2026-07-28T12:00:00Z".into()),
                trace_id: Some("trace-1".into()),
                span_id: Some("span-1".into()),
            }),
            security: None,
            http: None,
            meta: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        let req = native.request.unwrap();
        assert_eq!(req.environment, Some("production".into()));
        assert_eq!(req.request_id, Some("req-abc".into()));
        assert_eq!(req.trace_id, Some("trace-1".into()));
    }

    // ── OwnedExtensions: Native → WIT (and verify what's lost) ───────────────

    #[test]
    fn test_owned_extensions_security_roundtrip() {
        use cpex_core::extensions::container::OwnedExtensions;

        let mut sec = NativeSecurityExtension::default();
        sec.labels = cpex_core::extensions::monotonic::MonotonicSet::from_set(
            ["PII".to_string(), "AUDIT".to_string()].into_iter().collect(),
        );
        sec.subject = Some(NativeSubjectExtension {
            id: Some("user-1".into()),
            subject_type: Some(NativeSubjectType::Agent),
            roles: ["admin".into()].into_iter().collect(),
            permissions: HashSet::new(),
            teams: HashSet::new(),
            claims: HashMap::new(),
        });
        sec.auth_method = Some("mtls".into());

        let owned = OwnedExtensions {
            security: Some(sec),
            request: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            meta: None,
            raw_credentials: None,
            http: None,
            delegation: None,
            custom: None,
            http_write_token: None,
            labels_write_token: None,
            delegation_write_token: None,
        };

        let wit = native_owned_extensions_to_wit(&owned);
        let wit_sec = wit.security.unwrap();

        assert!(wit_sec.labels.contains(&"PII".to_string()));
        assert!(wit_sec.labels.contains(&"AUDIT".to_string()));
        assert_eq!(wit_sec.subject.as_ref().unwrap().id, Some("user-1".into()));
        assert_eq!(
            wit_sec.subject.as_ref().unwrap().subject_type,
            Some(SubjectType::Agent)
        );
        assert!(wit_sec.subject.as_ref().unwrap().roles.contains(&"admin".to_string()));
        assert_eq!(wit_sec.auth_method, Some("mtls".into()));
    }

    #[test]
    fn test_owned_extensions_http_roundtrip() {
        use cpex_core::extensions::container::OwnedExtensions;
        use cpex_core::extensions::guarded::Guarded;

        let http = NativeHttpExtension {
            request_headers: [("Host".into(), "example.com".into())].into_iter().collect(),
            response_headers: HashMap::new(),
            method: Some("GET".into()),
            path: Some("/test".into()),
            host: Some("example.com".into()),
            scheme: Some("https".into()),
        };

        let owned = OwnedExtensions {
            http: Some(Guarded::new(http)),
            security: None,
            request: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            meta: None,
            raw_credentials: None,
            delegation: None,
            custom: None,
            http_write_token: None,
            labels_write_token: None,
            delegation_write_token: None,
        };

        let wit = native_owned_extensions_to_wit(&owned);
        let wit_http = wit.http.unwrap();

        assert!(wit_http.request_headers.contains(&("Host".into(), "example.com".into())));
        assert_eq!(wit_http.method, Some("GET".into()));
        assert_eq!(wit_http.path, Some("/test".into()));
    }

    #[test]
    fn test_owned_extensions_drops_unsupported_fields() {
        use cpex_core::extensions::container::OwnedExtensions;

        let owned = OwnedExtensions {
            security: None,
            request: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            meta: None,
            raw_credentials: None,
            http: None,
            delegation: None,
            custom: None,
            http_write_token: None,
            labels_write_token: None,
            delegation_write_token: None,
        };

        let wit = native_owned_extensions_to_wit(&owned);

        assert!(wit.agent.is_none());
        assert!(wit.mcp.is_none());
        assert!(wit.completion.is_none());
        assert!(wit.provenance.is_none());
        assert!(wit.llm.is_none());
        assert!(wit.framework.is_none());
        assert!(wit.delegation.is_none());
        assert!(wit.custom.is_none());
    }

    // ── Edge cases ───────────────────────────────────────────────────────────

    #[test]
    fn test_tool_call_malformed_json_arguments() {
        let wit_payload = MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall(ToolCall {
                    tool_call_id: "tc_1".into(),
                    name: "test".into(),
                    arguments: "not valid json{{{".into(),
                    namespace: None,
                })],
                channel: None,
            },
        };

        let native = wit_payload_to_native(wit_payload);
        match &native.message.content[0] {
            native_content::ContentPart::ToolCall { content } => {
                assert!(content.arguments.is_empty());
            }
            _ => panic!("expected ToolCall"),
        }
    }

    #[test]
    fn test_tool_call_empty_arguments() {
        let wit_payload = MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall(ToolCall {
                    tool_call_id: "tc_1".into(),
                    name: "test".into(),
                    arguments: "{}".into(),
                    namespace: None,
                })],
                channel: None,
            },
        };

        let native = wit_payload_to_native(wit_payload);
        match &native.message.content[0] {
            native_content::ContentPart::ToolCall { content } => {
                assert!(content.arguments.is_empty());
            }
            _ => panic!("expected ToolCall"),
        }
    }

    #[test]
    fn test_unicode_in_tool_name_and_arguments() {
        let mut args = HashMap::new();
        args.insert("query".to_string(), serde_json::json!("日本語テスト"));

        let native = native_msg::MessagePayload {
            message: native_msg::Message {
                schema_version: SCHEMA_VERSION.into(),
                role: native_enums::Role::Assistant,
                content: vec![native_content::ContentPart::ToolCall {
                    content: native_content::ToolCall {
                        tool_call_id: "tc_unicode".into(),
                        name: "검색_도구".into(),
                        arguments: args.clone(),
                        namespace: None,
                    },
                }],
                channel: None,
            },
        };

        let wit = native_payload_to_wit(native);
        let back = wit_payload_to_native(wit);

        match &back.message.content[0] {
            native_content::ContentPart::ToolCall { content } => {
                assert_eq!(content.name, "검색_도구");
                assert_eq!(
                    content.arguments.get("query").unwrap(),
                    &serde_json::json!("日本語テスト")
                );
            }
            _ => panic!("expected ToolCall"),
        }
    }

    #[test]
    fn test_context_with_nested_json_values() {
        let mut native = NativePluginContext::default();
        let complex = serde_json::json!({
            "array": [1, 2, 3],
            "nested": {"deep": {"value": true}},
            "null_field": null
        });
        native.set_local("complex", complex.clone());

        let wit = native_context_to_wit(&native);
        let back = wit_context_to_native(wit);

        assert_eq!(back.get_local("complex").unwrap(), &complex);
    }

    #[test]
    fn test_empty_strings_and_vectors() {
        let native = native_msg::MessagePayload {
            message: native_msg::Message {
                schema_version: "".into(),
                role: native_enums::Role::User,
                content: vec![],
                channel: None,
            },
        };

        let wit = native_payload_to_wit(native);
        let back = wit_payload_to_native(wit);

        assert_eq!(back.message.schema_version, "");
        assert!(back.message.content.is_empty());
    }

    #[test]
    fn test_extensions_agent_roundtrip() {
        let wit = Extensions {
            agent: Some(AgentExtension {
                input: Some("user query".into()),
                session_id: Some("sess-1".into()),
                conversation_id: Some("conv-1".into()),
                turn: Some(3),
                agent_id: Some("agent-1".into()),
                parent_agent_id: None,
                conversation: None,
            }),
            request: None,
            security: None,
            http: None,
            meta: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        let agent = native.agent.unwrap();
        assert_eq!(agent.input, Some("user query".into()));
        assert_eq!(agent.session_id, Some("sess-1".into()));
        assert_eq!(agent.turn, Some(3));
    }

    #[test]
    fn test_extensions_completion_roundtrip() {
        let wit = Extensions {
            completion: Some(CompletionExtension {
                stop_reason: Some(StopReason::MaxTokens),
                tokens: Some(TokenUsage {
                    input_tokens: 100,
                    output_tokens: 200,
                    total_tokens: 300,
                }),
                model: Some("claude-opus-4".into()),
                raw_format: None,
                created_at: Some("2026-07-28T12:00:00Z".into()),
                latency_ms: Some(1500),
            }),
            request: None,
            security: None,
            http: None,
            meta: None,
            agent: None,
            mcp: None,
            provenance: None,
            llm: None,
            framework: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        let comp = native.completion.unwrap();
        assert_eq!(comp.stop_reason, Some(NativeStopReason::MaxTokens));
        assert_eq!(comp.tokens.as_ref().unwrap().input_tokens, 100);
        assert_eq!(comp.tokens.as_ref().unwrap().total_tokens, 300);
        assert_eq!(comp.model, Some("claude-opus-4".into()));
        assert_eq!(comp.latency_ms, Some(1500));
    }

    // ── Identity Payload Conversion ────────────────────────────────────────

    #[test]
    fn test_identity_payload_minimal() {
        let wit = IdentityPayload {
            source: TokenSource::Bearer,
            source_custom: None,
            source_header: None,
            headers: vec![],
            client_host: None,
            client_port: None,
            subject: None,
            client: None,
            caller_workload: None,
            delegation: None,
            resolved_at: None,
            raw_claims: None,
        };

        let native = super::wit_identity_payload_to_native(wit);
        assert!(matches!(native.source(), cpex_core::identity::TokenSource::Bearer));
        assert!(native.subject.is_none());
        assert!(native.client.is_none());
        assert!(native.caller_workload.is_none());
        assert!(native.delegation.is_none());
        assert!(native.resolved_at.is_none());
        assert!(native.raw_claims.is_empty());
    }

    #[test]
    fn test_identity_payload_with_subject_and_headers() {
        let wit = IdentityPayload {
            source: TokenSource::Custom,
            source_custom: Some("oauth2".into()),
            source_header: Some("x-custom-auth".into()),
            headers: vec![
                ("x-user-id".into(), "alice".into()),
                ("authorization".into(), "Bearer tok".into()),
            ],
            client_host: Some("10.0.0.1".into()),
            client_port: Some(443),
            subject: Some(SubjectExtension {
                id: Some("alice".into()),
                subject_type: Some(SubjectType::User),
                roles: vec!["admin".into()],
                permissions: vec!["read".into(), "write".into()],
                teams: vec!["engineering".into()],
                claims: vec![("org".into(), "acme".into())],
            }),
            client: None,
            caller_workload: None,
            delegation: None,
            resolved_at: Some("2026-01-15T10:30:00Z".into()),
            raw_claims: Some(r#"{"sub":"alice","iss":"idp"}"#.into()),
        };

        let native = super::wit_identity_payload_to_native(wit);
        assert!(matches!(native.source(), cpex_core::identity::TokenSource::Custom(s) if s == "oauth2"));
        assert_eq!(native.source_header(), Some("x-custom-auth"));
        assert_eq!(native.headers().get("x-user-id"), Some(&"alice".to_string()));
        assert_eq!(native.client_host(), Some("10.0.0.1"));
        assert_eq!(native.client_port(), Some(443));

        let subject = native.subject.unwrap();
        assert_eq!(subject.id.as_deref(), Some("alice"));
        assert_eq!(subject.subject_type, Some(NativeSubjectType::User));
        assert!(subject.roles.contains("admin"));
        assert!(subject.permissions.contains("read"));
        assert!(subject.teams.contains("engineering"));

        assert!(native.resolved_at.is_some());
        assert_eq!(native.raw_claims.get("sub").and_then(|v| v.as_str()), Some("alice"));
    }

    // ── Delegation Payload Conversion ──────────────────────────────────────

    #[test]
    fn test_delegation_payload_minimal() {
        let wit = DelegationPayload {
            target_name: "my-tool".into(),
            target_type: TargetType::Tool,
            target_type_custom: None,
            target_audience: None,
            required_permissions: vec![],
            trust_domain: None,
            auth_enforced_by: AuthEnforcedBy::Caller,
            route_attenuation: None,
            delegated_token: None,
            delegation_update: None,
            delegation_mode: None,
            minted_at: None,
            metadata: None,
        };

        let native = super::wit_delegation_payload_to_native(wit);
        assert_eq!(native.target_name(), "my-tool");
        assert!(matches!(native.target_type(), NativeTargetType::Tool));
        assert!(matches!(native.auth_enforced_by(), NativeAuthEnforcedBy::Caller));
        assert!(native.delegated_token.is_none());
        assert!(native.delegation_update.is_none());
        assert!(native.delegation_mode.is_none());
    }

    #[test]
    fn test_delegation_payload_full() {
        let wit = DelegationPayload {
            target_name: "query-svc".into(),
            target_type: TargetType::Service,
            target_type_custom: None,
            target_audience: Some("https://api.example.com".into()),
            required_permissions: vec!["read:data".into(), "write:logs".into()],
            trust_domain: Some("corp.internal".into()),
            auth_enforced_by: AuthEnforcedBy::Both,
            route_attenuation: Some(AttenuationConfig {
                capabilities: vec!["read".into()],
                resource_template: Some("/api/v1/*".into()),
                actions: vec!["GET".into()],
                ttl_seconds: Some(300),
            }),
            delegated_token: Some(RawDelegatedToken {
                outbound_header: "X-Service-Token".into(),
                audience: "https://api.example.com".into(),
                scopes: vec!["read:data".into()],
                expires_at: "2026-06-15T12:00:00Z".into(),
            }),
            delegation_update: None,
            delegation_mode: Some(DelegationMode::AsGateway),
            minted_at: Some("2026-06-15T11:55:00Z".into()),
            metadata: Some(r#"{"minter":"test"}"#.into()),
        };

        let native = super::wit_delegation_payload_to_native(wit);
        assert_eq!(native.target_name(), "query-svc");
        assert!(matches!(native.target_type(), NativeTargetType::Service));
        assert_eq!(native.target_audience(), Some("https://api.example.com"));
        assert_eq!(native.required_permissions(), &["read:data", "write:logs"]);
        assert_eq!(native.trust_domain(), Some("corp.internal"));
        assert!(matches!(native.auth_enforced_by(), NativeAuthEnforcedBy::Both));

        let att = native.route_attenuation().unwrap();
        assert_eq!(att.capabilities, vec!["read"]);
        assert_eq!(att.resource_template.as_deref(), Some("/api/v1/*"));
        assert_eq!(att.ttl_seconds, Some(300));

        let token = native.delegated_token.as_ref().unwrap();
        assert_eq!(token.outbound_header, "X-Service-Token");
        assert_eq!(token.audience, "https://api.example.com");
        assert_eq!(token.scopes, vec!["read:data"]);

        assert_eq!(native.delegation_mode, Some(NativeDelegationMode::AsGateway));
        assert!(native.minted_at.is_some());
        assert_eq!(native.metadata.get("minter").and_then(|v| v.as_str()), Some("test"));
    }

    // ── Content Parts Roundtrip ─────────────────────────────────────────────

    #[test]
    fn test_payload_roundtrip_resource() {
        let native = native_msg::MessagePayload {
            message: native_msg::Message {
                schema_version: SCHEMA_VERSION.into(),
                role: native_enums::Role::Tool,
                content: vec![native_content::ContentPart::Resource {
                    content: native_content::Resource {
                        resource_request_id: "rr-001".into(),
                        uri: "file:///src/main.rs".into(),
                        name: Some("main.rs".into()),
                        description: Some("Entry point".into()),
                        resource_type: native_enums::ResourceType::File,
                        content: Some("fn main() {}".into()),
                        blob: None,
                        mime_type: Some("text/x-rust".into()),
                        size_bytes: Some(12),
                        annotations: HashMap::new(),
                        version: Some("v1".into()),
                    },
                }],
                channel: None,
            },
        };

        let wit = native_payload_to_wit(native.clone());
        let back = wit_payload_to_native(wit);

        match &back.message.content[0] {
            native_content::ContentPart::Resource { content } => {
                assert_eq!(content.resource_request_id, "rr-001");
                assert_eq!(content.uri, "file:///src/main.rs");
                assert_eq!(content.name, Some("main.rs".into()));
                assert_eq!(content.resource_type, native_enums::ResourceType::File);
                assert_eq!(content.content, Some("fn main() {}".into()));
                assert_eq!(content.mime_type, Some("text/x-rust".into()));
                assert_eq!(content.size_bytes, Some(12));
                assert_eq!(content.version, Some("v1".into()));
            }
            _ => panic!("expected Resource"),
        }
    }

    #[test]
    fn test_payload_roundtrip_image() {
        let native = native_msg::MessagePayload {
            message: native_msg::Message {
                schema_version: SCHEMA_VERSION.into(),
                role: native_enums::Role::User,
                content: vec![native_content::ContentPart::Image {
                    content: native_content::ImageSource {
                        source_type: "base64".into(),
                        data: "iVBORw0KGgo=".into(),
                        media_type: Some("image/png".into()),
                    },
                }],
                channel: None,
            },
        };

        let wit = native_payload_to_wit(native.clone());
        let back = wit_payload_to_native(wit);

        match &back.message.content[0] {
            native_content::ContentPart::Image { content } => {
                assert_eq!(content.source_type, "base64");
                assert_eq!(content.data, "iVBORw0KGgo=");
                assert_eq!(content.media_type, Some("image/png".into()));
            }
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn test_payload_roundtrip_document() {
        let native = native_msg::MessagePayload {
            message: native_msg::Message {
                schema_version: SCHEMA_VERSION.into(),
                role: native_enums::Role::User,
                content: vec![native_content::ContentPart::Document {
                    content: native_content::DocumentSource {
                        source_type: "base64".into(),
                        data: "JVBERi0xLjQ=".into(),
                        media_type: Some("application/pdf".into()),
                        title: Some("Report Q4".into()),
                    },
                }],
                channel: None,
            },
        };

        let wit = native_payload_to_wit(native.clone());
        let back = wit_payload_to_native(wit);

        match &back.message.content[0] {
            native_content::ContentPart::Document { content } => {
                assert_eq!(content.source_type, "base64");
                assert_eq!(content.data, "JVBERi0xLjQ=");
                assert_eq!(content.media_type, Some("application/pdf".into()));
                assert_eq!(content.title, Some("Report Q4".into()));
            }
            _ => panic!("expected Document"),
        }
    }

    // ── Extensions Roundtrip: MCP, LLM, Framework ───────────────────────────

    #[test]
    fn test_extensions_mcp_tool_metadata() {
        let wit = Extensions {
            mcp: Some(McpExtension {
                tool: Some(ToolMetadata {
                    name: "search_docs".into(),
                    title: Some("Search Documents".into()),
                    description: Some("Searches the document index".into()),
                    input_schema: Some(r#"{"type":"object","properties":{"query":{"type":"string"}}}"#.into()),
                    output_schema: None,
                    server_id: Some("docs-server".into()),
                    namespace: Some("knowledge".into()),
                    annotations: vec![("priority".into(), r#""high""#.into())],
                }),
                resource_info: None,
                prompt: None,
            }),
            request: None,
            security: None,
            http: None,
            meta: None,
            agent: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        let mcp = native.mcp.unwrap();
        let tool = mcp.tool.as_ref().unwrap();
        assert_eq!(tool.name, "search_docs");
        assert_eq!(tool.title, Some("Search Documents".into()));
        assert_eq!(tool.description, Some("Searches the document index".into()));
        assert!(tool.input_schema.is_some());
        let schema = tool.input_schema.as_ref().unwrap();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["query"]["type"], "string");
        assert_eq!(tool.server_id, Some("docs-server".into()));
        assert_eq!(tool.namespace, Some("knowledge".into()));
        assert_eq!(
            tool.annotations.get("priority").unwrap(),
            &serde_json::json!("high")
        );
    }

    #[test]
    fn test_extensions_llm() {
        let wit = Extensions {
            llm: Some(LlmExtension {
                model_id: Some("claude-opus-4".into()),
                provider: Some("anthropic".into()),
                capabilities: vec!["tool_use".into(), "vision".into(), "streaming".into()],
            }),
            request: None,
            security: None,
            http: None,
            meta: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            framework: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        let llm = native.llm.unwrap();
        assert_eq!(llm.model_id, Some("claude-opus-4".into()));
        assert_eq!(llm.provider, Some("anthropic".into()));
        assert_eq!(llm.capabilities, vec!["tool_use", "vision", "streaming"]);
    }

    #[test]
    fn test_extensions_framework() {
        let wit = Extensions {
            framework: Some(FrameworkExtension {
                framework: Some("langchain".into()),
                framework_version: Some("0.2.1".into()),
                node_id: Some("node-transform-42".into()),
                graph_id: Some("pipeline-main".into()),
                metadata: Some(r#"{"retry_count":3}"#.into()),
            }),
            request: None,
            security: None,
            http: None,
            meta: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            delegation: None,
            custom: None,
        };

        let native = wit_extensions_to_native(wit);
        let fw = native.framework.unwrap();
        assert_eq!(fw.framework, Some("langchain".into()));
        assert_eq!(fw.framework_version, Some("0.2.1".into()));
        assert_eq!(fw.node_id, Some("node-transform-42".into()));
        assert_eq!(fw.graph_id, Some("pipeline-main".into()));
        assert_eq!(fw.metadata.get("retry_count").unwrap(), &serde_json::json!(3));
    }

    // ── OwnedExtensions Writeback: Delegation, Custom, Security ─────────────

    #[test]
    fn test_owned_extensions_delegation_writeback() {
        use cpex_core::extensions::container::OwnedExtensions;

        let delegation = NativeDelegationExtension {
            chain: vec![NativeDelegationHop {
                subject_id: "user-alice".into(),
                subject_type: Some(NativeSubjectType::User),
                audience: Some("https://backend.internal".into()),
                scopes_granted: vec!["read:data".into()],
                authorization_details: vec![],
                timestamp: chrono::Utc::now(),
                ttl_seconds: Some(600),
                strategy: Some(NativeDelegationStrategy::TokenExchange),
                from_cache: false,
            }],
            depth: 1,
            origin_subject_id: Some("user-alice".into()),
            actor_subject_id: Some("user-alice".into()),
            delegated: true,
            age_seconds: 5.0,
        };

        let owned = OwnedExtensions {
            delegation: Some(delegation),
            security: None,
            request: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            meta: None,
            raw_credentials: None,
            http: None,
            custom: None,
            http_write_token: None,
            labels_write_token: None,
            delegation_write_token: None,
        };

        let wit = native_owned_extensions_to_wit(&owned);
        let wit_del = wit.delegation.unwrap();

        assert_eq!(wit_del.chain.len(), 1);
        assert_eq!(wit_del.chain[0].subject_id, "user-alice");
        assert_eq!(wit_del.chain[0].subject_type, Some(SubjectType::User));
        assert_eq!(wit_del.chain[0].audience, Some("https://backend.internal".into()));
        assert_eq!(wit_del.chain[0].scopes_granted, vec!["read:data"]);
        assert_eq!(wit_del.chain[0].ttl_seconds, Some(600));
        assert_eq!(wit_del.chain[0].strategy, Some(DelegationStrategy::TokenExchange));
        assert!(!wit_del.chain[0].from_cache);
        assert_eq!(wit_del.depth, 1);
        assert!(wit_del.delegated);
        assert_eq!(wit_del.origin_subject_id, Some("user-alice".into()));
        assert_eq!(wit_del.actor_subject_id, Some("user-alice".into()));
    }

    #[test]
    fn test_owned_extensions_custom_writeback() {
        use cpex_core::extensions::container::OwnedExtensions;

        let mut custom_map = HashMap::new();
        custom_map.insert("feature_flag".to_string(), serde_json::json!(true));
        custom_map.insert("max_retries".to_string(), serde_json::json!(3));

        let owned = OwnedExtensions {
            custom: Some(custom_map),
            security: None,
            request: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            meta: None,
            raw_credentials: None,
            http: None,
            delegation: None,
            http_write_token: None,
            labels_write_token: None,
            delegation_write_token: None,
        };

        let wit = native_owned_extensions_to_wit(&owned);
        let wit_custom_str = wit.custom.unwrap();
        let parsed: HashMap<String, serde_json::Value> =
            serde_json::from_str(&wit_custom_str).unwrap();

        assert_eq!(parsed.get("feature_flag").unwrap(), &serde_json::json!(true));
        assert_eq!(parsed.get("max_retries").unwrap(), &serde_json::json!(3));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_owned_extensions_security_client_and_workload_writeback() {
        use cpex_core::extensions::container::OwnedExtensions;

        let sec = NativeSecurityExtension {
            labels: cpex_core::extensions::monotonic::MonotonicSet::default(),
            classification: None,
            subject: None,
            client: Some(NativeClientExtension {
                client_id: "client-web-app".into(),
                client_name: Some("Web App".into()),
                trust_level: NativeClientTrustLevel::FirstParty,
                authorized_scopes: vec!["openid".into(), "profile".into()],
                authorized_audiences: vec!["https://api.example.com".into()],
                roles: vec!["service-role".into()],
                permissions: vec!["invoke:tools".into()],
                teams: vec!["platform".into()],
                claims: [("iss".into(), serde_json::json!("https://idp.example.com"))].into_iter().collect(),
            }),
            caller_workload: Some(NativeWorkloadIdentity {
                spiffe_id: Some("spiffe://corp.internal/ns/prod/sa/web-app".into()),
                trust_domain: Some("corp.internal".into()),
                attested_at: None,
                attestor: Some("spire-agent".into()),
                selectors: vec!["k8s:ns:prod".into(), "k8s:sa:web-app".into()],
                client_id: Some("client-web-app".into()),
            }),
            this_workload: None,
            auth_method: Some("mtls".into()),
            objects: HashMap::new(),
            data: HashMap::new(),
        };

        let owned = OwnedExtensions {
            security: Some(sec),
            request: None,
            agent: None,
            mcp: None,
            completion: None,
            provenance: None,
            llm: None,
            framework: None,
            meta: None,
            raw_credentials: None,
            http: None,
            delegation: None,
            custom: None,
            http_write_token: None,
            labels_write_token: None,
            delegation_write_token: None,
        };

        let wit = native_owned_extensions_to_wit(&owned);
        let wit_sec = wit.security.unwrap();

        // Client assertions
        let wit_client = wit_sec.client.unwrap();
        assert_eq!(wit_client.client_id, "client-web-app");
        assert_eq!(wit_client.client_name, Some("Web App".into()));
        assert_eq!(wit_client.trust_level, ClientTrustLevel::FirstParty);
        assert!(wit_client.authorized_scopes.contains(&"openid".to_string()));
        assert!(wit_client.authorized_scopes.contains(&"profile".to_string()));
        assert!(wit_client.authorized_audiences.contains(&"https://api.example.com".to_string()));
        assert!(wit_client.roles.contains(&"service-role".to_string()));
        assert!(wit_client.permissions.contains(&"invoke:tools".to_string()));
        assert!(wit_client.teams.contains(&"platform".to_string()));

        // Caller workload assertions
        let wit_workload = wit_sec.caller_workload.unwrap();
        assert_eq!(
            wit_workload.spiffe_id,
            Some("spiffe://corp.internal/ns/prod/sa/web-app".into())
        );
        assert_eq!(wit_workload.trust_domain, Some("corp.internal".into()));
        assert_eq!(wit_workload.attestor, Some("spire-agent".into()));
        assert!(wit_workload.selectors.contains(&"k8s:ns:prod".to_string()));
        assert!(wit_workload.selectors.contains(&"k8s:sa:web-app".to_string()));
        assert_eq!(wit_workload.client_id, Some("client-web-app".into()));

        assert_eq!(wit_sec.auth_method, Some("mtls".into()));
    }
}
