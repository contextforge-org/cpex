// Location: ./crates/cpex-core/src/extensions/mod.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Typed extension models for the CPEX framework.
//
// Each extension carries contextual metadata with an explicit
// mutability tier enforced by the processing pipeline. Extensions
// are always passed separately from the payload to handlers.
//
// Mirrors the Python extensions in cpex/framework/extensions/.

pub mod agent;
pub mod authorization;
pub mod completion;
pub mod container;
pub mod delegation;
pub mod filter;
pub mod framework;
pub mod guarded;
pub mod http;
pub mod llm;
pub mod mcp;
pub mod meta;
pub mod monotonic;
pub mod provenance;
pub mod raw_credentials;
pub mod request;
pub mod security;
pub mod tiers;

// Re-export containers
pub use container::{Extensions, OwnedExtensions};

// Re-export all extension types
pub use agent::{AgentExtension, ConversationContext};
pub use authorization::AuthorizationDetail;
pub use completion::{CompletionExtension, StopReason, TokenUsage};
pub use delegation::{DelegationExtension, DelegationHop, DelegationStrategy};
pub use filter::{filter_extensions, SlotName};
pub use framework::FrameworkExtension;
pub use guarded::{Guarded, WriteToken};
pub use http::HttpExtension;
pub use llm::LLMExtension;
pub use mcp::{MCPExtension, PromptMetadata, ResourceMetadata, ToolMetadata};
pub use meta::MetaExtension;
pub use monotonic::{DeclassifierToken, MonotonicSet};
pub use provenance::ProvenanceExtension;
pub use raw_credentials::{
    DelegationKey, DelegationMode, RawCredentialsExtension, RawDelegatedToken, RawInboundToken,
    TokenKind, TokenRole,
};
pub use request::RequestExtension;
pub use security::{
    ClientExtension, ClientTrustLevel, DataPolicy, ObjectSecurityProfile, RetentionPolicy,
    SecurityExtension, SubjectExtension, SubjectType, WorkloadIdentity,
};
pub use tiers::{AccessPolicy, Capability, MutabilityTier, SlotPolicy};
