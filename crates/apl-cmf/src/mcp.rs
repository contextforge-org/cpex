// Location: ./crates/apl-cmf/src/mcp.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// MCPExtension → AttributeBag.
//
// Tool, resource, and prompt metadata each flatten under their own sub-namespace.
// Schemas and annotations are deliberately NOT flattened — they're free-form
// JSON; policies that need them should call a plugin.
//
// Namespace:
//   mcp.tool.name           : String     (always set if tool present)
//   mcp.tool.title          : String
//   mcp.tool.description    : String
//   mcp.tool.server_id      : String
//   mcp.tool.namespace      : String
//   mcp.resource.uri        : String     (always set if resource present)
//   mcp.resource.name       : String
//   mcp.resource.description: String
//   mcp.resource.mime_type  : String
//   mcp.resource.server_id  : String
//   mcp.prompt.name         : String     (always set if prompt present)
//   mcp.prompt.description  : String
//   mcp.prompt.server_id    : String

use apl_core::AttributeBag;
use cpex_core::extensions::MCPExtension;

pub fn extract_mcp(mcp: &MCPExtension, bag: &mut AttributeBag) {
    if let Some(tool) = &mcp.tool {
        bag.set("mcp.tool.name", tool.name.clone());
        if let Some(v) = &tool.title { bag.set("mcp.tool.title", v.clone()); }
        if let Some(v) = &tool.description { bag.set("mcp.tool.description", v.clone()); }
        if let Some(v) = &tool.server_id { bag.set("mcp.tool.server_id", v.clone()); }
        if let Some(v) = &tool.namespace { bag.set("mcp.tool.namespace", v.clone()); }
    }
    if let Some(res) = &mcp.resource {
        bag.set("mcp.resource.uri", res.uri.clone());
        if let Some(v) = &res.name { bag.set("mcp.resource.name", v.clone()); }
        if let Some(v) = &res.description { bag.set("mcp.resource.description", v.clone()); }
        if let Some(v) = &res.mime_type { bag.set("mcp.resource.mime_type", v.clone()); }
        if let Some(v) = &res.server_id { bag.set("mcp.resource.server_id", v.clone()); }
    }
    if let Some(prompt) = &mcp.prompt {
        bag.set("mcp.prompt.name", prompt.name.clone());
        if let Some(v) = &prompt.description { bag.set("mcp.prompt.description", v.clone()); }
        if let Some(v) = &prompt.server_id { bag.set("mcp.prompt.server_id", v.clone()); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::extensions::mcp::{ResourceMetadata, ToolMetadata};

    #[test]
    fn tool_metadata_flattens() {
        let mcp = MCPExtension {
            tool: Some(ToolMetadata {
                name: "get_compensation".into(),
                description: Some("HR comp lookup".into()),
                server_id: Some("hr-srv".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_mcp(&mcp, &mut bag);
        assert_eq!(bag.get_string("mcp.tool.name"), Some("get_compensation"));
        assert_eq!(bag.get_string("mcp.tool.description"), Some("HR comp lookup"));
        assert_eq!(bag.get_string("mcp.tool.server_id"), Some("hr-srv"));
        // Schemas are deliberately not in the bag.
        assert!(!bag.contains("mcp.tool.input_schema"));
    }

    #[test]
    fn resource_uri_is_required_field() {
        let mcp = MCPExtension {
            resource: Some(ResourceMetadata {
                uri: "hr://employees/123".into(),
                mime_type: Some("application/json".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_mcp(&mcp, &mut bag);
        assert_eq!(bag.get_string("mcp.resource.uri"), Some("hr://employees/123"));
        assert_eq!(bag.get_string("mcp.resource.mime_type"), Some("application/json"));
    }
}
