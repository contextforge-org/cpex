// Location: ./crates/cpex-hosts-python/src/legacy/cmf_shim.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Payload shim between PPE's `cmf.*` hooks and the legacy typed hooks.
//
// # Why this exists
//
// PPE dispatches tool, prompt and resource traffic only on `cmf.*` hooks, with
// a CMF `MessagePayload`. Python workers that predate `cmf.*` hook support
// (the released 0.1.x SDK) register no `cmf.*` hook in the worker, and their
// plugins implement `tool_pre_invoke` and friends against the typed payloads
// (`ToolPreInvokePayload` and so on). Without this module such a plugin cannot
// run on PPE at all.
//
// So, for a worker that does not claim the `cmf_hooks` handshake feature, the
// adapter routes each of the six tool, prompt and resource `cmf.*` hooks
// through here:
//
//   outbound: the CMF message ──> the legacy typed payload + legacy hook name
//   inbound:  a modified legacy payload ──> the same CMF message with only the
//             fields the legacy payload carries replaced
//
// Allow, deny and violations pass through untouched; only `modified_payload`
// is translated. A message the legacy payload cannot represent fails closed
// with `HostError::LegacyShim`, never a silent allow.
//
// # Field decisions
//
// Every field of the CMF parts the shim reads. "sent" fields reach the plugin
// and are mapped back. "kept" fields are not sent and survive unchanged, which
// is safe because they neither qualify what is authorized nor carry content a
// plugin could need to rewrite. "refuse" fields are security-relevant and have
// no legacy slot, so a message that sets them fails closed.
//
//   part              field                decision
//   ----------------  -------------------  -------------------------------------
//   tool_call         tool_call_id         kept: correlation only
//                     name, arguments      sent
//                     namespace            refuse when non-empty: a plugin that
//                                          authorizes by bare name would approve
//                                          the same name in any namespace
//   tool_result       tool_call_id         kept: correlation only
//                     tool_name, content   sent (structured content travels
//                                          inside `content` as is)
//                     is_error             refuse when true unless `content`
//                                          carries `"isError": true`; a modified
//                                          result must keep it
//   prompt_request    prompt_request_id    kept: correlation only
//                     name, arguments      sent
//                     server_id            refuse when non-empty: same reason as
//                                          tool namespace
//   prompt_result     prompt_request_id    kept: correlation only
//                     prompt_name          sent
//                     messages             sent (role and text; per-message
//                                          `schema_version` and `channel` kept)
//                     content              refuse when non-empty: rendered text
//                                          the plugin cannot see or redact
//                     is_error             refuse when true: no legacy slot
//                     error_message        refuse when non-empty: same as content
//   resource          resource_request_id  sent on post-fetch as `id`, else kept
//                     uri                  sent
//                     name, description    kept: descriptive labels
//                     resource_type        kept: the URI is the address
//                     annotations          kept: labels that only restrict
//                                          downstream, never widen
//                     version              refuse when non-empty: selects which
//                                          revision the URI resolves to
//                     content              sent on post-fetch as `text`; on
//                                          pre-fetch a URI rewrite refuses if set
//                     blob                 refuse when set
//                     mime_type            sent on post-fetch; on pre-fetch a
//                                          URI rewrite refuses if set
//                     size_bytes           not sent; recomputed when post-fetch
//                                          text changes; on pre-fetch a URI
//                                          rewrite refuses if set
//   resource_ref      resource_request_id  kept: correlation only
//                     uri                  sent
//                     name, resource_type  kept: descriptive
//                     range_start/end,     kept: they narrow what is read within
//                     selector             the URI the plugin approved
//
// # Removing it
//
// Once every supported worker claims `cmf_hooks`, delete this file, its
// `pub mod` line in `legacy/mod.rs`, and the `shim` branch in
// `PythonHookAdapter::invoke` and `build_task`. Nothing else depends on it.

use std::collections::HashMap;

use praxis_policy_core::cmf::constants::{
    HOOK_CMF_LLM_INPUT, HOOK_CMF_LLM_OUTPUT, HOOK_CMF_PROMPT_POST_INVOKE,
    HOOK_CMF_PROMPT_PRE_INVOKE, HOOK_CMF_RESOURCE_POST_FETCH, HOOK_CMF_RESOURCE_PRE_FETCH,
    HOOK_CMF_TOOL_POST_INVOKE, HOOK_CMF_TOOL_PRE_INVOKE,
};
use praxis_policy_core::cmf::{ContentPart, Message, MessagePayload, Resource, Role};
use praxis_policy_core::hooks::payload::PluginPayload;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use super::payloads::{
    PromptPostFetchPayload, PromptPreFetchPayload, ResourcePostFetchPayload,
    ResourcePreFetchPayload, ToolPostInvokePayload, ToolPreInvokePayload,
};
use crate::error::HostError;

/// The six `cmf.*` hooks the shim translates, and the legacy hook each one
/// reaches the worker as.
const SHIMMED_HOOKS: &[(&str, Shim)] = &[
    (HOOK_CMF_TOOL_PRE_INVOKE, Shim::ToolPreInvoke),
    (HOOK_CMF_TOOL_POST_INVOKE, Shim::ToolPostInvoke),
    (HOOK_CMF_PROMPT_PRE_INVOKE, Shim::PromptPreFetch),
    (HOOK_CMF_PROMPT_POST_INVOKE, Shim::PromptPostFetch),
    (HOOK_CMF_RESOURCE_PRE_FETCH, Shim::ResourcePreFetch),
    (HOOK_CMF_RESOURCE_POST_FETCH, Shim::ResourcePostFetch),
];

/// Which legacy hook a shimmed `cmf.*` hook maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shim {
    ToolPreInvoke,
    ToolPostInvoke,
    PromptPreFetch,
    PromptPostFetch,
    ResourcePreFetch,
    ResourcePostFetch,
}

impl Shim {
    fn for_hook(hook_name: &str) -> Option<Self> {
        SHIMMED_HOOKS
            .iter()
            .find(|(name, _)| *name == hook_name)
            .map(|(_, shim)| *shim)
    }

    /// The legacy hook name: the `hook_type` the worker dispatches on and the
    /// method name a 0.1.x plugin implements.
    fn legacy_hook(self) -> &'static str {
        match self {
            Self::ToolPreInvoke => "tool_pre_invoke",
            Self::ToolPostInvoke => "tool_post_invoke",
            Self::PromptPreFetch => "prompt_pre_fetch",
            Self::PromptPostFetch => "prompt_post_fetch",
            Self::ResourcePreFetch => "resource_pre_fetch",
            Self::ResourcePostFetch => "resource_post_fetch",
        }
    }

    /// The CMF content part the legacy payload is built from, for diagnostics.
    fn part_name(self) -> &'static str {
        match self {
            Self::ToolPreInvoke => "tool_call",
            Self::ToolPostInvoke => "tool_result",
            Self::PromptPreFetch => "prompt_request",
            Self::PromptPostFetch => "prompt_result",
            Self::ResourcePreFetch => "resource or resource_ref",
            Self::ResourcePostFetch => "resource",
        }
    }

    /// Whether `part` is the kind this hook's legacy payload is built from.
    fn matches(self, part: &ContentPart) -> bool {
        match self {
            Self::ToolPreInvoke => matches!(part, ContentPart::ToolCall { .. }),
            Self::ToolPostInvoke => matches!(part, ContentPart::ToolResult { .. }),
            Self::PromptPreFetch => matches!(part, ContentPart::PromptRequest { .. }),
            Self::PromptPostFetch => matches!(part, ContentPart::PromptResult { .. }),
            // A pre-fetch only needs the URI, which both resource parts carry.
            // A post-fetch needs the content, which only `resource` carries; a
            // `resource_ref` there is counted so it fails with a clear reason
            // rather than as "no resource part".
            Self::ResourcePreFetch | Self::ResourcePostFetch => matches!(
                part,
                ContentPart::Resource { .. } | ContentPart::ResourceRef { .. }
            ),
        }
    }
}

/// Whether `hook_name` is a `cmf.*` hook PPE dispatches.
///
/// Every one of these needs either a worker that claims `cmf_hooks` or the
/// shim. The two LLM hooks are included: they have no legacy equivalent, so a
/// worker without `cmf_hooks` cannot serve them and [`to_legacy`] refuses.
pub fn is_cmf_hook(hook_name: &str) -> bool {
    Shim::for_hook(hook_name).is_some()
        || hook_name == HOOK_CMF_LLM_INPUT
        || hook_name == HOOK_CMF_LLM_OUTPUT
}

/// The legacy hook name a shimmed `cmf.*` hook reaches the worker as, or
/// `None` for any other name.
pub fn legacy_hook_name(hook_name: &str) -> Option<&'static str> {
    Shim::for_hook(hook_name).map(Shim::legacy_hook)
}

/// One translated invocation: the legacy payload to send, plus what is needed
/// to map a modified legacy payload back onto the original message.
#[derive(Debug)]
pub struct ShimmedPayload {
    shim: Shim,
    hook_name: String,
    /// The message as dispatched. A modified payload is applied to a clone of
    /// it, so every part and field the legacy payload does not carry survives.
    original: MessagePayload,
    /// Index of the content part the legacy payload was built from.
    part: usize,
    json: Value,
}

impl ShimmedPayload {
    /// The legacy hook name to send as the task's `hook_type`.
    pub fn legacy_hook(&self) -> &'static str {
        self.shim.legacy_hook()
    }

    /// The legacy payload JSON, in the shape the worker's `json_to_payload`
    /// rebuilds into the matching Pydantic model.
    pub fn payload(&self) -> &Value {
        &self.json
    }

    /// Map a worker's modified legacy payload back onto the original message.
    ///
    /// Only the fields the legacy payload carries are written. A modification
    /// the message has nowhere to hold (tool headers, resource metadata, a
    /// prompt result description, a resource blob) fails closed: dropping it
    /// would silently undo what the plugin asked for.
    pub fn apply_modified(&self, modified: Value) -> Result<MessagePayload, HostError> {
        let mut payload = self.original.clone();
        let part = payload
            .message
            .content
            .get_mut(self.part)
            .ok_or_else(|| self.error("the original content part is gone"))?;

        match (self.shim, part) {
            (Shim::ToolPreInvoke, ContentPart::ToolCall { content }) => {
                let legacy: ToolPreInvokePayload = self.parse(modified)?;
                if legacy.headers.as_ref().is_some_and(|h| !h.is_empty()) {
                    return Err(self.error(
                        "the plugin returned `headers`, which a CMF tool call cannot carry",
                    ));
                }
                content.name = legacy.name;
                content.arguments = legacy.args.unwrap_or_default();
            },
            (Shim::ToolPostInvoke, ContentPart::ToolResult { content }) => {
                let legacy: ToolPostInvokePayload = self.parse(modified)?;
                if content.is_error && !result_says_error(&legacy.result) {
                    return Err(self.error(
                        "the plugin cleared `isError` on an error tool result, and the CMF \
                         `is_error` flag is not mapped back",
                    ));
                }
                content.tool_name = legacy.name;
                content.content = legacy.result;
            },
            (Shim::PromptPreFetch, ContentPart::PromptRequest { content }) => {
                let legacy: PromptPreFetchPayload = self.parse(modified)?;
                content.name = legacy.prompt_id;
                content.arguments = legacy
                    .args
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| (k, Value::String(v)))
                    .collect();
            },
            (Shim::PromptPostFetch, ContentPart::PromptResult { content }) => {
                let legacy: PromptPostFetchPayload = self.parse(modified)?;
                content.messages = self.messages_from_legacy(legacy.result, &content.messages)?;
                content.prompt_name = legacy.prompt_id;
            },
            (Shim::ResourcePreFetch, ContentPart::Resource { content }) => {
                let uri = self.resource_pre_uri(modified)?;
                // Embedded content, its type and its size describe the
                // original URI. Carrying them onto a rewritten URI would serve
                // the old content under the address the plugin chose.
                if uri != content.uri
                    && (content.is_embedded()
                        || content.mime_type.is_some()
                        || content.size_bytes.is_some())
                {
                    return Err(self.error(
                        "the plugin rewrote the URI of a resource that carries content, \
                         mime_type or size_bytes from the original URI",
                    ));
                }
                content.uri = uri;
            },
            (Shim::ResourcePreFetch, ContentPart::ResourceRef { content }) => {
                content.uri = self.resource_pre_uri(modified)?;
            },
            (Shim::ResourcePostFetch, ContentPart::Resource { content }) => {
                let legacy: ResourcePostFetchPayload = self.parse(modified)?;
                let before = content.content.clone();
                let original_uri = std::mem::replace(&mut content.uri, legacy.uri);
                match legacy.content {
                    Value::Null => content.content = None,
                    Value::String(text) => content.content = Some(text),
                    Value::Object(fields) => {
                        if fields.get("blob").is_some_and(|b| !b.is_null()) {
                            return Err(self.error(
                                "the plugin returned resource `content.blob`; binary resource \
                                 content is not carried by the shim",
                            ));
                        }
                        // `content.id` and `content.uri` have no slot of their
                        // own: the part keeps one id and one URI. A change to
                        // either would otherwise be dropped.
                        if fields.get("id").is_some_and(|id| {
                            id.as_str() != Some(content.resource_request_id.as_str())
                        }) {
                            return Err(self.error(
                                "the plugin changed `content.id`, which is not mapped back",
                            ));
                        }
                        if fields.get("uri").is_some_and(|u| {
                            u.as_str() != Some(content.uri.as_str())
                                && u.as_str() != Some(original_uri.as_str())
                        }) {
                            return Err(self.error(
                                "the plugin changed `content.uri` to a value other than `uri`, \
                                 and only `uri` is mapped back",
                            ));
                        }
                        content.content = match fields.get("text") {
                            None | Some(Value::Null) => None,
                            Some(Value::String(text)) => Some(text.clone()),
                            Some(_) => {
                                return Err(self.error("`content.text` must be a string or null"))
                            },
                        };
                        if let Some(mime) = fields.get("mime_type") {
                            content.mime_type = match mime {
                                Value::Null => None,
                                Value::String(m) => Some(m.clone()),
                                _ => {
                                    return Err(
                                        self.error("`content.mime_type` must be a string or null")
                                    )
                                },
                            };
                        }
                    },
                    _ => return Err(self.error("`content` must be an object, a string, or null")),
                }
                // A size measured from the original text would misstate the
                // text the plugin returned.
                if content.content != before && content.size_bytes.is_some() {
                    content.size_bytes = content.content.as_ref().map(|t| t.len() as u64);
                }
            },
            _ => return Err(self.error("the original content part changed kind")),
        }

        Ok(payload)
    }

    fn resource_pre_uri(&self, modified: Value) -> Result<String, HostError> {
        let legacy: ResourcePreFetchPayload = self.parse(modified)?;
        if legacy.metadata.as_ref().is_some_and(|m| !m.is_empty()) {
            return Err(self.error(
                "the plugin returned resource `metadata`, which a CMF resource part cannot carry",
            ));
        }
        Ok(legacy.uri)
    }

    /// Rebuild CMF prompt messages from a legacy `PromptResult` shape.
    ///
    /// A message keeps its original `schema_version` and `channel` when one
    /// exists at the same position; a message the plugin appended gets the
    /// defaults.
    fn messages_from_legacy(
        &self,
        result: Value,
        original: &[Message],
    ) -> Result<Vec<Message>, HostError> {
        let Value::Object(result) = result else {
            return Err(self.error("`result` must be an object with a `messages` list"));
        };
        if result.get("description").is_some_and(|d| !d.is_null()) {
            return Err(self.error(
                "the plugin returned a prompt result `description`, which a CMF prompt result \
                 cannot carry",
            ));
        }
        let Some(Value::Array(items)) = result.get("messages") else {
            return Err(self.error("`result.messages` must be a list"));
        };

        items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let role = item
                    .get("role")
                    .cloned()
                    .and_then(|r| serde_json::from_value::<Role>(r).ok())
                    .ok_or_else(|| {
                        self.error(&format!("`result.messages[{i}].role` is not a CMF role"))
                    })?;
                let text = match item.get("content") {
                    Some(Value::Object(c))
                        if c.get("type").and_then(Value::as_str) == Some("text") =>
                    {
                        c.get("text").and_then(Value::as_str)
                    },
                    _ => None,
                }
                .ok_or_else(|| {
                    self.error(&format!(
                        "`result.messages[{i}].content` must be text content \
                         ({{\"type\": \"text\", \"text\": ...}})"
                    ))
                })?;

                let mut message = original
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| Message::text(role, ""));
                message.role = role;
                message.content = vec![ContentPart::Text {
                    text: text.to_string(),
                }];
                Ok(message)
            })
            .collect()
    }

    fn parse<T: DeserializeOwned>(&self, modified: Value) -> Result<T, HostError> {
        serde_json::from_value(modified).map_err(|e| HostError::Protocol {
            message: format!(
                "worker returned a modified payload that does not match the legacy hook '{}' \
                 (dispatched as '{}'): {e}",
                self.shim.legacy_hook(),
                self.hook_name
            ),
        })
    }

    fn error(&self, message: &str) -> HostError {
        shim_error(&self.hook_name, self.shim.legacy_hook(), message)
    }
}

fn shim_error(hook_name: &str, legacy: &str, message: &str) -> HostError {
    HostError::LegacyShim {
        hook: hook_name.to_string(),
        message: format!("translating to the legacy '{legacy}' payload: {message}"),
    }
}

/// Translate a `cmf.*` hook invocation into the legacy hook a worker without
/// `cmf_hooks` support understands.
///
/// Fails closed for the LLM hooks (no legacy equivalent), for a payload that
/// is not a `MessagePayload`, and for a message that does not hold exactly one
/// content part of the kind the hook's legacy payload is built from.
pub fn to_legacy(
    hook_name: &str,
    payload: &dyn PluginPayload,
) -> Result<ShimmedPayload, HostError> {
    let Some(shim) = Shim::for_hook(hook_name) else {
        return Err(HostError::LegacyShim {
            hook: hook_name.to_string(),
            message: "it has no legacy hook equivalent, so only a worker that claims the \
                      `cmf_hooks` feature can run it. Upgrade the cpex package in the plugin's \
                      venv, or remove the hook from the plugin's `hooks:` list."
                .into(),
        });
    };
    let legacy = shim.legacy_hook();

    let original = payload
        .as_any()
        .downcast_ref::<MessagePayload>()
        .ok_or_else(|| shim_error(hook_name, legacy, "the payload is not a CMF MessagePayload"))?
        .clone();

    let candidates: Vec<usize> = original
        .message
        .content
        .iter()
        .enumerate()
        .filter(|(_, p)| shim.matches(p))
        .map(|(i, _)| i)
        .collect();
    let part = match candidates.as_slice() {
        [only] => *only,
        [] => {
            return Err(shim_error(
                hook_name,
                legacy,
                &format!("the message has no {} content part", shim.part_name()),
            ))
        },
        many => {
            return Err(shim_error(
                hook_name,
                legacy,
                &format!(
                    "the message has {} {} content parts and the legacy payload holds one",
                    many.len(),
                    shim.part_name()
                ),
            ))
        },
    };

    let err = |message: &str| shim_error(hook_name, legacy, message);
    let json = match (shim, &original.message.content[part]) {
        (Shim::ToolPreInvoke, ContentPart::ToolCall { content }) => {
            if is_set(&content.namespace) {
                return Err(err(
                    "the tool call has a `namespace`, which the legacy payload cannot carry; \
                     a plugin that authorizes by bare `name` would approve it in any namespace",
                ));
            }
            to_json(
                &ToolPreInvokePayload {
                    name: content.name.clone(),
                    args: Some(content.arguments.clone()),
                    headers: None,
                },
                &err,
            )?
        },
        (Shim::ToolPostInvoke, ContentPart::ToolResult { content }) => {
            if content.is_error && !result_says_error(&content.content) {
                return Err(err(
                    "the tool result has `is_error` set, and its `content` does not carry \
                     `\"isError\": true` for the legacy plugin to see",
                ));
            }
            to_json(
                &ToolPostInvokePayload {
                    name: content.tool_name.clone(),
                    result: content.content.clone(),
                },
                &err,
            )?
        },
        (Shim::PromptPreFetch, ContentPart::PromptRequest { content }) => {
            if is_set(&content.server_id) {
                return Err(err(
                    "the prompt request has a `server_id`, which the legacy payload cannot \
                     carry; a plugin that authorizes by bare `prompt_id` would approve it on \
                     any server",
                ));
            }
            // dict[str, str] on the Python side, which Pydantic will not coerce
            // a number or an object into.
            let mut args = HashMap::with_capacity(content.arguments.len());
            for (key, value) in &content.arguments {
                let Value::String(s) = value else {
                    return Err(err(&format!(
                        "prompt argument '{key}' is not a string, and the legacy payload's \
                         `args` is dict[str, str]"
                    )));
                };
                args.insert(key.clone(), s.clone());
            }
            to_json(
                &PromptPreFetchPayload {
                    prompt_id: content.name.clone(),
                    args: Some(args),
                },
                &err,
            )?
        },
        (Shim::PromptPostFetch, ContentPart::PromptResult { content }) => {
            // The legacy result holds only messages. Text left in these fields
            // would survive a plugin that redacted the messages.
            if is_set(&content.content) {
                return Err(err(
                    "the prompt result has rendered `content`, which the legacy payload cannot \
                     carry, so a plugin could not inspect or redact it",
                ));
            }
            if is_set(&content.error_message) {
                return Err(err(
                    "the prompt result has an `error_message`, which the legacy payload cannot \
                     carry, so a plugin could not inspect or redact it",
                ));
            }
            if content.is_error {
                return Err(err(
                    "the prompt result has `is_error` set, which the legacy payload cannot carry",
                ));
            }
            let mut messages = Vec::with_capacity(content.messages.len());
            for (i, message) in content.messages.iter().enumerate() {
                let [ContentPart::Text { text }] = message.content.as_slice() else {
                    return Err(err(&format!(
                        "prompt result message {i} is not a single text part, and the legacy \
                         prompt message holds one text content"
                    )));
                };
                messages.push(serde_json::json!({
                    "role": message.role,
                    "content": { "type": "text", "text": text },
                }));
            }
            to_json(
                &PromptPostFetchPayload {
                    prompt_id: content.prompt_name.clone(),
                    result: serde_json::json!({ "messages": messages, "description": null }),
                },
                &err,
            )?
        },
        (Shim::ResourcePreFetch, ContentPart::Resource { content }) => {
            refuse_resource_version(content, &err)?;
            to_json(
                &ResourcePreFetchPayload {
                    uri: content.uri.clone(),
                    metadata: None,
                },
                &err,
            )?
        },
        (Shim::ResourcePreFetch, ContentPart::ResourceRef { content }) => to_json(
            &ResourcePreFetchPayload {
                uri: content.uri.clone(),
                metadata: None,
            },
            &err,
        )?,
        (Shim::ResourcePostFetch, ContentPart::Resource { content }) => {
            refuse_resource_version(content, &err)?;
            if content.blob.is_some() {
                return Err(err(
                    "the resource carries binary `blob` content, which the shim does not \
                     translate",
                ));
            }
            // The legacy `ResourceContent` shape 0.1.x plugins read.
            to_json(
                &ResourcePostFetchPayload {
                    uri: content.uri.clone(),
                    content: serde_json::json!({
                        "type": "resource",
                        "id": content.resource_request_id,
                        "uri": content.uri,
                        "mime_type": content.mime_type,
                        "text": content.content,
                    }),
                },
                &err,
            )?
        },
        (Shim::ResourcePostFetch, ContentPart::ResourceRef { .. }) => {
            return Err(err(
                "the message holds a resource_ref with no content, and the legacy post-fetch \
                 payload carries the content",
            ))
        },
        // `candidates` only holds parts `shim.matches` accepted, and every
        // accepted pairing is handled above.
        _ => return Err(err("unexpected content part")),
    };

    Ok(ShimmedPayload {
        shim,
        hook_name: hook_name.to_string(),
        original,
        part,
        json,
    })
}

/// Whether an optional string field holds a value. An empty string carries
/// nothing and counts as unset.
fn is_set(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.is_empty())
}

/// Whether a legacy tool result tells the plugin it is an error, the MCP
/// `CallToolResult` way.
fn result_says_error(result: &Value) -> bool {
    result.get("isError") == Some(&Value::Bool(true))
}

fn refuse_resource_version(
    resource: &Resource,
    err: &dyn Fn(&str) -> HostError,
) -> Result<(), HostError> {
    if is_set(&resource.version) {
        return Err(err(
            "the resource has a `version`, which the legacy payload cannot carry; a plugin \
             that authorizes by `uri` would approve any revision",
        ));
    }
    Ok(())
}

fn to_json<T: Serialize>(value: &T, err: &dyn Fn(&str) -> HostError) -> Result<Value, HostError> {
    serde_json::to_value(value).map_err(|e| err(&format!("could not serialize: {e}")))
}

#[cfg(test)]
mod tests {
    use praxis_policy_core::cmf::{
        Channel, PromptRequest, PromptResult, Resource, ResourceReference, ResourceType, ToolCall,
        ToolResult,
    };
    use serde_json::json;

    use super::*;

    // --- fixtures -----------------------------------------------------------

    /// A text part placed around the target part, so every round trip can
    /// assert that unrelated content survives.
    fn context_text() -> ContentPart {
        ContentPart::Text {
            text: "unrelated context".into(),
        }
    }

    /// A message with the target part between two unrelated parts.
    fn message_around(part: ContentPart) -> MessagePayload {
        let mut message = Message::with_content(
            Role::Assistant,
            vec![
                context_text(),
                part,
                ContentPart::Thinking {
                    text: "unrelated reasoning".into(),
                },
            ],
        );
        message.channel = Some(Channel::Commentary);
        MessagePayload { message }
    }

    fn tool_call(args: Value) -> ContentPart {
        ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "call-1".into(),
                name: "search".into(),
                arguments: serde_json::from_value(args).unwrap(),
                namespace: None,
            },
        }
    }

    fn tool_result(content: Value) -> ContentPart {
        ContentPart::ToolResult {
            content: ToolResult {
                tool_call_id: "call-1".into(),
                tool_name: "search".into(),
                content,
                is_error: false,
            },
        }
    }

    fn prompt_request(args: Value) -> ContentPart {
        ContentPart::PromptRequest {
            content: PromptRequest {
                prompt_request_id: "pr-1".into(),
                name: "greeting".into(),
                arguments: serde_json::from_value(args).unwrap(),
                server_id: None,
            },
        }
    }

    fn prompt_result(messages: Vec<Message>) -> ContentPart {
        ContentPart::PromptResult {
            content: PromptResult {
                prompt_request_id: "pr-1".into(),
                prompt_name: "greeting".into(),
                messages,
                content: None,
                is_error: false,
                error_message: None,
            },
        }
    }

    fn resource(text: Option<&str>) -> Resource {
        Resource {
            resource_request_id: "res-1".into(),
            uri: "file:///tmp/a.txt".into(),
            name: Some("a".into()),
            description: None,
            resource_type: ResourceType::File,
            content: text.map(str::to_string),
            blob: None,
            mime_type: Some("text/plain".into()),
            size_bytes: Some(5),
            annotations: HashMap::from([("k".into(), json!("v"))]),
            version: None,
        }
    }

    fn resource_ref() -> ContentPart {
        ContentPart::ResourceRef {
            content: ResourceReference {
                resource_request_id: "res-1".into(),
                uri: "file:///tmp/a.txt".into(),
                name: None,
                resource_type: ResourceType::File,
                range_start: Some(1),
                range_end: None,
                selector: None,
            },
        }
    }

    fn json_of(payload: &MessagePayload) -> Value {
        serde_json::to_value(payload).unwrap()
    }

    /// Assert the parts around index 1 and the message-level fields are what
    /// `message_around` built.
    fn assert_surroundings_kept(payload: &MessagePayload) {
        let json = json_of(payload);
        assert_eq!(
            json["message"]["content"][0],
            json!({"content_type": "text", "text": "unrelated context"})
        );
        assert_eq!(
            json["message"]["content"][2],
            json!({"content_type": "thinking", "text": "unrelated reasoning"})
        );
        assert_eq!(json["message"]["role"], "assistant");
        assert_eq!(json["message"]["channel"], "commentary");
        assert_eq!(payload.message.content.len(), 3);
    }

    /// The JSON the target part serializes to, for a whole-part comparison.
    fn part_json(payload: &MessagePayload) -> Value {
        json_of(payload)["message"]["content"][1].clone()
    }

    fn assert_shim_error(err: HostError, hook: &str, needle: &str) {
        let text = err.to_string();
        assert!(matches!(err, HostError::LegacyShim { .. }), "got {err:?}");
        assert!(text.contains(hook), "the error must name the hook: {text}");
        assert!(text.contains(needle), "expected '{needle}' in: {text}");
    }

    // --- hook table ---------------------------------------------------------

    #[test]
    fn the_six_tool_prompt_and_resource_hooks_map_to_legacy_names() {
        for (cmf, legacy) in [
            ("cmf.tool_pre_invoke", "tool_pre_invoke"),
            ("cmf.tool_post_invoke", "tool_post_invoke"),
            ("cmf.prompt_pre_invoke", "prompt_pre_fetch"),
            ("cmf.prompt_post_invoke", "prompt_post_fetch"),
            ("cmf.resource_pre_fetch", "resource_pre_fetch"),
            ("cmf.resource_post_fetch", "resource_post_fetch"),
        ] {
            assert_eq!(legacy_hook_name(cmf), Some(legacy), "{cmf}");
            assert!(is_cmf_hook(cmf));
        }
    }

    #[test]
    fn every_cmf_hook_ppe_dispatches_is_covered() {
        // A new upstream cmf hook must be either shimmed or refused, never
        // forwarded under a name the old worker does not know.
        for hook in praxis_policy_core::hooks::builtin_hook_types() {
            let name = hook.as_str();
            if name.starts_with("cmf.") {
                assert!(
                    is_cmf_hook(name),
                    "'{name}' is not covered by the shim table"
                );
            }
        }
    }

    #[test]
    fn non_cmf_hooks_are_not_shimmed() {
        for hook in [
            "tool_pre_invoke",
            "identity.resolve",
            "token.delegate",
            "cmf.custom",
        ] {
            assert!(!is_cmf_hook(hook), "{hook}");
            assert_eq!(legacy_hook_name(hook), None, "{hook}");
        }
    }

    // --- cmf.tool_pre_invoke ------------------------------------------------

    #[test]
    fn tool_pre_invoke_sends_name_and_args() {
        let payload = message_around(tool_call(json!({"q": "rust", "n": 3})));
        let shimmed = to_legacy("cmf.tool_pre_invoke", &payload).unwrap();

        assert_eq!(shimmed.legacy_hook(), "tool_pre_invoke");
        assert_eq!(
            shimmed.payload(),
            &json!({"name": "search", "args": {"q": "rust", "n": 3}})
        );
    }

    #[test]
    fn tool_pre_invoke_unchanged_round_trip_preserves_the_message() {
        let payload = message_around(tool_call(json!({"q": "rust"})));
        let shimmed = to_legacy("cmf.tool_pre_invoke", &payload).unwrap();

        // What the 0.1.x worker's `model_dump(mode="json")` returns for an
        // unmodified payload: every field, `headers` as null.
        let back = shimmed
            .apply_modified(json!({"name": "search", "args": {"q": "rust"}, "headers": null}))
            .unwrap();
        assert_eq!(json_of(&back), json_of(&payload));
    }

    #[test]
    fn tool_pre_invoke_modified_args_map_back() {
        let payload = message_around(tool_call(json!({"q": "alice@example.com"})));
        let shimmed = to_legacy("cmf.tool_pre_invoke", &payload).unwrap();

        let back = shimmed
            .apply_modified(
                json!({"name": "search", "args": {"q": "[REDACTED]", "extra": 1}, "headers": {}}),
            )
            .unwrap();
        assert_eq!(
            part_json(&back),
            json!({"content_type": "tool_call", "content": {
                "tool_call_id": "call-1",
                "name": "search",
                "arguments": {"q": "[REDACTED]", "extra": 1},
            }})
        );
        assert_surroundings_kept(&back);
    }

    #[test]
    fn tool_pre_invoke_returned_headers_fail_closed() {
        let payload = message_around(tool_call(json!({})));
        let shimmed = to_legacy("cmf.tool_pre_invoke", &payload).unwrap();
        let err = shimmed
            .apply_modified(json!({"name": "search", "args": {}, "headers": {"X-Injected": "1"}}))
            .unwrap_err();
        assert_shim_error(err, "cmf.tool_pre_invoke", "headers");
    }

    #[test]
    fn tool_pre_invoke_without_a_tool_call_fails_closed() {
        let payload = MessagePayload {
            message: Message::text(Role::User, "what is the weather?"),
        };
        let err = to_legacy("cmf.tool_pre_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.tool_pre_invoke", "no tool_call content part");
    }

    #[test]
    fn tool_pre_invoke_with_two_tool_calls_fails_closed() {
        let payload = MessagePayload {
            message: Message::with_content(
                Role::Assistant,
                vec![tool_call(json!({})), tool_call(json!({}))],
            ),
        };
        let err = to_legacy("cmf.tool_pre_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.tool_pre_invoke", "2 tool_call content parts");
    }

    #[test]
    fn a_modified_payload_missing_required_fields_is_a_protocol_error() {
        let payload = message_around(tool_call(json!({})));
        let shimmed = to_legacy("cmf.tool_pre_invoke", &payload).unwrap();
        let err = shimmed.apply_modified(json!({"args": {}})).unwrap_err();
        assert!(matches!(err, HostError::Protocol { .. }), "got {err:?}");
        assert!(err.to_string().contains("tool_pre_invoke"), "{err}");
    }

    // --- cmf.tool_post_invoke -----------------------------------------------

    #[test]
    fn tool_post_invoke_sends_name_and_result() {
        let result = json!({"content": [{"type": "text", "text": "3 hits"}], "isError": false});
        let payload = message_around(tool_result(result.clone()));
        let shimmed = to_legacy("cmf.tool_post_invoke", &payload).unwrap();

        assert_eq!(shimmed.legacy_hook(), "tool_post_invoke");
        assert_eq!(
            shimmed.payload(),
            &json!({"name": "search", "result": result})
        );

        let back = shimmed.apply_modified(shimmed.payload().clone()).unwrap();
        assert_eq!(json_of(&back), json_of(&payload));
    }

    #[test]
    fn tool_post_invoke_modified_result_maps_back() {
        let payload = message_around(tool_result(json!({"text": "ssn 123-45-6789"})));
        let shimmed = to_legacy("cmf.tool_post_invoke", &payload).unwrap();

        let back = shimmed
            .apply_modified(json!({"name": "search", "result": {"text": "ssn [REDACTED]"}}))
            .unwrap();
        assert_eq!(
            part_json(&back),
            json!({"content_type": "tool_result", "content": {
                "tool_call_id": "call-1",
                "tool_name": "search",
                "content": {"text": "ssn [REDACTED]"},
                "is_error": false,
            }})
        );
        assert_surroundings_kept(&back);
    }

    #[test]
    fn tool_post_invoke_without_a_tool_result_fails_closed() {
        let payload = message_around(tool_call(json!({})));
        let err = to_legacy("cmf.tool_post_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.tool_post_invoke", "no tool_result content part");
    }

    // --- cmf.prompt_pre_invoke ----------------------------------------------

    #[test]
    fn prompt_pre_invoke_sends_prompt_id_and_string_args() {
        let payload = message_around(prompt_request(json!({"lang": "en"})));
        let shimmed = to_legacy("cmf.prompt_pre_invoke", &payload).unwrap();

        assert_eq!(shimmed.legacy_hook(), "prompt_pre_fetch");
        assert_eq!(
            shimmed.payload(),
            &json!({"prompt_id": "greeting", "args": {"lang": "en"}})
        );

        let back = shimmed.apply_modified(shimmed.payload().clone()).unwrap();
        assert_eq!(json_of(&back), json_of(&payload));
    }

    #[test]
    fn prompt_pre_invoke_modified_args_map_back() {
        let payload = message_around(prompt_request(json!({"lang": "en", "who": "bob"})));
        let shimmed = to_legacy("cmf.prompt_pre_invoke", &payload).unwrap();

        let back = shimmed
            .apply_modified(json!({"prompt_id": "greeting", "args": {"lang": "fr"}}))
            .unwrap();
        assert_eq!(
            part_json(&back),
            json!({"content_type": "prompt_request", "content": {
                "prompt_request_id": "pr-1",
                "name": "greeting",
                "arguments": {"lang": "fr"},
            }})
        );
        assert_surroundings_kept(&back);
    }

    #[test]
    fn prompt_pre_invoke_with_a_non_string_argument_fails_closed() {
        let payload = message_around(prompt_request(json!({"count": 5})));
        let err = to_legacy("cmf.prompt_pre_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.prompt_pre_invoke", "'count' is not a string");
    }

    #[test]
    fn prompt_pre_invoke_without_a_prompt_request_fails_closed() {
        let payload = message_around(tool_call(json!({})));
        let err = to_legacy("cmf.prompt_pre_invoke", &payload).unwrap_err();
        assert_shim_error(
            err,
            "cmf.prompt_pre_invoke",
            "no prompt_request content part",
        );
    }

    // --- cmf.prompt_post_invoke ---------------------------------------------

    #[test]
    fn prompt_post_invoke_sends_mcp_shaped_messages() {
        let payload = message_around(prompt_result(vec![
            Message::text(Role::System, "be brief"),
            Message::text(Role::User, "hi bob"),
        ]));
        let shimmed = to_legacy("cmf.prompt_post_invoke", &payload).unwrap();

        assert_eq!(shimmed.legacy_hook(), "prompt_post_fetch");
        assert_eq!(
            shimmed.payload(),
            &json!({"prompt_id": "greeting", "result": {
                "messages": [
                    {"role": "system", "content": {"type": "text", "text": "be brief"}},
                    {"role": "user", "content": {"type": "text", "text": "hi bob"}},
                ],
                "description": null,
            }})
        );

        let back = shimmed.apply_modified(shimmed.payload().clone()).unwrap();
        assert_eq!(json_of(&back), json_of(&payload));
    }

    #[test]
    fn prompt_post_invoke_modified_messages_map_back() {
        let mut first = Message::text(Role::User, "hi bob");
        first.channel = Some(Channel::Final);
        let payload = message_around(prompt_result(vec![first]));
        let shimmed = to_legacy("cmf.prompt_post_invoke", &payload).unwrap();

        // Pydantic dumps the fixture TextContent's extra fields; they are
        // tolerated and dropped.
        let back = shimmed
            .apply_modified(json!({"prompt_id": "greeting", "result": {
                "messages": [
                    {"role": "user", "content": {"type": "text", "text": "hi [NAME]", "annotations": null}},
                    {"role": "assistant", "content": {"type": "text", "text": "appended"}},
                ],
                "description": null,
            }}))
            .unwrap();

        let part = part_json(&back);
        assert_eq!(
            part["content"]["prompt_request_id"], "pr-1",
            "unmapped fields survive"
        );
        let messages = &part["content"]["messages"];
        assert_eq!(messages[0]["content"][0]["text"], "hi [NAME]");
        assert_eq!(
            messages[0]["channel"], "final",
            "the original message's channel is kept"
        );
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["content"][0]["text"], "appended");
        assert_surroundings_kept(&back);
    }

    #[test]
    fn prompt_post_invoke_with_a_multipart_message_fails_closed() {
        let payload = message_around(prompt_result(vec![Message::with_content(
            Role::User,
            vec![context_text(), context_text()],
        )]));
        let err = to_legacy("cmf.prompt_post_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.prompt_post_invoke", "not a single text part");
    }

    #[test]
    fn prompt_post_invoke_returned_description_fails_closed() {
        let payload = message_around(prompt_result(vec![]));
        let shimmed = to_legacy("cmf.prompt_post_invoke", &payload).unwrap();
        let err = shimmed
            .apply_modified(
                json!({"prompt_id": "greeting", "result": {"messages": [], "description": "x"}}),
            )
            .unwrap_err();
        assert_shim_error(err, "cmf.prompt_post_invoke", "description");
    }

    #[test]
    fn prompt_post_invoke_returned_non_text_content_fails_closed() {
        let payload = message_around(prompt_result(vec![]));
        let shimmed = to_legacy("cmf.prompt_post_invoke", &payload).unwrap();
        let err = shimmed
            .apply_modified(json!({"prompt_id": "greeting", "result": {"messages": [
                {"role": "user", "content": {"type": "image", "data": "..."}}
            ]}}))
            .unwrap_err();
        assert_shim_error(err, "cmf.prompt_post_invoke", "messages[0].content");
    }

    // --- cmf.resource_pre_fetch ---------------------------------------------

    #[test]
    fn resource_pre_fetch_sends_the_uri_from_a_reference() {
        let payload = message_around(resource_ref());
        let shimmed = to_legacy("cmf.resource_pre_fetch", &payload).unwrap();

        assert_eq!(shimmed.legacy_hook(), "resource_pre_fetch");
        assert_eq!(shimmed.payload(), &json!({"uri": "file:///tmp/a.txt"}));

        // `metadata: {}` is what Pydantic's default dumps as.
        let back = shimmed
            .apply_modified(json!({"uri": "file:///tmp/a.txt", "metadata": {}}))
            .unwrap();
        assert_eq!(json_of(&back), json_of(&payload));
    }

    /// A resource with no fetched content yet: nothing describes the URI
    /// beyond labels.
    fn unfetched_resource() -> Resource {
        Resource {
            mime_type: None,
            size_bytes: None,
            ..resource(None)
        }
    }

    #[test]
    fn resource_pre_fetch_modified_uri_maps_back_onto_an_unfetched_resource() {
        let payload = message_around(ContentPart::Resource {
            content: unfetched_resource(),
        });
        let shimmed = to_legacy("cmf.resource_pre_fetch", &payload).unwrap();

        let back = shimmed
            .apply_modified(json!({"uri": "file:///safe/a.txt", "metadata": {}}))
            .unwrap();
        let mut expected = unfetched_resource();
        expected.uri = "file:///safe/a.txt".into();
        assert_eq!(
            part_json(&back),
            serde_json::to_value(ContentPart::Resource { content: expected }).unwrap()
        );
        assert_surroundings_kept(&back);
    }

    #[test]
    fn resource_pre_fetch_returned_metadata_fails_closed() {
        let payload = message_around(resource_ref());
        let shimmed = to_legacy("cmf.resource_pre_fetch", &payload).unwrap();
        let err = shimmed
            .apply_modified(json!({"uri": "file:///tmp/a.txt", "metadata": {"etag": "x"}}))
            .unwrap_err();
        assert_shim_error(err, "cmf.resource_pre_fetch", "metadata");
    }

    #[test]
    fn resource_pre_fetch_without_a_resource_fails_closed() {
        let payload = MessagePayload {
            message: Message::text(Role::User, "no resource here"),
        };
        let err = to_legacy("cmf.resource_pre_fetch", &payload).unwrap_err();
        assert_shim_error(err, "cmf.resource_pre_fetch", "no resource or resource_ref");
    }

    // --- cmf.resource_post_fetch --------------------------------------------

    #[test]
    fn resource_post_fetch_sends_legacy_resource_content() {
        let payload = message_around(ContentPart::Resource {
            content: resource(Some("hello")),
        });
        let shimmed = to_legacy("cmf.resource_post_fetch", &payload).unwrap();

        assert_eq!(shimmed.legacy_hook(), "resource_post_fetch");
        assert_eq!(
            shimmed.payload(),
            &json!({"uri": "file:///tmp/a.txt", "content": {
                "type": "resource",
                "id": "res-1",
                "uri": "file:///tmp/a.txt",
                "mime_type": "text/plain",
                "text": "hello",
            }})
        );

        let back = shimmed.apply_modified(shimmed.payload().clone()).unwrap();
        assert_eq!(json_of(&back), json_of(&payload));
    }

    #[test]
    fn resource_post_fetch_modified_content_maps_back() {
        let payload = message_around(ContentPart::Resource {
            content: resource(Some("password=hunter2")),
        });
        let shimmed = to_legacy("cmf.resource_post_fetch", &payload).unwrap();

        let back = shimmed
            .apply_modified(json!({"uri": "file:///tmp/a.txt", "content": {
                "type": "resource", "id": "res-1", "uri": "file:///tmp/a.txt",
                "mime_type": "text/plain", "text": "password=[REDACTED]", "blob": null,
            }}))
            .unwrap();
        let mut expected = resource(Some("password=[REDACTED]"));
        expected.size_bytes = Some("password=[REDACTED]".len() as u64);
        assert_eq!(
            part_json(&back),
            serde_json::to_value(ContentPart::Resource { content: expected }).unwrap(),
            "the text changes and the size follows it; name and annotations survive"
        );
        assert_surroundings_kept(&back);
    }

    #[test]
    fn resource_post_fetch_accepts_plain_string_content() {
        let payload = message_around(ContentPart::Resource {
            content: resource(Some("a")),
        });
        let shimmed = to_legacy("cmf.resource_post_fetch", &payload).unwrap();
        let back = shimmed
            .apply_modified(json!({"uri": "file:///tmp/a.txt", "content": "b"}))
            .unwrap();
        assert_eq!(part_json(&back)["content"]["content"], "b");
    }

    #[test]
    fn resource_post_fetch_with_a_blob_fails_closed() {
        let mut binary = resource(None);
        binary.blob = Some(vec![0, 1, 2]);
        let payload = message_around(ContentPart::Resource { content: binary });
        let err = to_legacy("cmf.resource_post_fetch", &payload).unwrap_err();
        assert_shim_error(err, "cmf.resource_post_fetch", "blob");
    }

    #[test]
    fn resource_post_fetch_with_only_a_reference_fails_closed() {
        let payload = message_around(resource_ref());
        let err = to_legacy("cmf.resource_post_fetch", &payload).unwrap_err();
        assert_shim_error(
            err,
            "cmf.resource_post_fetch",
            "resource_ref with no content",
        );
    }

    #[test]
    fn resource_post_fetch_returned_blob_fails_closed() {
        let payload = message_around(ContentPart::Resource {
            content: resource(Some("a")),
        });
        let shimmed = to_legacy("cmf.resource_post_fetch", &payload).unwrap();
        let err = shimmed
            .apply_modified(json!({"uri": "file:///tmp/a.txt", "content": {"blob": "AAEC"}}))
            .unwrap_err();
        assert_shim_error(err, "cmf.resource_post_fetch", "blob");
    }

    // --- fields the legacy payload cannot carry ------------------------------

    #[test]
    fn tool_pre_invoke_with_a_namespace_fails_closed() {
        let mut part = tool_call(json!({}));
        if let ContentPart::ToolCall { content } = &mut part {
            content.namespace = Some("other-tenant".into());
        }
        let err = to_legacy("cmf.tool_pre_invoke", &message_around(part)).unwrap_err();
        assert_shim_error(err, "cmf.tool_pre_invoke", "namespace");
    }

    #[test]
    fn tool_pre_invoke_with_an_empty_namespace_is_unqualified() {
        let mut part = tool_call(json!({}));
        if let ContentPart::ToolCall { content } = &mut part {
            content.namespace = Some(String::new());
        }
        let payload = message_around(part);
        let shimmed = to_legacy("cmf.tool_pre_invoke", &payload).unwrap();
        let back = shimmed.apply_modified(shimmed.payload().clone()).unwrap();
        assert_eq!(json_of(&back), json_of(&payload));
    }

    fn error_tool_result(content: Value) -> ContentPart {
        let mut part = tool_result(content);
        if let ContentPart::ToolResult { content } = &mut part {
            content.is_error = true;
        }
        part
    }

    #[test]
    fn tool_post_invoke_error_the_result_does_not_show_fails_closed() {
        let payload = message_around(error_tool_result(json!({"text": "boom"})));
        let err = to_legacy("cmf.tool_post_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.tool_post_invoke", "is_error");
    }

    #[test]
    fn tool_post_invoke_error_the_result_shows_round_trips() {
        let payload = message_around(error_tool_result(json!({"content": [], "isError": true})));
        let shimmed = to_legacy("cmf.tool_post_invoke", &payload).unwrap();
        let back = shimmed.apply_modified(shimmed.payload().clone()).unwrap();
        assert_eq!(json_of(&back), json_of(&payload));
    }

    #[test]
    fn tool_post_invoke_clearing_is_error_fails_closed() {
        let payload = message_around(error_tool_result(json!({"content": [], "isError": true})));
        let shimmed = to_legacy("cmf.tool_post_invoke", &payload).unwrap();
        let err = shimmed
            .apply_modified(json!({"name": "search", "result": {"content": [], "isError": false}}))
            .unwrap_err();
        assert_shim_error(err, "cmf.tool_post_invoke", "isError");
    }

    #[test]
    fn prompt_pre_invoke_with_a_server_id_fails_closed() {
        let mut part = prompt_request(json!({}));
        if let ContentPart::PromptRequest { content } = &mut part {
            content.server_id = Some("other-server".into());
        }
        let err = to_legacy("cmf.prompt_pre_invoke", &message_around(part)).unwrap_err();
        assert_shim_error(err, "cmf.prompt_pre_invoke", "server_id");
    }

    fn prompt_result_with(edit: impl FnOnce(&mut PromptResult)) -> MessagePayload {
        let mut part = prompt_result(vec![Message::text(Role::User, "hi bob")]);
        if let ContentPart::PromptResult { content } = &mut part {
            edit(content);
        }
        message_around(part)
    }

    #[test]
    fn prompt_post_invoke_with_rendered_content_fails_closed() {
        // A plugin that redacts `messages` would leave "hi bob" here.
        let payload = prompt_result_with(|r| r.content = Some("hi bob".into()));
        let err = to_legacy("cmf.prompt_post_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.prompt_post_invoke", "`content`");
    }

    #[test]
    fn prompt_post_invoke_with_an_error_message_fails_closed() {
        let payload = prompt_result_with(|r| r.error_message = Some("failed for bob".into()));
        let err = to_legacy("cmf.prompt_post_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.prompt_post_invoke", "error_message");
    }

    #[test]
    fn prompt_post_invoke_with_is_error_fails_closed() {
        let payload = prompt_result_with(|r| r.is_error = true);
        let err = to_legacy("cmf.prompt_post_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.prompt_post_invoke", "is_error");
    }

    #[test]
    fn resource_hooks_with_a_version_fail_closed() {
        let mut versioned = resource(Some("a"));
        versioned.version = Some("v1".into());
        let payload = message_around(ContentPart::Resource { content: versioned });
        for hook in ["cmf.resource_pre_fetch", "cmf.resource_post_fetch"] {
            let err = to_legacy(hook, &payload).unwrap_err();
            assert_shim_error(err, hook, "version");
        }
    }

    #[test]
    fn resource_pre_fetch_unchanged_uri_keeps_embedded_content() {
        let payload = message_around(ContentPart::Resource {
            content: resource(Some("hello")),
        });
        let shimmed = to_legacy("cmf.resource_pre_fetch", &payload).unwrap();
        let back = shimmed
            .apply_modified(json!({"uri": "file:///tmp/a.txt", "metadata": {}}))
            .unwrap();
        assert_eq!(json_of(&back), json_of(&payload));
    }

    #[test]
    fn resource_pre_fetch_uri_rewrite_on_fetched_content_fails_closed() {
        let embedded = resource(Some("hello"));
        let mut sized = unfetched_resource();
        sized.size_bytes = Some(5);
        let mut typed = unfetched_resource();
        typed.mime_type = Some("text/plain".into());
        let mut binary = unfetched_resource();
        binary.blob = Some(vec![1]);
        for res in [embedded, sized, typed, binary] {
            let payload = message_around(ContentPart::Resource { content: res });
            let shimmed = to_legacy("cmf.resource_pre_fetch", &payload).unwrap();
            let err = shimmed
                .apply_modified(json!({"uri": "file:///safe/a.txt", "metadata": {}}))
                .unwrap_err();
            assert_shim_error(err, "cmf.resource_pre_fetch", "rewrote the URI");
        }
    }

    #[test]
    fn resource_post_fetch_changed_content_id_fails_closed() {
        let payload = message_around(ContentPart::Resource {
            content: resource(Some("a")),
        });
        let shimmed = to_legacy("cmf.resource_post_fetch", &payload).unwrap();
        let err = shimmed
            .apply_modified(json!({"uri": "file:///tmp/a.txt", "content": {
                "id": "res-2", "uri": "file:///tmp/a.txt", "text": "a",
            }}))
            .unwrap_err();
        assert_shim_error(err, "cmf.resource_post_fetch", "content.id");
    }

    #[test]
    fn resource_post_fetch_content_uri_alone_changed_fails_closed() {
        let payload = message_around(ContentPart::Resource {
            content: resource(Some("a")),
        });
        let shimmed = to_legacy("cmf.resource_post_fetch", &payload).unwrap();
        let err = shimmed
            .apply_modified(json!({"uri": "file:///tmp/a.txt", "content": {
                "id": "res-1", "uri": "file:///safe/a.txt", "text": "a",
            }}))
            .unwrap_err();
        assert_shim_error(err, "cmf.resource_post_fetch", "content.uri");
    }

    #[test]
    fn resource_post_fetch_top_level_uri_change_maps_back() {
        let payload = message_around(ContentPart::Resource {
            content: resource(Some("a")),
        });
        let shimmed = to_legacy("cmf.resource_post_fetch", &payload).unwrap();
        let back = shimmed
            .apply_modified(json!({"uri": "file:///safe/a.txt", "content": {
                "id": "res-1", "uri": "file:///tmp/a.txt", "text": "a",
            }}))
            .unwrap();
        assert_eq!(part_json(&back)["content"]["uri"], "file:///safe/a.txt");
        assert_eq!(
            part_json(&back)["content"]["size_bytes"],
            5,
            "text unchanged"
        );
    }

    // --- refusals -----------------------------------------------------------

    #[test]
    fn llm_hooks_have_no_legacy_equivalent_and_fail_closed() {
        let payload = MessagePayload {
            message: Message::text(Role::User, "hello"),
        };
        for hook in ["cmf.llm_input", "cmf.llm_output"] {
            assert!(is_cmf_hook(hook));
            let err = to_legacy(hook, &payload).unwrap_err();
            assert_shim_error(err, hook, "cmf_hooks");
        }
    }

    #[test]
    fn a_non_message_payload_fails_closed() {
        let payload = ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        };
        let err = to_legacy("cmf.tool_pre_invoke", &payload).unwrap_err();
        assert_shim_error(err, "cmf.tool_pre_invoke", "not a CMF MessagePayload");
    }

    #[test]
    fn shim_errors_carry_no_payload_values() {
        // Error text reaches logs. A refusal must name shapes, not content.
        let payload = MessagePayload {
            message: Message::text(Role::User, "SECRET-USER-TEXT"),
        };
        let err = to_legacy("cmf.tool_pre_invoke", &payload).unwrap_err();
        assert!(!err.to_string().contains("SECRET-USER-TEXT"), "{err}");
    }
}
