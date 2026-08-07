// Location: ./crates/apl-cpex/src/message_projection.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor, Fred Araujo
//
// Projections between a CMF `Message` and the flat JSON APL evaluates
// against (`RoutePayload.args` / `RoutePayload.result`), plus their
// inverses.
//
// APL reasons about `args.<field>` and `result.<field>`; CMF carries
// typed content parts. These functions are the only translation between
// the two, and both consumers depend on them agreeing:
//
//   * `AplRouteHandler` projects before evaluation and writes back
//     after, so pipeline edits reach the host's body re-serializer.
//   * `CmfPluginInvoker` projects a plugin-mutated message to read back
//     the field a pipeline stage was focused on.
//
// Phase decides the side: Pre projects args, Post projects result. Each
// `write_*` is the inverse of the matching `extract_*`, so
// extract → write round-trips a message unchanged.
//
// The projections are lossy by design: they surface the one part APL
// addresses (a tool call's arguments, a tool result's content) and
// ignore the rest. That makes them unfit for answering "did anything
// change?" about a whole message — a mutation to any part they don't
// read is invisible. Callers needing that answer read the mutation
// signal the executor reports instead.

use serde_json::Value;

use cpex_core::cmf::{ContentPart, Message};

/// Rewrite the first text part of `msg` with `new_text`. If there is no
/// text part, append one. Mirrors what `MessagePayload`'s normal
/// modify-path does for single-view v0.
pub(crate) fn rewrite_message_text(msg: &mut Message, new_text: &str) {
    for part in msg.content.iter_mut() {
        if let ContentPart::Text { text } = part {
            *text = new_text.to_string();
            return;
        }
    }
    msg.content.push(ContentPart::Text {
        text: new_text.to_string(),
    });
}

/// Extract `RoutePayload.args` from a CMF message. v0 maps:
///   * First `ContentPart::ToolCall`      → `arguments` map (Object)
///   * First `ContentPart::PromptRequest` → `arguments` map (Object)
///   * Else (text / no entity parts)      → JSON String of text content
///
/// `args.<field>` APL paths target tool / prompt arguments directly.
/// For text-only messages we fall back to the v0 "args = whole text"
/// shape so `args.text` predicates keep working.
pub(crate) fn extract_args_from_message(msg: &Message) -> Value {
    for part in &msg.content {
        match part {
            ContentPart::ToolCall { content } => {
                return Value::Object(
                    content
                        .arguments
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                );
            },
            ContentPart::PromptRequest { content } => {
                return Value::Object(
                    content
                        .arguments
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                );
            },
            _ => {},
        }
    }
    Value::String(msg.get_text_content())
}

/// Inverse of [`extract_args_from_message`]: write `args` back into
/// `msg`'s first ToolCall / PromptRequest argument map, or — for
/// text payloads — into the first text part.
///
/// Silently no-ops when the args shape doesn't match the message
/// content shape (e.g. operator pipeline produced a String for what
/// was originally a ToolCall). The mismatch path is recoverable —
/// the upstream just sees the original unmodified content rather
/// than a malformed rewrite.
pub(crate) fn write_args_back_to_message(msg: &mut Message, args: &Value) {
    for part in msg.content.iter_mut() {
        match part {
            ContentPart::ToolCall { content } => {
                if let Some(obj) = args.as_object() {
                    content.arguments = obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                }
                return;
            },
            ContentPart::PromptRequest { content } => {
                if let Some(obj) = args.as_object() {
                    content.arguments = obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                }
                return;
            },
            _ => {},
        }
    }
    // Fall through: no structured entity part — treat as text.
    if let Some(text) = args.as_str() {
        rewrite_message_text(msg, text);
    }
}

/// Extract `RoutePayload.result` from a CMF message. Mirror of
/// [`extract_args_from_message`] for the Post phase. v0 maps:
///   * First `ContentPart::ToolResult` → its `content` JSON value
///   * Else (text / no structured result part) → JSON String of text
///
/// `result.<field>` APL paths target the structured result directly.
pub(crate) fn extract_result_from_message(msg: &Message) -> Value {
    for part in &msg.content {
        if let ContentPart::ToolResult { content } = part {
            return content.content.clone();
        }
    }
    Value::String(msg.get_text_content())
}

/// Inverse of [`extract_result_from_message`]: write a mutated
/// `result` back into the message's first `ContentPart::ToolResult.content`,
/// or — for text-only messages — into the first text part. The praxis
/// filter's response-body re-serializer then lifts the new content
/// out of the ContentPart and folds it back into the JSON-RPC
/// `result.content[*].text` payload.
pub(crate) fn write_result_back_to_message(msg: &mut Message, result: &Value) {
    for part in msg.content.iter_mut() {
        if let ContentPart::ToolResult { content } = part {
            content.content = result.clone();
            return;
        }
    }
    if let Some(text) = result.as_str() {
        rewrite_message_text(msg, text);
    }
}

/// Apply to `base` only what changed between `pre` and `post`.
///
/// `pre` and `post` bracket one editor's work (an APL pipeline: the
/// projection it started from, and the projection it produced). `base`
/// is the same projection taken from a payload a *different* editor (a
/// plugin) has since rewritten. Copying `post` over `base` wholesale
/// would discard the plugin's edits to keys the pipeline never touched,
/// so instead each differing leaf, added key, and removed key is applied
/// individually.
///
/// When nothing else edited the payload, `base` equals `pre` and the
/// result is exactly `post`.
///
/// Objects merge key by key; arrays and scalars are single values, so a
/// change to one replaces it whole. That matches how APL writes fields:
/// its dotted paths only traverse objects.
///
/// # Precedence when both editors touched the same path
///
/// **The pipeline wins.** If a plugin rewrote a key and the pipeline
/// rewrote it too, the pipeline's value lands; if the plugin *removed* a
/// key the pipeline then rewrote, the key comes back with the pipeline's
/// value; if the pipeline *omitted* a key the plugin had rewritten, the
/// key goes and the plugin's edit with it. Every case logs a warning
/// naming the key, because the losing edit is usually also a redaction
/// and a silent tie-break in this path is exactly the class of bug this
/// function exists to prevent.
///
/// The rule is config-author-wins: an `args:` / `result:` pipeline is
/// written by the operator deploying the policy, so it outranks a
/// plugin's own view when the two genuinely conflict. Neither ordering
/// leaks plaintext (both editors write redacted values), but a coarse
/// pipeline stage can beat a finer plugin redaction, which is why the
/// conflict is logged rather than resolved silently.
pub(crate) fn apply_changed_paths(base: &mut Value, pre: &Value, post: &Value) {
    let (Some(pre_map), Some(post_map)) = (pre.as_object(), post.as_object()) else {
        // Not a keyed shape at this level, so there's nothing to merge
        // per-key: the value either changed or it didn't.
        if pre != post {
            *base = post.clone();
        }
        return;
    };
    let Some(base_map) = base.as_object_mut() else {
        // The other editor replaced the keyed shape with something else
        // entirely. There's no key to merge into, so take this editor's
        // view rather than invent a reconciliation.
        tracing::warn!(
            "payload projection changed shape under a field pipeline; \
             applying the pipeline's view and discarding the other edit"
        );
        *base = post.clone();
        return;
    };

    for (key, pre_value) in pre_map {
        if !post_map.contains_key(key) {
            // Silent when the plugin left the key alone, which is the
            // common case for an `omit`.
            if base_map
                .get(key)
                .is_some_and(|base_value| base_value != pre_value)
            {
                tracing::warn!(
                    field = %key,
                    "pipeline omitted this field, discarding a plugin's edit to it"
                );
            }
            base_map.remove(key);
        }
    }

    for (key, post_value) in post_map {
        match pre_map.get(key) {
            // Untouched by this editor — leave whatever `base` holds,
            // which is the whole point.
            Some(pre_value) if pre_value == post_value => {},
            Some(pre_value) => {
                let nested = base_map
                    .get_mut(key)
                    .filter(|base_value| base_value.is_object())
                    .filter(|_| pre_value.is_object() && post_value.is_object());
                match nested {
                    Some(base_value) => apply_changed_paths(base_value, pre_value, post_value),
                    None => {
                        warn_on_conflict(base_map.get(key), pre_value, key);
                        base_map.insert(key.clone(), post_value.clone());
                    },
                }
            },
            None => {
                // Both editors added the same key. Same precedence, same
                // reason to say so out loud.
                if base_map.contains_key(key) {
                    tracing::warn!(
                        field = %key,
                        "pipeline and plugin both added this field; keeping the pipeline's value"
                    );
                }
                base_map.insert(key.clone(), post_value.clone());
            },
        }
    }
}

/// Log the two ways a pipeline edit can override a plugin's work on the
/// same key: the plugin changed it too, or the plugin removed it. Silent
/// in the common case where the plugin left the key alone.
fn warn_on_conflict(base_value: Option<&Value>, pre_value: &Value, key: &str) {
    match base_value {
        Some(base_value) if base_value != pre_value => tracing::warn!(
            field = %key,
            "pipeline edit overrides a plugin's edit to the same field; \
             keeping the pipeline's value"
        ),
        Some(_) => {},
        None => tracing::warn!(
            field = %key,
            "pipeline edit reinstates a field the plugin removed"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::cmf::enums::Role;
    use cpex_core::cmf::{ToolCall, ToolResult};

    fn tool_call_message() -> Message {
        Message::with_content(
            Role::User,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".to_string(),
                    name: "get_weather".to_string(),
                    arguments: [
                        ("city".to_string(), serde_json::json!("London")),
                        ("units".to_string(), serde_json::json!("metric")),
                    ]
                    .into_iter()
                    .collect(),
                    namespace: None,
                },
            }],
        )
    }

    fn tool_result_message() -> Message {
        Message::with_content(
            Role::Tool,
            vec![ContentPart::ToolResult {
                content: ToolResult {
                    tool_call_id: "tc_001".to_string(),
                    tool_name: "get_weather".to_string(),
                    content: serde_json::json!({"temp": 12, "sky": "grey"}),
                    is_error: false,
                },
            }],
        )
    }

    #[test]
    fn args_round_trip_leaves_a_tool_call_unchanged() {
        let mut msg = tool_call_message();
        let args = extract_args_from_message(&msg);
        write_args_back_to_message(&mut msg, &args);
        assert_eq!(extract_args_from_message(&msg), args);
    }

    #[test]
    fn result_round_trip_leaves_a_tool_result_unchanged() {
        let mut msg = tool_result_message();
        let result = extract_result_from_message(&msg);
        write_result_back_to_message(&mut msg, &result);
        assert_eq!(extract_result_from_message(&msg), result);
    }

    #[test]
    fn text_message_projects_to_its_whole_text_both_ways() {
        let mut msg = Message::text(Role::User, "hello");
        assert_eq!(
            extract_args_from_message(&msg),
            serde_json::json!("hello"),
            "a text-only message has no structured args, so args are the text"
        );
        write_args_back_to_message(&mut msg, &serde_json::json!("goodbye"));
        assert_eq!(msg.get_text_content(), "goodbye");
    }

    #[test]
    fn changed_paths_apply_over_an_untouched_base() {
        // Nobody else edited the payload, so base == pre and applying
        // the changes must land exactly on post.
        let pre = serde_json::json!({"city": "London", "units": "metric"});
        let post = serde_json::json!({"city": "[REDACTED]", "units": "metric"});
        let mut base = pre.clone();
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(base, post);
    }

    #[test]
    fn changed_paths_preserve_another_editors_keys() {
        let pre = serde_json::json!({"city": "London", "token": "sk-secret"});
        // The pipeline rewrote `city` only.
        let post = serde_json::json!({"city": "[REDACTED]", "token": "sk-secret"});
        // Meanwhile a plugin rewrote `token`.
        let mut base = serde_json::json!({"city": "London", "token": "[SCRUBBED]"});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(
            base,
            serde_json::json!({"city": "[REDACTED]", "token": "[SCRUBBED]"}),
            "both editors' work must survive"
        );
    }

    #[test]
    fn changed_paths_apply_removals() {
        let pre = serde_json::json!({"city": "London", "debug": true});
        let post = serde_json::json!({"city": "London"});
        let mut base = serde_json::json!({"city": "Paris", "debug": true});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(base, serde_json::json!({"city": "Paris"}));
    }

    /// The removal counterpart of the same-key conflict: a pipeline `omit`
    /// of a key the plugin had just rewritten still drops the key, and the
    /// plugin's edit with it. Safe in either ordering (the key is gone
    /// whoever wins), so this pins the outcome rather than a leak.
    #[test]
    fn changed_paths_omit_a_key_the_plugin_rewrote() {
        let pre = serde_json::json!({"city": "London", "ssn": "123-45-6789"});
        let post = serde_json::json!({"city": "London"});
        let mut base = serde_json::json!({"city": "London", "ssn": "[REDACTED]"});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(
            base,
            serde_json::json!({"city": "London"}),
            "an omitted key must not survive because a plugin rewrote it"
        );
    }

    #[test]
    fn changed_paths_recurse_into_nested_objects() {
        let pre = serde_json::json!({"user": {"name": "ada", "ssn": "123-45-6789"}});
        let post = serde_json::json!({"user": {"name": "ada", "ssn": "[REDACTED]"}});
        let mut base = serde_json::json!({"user": {"name": "ADA", "ssn": "123-45-6789"}});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(
            base,
            serde_json::json!({"user": {"name": "ADA", "ssn": "[REDACTED]"}}),
            "a sibling edit inside the same object must not be clobbered"
        );
    }

    /// Documented precedence: when both editors rewrote the same key, the
    /// pipeline's value lands. Pinned so a future change to the rule is
    /// deliberate rather than incidental.
    #[test]
    fn changed_paths_let_the_pipeline_win_a_same_key_conflict() {
        let pre = serde_json::json!({"ssn": "123-45-6789"});
        let post = serde_json::json!({"ssn": "***-**-6789"});
        // The plugin redacted the same key more aggressively.
        let mut base = serde_json::json!({"ssn": "[REDACTED]"});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(base, serde_json::json!({"ssn": "***-**-6789"}));
    }

    /// A key the plugin removed comes back when the pipeline rewrote it,
    /// carrying the pipeline's (redacted) value.
    #[test]
    fn changed_paths_reinstate_a_key_the_plugin_removed() {
        let pre = serde_json::json!({"ssn": "123-45-6789", "name": "Ada"});
        let post = serde_json::json!({"ssn": "[REDACTED]", "name": "Ada"});
        let mut base = serde_json::json!({"name": "Ada"});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(
            base,
            serde_json::json!({"ssn": "[REDACTED]", "name": "Ada"}),
            "the pipeline's redaction lands even though the plugin dropped the key"
        );
    }

    #[test]
    fn changed_paths_replace_a_scalar_projection_whole() {
        let mut base = serde_json::json!("plugin text");
        apply_changed_paths(
            &mut base,
            &serde_json::json!("original"),
            &serde_json::json!("pipeline text"),
        );
        assert_eq!(base, serde_json::json!("pipeline text"));
    }

    #[test]
    fn changed_paths_take_the_pipeline_view_when_base_shape_differs() {
        let pre = serde_json::json!({"city": "London"});
        let post = serde_json::json!({"city": "[REDACTED]"});
        let mut base = serde_json::json!("no longer an object");
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(base, post);
    }

    #[test]
    fn shape_mismatch_leaves_a_tool_call_untouched() {
        let mut msg = tool_call_message();
        let before = extract_args_from_message(&msg);
        // A pipeline that produced a string where the message holds
        // structured arguments: better to forward the original than a
        // malformed rewrite.
        write_args_back_to_message(&mut msg, &serde_json::json!("not an object"));
        assert_eq!(extract_args_from_message(&msg), before);
    }
}
