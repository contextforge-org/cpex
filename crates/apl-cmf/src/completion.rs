// Location: ./crates/apl-cmf/src/completion.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CompletionExtension → AttributeBag.
//
// Namespace:
//   completion.stop_reason     : String  (snake_case: "end" | "return" | "call" | "max_tokens" | "stop_sequence")
//   completion.model           : String
//   completion.raw_format      : String
//   completion.created_at      : String
//   completion.latency_ms      : Int
//   completion.tokens.input    : Int
//   completion.tokens.output   : Int
//   completion.tokens.total    : Int

use apl_core::AttributeBag;
use cpex_core::extensions::{CompletionExtension, StopReason};

pub fn extract_completion(c: &CompletionExtension, bag: &mut AttributeBag) {
    if let Some(sr) = c.stop_reason {
        bag.set("completion.stop_reason", stop_reason_str(sr));
    }
    if let Some(tu) = &c.tokens {
        bag.set("completion.tokens.input", tu.input_tokens as i64);
        bag.set("completion.tokens.output", tu.output_tokens as i64);
        bag.set("completion.tokens.total", tu.total_tokens as i64);
    }
    if let Some(v) = &c.model { bag.set("completion.model", v.clone()); }
    if let Some(v) = &c.raw_format { bag.set("completion.raw_format", v.clone()); }
    if let Some(v) = &c.created_at { bag.set("completion.created_at", v.clone()); }
    if let Some(ms) = c.latency_ms { bag.set("completion.latency_ms", ms as i64); }
}

fn stop_reason_str(sr: StopReason) -> &'static str {
    match sr {
        StopReason::End => "end",
        StopReason::Return => "return",
        StopReason::Call => "call",
        StopReason::MaxTokens => "max_tokens",
        StopReason::StopSequence => "stop_sequence",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::extensions::completion::TokenUsage;

    #[test]
    fn stop_reason_serializes_as_snake_case_string() {
        let c = CompletionExtension {
            stop_reason: Some(StopReason::MaxTokens),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_completion(&c, &mut bag);
        assert_eq!(bag.get_string("completion.stop_reason"), Some("max_tokens"));
    }

    #[test]
    fn tokens_flatten_to_nested_ints() {
        let c = CompletionExtension {
            tokens: Some(TokenUsage { input_tokens: 100, output_tokens: 50, total_tokens: 150 }),
            latency_ms: Some(420),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_completion(&c, &mut bag);
        assert_eq!(bag.get_int("completion.tokens.input"), Some(100));
        assert_eq!(bag.get_int("completion.tokens.output"), Some(50));
        assert_eq!(bag.get_int("completion.tokens.total"), Some(150));
        assert_eq!(bag.get_int("completion.latency_ms"), Some(420));
    }
}
