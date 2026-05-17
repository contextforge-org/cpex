// Location: ./crates/apl-cpex/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// apl-cpex — bridge between APL evaluator (`apl-core`) and CPEX runtime
// (`cpex-core`).
//
// `apl-core::PluginInvoker` is string-typed by design (so `apl-core`
// stays free of CPEX deps). The actual typed boundary lives in this
// crate: one `PluginInvoker` implementation per `HookTypeDef`. The
// payload type is locked at the impl level — e.g. [`CmfPluginInvoker`]
// can only dispatch to CMF hooks because every internal call goes
// through `invoke_named::<CmfHook>`, and the compiler enforces that
// the payload is `MessagePayload`.
//
// # v0 simplification — single-view-per-Message
//
// CMF spec §4.2 distinguishes two messaging patterns:
//   - LLM wire format — bundled multi-part Messages (thinking + text +
//     tool_call(s)) — many MessageViews per Message.
//   - Framework/protocol format (MCP, A2A, LangGraph) — single
//     ContentPart per Message — one view per Message.
//
// v0 only handles request-side flows (outbound LLM call from the user,
// outbound MCP tools/call from the agent). Both are single-part, so the
// route → MessageView matching collapses to "one route fires per
// Message." When response-side handling lands, this assumption breaks
// and apl-core's route-matching layer needs to switch from
// routes-as-map to routes-as-list with a `match:` block filtering on
// MessageView attributes. See the APL implementation memory's
// "list-with-matchers" deferred item.

pub mod cmf_invoker;

pub use cmf_invoker::CmfPluginInvoker;
