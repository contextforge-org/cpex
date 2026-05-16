// Location: ./integrations/authbridge/cpex-runtime/bridge.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// pctx ↔ CPEX MessagePayload + Extensions translation.
//
// AuthBridge's `pipeline.Context` (pctx) and CPEX's payload + extensions
// describe overlapping but not identical concerns. This file is the only
// place that knows both shapes; everything outside it sees either a CPEX
// MessagePayload + cpex.Extensions or a pctx — never mixes them.
//
// Mapping (request path):
//
//   pctx.Identity.Subject()        → SecurityExtension.subject.id
//   pctx.Identity.ClientID()       → SecurityExtension.subject.claims["azp"]
//   pctx.Identity.Scopes()         → SecurityExtension.subject.permissions
//   pctx.Agent.ClientID            → SecurityExtension.agent.client_id
//   pctx.Agent.WorkloadID          → SecurityExtension.agent.workload_id
//   pctx.Agent.TrustDomain         → SecurityExtension.agent.trust_domain
//   pctx.Extensions.MCP (tools/call)
//       Params["name"]             → MCPExtension.tool.name
//   pctx.Extensions.Inference.Messages
//       []InferenceMessage         → MessagePayload.message.content (one
//                                    Text part per message, in order)
//
// On the way back:
//
//   PluginResult denied            → pipeline.DenyAndRecord(reason, code, ...)
//   PluginResult modified payload  → re-serialize into outbound LLM JSON
//                                    body and pctx.SetBody (auto-emits a
//                                    modify Invocation)
//   PluginResult allow             → pctx.Allow (records the allow)
//
// Hook selection: cpex-runtime invokes cmf.llm_input when Inference is
// populated, cmf.tool_pre_invoke when MCP describes a tools/call, and
// skips otherwise.

package cpexruntime

import (
	"encoding/json"
	"fmt"

	"github.com/kagenti/kagenti-extensions/authbridge/authlib/pipeline"

	cpex "github.com/contextforge-org/contextforge-plugins-framework/go/cpex"
)

// buildExtensions translates pctx into a CPEX Extensions container.
// Only slots we have data for are populated; everything else stays nil
// so CPEX plugins see the same shape they would in any other host.
func buildExtensions(pctx *pipeline.Context) *cpex.Extensions {
	ext := &cpex.Extensions{}

	if pctx.Identity != nil {
		subj := &cpex.SubjectExtension{
			ID:          pctx.Identity.Subject(),
			Permissions: pctx.Identity.Scopes(),
		}
		if clientID := pctx.Identity.ClientID(); clientID != "" {
			subj.Claims = map[string]string{"azp": clientID}
		}
		ext.Security = &cpex.SecurityExtension{Subject: subj}
	}

	if pctx.Agent != nil {
		if ext.Security == nil {
			ext.Security = &cpex.SecurityExtension{}
		}
		ext.Security.Agent = &cpex.AgentIdentity{
			ClientID:    pctx.Agent.ClientID,
			WorkloadID:  pctx.Agent.WorkloadID,
			TrustDomain: pctx.Agent.TrustDomain,
		}
	}

	if mcp := pctx.Extensions.MCP; mcp != nil && mcp.Method == "tools/call" {
		if name, _ := mcp.Params["name"].(string); name != "" {
			ext.MCP = &cpex.MCPExtension{
				Tool: &cpex.ToolMetadata{Name: name},
			}
		}
	}

	return ext
}

// buildLLMPayload constructs a MessagePayload from the parsed Inference
// messages. One Text content part per message preserves ordering so the
// PII redactor can map its rewritten content back to the original
// messages slot by slot.
//
// Returns nil when Inference is absent or carries no messages.
func buildLLMPayload(pctx *pipeline.Context) *cpex.MessagePayload {
	inf := pctx.Extensions.Inference
	if inf == nil || len(inf.Messages) == 0 {
		return nil
	}
	parts := make([]cpex.ContentPart, 0, len(inf.Messages))
	for _, m := range inf.Messages {
		parts = append(parts, cpex.NewTextPart(m.Content))
	}
	return &cpex.MessagePayload{Message: cpex.NewMessage("user", parts...)}
}

// buildToolPayload constructs a minimal MessagePayload for MCP tool
// calls. scope-tool-gate doesn't actually read the payload — its decision
// is based entirely on extensions.mcp.tool.name and
// extensions.security.subject.permissions — but the hook contract
// requires a payload.
//
// We pass a placeholder Text part instead of an empty content list:
// Go's variadic with zero args produces a nil slice, which msgpack
// encodes as `unit`, and the Rust side's `Vec<ContentPart>` rejects
// it with "invalid type: unit value, expected a sequence". A
// single-element list is the smallest payload that round-trips.
func buildToolPayload(pctx *pipeline.Context) *cpex.MessagePayload {
	toolName := ""
	if mcp := pctx.Extensions.MCP; mcp != nil {
		toolName, _ = mcp.Params["name"].(string)
	}
	return &cpex.MessagePayload{
		Message: cpex.NewMessage("user", cpex.NewTextPart("tools/call:"+toolName)),
	}
}

// applyLLMModification re-serializes a modified MessagePayload back into
// the outbound LLM JSON body. Parses the original body so all
// non-content fields (model, tools, temperature, etc.) are preserved
// verbatim, then overwrites each user message's `content` from the
// matching Text part. Calls pctx.SetBody on success, which auto-emits a
// modify Invocation and the body-mutation/event.
func applyLLMModification(pctx *pipeline.Context, modified *cpex.MessagePayload) error {
	if len(pctx.Body) == 0 {
		return fmt.Errorf("pctx.Body is empty — cannot rewrite LLM request")
	}
	var bodyMap map[string]any
	if err := json.Unmarshal(pctx.Body, &bodyMap); err != nil {
		return fmt.Errorf("unmarshal original body: %w", err)
	}
	messages, ok := bodyMap["messages"].([]any)
	if !ok {
		return fmt.Errorf("body has no \"messages\" array")
	}

	parts := modified.Message.Content
	for i := range messages {
		if i >= len(parts) {
			break
		}
		msg, ok := messages[i].(map[string]any)
		if !ok {
			continue
		}
		// Only Text/Thinking parts carry inspectable strings; everything
		// else (tool_call, resource, …) is passed through untouched.
		switch parts[i].ContentType {
		case cpex.ContentTypeText, cpex.ContentTypeThinking:
			msg["content"] = parts[i].Text
		}
	}

	newBody, err := json.Marshal(bodyMap)
	if err != nil {
		return fmt.Errorf("marshal rewritten body: %w", err)
	}
	pctx.SetBody(newBody)
	return nil
}

// dispatchOnRequest is the request-path entry point: pick a hook based on
// what's in pctx, run the CPEX chain, and translate the result into a
// pipeline.Action. Records exactly one Invocation per call (allow / skip
// / deny / modify is determined by the result; modify is recorded as a
// side effect of pctx.SetBody).
func (r *CPEXRuntime) dispatchOnRequest(pctx *pipeline.Context) pipeline.Action {
	if r.manager == nil {
		pctx.Skip("not_initialized")
		return pipeline.Action{Type: pipeline.Continue}
	}

	var hookName string
	var payload *cpex.MessagePayload
	switch {
	case pctx.Extensions.Inference != nil && len(pctx.Extensions.Inference.Messages) > 0:
		hookName = "cmf.llm_input"
		payload = buildLLMPayload(pctx)
	case pctx.Extensions.MCP != nil && pctx.Extensions.MCP.Method == "tools/call":
		hookName = "cmf.tool_pre_invoke"
		payload = buildToolPayload(pctx)
	default:
		pctx.Skip("no_actionable_extensions")
		return pipeline.Action{Type: pipeline.Continue}
	}

	// If no plugin in our chain handles this hook, treat it as a no-op
	// to avoid an FFI round-trip for nothing.
	if !r.manager.HasHooksFor(hookName) {
		pctx.Skip("no_handler_for_" + hookName)
		return pipeline.Action{Type: pipeline.Continue}
	}

	ext := buildExtensions(pctx)
	result, ctOut, _, err := cpex.Invoke[cpex.MessagePayload](
		r.manager, hookName, cpex.PayloadCMFMessage,
		*payload, ext, nil,
	)
	if ctOut != nil {
		ctOut.Close()
	}
	if err != nil {
		// Fail-open: a bridge / FFI error shouldn't take down customer
		// traffic. Record so it's visible in the session API.
		pctx.Observe("invoke_error:" + err.Error())
		return pipeline.Action{Type: pipeline.Continue}
	}

	if result.IsDenied() {
		v := result.Violation
		if v == nil {
			return pctx.DenyAndRecord("denied", "policy.forbidden", "denied by CPEX plugin")
		}
		return pctx.DenyAndRecord(v.Reason, v.Code, v.Description)
	}

	// `result.ModifiedPayload` is non-nil whenever any plugin ran — the
	// CPEX executor threads the (possibly-unchanged) payload through to
	// the next plugin and back to the caller. To distinguish "actually
	// modified" from "echoed back unchanged" we compare the text content
	// part-by-part against what we sent in.
	if hookName == "cmf.llm_input" && result.ModifiedPayload != nil &&
		messageTextChanged(payload, result.ModifiedPayload) {
		if err := applyLLMModification(pctx, result.ModifiedPayload); err != nil {
			pctx.Observe("modify_failed:" + err.Error())
			return pipeline.Action{Type: pipeline.Continue}
		}
		// pctx.SetBody already recorded a modify Invocation; no need
		// to record another.
		return pipeline.Action{Type: pipeline.Continue}
	}

	pctx.Allow("ok")
	return pipeline.Action{Type: pipeline.Continue}
}

// messageTextChanged returns true if any Text/Thinking ContentPart in
// `after` differs from the corresponding part in `before`. Used to
// disambiguate "plugin returned a modified payload" from "plugin chain
// ran but produced no changes" — CPEX's pipeline echoes the payload
// through every result regardless, so pointer-nil isn't a useful signal.
func messageTextChanged(before, after *cpex.MessagePayload) bool {
	if before == nil || after == nil {
		return before != after
	}
	b, a := before.Message.Content, after.Message.Content
	if len(b) != len(a) {
		return true
	}
	for i := range b {
		if b[i].ContentType != a[i].ContentType {
			return true
		}
		switch b[i].ContentType {
		case cpex.ContentTypeText, cpex.ContentTypeThinking:
			if b[i].Text != a[i].Text {
				return true
			}
		}
	}
	return false
}

// dispatchOnResponse is the response-path entry point. For v0 the
// response path is intentionally lighter: we record an observe so the
// pipeline pane shows cpex-runtime ran, but we don't dispatch a CPEX
// hook (no `cmf.llm_output` / `cmf.tool_post_invoke` plugins ship in
// v0). Adding them is a follow-up — same pattern as dispatchOnRequest.
func (r *CPEXRuntime) dispatchOnResponse(pctx *pipeline.Context) pipeline.Action {
	pctx.Observe("response_passthrough")
	return pipeline.Action{Type: pipeline.Continue}
}
