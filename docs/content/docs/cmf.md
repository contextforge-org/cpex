---
title: "Common Message Format"
weight: 40
---

# Common Message Format

APL evaluates policy against a request. The Common Message Format (CMF) is the shape of that request: a protocol-agnostic envelope that represents any mediated operation in one structure, so a single policy can apply across tool calls, A2A methods, inference, prompts, and resources without caring which protocol carried them.

## Why a common format

Without CMF, a redaction policy for tool results and a redaction policy for LLM output are different code against different payload types, even though they do the same thing. CMF gives every interception point the same representation, so cross-cutting policy is written once and evaluated everywhere. This is what lets the same APL field pipeline redact a field whether it arrived in a tool result or a model completion.

## Message structure

A CMF `Message` carries:

- **role**: `system`, `developer`, `user`, `assistant`, or `tool`.
- **content**: a list of typed parts: text, thinking, tool call, tool result, resource, prompt request, image, video, audio, document.
- **channel**: optional routing such as `analysis`, `commentary`, or `final`.

Because content is a list of typed parts rather than a flat string, policy can target precisely: scan only `tool_call` arguments, redact a field inside a `tool_result`, or check a `text` part for injection, without disturbing the rest.

## Views

A `MessageView` is a flattened projection of a message for uniform evaluation: each view has a kind (`text`, `tool_call`, `tool_result`, and so on), an optional name, and the text or structured payload. Plugins and APL field pipelines operate over views, which is why one policy expression works across content types.

## CMF hooks

CMF operations run at CMF hooks, which parallel the typed hooks but carry a `Message`:

| Hook | Fires |
|------|-------|
| `cmf.tool_pre_invoke` / `cmf.tool_post_invoke` | around a tool call |
| `cmf.llm_input` / `cmf.llm_output` | around an inference call |
| `cmf.prompt_pre_fetch` / `cmf.prompt_post_fetch` | around a prompt fetch |
| `cmf.resource_pre_fetch` / `cmf.resource_post_fetch` | around a resource fetch |

An APL route's `policy` phase runs at the relevant `*_pre_*` hook and its `result` phase at the `*_post_*` hook. Writing a guardrail against the CMF hook means it covers every operation type that maps to it, rather than one protocol's payload.

## How it connects to policy

CMF is the "what you evaluate" layer (see [Vision]({{< relref "/docs/vision" >}})). Identity, security labels, and delegation context ride alongside the message as typed extensions ([Extensions & Capability-Gating]({{< relref "/docs/extensions" >}})), and APL reads all of it through one attribute bag. The message gives policy the content; the extensions give it the context; APL decides.
