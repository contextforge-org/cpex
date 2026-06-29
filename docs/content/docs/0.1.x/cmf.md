---
title: "Common Message Format"
weight: 50
---

# Common Message Format (CMF)

The Common Message Format is a canonical message representation for interactions between users, agents, tools, and language models. It lets you write a single plugin that evaluates content at *every* interception point — tool calls, LLM input/output, resource access — using one unified interface.

---

## Why CMF?

Without CMF, you write separate handlers for each hook type:

```python
async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context):
    # check tool arguments for prohibited content
    ...

async def agent_pre_invoke(self, payload: AgentPreInvokePayload, context):
    # check agent messages for prohibited content — same logic, different payload
    ...
```

With CMF, you write the logic once and register for multiple hook points:

```python
from cpex.framework import hook, Plugin, PluginContext
from cpex.framework.hooks.message import CmfHookType, MessagePayload, MessageResult


class ContentGuardrailPlugin(Plugin):
    @hook([CmfHookType.TOOL_PRE_INVOKE, CmfHookType.LLM_INPUT, CmfHookType.LLM_OUTPUT])
    async def evaluate(self, payload: MessagePayload, context: PluginContext) -> MessageResult:
        for view in payload.message.iter_views():
            if view.text and self._contains_prohibited_content(view.text):
                return MessageResult(
                    continue_processing=False,
                    violation=PluginViolation(
                        reason="Prohibited content detected",
                        description=f"Content blocked at {payload.hook.value}",
                        code="CONTENT_BLOCKED",
                    ),
                )
        return MessageResult(continue_processing=True)
```

---

## Message

A `Message` is the top-level CMF object representing a single turn in a conversation:

```python
from cpex.framework.cmf.message import Message, Role, TextContent, ToolCallContentPart, ToolCall

msg = Message(
    role=Role.ASSISTANT,
    content=[
        TextContent(text="Let me look that up."),
        ToolCallContentPart(
            content=ToolCall(
                tool_call_id="tc_001",
                name="web_search",
                arguments={"query": "CPEX framework"},
            ),
        ),
    ],
)

msg.role                     # Role.ASSISTANT
msg.content[0].text          # "Let me look that up."
msg.content[1].content.name  # "web_search"
```

Messages are frozen. Use `model_copy(update={...})` to create modified copies.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `str` | Schema version (default `"2.0"`) |
| `role` | `Role` | Who is speaking: `SYSTEM`, `DEVELOPER`, `USER`, `ASSISTANT`, `TOOL` |
| `content` | `list[ContentPartUnion]` | List of typed content parts (multimodal) |
| `channel` | `Channel \| None` | Output classification: `ANALYSIS`, `COMMENTARY`, `FINAL` |

---

## Content Parts

Messages carry a list of typed content parts. Each part has a `content_type` discriminator:

| Content Type | Class | Wraps |
|-------------|-------|-------|
| `text` | `TextContent` | Plain text |
| `thinking` | `ThinkingContent` | Chain-of-thought reasoning |
| `tool_call` | `ToolCallContentPart` | `ToolCall` — function invocation request |
| `tool_result` | `ToolResultContentPart` | `ToolResult` — function execution result |
| `resource` | `ResourceContentPart` | `Resource` — embedded resource with content |
| `resource_ref` | `ResourceRefContentPart` | `ResourceReference` — lightweight reference |
| `prompt_request` | `PromptRequestContentPart` | `PromptRequest` — template invocation |
| `prompt_result` | `PromptResultContentPart` | `PromptResult` — rendered template |
| `image` | `ImageContentPart` | `ImageSource` — URL or base64 image |
| `video` | `VideoContentPart` | `VideoSource` — URL or base64 video |
| `audio` | `AudioContentPart` | `AudioSource` — URL or base64 audio |
| `document` | `DocumentContentPart` | `DocumentSource` — PDF, Word, etc. |

---

## MessageView

`Message.iter_views()` decomposes a message into individually addressable `MessageView` objects. Each view provides a uniform interface for policy evaluation regardless of content type:

```python
for view in message.iter_views():
    print(f"kind={view.kind}, name={view.name}, text={view.text}")
```

This is the recommended way to inspect message content in plugins. Each view exposes the same fields, so your policy logic doesn't need to branch on content type.

---

## CMF Hook Types

CMF hooks parallel the typed hooks but accept `MessagePayload` instead of per-type payloads:

| CMF Hook | Fires at | Parallel to |
|----------|----------|-------------|
| `cmf.tool_pre_invoke` | Before tool execution | `tool_pre_invoke` |
| `cmf.tool_post_invoke` | After tool execution | `tool_post_invoke` |
| `cmf.llm_input` | Before model/LLM call | — |
| `cmf.llm_output` | After model/LLM call | — |
| `cmf.prompt_pre_fetch` | Before prompt fetch | `prompt_pre_fetch` |
| `cmf.prompt_post_fetch` | After prompt fetch | `prompt_post_fetch` |
| `cmf.resource_pre_fetch` | Before resource fetch | `resource_pre_fetch` |
| `cmf.resource_post_fetch` | After resource fetch | `resource_post_fetch` |

The gateway fires both the typed hook and the CMF hook at each interception point. You can use either or both.

---

## MessagePayload

The payload for all CMF hooks:

```python
from cpex.framework.hooks.message import MessagePayload, MessageHookType

payload = MessagePayload(message=msg, hook=MessageHookType.LLM_INPUT)
payload.message   # the CMF Message
payload.hook      # where in the pipeline this evaluation is happening
```

The `hook` field tells your plugin *where* the evaluation is happening, so you can apply different policies at different stages if needed.

---

## Migration Path

You can migrate from typed hooks to CMF incrementally:

1. **Typed plugins** register for `tool_pre_invoke` and receive `ToolPreInvokePayload`
2. **CMF plugins** register for `cmf.tool_pre_invoke` and receive `MessagePayload`
3. Both fire at the same interception point — no conflict

Start with CMF for new cross-cutting policies (content guardrails, PII scanning) where the unified interface saves duplication. Keep typed hooks for domain-specific logic that benefits from the typed payload fields.
