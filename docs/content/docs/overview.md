---
title: "Overview"
weight: 10
---

# Overview

## Why CPEX?

AI systems interact with tools, APIs, data sources, and other agents. Adding guardrails, observability, or policy checks typically means embedding that logic directly into application code — leading to duplication, tight coupling, and drift.

CPEX introduces **standardized interception hooks** between your application and its operations. Plugins attach to these hooks and run automatically, keeping enforcement logic separate from business logic.

## How It Works

Your application defines **hooks** — named interception points before and after critical operations. Plugins register against these hooks and execute automatically when triggered. The plugin manager handles registration, ordering, execution, timeouts, and error isolation.

```goat
  .---.        .----.        .-------.         .------.        .---.
 | App +----->| Hook +----->| Manager +------>| Result +----->| App |
  '---'        '----'        '---+---'         '------'        '---'
                                 |
                     .-----------+-----------.
                    |            |            |
                    v            v            v
                .--------.   .--------.   .--------.
               | Plugin A | | Plugin B | | Plugin C |
                '--------'   '--------'   '--------'
```

When a hook fires, the plugin manager dispatches the payload to every registered plugin in priority order. Each plugin can:

- **Allow** execution to continue unchanged
- **Modify** the payload (e.g., redact sensitive data, inject defaults)
- **Block** execution with a violation (e.g., deny a prohibited tool call)

You get a deterministic pipeline with no surprises.

## Built-in Hooks

CPEX ships with hooks for common AI operations — tools, prompts, resources, agents, HTTP requests, identity resolution, and a unified Common Message Format for cross-cutting policy evaluation. You can also [register your own hooks]({{< relref "/docs/hooks#custom-hooks" >}}) for any domain.

## Next Steps

Ready to build? The [Quick Start]({{< relref "/docs/quickstart" >}}) gets you a working plugin in five minutes.
