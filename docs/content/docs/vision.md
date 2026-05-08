---
title: "Vision"
weight: 5
---

# Universal Extensibility for AI Security

AI agents execute across trust domains, calling tools, accessing data, and delegating to other agents. No single policy engine or enforcement point is sufficient. The execution path spans LLM proxies, agent frameworks, gateways, and external services. Security policies must be injected across the entire stack.

CPEX is the **composable enforcement framework** that makes this possible.

---

## Hooks Are the Enforcement Plane

Hooks are standardized interception points placed at every boundary where an agent acts, before and after tool calls, LLM completions, prompt fetches, and protocol messages. Plugins attach to hooks and run automatically, keeping enforcement logic separate from business logic.

This architecture deploys identically across the stack, inside LLM proxies, agent frameworks, and gateways. Each layer runs its own plugins. Prompt injection detection at the proxy. Tool authorization at the gateway. Data loss prevention at the agent.

![CPEX hooks deployed across the agent stack](/contextforge-plugins-framework/images/distributed_hooks_control_plane.png)

---

## Hooks Need Policy. Policy Needs Context.

Enforcement is a three-layer problem.

| Layer | Role |
|-------|------|
| **Hooks** | Where enforcement happens. Interception, decision, transformation. |
| **CMF** (Common Message Format) | What you evaluate. A protocol-agnostic context envelope carrying identity, security labels, delegation chains, and content. |
| **APL** (Attribute Policy Language) | How you define policy. Declarative, attribute-based rules with explicit effects. |

![Hooks, CMF, and APL form a unified enforcement stack](/contextforge-plugins-framework/images/overview_vision.png)

Hooks make enforcement **possible**. Policy makes it **usable**. Context makes it **correct**.

---

## The Policy Spectrum

Different policy types require different enforcement points. CPEX provides hooks at every layer, from soft stylistic policies enforced at the prompt level to hard compliance requirements enforced at infrastructure boundaries.

![Policy spectrum: each policy type maps to a different enforcement point](/contextforge-plugins-framework/images/policy_spectrum.png)

---

## How It Works

An application or framework invokes a hook at a critical operation boundary. The plugin manager dispatches registered plugins (sequentially, concurrently, or fire-and-forget) and returns a result. Plugins can **allow** execution to continue, **block** it with a violation, or **modify** the payload using copy-on-write isolation.

![Plugin execution model: agent → middleware → hook → manager → plugins](/contextforge-plugins-framework/images/integration_execution_model.png)

The plugin manager handles registration, ordering, timeouts, error isolation, and payload chaining. You get a deterministic enforcement pipeline with no surprises.

---

## Where We're Going

CPEX is under active development. The current Python framework is production-ready. The roadmap extends the core in several directions.

- **Rust core.** A shared plugin execution engine with type-safe CMF invariant enforcement, replacing convention-based rules with compile-time guarantees. Python (PyO3) and Go (cgo) bindings enable a single runtime across language consumers.

- **WASM sandboxing.** Portable, capability-based isolation for third-party plugins. Zero-trust by default: no filesystem, network, or host memory unless explicitly granted.

- **APL integration.** Declarative policy pipelines that compose built-in attribute checks with external policy engines (OPA, Cedar, AuthZEN, NeMo Guardrails) in a single evaluation.

- **Plugin catalog.** Discovery, versioning, and installation of plugins from registries. Multiple instances from a single manifest, managed through the CLI.

See the [GitHub milestones](https://github.com/contextforge-org/contextforge-plugins-framework/milestones) and [open issues](https://github.com/contextforge-org/contextforge-plugins-framework/issues) for details.

---

## Projects Using CPEX

| Project | Description |
|---------|-------------|
| [ContextForge](https://github.com/IBM/mcp-context-forge) | MCP gateway with CPEX enforcement built in |
| [Mellea](https://github.com/generative-computing/mellea) | Agentic framework with CPEX plugin integration |

---

## Get Involved

CPEX is part of the [ContextForge](https://github.com/contextforge-org) ecosystem.

- [CPEX Plugin Framework](https://github.com/contextforge-org/contextforge-plugins-framework) (this project)
- [Contributing Guide](https://github.com/contextforge-org/contextforge-plugins-framework/blob/main/CONTRIBUTING.md)

Contributions, feedback, and plugin ideas are welcome. Open an issue or submit a pull request.
