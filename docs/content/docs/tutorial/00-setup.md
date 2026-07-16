---
title: "Setup & orientation"
weight: 1
---

# Module 0: Setup & orientation

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module gets you oriented and checks your setup. It changes nothing on your system.

**Goal:** understand what CPEX is, confirm your toolchain, and know which modules need the IdP.

## What CPEX is

CPEX is a policy enforcement runtime for AI agents. It is a deterministic reference monitor between an agent and every capability it invokes: tools, prompts, resources, inference providers. Each capability defines its own enforcement pipeline (authorization, delegation, redaction, information-flow control, audit), written declaratively in [APL]({{< relref "/docs/apl" >}}) and run at the boundary.

You are the host: the process that embeds CPEX and drives the loop of resolving identity, running policy, calling the backend, and running policy again on the result. The tutorial harness wraps that loop in a single `mediate()` call so you can focus on policy. Module 9 opens `mediate()` up and shows the real dispatch API underneath.

## Check your setup

```bash
cargo run -p cpex-tutorial --example m00_setup
```

The crate builds, and you are told whether the IdP is up:

```
=== Module 0: Setup & orientation ===
...
Checking the tutorial IdP (Keycloak) ... not running
Modules 0–1 work without it. For module 2 onward, start it:
  docker compose -f examples/tutorial/idp/docker-compose.yml up -d
```

## The IdP

From [module 2]({{< relref "02-identity" >}}) on, the tutorial resolves real JWTs from a Keycloak realm. Identity, token exchange, and JWKS validation are core to what CPEX enforces, so mocking them would teach a fake shape of the problem. Starting it is one command:

```bash
docker compose -f examples/tutorial/idp/docker-compose.yml up -d   # about 30s on first boot
```

The realm is imported on start and lives only in the container. `docker compose ... down` wipes it, which is also your reset button. Every credential in it is tutorial-only. Never reuse them. See [`idp/README.md`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/idp) for the personas.

You do not need it yet. Modules 0 and 1 run on Rust alone.

## Checkpoint

{{< details "Who runs the enforcement loop, CPEX or your application?" >}}
Your application (the host). CPEX is a library you embed at the boundary. It evaluates and enforces policy, but the host owns the loop that calls it. The tutorial's `mediate()` is that loop.
{{< /details >}}

{{< details "Why a real Keycloak instead of a mock?" >}}
Identity resolution, token exchange, and JWKS-based validation are central to what CPEX does. A mock would let you write policy against a shape that does not match reality. The realm is small and disposable, so the cost is one `docker compose up`.
{{< /details >}}

## Next

[Module 1: Hello, enforcement]({{< relref "01-hello" >}}): the smallest CPEX host, and your first allow and deny.
