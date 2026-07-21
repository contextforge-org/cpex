---
title: "Tutorial"
weight: 25
bookCollapseSection: true
---

# CPEX Tutorial

A self-paced tutorial. You build a policy enforcement point in front of an agent's tools, one capability at a time, and watch policy decide every outcome. Every module is a runnable program you can edit, break, and re-run.

By the end you can put CPEX in front of your own tools, write APL for them, extend it with a custom plugin, and test your policy.

## What you'll build

The running example is the scenario from the [Overview]({{< relref "/docs/overview" >}}): one agent, three backends (HR records, source repos, outbound email), and three callers whose requests get different treatment. The docs describe that scenario. Here you build it, finishing with a capstone that reconstructs it end to end.

One idea repeats in every module: the application never changes. Only the policy changes.

## Before you start

- Rust 1.96 or newer, and Cargo.
- A container runtime with compose (Rancher Desktop, Podman, or Docker Desktop). You need it from module 2 on, where a real Keycloak resolves tokens. Modules 0 and 1 need only Rust.
- The code lives in [`examples/tutorial`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial). Run a module with `cargo run -p cpex-tutorial --example m01_hello`.

Budget about 3 to 4 hours total, 15 to 25 minutes per module.

## Modules

| # | Module | You'll learn | IdP? |
|---|--------|--------------|------|
| 0 | [Setup & orientation]({{< relref "00-setup" >}}) | What CPEX is; verify your setup | no |
| 1 | [Hello, enforcement]({{< relref "01-hello" >}}) | Stand up an enforcement point; a route with `require()`; allow vs. deny | no |
| 2 | [Who's calling? (Identity)]({{< relref "02-identity" >}}) | Resolve real JWTs from Keycloak into roles and permissions | yes |
| 3 | [Shaping data]({{< relref "03-shaping" >}}) | `result:` field pipelines that redact and mask per permission | yes |
| 4 | [Effects & sequencing]({{< relref "04-effects" >}}) | Ordered effects, halt-on-deny, custom deny codes, auditing | yes |
| 5 | [Delegating decisions (PDP)]({{< relref "05-pdp" >}}) | Hand a decision to CEL or Cedar; CPEX enforces the verdict | yes |
| 6 | [Scoped credentials (Delegation)]({{< relref "06-delegation" >}}) | Mint a downstream-scoped token via RFC 8693 exchange | yes |
| 7 | [Information flow (Tainting)]({{< relref "07-tainting" >}}) | Carry session state across requests; block write-down | yes |
| 8 | [Human in the loop]({{< relref "08-elicitation" >}}) | Suspend an operation for human approval, then resume | yes |
| 9 | [Write your own plugin]({{< relref "09-custom-plugin" >}}) | Build a custom plugin with the SDK; reference it from policy | no |
| 10 | [Testing your policy]({{< relref "10-testing" >}}) | Table-driven allow/deny tests that run in CI | no |
| C | [Capstone: the three-backend agent]({{< relref "capstone" >}}) | Assemble every control into the full Overview scenario | yes |

Start at [module 0]({{< relref "00-setup" >}}).

## How each module is structured

Every module page follows the same shape. **Goal** states what you can do after it in one sentence. **The problem** shows a concrete failure. **Build it** shows the policy change. **Run it** gives the command and expected output. **Try it** lists guided edits, each with the outcome to expect. **Checkpoint** is a short self-check. **Go deeper** links to the reference.
