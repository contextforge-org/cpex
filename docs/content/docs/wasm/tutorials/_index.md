---
title: "Tutorials"
weight: 70
bookCollapseSection: false
---

# Tutorials

Hands-on walkthroughs using the built-in demos. Each tutorial runs real WASM plugins end-to-end.

## Prerequisites

```bash
rustup target add wasm32-wasip2
cd crates/cpex-wasm-host
```

## What's in this section

- [Part 1: Plugin Demos]({{< relref "part1" >}}) — custom payloads, policy-based routing, and capability filtering
- [Part 2: Sandboxing Demos]({{< relref "part2" >}}) — filesystem, env, network, and resource limit enforcement

---

## Running all demos at once

```bash
make run-all-demos
```

This builds all plugins and runs every demo sequentially, producing a full output log showing each sandboxing dimension in action.
