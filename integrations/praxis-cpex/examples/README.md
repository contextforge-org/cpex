<!--
Location: ./integrations/praxis-cpex/examples/README.md
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor
-->

# Praxis-CPEX examples

The canonical worked example for this integration lives in **`./demo/`** —
a runnable HR-copilot scenario with Keycloak (OIDC IdP), a mock MCP
backend, the Praxis-CPEX gateway, and an LLM agent. Start there:

* [`./demo/README.md`](./demo/README.md) — bring-up + walkthrough
* [`./demo/walkthrough.sh`](./demo/walkthrough.sh) — narrated end-to-end
  script through every demo feature
* [`./demo/agent/CHAT-WALKTHROUGH.md`](./demo/agent/CHAT-WALKTHROUGH.md) —
  per-persona prompts to type into the interactive LLM agent

Older slice-specific examples (`cpex.yaml` / `praxis.yaml` at this
level) were removed because they were strict subsets of `./demo/`
and drifted out of sync with the active codebase. The demo replaces
them: it shows multi-role identity, RFC 8693 token exchange, APL
policy + Cedar PDP + field-level body rewriting, and MCP-compliant
JSON-RPC error envelopes all in one place.
