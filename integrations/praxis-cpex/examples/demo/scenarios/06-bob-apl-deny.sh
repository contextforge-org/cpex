#!/usr/bin/env bash
# Bob (HR, group=hr) tries to search github repos. APL's coarse
# gate fails immediately — Bob isn't in engineering or security.
# The deny happens BEFORE Cedar runs, before any IdP call.
#
# This shows the "fast path" in the policy: cheap predicates run
# first, expensive PDP / IdP work only happens for requests that
# clear them.
#
#   Layer 1 — APL gate `require(team.engineering | team.security)`
#             → FAILS (Bob is in team.hr)
#   Layers 2-4 — never reached. Cedar never invoked, IdP never
#             called, no token-exchange round-trip.
#
# Result: HTTP 200 + JSON-RPC error code -32001, data.violation =
# the apl.policy step index that failed.

set -euo pipefail
source "$(dirname "$0")/_lib.sh"

step "Bob (HR) → search_repos (gateway short-circuits at the APL gate)"
note "Expected: HTTP 200 + JSON-RPC error -32001, violation=routes.tool:search_repos.apl.policy[0]"
note "Triggered by: require(team.engineering | team.security) — Bob is team.hr"
note "Expected: Cedar never runs; IdP never called"

BOB=$(mint bob)
CLIENT=$(mint hr-copilot)

curl -s -X POST "$GATEWAY/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CLIENT" \
  -H "X-User-Token: $BOB" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "search_repos",
      "arguments": { "visibility": "internal" }
    }
  }' -i 2>&1 | head -20
