#!/usr/bin/env bash
# Alice (engineer, role.engineer) calls get_compensation. Expected:
#
#   * Gateway returns an MCP JSON-RPC error (HTTP 200 + error envelope,
#     code -32001) — per MCP's Tools spec, gateway-side denials are
#     reported via the JSON-RPC error mechanism so MCP clients can
#     correlate the failure to the original request id
#   * No token exchange happened (Keycloak's /token endpoint
#     should NOT receive a token-exchange call for this request)
#   * MCP server NEVER sees the call (request short-circuits at policy)

set -euo pipefail
source "$(dirname "$0")/_lib.sh"

step "Alice (engineer) → get_compensation"
note "Expected: HTTP 200 + JSON-RPC error -32001, violation=routes.tool:get_compensation.apl.policy[0]"
note "Triggered by: require(role.hr) deny BEFORE delegation runs"
note "Expected upstream: no inbound request (gateway short-circuited)"

ALICE=$(mint alice)
CLIENT=$(mint hr-copilot)

call_get_compensation "$ALICE" "$CLIENT" false
