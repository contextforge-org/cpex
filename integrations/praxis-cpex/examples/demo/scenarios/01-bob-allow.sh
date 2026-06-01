#!/usr/bin/env bash
# Bob (HR manager, perm.view_ssn) calls get_compensation. Expected:
#
#   * Gateway returns 200 with the tool's response
#   * The HR MCP server logs show:
#       - Authorization: Bearer <minted workday-api-scoped token>
#         (NOT bob's user JWT)
#       - args.ssn arrived intact (Bob has perm.view_ssn → no redact)
#
# Watch the MCP server with:
#   docker compose logs -f hr-mcp

set -euo pipefail
source "$(dirname "$0")/_lib.sh"

step "Bob (HR) → get_compensation (include_ssn=true)"
note "Expected: 200 OK"
note "Expected upstream: Authorization is the IdP-minted workday-api token (NOT bob's user JWT)"
note "Expected upstream: args.ssn intact ('would-be-removed-if-redact-fires')"

BOB=$(mint bob)
CLIENT=$(mint hr-copilot)

call_get_compensation "$BOB" "$CLIENT" true
