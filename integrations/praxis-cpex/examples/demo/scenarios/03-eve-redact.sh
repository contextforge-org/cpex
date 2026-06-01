#!/usr/bin/env bash
# Eve (HR, no view_ssn perm) calls get_compensation. Expected:
#
#   * Gateway returns 200 (policy passes — Eve is HR)
#   * Token exchange happens via Keycloak
#   * MCP server logs show args.ssn = "[REDACTED]" — the gateway
#     rewrote it before forwarding. The downstream tool never sees
#     the original SSN value.
#   * Other args (employee_id, include_ssn) pass through unchanged.

set -euo pipefail
source "$(dirname "$0")/_lib.sh"

step "Eve (HR, no view_ssn) → get_compensation"
note "Expected: 200 OK"
note "Expected upstream: Authorization is the IdP-minted workday-api token"
note "Expected upstream: args.ssn = '[REDACTED]' (gateway rewrote the body)"

EVE=$(mint eve)
CLIENT=$(mint hr-copilot)

call_get_compensation "$EVE" "$CLIENT" false
