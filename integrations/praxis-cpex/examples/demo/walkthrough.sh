#!/usr/bin/env bash
# Location: ./integrations/praxis-cpex/examples/demo/walkthrough.sh
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
# Authors: Teryl Taylor
#
# Narrated end-to-end walkthrough of every demo feature. Fires the
# 7 scenario scripts in sequence with explanatory text between each,
# so a live audience can see:
#
#   * the actual HTTP request the gateway received
#   * what the gateway responded with (success result vs MCP JSON-RPC
#     error envelope vs HTTP 401)
#   * which violation code (if any) the gateway emitted
#
# Pairs well with a second terminal running:
#
#     docker compose logs -f hr-mcp
#
# so the audience can see (or NOT see) the request reaching the
# backend — and the audit-log JSON the gateway emits on its stderr.
#
# Usage:
#
#     ./walkthrough.sh            # narrated, pause for input between scenarios
#     ./walkthrough.sh --fast     # no pauses — for smoke-testing
#
# Assumes the stack is already up: `docker compose up -d` and the
# gateway is running on :8090. Run `./verify-token-exchange.sh` first
# if you want to double-check Keycloak.

set -euo pipefail

FAST="${1:-}"

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DEMO_DIR"

bold()  { printf '\033[1m%s\033[0m' "$*"; }
dim()   { printf '\033[2m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
yellow(){ printf '\033[33m%s\033[0m' "$*"; }
cyan()  { printf '\033[36m%s\033[0m' "$*"; }

banner() {
  echo
  echo "$(cyan ════════════════════════════════════════════════════════════)"
  echo "$(cyan "  $*")"
  echo "$(cyan ════════════════════════════════════════════════════════════)"
}

beat() {
  echo
  echo "  $(yellow ▸) $*"
}

pause() {
  if [ "$FAST" = "--fast" ]; then
    return
  fi
  echo
  echo "  $(dim "[press enter to continue, q to quit]")"
  read -r ans
  if [ "${ans:-}" = "q" ] || [ "${ans:-}" = "quit" ]; then
    echo "  $(dim bye)"
    exit 0
  fi
}

# ----- Pre-flight ---------------------------------------------------------

banner "Pre-flight"

beat "Is the gateway listening on :8090?"
if ! curl -fsS --max-time 2 -o /dev/null -X POST http://localhost:8090/mcp \
    -H "Content-Type: application/json" -d '{}' 2>/dev/null; then
  if ! lsof -nP -iTCP:8090 -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; then
    echo "  $(yellow ✗) gateway is not listening on :8090"
    echo "  $(dim "from this directory: ../../target/release/praxis-cpex -c ./praxis.yaml &")"
    exit 1
  fi
fi
echo "  $(green ✓) gateway up"

beat "Can Keycloak mint a token?"
if ! ./verify-token-exchange.sh >/dev/null 2>&1; then
  echo "  $(yellow ✗) verify-token-exchange.sh failed"
  echo "  $(dim "try: docker compose down -v && docker compose up -d")"
  exit 1
fi
echo "  $(green ✓) Keycloak STE v2 works"

beat "Tip — open a second terminal and run:"
echo "      $(dim "docker compose logs -f hr-mcp")"
echo "    you'll see what reaches the backend (or doesn't)."
pause

# ----- WORKDAY FLOW (Pattern 1) -------------------------------------------

banner "WORKDAY FLOW — single-IdP perms on the user token"

beat "Scenario 1 — Bob (HR + view_ssn) asks for compensation."
beat "Expected: HTTP 200 + full record including the SSN."
beat "Backend (hr-mcp) sees: the IdP-minted workday-api token (NOT bob's user JWT)"
beat "                       AND the SSN value as bob sent it (no redact, he has view_ssn)."
pause
bash scenarios/01-bob-allow.sh
pause

beat "Scenario 2 — Alice (engineer, NOT HR) asks for the same."
beat "Expected: HTTP 200 + JSON-RPC error envelope, code -32001."
beat "          data.violation = routes.tool:get_compensation.apl.policy[0]"
beat "Why HTTP 200 + JSON-RPC error (not HTTP 403)? Per MCP's Tools spec,"
beat "gateway-side denials are reported as JSON-RPC errors so MCP clients"
beat "can correlate the failure to the original request id."
beat "Backend: NEVER sees the request — gateway short-circuits at the APL gate."
beat "Keycloak: NEVER sees a token-exchange call (delegate() runs AFTER policy)."
pause
bash scenarios/02-alice-deny.sh
pause

beat "Scenario 3 — Eve (HR but NO view_ssn) asks for compensation with SSN."
beat "Expected: HTTP 200 + success. BUT — args.ssn was rewritten to [REDACTED]"
beat "before the request reached the backend. The tool literally never sees the SSN."
beat "Watch hr-mcp logs: body.params.arguments will show ssn=[REDACTED]."
beat ""
beat "Caveat (full disclosure): the body-rewrite uses a 'pad with trailing"
beat "spaces' workaround today because praxis doesn't expose Content-Length"
beat "recompute from on_request_body. Documented as a known upstream issue in"
beat "docs/upstream-issues/01-content-length-on-body-rewrite.md. The redact"
beat "logic itself is real — the wire-format trick is a workaround."
pause
bash scenarios/03-eve-redact.sh
pause

# ----- GITHUB FLOW (Pattern 3 — Cedar PDP) -------------------------------

banner "GITHUB FLOW — Cedar PDP + per-audience IdP claim mapping"

beat "Scenario 4 — Alice (engineering) searches internal repos."
beat "Expected: HTTP 200 + success."
beat "Layer 1: APL gate require(team.engineering | team.security) → PASS"
beat "Layer 2: Cedar policy engineering-internal-repos → PERMIT"
beat "Layer 3: Token exchange to github-api audience → succeeds"
beat "Layer 4: delegation.granted.permissions contains repo:read:internal → PASS"
pause
bash scenarios/04-alice-internal-allow.sh
pause

beat "Scenario 5 — Alice (engineering) searches EXTERNAL repos."
beat "Expected: HTTP 200 + JSON-RPC error, data.violation=cedar.default_deny."
beat "Cedar's engineer policy when-clause requires visibility==internal."
beat "External fails the when-clause → no permit fires → default deny."
beat "No IdP call happens. GitHub never sees the request."
pause
bash scenarios/05-alice-external-cedar-deny.sh
pause

beat "Scenario 6 — Bob (HR) tries to search ANY repos."
beat "Expected: HTTP 200 + JSON-RPC error at the APL gate."
beat "Fast-path deny: cheap predicate (require team.engineering | team.security)"
beat "runs first. Bob is team.hr, neither matches. Cedar never runs."
pause
bash scenarios/06-bob-apl-deny.sh
pause

# ----- PLUGIN FLOW (PII scanner + audit logger) --------------------------

banner "PLUGIN FLOW — validator + observation plugins"

beat "Scenario 7 — Bob tries to send_email with an SSN in the body."
beat "Expected: HTTP 200 + JSON-RPC error, data.violation=pii.detected."
beat "APL gate require(perm.email_send) PASSES (Bob has the perm)."
beat "The pii-scan plugin walks args.body, hits the SSN regex pattern, denies."
beat "The audit-log plugin still fires — observation-only, can't block — and"
beat "writes a JSON record to the gateway's stderr describing the denied attempt."
beat "(Check the praxis-cpex process stderr to see it.)"
pause
bash scenarios/07-bob-pii-deny.sh

# ----- Wrap up ------------------------------------------------------------

banner "Walkthrough complete"

beat "Recap of what the gateway demonstrated:"
echo "      $(dim "•") identity from JWT (jwt-user reads X-User-Token,"
echo "        jwt-client reads Authorization — both validated against"
echo "        Keycloak's live JWKS)"
echo "      $(dim "•") attribute-based APL policy (require(team.X), role.Y,"
echo "        perm.Z) with fast-path deny semantics"
echo "      $(dim "•") Cedar PDP for relationship-based authorization"
echo "        (principal × resource attributes), with \${args.X}"
echo "        substitution into the resource block"
echo "      $(dim "•") RFC 8693 OAuth token exchange against real Keycloak"
echo "        v2 Standard Token Exchange — per-audience minted tokens"
echo "      $(dim "•") on-the-wire body rewriting (redact) — the tool"
echo "        literally never sees the redacted field"
echo "      $(dim "•") field-level plugin (PII scanner) catching content"
echo "        BEFORE it reaches the backend"
echo "      $(dim "•") audit observation plugin — fire-once record of every"
echo "        policy/PDP/delegation decision"
echo "      $(dim "•") MCP-compliant error responses: JSON-RPC error envelope"
echo "        for application denials (HTTP 200, code -32001), HTTP 401 +"
echo "        WWW-Authenticate for transport-level auth failures."
echo
beat "To try this through an LLM, start chat.py:"
echo "      $(dim "cd agent && ./run-watsonx.sh bob       # or use --model")"
echo
