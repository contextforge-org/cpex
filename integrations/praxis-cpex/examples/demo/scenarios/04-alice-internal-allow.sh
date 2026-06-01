#!/usr/bin/env bash
# Alice (engineering, gh_permissions=[repo:read:internal]) calls
# search_repos for an INTERNAL repo. Expected:
#
#   Layer 1 — APL gate `require(group.engineering OR group.security)`
#             → passes (Alice is engineering)
#   Layer 2 — Cedar policy `engineering-internal-repos`
#             → permits (engineer + visibility=internal)
#   Layer 3 — Token exchange to github-api
#             → Keycloak mints token with permissions=[repo:read:internal]
#             (Alice's gh_permissions user attribute → claim mapper)
#   Layer 4 — `delegation.granted.permissions contains 'repo:read:internal'`
#             → passes
#
# Result: 200, hr-mcp logs show Authorization=<minted github token>
#         and the parsed args reach the tool intact.

set -euo pipefail
source "$(dirname "$0")/_lib.sh"

step "Alice (engineering) → search_repos(repo_name='web-app', visibility='internal')"
note "Expected: 200 OK"
note "Expected upstream: Authorization = minted github-api token"
note "                  permissions claim includes repo:read:internal"

ALICE=$(mint alice)
CLIENT=$(mint hr-copilot)

curl -s -X POST "$GATEWAY/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CLIENT" \
  -H "X-User-Token: $ALICE" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "search_repos",
      "arguments": { "repo_name": "web-app", "visibility": "internal" }
    }
  }' | jq . 2>/dev/null || true
