#!/usr/bin/env bash
# Mint an access token for a demo persona by hitting Keycloak's
# direct password-grant endpoint. Echoes the raw JWT on stdout.
#
# Usage:
#   ./mint-token.sh alice            # prints alice's user token
#   ./mint-token.sh hr-copilot       # prints the hr-copilot client's
#                                    # service-account token (used as
#                                    # the gateway-Authorization)
#
# Personas:
#   alice    — engineer, role=engineer,  perms=[tool_execute]
#   bob      — HR, role=hr, perms=[tool_execute, view_ssn, pii_access, email_send]
#   charlie  — auditor, role=auditor, perms=[tool_execute, pii_access]
#   eve      — HR, role=hr, perms=[tool_execute]   (NO view_ssn)
#
# Requires `jq`. Token endpoint defaults to localhost:8081 (the
# docker-compose mapping for Keycloak).

set -euo pipefail

KEYCLOAK_HOST="${KEYCLOAK_HOST:-http://localhost:8081}"
REALM="${KEYCLOAK_REALM:-cpex-demo}"
TOKEN_ENDPOINT="${KEYCLOAK_HOST}/realms/${REALM}/protocol/openid-connect/token"

CLIENT_ID="hr-copilot"
CLIENT_SECRET="hr-copilot-secret"

persona="${1:?usage: $0 <alice|bob|charlie|eve|hr-copilot>}"

case "$persona" in
  alice|bob|charlie|eve)
    response=$(curl -s -X POST "$TOKEN_ENDPOINT" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=password" \
      -d "client_id=$CLIENT_ID" \
      -d "client_secret=$CLIENT_SECRET" \
      -d "username=$persona" \
      -d "password=$persona" \
      -d "scope=openid")
    ;;
  hr-copilot)
    # Service-account / client_credentials grant — for the
    # Authorization header (the client's own identity).
    response=$(curl -s -X POST "$TOKEN_ENDPOINT" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials" \
      -d "client_id=$CLIENT_ID" \
      -d "client_secret=$CLIENT_SECRET" \
      -d "scope=openid")
    ;;
  *)
    echo "unknown persona: $persona" >&2
    echo "valid: alice bob charlie eve hr-copilot" >&2
    exit 1
    ;;
esac

if ! token=$(echo "$response" | jq -er '.access_token'); then
  echo "ERROR: Keycloak did not return an access_token" >&2
  echo "$response" | jq . >&2 || echo "$response" >&2
  exit 1
fi

echo "$token"
