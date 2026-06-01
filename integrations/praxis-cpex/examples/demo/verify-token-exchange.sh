#!/usr/bin/env bash
# Verify Keycloak is wired correctly for RFC 8693 token exchange.
# Mints a user token, asks Keycloak to exchange it for the
# workday-api audience as the praxis-gateway client, and prints
# whether the response carries the right `aud` claim.
#
# Usage:
#   ./verify-token-exchange.sh
#
# Expected output:
#   ✓ alice mint                       OK
#   ✓ praxis-gateway → workday-api     OK (aud=workday-api)
#   minted token aud claim: workday-api
#   minted token sub claim: <alice's subject id>
#
# If you see "Client not allowed to exchange" or similar — the
# token-exchange permission on workday-api didn't import correctly.
# Tear down + redo: `docker compose down -v && docker compose up -d`.
# Keycloak needs ~20-30s after start to finish realm import.

set -euo pipefail

KEYCLOAK="${KEYCLOAK_HOST:-http://localhost:8081}"
REALM="${KEYCLOAK_REALM:-cpex-demo}"
TOKEN_ENDPOINT="${KEYCLOAK}/realms/${REALM}/protocol/openid-connect/token"

USER_CLIENT_ID="hr-copilot"
USER_CLIENT_SECRET="hr-copilot-secret"
GATEWAY_CLIENT_ID="praxis-gateway"
GATEWAY_CLIENT_SECRET="praxis-gateway-secret"
AUDIENCE="workday-api"

red()   { printf '\033[31m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
dim()   { printf '\033[2m%s\033[0m' "$*"; }

ok()   { printf "  %s %-32s %s\n" "$(green ✓)" "$1" "$2"; }
fail() { printf "  %s %-32s %s\n" "$(red ✗)" "$1" "$2"; }

# 1. Mint alice's user token via password grant.
alice_resp=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=$USER_CLIENT_ID" \
  -d "client_secret=$USER_CLIENT_SECRET" \
  -d "username=alice" \
  -d "password=alice" \
  -d "scope=openid")

alice_token=$(echo "$alice_resp" | jq -r '.access_token // empty')
if [ -z "$alice_token" ]; then
  fail "alice mint" "(see error below)"
  echo "$alice_resp" | jq . >&2 || echo "$alice_resp" >&2
  exit 1
fi
ok "alice mint" "OK"

# 2. Exchange alice's token for workday-api audience as the
#    praxis-gateway client. This is exactly the call the
#    OAuthDelegator makes from inside the gateway.
exchange_resp=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${GATEWAY_CLIENT_ID}:${GATEWAY_CLIENT_SECRET}" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$alice_token" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=$AUDIENCE")

minted=$(echo "$exchange_resp" | jq -r '.access_token // empty')
if [ -z "$minted" ]; then
  err=$(echo "$exchange_resp" | jq -r '.error // empty')
  desc=$(echo "$exchange_resp" | jq -r '.error_description // empty')
  fail "praxis-gateway → workday-api" "${err}: ${desc}"
  echo
  echo "$(dim 'Full Keycloak response:')"
  echo "$exchange_resp" | jq . >&2 || echo "$exchange_resp" >&2
  echo
  echo "$(dim 'Common causes:')"
  echo "$(dim '  - Realm import didn'\''t finish yet — wait ~30s then retry')"
  echo "$(dim '  - Realm imported but authorization-services permission')"
  echo "$(dim '    on workday-api didn'\''t pick up. Try:')"
  echo "$(dim '      docker compose down -v && docker compose up -d')"
  echo "$(dim '  - token-exchange feature not enabled in the running')"
  echo "$(dim '    Keycloak (check KC_FEATURES in docker-compose.yml)')"
  exit 1
fi

# Decode the minted token's payload (middle JWT segment, base64url).
payload=$(echo "$minted" | awk -F. '{print $2}')
# pad the base64 to a multiple of 4
case $((${#payload} % 4)) in
  2) payload="${payload}==" ;;
  3) payload="${payload}=" ;;
esac
decoded=$(printf "%s" "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null || true)
aud=$(echo "$decoded" | jq -r 'if .aud | type == "array" then .aud[0] else .aud end' 2>/dev/null || echo "?")
sub=$(echo "$decoded" | jq -r '.sub // "?"' 2>/dev/null || echo "?")

if [ "$aud" = "$AUDIENCE" ]; then
  ok "praxis-gateway → workday-api" "OK (aud=$aud)"
else
  fail "praxis-gateway → workday-api" "aud mismatch: expected '$AUDIENCE' got '$aud'"
  exit 1
fi

echo
echo "$(dim 'minted token aud claim:') $aud"
echo "$(dim 'minted token sub claim:') $sub"
echo
echo "$(green 'Token exchange works.') The OAuthDelegator inside the gateway will use the same call shape during the demo scenarios."
