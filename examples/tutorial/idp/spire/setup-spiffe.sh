#!/usr/bin/env bash
# Configure the tutorial Keycloak to trust SPIRE and bind the agent's SPIFFE
# ID: the one-time setup for module 16 (Workload identity / SVID).
#
# Run it AFTER bringing up the SPIRE overlay:
#   docker compose -f idp/docker-compose.yml -f idp/docker-compose.spire.yml up -d
#   ./idp/spire/setup-spiffe.sh
#
# Needs curl and jq. `make tutorial-check-spire` runs it for you.
#
# Safe to re-run: the identity provider is updated in place and the client is
# recreated. It applies two things through the admin API, kept OUT of
# realm-export.json so modules 0 to 15, on the base Keycloak, never see SPIFFE
# config:
#
#   1. a SPIFFE identity provider (providerId: spiffe) that validates JWT-SVIDs
#      from trust domain spiffe://cpex.tutorial against SPIRE's JWKS.
#   2. a `federated-jwt` client (hr-copilot-agent) bound to the agent's SPIFFE
#      ID, so presenting that SVID as a client_assertion authenticates the
#      agent. An audience mapper puts cpex-gateway in its token so the gateway
#      can exchange it (leg 2).
set -euo pipefail

KC="${KC:-http://localhost:8081}"
REALM="${REALM:-cpex-tutorial}"
ADMIN="${ADMIN:-admin}"
ADMIN_PW="${ADMIN_PW:-admin}"
IDP_ALIAS="spiffe"
TRUST_DOMAIN="spiffe://cpex.tutorial"
BUNDLE_ENDPOINT="http://spire-oidc:8443/keys"
CLIENT_ID="hr-copilot-agent"
EXPECTED_SUB="spiffe://cpex.tutorial/agent/hr-copilot"
EXCHANGE_CLIENT_AUD="cpex-gateway"

echo "-> obtaining admin token"
TOKEN=$(curl -sf -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username="$ADMIN" -d password="$ADMIN_PW" \
  | jq -r .access_token)

# --- 1. SPIFFE identity provider -------------------------------------------
read -r -d '' IDP_JSON <<JSON || true
{
  "alias": "$IDP_ALIAS",
  "displayName": "SPIFFE (SPIRE)",
  "providerId": "spiffe",
  "enabled": true,
  "storeToken": false,
  "trustEmail": true,
  "config": {
    "trustDomain": "$TRUST_DOMAIN",
    "bundleEndpoint": "$BUNDLE_ENDPOINT",
    "validateSignature": "true"
  }
}
JSON

if curl -sf -o /dev/null -H "Authorization: Bearer $TOKEN" \
     "$KC/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS"; then
  echo "-> updating existing SPIFFE IdP '$IDP_ALIAS'"
  curl -sf -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    "$KC/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS" -d "$IDP_JSON"
else
  echo "-> creating SPIFFE IdP '$IDP_ALIAS'"
  curl -sf -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    "$KC/admin/realms/$REALM/identity-provider/instances" -d "$IDP_JSON"
fi

# --- 2. federated-jwt client bound to the SVID -----------------------------
read -r -d '' CLIENT_JSON <<JSON || true
{
  "clientId": "$CLIENT_ID",
  "enabled": true,
  "protocol": "openid-connect",
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "clientAuthenticatorType": "federated-jwt",
  "attributes": {
    "jwt.credential.issuer": "$IDP_ALIAS",
    "jwt.credential.sub": "$EXPECTED_SUB"
  },
  "protocolMappers": [
    {
      "name": "cpex-gateway-as-audience",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "config": {
        "included.client.audience": "$EXCHANGE_CLIENT_AUD",
        "access.token.claim": "true",
        "id.token.claim": "false"
      }
    }
  ]
}
JSON

CID=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  "$KC/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
  | jq -r 'if length > 0 then .[0].id else "" end')
if [ -n "$CID" ]; then
  echo "-> removing existing client '$CLIENT_ID' before recreate"
  curl -sf -X DELETE -H "Authorization: Bearer $TOKEN" "$KC/admin/realms/$REALM/clients/$CID"
fi
echo "-> creating federated-jwt client '$CLIENT_ID' (sub=$EXPECTED_SUB, aud+=$EXCHANGE_CLIENT_AUD)"
curl -sf -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$KC/admin/realms/$REALM/clients" -d "$CLIENT_JSON"

echo
echo "-> done. Keycloak now authenticates $EXPECTED_SUB by its SVID and can exchange its token for cpex-gateway audiences."
