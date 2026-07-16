# CPEX Tutorial: Keycloak IdP

A throwaway [Keycloak](https://www.keycloak.org/) realm that provides users,
roles, and clients for the CPEX tutorial. It mints the JWTs the CPEX gateway
validates, and it backs the token-exchange and CIBA exercises.

> **⚠️ Tutorial-only credentials.** The admin login, every client secret, and
> every user password in this stack are hard-coded, public, and identical to
> the usernames. They exist so the tutorial is reproducible on your laptop.
> **Never use any of this in production, and never reuse these secrets.**

---

## What's in the realm

Realm name: **`cpex-tutorial`**

### Personas

| User  | Password | Realm role | `permissions` | `team`        | `manager` | Notes                              |
|-------|----------|------------|---------------|---------------|-----------|------------------------------------|
| alice | `alice`  | `hr`       | `view_ssn`    | `compliance`  | n/a       | HR analyst who **can** see SSNs    |
| dana  | `dana`   | `hr`       | *(none)*      | `compliance`  | n/a       | HR analyst who **cannot** see SSNs |
| evan  | `evan`   | `engineer` | *(none)*      | `engineering` | `mona`    | Engineer with a manager            |
| sam   | `sam`    | `security` | *(none)*      | `security`    | n/a       | Security team member               |
| mona  | `mona`   | `hr`       | *(none)*      | `compliance`  | n/a       | Manager persona (elicitation approvals) |

All users have `emailVerified: true` and are enabled for the password
(direct access) grant.

### Clients

| Client          | Type         | Purpose                                                        | Secret               |
|-----------------|--------------|----------------------------------------------------------------|----------------------|
| `cpex-tutorial` | public       | Mints user tokens (password + standard flow). Redirect `*`.    | n/a (public)         |
| `workday-api`   | confidential | Token-exchange **target** audience (resource server).          | `workday-dev-secret` |
| `github-api`    | confidential | Token-exchange **target** audience (resource server).          | `github-dev-secret`  |
| `cpex-gateway`  | confidential | Token-exchange **requester** + CIBA client. Service account on.| `gateway-dev-secret` |

`cpex-gateway` has CIBA (`oidc.ciba.grant.enabled=true`) and standard OAuth2
token exchange (`standard.token.exchange.enabled=true`) enabled.

### Flat claims (important)

The CPEX JWT validator reads **flat, top-level** claims, not Keycloak's
default nested `realm_access.roles`. The `cpex-tutorial` client therefore
carries protocol mappers that emit these claims into the **access token**:

| Claim         | Source                                    | Shape          |
|---------------|-------------------------------------------|----------------|
| `roles`       | realm-role mapper (flat, no prefix)       | array of string |
| `permissions` | user attribute `permissions`, multivalued | array of string |
| `team`        | user attribute `team`, multivalued        | array of string |
| `manager`     | user attribute `manager`, single-valued   | string         |
| `aud`         | audience mapper                           | includes `cpex-tutorial` |

---

## Start it

```bash
docker compose up -d
```

First boot pulls the `quay.io/keycloak/keycloak:26.1` image and imports the
realm, roughly **30 seconds**. Watch readiness with:

```bash
docker compose ps          # STATUS becomes "healthy" once the realm is up
docker compose logs -f keycloak
```

Optional Valkey session store (tutorial Module 7), off by default:

```bash
docker compose --profile valkey up -d
```

## Reset it (ephemeral = your reset button)

This runs in dev mode with **no persistent database**. The realm is imported
fresh on every start and discarded on stop:

```bash
docker compose down        # wipes all users, tokens, and config
docker compose up -d       # clean realm again
```

There is nothing to migrate and no state to clean up. If anything gets into a
weird state, `down` then `up -d`.

---

## Admin console

- URL: <http://localhost:8081>
- Login: `admin` / `admin`

Inspect the realm: switch the realm dropdown (top-left) to **cpex-tutorial**,
then browse **Clients → cpex-tutorial → Client scopes / Dedicated scopes** to
see the protocol mappers, or **Users** to see attributes and role mappings.

---

## Endpoints (wire these into the JWT plugin)

Base issuer:

```
http://localhost:8081/realms/cpex-tutorial
```

| Endpoint          | URL                                                                            |
|-------------------|--------------------------------------------------------------------------------|
| Issuer            | `http://localhost:8081/realms/cpex-tutorial`                                   |
| OIDC discovery    | `http://localhost:8081/realms/cpex-tutorial/.well-known/openid-configuration`  |
| Token             | `http://localhost:8081/realms/cpex-tutorial/protocol/openid-connect/token`     |
| JWKS              | `http://localhost:8081/realms/cpex-tutorial/protocol/openid-connect/certs`     |

Configure the JWT validator with audience **`cpex-tutorial`**.

---

## Mint a token (password grant)

Get an access token for **alice**:

```bash
curl -s \
  -X POST \
  http://localhost:8081/realms/cpex-tutorial/protocol/openid-connect/token \
  -d grant_type=password \
  -d client_id=cpex-tutorial \
  -d username=alice \
  -d password=alice \
  | jq -r .access_token
```

Decode the payload to confirm the flat claims (`roles`, `permissions`, `team`,
`manager`, `aud`):

```bash
TOKEN=$(curl -s -X POST \
  http://localhost:8081/realms/cpex-tutorial/protocol/openid-connect/token \
  -d grant_type=password -d client_id=cpex-tutorial \
  -d username=alice -d password=alice | jq -r .access_token)

echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

For **alice** you should see `"roles": ["hr"]`, `"permissions": ["view_ssn"]`,
`"team": ["compliance"]`, and `cpex-tutorial` in `aud`. For **dana**, the same
minus `permissions`.
