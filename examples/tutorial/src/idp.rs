// Location: ./examples/tutorial/src/idp.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Helpers for talking to the tutorial Keycloak realm (started by
// `idp/docker-compose.yml`). Modules 2+ call `mint_token` to get a real
// JWT for a persona; the JWT plugin in policy then validates it against
// the realm's JWKS. This is the ONLY place the tutorial speaks HTTP to
// the IdP, policy never does; it verifies tokens offline against cached
// JWKS.

use std::time::Duration;

/// Base URL of the tutorial Keycloak realm. Override with the
/// `CPEX_TUTORIAL_ISSUER` env var if you mapped Keycloak to another port.
pub fn issuer() -> String {
    std::env::var("CPEX_TUTORIAL_ISSUER")
        .unwrap_or_else(|_| "http://localhost:8081/realms/cpex-tutorial".into())
}

/// The realm's OIDC token endpoint.
pub fn token_endpoint() -> String {
    format!("{}/protocol/openid-connect/token", issuer())
}

/// The realm's JWKS endpoint, where the JWT plugin fetches signing keys.
pub fn jwks_url() -> String {
    format!("{}/protocol/openid-connect/certs", issuer())
}

/// POST a form to a token endpoint and return its `access_token`.
///
/// Every grant the tutorial uses (password, client_credentials, and the same
/// password grant against another realm) differs only in the form fields and
/// the endpoint, so they all come through here. `what` names the request in
/// the error, e.g. "token request for 'alice'".
async fn post_token_form(
    endpoint: &str,
    form: &[(&str, &str)],
    what: &str,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client.post(endpoint).form(form).send().await.map_err(|e| {
        format!(
            "could not reach the tutorial IdP at {endpoint} ({e}).\n       \
                 Is it running? Start it with:\n       \
                 docker compose -f examples/tutorial/idp/docker-compose.yml up -d"
        )
    })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("{what} failed ({status}): {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("token response was not JSON: {e}"))?;
    json.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "token response had no access_token".into())
}

/// Mint an access token for a persona via the OAuth password grant against
/// the tutorial realm, through the public `cpex-tutorial` client.
///
/// Returns the raw JWT string, ready to hand to
/// [`crate::Caller::with_token`]. Errors carry a human-readable hint so a
/// reader whose IdP isn't up sees "is the stack running?" rather than a
/// bare connection error.
pub async fn mint_token(username: &str, password: &str) -> Result<String, String> {
    post_token_form(
        &token_endpoint(),
        &[
            ("grant_type", "password"),
            ("client_id", "cpex-tutorial"),
            ("username", username),
            ("password", password),
            ("scope", "openid"),
        ],
        &format!("token request for '{username}'"),
    )
    .await
}

/// Base URL of the tutorial Keycloak (everything before `/realms/...`),
/// derived from [`issuer`] so a `CPEX_TUTORIAL_ISSUER` override carries through.
fn base_url() -> String {
    issuer()
        .split_once("/realms/")
        .map(|(base, _)| base.to_string())
        .unwrap_or_else(|| "http://localhost:8081".to_string())
}

/// Mint a user token from an arbitrary realm and client via the password
/// grant. The multi-issuer module (17) uses this to get a token from a second
/// trusted issuer, the partner realm, alongside the home realm's, so one
/// resolver can validate both.
pub async fn mint_token_in_realm(
    realm: &str,
    client_id: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let endpoint = format!(
        "{}/realms/{realm}/protocol/openid-connect/token",
        base_url()
    );
    post_token_form(
        &endpoint,
        &[
            ("grant_type", "password"),
            ("client_id", client_id),
            ("username", username),
            ("password", password),
            ("scope", "openid"),
        ],
        &format!("token request for '{username}' in realm '{realm}'"),
    )
    .await
}

/// Mint an access token for an OAuth *client* via the `client_credentials`
/// grant. Unlike [`mint_token`], there is no user: the token speaks for the
/// client's own service account. This is how an agent that authenticates to
/// the IdP as a registered client, not on behalf of a signed-in human, gets a
/// token, the inbound credential a `subject: client` delegation then scopes.
///
/// `client_id` / `client_secret` identify the calling agent (e.g. the tutorial
/// realm's `cpex-agent`). Returns the raw JWT string.
pub async fn mint_client_token(client_id: &str, client_secret: &str) -> Result<String, String> {
    post_token_form(
        &token_endpoint(),
        &[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ],
        &format!("client_credentials token request for '{client_id}'"),
    )
    .await
}

/// Mint a SPIFFE JWT-SVID for `spiffe_id` off the tutorial's SPIRE server
/// (module 16). Unlike the OAuth token minters, this shells out to the running
/// `cpex-tutorial-spire-server` container: the SVID is signed by SPIRE, not
/// the IdP. Its audience is the tutorial realm issuer, as the SPIFFE
/// client-auth draft requires (leg 1 presents it to that realm). Needs the
/// SPIRE overlay up, see `idp/docker-compose.spire.yml`.
///
/// Blocking on purpose: it runs once, before any concurrent work, and the
/// tutorial reads better without a second process API in play.
pub fn mint_svid(spiffe_id: &str) -> Result<String, String> {
    let out = std::process::Command::new("docker")
        .args([
            "exec",
            "cpex-tutorial-spire-server",
            "/opt/spire/bin/spire-server",
            "jwt",
            "mint",
            "-spiffeID",
            spiffe_id,
            "-audience",
            &issuer(),
        ])
        .output()
        .map_err(|e| format!("could not run `docker` to mint an SVID: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`spire-server jwt mint` failed: {}\n       Is the SPIRE overlay up?\n       \
             docker compose -f examples/tutorial/idp/docker-compose.yml \
             -f examples/tutorial/idp/docker-compose.spire.yml up -d",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // `jwt mint` prints the token on its own line.
    let svid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if svid.is_empty() {
        return Err("`spire-server jwt mint` produced no token".into());
    }
    Ok(svid)
}

/// Poll the realm's discovery document until Keycloak answers or the
/// deadline passes. Modules call this in `--check` mode so CI waits for
/// the container to finish booting before minting tokens.
pub async fn wait_until_ready(max_wait: Duration) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let url = format!("{}/.well-known/openid-configuration", issuer());
    let deadline = tokio::time::Instant::now() + max_wait;
    loop {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "tutorial IdP not ready at {url} after {max_wait:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
