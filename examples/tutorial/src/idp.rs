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

/// Mint an access token for a persona via the OAuth password grant against
/// the tutorial realm. `client_id` is the public `cpex-tutorial` client.
///
/// Returns the raw JWT string, ready to hand to
/// [`crate::Caller::with_token`]. Errors carry a human-readable hint so a
/// reader whose IdP isn't up sees "is the stack running?" rather than a
/// bare connection error.
pub async fn mint_token(username: &str, password: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client
        .post(token_endpoint())
        .form(&[
            ("grant_type", "password"),
            ("client_id", "cpex-tutorial"),
            ("username", username),
            ("password", password),
            ("scope", "openid"),
        ])
        .send()
        .await
        .map_err(|e| {
            format!(
                "could not reach the tutorial IdP at {} ({e}).\n       \
                 Is it running? Start it with:\n       \
                 docker compose -f examples/tutorial/idp/docker-compose.yml up -d",
                token_endpoint()
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "token request for '{username}' failed ({status}): {body}"
        ));
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
