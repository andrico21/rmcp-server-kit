//! Callback and token rejections observed through the real-listener harness.

use super::*;

/// Issuer comparison is byte-exact, including near misses that URL normalization would hide.
#[tokio::test]
async fn callback_rejects_issuer_near_misses() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let cid = server.register("Issuer exactness fixture").await?;
    let flow = approved_flow(
        &server,
        &cid,
        "issuer-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-",
    )
    .await?;
    let issuer = format!("http://localhost:{}", server.upstream.address().port());
    let mut cases: Vec<(Option<String>, u16)> = vec![(None, 302), (Some(issuer.clone()), 302)];
    cases.extend(
        [
            issuer.replacen("http", "HTTP", 1),
            issuer.replace("localhost", "LOCALHOST"),
            format!("{issuer}/"),
            format!("{issuer}/extra"),
            issuer.trim_end_matches(char::is_numeric).to_owned(),
            format!("{issuer}suffix"),
            issuer.replace("localhost", "%6cocalhost"),
            "http://localhost:80".into(),
            format!(" {issuer}"),
            format!("{issuer} "),
            String::new(),
        ]
        .into_iter()
        .map(|value| (Some(value), 400)),
    );
    for (iss, status) in cases {
        let mut pairs = vec![("state", flow.0.as_str()), ("code", "issuer-case-code")];
        if let Some(value) = &iss {
            pairs.push(("iss", value));
        }
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        // When
        let response = server
            .client
            .get(format!("{}/oauth/callback?{query}", server.base))
            .header("cookie", &flow.1)
            .send()
            .await?;
        // Then
        ensure!(response.status() == status, "issuer near-miss verdict");
        ensure!(
            response.headers().contains_key("location") == (status == 302),
            "issuer redirect class"
        );
        ensure!(
            response
                .headers()
                .get("set-cookie")
                .context("clear")?
                .to_str()?
                == format!(
                    "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
                    flow.1.split_once('=').context("name")?.0
                ),
            "selected cookie always cleared"
        );
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("state", flow.0.as_str()),
            ("code", "duplicate-issuer-code"),
            ("iss", issuer.as_str()),
            ("iss", issuer.as_str()),
        ])
        .finish();
    let repeated = server
        .client
        .get(format!("{}/oauth/callback?{query}", server.base))
        .header("cookie", &flow.1)
        .send()
        .await?;
    ensure!(
        repeated.status() == 400 && !repeated.headers().contains_key("location"),
        "repeated issuer rejected"
    );
    server.close().await
}

/// Malformed callbacks cannot use ambient Lax cookies to abort unrelated browser logins.
#[tokio::test]
async fn invalid_state_preserves_ambient_flows() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let cid = server.register("Ambient flows fixture").await?;
    let first = approved_flow(
        &server,
        &cid,
        "ambient-first-0123456789abcdefghijklmnopqrstuvwxyz._~-",
    )
    .await?;
    let second = approved_flow(
        &server,
        &cid,
        "ambient-second-9876543210ZYXWVUTSRQPONMLKJIHGFED._~-",
    )
    .await?;
    for query in ["", "state=short", "state=", "state=%20", "code=x&code=y"] {
        // When
        let response = server
            .client
            .get(format!("{}/oauth/callback?{query}", server.base))
            .header("cookie", format!("{}; {}", first.1, second.1))
            .send()
            .await?;
        // Then
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "malformed state page"
        );
        ensure!(
            !response.headers().contains_key("set-cookie"),
            "no derivable state means no cookie clearing"
        );
    }
    server.close().await
}

/// The real token route rejects client migration mistakes, smuggling and broken grant bindings locally.
#[tokio::test]
async fn token_route_rejects_bad_clients_and_bindings_locally() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let owner = server.register("Wire rejection owner").await?;
    let verifier = "wire-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-";
    let flow = approved_flow(&server, &owner, verifier).await?;
    let callback = callback_flow(&server, &flow, "wire-rejection-code").await?;
    let target = location(&callback)?;
    let code = target
        .query_pairs()
        .find(|(key, _)| key == "code")
        .context("code")?
        .1
        .into_owned();
    for (client, encoded, redirect, duplicate, status, error) in [
        (
            "garbage-client",
            code.clone(),
            CALLBACK.to_owned(),
            false,
            401,
            "invalid_client",
        ),
        (
            "static-upstream",
            code.clone(),
            CALLBACK.to_owned(),
            false,
            401,
            "invalid_client",
        ),
        (
            owner.as_str(),
            code.clone(),
            CALLBACK.to_owned(),
            true,
            400,
            "invalid_request",
        ),
        (
            owner.as_str(),
            format!("{code}x"),
            CALLBACK.to_owned(),
            false,
            400,
            "invalid_grant",
        ),
        (
            owner.as_str(),
            code.clone(),
            format!("{CALLBACK}/"),
            false,
            400,
            "invalid_grant",
        ),
    ] {
        let mut pairs = vec![
            ("grant_type", "authorization_code"),
            ("client_id", client),
            ("code", &encoded),
            ("redirect_uri", &redirect),
            ("code_verifier", verifier),
        ];
        if duplicate {
            pairs.push(("code", "raw-smuggled-code"));
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        // When
        let response = server
            .client
            .post(format!("{}/token", server.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;
        // Then
        ensure!(response.status() == status, "wire rejection status");
        ensure!(
            response.json::<Value>().await? == json!({"error":error}),
            "complete wire rejection JSON"
        );
        ensure!(
            server
                .upstream
                .received_requests()
                .await
                .context("requests")?
                .is_empty(),
            "no upstream request on local rejection"
        );
    }
    server.close().await
}
