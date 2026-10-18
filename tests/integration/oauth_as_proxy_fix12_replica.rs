/// Foreign and static client IDs return complete error bodies without contacting upstream.
#[tokio::test]
async fn fix12_refresh_foreign_client_wire_table() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let owner = server.register("Refresh rejection owner A").await?;
    let foreign = server.register("Refresh rejection foreign B").await?;
    let wrapped = reference_seal(
        "fixture-secret-with-at-least-32-bytes",
        "refresh",
        &json!({"rt":"foreign-rejection-raw","cid":fixture_digest(&owner)}),
    )?;
    for (client, status, error) in [
        (foreign.as_str(), 400, "invalid_grant"),
        ("static-upstream", 401, "invalid_client"),
        ("garbage-client", 401, "invalid_client"),
    ] {
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "refresh_token"),
                ("refresh_token", wrapped.as_str()),
                ("client_id", client),
            ])
            .finish();
        // When
        let response = server
            .client
            .post(format!("{}/token", server.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await?;
        // Then
        ensure!(response.status() == status, "refresh foreign/static status");
        ensure!(
            response.json::<Value>().await? == json!({"error":error}),
            "complete refresh rejection body"
        );
        ensure!(
            server
                .upstream
                .received_requests()
                .await
                .context("requests")?
                .is_empty(),
            "foreign refresh has no upstream effect"
        );
    }
    server.close().await
}

/// Replicas sharing an issuer accept the untouched browser cookie without renaming it.
#[tokio::test]
async fn fix12_same_public_origin_replicas() -> anyhow::Result<()> {
    use url::form_urlencoded;
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };
    // Given
    let first = Harness::start("30days").await?;
    let second = Harness::start_public(
        "30days",
        "authorization_server",
        (false, false),
        Some(&first.base),
    )
    .await?;
    let owner = first.register("Shared public origin replica owner").await?;
    let verifier = "shared-origin-verifier-0123456789abcdefghijklmnopqrstuvwxyz._~-";
    let flow = approved_flow(&first, &owner, verifier).await?;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"access_token":"shared-origin-access","refresh_token":"shared-origin-refresh"}),
        ))
        .expect(1)
        .mount(&second.upstream)
        .await;
    // When
    let callback = callback_flow(&second, &flow, "shared-origin-code").await?;
    let target = location(&callback)?;
    let code = target
        .query_pairs()
        .find(|(key, _)| key == "code")
        .context("code")?
        .1
        .into_owned();
    let response = redeem(&second, &owner, &code, verifier).await?;
    // Then
    ensure!(
        target
            .query_pairs()
            .any(|(key, value)| key == "iss" && value == first.base),
        "shared issuer retained"
    );
    ensure!(
        response.status() == 200,
        "unaltered cross-replica cookie and code accepted"
    );
    let output: Value = response.json().await?;
    ensure!(
        reference_open(
            "refresh",
            output
                .get("refresh_token")
                .and_then(Value::as_str)
                .context("refresh")?
        )? == json!({"rt":"shared-origin-refresh","cid":fixture_digest(&owner)}),
        "replica wrapper binding"
    );
    let requests = second
        .upstream
        .received_requests()
        .await
        .context("requests")?;
    let pairs: Vec<_> =
        form_urlencoded::parse(&requests.first().context("request")?.body).collect();
    ensure!(
        pairs.iter().any(|(key, value)| key == "redirect_uri"
            && value == &format!("{}/oauth/callback", first.base)),
        "shared origin upstream redirect"
    );
    first.close().await?;
    second.close().await
}
