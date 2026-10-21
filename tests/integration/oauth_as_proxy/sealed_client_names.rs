//! Sealed client names that fail the registration rules are shown as unnamed on the consent page.

use super::{client_name_spoofing::sealed_client, *};

/// Sealed names that fail the registration rules, one per rejected class.
fn rejected_names() -> [String; 8] {
    [
        "MarkerOne\u{202E}x".to_owned(),
        "MarkerTwo\u{200B}x".to_owned(),
        "MarkerThree\u{3164}x".to_owned(),
        "MarkerFour\u{E0041}x".to_owned(),
        "MarkerFive\u{7}x".to_owned(),
        "MarkerSix\u{2028}x".to_owned(),
        format!("MarkerSeven{}", "x".repeat(118)),
        "MarkerEight\u{180E}x".to_owned(),
    ]
}

/// The HTML text a browser receives for an untrusted value.
fn escaped(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// A sealed name that fails the registration rules is shown as an unnamed application and no
/// part of it reaches the page.
#[tokio::test]
async fn consent_page_shows_a_rejected_sealed_name_as_unnamed() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for name in rejected_names() {
        let cid = sealed_client(&[CALLBACK.to_owned()], Some(&name))?;
        // When
        let response = server.authorize(&Harness::params(&cid), None).await?;
        // Then
        let status = response.status();
        let html = response.text().await?;
        ensure!(status == 200, "{name:?}: consent page status {status}");
        ensure!(
            html.contains("<p>An unnamed application</p>"),
            "{name:?}: shown as unnamed"
        );
        ensure!(
            !html.contains("(name supplied by the application, not verified)"),
            "{name:?}: no supplied-name label"
        );
        ensure!(!html.contains("Marker"), "{name:?}: no part of the name");
    }
    server.close().await
}

/// A sealed name that passes the registration rules is rendered inside the name isolate.
#[tokio::test]
async fn consent_page_shows_an_accepted_sealed_name() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let accepted = [
        "Plain name".to_owned(),
        "\u{5E9}\u{5DC}\u{5D5}\u{5DD}".to_owned(),
        "Heart \u{2764}\u{FE0F}".to_owned(),
        "y".repeat(128),
    ];
    for name in accepted {
        let cid = sealed_client(&[CALLBACK.to_owned()], Some(&name))?;
        // When
        let response = server.authorize(&Harness::params(&cid), None).await?;
        // Then
        let status = response.status();
        let html = response.text().await?;
        ensure!(status == 200, "{name:?}: consent page status {status}");
        ensure!(
            html.contains(&format!(
                "<p><bdi>{}</bdi> (name supplied by the application, not verified)</p>",
                escaped(&name)
            )),
            "{name:?}: rendered inside the isolate"
        );
    }
    server.close().await
}

/// Approval continues at the identity provider for a client whose sealed name is shown as unnamed.
#[tokio::test]
async fn approval_continues_for_a_rejected_sealed_name() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let cid = sealed_client(&[CALLBACK.to_owned()], Some("MarkerOne\u{202E}x"))?;
    let response = server.authorize(&Harness::params(&cid), None).await?;
    let csrf = response.headers().get("set-cookie").cloned();
    let html = response.text().await?;
    ensure!(
        html.contains("<p>An unnamed application</p>"),
        "shown as unnamed"
    );
    let token = html
        .split("name=\"request\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .context("hidden request")?;
    let cookie = csrf
        .context("CSRF cookie")?
        .to_str()?
        .split(';')
        .next()
        .context("cookie pair")?
        .to_owned();
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("request", token), ("decision", "approve")])
        .finish();
    // When
    let decided = server
        .client
        .post(format!("{}/oauth/consent", server.base))
        .header("cookie", cookie)
        .header("origin", &server.base)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    // Then
    ensure!(decided.status() == 302, "approval redirects");
    let target = location(&decided)?;
    ensure!(
        target.path() == "/authorize" && target.port() == Some(server.upstream.address().port()),
        "approval continues at the identity provider"
    );
    server.close().await
}
