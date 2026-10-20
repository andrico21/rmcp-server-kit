//! Phone readability and tap targets of the consent and error pages under their page policy.

use std::path::Path;

use super::{
    page_markup::{
        UNMODELLED_ELEMENTS, attribute_names, buttons, declarations, directive, hash_source, head,
        pixels, start_tags, style_start_tags, style_texts, tag_name,
    },
    *,
};

/// The HTML pages of `authorization_server` mode that share one page template.
#[derive(Clone, Copy, Debug)]
enum PageKind {
    /// The consent page served by `/authorize` for a valid request.
    Consent,
    /// The nonredirecting error page served by `/authorize` for an unknown client.
    AuthorizeError,
    /// The nonredirecting error page served by `/oauth/callback` for a malformed state.
    CallbackError,
    /// The consent page of a client whose name spells markup, which the page must escape.
    ConsentWithMarkupName,
}

/// Every page kind; each table-driven test below runs against all of them.
const PAGE_KINDS: [PageKind; 4] = [
    PageKind::Consent,
    PageKind::ConsentWithMarkupName,
    PageKind::AuthorizeError,
    PageKind::CallbackError,
];

/// A client name whose text looks like an inline style attribute and a style element.
const MARKUP_NAME: &str = "Phone style=x <style>b</style>";

/// Fetch one page kind and return its status, CSP header and HTML body.
async fn fetch(server: &Harness, kind: PageKind) -> anyhow::Result<(u16, String, String)> {
    let response = match kind {
        PageKind::Consent => {
            let cid = server.register("Phone layout").await?;
            server.page(&cid).await?
        }
        PageKind::ConsentWithMarkupName => {
            let cid = server.register(MARKUP_NAME).await?;
            server.page(&cid).await?
        }
        PageKind::AuthorizeError => server.page("not-sealed").await?,
        PageKind::CallbackError => {
            server
                .client
                .get(format!("{}/oauth/callback?state=short", server.base))
                .send()
                .await?
        }
    };
    let status = response.status().as_u16();
    let csp = response
        .headers()
        .get("content-security-policy")
        .context("page CSP")?
        .to_str()?
        .to_owned();
    Ok((status, csp, response.text().await?))
}

/// Every page sets a device-width layout viewport exactly once, inside its head.
#[tokio::test]
async fn every_page_declares_a_device_width_viewport_once_in_its_head() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let viewport = "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">";
    for kind in PAGE_KINDS {
        // When
        let (status, _csp, html) = fetch(&server, kind).await?;
        // Then
        let expected = match kind {
            PageKind::Consent | PageKind::ConsentWithMarkupName => 200,
            PageKind::AuthorizeError | PageKind::CallbackError => 400,
        };
        ensure!(
            status == expected,
            "{kind:?} status {status}, want {expected}"
        );
        ensure!(
            html.matches("name=\"viewport\"").count() == 1,
            "{kind:?} has exactly one viewport declaration"
        );
        ensure!(
            head(&html)?.contains(viewport),
            "{kind:?} viewport is a device-width head meta"
        );
    }
    server.close().await
}

/// Every page carries one head stylesheet that its own CSP admits by hash and nothing else.
#[tokio::test]
async fn every_page_stylesheet_is_admitted_only_by_its_hash() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for kind in PAGE_KINDS {
        // When
        let (_status, csp, html) = fetch(&server, kind).await?;
        // Then
        let tags = style_start_tags(&html);
        ensure!(
            tags == ["<style"],
            "{kind:?} has one style element, a bare <style> whose text is hashed: {tags:?}"
        );
        let sheets = style_texts(&html);
        ensure!(sheets.len() == 1, "{kind:?} has one style element");
        ensure!(
            style_texts(head(&html)?).len() == 1,
            "{kind:?} style element is in the head"
        );
        let sheet = sheets.first().context("stylesheet")?;
        ensure!(
            directive(&csp, "style-src") == Some(vec![hash_source(sheet).as_str()]),
            "{kind:?} style-src admits exactly the served stylesheet: {csp}"
        );
        ensure!(
            directive(&csp, "default-src") == Some(vec!["'none'"]),
            "{kind:?} default-src stays 'none'"
        );
        for forbidden in ["unsafe-inline", "unsafe-hashes", "unsafe-eval", "nonce-"] {
            ensure!(!csp.contains(forbidden), "{kind:?} CSP has no {forbidden}");
        }
        for tag in start_tags(&html) {
            ensure!(
                !attribute_names(tag).iter().any(|name| name == "style"),
                "{kind:?} has no style attribute, which a hash source cannot admit: {tag}"
            );
            let name = tag_name(tag);
            ensure!(
                !UNMODELLED_ELEMENTS.contains(&name.as_str()),
                "{kind:?} uses no element the page-markup reader does not model: {tag}"
            );
            ensure!(
                !matches!(name.as_str(), "script" | "link"),
                "{kind:?} loads no script and no external resource: {tag}"
            );
        }
        ensure!(!html.contains("<!--"), "{kind:?} has no comment");
        if matches!(kind, PageKind::ConsentWithMarkupName) {
            ensure!(
                html.contains("Phone style=x &lt;style&gt;b&lt;/style&gt;"),
                "{kind:?} shows the name as escaped text"
            );
        }
        ensure!(
            !html.contains("<script") && !html.contains("<link"),
            "{kind:?} loads no script and no external resource"
        );
    }
    server.close().await
}

/// The shared stylesheet makes buttons at least 44 by 44 CSS px and wraps unbreakable text.
#[tokio::test]
async fn every_page_stylesheet_sizes_tap_targets_and_wraps_long_text() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for kind in PAGE_KINDS {
        // When
        let (_status, _csp, html) = fetch(&server, kind).await?;
        // Then
        let sheet = *style_texts(&html).first().context("stylesheet")?;
        let button = declarations(sheet, "button");
        for property in ["min-height", "min-width"] {
            ensure!(
                pixels(&button, property).is_some_and(|value| value >= 44),
                "{kind:?} button {property} is at least 44px: {sheet}"
            );
        }
        ensure!(
            button.contains(&"font-size:1rem"),
            "{kind:?} button text keeps the root size"
        );
        let body = declarations(sheet, "body");
        ensure!(
            body.contains(&"overflow-wrap:anywhere"),
            "{kind:?} long names and redirect URIs wrap: {sheet}"
        );
        ensure!(
            body.iter()
                .any(|declaration| declaration.starts_with("max-width:")),
            "{kind:?} line length is bounded on wide screens"
        );
    }
    server.close().await
}

/// Tapping a consent button submits the decision its label names to the consent endpoint.
#[tokio::test]
async fn consent_buttons_submit_the_decision_their_label_names() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for label in ["Approve", "Deny"] {
        let cid = server.register("Button labels").await?;
        let response = server.page(&cid).await?;
        let csrf = response.headers().get("set-cookie").cloned();
        let html = response.text().await?;
        ensure!(
            html.matches("<form method=\"post\" action=\"/oauth/consent\">")
                .count()
                == 1,
            "one consent form posting to the consent endpoint"
        );
        let all = buttons(&html);
        ensure!(all.len() == 2, "exactly the two decision buttons");
        let button = all
            .iter()
            .find(|button| button.label == label)
            .context("labelled button")?;
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
            .extend_pairs([
                ("request", token),
                (button.name.as_str(), button.value.as_str()),
            ])
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
        if label == "Approve" {
            ensure!(decided.status() == 302, "approval redirects");
            let target = location(&decided)?;
            ensure!(
                target.path() == "/authorize"
                    && target.port() == Some(server.upstream.address().port()),
                "approval continues at the identity provider"
            );
        } else {
            assert_error_redirect(&decided, "access_denied", &server.base)?;
        }
    }
    server.close().await
}

/// The consent-page policy quoted in `docs/OAUTH_PROXY.md` row 2a is the header the server sends.
#[tokio::test]
async fn documented_consent_policy_is_the_served_header() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let (_status, csp, _html) = fetch(&server, PageKind::Consent).await?;
    // When
    let doc =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/OAUTH_PROXY.md"))?;
    let rows: Vec<&str> = doc
        .lines()
        .filter(|line| line.starts_with("| 2a |"))
        .collect();
    // Then
    ensure!(rows.len() == 1, "one row 2a, found {}", rows.len());
    let row = rows.first().context("row 2a")?;
    ensure!(
        row.contains(&format!("`Content-Security-Policy: {csp}`")),
        "docs/OAUTH_PROXY.md row 2a quotes the served policy {csp:?}"
    );
    server.close().await
}
