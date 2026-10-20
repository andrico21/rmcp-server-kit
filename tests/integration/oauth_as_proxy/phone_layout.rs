//! Phone readability and tap targets of the consent and error pages under their page policy.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};

use super::*;

/// The HTML pages of `authorization_server` mode that share one page template.
#[derive(Clone, Copy, Debug)]
enum PageKind {
    /// The consent page served by `/authorize` for a valid request.
    Consent,
    /// The nonredirecting error page served by `/authorize` for an unknown client.
    AuthorizeError,
    /// The nonredirecting error page served by `/oauth/callback` for a malformed state.
    CallbackError,
}

/// Every page kind; each table-driven test below runs against all of them.
const PAGE_KINDS: [PageKind; 3] = [
    PageKind::Consent,
    PageKind::AuthorizeError,
    PageKind::CallbackError,
];

/// Fetch one page kind and return its status, CSP header and HTML body.
async fn fetch(server: &Harness, kind: PageKind) -> anyhow::Result<(u16, String, String)> {
    let response = match kind {
        PageKind::Consent => {
            let cid = server.register("Phone layout").await?;
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

/// The markup between `<head>` and `</head>`.
fn head(html: &str) -> anyhow::Result<&str> {
    html.split_once("<head>")
        .and_then(|(_, rest)| rest.split_once("</head>"))
        .map(|(inside, _)| inside)
        .context("head element")
}

/// The text content of every `<style>` element in `markup`, in document order.
fn style_texts(markup: &str) -> Vec<&str> {
    markup
        .split("<style>")
        .skip(1)
        .filter_map(|rest| rest.split_once("</style>").map(|(text, _)| text))
        .collect()
}

/// The start tag up to its `>` of every `<style` element in `markup`, matched in any letter case.
fn style_start_tags(markup: &str) -> Vec<&str> {
    let lower = markup.to_ascii_lowercase();
    lower
        .match_indices("<style")
        .filter_map(|(start, _)| {
            let next = lower.get(start..)?.strip_prefix("<style")?.chars().next();
            next.is_some_and(|after| after.is_ascii_whitespace() || matches!(after, '>' | '/'))
                .then(|| markup.get(start..))?
        })
        .map(|rest| rest.split_once('>').map_or(rest, |(tag, _)| tag))
        .collect()
}

/// The CSP hash source a browser computes for an inline element with this exact text.
fn hash_source(text: &str) -> String {
    format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(text.as_bytes()))
    )
}

/// The source list of one CSP directive, or `None` when the policy omits the directive.
fn directive<'policy>(csp: &'policy str, name: &str) -> Option<Vec<&'policy str>> {
    csp.split(';').find_map(|part| {
        let mut tokens = part.split_ascii_whitespace();
        (tokens.next() == Some(name)).then(|| tokens.collect())
    })
}

/// The declarations of the rule whose selector is exactly `selector`.
fn declarations<'sheet>(sheet: &'sheet str, selector: &str) -> Vec<&'sheet str> {
    sheet
        .split('}')
        .filter_map(|rule| rule.split_once('{'))
        .filter(|(rule_selector, _)| rule_selector.trim() == selector)
        .flat_map(|(_, body)| body.split(';').map(str::trim))
        .filter(|declaration| !declaration.is_empty())
        .collect()
}

/// The CSS pixel value of `property` in `rule`, when it is given in `px`.
fn pixels(rule: &[&str], property: &str) -> Option<u32> {
    rule.iter().find_map(|declaration| {
        let (name, value) = declaration.split_once(':')?;
        (name.trim() == property)
            .then(|| value.trim().strip_suffix("px")?.parse().ok())
            .flatten()
    })
}

/// A button of the consent form: its submitted name and value, and its visible label.
struct Button {
    /// The submitted field name.
    name: String,
    /// The submitted field value.
    value: String,
    /// The label text the user taps.
    label: String,
}

/// The value of attribute `name` inside one start tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    tag.split_once(&format!(" {name}=\""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

/// Every `<button>` of `markup` with its attributes and label.
fn buttons(markup: &str) -> Vec<Button> {
    markup
        .split("<button")
        .skip(1)
        .filter_map(|rest| {
            let (tag, after) = rest.split_once('>')?;
            let (label, _) = after.split_once("</button>")?;
            Some(Button {
                name: attribute(tag, "name")?,
                value: attribute(tag, "value")?,
                label: label.to_owned(),
            })
        })
        .collect()
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
        ensure!(
            matches!((kind, status), (PageKind::Consent, 200) | (_, 400)),
            "{kind:?} status {status}"
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
        let lower = html.to_ascii_lowercase();
        ensure!(
            !lower
                .split_ascii_whitespace()
                .any(|word| word.starts_with("style=")),
            "{kind:?} has no style attribute in any case or quoting, which a hash source cannot admit"
        );
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
