//! Real-wire paired controls for request transmission and exchange-local recordings.

use anyhow::{Context as _, ensure};
use tokio::task::spawn_blocking;

use super::{
    fixtures::{AUTHORIZE, INIT, TOKEN, document, exchange, fence},
    grammar::parse_cases,
    identity::Identity,
    runtime::run_case,
};

/// Real transport preserves Host, body, headers and rewritten redirect expectations.
// cancel-safe: each run_case owns bounded requests and abort-on-drop server tasks.
#[tokio::test]
async fn wire_table_distinguishes_when_documented_requests_change() -> anyhow::Result<()> {
    let identity = spawn_blocking(Identity::generate).await??;
    for (name, request, response, passes) in [
        ("initialize", INIT.to_owned(), "HTTP/1.1 200 OK", true),
        (
            "request-body",
            INIT.replace("\"initialize\"", "\"unknown\""),
            "HTTP/1.1 200 OK",
            false,
        ),
        (
            "request-header",
            INIT.replace("Content-Type: application/json", "Content-Type: text/plain"),
            "HTTP/1.1 200 OK",
            false,
        ),
        (
            "host",
            INIT.replace("Host: mcp.example", "Host: evil.example"),
            "HTTP/1.1 403 Forbidden",
            true,
        ),
        (
            "host",
            INIT.replace("Host: mcp.example", "Host: evil.example"),
            "HTTP/1.1 200 OK",
            false,
        ),
        (
            "redirect",
            AUTHORIZE.to_owned(),
            "HTTP/1.1 302 Found\nLocation: https://idp.example/authorize?<any>",
            true,
        ),
        (
            "redirect",
            AUTHORIZE.to_owned(),
            "HTTP/1.1 404 Not Found",
            false,
        ),
        (
            "rewrite-expectation",
            AUTHORIZE.to_owned(),
            "HTTP/1.1 302 Found\nLocation: https://other.example/authorize?<any>",
            false,
        ),
        (
            "rewrite-request",
            format!("{TOKEN}&redirect_uri=https://idp.example/cb"),
            "HTTP/1.1 200 OK",
            true,
        ),
    ] {
        // Given: an independent real exchange; no state is carried between rows.
        let mut tail = exchange(&request, response);
        if name == "rewrite-request" {
            tail.push_str(&fence(
                "http,case=X,upstream",
                "POST /custom/token\n\nredirect_uri=http://localhost:<any>/cb",
            ));
        }
        let cases = parse_cases(&document(&tail))?;
        // When: run through the framework listener and loopback IdP.
        let result = run_case(cases.first().context("case")?, &identity).await;
        // Then: the documented response and request semantics agree.
        ensure!(result.is_ok() == passes, "{name}: {result:?}");
    }
    Ok(())
}

/// Repeated case IDs never let one exchange borrow an earlier or later IdP request.
// cancel-safe: case-owned listeners and requests drop on every outcome.
#[tokio::test]
async fn upstream_table_rejects_when_recording_belongs_to_another_exchange() -> anyhow::Result<()> {
    let identity = spawn_blocking(Identity::generate).await??;
    for (name, second, expected, passes) in [
        (
            "current",
            TOKEN.replace("first-code", "second-code"),
            "second-code",
            true,
        ),
        (
            "earlier",
            TOKEN.replace("first-code", "second-code"),
            "first-code",
            false,
        ),
        (
            "absent",
            "POST /mcp HTTP/1.1\nHost: mcp.example".to_owned(),
            "first-code",
            false,
        ),
    ] {
        // Given: the same case ID occurs in multiple independent exchanges.
        let status = if name == "absent" {
            "HTTP/1.1 401 Unauthorized"
        } else {
            "HTTP/1.1 200 OK"
        };
        let tail = format!(
            "{}{}{}{}",
            exchange(TOKEN, "HTTP/1.1 200 OK"),
            fence(
                "http,case=X,upstream",
                "POST /custom/token\n\ncode=first-code"
            ),
            exchange(&second, status),
            fence(
                "http,case=X,upstream",
                &format!("POST /custom/token\n\ncode={expected}")
            )
        );
        let cases = parse_cases(&document(&tail))?;
        // When: execute every exchange in document order.
        let result = run_case(cases.first().context("case")?, &identity).await;
        // Then: each assertion sees only requests made during its own exchange.
        ensure!(result.is_ok() == passes, "{name}: {result:?}");
    }
    Ok(())
}
