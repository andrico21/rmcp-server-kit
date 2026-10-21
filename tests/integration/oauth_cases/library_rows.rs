//! Generated library-call rows: each rule gets accepted and rejected executed variants.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::fixtures::{CONFIG, TOKEN, exchange, fence};

const EXCHANGE_TABLE: &str = "\n[server.auth.oauth.token_exchange]\ntoken_url='https://idp.example/custom/exchange'\nclient_id='mcp-example'\nclient_secret='case-test-exchange-secret'\naudience='downstream-api'";
const CALL: &str = "oauth::exchange_token(&http, &exchange, subject.expose_secret()).await?;";
const UPSTREAM: &str = "POST /custom/exchange\nAuthorization: Basic <any>\n\ngrant_type=urn:ietf:params:oauth:grant-type:token-exchange\nsubject_token=subject-token\nsubject_token_type=urn:ietf:params:oauth:token-type:access_token\nrequested_token_type=urn:ietf:params:oauth:token-type:access_token\naudience=downstream-api";

pub(super) struct Row {
    pub rule: &'static str,
    pub config: String,
    pub exchanges: String,
    pub passes: bool,
    pub needle: String,
}

fn config() -> String {
    format!("{CONFIG}{EXCHANGE_TABLE}")
}

fn library(snippet: &str, upstream: &str) -> String {
    format!(
        "{}{}",
        fence("rust,ignore", snippet),
        fence("http,case=X,upstream", upstream)
    )
}

fn row(rule: &'static str, exchanges: String, passes: bool, needle: &str) -> Row {
    Row {
        rule,
        config: config(),
        exchanges,
        passes,
        needle: needle.to_owned(),
    }
}

/// Every `oauth::` path form crossed with supported and unsupported function names.
fn function_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    for prefix in ["oauth::", "rmcp_server_kit::oauth::", ""] {
        for name in ["exchange_token", "exchange_token_with_cancel", "introspect"] {
            let passes = !prefix.is_empty() && name == "exchange_token";
            let needle = if prefix.is_empty() {
                "exactly one".to_owned()
            } else {
                format!("unsupported library function `oauth::{name}`")
            };
            let snippet =
                format!("let downstream = {prefix}{name}(&http, &exchange, token).await?;");
            rows.push(row(
                "function-name",
                library(&snippet, UPSTREAM),
                passes,
                &needle,
            ));
        }
    }
    rows.push(row(
        "function-name",
        library(&format!("{CALL}\n{CALL}"), UPSTREAM),
        false,
        "exactly one",
    ));
    rows.push(row(
        "function-name",
        library(
            &format!("let http: oauth::OauthHttpClient = oauth::OauthHttpClient::with_config(&config)?;\n{CALL}"),
            UPSTREAM,
        ),
        true,
        "",
    ));
    rows
}

/// One accepted minimal fence per documented upstream line and one drift of that line.
fn upstream_rows() -> Vec<Row> {
    let (target, rest) = UPSTREAM.split_once('\n').unwrap_or((UPSTREAM, ""));
    let (headers, form) = rest.split_once("\n\n").unwrap_or((rest, ""));
    let mut rows = vec![
        row("upstream-target", library(CALL, target), true, ""),
        row("upstream-target", library(CALL, UPSTREAM), true, ""),
    ];
    for drift in ["GET /custom/exchange", "POST /custom/other"] {
        let fence = UPSTREAM.replacen(target, drift, 1);
        rows.push(row(
            "upstream-target",
            library(CALL, &fence),
            false,
            "upstream request mismatch",
        ));
    }
    for header in headers.lines() {
        let drift = header.replace("Basic", "Bearer");
        for (line, passes) in [(header.to_owned(), true), (drift, false)] {
            let needle = if passes {
                ""
            } else {
                "upstream request mismatch"
            };
            rows.push(row(
                "upstream-header",
                library(CALL, &format!("{target}\n{line}")),
                passes,
                needle,
            ));
        }
    }
    for field in form.lines().chain(["resource=<any>"]) {
        let rule = if field.starts_with("subject_token=") {
            "subject-token"
        } else {
            "upstream-form"
        };
        let present = field != "resource=<any>";
        let drift = format!("{field}-drift");
        for (line, passes) in [(field.to_owned(), present), (drift, false)] {
            let needle = if passes {
                ""
            } else {
                "upstream request mismatch"
            };
            rows.push(row(
                rule,
                library(CALL, &format!("{target}\n\n{line}")),
                passes,
                needle,
            ));
        }
    }
    rows
}

/// Client authentication is exact HTTP Basic, and the secret-holding form omits `client_id`.
fn client_rows() -> Vec<Row> {
    let basic = |secret: &str| STANDARD.encode(format!("mcp-example:{secret}"));
    let target = "POST /custom/exchange";
    vec![
        row(
            "client-auth",
            library(
                CALL,
                &format!(
                    "{target}\nAuthorization: Basic {}",
                    basic("case-test-exchange-secret")
                ),
            ),
            true,
            "",
        ),
        row(
            "client-auth",
            library(
                CALL,
                &format!("{target}\nAuthorization: Basic {}", basic("other-secret")),
            ),
            false,
            "upstream request mismatch",
        ),
        row(
            "client-auth",
            library(CALL, &format!("{target}\n\nclient_id=<any>")),
            false,
            "upstream request mismatch",
        ),
    ]
}

/// Library calls require their table, and recordings never cross exchange boundaries.
fn isolation_rows() -> Vec<Row> {
    let unauthorized = exchange(
        "POST /mcp HTTP/1.1\nHost: mcp.example",
        "HTTP/1.1 401 Unauthorized",
    );
    let leaked = fence(
        "http,case=X,upstream",
        "POST /custom/exchange\n\nsubject_token=subject-token",
    );
    let shared = config().replace("/custom/token", "/custom/exchange");
    let token = exchange(TOKEN, "HTTP/1.1 200 OK");
    let mut rows = vec![
        row(
            "exchange-local",
            format!("{unauthorized}{}", library(CALL, UPSTREAM)),
            true,
            "",
        ),
        row(
            "exchange-local",
            format!("{}{unauthorized}{leaked}", library(CALL, UPSTREAM)),
            false,
            "exchange 2",
        ),
    ];
    for (expected, passes) in [
        ("subject_token=subject-token", true),
        ("code=first-code", false),
    ] {
        rows.push(Row {
            rule: "exchange-local",
            config: shared.clone(),
            exchanges: format!(
                "{token}{}",
                library(CALL, &format!("POST /custom/exchange\n\n{expected}"))
            ),
            passes,
            needle: if passes {
                String::new()
            } else {
                "exchange 2".to_owned()
            },
        });
    }
    for (config, passes) in [(config(), true), (CONFIG.to_owned(), false)] {
        rows.push(Row {
            rule: "requires-config",
            config,
            exchanges: library(CALL, UPSTREAM),
            passes,
            needle: if passes {
                String::new()
            } else {
                "token_exchange".to_owned()
            },
        });
    }
    rows
}

/// Every generated row family, in execution order.
pub(super) fn rows() -> [Vec<Row>; 4] {
    [
        function_rows(),
        upstream_rows(),
        client_rows(),
        isolation_rows(),
    ]
}
