//! Display-name spoofing characters at registration and name isolation on the consent page.

use core::slice::from_ref;

use super::*;

/// Reference model: every rejected code point range, inclusive, as written in the policy.
const RANGES: [(u32, u32); 23] = [
    (0x061C, 0x061C),
    (0x200E, 0x200F),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
    (0x200B, 0x200D),
    (0x2060, 0x2064),
    (0xFEFF, 0xFEFF),
    (0x00AD, 0x00AD),
    (0x2028, 0x2029),
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x2065, 0x2065),
    (0x206A, 0x206F),
    (0x2800, 0x2800),
    (0x3164, 0x3164),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE00FF),
    (0xE01F0, 0xE0FFF),
];

/// Whether the reference model rejects this code point.
fn in_ranges(code: u32) -> bool {
    RANGES.iter().any(|(lo, hi)| (*lo..=*hi).contains(&code))
}

/// Every rejected character for the HTTP sweeps: every code point of a range with at most 32
/// members, and only the first, middle and last code point of a larger range.
fn rejected_chars() -> Vec<char> {
    RANGES
        .iter()
        .flat_map(|(lo, hi)| {
            let codes: Vec<u32> = if hi.saturating_sub(*lo) < 32 {
                (*lo..=*hi).collect()
            } else {
                vec![*lo, lo.midpoint(*hi), *hi]
            };
            codes
        })
        .filter_map(char::from_u32)
        .collect()
}

/// The characters just below and above each rejected range that are not rejected themselves,
/// plus legal look-alikes and the variation selectors that emoji sequences need.
fn outside_chars() -> Vec<char> {
    let mut codes: Vec<u32> = RANGES
        .iter()
        .flat_map(|(lo, hi)| [lo.saturating_sub(1), hi.saturating_add(1)])
        .filter(|code| !in_ranges(*code))
        .collect();
    codes.extend([
        0x2058, 0x202F, 0x200A, 0x2027, 0xFEFE, 0xFF00, 0x061B, 0x00AC, 0x00AE, 0x2070, 0x2010,
        0x061D, 0x205F, 0xFE00, 0xFE0E, 0xFE0F, 0xE0100, 0xE01EF, 0x2764, 0x1F680,
    ]);
    codes.sort_unstable();
    codes.dedup();
    codes.into_iter().filter_map(char::from_u32).collect()
}

/// The first and last code point of every rejected range, used where a full sweep is not needed.
fn range_samples() -> Vec<char> {
    let mut codes: Vec<u32> = RANGES.iter().flat_map(|(lo, hi)| [*lo, *hi]).collect();
    codes.sort_unstable();
    codes.dedup();
    codes.into_iter().filter_map(char::from_u32).collect()
}

/// A 128-character name with `ch` at character index `index`, filler elsewhere.
fn name_with_at(ch: char, index: usize) -> String {
    (0..128)
        .map(|i| if i == index { ch } else { 'x' })
        .collect()
}

/// Character indexes probed in a 128-character name: first, second, middle, penultimate, last.
const NAME_POSITIONS: [usize; 5] = [0, 1, 64, 126, 127];

/// Post a raw registration document and return the status with the body text.
async fn post_registration(server: &Harness, input: &Value) -> anyhow::Result<(u16, String)> {
    let response = server
        .client
        .post(format!("{}/register", server.base))
        .json(input)
        .send()
        .await?;
    let status = response.status().as_u16();
    Ok((status, response.text().await?))
}

/// Every invisible or bidirectional name character is rejected at every probed position.
#[tokio::test]
async fn registration_rejects_invisible_and_bidirectional_name_characters() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for ch in rejected_chars() {
        for index in NAME_POSITIONS {
            let name = name_with_at(ch, index);
            // When
            let (status, body) = post_registration(
                &server,
                &json!({"redirect_uris":[CALLBACK],"client_name":name}),
            )
            .await?;
            // Then
            ensure!(
                status == 400,
                "U+{:04X} at index {index} rejected, got {status}",
                u32::from(ch)
            );
            let parsed: Value = serde_json::from_str(&body)?;
            ensure!(
                parsed.get("error") == Some(&json!("invalid_client_metadata")),
                "U+{:04X} at index {index} error code",
                u32::from(ch)
            );
            ensure!(
                !body.contains(ch) && !body.contains(&format!("\\u{:04x}", u32::from(ch))),
                "U+{:04X} is not echoed",
                u32::from(ch)
            );
        }
    }
    server.close().await
}

/// A name made only of one rejected character is rejected as well as an embedded one.
#[tokio::test]
async fn registration_rejects_a_name_that_is_only_a_spoofing_character() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    // When
    let (status, _) = post_registration(
        &server,
        &json!({"redirect_uris":[CALLBACK],"client_name":"\u{202e}"}),
    )
    .await?;
    // Then
    ensure!(status == 400, "lone override rejected");
    server.close().await
}

/// The characters adjacent to each rejected range remain legal in names at any position.
#[tokio::test]
async fn registration_accepts_characters_adjacent_to_the_rejected_ranges() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for ch in outside_chars() {
        for index in [0, 1, 127] {
            let name = name_with_at(ch, index);
            // When
            let (status, body) = post_registration(
                &server,
                &json!({"redirect_uris":[CALLBACK],"client_name":name}),
            )
            .await?;
            // Then
            ensure!(
                status == 201,
                "U+{:04X} at index {index} accepted, got {status}",
                u32::from(ch)
            );
            let parsed: Value = serde_json::from_str(&body)?;
            ensure!(
                parsed.get("client_name") == Some(&json!(name)),
                "U+{:04X} survives the response",
                u32::from(ch)
            );
        }
    }
    server.close().await
}

/// Ordinary names in several scripts, including right-to-left ones, still register.
#[tokio::test]
async fn registration_accepts_ordinary_names_in_every_script() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for name in [
        "Plain ASCII client",
        "Caf\u{e9} \u{c5}ngstr\u{f6}m",
        "\u{65e5}\u{672c}\u{8a9e}\u{30af}\u{30e9}\u{30a4}\u{30a2}\u{30f3}\u{30c8}",
        "\u{62a}\u{637}\u{628}\u{64a}\u{642} \u{627}\u{644}\u{639}\u{645}\u{64a}\u{644}",
        "\u{5d0}\u{5e4}\u{5dc}\u{5d9}\u{5e7}\u{5e6}\u{5d9}\u{5d4} \u{5e2}\u{5d1}\u{5e8}\u{5d9}\u{5ea}",
        "Rocket \u{1F680} client",
    ] {
        // When
        let (status, body) = post_registration(
            &server,
            &json!({"redirect_uris":[CALLBACK],"client_name":name}),
        )
        .await?;
        // Then
        ensure!(status == 201, "ordinary name accepted: {name}");
        let parsed: Value = serde_json::from_str(&body)?;
        ensure!(
            parsed.get("client_name") == Some(&json!(name)),
            "name returned unchanged: {name}"
        );
    }
    server.close().await
}

/// An emoji sequence joined by a zero-width joiner is rejected as a documented trade-off.
#[tokio::test]
async fn registration_rejects_joiner_emoji_sequences() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    // When
    let (status, _) = post_registration(
        &server,
        &json!({"redirect_uris":[CALLBACK],"client_name":"family \u{1F468}\u{200D}\u{1F469}"}),
    )
    .await?;
    // Then
    ensure!(status == 400, "joiner sequence rejected");
    server.close().await
}

/// The consent page isolates an Arabic name and keeps the marker outside the isolate.
#[tokio::test]
async fn consent_page_isolates_a_right_to_left_name_from_the_marker() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let name = "\u{62a}\u{637}\u{628}\u{64a}\u{642} \u{627}\u{644}\u{639}\u{645}\u{64a}\u{644}";
    let cid = server.register(name).await?;
    // When
    let html = server.page(&cid).await?.text().await?;
    // Then
    let expected = format!("<bdi>{name}</bdi> (name supplied by the application, not verified)");
    ensure!(html.contains(&expected), "exact isolated fragment");
    ensure!(
        html.contains(&format!("<p>{expected}</p>")),
        "fragment fills its own paragraph"
    );
    server.close().await
}

/// A registration without a name keeps the unnamed fallback and no isolate.
#[tokio::test]
async fn consent_page_without_a_name_keeps_the_unnamed_fallback() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let (status, body) = post_registration(&server, &json!({"redirect_uris":[CALLBACK]})).await?;
    ensure!(status == 201, "nameless registration");
    let registration: Value = serde_json::from_str(&body)?;
    let cid = registration
        .get("client_id")
        .and_then(Value::as_str)
        .context("client id")?;
    // When
    let html = server.page(cid).await?.text().await?;
    // Then
    ensure!(
        html.contains("<p>An unnamed application</p>"),
        "fallback unchanged"
    );
    let paragraph = html
        .split("<p>An unnamed application")
        .nth(1)
        .and_then(|rest| rest.split("</p>").next())
        .context("fallback paragraph")?;
    ensure!(
        !paragraph.contains("<bdi>"),
        "fallback paragraph has no isolate"
    );
    ensure!(
        html.contains("<bdi>http://127.0.0.1:18999/cb?original=1</bdi>")
            && html.contains("<bdi><strong>127.0.0.1</strong></bdi>"),
        "redirect URI and host are isolated even without a name"
    );
    server.close().await
}

/// Markup in a name stays escaped inside the isolate.
#[tokio::test]
async fn consent_page_escapes_markup_inside_the_name_isolate() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for (name, escaped) in [
        ("<img/src=x>", "&lt;img/src=x&gt;"),
        ("fish & chips", "fish &amp; chips"),
        ("it's", "it&#39;s"),
        ("say \"hi\"", "say &quot;hi&quot;"),
        ("<img/src=x>&'\"", "&lt;img/src=x&gt;&amp;&#39;&quot;"),
    ] {
        let cid = server.register(name).await?;
        // When
        let html = server.page(&cid).await?.text().await?;
        // Then
        let expected =
            format!("<bdi>{escaped}</bdi> (name supplied by the application, not verified)");
        ensure!(html.contains(&expected), "escaped inside isolate: {name}");
        ensure!(!html.contains("<img/src=x>"), "no injected element");
    }
    server.close().await
}

/// Scope tokens cannot carry bidirectional or invisible characters.
#[tokio::test]
async fn authorize_rejects_spoofing_characters_in_scope_tokens() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let cid = server.register("Scope spoofing fixture").await?;
    for ch in ['\u{202E}', '\u{2066}', '\u{200B}', '\u{061C}'] {
        let scope = format!("mcp:read{ch}admin");
        let mut pairs = Harness::params(&cid);
        pairs.retain(|(key, _)| *key != "scope");
        pairs.push(("scope", scope.as_str()));
        // When
        let response = server.authorize(&pairs, None).await?;
        // Then
        ensure!(
            response.status() == 302,
            "U+{:04X} scope is a protocol error redirect",
            u32::from(ch)
        );
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .context("location")?
            .to_owned();
        ensure!(
            location.contains("error=") && !location.contains("code="),
            "protocol error without a code for U+{:04X}",
            u32::from(ch)
        );
    }
    server.close().await
}

/// A redirect URI cannot carry bidirectional or invisible characters in host or path.
#[tokio::test]
async fn registration_rejects_spoofing_characters_in_redirect_uris() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for uri in [
        "https://exa\u{202E}mple.test/cb",
        "https://example.test/c\u{202E}b",
        "https://example.test/cb?x=\u{2066}y",
        "https://example.test/cb?x=y#\u{200B}",
        "https://example.\u{200B}test/cb",
        "https://example.test/\u{FEFF}cb",
    ] {
        // When
        let (status, body) = post_registration(
            &server,
            &json!({"redirect_uris":[uri],"client_name":"Redirect spoofing fixture"}),
        )
        .await?;
        // Then
        ensure!(status == 400, "redirect URI rejected: {uri:?}");
        ensure!(
            body.contains("invalid_redirect_uri"),
            "redirect error code: {uri:?}"
        );
    }
    server.close().await
}

/// A spoofing character in any of three redirect URIs rejects the registration.
#[tokio::test]
async fn registration_rejects_spoofing_characters_at_every_redirect_uri_position()
-> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let clean = [
        "https://example.test/first",
        "https://example.test/second",
        "https://example.test/third",
    ];
    for ch in range_samples() {
        for position in 0..clean.len() {
            let uris: Vec<String> = clean
                .iter()
                .enumerate()
                .map(|(i, uri)| {
                    if i == position {
                        format!("{uri}{ch}tail")
                    } else {
                        (*uri).to_owned()
                    }
                })
                .collect();
            // When
            let (status, body) = post_registration(
                &server,
                &json!({"redirect_uris":uris,"client_name":"Multi URI fixture"}),
            )
            .await?;
            // Then
            ensure!(
                status == 400,
                "U+{:04X} in URI {position} rejected, got {status}",
                u32::from(ch)
            );
            ensure!(
                body.contains("invalid_redirect_uri"),
                "U+{:04X} in URI {position} error code",
                u32::from(ch)
            );
        }
    }
    // Control: all-clean URIs register.
    let (status, _) = post_registration(
        &server,
        &json!({"redirect_uris":clean,"client_name":"Multi URI fixture"}),
    )
    .await?;
    ensure!(status == 201, "clean multi-URI registration accepted");
    server.close().await
}

/// The passthrough registration stub stays byte-identical for spoofing names.
#[tokio::test]
async fn passthrough_registration_echoes_spoofing_names_unchanged() -> anyhow::Result<()> {
    // Given
    let server = Harness::start_mode("30days", "passthrough").await?;
    for ch in [
        '\u{202E}',
        '\u{2066}',
        '\u{200B}',
        '\u{FEFF}',
        '\u{0007}',
        '\u{3164}',
        '\u{034F}',
        '\u{2065}',
        '\u{E0001}',
        '\u{FFF9}',
    ] {
        let name = format!("lead{ch}tail");
        // When
        let (status, body) = post_registration(
            &server,
            &json!({"redirect_uris":[CALLBACK],"client_name":name}),
        )
        .await?;
        // Then
        ensure!(
            status == 200,
            "passthrough status for U+{:04X}: {status}",
            u32::from(ch)
        );
        let parsed: Value = serde_json::from_str(&body)?;
        let expected = json!({
            "client_id":"static-upstream","token_endpoint_auth_method":"none",
            "redirect_uris":[CALLBACK],"client_name":name
        });
        ensure!(
            parsed == expected,
            "passthrough body for U+{:04X}: {body}",
            u32::from(ch)
        );
    }
    server.close().await
}

/// The `client_name` shapes a registration can take: absent, clean and empty.
const NAME_SHAPES: [Option<&str>; 3] = [None, Some("Clean fixture name"), Some("")];

/// A registration document with the optional metadata fields selected by the low three bits of `mask`.
fn registration_with(uris: &[String], name: Option<&str>, mask: u8) -> Value {
    let mut doc = json!({"redirect_uris": uris});
    if let Some(object) = doc.as_object_mut() {
        if let Some(client_name) = name {
            drop(object.insert("client_name".into(), json!(client_name)));
        }
        if mask & 1 != 0 {
            drop(object.insert("grant_types".into(), json!(["authorization_code"])));
        }
        if mask & 2 != 0 {
            drop(object.insert("scope".into(), json!("mcp:read")));
        }
        if mask & 4 != 0 {
            drop(object.insert("token_endpoint_auth_method".into(), json!("none")));
        }
    }
    doc
}

/// The exact body of an invalid redirect URI rejection.
fn exact_redirect_error() -> Value {
    json!({"error":"invalid_redirect_uri","error_description":"Invalid client registration metadata"})
}

/// Redirect URI spoofing is rejected for every name shape, character group and URI position.
#[tokio::test]
async fn registration_rejects_redirect_spoofing_for_every_name_shape_and_position()
-> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let clean = [
        "https://example.test/first",
        "https://example.test/second",
        "https://example.test/third",
    ];
    for name in NAME_SHAPES {
        // Control: clean URIs register for this name shape.
        for uris in [&clean[..], &clean[..1]] {
            let owned: Vec<String> = uris.iter().map(|uri| (*uri).to_owned()).collect();
            // When
            let (status, _) =
                post_registration(&server, &registration_with(&owned, name, 0)).await?;
            // Then
            ensure!(
                status == 201,
                "clean control accepted for name {name:?}, {} URIs, got {status}",
                owned.len()
            );
        }
        for ch in range_samples() {
            for (count, position) in [(1, 0), (3, 0), (3, 1), (3, 2)] {
                let uris: Vec<String> = clean
                    .iter()
                    .take(count)
                    .enumerate()
                    .map(|(i, uri)| {
                        if i == position {
                            format!("{uri}{ch}tail")
                        } else {
                            (*uri).to_owned()
                        }
                    })
                    .collect();
                // When
                let (status, body) =
                    post_registration(&server, &registration_with(&uris, name, 0)).await?;
                // Then
                ensure!(
                    status == 400,
                    "U+{:04X} in URI {position} of {count} rejected for name {name:?}, got {status}",
                    u32::from(ch)
                );
                let parsed: Value = serde_json::from_str(&body)?;
                ensure!(
                    parsed == exact_redirect_error(),
                    "exact body for U+{:04X} in URI {position} of {count}, name {name:?}: {body}",
                    u32::from(ch)
                );
            }
        }
    }
    server.close().await
}

/// A name-less registration rejects redirect spoofing whichever optional metadata accompanies it.
#[tokio::test]
async fn nameless_registration_rejects_redirect_spoofing_with_any_optional_metadata()
-> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for mask in 0..8_u8 {
        let clean = vec!["https://example.test/ok".to_owned()];
        // When
        let (control_status, _) =
            post_registration(&server, &registration_with(&clean, None, mask)).await?;
        // Then
        ensure!(
            control_status == 201,
            "clean name-less control, mask {mask}: {control_status}"
        );
        for ch in range_samples() {
            let uris = vec![
                "https://example.test/a".to_owned(),
                format!("https://example.test/b{ch}"),
            ];
            // When
            let (status, body) =
                post_registration(&server, &registration_with(&uris, None, mask)).await?;
            // Then
            ensure!(
                status == 400,
                "U+{:04X} rejected with metadata mask {mask}, got {status}",
                u32::from(ch)
            );
            let parsed: Value = serde_json::from_str(&body)?;
            ensure!(
                parsed == exact_redirect_error(),
                "exact body with metadata mask {mask}: {body}"
            );
        }
    }
    server.close().await
}

/// One redirect URI shape: authority, path, optional query and fragment, and an optional exact total size.
struct UriShape {
    label: &'static str,
    authority: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    fragment: Option<&'static str>,
    total: Option<usize>,
    accepted: bool,
}

/// The redirect URI shapes a native or web client registers, from short to the 512-byte bound.
const URI_SHAPES: [UriShape; 12] = [
    UriShape {
        label: "https short",
        authority: "https://example.test",
        path: "/cb",
        query: None,
        fragment: None,
        total: None,
        accepted: true,
    },
    UriShape {
        label: "https over 40 bytes",
        authority: "https://callbacks.example.test",
        path: "/oauth/return/handler/with/a/long/path",
        query: None,
        fragment: None,
        total: None,
        accepted: true,
    },
    UriShape {
        label: "https over 100 bytes",
        authority: "https://callbacks.example.test",
        path: "/oauth/return/handler/with/a/very/long/path/that/keeps/going/and/going/until/it/clearly/passes/one/hundred",
        query: None,
        fragment: None,
        total: None,
        accepted: true,
    },
    UriShape {
        label: "http localhost",
        authority: "http://localhost",
        path: "/cb",
        query: None,
        fragment: None,
        total: None,
        accepted: true,
    },
    UriShape {
        label: "http ipv4 loopback with port",
        authority: "http://127.0.0.1:18999",
        path: "/cb",
        query: None,
        fragment: None,
        total: None,
        accepted: true,
    },
    UriShape {
        label: "http ipv6 loopback with port",
        authority: "http://[::1]:18999",
        path: "/cb",
        query: None,
        fragment: None,
        total: None,
        accepted: true,
    },
    UriShape {
        label: "https with explicit port",
        authority: "https://example.test:8443",
        path: "/cb",
        query: None,
        fragment: None,
        total: None,
        accepted: true,
    },
    UriShape {
        label: "https with query",
        authority: "https://example.test",
        path: "/cb",
        query: Some("state=abcdef&mode=web"),
        fragment: None,
        total: None,
        accepted: true,
    },
    UriShape {
        label: "https with query and fragment",
        authority: "https://example.test",
        path: "/cb",
        query: Some("state=abcdef&mode=web"),
        fragment: Some("section-two"),
        total: None,
        accepted: false,
    },
    UriShape {
        label: "https multi-segment path",
        authority: "https://example.test",
        path: "/one/two/three/four/five/six/seven",
        query: None,
        fragment: None,
        total: None,
        accepted: true,
    },
    UriShape {
        label: "https exactly 512 bytes",
        authority: "https://example.test",
        path: "",
        query: None,
        fragment: None,
        total: Some(512),
        accepted: true,
    },
    UriShape {
        label: "http loopback exactly 512 bytes",
        authority: "http://127.0.0.1:18999",
        path: "",
        query: None,
        fragment: None,
        total: Some(512),
        accepted: true,
    },
];

impl UriShape {
    /// The path, padded so that the URI plus `extra` further bytes is exactly the shape's total size.
    fn path_with(&self, extra: usize) -> String {
        self.total.map_or_else(
            || self.path.to_owned(),
            |total| {
                let used = self.authority.len().saturating_add(1).saturating_add(extra);
                format!("/{}", "a".repeat(total.saturating_sub(used)))
            },
        )
    }

    /// The clean URI, `extra` bytes short of the shape's total size when it has one.
    fn clean(&self, extra: usize) -> String {
        let query = self
            .query
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        let fragment = self
            .fragment
            .map(|frag| format!("#{frag}"))
            .unwrap_or_default();
        [self.authority, &self.path_with(extra), &query, &fragment].concat()
    }

    /// Variants with `ch` inserted at host end, path start, path middle, last path byte, query and fragment.
    fn spoofed(&self, ch: char) -> Vec<(&'static str, String)> {
        let width = ch.len_utf8();
        let path = self.path_with(width);
        let query = self.query.unwrap_or_default();
        let fragment = self.fragment.unwrap_or_default();
        let query_sep = if query.is_empty() { "" } else { "?" };
        let fragment_sep = if fragment.is_empty() { "" } else { "#" };
        let insert = |text: &str, at: usize| -> String {
            let (head, tail) = text.split_at_checked(at).unwrap_or((text, ""));
            format!("{head}{ch}{tail}")
        };
        let join = |host: &str, tail: &str, qpart: &str, fpart: &str| -> String {
            [host, tail, query_sep, qpart, fragment_sep, fpart].concat()
        };
        let mut variants = vec![
            (
                "host end",
                join(
                    &insert(self.authority, self.authority.len()),
                    &path,
                    query,
                    fragment,
                ),
            ),
            (
                "path start",
                join(self.authority, &insert(&path, 1), query, fragment),
            ),
            (
                "path middle",
                join(
                    self.authority,
                    &insert(&path, path.len().midpoint(0)),
                    query,
                    fragment,
                ),
            ),
            (
                "path last byte",
                join(
                    self.authority,
                    &insert(&path, path.len().saturating_sub(1)),
                    query,
                    fragment,
                ),
            ),
        ];
        if !query.is_empty() {
            let at = query.len().midpoint(0);
            variants.push((
                "query",
                join(self.authority, &path, &insert(query, at), fragment),
            ));
        }
        if !fragment.is_empty() {
            let at = fragment.len().midpoint(0);
            variants.push((
                "fragment",
                join(self.authority, &path, query, &insert(fragment, at)),
            ));
        }
        variants
    }
}

/// Every URI shape registers cleanly, except those the policy rejects for carrying a fragment.
#[tokio::test]
async fn registration_accepts_clean_redirect_uris_of_every_shape() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for shape in &URI_SHAPES {
        for name in [None, Some("Shape control fixture")] {
            let uri = shape.clean(0);
            // When
            let (status, body) =
                post_registration(&server, &registration_with(from_ref(&uri), name, 0)).await?;
            // Then
            if shape.accepted {
                ensure!(
                    status == 201,
                    "{} accepted for name {name:?}, got {status}: {body}",
                    shape.label
                );
            } else {
                ensure!(
                    status == 400
                        && serde_json::from_str::<Value>(&body)? == exact_redirect_error(),
                    "{} rejected for its fragment: {status} {body}",
                    shape.label
                );
            }
        }
    }
    server.close().await
}

/// A clean URI one byte over the 512-byte bound is rejected and one byte under it is accepted.
#[tokio::test]
async fn registration_enforces_the_redirect_uri_size_bound_on_both_sides() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let shape = &URI_SHAPES[10];
    for (extra, expected) in [(1, 201), (0, 201), (usize::MAX, 0)] {
        if extra == usize::MAX {
            let over = format!("{}{}", shape.clean(0), "a");
            // When
            let (status, body) =
                post_registration(&server, &registration_with(&[over], None, 0)).await?;
            // Then
            ensure!(
                status == 400 && serde_json::from_str::<Value>(&body)? == exact_redirect_error(),
                "513-byte URI rejected: {status} {body}"
            );
        } else {
            let uri = shape.clean(extra);
            // When
            let (status, _) =
                post_registration(&server, &registration_with(&[uri], None, 0)).await?;
            // Then
            ensure!(status == expected, "bound control {extra}: {status}");
        }
    }
    server.close().await
}

/// A spoofing character is rejected in every URI shape at every position, with or without a client name.
#[tokio::test]
async fn registration_rejects_spoofing_characters_in_every_redirect_uri_shape() -> anyhow::Result<()>
{
    // Given
    let server = Harness::start("30days").await?;
    for shape in &URI_SHAPES {
        for ch in range_samples() {
            for (place, uri) in shape.spoofed(ch) {
                for name in [None, Some("Shape spoofing fixture")] {
                    // When
                    let (status, body) =
                        post_registration(&server, &registration_with(from_ref(&uri), name, 0))
                            .await?;
                    // Then
                    ensure!(
                        status == 400,
                        "{} with U+{:04X} at {place}, name {name:?}: {status}",
                        shape.label,
                        u32::from(ch)
                    );
                    ensure!(
                        serde_json::from_str::<Value>(&body)? == exact_redirect_error(),
                        "{} with U+{:04X} at {place}: exact body {body}",
                        shape.label,
                        u32::from(ch)
                    );
                }
            }
        }
    }
    server.close().await
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

/// The signing secret shared by every harness server.
const FIXTURE_SECRET: &str = "fixture-secret-with-at-least-32-bytes";

/// A client identifier sealed independently of the server, forged to model a client minted under looser rules.
fn sealed_client(uris: &[String], name: Option<&str>) -> anyhow::Result<String> {
    reference_seal(
        FIXTURE_SECRET,
        "client",
        &json!({"ru":uris,"n":name,"iat":1_700_000_000_u64}),
    )
}

/// Open `/authorize` for `uri` under client `cid` and return the status with the body text.
async fn authorize_uri(server: &Harness, cid: &str, uri: &str) -> anyhow::Result<(u16, String)> {
    let mut pairs = Harness::params(cid);
    pairs.retain(|(key, _)| *key != "redirect_uri");
    pairs.push(("redirect_uri", uri));
    let response = server.authorize(&pairs, None).await?;
    let status = response.status().as_u16();
    Ok((status, response.text().await?))
}

/// An emoji with a variation selector registers and is rendered inside the name isolate.
#[tokio::test]
async fn registration_accepts_an_emoji_with_a_variation_selector() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let name = "Heart \u{2764}\u{FE0F}";
    for sample in [name, "Tag \u{E0100} \u{FE00} \u{E01EF} \u{FE0E} end"] {
        // When
        let (status, body) = post_registration(
            &server,
            &json!({"redirect_uris":[CALLBACK],"client_name":sample}),
        )
        .await?;
        // Then
        ensure!(status == 201, "variation selectors accepted: {status}");
        let parsed: Value = serde_json::from_str(&body)?;
        ensure!(
            parsed.get("client_name") == Some(&json!(sample)),
            "name unchanged"
        );
    }
    let cid = server.register(name).await?;
    let html = server.page(&cid).await?.text().await?;
    ensure!(
        html.contains(&format!(
            "<p><bdi>{name}</bdi> (name supplied by the application, not verified)</p>"
        )),
        "rendered inside the isolate"
    );
    server.close().await
}

/// A sealed client whose redirect URI holds a rejected character never reaches the consent page.
#[tokio::test]
async fn authorize_rejects_a_sealed_client_with_a_spoofing_redirect_uri() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let clean = [
        "https://example.test/first",
        "http://127.0.0.1:18999/second?mode=web",
        "https://callbacks.example.test/oauth/return/handler/with/a/long/path",
    ];
    let clean_uris: Vec<String> = clean.iter().map(|uri| (*uri).to_owned()).collect();
    let control = sealed_client(&clean_uris, Some("Sealed control"))?;
    for uri in clean {
        // When
        let (status, html) = authorize_uri(&server, &control, uri).await?;
        // Then
        ensure!(
            status == 200 && html.contains("Authorize access"),
            "clean sealed client reaches consent for {uri}: {status}"
        );
    }
    for ch in range_samples() {
        for position in 0..clean.len() {
            let uris: Vec<String> = clean_uris
                .iter()
                .enumerate()
                .map(|(i, uri)| {
                    if i == position {
                        format!("{uri}{ch}")
                    } else {
                        uri.clone()
                    }
                })
                .collect();
            for name in [None, Some("Sealed spoofing fixture")] {
                let cid = sealed_client(&uris, name)?;
                for (index, candidate) in uris.iter().enumerate() {
                    // When
                    let (status, html) = authorize_uri(&server, &cid, candidate).await?;
                    // Then
                    if index == position {
                        ensure!(
                            status == 400
                                && html.contains("<h1>Authorization request rejected</h1>")
                                && !html.contains("Authorize access")
                                && !html.contains(ch),
                            "U+{:04X} in sealed URI {position} rejected, got {status}",
                            u32::from(ch)
                        );
                    } else {
                        ensure!(
                            status == 200 && html.contains("Authorize access"),
                            "clean sibling {index} of U+{:04X} in {position} still works: {status}",
                            u32::from(ch)
                        );
                    }
                }
            }
        }
    }
    server.close().await
}

/// The consent page isolates the redirect URI and its host for every accepted URI shape.
#[tokio::test]
async fn consent_page_isolates_the_redirect_uri_and_host_for_every_uri_shape() -> anyhow::Result<()>
{
    // Given
    let server = Harness::start("30days").await?;
    for shape in URI_SHAPES.iter().filter(|shape| shape.accepted) {
        let uri = shape.clean(0);
        let host = url::Url::parse(&uri)?
            .host_str()
            .context("host")?
            .to_owned();
        let cid = sealed_client(from_ref(&uri), None)?;
        // When
        let (status, html) = authorize_uri(&server, &cid, &uri).await?;
        // Then
        ensure!(status == 200, "{} consent page: {status}", shape.label);
        let expected = format!(
            "sent to: <bdi>{}</bdi> <bdi><strong>{}</strong></bdi></p>",
            escaped(&uri),
            escaped(&host)
        );
        ensure!(
            html.contains(&expected),
            "{} isolated fragment",
            shape.label
        );
    }
    server.close().await
}

/// Hostile characters in the redirect URI stay escaped inside the isolate and the name marker stays outside.
#[tokio::test]
async fn consent_page_escapes_hostile_redirect_uri_characters_inside_the_isolate()
-> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    for uri in [
        "https://example.test/cb?x=<img/src=x>&quote='\"",
        "https://ex&a'mple.test/cb?q=1&r=2",
        "https://example.test/a'b&c",
    ] {
        let host = url::Url::parse(uri)?.host_str().context("host")?.to_owned();
        let cid = sealed_client(&[uri.to_owned()], Some("Hostile URI fixture"))?;
        // When
        let (status, html) = authorize_uri(&server, &cid, uri).await?;
        // Then
        ensure!(status == 200, "hostile URI consent page: {status}");
        let expected = format!(
            "sent to: <bdi>{}</bdi> <bdi><strong>{}</strong></bdi></p>",
            escaped(uri),
            escaped(&host)
        );
        ensure!(html.contains(&expected), "escaped inside isolates: {uri}");
        ensure!(!html.contains("<img/src=x>"), "no injected element");
        ensure!(
            html.contains(
                "<p><bdi>Hostile URI fixture</bdi> (name supplied by the application, not verified)</p>"
            ),
            "marker stays outside the name isolate"
        );
    }
    server.close().await
}

/// A remembered approval for a sealed client does not let a spoofing redirect URI skip the check.
#[tokio::test]
async fn remembered_approval_does_not_bypass_redirect_uri_validation() -> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let clean = "https://example.test/first";
    for ch in range_samples() {
        let hostile = format!("https://example.test/second{ch}");
        let uris = vec![clean.to_owned(), hostile.clone()];
        let cid = sealed_client(&uris, Some("Remembered fixture"))?;
        let mut pairs = Harness::params(&cid);
        pairs.retain(|(key, _)| *key != "redirect_uri");
        pairs.push(("redirect_uri", clean));
        let (token, csrf) = consent_form(server.authorize(&pairs, None).await?).await?;
        let approved = server.decide(&token, &csrf, "approve").await?;
        let remembered = response_cookie(&approved, "rmcp_consent_")?;
        // When
        let control = server.authorize(&pairs, Some(&remembered)).await?;
        let mut spoofed = Harness::params(&cid);
        spoofed.retain(|(key, _)| *key != "redirect_uri");
        spoofed.push(("redirect_uri", hostile.as_str()));
        let response = server.authorize(&spoofed, Some(&remembered)).await?;
        // Then
        ensure!(control.status() == 302, "remembered clean URI redirects");
        ensure!(
            response.status() == 400 && !response.headers().contains_key("location"),
            "U+{:04X} URI rejected despite remembered approval: {}",
            u32::from(ch),
            response.status()
        );
    }
    server.close().await
}

/// What `/authorize` must answer for one request shape.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Answer {
    /// The consent page (HTTP 200).
    Page,
    /// A protocol error redirected to the registered URI (HTTP 302 with `error` and `iss`).
    Redirect,
    /// A nonredirecting error page (HTTP 400 without a `Location` header).
    Plain,
}

/// One way an authorization request can be defective, and what a clean client receives for it.
struct Defect {
    label: &'static str,
    /// Keys removed from the valid parameters.
    drop: &'static [&'static str],
    /// Pairs appended after removal.
    add: &'static [(&'static str, &'static str)],
    /// Whether the request targets a URI that no sealed entry holds.
    unmatched: bool,
    expected: Answer,
}

/// The authorization-request defects, each with the answer a clean sealed client receives.
const DEFECTS: [Defect; 15] = [
    Defect {
        label: "no defect",
        drop: &[],
        add: &[],
        unmatched: false,
        expected: Answer::Page,
    },
    Defect {
        label: "response_type token",
        drop: &["response_type"],
        add: &[("response_type", "token")],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "missing response_type",
        drop: &["response_type"],
        add: &[],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "missing code_challenge",
        drop: &["code_challenge"],
        add: &[],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "short code_challenge",
        drop: &["code_challenge"],
        add: &[("code_challenge", "short")],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "bad charset code_challenge",
        drop: &["code_challenge"],
        add: &[(
            "code_challenge",
            "abcdefghijklmnopqrstuvwxyz0123456789ABCDE!!",
        )],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "method plain",
        drop: &["code_challenge_method"],
        add: &[("code_challenge_method", "plain")],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "missing method",
        drop: &["code_challenge_method"],
        add: &[],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "duplicated state",
        drop: &[],
        add: &[("state", "second-state")],
        unmatched: false,
        expected: Answer::Plain,
    },
    Defect {
        label: "duplicated response_type",
        drop: &[],
        add: &[("response_type", "code")],
        unmatched: false,
        expected: Answer::Plain,
    },
    Defect {
        label: "unmatched redirect_uri",
        drop: &[],
        add: &[],
        unmatched: true,
        expected: Answer::Plain,
    },
    Defect {
        label: "long code_challenge",
        drop: &["code_challenge"],
        add: &[("code_challenge", LONG_CHALLENGE)],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "oversized state",
        drop: &["state"],
        add: &[("state", OVERSIZED)],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "oversized scope",
        drop: &["scope"],
        add: &[("scope", OVERSIZED)],
        unmatched: false,
        expected: Answer::Redirect,
    },
    Defect {
        label: "duplicated code_challenge_method",
        drop: &[],
        add: &[("code_challenge_method", "S256")],
        unmatched: false,
        expected: Answer::Plain,
    },
];

/// A 129-character challenge, one past the maximum.
const LONG_CHALLENGE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A 513-character value, one past the state and scope maximum.
const OVERSIZED: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

/// The sealed redirect URIs used by the defect table.
const DEFECT_URIS: [&str; 3] = [
    "https://example.test/first",
    "http://127.0.0.1:18999/second?mode=web",
    "https://callbacks.example.test/oauth/return/handler/with/a/long/path",
];

/// Send an authorization request for `uri` shaped by `defect` and classify the answer.
async fn classify(
    server: &Harness,
    cid: &str,
    uri: &str,
    defect: &Defect,
) -> anyhow::Result<(Answer, String)> {
    let target = if defect.unmatched {
        "https://unregistered.example.test/elsewhere"
    } else {
        uri
    };
    let mut pairs = Harness::params(cid);
    pairs.retain(|(key, _)| *key != "redirect_uri" && !defect.drop.contains(key));
    pairs.push(("redirect_uri", target));
    pairs.extend_from_slice(defect.add);
    let response = server.authorize(&pairs, None).await?;
    let status = response.status().as_u16();
    let location = response.headers().contains_key("location");
    let body = response.text().await?;
    let answer = match (status, location) {
        (200, false) => Answer::Page,
        (302, true) => Answer::Redirect,
        (400, false) => Answer::Plain,
        other => anyhow::bail!("{}: unexpected {other:?}", defect.label),
    };
    Ok((answer, body))
}

/// A protocol defect never turns a sealed spoofing redirect URI into a redirect target.
#[tokio::test]
async fn sealed_spoofing_redirect_uri_is_never_a_redirect_target_for_any_request_defect()
-> anyhow::Result<()> {
    // Given
    let server = Harness::start("30days").await?;
    let clean_uris: Vec<String> = DEFECT_URIS.iter().map(|uri| (*uri).to_owned()).collect();
    let control = sealed_client(&clean_uris, Some("Defect control"))?;
    for defect in &DEFECTS {
        for uri in DEFECT_URIS {
            // When
            let (answer, _) = classify(&server, &control, uri, defect).await?;
            // Then
            ensure!(
                answer == defect.expected,
                "clean sealed client, {}: {answer:?}",
                defect.label
            );
        }
    }
    for ch in range_samples() {
        for position in 0..DEFECT_URIS.len() {
            let uris: Vec<String> = clean_uris
                .iter()
                .enumerate()
                .map(|(i, uri)| {
                    if i == position {
                        format!("{uri}{ch}")
                    } else {
                        uri.clone()
                    }
                })
                .collect();
            let cid = sealed_client(&uris, Some("Defect spoofing fixture"))?;
            let hostile = uris.get(position).context("hostile URI")?;
            for defect in &DEFECTS {
                // When
                let (answer, body) = classify(&server, &cid, hostile, defect).await?;
                // Then
                ensure!(
                    answer == Answer::Plain && !body.contains(ch),
                    "U+{:04X} in sealed URI {position}, {}: {answer:?}",
                    u32::from(ch),
                    defect.label
                );
            }
        }
    }
    server.close().await
}
