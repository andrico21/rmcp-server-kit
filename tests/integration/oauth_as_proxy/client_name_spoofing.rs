//! Display-name spoofing characters at registration and name isolation on the consent page.

use core::slice::from_ref;

use super::*;

/// Reference model: every rejected code point range, inclusive, as written in the policy.
const RANGES: [(u32, u32); 9] = [
    (0x061C, 0x061C),
    (0x200E, 0x200F),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
    (0x200B, 0x200D),
    (0x2060, 0x2064),
    (0xFEFF, 0xFEFF),
    (0x00AD, 0x00AD),
    (0x2028, 0x2029),
];

/// Whether the reference model rejects this code point.
fn in_ranges(code: u32) -> bool {
    RANGES.iter().any(|(lo, hi)| (*lo..=*hi).contains(&code))
}

/// Every rejected character, derived from the range definitions.
fn rejected_chars() -> Vec<char> {
    RANGES
        .iter()
        .flat_map(|(lo, hi)| *lo..=*hi)
        .filter_map(char::from_u32)
        .collect()
}

/// The characters just below and above each rejected range that are not rejected themselves,
/// plus a fixed set of legal look-alikes.
fn outside_chars() -> Vec<char> {
    let mut codes: Vec<u32> = RANGES
        .iter()
        .flat_map(|(lo, hi)| [lo.saturating_sub(1), hi.saturating_add(1)])
        .filter(|code| !in_ranges(*code))
        .collect();
    codes.extend([
        0x2058, 0x2065, 0x202F, 0x200A, 0x2027, 0xFEFE, 0xFF00, 0x061B, 0x00AC, 0x00AE, 0x2070,
        0x2010, 0x061D, 0x205F, 0x206A,
    ]);
    codes.sort_unstable();
    codes.dedup();
    codes.into_iter().filter_map(char::from_u32).collect()
}

/// One character of each range group, used where a full sweep is not needed.
const GROUP_SAMPLES: [char; 4] = ['\u{061C}', '\u{202E}', '\u{2066}', '\u{200B}'];

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
        html.contains("<p>An unnamed application</p>") && !html.contains("<bdi>"),
        "fallback unchanged"
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
    for ch in GROUP_SAMPLES {
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
    for ch in ['\u{202E}', '\u{2066}', '\u{200B}', '\u{FEFF}', '\u{0007}'] {
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
        for ch in GROUP_SAMPLES {
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
        for ch in GROUP_SAMPLES {
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
        for ch in GROUP_SAMPLES {
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
