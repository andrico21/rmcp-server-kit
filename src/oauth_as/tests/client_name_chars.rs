//! Spoofing-character classification and the sealed client name round trip.

use super::*;

/// Reference model: every rejected code point range, inclusive.
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
fn model_rejects(code: u32) -> bool {
    RANGES.iter().any(|(lo, hi)| (*lo..=*hi).contains(&code))
}

/// Every code point of every range is a spoofing character and the neighbours outside are not,
/// including the variation selector blocks that emoji sequences need.
#[test]
fn spoofing_classification_matches_each_range_edge() -> anyhow::Result<()> {
    // Given
    let outside: Vec<u32> = RANGES
        .iter()
        .flat_map(|(lo, hi)| [lo - 1, hi + 1])
        .filter(|code| !model_rejects(*code))
        .chain([
            0x2058, 0x202F, 0x200A, 0x2027, 0xFEFE, 0xFF00, 0x061B, 0x00AC, 0x00AE, 0x2070, 0x2010,
            0x061D, 0x205F, 0x062A, 0x05D0, 0x61, 0x20, 0xFE00, 0xFE0E, 0xFE0F, 0xE0100, 0xE01EF,
            0x2764, 0x1F680, 0x1F3F4,
        ])
        .collect();
    // When / Then
    for (lo, hi) in RANGES {
        for code in lo..=hi {
            let ch = char::from_u32(code).context("scalar value")?;
            ensure!(is_spoofing_char(ch), "U+{code:04X} is spoofing");
        }
    }
    for code in outside {
        let ch = char::from_u32(code).context("scalar value")?;
        ensure!(!is_spoofing_char(ch), "U+{code:04X} is legal");
    }
    Ok(())
}

/// Over the whole scalar value space the predicate agrees with the reference model.
#[test]
fn spoofing_classification_agrees_with_the_model_for_every_scalar_value() -> anyhow::Result<()> {
    // Given
    let scalars =
        (0..=0x0010_FFFF_u32).filter_map(|code| char::from_u32(code).map(|ch| (code, ch)));
    // When / Then
    for (code, ch) in scalars {
        ensure!(
            is_spoofing_char(ch) == model_rejects(code),
            "U+{code:04X} classification"
        );
    }
    Ok(())
}

/// The registration name rule accepts and rejects one sample of each class, and over the whole
/// scalar value space it rejects exactly the control and spoofing characters.
#[test]
fn client_name_rule_accepts_and_rejects_each_class() -> anyhow::Result<()> {
    // Given
    let accepted = [
        "Plain name".to_owned(),
        "\u{5E9}\u{5DC}\u{5D5}\u{5DD}".to_owned(),
        "Heart \u{2764}\u{FE0F}".to_owned(),
        "y".repeat(128),
        String::new(),
    ];
    let rejected = [
        "MarkerOne\u{202E}x".to_owned(),
        "MarkerTwo\u{200B}x".to_owned(),
        "MarkerThree\u{3164}x".to_owned(),
        "MarkerFour\u{E0041}x".to_owned(),
        "MarkerFive\u{7}x".to_owned(),
        "MarkerSix\u{2028}x".to_owned(),
        format!("MarkerSeven{}", "x".repeat(118)),
    ];
    // When / Then
    for name in &accepted {
        ensure!(client_name_allowed(name), "accepted: {name:?}");
    }
    for name in &rejected {
        ensure!(!client_name_allowed(name), "rejected: {name:?}");
    }
    for ch in '\0'..=char::MAX {
        let control_or_spoofing = ch.is_control() || is_spoofing_char(ch);
        ensure!(
            client_name_allowed(&format!("a{ch}b")) != control_or_spoofing,
            "U+{:04X} classification",
            u32::from(ch)
        );
    }
    Ok(())
}

/// A sealed client identifier returns the accepted Arabic name byte for byte.
#[tokio::test]
// cancel-safe: test body only; no state outlives an await.
async fn sealed_client_id_preserves_an_accepted_right_to_left_name() -> anyhow::Result<()> {
    // Given
    let state = Arc::new(state(false)?);
    let name = "\u{62a}\u{637}\u{628}\u{64a}\u{642} \u{627}\u{644}\u{639}\u{645}\u{64a}\u{644}";
    let body = serde_json::to_vec(&serde_json::json!({
        "redirect_uris":["https://client.example/return-arabic"],"client_name":name
    }))?;
    // When
    let response = register(State(Arc::clone(&state)), Bytes::from(body)).await;
    // Then
    ensure!(response.status() == StatusCode::CREATED, "registered");
    let bytes = to_bytes(response.into_body(), 0x8000).await?;
    let output: serde_json::Value = serde_json::from_slice(&bytes)?;
    let cid = output
        .get("client_id")
        .and_then(serde_json::Value::as_str)
        .context("client id")?;
    let opened: ClientReg = state.sealer.open(SealKind::Client, cid)?;
    ensure!(
        opened.name.as_deref().map(str::as_bytes) == Some(name.as_bytes()),
        "name preserved byte for byte"
    );
    Ok(())
}
