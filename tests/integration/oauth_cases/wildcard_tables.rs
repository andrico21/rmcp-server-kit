//! Exhaustive independent wildcard-language oracle.

use anyhow::ensure;

use super::compare::matches_value;

pub(super) const RULES: &[&str] = &["wildcard-backtracking"];

/// Wildcards preserve literal anchors and allow empty substrings at every position.
#[test]
fn values_match_when_wildcards_preserve_literal_anchors() -> anyhow::Result<()> {
    // Given: anchored patterns with wildcard positions and literal controls.
    for (pattern, actual, expected) in [
        ("<any>tail", "tail", true),
        ("<any>tail", "xtail", true),
        ("head<any>", "head", true),
        ("head<any>", "headx", true),
        ("a<any>b", "ab", true),
        ("a<any>b", "axyb", true),
        ("<any>", "", true),
        ("<any>", "x", true),
        ("a<any>b", "ac", false),
        ("<any>tail", "tailx", false),
        ("head<any>", "xhead", false),
        ("literal", "different", false),
        ("literal", "literal", true),
        ("a<any>b<any>c", "abc", true),
        ("a<any>b<any>c", "axbxc", true),
        ("a<any>b<any>c", "acb", false),
        ("<any><any>", "", true),
        ("a<any>b<any>c", "xabcy", false),
        ("<any>b<any>bc", "bbc", true),
        ("a<any><any>b", "ab", true),
        ("a<any>b<any>bc", "abbbc", true),
        ("a<any>b<any>bc", "abbc", true),
        ("Bearer <any>\"<any>\"", "Bearer a=\"one\", b=\"two\"", true),
        (
            "Bearer <any><any>error=\"invalid_token\"<any>",
            "Bearer a=\"one\", error=\"invalid_token\"",
            true,
        ),
    ] {
        // When: a documented value is compared.
        let matched = matches_value(pattern, actual);
        // Then: only complete anchored matches succeed.
        ensure!(matched == expected, "pattern {pattern} comparison differs");
    }
    Ok(())
}

fn reference(pattern: &str, actual: &str) -> bool {
    if let Some(tail) = pattern.strip_prefix("<any>") {
        return (0..=actual.len())
            .filter_map(|offset| actual.get(offset..))
            .any(|suffix| reference(tail, suffix));
    }
    match (
        pattern.as_bytes().split_first(),
        actual.as_bytes().split_first(),
    ) {
        (None, None) => true,
        (Some((expected, _)), Some((observed, _))) if expected == observed => pattern
            .get(1..)
            .zip(actual.get(1..))
            .is_some_and(|(tail, rest)| reference(tail, rest)),
        (None | Some(_), Some(_)) | (Some(_), None) => false,
    }
}

fn words(alphabet: &[&str], limit: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut level = vec![String::new()];
    for _depth in 0..limit {
        let next: Vec<_> = level
            .iter()
            .flat_map(|prefix| alphabet.iter().map(move |token| format!("{prefix}{token}")))
            .collect();
        all.extend(next.iter().cloned());
        level = next;
    }
    all
}

/// Every bounded pattern agrees with a matcher that tries every possible split.
#[test]
fn values_match_when_some_wildcard_split_satisfies_literals() -> anyhow::Result<()> {
    // Given: all token patterns through six tokens and binary strings through seven bytes.
    let patterns = words(&["a", "b", "<any>"], 6);
    let strings = words(&["a", "b"], 7);
    // When/Then: compare against an independent recursive language definition.
    for pattern in &patterns {
        for actual in &strings {
            ensure!(
                matches_value(pattern, actual) == reference(pattern, actual),
                "{}: {pattern:?} / {actual:?}",
                RULES.first().copied().unwrap_or_default()
            );
        }
    }
    let covered = ["wildcard-backtracking"];
    ensure!(
        RULES.len() == covered.len() && RULES.iter().all(|rule| covered.contains(rule)),
        "wildcard rule lacks a table row"
    );
    Ok(())
}
