//! Paired literal response controls, including anchored substring near misses.

use alloc::collections::BTreeMap;

use anyhow::ensure;

use super::compare::{Message, RULES};

/// Response comparison rejects every independent literal drift with paired controls.
#[test]
fn response_table_distinguishes_when_literal_fields_drift() -> anyhow::Result<()> {
    // Given: each row changes one observed response contract.
    let mut coverage = BTreeMap::<&str, (bool, bool)>::new();
    for &(rule, expected, actual, passes) in ROWS {
        let result = Message::parse(&format!("HTTP/1.1 {expected}"))?
            .compare_response(&Message::parse(&format!("HTTP/1.1 {actual}"))?);
        ensure!(
            result.is_ok() == passes,
            "{rule}: expected {expected:?}, actual {actual:?}"
        );
        let covered = coverage.entry(rule).or_default();
        if passes {
            covered.0 = true;
        } else {
            covered.1 = true;
        }
    }
    for rule in RULES {
        ensure!(
            coverage.get(rule) == Some(&(true, true)),
            "response rule {rule} lacks paired coverage"
        );
    }
    ensure!(
        coverage.len() == RULES.len(),
        "response rule coverage drifted"
    );
    Ok(())
}

const ROWS: &[(&str, &str, &str, bool)] = &[
    ("status-code", "401 Unauthorized", "401 Unauthorized", true),
    ("status-code", "401 Unauthorized", "403 Unauthorized", false),
    ("reason-case", "401 Unauthorized", "401 Unauthorized", true),
    ("reason-case", "401 unauthorized", "401 Unauthorized", false),
    (
        "duplicate-header",
        "200 OK\nSet-Cookie: b=2<any>",
        "200 OK\nSet-Cookie: a=1; Path=/\nSet-Cookie: b=2; Path=/",
        true,
    ),
    (
        "duplicate-header",
        "200 OK\nSet-Cookie: c=3<any>",
        "200 OK\nSet-Cookie: a=1; Path=/\nSet-Cookie: b=2; Path=/",
        false,
    ),
    (
        "duplicate-header",
        "200 OK\nSet-Cookie: b=2<any>\nSet-Cookie: b=2<any>",
        "200 OK\nSet-Cookie: b=2; Path=/",
        true,
    ),
    (
        "status-reason",
        "401 Unauthorized",
        "401 Unauthorized",
        true,
    ),
    ("status-reason", "401 Forbidden", "401 Unauthorized", false),
    ("status-reason", "401 Unauthor", "401 Unauthorized", false),
    (
        "status-reason",
        "401 Unauthorized extra",
        "401 Unauthorized",
        false,
    ),
    (
        "header-name",
        "200 OK\nX-Name: alpha",
        "200 OK\nx-name: alpha",
        true,
    ),
    (
        "header-name",
        "200 OK\nX-Name: alpha",
        "200 OK\nx-other: alpha",
        false,
    ),
    (
        "header-value",
        "200 OK\nX-Name: alpha",
        "200 OK\nX-Name: alpha",
        true,
    ),
    (
        "header-value",
        "200 OK\nX-Name: alpha",
        "200 OK\nX-Name: alphA",
        false,
    ),
    (
        "body",
        "401 Unauthorized\n\nunauthorized: missing credential",
        "401 Unauthorized\n\nunauthorized: missing credential",
        true,
    ),
    (
        "body",
        "401 Unauthorized\n\nunauthorized: missing",
        "401 Unauthorized\n\nunauthorized: missing credential",
        false,
    ),
    (
        "body",
        "401 Unauthorized\n\nmissing credential",
        "401 Unauthorized\n\nunauthorized: missing credential",
        false,
    ),
    ("body", "200 OK\n\nbody", "200 OK\n\nbody\n", false),
    ("body", "200 OK\n\nbody\n", "200 OK\n\nbody\n", true),
    ("body", "200 OK\n\nbody ", "200 OK\n\nbody", false),
    ("body", "200 OK\n\n", "200 OK\n\n", true),
    ("body", "200 OK\n\n", "200 OK\n\nx", false),
    ("body", "200 OK\n\n<any>body<any>", "200 OK\n\nxbodyy", true),
];
