//! Exact-value tables, properties, and serde adapters for `parse_duration`.

use core::time::Duration;

use anyhow::ensure;
use proptest::prelude::*;
use serde::Deserialize;
use toml::de::Error as TomlError;

use super::{ErrorKind, parse_duration};

/// Every unit alias with its value for the number `1`.
const ALIASES: &[(&str, Duration)] = &[
    ("nanos", Duration::from_nanos(1)),
    ("nsec", Duration::from_nanos(1)),
    ("ns", Duration::from_nanos(1)),
    ("usec", Duration::from_micros(1)),
    ("us", Duration::from_micros(1)),
    ("\u{b5}s", Duration::from_micros(1)),
    ("millis", Duration::from_millis(1)),
    ("msec", Duration::from_millis(1)),
    ("ms", Duration::from_millis(1)),
    ("seconds", Duration::from_secs(1)),
    ("second", Duration::from_secs(1)),
    ("secs", Duration::from_secs(1)),
    ("sec", Duration::from_secs(1)),
    ("s", Duration::from_secs(1)),
    ("minutes", Duration::from_secs(60)),
    ("minute", Duration::from_secs(60)),
    ("min", Duration::from_secs(60)),
    ("mins", Duration::from_secs(60)),
    ("m", Duration::from_secs(60)),
    ("hours", Duration::from_secs(3_600)),
    ("hour", Duration::from_secs(3_600)),
    ("hr", Duration::from_secs(3_600)),
    ("hrs", Duration::from_secs(3_600)),
    ("h", Duration::from_secs(3_600)),
    ("days", Duration::from_hours(24)),
    ("day", Duration::from_hours(24)),
    ("d", Duration::from_hours(24)),
    ("weeks", Duration::from_hours(168)),
    ("week", Duration::from_hours(168)),
    ("wk", Duration::from_hours(168)),
    ("wks", Duration::from_hours(168)),
    ("w", Duration::from_hours(168)),
    ("months", Duration::from_secs(2_630_016)),
    ("month", Duration::from_secs(2_630_016)),
    ("M", Duration::from_secs(2_630_016)),
    ("years", Duration::from_hours(8766)),
    ("year", Duration::from_hours(8766)),
    ("yr", Duration::from_hours(8766)),
    ("yrs", Duration::from_hours(8766)),
    ("y", Duration::from_hours(8766)),
];

/// Accepted inputs and their exact values.
const ACCEPTED: &[(&str, Duration)] = &[
    ("0", Duration::ZERO),
    ("1h30m", Duration::from_mins(90)),
    ("1h 30m", Duration::from_mins(90)),
    ("1s1s", Duration::from_secs(2)),
    ("1m1h", Duration::from_mins(61)),
    ("2d3h4m5s6ms7us8ns", Duration::new(183_845, 6_007_008)),
    ("  5s  ", Duration::from_secs(5)),
    ("10 m", Duration::from_secs(600)),
    ("1.5h", Duration::from_mins(90)),
    ("0.001s", Duration::from_millis(1)),
    ("1.5ms", Duration::from_micros(1_500)),
    ("0.5min", Duration::from_secs(30)),
    ("1.5 s", Duration::from_millis(1_500)),
    ("3s", Duration::from_secs(3)),
    ("30s", Duration::from_secs(30)),
    ("120s", Duration::from_secs(120)),
    ("10m", Duration::from_secs(600)),
    ("30d", Duration::from_hours(720)),
    ("2h", Duration::from_secs(7_200)),
    ("20m", Duration::from_mins(20)),
    ("50ms", Duration::from_millis(50)),
    ("0s", Duration::ZERO),
    ("18446744073709551615s 999999999ns", Duration::MAX),
    ("1.1y", Duration::from_mins(578_556)),
    ("0.10000000000s", Duration::from_millis(100)),
    (
        "18446744073709551615ns 1ns",
        Duration::new(18_446_744_073, 709_551_616),
    ),
    ("\u{a0}1s\u{a0}2s\u{a0}", Duration::from_secs(3)),
    ("1\u{2003}s", Duration::from_secs(1)),
    ("\t1s\n2m\u{3000}", Duration::from_secs(121)),
];

/// Rejected inputs and the exact error kind.
const REJECTED: &[(&str, ErrorKind)] = &[
    ("", ErrorKind::Empty),
    ("   ", ErrorKind::Empty),
    ("\t\n\u{a0}", ErrorKind::Empty),
    ("10", ErrorKind::UnknownUnit),
    ("m", ErrorKind::NumberExpected),
    (".5s", ErrorKind::NumberExpected),
    ("1.", ErrorKind::FractionDigitsExpected),
    ("1.s", ErrorKind::FractionDigitsExpected),
    ("10x", ErrorKind::UnknownUnit),
    ("10M5", ErrorKind::UnknownUnit),
    ("10 m s", ErrorKind::NumberExpected),
    ("10 m 5", ErrorKind::UnknownUnit),
    (" 0", ErrorKind::UnknownUnit),
    ("0 ", ErrorKind::UnknownUnit),
    ("00", ErrorKind::UnknownUnit),
    ("0.0", ErrorKind::UnknownUnit),
    ("1s0", ErrorKind::UnknownUnit),
    ("+1s", ErrorKind::NumberExpected),
    ("-1s", ErrorKind::NumberExpected),
    ("1e3s", ErrorKind::UnknownUnit),
    ("1.0ns", ErrorKind::NanosecondFraction),
    ("1.0001h", ErrorKind::Unrepresentable),
    ("1.001y", ErrorKind::Unrepresentable),
    ("0.00000005d", ErrorKind::Unrepresentable),
    ("0.100000000000s", ErrorKind::Unrepresentable),
    ("0.00000000000000000000s", ErrorKind::Unrepresentable),
    ("0.99999999999999999999s", ErrorKind::Unrepresentable),
    ("18446744073709551616ns", ErrorKind::Unrepresentable),
    ("18446744073709551616s", ErrorKind::Unrepresentable),
    ("18446744073710ms", ErrorKind::Unrepresentable),
    ("1ns 18446744073709551615ns", ErrorKind::Unrepresentable),
    ("1 0s", ErrorKind::WhitespaceInNumber),
    ("1 .5s", ErrorKind::WhitespaceInNumber),
    ("1. 5s", ErrorKind::WhitespaceInNumber),
    ("1.5 0s", ErrorKind::WhitespaceInNumber),
    ("1h3 0m", ErrorKind::WhitespaceInNumber),
    (
        "18446744073709551615s 1000000000ns",
        ErrorKind::Unrepresentable,
    ),
    ("18446744073709551615.5s 0.5s", ErrorKind::Unrepresentable),
    (
        "18446744073709551615s 999999999ns 1ns",
        ErrorKind::Unrepresentable,
    ),
    ("1\u{3bc}s", ErrorKind::InvalidCharacter),
    ("\u{ff11}s", ErrorKind::NumberExpected),
    ("\u{663}s", ErrorKind::NumberExpected),
    ("1\u{ff10}s", ErrorKind::InvalidCharacter),
    ("1s.5", ErrorKind::InvalidCharacter),
    ("1.5.5s", ErrorKind::InvalidCharacter),
];

/// Rows promoted from the differential run against `humantime` 2.4.0
/// (`.omo/evidence/humantime-diff/`): `Some((seconds, nanos))` is the agreed
/// value, `None` a rejection; `D3` / `D3b` rows are the two deviations.
const GOLDEN: &[(&str, Option<(u64, u32)>)] = &[
    ("1.5nanos", None),
    ("1.5nsec", None),
    ("1.5ns", None),
    ("1.5usec", Some((0, 1_500))),
    ("1.5us", Some((0, 1_500))),
    ("1.5\u{b5}s", Some((0, 1_500))),
    ("1.5millis", Some((0, 1_500_000))),
    ("1.5msec", Some((0, 1_500_000))),
    ("1.5ms", Some((0, 1_500_000))),
    ("1.5seconds", Some((1, 500_000_000))),
    ("1.5second", Some((1, 500_000_000))),
    ("1.5secs", Some((1, 500_000_000))),
    ("1.5sec", Some((1, 500_000_000))),
    ("1.5s", Some((1, 500_000_000))),
    ("1.5minutes", Some((90, 0))),
    ("1.5minute", Some((90, 0))),
    ("1.5min", Some((90, 0))),
    ("1.5mins", Some((90, 0))),
    ("1.5m", Some((90, 0))),
    ("1.5hours", Some((5_400, 0))),
    ("1.5hour", Some((5_400, 0))),
    ("1.5hr", Some((5_400, 0))),
    ("1.5hrs", Some((5_400, 0))),
    ("1.5h", Some((5_400, 0))),
    ("1.5days", Some((129_600, 0))),
    ("1.5day", Some((129_600, 0))),
    ("1.5d", Some((129_600, 0))),
    ("1.5weeks", Some((907_200, 0))),
    ("1.5week", Some((907_200, 0))),
    ("1.5wk", Some((907_200, 0))),
    ("1.5wks", Some((907_200, 0))),
    ("1.5w", Some((907_200, 0))),
    ("1.5months", Some((3_945_024, 0))),
    ("1.5month", Some((3_945_024, 0))),
    ("1.5M", Some((3_945_024, 0))),
    ("1.5years", Some((47_336_400, 0))),
    ("1.5year", Some((47_336_400, 0))),
    ("1.5yr", Some((47_336_400, 0))),
    ("1.5yrs", Some((47_336_400, 0))),
    ("1.5y", Some((47_336_400, 0))),
    ("18446744073709551us", Some((18_446_744_073, 709_551_000))),
    ("18446744073709552us", None),
    ("18446744073709ms", Some((18_446_744_073, 709_000_000))),
    ("18446744073710ms", None),
    ("307445734561825860m", Some((0xFFFF_FFFF_FFFF_FFF0, 0))),
    ("307445734561825861m", None),
    ("5124095576030431h", Some((0xFFFF_FFFF_FFFF_FFF0, 0))),
    ("5124095576030432h", None),
    ("213503982334601d", Some((18_446_744_073_709_526_400, 0))),
    ("213503982334602d", None),
    ("30500568904943w", Some((18_446_744_073_709_526_400, 0))),
    ("30500568904944w", None),
    ("7013928460400M", Some((18_446_744_073_707_366_400, 0))),
    ("7013928460401M", None),
    ("584542046090y", Some((18_446_744_073_689_784_000, 0))),
    ("584542046091y", None),
    (
        "18446744073709551615ns",
        Some((18_446_744_073, 709_551_615)),
    ),
    ("18446744073709551616ns", None),
    ("18446744073709551615s", Some((0xFFFF_FFFF_FFFF_FFFF, 0))),
    ("18446744073709551616s", None),
    ("1.25ns", None),
    ("1.0001ns", None),
    ("1.000000001ns", None),
    ("1.25us", Some((0, 1_250))),
    ("1.0001us", None),
    ("1.000000001us", None),
    ("1.25ms", Some((0, 1_250_000))),
    ("1.0001ms", Some((0, 1_000_100))),
    ("1.000000001ms", None),
    ("1.25s", Some((1, 250_000_000))),
    ("1.0001s", Some((1, 100_000))),
    ("1.000000001s", Some((1, 1))),
    ("1.25m", Some((75, 0))),
    ("1.0001m", Some((60, 6_000_000))),
    ("1.000000001m", Some((60, 60))),
    ("1.25h", Some((4_500, 0))),
    ("1.0001h", None),
    ("1.000000001h", None),
    ("1.25d", Some((108_000, 0))),
    ("1.0001d", None),
    ("1.000000001d", None),
    ("1.25w", Some((756_000, 0))),
    ("1.0001w", None),
    ("1.000000001w", None),
    ("1.25M", Some((3_287_520, 0))),
    ("1.0001M", None),
    ("1.000000001M", None),
    ("1.25y", Some((39_447_000, 0))),
    ("1.0001y", None),
    ("1.000000001y", None),
    (
        "18446744073709551615s 999999999ns",
        Some((0xFFFF_FFFF_FFFF_FFFF, 999_999_999)),
    ),
    (
        "18446744073709551615s 999999998ns 1ns",
        Some((0xFFFF_FFFF_FFFF_FFFF, 999_999_999)),
    ),
    (
        "18446744073709551614s 999999999ns 1ns",
        Some((0xFFFF_FFFF_FFFF_FFFF, 0)),
    ),
    ("0.5s 0.5s", Some((1, 0))),
    ("0.999999999s 1ns", Some((1, 0))),
    ("999999999ns 1ns", Some((1, 0))),
    ("500ms 500000us", Some((1, 0))),
    (
        "18446744073709551615ns 1ns",
        Some((18_446_744_073, 709_551_616)),
    ),
    ("1ns 18446744073709551615ns", None),
    ("0.5min 0.5min", Some((60, 0))),
    ("1s\u{9}2m", Some((121, 0))),
    ("\u{9}1\u{9}s\u{9}", Some((1, 0))),
    ("1s\u{a}2m", Some((121, 0))),
    ("\u{a}1\u{a}s\u{a}", Some((1, 0))),
    ("1s\u{a0}2m", Some((121, 0))),
    ("\u{a0}1\u{a0}s\u{a0}", Some((1, 0))),
    ("1s\u{2003}2m", Some((121, 0))),
    ("\u{2003}1\u{2003}s\u{2003}", Some((1, 0))),
    ("1s\u{3000}2m", Some((121, 0))),
    ("\u{3000}1\u{3000}s\u{3000}", Some((1, 0))),
    ("1s\u{85}2m", Some((121, 0))),
    ("\u{85}1\u{85}s\u{85}", Some((1, 0))),
    ("1\u{b5}s", Some((0, 1_000))),
    ("1\u{3bc}s", None),
    ("\u{663}s", None),
    ("\u{ff13}s", None),
    ("1\u{e9}", None),
    ("1s\u{1b}", None),
    ("0", Some((0, 0))),
    (" 0", None),
    ("0 ", None),
    ("00", None),
    ("0.0", None),
    ("1s0", None),
    ("10", None),
    (".5s", None),
    ("1.", None),
    ("10M5", None),
    ("10 m s", None),
    ("+1s", None),
    ("1e3s", None),
    ("", None),
    ("1 0s", None),                                  // D3
    ("1 .5s", None),                                 // D3
    ("1. 5s", None),                                 // D3
    ("1.5 0s", None),                                // D3
    ("0 0s", None),                                  // D3
    ("1h3 0m", None),                                // D3
    ("18446744073709551615s 1000000000ns", None),    // D3b
    ("18446744073709551615.5s 0.5s", None),          // D3b
    ("18446744073709551615s 999999999ns 1ns", None), // D3b
    ("0.5s18446744073709551615.5s", None),           // D3b
    ("18446744073709551615s1000000000ns", None),     // D3b
    ("18446744073709551615s 1s", None),
];

/// Every golden row parses to exactly its recorded outcome.
#[test]
fn golden_rows_match_the_differential() -> anyhow::Result<()> {
    for &(input, expected) in GOLDEN {
        let actual = parse_duration(input).ok();
        let wanted = expected.map(|(seconds, nanos)| Duration::new(seconds, nanos));
        ensure!(actual == wanted, "{input:?}: {actual:?} != {wanted:?}");
    }
    Ok(())
}

/// Assert that `input` parses to exactly `expected`.
fn check_accepted(input: &str, expected: Duration) -> anyhow::Result<()> {
    let actual = parse_duration(input);
    ensure!(
        actual == Ok(expected),
        "{input:?}: {actual:?} != {expected:?}"
    );
    Ok(())
}

/// Assert that `input` is rejected with exactly `expected`.
fn check_rejected(input: &str, expected: ErrorKind) -> anyhow::Result<()> {
    let actual = parse_duration(input).map_err(|error| error.kind);
    ensure!(
        actual == Err(expected),
        "{input:?}: {actual:?} != {expected:?}"
    );
    Ok(())
}

/// Every alias of every unit parses with the number `1`.
#[test]
fn every_unit_alias_parses_one() -> anyhow::Result<()> {
    for &(alias, expected) in ALIASES {
        check_accepted(&format!("1{alias}"), expected)?;
    }
    Ok(())
}

/// Accepted forms, including the documented edge values.
#[test]
fn accepted_inputs_have_exact_values() -> anyhow::Result<()> {
    for &(input, expected) in ACCEPTED {
        check_accepted(input, expected)?;
    }
    Ok(())
}

/// Rejected forms, including both deviations from `humantime` 2.4.0.
#[test]
fn rejected_inputs_have_exact_kinds() -> anyhow::Result<()> {
    for &(input, expected) in REJECTED {
        check_rejected(input, expected)?;
    }
    Ok(())
}

/// Linear-time smoke inputs of one megabyte each.
#[test]
fn megabyte_inputs_return() -> anyhow::Result<()> {
    check_rejected(&"1".repeat(1 << 20), ErrorKind::Unrepresentable)?;
    check_accepted(&"1s".repeat(1 << 19), Duration::from_secs(1 << 19))
}

proptest! {
    /// Random valid groups sum to the independently computed total.
    #[test]
    fn random_groups_sum_exactly(
        groups in prop::collection::vec((any::<u32>(), 0..ALIASES.len()), 1..8),
        spaced in any::<bool>(),
    ) {
        let mut text = String::new();
        let mut expected = Duration::ZERO;
        for &(count, index) in &groups {
            let Some(&(alias, unit)) = ALIASES.get(index) else {
                return Err(TestCaseError::fail("alias index out of range"));
            };
            if spaced && !text.is_empty() {
                text.push(' ');
            }
            text.push_str(&count.to_string());
            text.push_str(alias);
            let Some(sum) = unit.checked_mul(count).and_then(|value| expected.checked_add(value)) else {
                return Err(TestCaseError::fail("reference sum overflowed"));
            };
            expected = sum;
        }
        prop_assert_eq!(parse_duration(&text), Ok(expected));
    }

    /// Arbitrary text, including non-ASCII, returns without panicking.
    #[test]
    fn arbitrary_text_never_panics(text in any::<String>()) {
        let _outcome = parse_duration(&text);
    }
}

/// A struct using both serde adapters.
#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Timeouts {
    /// Required duration with a default when absent.
    #[serde(default = "default_wait", with = "crate::duration_text::serde_with")]
    wait: Duration,
    /// Optional duration.
    #[serde(default, with = "crate::duration_text::serde_with::option")]
    refresh: Option<Duration>,
}

/// Default for [`Timeouts::wait`].
const fn default_wait() -> Duration {
    Duration::from_secs(7)
}

/// TOML strings decode through both adapters; absent keys use the defaults.
#[test]
fn serde_adapters_decode_toml() -> anyhow::Result<()> {
    let both: Timeouts = toml::from_str("wait = \"1h30m\"\nrefresh = \"0s\"")?;
    ensure!(
        both == Timeouts {
            wait: Duration::from_mins(90),
            refresh: Some(Duration::ZERO),
        }
    );
    let neither: Timeouts = toml::from_str("")?;
    ensure!(
        neither
            == Timeouts {
                wait: Duration::from_secs(7),
                refresh: None,
            }
    );
    Ok(())
}

/// An invalid TOML string is `invalid_value` naming "a duration".
#[test]
fn serde_adapters_reject_invalid_toml() -> anyhow::Result<()> {
    let wait = toml::from_str::<Timeouts>("wait = \"soon\"").err();
    ensure!(
        wait.as_ref().map(TomlError::message)
            == Some("invalid value: string \"soon\", expected a duration")
    );
    let refresh = toml::from_str::<Timeouts>("refresh = \"1 0s\"").err();
    ensure!(
        refresh.as_ref().map(TomlError::message)
            == Some("invalid value: string \"1 0s\", expected a duration")
    );
    Ok(())
}

/// JSON decodes strings only; a number is an invalid type.
#[test]
fn serde_adapters_decode_json_strings_only() -> anyhow::Result<()> {
    let both: Timeouts = serde_json::from_str(r#"{"wait":"2s","refresh":"50ms"}"#)?;
    ensure!(
        both == Timeouts {
            wait: Duration::from_secs(2),
            refresh: Some(Duration::from_millis(50)),
        }
    );
    let invalid = serde_json::from_str::<Timeouts>(r#"{"wait":"soon"}"#)
        .err()
        .map(|error| error.to_string());
    ensure!(
        invalid.as_deref()
            == Some("invalid value: string \"soon\", expected a duration at line 1 column 14")
    );
    let number = serde_json::from_str::<Timeouts>(r#"{"wait":5}"#)
        .err()
        .map(|error| error.to_string());
    ensure!(
        number.as_deref()
            == Some("invalid type: integer `5`, expected a duration at line 1 column 9")
    );
    Ok(())
}
