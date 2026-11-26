//! Serde adapters for duration strings, used with `#[serde(with = "...")]`.
//!
//! Only strings are accepted; a parse failure is reported as
//! `invalid_value` expecting "a duration".

use core::{fmt, time::Duration};

use serde::de::{Deserialize, Deserializer, Error, Unexpected, Visitor};

use super::parse_duration;

pub(crate) mod option;

/// A duration decoded from a string.
#[derive(Debug, Clone, Copy)]
struct DurationText(Duration);

/// Visitor accepting only strings.
#[derive(Debug, Clone, Copy)]
struct DurationTextVisitor;

impl Visitor<'_> for DurationTextVisitor {
    type Value = DurationText;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a duration")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        match parse_duration(v) {
            Ok(duration) => Ok(DurationText(duration)),
            Err(_rejected) => Err(E::invalid_value(Unexpected::Str(v), &self)),
        }
    }
}

impl<'de> Deserialize<'de> for DurationText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DurationTextVisitor)
    }
}

/// Deserialize a required duration string.
///
/// # Errors
///
/// Returns the deserializer's error for a non-string or an invalid duration.
pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    DurationText::deserialize(deserializer).map(|DurationText(duration)| duration)
}
