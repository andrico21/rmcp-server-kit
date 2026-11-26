//! Serde adapter for an optional duration string.

use core::time::Duration;

use serde::de::{Deserialize as _, Deserializer};

use super::DurationText;

/// Deserialize an optional duration string.
///
/// # Errors
///
/// Returns the deserializer's error for a non-string or an invalid duration.
pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<DurationText>::deserialize(deserializer)
        .map(|value| value.map(|DurationText(duration)| duration))
}
