//! Duration text parsing for configuration values.
//!
//! The grammar is compatible with the `humantime` 2.4.0 duration format:
//! one or more `number unit` groups such as `"1h 30m"`, `"1h30m"`, or
//! `"1.5s"`, where a number is ASCII digits with an optional `.digits`
//! fraction and a unit is one of the names in [`Unit::from_name`]. The bare
//! string `"0"` is zero. Whitespace is [`char::is_whitespace`] and is accepted
//! before the first number, between a number and its unit, between groups,
//! and after the last unit.
//!
//! Arithmetic is staged in `u64` like the original format: each group's
//! whole part and fraction part are converted and added separately, every
//! step is checked, and fractions must convert exactly (seconds for hours
//! and larger units, nanoseconds otherwise). Two deliberate deviations:
//!
//! - whitespace inside a number (`"1 0s"`, `"1. 5s"`) is rejected;
//! - a total whose nanosecond carry overflows the seconds counter is an
//!   error instead of a panic.

use core::{error::Error, fmt, iter::Peekable, str::CharIndices, time::Duration};

/// Nanoseconds in one second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Why a duration string was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    /// The input was empty or whitespace only.
    Empty,
    /// A group did not start with an ASCII digit.
    NumberExpected,
    /// A character that cannot appear at this position.
    InvalidCharacter,
    /// A decimal point was not followed by a digit.
    FractionDigitsExpected,
    /// Whitespace between two parts of one number.
    WhitespaceInNumber,
    /// A unit name that is not in the unit table (including a missing unit).
    UnknownUnit,
    /// A fraction on nanoseconds, which have no smaller unit.
    NanosecondFraction,
    /// A value that overflows, or a fraction that does not convert exactly.
    Unrepresentable,
}

/// A rejected duration string, with the byte offset where parsing stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurationError {
    /// The reason for the rejection.
    kind: ErrorKind,
    /// Byte offset into the input.
    at: usize,
}

impl DurationError {
    /// Build an error of `kind` at byte offset `at`.
    const fn new(kind: ErrorKind, at: usize) -> Self {
        Self { kind, at }
    }
}

impl fmt::Display for DurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let at = self.at;
        match self.kind {
            ErrorKind::Empty => f.write_str("value was empty"),
            ErrorKind::NumberExpected => write!(f, "expected a number at byte {at}"),
            ErrorKind::InvalidCharacter => write!(f, "invalid character at byte {at}"),
            ErrorKind::FractionDigitsExpected => {
                write!(f, "expected a digit after the decimal point at byte {at}")
            }
            ErrorKind::WhitespaceInNumber => write!(f, "whitespace inside a number at byte {at}"),
            ErrorKind::UnknownUnit => write!(f, "unknown or missing unit at byte {at}"),
            ErrorKind::NanosecondFraction => {
                write!(f, "nanoseconds cannot have a fraction at byte {at}")
            }
            ErrorKind::Unrepresentable => write!(
                f,
                "number is too large or cannot be represented exactly at byte {at}"
            ),
        }
    }
}

impl Error for DurationError {}

/// Time units accepted after a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    /// `nanos nsec ns`.
    Nanosecond,
    /// `usec us µs`.
    Microsecond,
    /// `millis msec ms`.
    Millisecond,
    /// `seconds second secs sec s`.
    Second,
    /// `minutes minute min mins m`.
    Minute,
    /// `hours hour hr hrs h`.
    Hour,
    /// `days day d`.
    Day,
    /// `weeks week wk wks w`.
    Week,
    /// `months month M` (30.44 days).
    Month,
    /// `years year yr yrs y` (365.25 days).
    Year,
}

/// Where a unit's converted value lands, and its multiplier.
#[derive(Debug, Clone, Copy)]
enum Scale {
    /// Value times the factor is nanoseconds.
    Nanos(u64),
    /// Value times the factor is seconds.
    Seconds(u64),
}

impl Unit {
    /// Look a unit up by its exact, case-sensitive name.
    fn from_name(name: &str) -> Option<Self> {
        let unit = match name {
            "nanos" | "nsec" | "ns" => Self::Nanosecond,
            "usec" | "us" | "\u{b5}s" => Self::Microsecond,
            "millis" | "msec" | "ms" => Self::Millisecond,
            "seconds" | "second" | "secs" | "sec" | "s" => Self::Second,
            "minutes" | "minute" | "min" | "mins" | "m" => Self::Minute,
            "hours" | "hour" | "hr" | "hrs" | "h" => Self::Hour,
            "days" | "day" | "d" => Self::Day,
            "weeks" | "week" | "wk" | "wks" | "w" => Self::Week,
            "months" | "month" | "M" => Self::Month,
            "years" | "year" | "yr" | "yrs" | "y" => Self::Year,
            _ => return None,
        };
        Some(unit)
    }

    /// Scale applied to the whole part of a number.
    const fn whole_scale(self) -> Scale {
        match self {
            Self::Nanosecond => Scale::Nanos(1),
            Self::Microsecond => Scale::Nanos(1_000),
            Self::Millisecond => Scale::Nanos(1_000_000),
            Self::Second => Scale::Seconds(1),
            Self::Minute => Scale::Seconds(60),
            Self::Hour => Scale::Seconds(3_600),
            Self::Day => Scale::Seconds(86_400),
            Self::Week => Scale::Seconds(604_800),
            Self::Month => Scale::Seconds(2_630_016),
            Self::Year => Scale::Seconds(31_557_600),
        }
    }

    /// Scale applied to the fraction part; `None` for nanoseconds.
    const fn fraction_scale(self) -> Option<Scale> {
        match self {
            Self::Nanosecond => None,
            Self::Microsecond => Some(Scale::Nanos(1_000)),
            Self::Millisecond => Some(Scale::Nanos(1_000_000)),
            Self::Second => Some(Scale::Nanos(NANOS_PER_SEC)),
            Self::Minute => Some(Scale::Nanos(60_000_000_000)),
            Self::Hour => Some(Scale::Seconds(3_600)),
            Self::Day => Some(Scale::Seconds(86_400)),
            Self::Week => Some(Scale::Seconds(604_800)),
            Self::Month => Some(Scale::Seconds(2_630_016)),
            Self::Year => Some(Scale::Seconds(31_557_600)),
        }
    }
}

/// `numerator / denominator` of a parsed fraction (denominator is a power of ten).
#[derive(Debug, Clone, Copy)]
struct Fraction {
    /// Significant digits after the point.
    numerator: u64,
    /// Ten to the number of digits after the point.
    denominator: u64,
}

/// One parsed number.
#[derive(Debug, Clone, Copy)]
struct Number {
    /// Digits before the point.
    whole: u64,
    /// Digits after the point, if a point was present.
    fraction: Option<Fraction>,
}

/// Value of an ASCII decimal digit.
fn ascii_digit(character: char) -> Option<u64> {
    if character.is_ascii_digit() {
        character.to_digit(10).map(u64::from)
    } else {
        None
    }
}

/// A unit letter: ASCII letters and the micro sign U+00B5.
const fn is_unit_char(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '\u{b5}'
}

/// Add `seconds` plus `nanos` to `total`, carrying whole seconds out of `nanos`.
fn accumulate(total: Duration, (seconds, nanos): (u64, u64)) -> Option<Duration> {
    let all_nanos = u64::from(total.subsec_nanos()).checked_add(nanos)?;
    let carried = seconds.checked_add(all_nanos.checked_div(NANOS_PER_SEC)?)?;
    let total_seconds = total.as_secs().checked_add(carried)?;
    let subsec = u32::try_from(all_nanos.checked_rem(NANOS_PER_SEC)?).ok()?;
    Some(Duration::new(total_seconds, subsec))
}

/// Split a scaled value into `(seconds, nanoseconds)`.
const fn split(scale: Scale, value: u64) -> (u64, u64) {
    match scale {
        Scale::Nanos(_) => (0, value),
        Scale::Seconds(_) => (value, 0),
    }
}

/// The factor carried by a scale.
const fn factor(scale: Scale) -> u64 {
    match scale {
        Scale::Nanos(multiplier) | Scale::Seconds(multiplier) => multiplier,
    }
}

/// Add one `number unit` group to `total`: the whole part, then the fraction.
///
/// # Errors
///
/// Returns the [`ErrorKind`] for an overflow, an inexact fraction, or a
/// fraction on nanoseconds.
fn add_group(total: Duration, number: Number, unit: Unit) -> Result<Duration, ErrorKind> {
    let whole_scale = unit.whole_scale();
    let whole = number
        .whole
        .checked_mul(factor(whole_scale))
        .ok_or(ErrorKind::Unrepresentable)?;
    let with_whole =
        accumulate(total, split(whole_scale, whole)).ok_or(ErrorKind::Unrepresentable)?;
    let Some(fraction) = number.fraction else {
        return Ok(with_whole);
    };
    let scale = unit.fraction_scale().ok_or(ErrorKind::NanosecondFraction)?;
    let scaled = fraction
        .numerator
        .checked_mul(factor(scale))
        .ok_or(ErrorKind::Unrepresentable)?;
    if scaled.checked_rem(fraction.denominator) != Some(0) {
        return Err(ErrorKind::Unrepresentable);
    }
    let value = scaled
        .checked_div(fraction.denominator)
        .ok_or(ErrorKind::Unrepresentable)?;
    accumulate(with_whole, split(scale, value)).ok_or(ErrorKind::Unrepresentable)
}

/// Character cursor over the input with byte offsets.
#[derive(Debug)]
struct Cursor<'input> {
    /// The whole input, for unit lookups by byte range.
    input: &'input str,
    /// Remaining characters with their byte offsets.
    chars: Peekable<CharIndices<'input>>,
}

impl<'input> Cursor<'input> {
    /// Start at the beginning of `input`.
    fn new(input: &'input str) -> Self {
        Self {
            input,
            chars: input.char_indices().peekable(),
        }
    }

    /// Byte offset of the next character, or the input length at the end.
    fn offset(&mut self) -> usize {
        self.chars.peek().map_or(self.input.len(), |&(at, _)| at)
    }

    /// The next character without consuming it.
    fn peek(&mut self) -> Option<char> {
        self.chars.peek().map(|&(_, character)| character)
    }

    /// Skip whitespace; report whether any was skipped.
    fn skip_whitespace(&mut self) -> bool {
        let mut skipped = false;
        while self
            .chars
            .next_if(|&(_, character)| character.is_whitespace())
            .is_some()
        {
            skipped = true;
        }
        skipped
    }

    /// Consume ASCII digits, folding each into `fold`; return how many were read.
    ///
    /// # Errors
    ///
    /// Returns an `Unrepresentable` error when `fold` overflows.
    fn digits(&mut self, mut fold: impl FnMut(u64) -> Option<()>) -> Result<usize, DurationError> {
        let mut count = 0_usize;
        while let Some(digit) = self.peek().and_then(ascii_digit) {
            let at = self.offset();
            fold(digit).ok_or_else(|| DurationError::new(ErrorKind::Unrepresentable, at))?;
            let _digit = self.chars.next();
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    /// Parse `digits[.digits]`; the cursor is at an ASCII digit.
    ///
    /// # Errors
    ///
    /// Returns an error for overflow, a point without digits, or whitespace
    /// right after the point followed by more of the number.
    fn number(&mut self) -> Result<Number, DurationError> {
        let mut whole = 0_u64;
        let _count = self.digits(|digit| {
            whole = whole.checked_mul(10)?.checked_add(digit)?;
            Some(())
        })?;
        if self.peek() != Some('.') {
            return Ok(Number {
                whole,
                fraction: None,
            });
        }
        let _point = self.chars.next();
        let mut numerator = 0_u64;
        let mut denominator = 1_u64;
        let count = self.digits(|digit| {
            denominator = denominator.checked_mul(10)?;
            if digit != 0 || numerator != 0 {
                numerator = numerator.checked_mul(10)?.checked_add(digit)?;
            }
            Some(())
        })?;
        if count == 0 {
            let at = self.offset();
            let kind = if self.skip_whitespace() && self.peek().is_some_and(continues_number) {
                ErrorKind::WhitespaceInNumber
            } else {
                ErrorKind::FractionDigitsExpected
            };
            return Err(DurationError::new(kind, at));
        }
        Ok(Number {
            whole,
            fraction: Some(Fraction {
                numerator,
                denominator,
            }),
        })
    }

    /// Parse the unit after a number, ending at whitespace, a digit, or the end.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid character or an unknown unit.
    fn unit(&mut self) -> Result<Unit, DurationError> {
        let start = self.offset();
        while self
            .chars
            .next_if(|&(_, character)| is_unit_char(character))
            .is_some()
        {}
        let end = self.offset();
        if let Some(next) = self.peek()
            && !next.is_whitespace()
            && !next.is_ascii_digit()
        {
            return Err(DurationError::new(ErrorKind::InvalidCharacter, end));
        }
        self.input
            .get(start..end)
            .and_then(Unit::from_name)
            .ok_or_else(|| DurationError::new(ErrorKind::UnknownUnit, start))
    }
}

/// A digit or point after whitespace would continue the number before it.
const fn continues_number(character: char) -> bool {
    character.is_ascii_digit() || character == '.'
}

/// Parse a duration such as `"30s"`, `"1h 30m"`, or `"1.5h"`.
///
/// # Errors
///
/// Returns [`DurationError`] for text outside the grammar in the module
/// documentation, for values that overflow `u64` at any stage, and for
/// fractions that do not convert exactly.
pub(crate) fn parse_duration(input: &str) -> Result<Duration, DurationError> {
    if input == "0" {
        return Ok(Duration::ZERO);
    }
    let mut cursor = Cursor::new(input);
    let _leading = cursor.skip_whitespace();
    if cursor.peek().is_none() {
        return Err(DurationError::new(ErrorKind::Empty, cursor.offset()));
    }
    let mut total = Duration::ZERO;
    loop {
        let group_at = cursor.offset();
        if !cursor.peek().is_some_and(|next| next.is_ascii_digit()) {
            return Err(DurationError::new(ErrorKind::NumberExpected, group_at));
        }
        let number = cursor.number()?;
        let gap_at = cursor.offset();
        if cursor.skip_whitespace() && cursor.peek().is_some_and(continues_number) {
            return Err(DurationError::new(ErrorKind::WhitespaceInNumber, gap_at));
        }
        let unit = cursor.unit()?;
        total =
            add_group(total, number, unit).map_err(|kind| DurationError::new(kind, group_at))?;
        let _between = cursor.skip_whitespace();
        if cursor.peek().is_none() {
            return Ok(total);
        }
    }
}

pub(crate) mod serde_with;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests;
