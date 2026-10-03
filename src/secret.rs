//! Re-exports of [`secrecy`] types for handling sensitive values.
//!
//! Downstream crates use these to wrap credentials and secrets so that
//! they are not accidentally logged or serialized.
#![expect(clippy::pub_use, reason = "public facade")]

#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
pub use secrecy::{ExposeSecret, SecretBox, SecretString};
