//! Stateless binding between MCP task IDs and authenticated identities.
//!
//! # Why this exists
//!
//! MCP tasks (SEP-2663) hand the client a long-lived `taskId` that is later
//! presented to `tasks/get`, `tasks/update`, and `tasks/cancel`. Upstream
//! `rmcp` resolves those calls **by task ID alone** -- `TaskManager::get_task`
//! and friends take no principal argument -- and this crate's RBAC layer
//! inspects only `tools/call`. Without the binding in this module, any
//! *authenticated* identity holding another identity's task ID can read,
//! update, or cancel that task.
//!
//! That is the same "leaked identifier becomes a bearer capability" problem
//! [`crate::session_binding`] solves for `Mcp-Session-Id`, so this module
//! mirrors its design: the raw ID never leaves the process unwrapped, and the
//! wrapper is an HMAC over the ID plus the authenticated identity fingerprint.
//!
//! # Relationship to session binding
//!
//! Both features share one operator secret (`session_binding_secret`) but are
//! **domain-separated** by [`TASK_MAC_DOMAIN`]: a session token can never
//! verify as a task token, or vice versa, even under the same key. The token
//! prefixes differ too (`t1.` here, `v1.` for sessions), so the two spaces are
//! visibly disjoint.
//!
//! # Cancel safety
//!
//! Every function here is synchronous and pure, so cancel safety is not
//! applicable: there is no `.await` and no shared mutable state.
use core::str;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac as _;
use subtle::ConstantTimeEq as _;

use crate::session_binding::{IdentityFingerprint, SessionBindingSecret, keyed_mac};

/// Wrapped task-token prefix. Deliberately distinct from the session
/// binding's `v1` so the two token spaces cannot be confused by eye or by
/// a `split('.')` parser.
const TASK_VERSION: &str = "t1";

/// Field separator inside the MAC input, mirroring `session_binding`.
const DOMAIN_SEPARATOR: u8 = 0;

/// Domain-separation label mixed into every task MAC.
///
/// SECURITY: this is what makes sharing one secret with session binding safe.
/// It occupies the same MAC position that `session_binding` fills with its
/// `VERSION` string, so the two pre-images can never coincide.
const TASK_MAC_DOMAIN: &[u8] = b"rmcp-server-kit/task-id-binding/v1";

/// Upper bound on a raw task ID this module will wrap or accept.
///
/// Task IDs are chosen by the consumer's handler and are **not** constrained to
/// a UUID shape, unlike rmcp session IDs. Without an explicit ceiling a caller
/// could submit an unbounded token and force base64 and HMAC work on it, so the
/// bound is enforced before any decoding.
const MAX_RAW_TASK_ID_BYTES: usize = 512;

/// Byte length of the HMAC-SHA256 tag bound into every task token.
const MAC_LEN: usize = 32;
/// Character length of `MAC_LEN` bytes encoded with `URL_SAFE_NO_PAD`.
const MAC_B64_LEN: usize = 43;

/// `URL_SAFE_NO_PAD` expands `n` bytes to `ceil(n * 4 / 3)` characters.
const MAX_RAW_TASK_ID_B64_LEN: usize = MAX_RAW_TASK_ID_BYTES.div_ceil(3) * 4;

/// Upper bound in bytes on any externally supplied wrapped task token.
const MAX_WRAPPED_TASK_TOKEN_LEN: usize =
    TASK_VERSION.len() + 1 + MAX_RAW_TASK_ID_B64_LEN + 1 + MAC_B64_LEN;

/// A task ID as the consumer's handler knows it, after wrapper verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawTaskId(String);

impl RawTaskId {
    /// Accept any non-empty task ID within the size bound.
    ///
    /// Unlike `session_binding::RawSessionId`, this deliberately does **not**
    /// require a UUID shape: SEP-2663 leaves the ID opaque and a consumer may
    /// mint any string.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty() || raw.len() > MAX_RAW_TASK_ID_BYTES {
            return None;
        }
        Some(Self(raw.to_owned()))
    }

    /// Borrow the verified raw task ID as a string slice.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Wrap a raw task ID into an identity-bound external token.
pub(crate) fn wrap(
    secret: &SessionBindingSecret,
    raw_id: &RawTaskId,
    fp: &IdentityFingerprint,
) -> String {
    let mac = compute_mac(secret, raw_id, fp);
    format!(
        "{TASK_VERSION}.{}.{}",
        URL_SAFE_NO_PAD.encode(&raw_id.0),
        URL_SAFE_NO_PAD.encode(mac)
    )
}

/// Verify an external task token and recover the raw task ID.
///
/// SECURITY: the error is deliberately `None` rather than a reason enum.
/// Callers must not be able to distinguish "malformed", "not wrapped",
/// "signed for another identity", or "signed under a rotated secret" -- every
/// failure is reported to the client as the same unknown-task error, so this
/// never becomes an oracle confirming a task's existence to a non-owner.
pub(crate) fn unwrap_and_verify(
    secret: &SessionBindingSecret,
    token: &str,
    fp: &IdentityFingerprint,
) -> Option<RawTaskId> {
    if token.len() > MAX_WRAPPED_TASK_TOKEN_LEN {
        return None;
    }

    let (raw_part, mac_part) = split_token(token)?;
    if mac_part.len() != MAC_B64_LEN || raw_part.is_empty() {
        return None;
    }

    let mut mac = [0_u8; MAC_LEN];
    let mac_len = URL_SAFE_NO_PAD.decode_slice(mac_part, &mut mac).ok()?;
    if mac_len != MAC_LEN {
        return None;
    }

    let raw_bytes = URL_SAFE_NO_PAD.decode(raw_part).ok()?;
    let raw_str = str::from_utf8(&raw_bytes).ok()?;
    let raw_id = RawTaskId::parse(raw_str)?;

    let expected = compute_mac(secret, &raw_id, fp);
    bool::from(expected.ct_eq(&mac)).then_some(raw_id)
}

/// Split `t1.<raw>.<mac>`, rejecting any other shape.
fn split_token(token: &str) -> Option<(&str, &str)> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(TASK_VERSION), Some(raw), Some(mac), None) => Some((raw, mac)),
        _ => None,
    }
}

/// Compute the domain-separated HMAC tag binding `raw_id` to `fp`.
fn compute_mac(
    secret: &SessionBindingSecret,
    raw_id: &RawTaskId,
    fp: &IdentityFingerprint,
) -> [u8; MAC_LEN] {
    let mut mac = keyed_mac(secret);
    mac.update(TASK_MAC_DOMAIN);
    mac.update(&[DOMAIN_SEPARATOR]);
    mac.update(raw_id.0.as_bytes());
    mac.update(&[DOMAIN_SEPARATOR]);
    mac.update(fp.as_bytes());
    mac.finalize().into_bytes().into()
}

#[cfg_attr(
    all(test, target_os = "linux"),
    expect(clippy::expect_used, reason = "lint-migration: src/task_binding.rs")
)]
#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::min_ident_chars,
        reason = "lint-migration: src/task_binding.rs"
    )
)]
#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use secrecy::SecretString;

    use super::{
        MAC_LEN, MAX_RAW_TASK_ID_BYTES, MAX_WRAPPED_TASK_TOKEN_LEN, RawTaskId, unwrap_and_verify,
        wrap,
    };
    use crate::{
        auth::{AuthIdentity, AuthMethod},
        session_binding::{SessionBindingSecret, fingerprint},
    };

    fn secret() -> SessionBindingSecret {
        SessionBindingSecret::Configured(SecretString::from(
            "test-secret-that-is-at-least-32-bytes-long".to_owned(),
        ))
    }

    fn identity(name: &str) -> AuthIdentity {
        AuthIdentity {
            name: name.to_owned(),
            role: "ops".to_owned(),
            method: AuthMethod::BearerToken,
            raw_token: None,
            sub: None,
        }
    }

    #[test]
    fn roundtrip_recovers_the_raw_id() {
        let s = secret();
        let fp = fingerprint(&identity("alice"));
        let raw = RawTaskId::parse("task-abc-123").expect("valid id");
        let token = wrap(&s, &raw, &fp);
        assert!(token.starts_with("t1."), "token must carry the t1 prefix");
        assert!(
            !token.contains("task-abc-123"),
            "raw id must not appear verbatim in the token"
        );
        assert_eq!(unwrap_and_verify(&s, &token, &fp), Some(raw));
    }

    #[test]
    fn another_identity_cannot_verify_the_token() {
        let s = secret();
        let alice = fingerprint(&identity("alice"));
        let bob = fingerprint(&identity("bob"));
        let raw = RawTaskId::parse("task-abc-123").expect("valid id");
        let token = wrap(&s, &raw, &alice);
        assert_eq!(
            unwrap_and_verify(&s, &token, &bob),
            None,
            "a token minted for alice must not verify for bob"
        );
    }

    #[test]
    fn raw_unwrapped_id_is_rejected() {
        let s = secret();
        let fp = fingerprint(&identity("alice"));
        assert_eq!(unwrap_and_verify(&s, "task-abc-123", &fp), None);
        assert_eq!(
            unwrap_and_verify(&s, "550e8400-e29b-41d4-a716-446655440000", &fp),
            None
        );
    }

    #[test]
    fn a_different_secret_does_not_verify() {
        let fp = fingerprint(&identity("alice"));
        let raw = RawTaskId::parse("task-abc-123").expect("valid id");
        let token = wrap(&secret(), &raw, &fp);
        let rotated = SessionBindingSecret::Configured(SecretString::from(
            "a-completely-different-secret-over-32-bytes".to_owned(),
        ));
        assert_eq!(unwrap_and_verify(&rotated, &token, &fp), None);
    }

    /// SECURITY: the crux of sharing one secret with session binding. A session
    /// token must never verify as a task token, nor the reverse.
    #[test]
    fn session_and_task_tokens_are_domain_separated() {
        use crate::session_binding::{
            RawSessionId, unwrap_and_verify as session_unwrap, wrap as session_wrap,
        };

        let s = secret();
        let fp = fingerprint(&identity("alice"));
        let uuid = "550e8400-e29b-41d4-a716-446655440000";

        let raw_session = RawSessionId::parse(uuid).expect("valid uuid");
        let session_token = session_wrap(&s, &raw_session, &fp);
        assert_eq!(
            unwrap_and_verify(&s, &session_token, &fp),
            None,
            "a session token must not verify as a task token"
        );

        let raw_task = RawTaskId::parse(uuid).expect("valid id");
        let task_token = wrap(&s, &raw_task, &fp);
        assert!(
            session_unwrap(&s, &task_token, &fp).is_err(),
            "a task token must not verify as a session token"
        );
    }

    #[test]
    fn oversized_token_is_rejected_before_decoding() {
        let s = secret();
        let fp = fingerprint(&identity("alice"));
        let huge = format!(
            "t1.{}.{}",
            "A".repeat(MAX_WRAPPED_TASK_TOKEN_LEN),
            "B".repeat(43)
        );
        assert_eq!(unwrap_and_verify(&s, &huge, &fp), None);
    }

    #[test]
    fn empty_and_oversized_raw_ids_are_rejected() {
        assert_eq!(RawTaskId::parse(""), None);
        assert_eq!(
            RawTaskId::parse(&"x".repeat(MAX_RAW_TASK_ID_BYTES + 1)),
            None
        );
        assert!(RawTaskId::parse(&"x".repeat(MAX_RAW_TASK_ID_BYTES)).is_some());
    }

    #[test]
    fn malformed_shapes_are_rejected() {
        let s = secret();
        let fp = fingerprint(&identity("alice"));
        for bad in ["", "t1", "t1.", "t1.a", "v1.a.b", "t1.a.b.c", "t2.a.b"] {
            assert_eq!(unwrap_and_verify(&s, bad, &fp), None, "must reject {bad:?}");
        }
    }

    /// Build a secret that varies per generated byte.
    fn prop_secret(byte: u8) -> SessionBindingSecret {
        SessionBindingSecret::Process([byte; MAC_LEN])
    }

    /// A bounded, non-empty raw task ID (the only shape `parse` accepts).
    fn prop_task_id_strategy() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-]{1,64}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// Wrapping a raw task ID for an identity and then verifying with the
        /// same secret and identity must recover exactly that raw ID.
        #[test]
        fn prop_wrap_then_verify_roundtrips(
            secret_byte in any::<u8>(),
            raw in prop_task_id_strategy(),
            name in "[a-zA-Z0-9]{1,20}",
        ) {
            let secret = prop_secret(secret_byte);
            let identity_fp = fingerprint(&identity(&name));
            let raw_id = RawTaskId::parse(&raw)
                .ok_or_else(|| TestCaseError::fail("generated raw id must be bounded and non-empty"))?;
            let token = wrap(&secret, &raw_id, &identity_fp);
            prop_assert_eq!(
                unwrap_and_verify(&secret, &token, &identity_fp),
                Some(raw_id),
                "roundtrip must recover the raw task id"
            );
        }

        /// Flipping any single character of a valid task token must make
        /// verification fail instead of accepting the tampered token.
        #[test]
        fn prop_any_token_tamper_is_rejected(
            raw in prop_task_id_strategy(),
            position in any::<prop::sample::Index>(),
            replacement in any::<char>(),
        ) {
            let secret = prop_secret(7);
            let identity_fp = fingerprint(&identity("tamper"));
            let raw_id = RawTaskId::parse(&raw)
                .ok_or_else(|| TestCaseError::fail("generated raw id must be bounded and non-empty"))?;
            let token = wrap(&secret, &raw_id, &identity_fp);

            let characters = token.chars().collect::<Vec<char>>();
            let target = position.index(characters.len());
            let Some(original) = characters.get(target) else {
                return Ok(());
            };
            let replacement_character = if replacement == *original {
                if *original == '~' { '#' } else { '~' }
            } else {
                replacement
            };
            let mut mutated = String::with_capacity(token.len());
            for (offset, character) in characters.iter().enumerate() {
                if offset == target {
                    mutated.push(replacement_character);
                } else {
                    mutated.push(*character);
                }
            }
            prop_assert_ne!(&mutated, &token, "the mutation must change the token");
            prop_assert!(
                unwrap_and_verify(&secret, &mutated, &identity_fp).is_none(),
                "tampered token {:?} must be rejected",
                mutated
            );
        }

        /// A valid token must not verify under a different identity's
        /// fingerprint: the binding is to one principal only.
        #[test]
        fn prop_wrong_identity_is_rejected(
            raw in prop_task_id_strategy(),
            name in "[a-zA-Z0-9]{1,20}",
            other_name in "[a-zA-Z0-9]{1,20}",
        ) {
            prop_assume!(name != other_name);
            let secret = prop_secret(11);
            let raw_id = RawTaskId::parse(&raw)
                .ok_or_else(|| TestCaseError::fail("generated raw id must be bounded and non-empty"))?;
            let token = wrap(&secret, &raw_id, &fingerprint(&identity(&name)));
            prop_assert!(
                unwrap_and_verify(&secret, &token, &fingerprint(&identity(&other_name))).is_none(),
                "token bound to {:?} must not verify for {:?}",
                name,
                other_name
            );
        }
    }
}
