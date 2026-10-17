//! Integrity-only tokens for the authorization-server proxy.
//!
//! Wire format: `v1.<payload_b64url>.<mac_b64url>`, without base64 padding.
//! Each kind uses HMAC-SHA256(secret UTF-8 bytes,
//! `rmcp-server-kit/oauth-as/v1/` + label) as its signing key. The MAC covers
//! `v1.` + the encoded JSON payload. Sealing provides integrity, not secrecy:
//! payloads contain only data the client already sees. Callers enforce expiry.

use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

/// Maximum encoded token byte length, checked before decoding input.
pub(crate) const MAX_SEALED_LEN: usize = 8192;

/// Cryptographic purpose of a sealed payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealKind {
    /// Registered downstream client metadata.
    Client,
    /// Browser-bound pending consent transaction.
    ConsentRequest,
    /// Approved authorization flow stored in a browser cookie.
    State,
    /// Upstream authorization code bound to a downstream transaction.
    Code,
    /// Remembered browser approvals.
    Consent,
    /// Upstream refresh token bound to a downstream client.
    Refresh,
}

impl SealKind {
    /// Complete purpose set used for eager key derivation.
    const ALL: [Self; 6] = [
        Self::Client,
        Self::ConsentRequest,
        Self::State,
        Self::Code,
        Self::Consent,
        Self::Refresh,
    ];

    /// Stable domain-separation label for this purpose.
    const fn label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::ConsentRequest => "consent_req",
            Self::State => "state",
            Self::Code => "code",
            Self::Consent => "consent",
            Self::Refresh => "refresh",
        }
    }
}

/// Stable errors that never retain token or payload contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SealError {
    /// Encoded token exceeds the bounded wire size.
    #[error("sealed token exceeds length limit")]
    TooLong,
    /// Wire syntax or base64 encoding is invalid.
    #[error("malformed sealed token")]
    Malformed,
    /// Authentication or key initialization failed.
    #[error("sealed token authentication failed")]
    BadMac,
    /// Authenticated JSON cannot represent the requested payload.
    #[error("invalid sealed payload")]
    Payload,
}

/// Initialized purpose keys or their fail-closed construction errors.
type KindKeys = [(SealKind, Result<Hmac<Sha256>, SealError>); 6];

/// Domain-separated current signing keys and optional previous verifying keys.
pub(crate) struct Sealer {
    /// Active signing and verification keys.
    current: KindKeys,
    /// Retired keys accepted only during verification.
    previous: Option<KindKeys>,
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            current: _,
            previous: _,
        } = self;
        f.debug_struct("Sealer")
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl Sealer {
    /// Derive all purpose keys; construction errors remain fail-closed.
    pub(crate) fn new(current: &SecretString, previous: Option<&SecretString>) -> Self {
        Self {
            current: derive_keys(current),
            previous: previous.map(derive_keys),
        }
    }

    /// Serialize and authenticate a payload using only the current key.
    ///
    /// # Errors
    /// Returns `Payload` for serialization failure, `TooLong` for oversized
    /// output, or `BadMac` if key construction fails.
    pub(crate) fn seal<T>(&self, kind: SealKind, payload: &T) -> Result<String, SealError>
    where
        T: Serialize,
    {
        let encoded = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).map_err(|_error| SealError::Payload)?);
        let mut mac = keyed_mac(&self.current, kind)?;
        mac.update(b"v1.");
        mac.update(encoded.as_bytes());
        let token = format!(
            "v1.{encoded}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        );
        (token.len() <= MAX_SEALED_LEN).ok_or(SealError::TooLong)?;
        Ok(token)
    }

    /// Authenticate before decoding the payload into the caller's type.
    ///
    /// # Errors
    /// Returns `TooLong` before decoding oversized input, `Malformed` for wire
    /// syntax or encoding errors, `BadMac` for authentication failure, and
    /// `Payload` for authenticated JSON that cannot deserialize into `T`.
    pub(crate) fn open<T>(&self, kind: SealKind, token: &str) -> Result<T, SealError>
    where
        T: DeserializeOwned,
    {
        (token.len() <= MAX_SEALED_LEN).ok_or(SealError::TooLong)?;
        let mut parts = token.split('.');
        let (encoded, encoded_tag) = match (parts.next(), parts.next(), parts.next(), parts.next())
        {
            (Some("v1"), Some(payload), Some(mac), None) if !payload.is_empty() => (payload, mac),
            _ => return Err(SealError::Malformed),
        };
        let tag = URL_SAFE_NO_PAD
            .decode(encoded_tag)
            .map_err(|_error| SealError::Malformed)?;
        let mut mac = keyed_mac(&self.current, kind)?;
        mac.update(b"v1.");
        mac.update(encoded.as_bytes());
        if mac.verify_slice(&tag).is_err() {
            let previous = self.previous.as_ref().ok_or(SealError::BadMac)?;
            let mut previous_mac = keyed_mac(previous, kind)?;
            previous_mac.update(b"v1.");
            previous_mac.update(encoded.as_bytes());
            previous_mac
                .verify_slice(&tag)
                .map_err(|_error| SealError::BadMac)?;
        }
        let payload = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_error| SealError::Malformed)?;
        serde_json::from_slice(&payload).map_err(|_error| SealError::Payload)
    }
}

/// Derive independent MAC keys for every sealed-payload purpose.
fn derive_keys(secret: &SecretString) -> KindKeys {
    SealKind::ALL.map(|kind| {
        let key = Hmac::<Sha256>::new_from_slice(secret.expose_secret().as_bytes())
            .map_err(|_error| SealError::BadMac)
            .and_then(|mut mac| {
                mac.update(b"rmcp-server-kit/oauth-as/v1/");
                mac.update(kind.label().as_bytes());
                Hmac::<Sha256>::new_from_slice(&mac.finalize().into_bytes())
                    .map_err(|_error| SealError::BadMac)
            });
        (kind, key)
    })
}

/// Copy the initialized MAC for a purpose.
///
/// # Errors
/// Returns `BadMac` if a purpose is missing or key derivation failed.
fn keyed_mac(keys: &KindKeys, kind: SealKind) -> Result<Hmac<Sha256>, SealError> {
    keys.iter()
        .find(|(purpose, _key)| *purpose == kind)
        .ok_or(SealError::BadMac)?
        .1
        .clone()
}

/// Unix seconds, saturating to zero when the clock precedes the epoch.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// SHA-256 of UTF-8 input, encoded as unpadded base64url.
pub(crate) fn sha256_b64(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::collections::BTreeMap;
    use core::str;
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::{Context as _, ensure};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use proptest::{
        collection::{btree_map, vec as arb_vec},
        prelude::*,
        test_runner::{Config, RngSeed, TestRunner},
    };
    use secrecy::SecretString;
    use sha2::{Digest as _, Sha256};

    use super::{SealError, SealKind, Sealer, now_unix, sha256_b64};

    const KINDS: [SealKind; 6] = SealKind::ALL;

    /// Current-only, rotating-current and rotating-previous protocol fixtures.
    fn verification_cases() -> [(Sealer, &'static str); 3] {
        let current = SecretString::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let previous = SecretString::from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        [
            (
                Sealer::new(&current, None),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                Sealer::new(&current, Some(&previous)),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                Sealer::new(&current, Some(&previous)),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ]
    }

    /// Independent protocol model; no production constants, keys or helpers.
    mod reference {
        use core::iter::once;

        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use sha2::{Digest as _, Sha256};

        #[derive(Debug, PartialEq, Eq)]
        pub(super) enum RefOutcome {
            TooLong,
            Malformed,
            BadMac,
            Payload,
            Ok(Vec<u8>),
        }

        /// Derive a protocol key from exact UTF-8 bytes.
        ///
        /// # Panics
        /// Panics only if HMAC violates its arbitrary-key-length contract.
        pub(super) fn ref_key(secret: &str, kind_label: &str) -> Vec<u8> {
            #[expect(
                clippy::expect_used,
                reason = "invariant: Hmac::new_from_slice accepts every key length"
            )]
            let mut hmac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                .expect("HMAC accepts every key length");
            hmac.update(format!("rmcp-server-kit/oauth-as/v1/{kind_label}").as_bytes());
            hmac.finalize().into_bytes().to_vec()
        }

        /// Authenticate an arbitrary segment, including malformed encodings.
        ///
        /// # Panics
        /// Panics only if HMAC violates its arbitrary-key-length contract.
        pub(super) fn sign(secret: &str, kind_label: &str, segment: &str) -> String {
            #[expect(
                clippy::expect_used,
                reason = "invariant: Hmac::new_from_slice accepts every key length"
            )]
            let mut hmac = Hmac::<Sha256>::new_from_slice(&ref_key(secret, kind_label))
                .expect("HMAC accepts every key length");
            let message = format!("v1.{segment}");
            hmac.update(message.as_bytes());
            format!(
                "{message}.{}",
                URL_SAFE_NO_PAD.encode(hmac.finalize().into_bytes())
            )
        }

        pub(super) fn ref_seal(secret: &str, kind_label: &str, json: &[u8]) -> Option<String> {
            let token = sign(secret, kind_label, &URL_SAFE_NO_PAD.encode(json));
            (token.len() <= 8192).then_some(token)
        }

        pub(super) fn ref_open(
            current: &str,
            previous: Option<&str>,
            kind_label: &str,
            token: &str,
        ) -> RefOutcome {
            if token.len() > 8192 {
                return RefOutcome::TooLong;
            }
            let fields = token.split('.').collect::<Vec<_>>();
            let ["v1", payload, tag] = fields.as_slice() else {
                return RefOutcome::Malformed;
            };
            if payload.is_empty() {
                return RefOutcome::Malformed;
            }
            let Ok(tag_bytes) = URL_SAFE_NO_PAD.decode(tag) else {
                return RefOutcome::Malformed;
            };
            // Compare independent full tags, not production verification state.
            let authentic = once(current).chain(previous).any(|secret| {
                let signed = sign(secret, kind_label, payload);
                signed.rsplit('.').next().is_some_and(|expected| {
                    URL_SAFE_NO_PAD
                        .decode(expected)
                        .is_ok_and(|bytes| bytes == tag_bytes)
                })
            });
            if !authentic {
                return RefOutcome::BadMac;
            }
            let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload) else {
                return RefOutcome::Malformed;
            };
            match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(_) => RefOutcome::Ok(bytes),
                Err(_) => RefOutcome::Payload,
            }
        }

        pub(super) fn ref_sha256_b64(value: &str) -> String {
            URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
        }
    }

    const DOMAINS: [(SealKind, &str); 6] = [
        (SealKind::Client, "client"),
        (SealKind::ConsentRequest, "consent_req"),
        (SealKind::State, "state"),
        (SealKind::Code, "code"),
        (SealKind::Consent, "consent"),
        (SealKind::Refresh, "refresh"),
    ];

    /// Resolve the independent protocol label without the production accessor.
    ///
    /// # Errors
    /// Returns an error when the independent domain table omits a kind.
    fn domain_label(kind: SealKind) -> anyhow::Result<&'static str> {
        DOMAINS
            .into_iter()
            .find_map(|(candidate, label)| (candidate == kind).then_some(label))
            .context("independent kind label")
    }

    /// Convert the independent outcome for a JSON-value reader.
    ///
    /// # Errors
    /// Returns an error if the model emitted invalid JSON as a success.
    fn model_error(
        outcome: reference::RefOutcome,
    ) -> anyhow::Result<Result<serde_json::Value, SealError>> {
        use reference::RefOutcome;
        Ok(match outcome {
            RefOutcome::TooLong => Err(SealError::TooLong),
            RefOutcome::Malformed => Err(SealError::Malformed),
            RefOutcome::BadMac => Err(SealError::BadMac),
            RefOutcome::Payload => Err(SealError::Payload),
            RefOutcome::Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        })
    }

    fn text_strategy() -> BoxedStrategy<String> {
        prop_oneof![
            Just(String::new()),
            Just(" \tMiXeD\0\n\u{a0}e\u{301}\u{1f680} ".to_owned()),
            Just("\0".to_owned()),
            Just("Z".repeat(4096)),
            arb_vec(any::<char>(), 0..64).prop_map(|chars| chars.into_iter().collect()),
        ]
        .boxed()
    }

    fn json_strategy() -> BoxedStrategy<serde_json::Value> {
        let leaf = prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            any::<i64>().prop_map(serde_json::Value::from),
            any::<u64>().prop_map(serde_json::Value::from),
            Just(serde_json::json!(1.25_f64)),
            Just(serde_json::json!(-0.0_f64)),
            text_strategy().prop_map(serde_json::Value::String),
        ];
        leaf.prop_recursive(3, 24, 4, |inner| {
            prop_oneof![
                arb_vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
                btree_map("[a-z]{0,5}", inner, 0..4)
                    .prop_map(|entries| serde_json::Value::Object(entries.into_iter().collect())),
            ]
        })
        .boxed()
    }

    fn model_runner() -> TestRunner {
        TestRunner::new(Config {
            cases: 256,
            rng_seed: RngSeed::Fixed(0x5ea1_0005),
            failure_persistence: None,
            max_shrink_iters: 0,
            ..Config::default()
        })
    }

    /// Generated secrets and structured JSON match the independent wire model.
    ///
    /// # Errors
    /// Returns an error with fixed seed and case on a differential failure.
    #[test]
    fn differential_seal_and_rotation() -> anyhow::Result<()> {
        // Given: fixed seed, arbitrary UTF-8 keys and recursively structured JSON.
        model_runner()
            .run(
                &(text_strategy(), text_strategy(), json_strategy()),
                |(current, previous, payload)| {
                    let current_key = SecretString::from(current.as_str());
                    let previous_key = SecretString::from(previous.as_str());
                    let rotating = Sealer::new(&current_key, Some(&previous_key));
                    let bytes = serde_json::to_vec(&payload)
                        .map_err(|error| TestCaseError::fail(error.to_string()))?;
                    for (kind, label) in DOMAINS {
                        let expected =
                            reference::ref_seal(&current, label, &bytes).ok_or(SealError::TooLong);
                        let actual = rotating.seal(kind, &payload); // When
                        prop_assert_eq!(&actual, &expected, "seed=0x5ea10005 kind={:?}", kind); // Then
                        for secret in [&current, &previous] {
                            if let Some(token) = reference::ref_seal(secret, label, &bytes) {
                                prop_assert_eq!(
                                    rotating.open::<serde_json::Value>(kind, &token),
                                    Ok(payload.clone()),
                                    "seed=0x5ea10005 rotation"
                                );
                            }
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|error| anyhow::anyhow!("seed=0x5ea10005: {error}"))?;
        Ok(())
    }

    fn boundary_tokens() -> [String; 4] {
        [8191_usize, 8192, 8193, 8194].map(|length| {
            format!(
                "{}{}",
                "\u{a0}".repeat(length.checked_div(2).unwrap_or_default()),
                "x".repeat(length.checked_rem(2).unwrap_or_default())
            )
        })
    }

    /// Exact errors and recovered values agree for edited and adversarial tokens.
    ///
    /// # Errors
    /// Returns an error identifying the fixed seed and mismatching token case.
    #[test]
    fn differential_open() -> anyhow::Result<()> {
        // Given: independent signing, edits at generated character boundaries.
        model_runner()
            .run(
                &(text_strategy(), json_strategy(), any::<u16>()),
                |(secret, payload, position)| {
                    let previous = format!("previous:{secret}");
                    let current_key = SecretString::from(secret.as_str());
                    let previous_key = SecretString::from(previous.as_str());
                    let reader = Sealer::new(&current_key, Some(&previous_key));
                    let json = serde_json::to_vec(&payload)
                        .map_err(|error| TestCaseError::fail(error.to_string()))?;
                    for (kind, label) in DOMAINS {
                        let token = reference::sign(&secret, label, &URL_SAFE_NO_PAD.encode(&json));
                        let mut tokens = vec![
                            token.clone(),
                            reference::sign(&previous, label, &URL_SAFE_NO_PAD.encode(&json)),
                            reference::sign("other", label, &URL_SAFE_NO_PAD.encode(&json)),
                            reference::sign(
                                &secret,
                                "unconfigured-kind",
                                &URL_SAFE_NO_PAD.encode(&json),
                            ),
                        ];
                        let offset = usize::from(position)
                            .checked_rem(token.len().saturating_add(1))
                            .unwrap_or_default();
                        for edit in [" ", "\0", "\u{a0}", "=", "+", "/", ".", "V1", "\n", "\t"] {
                            let mut changed = token.clone();
                            changed.insert_str(offset, edit);
                            tokens.push(changed);
                            if offset < token.len() {
                                let mut substituted = token.clone();
                                substituted.replace_range(offset..offset.saturating_add(1), edit);
                                tokens.push(substituted);
                            }
                        }
                        let deleted = format!(
                            "{}{}",
                            token.get(..offset).unwrap_or_default(),
                            token.get(offset.saturating_add(1)..).unwrap_or_default()
                        );
                        tokens.extend([
                            deleted,
                            token.get(..offset).unwrap_or_default().to_owned(),
                            format!("{token}garbage"),
                            format!("{token}."),
                            format!("V1{}", token.get(2..).unwrap_or_default()),
                        ]);
                        let mut segments = token.split('.');
                        if let (Some(version), Some(encoded), Some(tag)) =
                            (segments.next(), segments.next(), segments.next())
                        {
                            tokens.extend([
                                format!("{version}.{tag}.{encoded}"),
                                format!("{version}.{encoded}."),
                                format!("{version}.{encoded}.{tag}="),
                            ]);
                        }
                        for bad in [
                            "",
                            "NDI=",
                            "NDJ",
                            "+/8",
                            "_w",
                            "bm90LWpzb24",
                            "NDIgZ2FyYmFnZQ",
                            "\0",
                            " NDI",
                            "NDI\n",
                        ] {
                            tokens.push(reference::sign(&secret, label, bad));
                        }
                        tokens.extend(boundary_tokens());
                        for (case, candidate) in tokens.iter().enumerate() {
                            let expected = model_error(reference::ref_open(
                                &secret,
                                Some(&previous),
                                label,
                                candidate,
                            ))
                            .map_err(|error| TestCaseError::fail(error.to_string()))?;
                            let actual = reader.open::<serde_json::Value>(kind, candidate); // When
                            prop_assert_eq!(
                                actual,
                                expected,
                                "seed=0x5ea10005 kind={:?} case={} token={:?}",
                                kind,
                                case,
                                candidate
                            ); // Then
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|error| anyhow::anyhow!("seed=0x5ea10005: {error}"))?;
        Ok(())
    }

    /// Random exact UTF-8 bytes hash identically and never enter diagnostics.
    ///
    /// # Errors
    /// Returns an error with the seed and generated case when outputs differ.
    #[test]
    fn differential_hash_and_diagnostics() -> anyhow::Result<()> {
        // Given: arbitrary bytes representable as UTF-8, including NUL edges.
        model_runner()
            .run(&text_strategy(), |secret| {
                let key = SecretString::from(secret.as_str());
                let sealer = Sealer::new(&key, Some(&key));
                let actual = sha256_b64(&secret); // When
                prop_assert_eq!(
                    actual,
                    reference::ref_sha256_b64(&secret),
                    "seed=0x5ea10005 hash"
                ); // Then
                prop_assert_eq!(
                    format!("{sealer:?}"),
                    "Sealer { keys: \"<redacted>\" }",
                    "seed=0x5ea10005 Debug"
                );
                prop_assert_eq!(
                    format!("{sealer:#?}"),
                    "Sealer {\n    keys: \"<redacted>\",\n}",
                    "seed=0x5ea10005 Debug pretty"
                );
                for (error, display, debug) in [
                    (
                        SealError::TooLong,
                        "sealed token exceeds length limit",
                        "TooLong",
                    ),
                    (SealError::Malformed, "malformed sealed token", "Malformed"),
                    (
                        SealError::BadMac,
                        "sealed token authentication failed",
                        "BadMac",
                    ),
                    (SealError::Payload, "invalid sealed payload", "Payload"),
                ] {
                    prop_assert_eq!(error.to_string(), display, "seed=0x5ea10005 Display");
                    prop_assert_eq!(format!("{error:?}"), debug, "seed=0x5ea10005 error Debug");
                }
                Ok(())
            })
            .map_err(|error| anyhow::anyhow!("seed=0x5ea10005: {error}"))?;
        Ok(())
    }

    /// Mixed-case keys retain their exact bytes against a Python HMAC oracle.
    ///
    /// # Errors
    /// Returns an error if key normalization changes either independent result.
    #[test]
    fn seal_preserves_mixed_case_secret() -> anyhow::Result<()> {
        let expected = "v1.NDI.PIpQSimIz-m06w9hllMoM7YbhSIMEqrOFwxIE4z7xbc"; // Given: Python hmac.digest.
        let actual =
            Sealer::new(&SecretString::from("MiXeD-Key"), None).seal(SealKind::Client, &42_u64); // When
        ensure!(
            actual == Ok(expected.to_owned()),
            "mixed-case secret oracle"
        ); // Then
        ensure!(
            reference::ref_seal("MiXeD-Key", "client", b"42").as_deref() == Some(expected),
            "reference HMAC oracle"
        );
        Ok(())
    }

    /// Leading and trailing spaces are HMAC key bytes, not configuration syntax.
    ///
    /// # Errors
    /// Returns an error if either implementation trims the Python fixture key.
    #[test]
    fn seal_preserves_secret_spaces() -> anyhow::Result<()> {
        let expected = "v1.NDI.lOWol9yZzNZCMIsdfTuq0y08WYZ50UOU0YEoKFihlNQ"; // Given
        let actual =
            Sealer::new(&SecretString::from(" key "), None).seal(SealKind::Client, &42_u64); // When
        ensure!(
            actual == Ok(expected.to_owned()),
            "space-bearing secret oracle"
        ); // Then
        ensure!(
            reference::ref_seal(" key ", "client", b"42").as_deref() == Some(expected),
            "reference spaced-key oracle"
        );
        Ok(())
    }

    /// NUL edge bytes remain in the SHA-256 message, checked against Python.
    ///
    /// # Errors
    /// Returns an error when a literal hashlib vector disagrees.
    #[test]
    fn sha256_preserves_nul_edges() -> anyhow::Result<()> {
        for (input, expected) in [
            // Given: hashlib.sha256, urlsafe_b64encode, rstrip("=").
            ("\0a\0", "mPtj9yErt6c40c1tbVHT6WFpsjcQrlETxlEj8CkHSGA"),
            ("\0", "bjQLnP-zepicpUTmu3gKLHiQHT-zNzh2hRGjBhevoB0"),
            ("\0\0", "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh-QQt4YwoJz8c"),
            ("\0a", "Aippeebat6pa5MPl5F9-l3ESp-Y1k4INvsHsc4ok-Tw"),
            ("a\0", "_-mq6qKi1QSBdN8LgFme8Bl-wCTEsFG8mGDP9Y73-fM"),
        ] {
            let actual = sha256_b64(input); // When
            ensure!(actual == expected, "NUL hash oracle"); // Then
            ensure!(
                reference::ref_sha256_b64(input) == expected,
                "reference digest oracle"
            );
        }
        Ok(())
    }

    /// The model agrees with existing Python digest vectors and empty-MAC behavior.
    ///
    /// # Errors
    /// Returns an error if an external vector or the recorded refinement disagrees.
    #[test]
    fn reference_matches_existing_external_vectors() -> anyhow::Result<()> {
        for (input, expected) in [
            (" a", "feWYs_-KmWOOH5v0kmC6oNmOBp3eMtHy4VOttc5HgkI"),
            ("a ", "ZYPc1gVv0yqt0NLQvpIN6Z9v8IuABl5LkUKqpBaTkcs"),
            ("\ta\n", "TZVSlqeLxKIGATiwurSm7aUzVpRN7ktMMD6qTxnCsZ8"),
            ("a\u{a0}", "953u5NeJD-18C9CUjA4fA5aJvSkIfAtiIyqgp1rVo6E"),
            ("", "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"),
            (
                "\u{e9}\u{1f680}\u{6c34}",
                "fqz4N3tgE2uwd0SgPr8SYVZutKo2UGyujmvld03waiw",
            ),
        ] {
            // Given: established external vectors.
            let actual = reference::ref_sha256_b64(input); // When
            ensure!(actual == expected, "reference external vector"); // Then
        }
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                ensure!(
                    reader.open::<u64>(kind, "v1.NDI.") == Err(SealError::BadMac),
                    "empty MAC refinement"
                );
            }
        }
        ensure!(
            reference::ref_open(&"a".repeat(32), None, "client", "v1.NDI.")
                == reference::RefOutcome::BadMac,
            "model empty MAC"
        );
        Ok(())
    }

    /// Multi-byte malformed tokens are bounded by bytes, never character count.
    ///
    /// # Errors
    /// Returns an error if the byte cap or exact boundary precedence changes.
    #[test]
    fn open_caps_unicode_bytes() -> anyhow::Result<()> {
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                for (count, expected) in [(4096, SealError::Malformed), (4097, SealError::TooLong)]
                {
                    let token = "\u{a0}".repeat(count); // Given
                    let actual = reader.open::<u64>(kind, &token); // When
                    ensure!(actual == Err(expected), "NBSP byte boundary"); // Then
                }
            }
        }
        Ok(())
    }

    fn sealer() -> Sealer {
        Sealer::new(&SecretString::from("a".repeat(32)), None)
    }

    /// Exact byte lengths include UTF-8 scalars with an ASCII remainder.
    fn length_text(length: usize, unit: &str) -> String {
        format!(
            "{}{}",
            unit.repeat(length.checked_div(unit.len()).unwrap_or_default()),
            "a".repeat(length.checked_rem(unit.len()).unwrap_or_default())
        )
    }

    /// Check signing, independent recovery and previous-key recovery together.
    ///
    /// # Errors
    /// Returns an error with the secret byte length and purpose on disagreement.
    fn check_secret(secret: &str) -> anyhow::Result<()> {
        let key = SecretString::from(secret);
        let current = SecretString::from("distinct-current-key");
        let writer = Sealer::new(&key, None);
        let rotating = Sealer::new(&current, Some(&key));
        let payload = serde_json::json!({"fixed": [42_u64, "fixture"]});
        let json = serde_json::to_vec(&payload)?;
        for (kind, label) in DOMAINS {
            let token = reference::ref_seal(secret, label, &json).context("small token")?;
            // When: sign and read independently produced tokens on both paths.
            ensure!(
                writer.seal(kind, &payload) == Ok(token.clone()),
                "secret seal len={} kind={kind:?}",
                secret.len()
            );
            for reader in [&writer, &rotating] {
                ensure!(
                    reader.open::<serde_json::Value>(kind, &token) == Ok(payload.clone()),
                    "secret open len={} kind={kind:?}",
                    secret.len()
                );
            }
        }
        Ok(())
    }

    /// Every small secret byte length interoperates in every cryptographic domain.
    ///
    /// # Errors
    /// Returns an error if either deterministic secret pass differs from the model.
    #[test]
    fn sweep_secret_byte_lengths() -> anyhow::Result<()> {
        // Given: all 301 byte lengths, including empty previous keys.
        for length in 0..=300 {
            for unit in ["a", "\u{e9}"] {
                let secret = length_text(length, unit);
                check_secret(&secret)?; // When / Then: independent wire and recovery.
            }
        }
        Ok(())
    }

    /// Digest inputs cover every byte length with UTF-8, whitespace and NUL edges.
    ///
    /// # Errors
    /// Returns an error identifying the exact input whose digest differs.
    #[test]
    fn sweep_hash_byte_lengths() -> anyhow::Result<()> {
        for length in 0..=520 {
            let mut inputs = vec![length_text(length, "a"), length_text(length, "\u{e9}")];
            for edge in [" ", "\t", "\n", "\0"] {
                if length > 0 {
                    let body = "a".repeat(length.saturating_sub(1));
                    inputs.extend([format!("{edge}{body}"), format!("{body}{edge}")]);
                }
                if length > 1 {
                    inputs.push(format!(
                        "{edge}{}{edge}",
                        "a".repeat(length.saturating_sub(2))
                    ));
                }
            }
            for input in inputs {
                // Given: byte-exact fixtures, not character counts.
                let actual = sha256_b64(&input); // When
                ensure!(
                    actual == reference::ref_sha256_b64(&input),
                    "hash input={input:?}"
                ); // Then
            }
        }
        Ok(())
    }

    /// Every representable small JSON byte length preserves exact wire and value.
    ///
    /// # Errors
    /// Returns an error when compact serialization or recovery diverges.
    #[test]
    fn sweep_payload_json_lengths() -> anyhow::Result<()> {
        let reader = sealer();
        // Given: zero-byte JSON is impossible; scalar 0 covers length one.
        for length in 1_usize..=400 {
            for unit in ["a", "\n", "\u{e9}"] {
                let payload = if length == 1 {
                    serde_json::json!(0_u64)
                } else {
                    let budget = length.saturating_sub(2);
                    let width = serde_json::to_vec(unit)?.len().saturating_sub(2);
                    serde_json::Value::String(format!(
                        "{}{}",
                        unit.repeat(budget.checked_div(width).context("unit width")?),
                        "a".repeat(budget.checked_rem(width).context("unit remainder")?)
                    ))
                };
                let json = serde_json::to_vec(&payload)?;
                ensure!(json.len() == length, "fixture JSON byte length");
                for (kind, label) in DOMAINS {
                    let token = reference::ref_seal(&"a".repeat(32), label, &json)
                        .context("small payload")?;
                    let actual = reader.seal(kind, &payload); // When
                    ensure!(
                        actual == Ok(token.clone()),
                        "payload seal length={length} kind={kind:?}"
                    ); // Then
                    ensure!(
                        reader.open::<serde_json::Value>(kind, &token) == Ok(payload.clone()),
                        "payload open length={length} kind={kind:?}"
                    );
                }
            }
        }
        Ok(())
    }

    /// Canonical output straddles the cap without assuming an impossible length.
    ///
    /// # Errors
    /// Returns an error if seal or open disagrees at an adjacent canonical length.
    #[test]
    fn sweep_canonical_cap_boundaries() -> anyhow::Result<()> {
        let reader = sealer();
        for (length, sealed_length) in
            [(6107_usize, 8190), (6108, 8191), (6109, 8193), (6110, 8194)]
        {
            let payload = serde_json::Value::String("a".repeat(length.saturating_sub(2))); // Given
            let json = serde_json::to_vec(&payload)?;
            for (kind, label) in DOMAINS {
                let token = reference::sign(&"a".repeat(32), label, &URL_SAFE_NO_PAD.encode(&json));
                ensure!(token.len() == sealed_length, "canonical cap fixture");
                let expected =
                    reference::ref_seal(&"a".repeat(32), label, &json).ok_or(SealError::TooLong);
                let actual = reader.seal(kind, &payload); // When
                ensure!(actual == expected, "cap seal length={length}"); // Then
                ensure!(
                    reader.open::<serde_json::Value>(kind, &token)
                        == model_error(reference::ref_open(&"a".repeat(32), None, label, &token))?,
                    "cap open length={length}"
                );
            }
        }
        Ok(())
    }

    /// MAC truncations, extensions and version deletions retain exact errors.
    ///
    /// # Errors
    /// Returns an error with payload length and edit when parsing differs.
    #[test]
    fn sweep_token_failure_lengths() -> anyhow::Result<()> {
        let reader = sealer();
        for length in 0..=200 {
            let json = serde_json::to_vec(&"a".repeat(length))?; // Given
            for (kind, label) in DOMAINS {
                let token = reference::sign(&"a".repeat(32), label, &URL_SAFE_NO_PAD.encode(&json));
                let (payload, tag) = parts(&token)?;
                let mut candidates = Vec::new();
                for cut in (1..=5).chain(40..=45) {
                    candidates.push(format!(
                        "v1.{payload}.{}",
                        tag.get(..tag.len().saturating_sub(cut))
                            .context("truncated MAC")?
                    ));
                    candidates.push(format!("{token}{}", "A".repeat(cut)));
                }
                for offset in 0_usize..3 {
                    candidates.push(format!(
                        "{}{}",
                        token.get(..offset).context("prefix")?,
                        token.get(offset.saturating_add(1)..).context("suffix")?
                    ));
                    candidates.push(
                        token
                            .get(offset.saturating_add(1)..)
                            .context("prefix removed")?
                            .to_owned(),
                    );
                }
                for (edit, candidate) in candidates.iter().enumerate() {
                    let expected =
                        model_error(reference::ref_open(&"a".repeat(32), None, label, candidate))?;
                    let actual = reader.open::<serde_json::Value>(kind, candidate); // When
                    ensure!(
                        actual == expected,
                        "token payload length={length} kind={kind:?} edit={edit}"
                    ); // Then
                }
            }
        }
        Ok(())
    }

    /// Byte-value shapes exercise exact key, digest and JSON bytes deterministically.
    ///
    /// # Errors
    /// Returns an error if a first, last or only byte shape changes behavior.
    #[test]
    fn sweep_byte_value_shapes() -> anyhow::Result<()> {
        let reader = sealer();
        for byte in 0_u8..=255 {
            // Given: ASCII bytes are literal; high bytes use their Latin-1 scalar.
            let scalar = char::from(byte);
            for input in [
                scalar.to_string(),
                format!("{scalar}middle"),
                format!("middle{scalar}"),
            ] {
                check_secret(&input)?;
                let actual = sha256_b64(&input); // When
                ensure!(
                    actual == reference::ref_sha256_b64(&input),
                    "byte hash {byte}"
                ); // Then
                let payload = serde_json::Value::String(input);
                let json = serde_json::to_vec(&payload)?;
                for (kind, label) in DOMAINS {
                    let token =
                        reference::sign(&"a".repeat(32), label, &URL_SAFE_NO_PAD.encode(&json));
                    ensure!(
                        reader.seal(kind, &payload) == Ok(token.clone()),
                        "byte payload seal {byte}"
                    );
                    ensure!(
                        reader.open::<serde_json::Value>(kind, &token) == Ok(payload.clone()),
                        "byte payload open {byte}"
                    );
                }
            }
            // Raw bytes also probe invalid UTF-8 and unescaped JSON controls.
            for (raw_reader, secret) in verification_cases() {
                for kind in SealKind::ALL {
                    let label = domain_label(kind)?;
                    let token =
                        reference::sign(secret, label, &URL_SAFE_NO_PAD.encode([b'"', byte, b'"']));
                    ensure!(
                        raw_reader.open::<serde_json::Value>(kind, &token)
                            == model_error(reference::ref_open(secret, None, label, &token))?,
                        "raw JSON byte {byte}"
                    );
                }
            }
        }
        Ok(())
    }

    /// Every wire position and final MAC sextet agrees with strict model parsing.
    ///
    /// # Errors
    /// Returns an error naming the purpose and positional edit on disagreement.
    #[test]
    fn sweep_token_byte_shapes() -> anyhow::Result<()> {
        let current = SecretString::from("shape-current");
        let previous = SecretString::from("");
        let reader = Sealer::new(&current, Some(&previous));
        for (kind, label) in DOMAINS {
            for secret in ["shape-current", ""] {
                let token = reference::sign(secret, label, &URL_SAFE_NO_PAD.encode(b"42")); // Given
                let (payload, tag) = parts(&token)?;
                let mut candidates = Vec::new();
                for byte in 0_u8..=255 {
                    let scalar = char::from(byte);
                    candidates.extend([
                        format!("{scalar}{token}"),
                        format!("{token}{scalar}"),
                        scalar.to_string(),
                    ]);
                }
                for offset in 0..=token.len() {
                    for symbol in ["=", "+", "/", "-", "_"] {
                        let mut candidate = token.clone();
                        candidate.insert_str(offset, symbol);
                        candidates.push(candidate);
                    }
                }
                for byte in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
                    candidates.push(format!(
                        "v1.{payload}.{}{}",
                        tag.get(..42).context("tag prefix")?,
                        char::from(*byte)
                    ));
                }
                for candidate in candidates {
                    let expected = model_error(reference::ref_open(
                        "shape-current",
                        Some(""),
                        label,
                        &candidate,
                    ))?;
                    let actual = reader.open::<serde_json::Value>(kind, &candidate); // When
                    ensure!(
                        actual == expected,
                        "shape kind={kind:?} token={candidate:?}"
                    ); // Then
                }
            }
        }
        Ok(())
    }

    /// Split the test token.
    ///
    /// # Errors
    /// Returns an error if the fixture lacks the expected segments.
    fn parts(token: &str) -> anyhow::Result<(&str, &str)> {
        let mut segments = token.split('.');
        ensure!(segments.next() == Some("v1"), "version");
        Ok((
            segments.next().context("payload")?,
            segments.next().context("MAC")?,
        ))
    }

    /// Independent wire fixture with no Sealer internals or label accessor.
    ///
    /// # Errors
    /// Returns an error if HMAC initialization fails.
    fn signed(secret: &str, kind: SealKind, payload: &str) -> anyhow::Result<String> {
        let mut derivation = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
        derivation
            .update(format!("rmcp-server-kit/oauth-as/v1/{}", domain_label(kind)?).as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&derivation.finalize().into_bytes())?;
        mac.update(format!("v1.{payload}").as_bytes());
        Ok(format!(
            "v1.{payload}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    /// Independently authenticate a version tag with a valid client payload.
    ///
    /// # Errors
    /// Returns an error if HMAC initialization fails.
    fn signed_version(secret: &str, kind: SealKind, version: &str) -> anyhow::Result<String> {
        let payload = URL_SAFE_NO_PAD.encode(b"42");
        let mut derivation = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
        derivation
            .update(format!("rmcp-server-kit/oauth-as/v1/{}", domain_label(kind)?).as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&derivation.finalize().into_bytes())?;
        let authenticated = format!("{version}.{payload}");
        mac.update(authenticated.as_bytes());
        Ok(format!(
            "{authenticated}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    /// Canonical encodings of the adversarial payload fixtures remain usable.
    ///
    /// # Errors
    /// Returns an error if independent signing or typed recovery fails.
    #[test]
    fn open_accepts_canonical_encoding_controls() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                for value in ["42", "\u{ffff}", "\u{10ffff}", ""] {
                    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?); // Given
                    let token = signed(secret, kind, &encoded)?;
                    let result = reader.open::<String>(kind, &token); // When
                    ensure!(result == Ok(value.to_owned()), "canonical fixture opens"); // Then
                }
            }
        }
        Ok(())
    }

    /// A valid MAC cannot make padded payload encoding canonical.
    ///
    /// # Errors
    /// Returns an error if signing or the exact rejection assertion fails.
    #[test]
    fn open_rejects_authenticated_padded_payload() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                for encoded in ["NDI=", "NDI==", "NDI==="] {
                    let token = signed(secret, kind, encoded)?; // Given: MAC covers padding verbatim.
                    let result = reader.open::<u64>(kind, &token); // When
                    ensure!(result == Err(SealError::Malformed), "padded payload"); // Then
                }
            }
        }
        Ok(())
    }

    /// Both standard-alphabet symbols are rejected despite valid authentication.
    ///
    /// # Errors
    /// Returns an error if fixture construction or the rejection assertion fails.
    #[test]
    fn open_rejects_authenticated_standard_alphabet_payload() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec("\u{ffff}")?); // Given
                ensure!(
                    encoded.contains('-') && encoded.contains('_'),
                    "both symbols"
                );
                for changed in [
                    encoded.replace('-', "+"),
                    encoded.replace('_', "/"),
                    encoded.replace('-', "+").replace('_', "/"),
                ] {
                    let token = signed(secret, kind, &changed)?;
                    let result = reader.open::<String>(kind, &token); // When
                    ensure!(result == Err(SealError::Malformed), "standard alphabet"); // Then
                }
            }
        }
        Ok(())
    }

    /// Authenticated whitespace inside or beside a payload is not normalized.
    ///
    /// # Errors
    /// Returns an error if signing or the exact rejection assertion fails.
    #[test]
    fn open_rejects_authenticated_payload_whitespace() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                for space in [" ", "\n", "\t", "\r\n", "\0", "\u{a0}"] {
                    for encoded in [
                        format!("N{space}DI"),
                        format!("{space}NDI"),
                        format!("NDI{space}"),
                    ] {
                        let token = signed(secret, kind, &encoded)?; // Given: exact encoding authenticated.
                        let result = reader.open::<u64>(kind, &token); // When
                        ensure!(result == Err(SealError::Malformed), "payload whitespace"); // Then
                    }
                }
            }
        }
        Ok(())
    }

    /// Surrounding whitespace or NUL never repairs a genuine sealed token.
    ///
    /// # Errors
    /// Returns an error if sealing or the exact rejection assertion fails.
    #[test]
    fn open_rejects_whitespace_around_genuine_token() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, "NDI")?; // Given
                for space in [" ", "\n", "\t", "\r\n", "\0", "\u{a0}"] {
                    for changed in [
                        format!("{space}{token}"),
                        format!("{token}{space}"),
                        format!("{space}{token}{space}"),
                    ] {
                        let result = reader.open::<u64>(kind, &changed); // When
                        ensure!(result == Err(SealError::Malformed), "token whitespace"); // Then
                    }
                }
            }
        }
        Ok(())
    }

    /// The genuine unpadded token used by whitespace attacks opens unchanged.
    ///
    /// # Errors
    /// Returns an error if sealing or the positive control assertion fails.
    #[test]
    fn open_accepts_genuine_unpadded_token_control() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, "NDI")?; // Given
                let result = reader.open::<u64>(kind, &token); // When
                ensure!(result == Ok(42), "unchanged token opens"); // Then
            }
        }
        Ok(())
    }

    /// Empty payloads and additional segments stay malformed with authentic tags.
    ///
    /// # Errors
    /// Returns an error if signing or the structural rejection assertion fails.
    #[test]
    fn open_rejects_authenticated_segment_count_and_empty_payload() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, "NDI")?; // Given
                for changed in [
                    signed(secret, kind, "")?,
                    format!("{token}."),
                    format!("{token}.."),
                    format!("{token}.extra"),
                    format!(".{token}"),
                ] {
                    let result = reader.open::<u64>(kind, &changed); // When
                    ensure!(
                        result == Err(SealError::Malformed),
                        "exact segment structure"
                    ); // Then
                }
            }
        }
        Ok(())
    }

    /// MAC syntax remains strict on both current and previous verification paths.
    ///
    /// # Errors
    /// Returns an error if fixture preparation or the encoding assertion fails.
    #[test]
    fn open_rejects_noncanonical_authentic_mac_encoding() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, "NDA")?; // Given
                let (payload, tag) = parts(&token)?;
                let standard = tag.replace('-', "+").replace('_', "/");
                let standard_encoding = if standard == tag {
                    format!("+{tag}")
                } else {
                    standard
                };
                for changed in [
                    format!("{tag}="),
                    standard_encoding,
                    format!(" {tag}"),
                    format!("{tag}\n"),
                ] {
                    let result = reader.open::<u64>(kind, &format!("v1.{payload}.{changed}")); // When
                    ensure!(result == Err(SealError::Malformed), "noncanonical MAC"); // Then
                }
            }
        }
        Ok(())
    }

    /// Nonzero unused base64 bits are rejected even with an authentic MAC.
    ///
    /// # Errors
    /// Returns an error if signing or the strict decoding assertion fails.
    #[test]
    fn open_rejects_authenticated_noncanonical_payload_bits() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, "NDJ")?; // Given: same decoded bytes as NDI in a lenient decoder.
                let result = reader.open::<u64>(kind, &token); // When
                ensure!(result == Err(SealError::Malformed), "unused payload bits"); // Then
            }
        }
        Ok(())
    }

    /// JSON parsing consumes the complete authenticated document.
    ///
    /// # Errors
    /// Returns an error if signing or the payload rejection assertion fails.
    #[test]
    fn open_rejects_authenticated_trailing_json_garbage() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                for json in ["42 garbage", "42 43", "42\0", "42{}"] {
                    let token = signed(secret, kind, &URL_SAFE_NO_PAD.encode(json))?; // Given
                    let result = reader.open::<u64>(kind, &token); // When
                    ensure!(result == Err(SealError::Payload), "complete JSON document"); // Then
                }
            }
        }
        Ok(())
    }

    /// Non-object JSON cannot deserialize into a required object payload.
    ///
    /// # Errors
    /// Returns an error if signing or the typed payload assertion fails.
    #[test]
    fn open_rejects_authenticated_nonobject_json() -> anyhow::Result<()> {
        #[derive(Debug, PartialEq, serde::Deserialize)]
        struct Payload {
            exp: u64,
        }
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                for json in ["null", "42", "true", "\"fixture\"", "[]", "{}"] {
                    let token = signed(secret, kind, &URL_SAFE_NO_PAD.encode(json))?; // Given
                    let result = reader.open::<Payload>(kind, &token); // When
                    ensure!(result == Err(SealError::Payload), "required typed object"); // Then
                }
            }
        }
        Ok(())
    }

    /// Sealing interoperates byte-for-byte with the independent wire signer.
    ///
    /// # Errors
    /// Returns an error if signing or the wire interoperability assertion fails.
    #[test]
    fn seal_matches_independent_canonical_wire() -> anyhow::Result<()> {
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                for value in ["", "a", "\u{ffff}", "\u{10ffff}"] {
                    let expected = signed(
                        &"a".repeat(32),
                        kind,
                        &URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?),
                    )?; // Given
                    let result = reader.seal(kind, &value); // When
                    ensure!(result == Ok(expected), "canonical independent wire"); // Then
                }
            }
        }
        Ok(())
    }

    /// Structured fields retain compact JSON bytes in declaration order.
    ///
    /// # Errors
    /// Returns an error if signing, sealing or the exact wire assertion fails.
    #[test]
    fn seal_matches_compact_struct_wire() -> anyhow::Result<()> {
        #[derive(serde::Serialize)]
        struct Payload<'payload> {
            z: &'payload str,
            count: u64,
            active: bool,
            absent: Option<u64>,
        }
        // Given: literal JSON is independent of the serializer under test.
        let payload = Payload {
            z: "first",
            count: 42,
            active: true,
            absent: None,
        };
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                let expected = signed(
                    &"a".repeat(32),
                    kind,
                    &URL_SAFE_NO_PAD
                        .encode(br#"{"z":"first","count":42,"active":true,"absent":null}"#),
                )?;
                let result = reader.seal(kind, &payload); // When
                ensure!(result == Ok(expected), "compact declaration-order wire"); // Then
            }
        }
        Ok(())
    }

    /// Nested arrays and objects retain compact numeric JSON encodings.
    ///
    /// # Errors
    /// Returns an error if signing, sealing or the exact wire assertion fails.
    #[test]
    fn seal_matches_compact_nested_wire() -> anyhow::Result<()> {
        // Given: nested arrays, object keys, floats and integer precision.
        let payload = (
            [1_u64, 2, 0x0020_0000_0000_0001],
            BTreeMap::from([("nested", (false, [1.0_f64, -0.0_f64, 1.25_f64]))]),
        );
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                let expected = signed(
                    &"a".repeat(32),
                    kind,
                    &URL_SAFE_NO_PAD
                        .encode(br#"[[1,2,9007199254740993],{"nested":[false,[1.0,-0.0,1.25]]}]"#),
                )?;
                let result = reader.seal(kind, &payload); // When
                ensure!(result == Ok(expected), "compact nested numeric wire"); // Then
            }
        }
        Ok(())
    }

    /// UTF-8 stays literal while JSON control characters are escaped exactly.
    ///
    /// # Errors
    /// Returns an error if signing, sealing or the exact wire assertion fails.
    #[test]
    fn seal_matches_compact_unicode_escape_wire() -> anyhow::Result<()> {
        let payload = ["\u{e9}\u{1f680}\u{6c34}\"\\\n\r\t\u{8}\u{c}\0/<>&"]; // Given
        let json = "[\"\u{e9}\u{1f680}\u{6c34}\\\"\\\\\\n\\r\\t\\b\\f\\u0000/<>&\"]";
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                let expected = signed(
                    &"a".repeat(32),
                    kind,
                    &URL_SAFE_NO_PAD.encode(json.as_bytes()),
                )?;
                let result = reader.seal(kind, &payload); // When
                ensure!(result == Ok(expected), "exact UTF-8 and JSON escapes"); // Then
            }
        }
        Ok(())
    }

    /// Every purpose interoperates with its independently derived protocol key.
    ///
    /// # Errors
    /// Returns an error if independent HMAC construction or wire comparison fails.
    #[test]
    fn seal_matches_independent_kind_domains() -> anyhow::Result<()> {
        for (kind, label) in [
            (SealKind::Client, "client"),
            (SealKind::ConsentRequest, "consent_req"),
            (SealKind::State, "state"),
            (SealKind::Code, "code"),
            (SealKind::Consent, "consent"),
            (SealKind::Refresh, "refresh"),
        ] {
            let mut derivation = Hmac::<Sha256>::new_from_slice(&[b'a'; 32])?; // Given
            derivation.update(format!("rmcp-server-kit/oauth-as/v1/{label}").as_bytes());
            let mut mac = Hmac::<Sha256>::new_from_slice(&derivation.finalize().into_bytes())?;
            mac.update(b"v1.NDI");
            let expected = format!(
                "v1.NDI.{}",
                URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
            );
            let result = sealer().seal(kind, &42_u64); // When
            ensure!(result == Ok(expected), "independent kind domain"); // Then
        }
        Ok(())
    }

    /// Serialization failures return a payload error without emitting a token.
    ///
    /// # Errors
    /// Returns an error if the serialization failure assertion fails.
    #[test]
    fn seal_rejects_unserializable_payload() -> anyhow::Result<()> {
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                let payload = BTreeMap::from([(vec![1_u64], 42_u64)]); // Given
                let result = reader.seal(kind, &payload); // When
                ensure!(
                    result == Err(SealError::Payload),
                    "JSON rejects structured map key"
                ); // Then
            }
        }
        Ok(())
    }

    /// Authenticated non-UTF-8 JSON remains a payload error.
    ///
    /// # Errors
    /// Returns an error if signing or the strict JSON assertion fails.
    #[test]
    fn open_rejects_authenticated_non_utf8_json() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, &URL_SAFE_NO_PAD.encode([b'"', 0xff, b'"']))?; // Given
                let result = reader.open::<String>(kind, &token); // When
                ensure!(result == Err(SealError::Payload), "UTF-8 is not repaired"); // Then
            }
        }
        Ok(())
    }

    /// JSON whitespace is payload data, unlike whitespace in wire encoding.
    ///
    /// # Errors
    /// Returns an error if signing or the valid JSON whitespace assertion fails.
    #[test]
    fn open_accepts_authenticated_json_whitespace() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, &URL_SAFE_NO_PAD.encode(" \t42\r\n"))?; // Given
                let result = reader.open::<u64>(kind, &token); // When
                ensure!(result == Ok(42), "JSON whitespace remains valid"); // Then
            }
        }
        Ok(())
    }

    /// Noncanonical MAC trailing bits cannot alias an authentic decoded tag.
    ///
    /// # Errors
    /// Returns an error if fixture preparation or the strict MAC assertion fails.
    #[test]
    fn open_rejects_noncanonical_authentic_mac_bits() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, "NDI")?; // Given
                let (payload, mac) = parts(&token)?;
                let mut bytes = mac.as_bytes().to_vec();
                let last = bytes.last_mut().context("MAC final character")?;
                let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let index = alphabet
                    .iter()
                    .position(|byte| byte == last)
                    .context("MAC sextet")?;
                *last = *alphabet
                    .get(index.checked_add(1).context("sextet increment")?)
                    .context("noncanonical sextet")?;
                let changed = format!("v1.{payload}.{}", String::from_utf8(bytes)?);
                let result = reader.open::<u64>(kind, &changed); // When
                ensure!(result == Err(SealError::Malformed), "unused MAC bits"); // Then
            }
        }
        Ok(())
    }

    /// The independent version fixture opens when its tag is supported.
    ///
    /// # Errors
    /// Returns an error if fixture signing, opening or the assertion fails.
    #[test]
    fn open_accepts_independently_signed_v1() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed_version(secret, kind, "v1")?; // Given
                let result = reader.open::<u64>(kind, &token); // When
                ensure!(result == Ok(42), "independent v1 fixture opens"); // Then
            }
        }
        Ok(())
    }

    /// Unsupported tags are malformed even with a correct MAC for that tag.
    ///
    /// # Errors
    /// Returns an error if fixture signing or a version rejection assertion fails.
    #[test]
    fn open_rejects_authenticated_unsupported_versions() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                for version in ["v2", "v0", "V1", "v1x", ""] {
                    let token = signed_version(secret, kind, version)?; // Given
                    let result = reader.open::<u64>(kind, &token); // When
                    ensure!(
                        result == Err(SealError::Malformed),
                        "unsupported version {version:?} must be malformed"
                    ); // Then
                    let relabelled_token =
                        signed(secret, kind, "NDI")?.replacen("v1.", &format!("{version}."), 1);
                    ensure!(
                        reader.open::<u64>(kind, &relabelled_token) == Err(SealError::Malformed),
                        "version rejected before MAC"
                    );
                }
            }
        }
        Ok(())
    }

    /// Authentic MAC prefixes and an extended authentic MAC never authenticate.
    ///
    /// # Errors
    /// Returns an error if fixture preparation or a MAC-length assertion fails.
    #[test]
    fn open_rejects_authentic_mac_with_wrong_length() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let label = domain_label(kind)?;
                let token = reference::sign(secret, label, "NDI"); // Given
                let (payload, encoded_mac) = parts(&token)?;
                let authentic_mac = URL_SAFE_NO_PAD.decode(encoded_mac)?;
                for length in (1..=31).chain(33..=40) {
                    let mut changed_mac = authentic_mac.clone();
                    changed_mac.resize(length, 0);
                    let changed = format!("v1.{payload}.{}", URL_SAFE_NO_PAD.encode(changed_mac));
                    let expected = model_error(reference::ref_open(secret, None, label, &changed))?;
                    ensure!(expected == Err(SealError::BadMac), "model MAC length");
                    let result = reader.open::<serde_json::Value>(kind, &changed); // When
                    ensure!(
                        result == expected,
                        "kind={kind:?} authentic MAC length={length} secret={secret:?}"
                    ); // Then
                }
            }
        }
        Ok(())
    }

    /// Current-key tokens remain usable while a distinct previous key is present.
    ///
    /// # Errors
    /// Returns an error if sealing or opening with the rotating verifier fails.
    #[test]
    fn open_accepts_current_key_when_previous_is_configured() -> anyhow::Result<()> {
        let current = SecretString::from("a".repeat(32)); // Given
        let previous = SecretString::from("b".repeat(32));
        let rotating = Sealer::new(&current, Some(&previous));
        for kind in KINDS {
            let token = Sealer::new(&current, None).seal(kind, &42_u64)?;
            let result = rotating.open::<u64>(kind, &token); // When
            ensure!(result == Ok(42), "current key opens during rotation"); // Then
        }
        Ok(())
    }

    /// Previous-only writers interoperate with a rotating verifier for every kind.
    ///
    /// # Errors
    /// Returns an error if sealing or opening with the previous key fails.
    #[test]
    fn open_accepts_previous_only_writer_when_rotating() -> anyhow::Result<()> {
        let current = SecretString::from("a".repeat(32)); // Given
        let previous = SecretString::from("b".repeat(32));
        let rotating = Sealer::new(&current, Some(&previous));
        for kind in KINDS {
            let token = Sealer::new(&previous, None).seal(kind, &42_u64)?;
            let result = rotating.open::<u64>(kind, &token); // When
            ensure!(result == Ok(42), "previous-only writer opens"); // Then
        }
        Ok(())
    }

    /// A rotating verifier rejects tokens signed by neither configured secret.
    ///
    /// # Errors
    /// Returns an error if sealing or an unknown-key rejection assertion fails.
    #[test]
    fn open_rejects_unconfigured_key_when_rotating() -> anyhow::Result<()> {
        let current = SecretString::from("a".repeat(32)); // Given
        let previous = SecretString::from("b".repeat(32));
        let other = SecretString::from("c".repeat(32));
        let rotating = Sealer::new(&current, Some(&previous));
        for kind in KINDS {
            let token = Sealer::new(&other, None).seal(kind, &42_u64)?;
            let result = rotating.open::<u64>(kind, &token); // When
            ensure!(result == Err(SealError::BadMac), "unconfigured key rejects"); // Then
        }
        Ok(())
    }

    /// Removing the previous key makes its tokens unauthenticatable.
    ///
    /// # Errors
    /// Returns an error if sealing or a retired-key rejection assertion fails.
    #[test]
    fn open_rejects_previous_only_writer_when_previous_is_absent() -> anyhow::Result<()> {
        let current = SecretString::from("a".repeat(32)); // Given
        let previous = SecretString::from("b".repeat(32));
        let current_only = Sealer::new(&current, None);
        for kind in KINDS {
            let token = Sealer::new(&previous, None).seal(kind, &42_u64)?;
            let result = current_only.open::<u64>(kind, &token); // When
            ensure!(result == Err(SealError::BadMac), "retired key rejects"); // Then
        }
        Ok(())
    }

    /// An authenticated 8192-byte token reaches payload decoding, not the length gate.
    ///
    /// # Errors
    /// Returns an error if fixture signing or the boundary assertion fails.
    #[test]
    fn open_decodes_authenticated_token_at_exact_length_limit() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                // Given: canonical seal output cannot be 8192 bytes; sign invalid base64.
                let token = signed(secret, kind, &"!".repeat(8145))?;
                ensure!(token.len() == 8192, "exact boundary fixture length");
                let result = reader.open::<u64>(kind, &token); // When
                ensure!(
                    result == Err(SealError::Malformed),
                    "boundary reaches decode"
                ); // Then
                ensure!(
                    reader.open::<serde_json::Value>(kind, &token)
                        == model_error(reference::ref_open(
                            secret,
                            None,
                            domain_label(kind)?,
                            &token
                        ))?,
                    "exact-cap input agrees with independent parser"
                );
            }
        }
        Ok(())
    }

    /// An authenticated 8193-byte token is too long before payload decoding.
    ///
    /// # Errors
    /// Returns an error if fixture signing or the length-priority assertion fails.
    #[test]
    fn open_rejects_authenticated_token_above_length_limit() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, &"!".repeat(8146))?; // Given
                ensure!(token.len() == 8193, "first oversized fixture length");
                let result = reader.open::<u64>(kind, &token); // When
                ensure!(
                    result == Err(SealError::TooLong),
                    "length gate precedes decode"
                ); // Then
            }
        }
        Ok(())
    }

    /// The largest canonical string fixture below the limit seals successfully.
    ///
    /// # Errors
    /// Returns an error if sealing or the admitted-length assertion fails.
    #[test]
    fn seal_accepts_canonical_output_just_under_length_limit() -> anyhow::Result<()> {
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                let payload = "x".repeat(6106); // Given: quoted JSON is 6108 bytes.
                let token = reader.seal(kind, &payload)?; // When
                ensure!(token.len() == 8191, "last canonical length below the cap"); // Then
            }
        }
        Ok(())
    }

    /// One more payload byte crosses the sealed-output cap.
    ///
    /// # Errors
    /// Returns an error if signing the independent fixture or rejection fails.
    #[test]
    fn seal_rejects_canonical_output_just_above_length_limit() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let payload = "x".repeat(6107); // Given: quoted JSON is 6109 bytes.
                let fixture = signed(
                    secret,
                    kind,
                    &URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?),
                )?;
                ensure!(
                    fixture.len() == 8193,
                    "first canonical length above the cap"
                );
                let result = reader.seal(kind, &payload); // When
                ensure!(
                    result == Err(SealError::TooLong),
                    "adjacent output exceeds cap"
                ); // Then
            }
        }
        Ok(())
    }

    /// Every kind recovers its original typed payload.
    ///
    /// # Errors
    /// Returns an error if sealing, opening or the assertion fails.
    #[test]
    fn round_trip_per_kind() -> anyhow::Result<()> {
        let sealer = sealer(); // Given
        for kind in KINDS {
            let token = sealer.seal(kind, &vec!["client", "scope"])?; // When
            ensure!(
                sealer.open::<Vec<String>>(kind, &token)? == vec!["client", "scope"],
                "round trip"
            ); // Then
        }
        Ok(())
    }

    /// Only the diagonal of all 36 kind bindings opens.
    ///
    /// # Errors
    /// Returns an error if sealing or a binding assertion fails.
    #[test]
    fn open_rejects_wrong_kind_all_pairs() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for (source_index, source) in SealKind::ALL.into_iter().enumerate() {
                let token = reference::sign(secret, domain_label(source)?, "NDI");
                for (target_index, target) in SealKind::ALL.into_iter().enumerate() {
                    let result = reader.open::<u64>(target, &token);
                    let expected = if source_index == target_index {
                        Ok(42)
                    } else {
                        Err(SealError::BadMac)
                    };
                    ensure!(result == expected, "kind binding");
                }
            }
        }
        Ok(())
    }

    /// A flipped payload byte fails authentication before JSON parsing.
    ///
    /// # Errors
    /// Returns an error if fixture preparation or the assertion fails.
    #[test]
    fn open_rejects_tampered_payload() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, "NDI")?;
                let (payload, mac) = parts(&token)?;
                let mut bytes = URL_SAFE_NO_PAD.decode(payload)?;
                *bytes.first_mut().context("payload byte")? ^= 1;
                let result = reader
                    .open::<u64>(kind, &format!("v1.{}.{mac}", URL_SAFE_NO_PAD.encode(bytes)));
                ensure!(
                    result == Err(SealError::BadMac),
                    "tampered payload must be BadMac"
                );
            }
        }
        Ok(())
    }

    /// A flipped MAC byte fails authentication.
    ///
    /// # Errors
    /// Returns an error if fixture preparation or the assertion fails.
    #[test]
    fn open_rejects_tampered_mac() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let label = domain_label(kind)?;
                let token = reference::sign(secret, label, "NDI"); // Given
                let (payload, mac) = parts(&token)?;
                let authentic = URL_SAFE_NO_PAD.decode(mac)?;
                let mut candidates = vec![vec![0_u8; 32]];
                for position in 0..32 {
                    for bit in 0_u32..8 {
                        let mut changed = authentic.clone();
                        *changed.get_mut(position).context("MAC byte")? ^= 1 << bit;
                        candidates.push(changed);
                    }
                }
                for bytes in candidates {
                    let changed = format!("v1.{payload}.{}", URL_SAFE_NO_PAD.encode(bytes));
                    let expected = model_error(reference::ref_open(secret, None, label, &changed))?;
                    ensure!(expected == Err(SealError::BadMac), "model MAC content");
                    let result = reader.open::<serde_json::Value>(kind, &changed); // When
                    ensure!(result == expected, "tampered MAC kind={kind:?}"); // Then
                }
            }
        }
        Ok(())
    }

    /// Rotation accepts old-current tokens only while that key remains present.
    ///
    /// # Errors
    /// Returns an error if sealing, opening or a rotation assertion fails.
    #[test]
    fn open_accepts_previous_key_during_rotation() -> anyhow::Result<()> {
        let current = SecretString::from("a".repeat(32));
        let previous = SecretString::from("b".repeat(32));
        let next = SecretString::from("c".repeat(32));
        let old = Sealer::new(&current, Some(&previous));
        let rotated = Sealer::new(&next, Some(&current));
        for kind in KINDS {
            let token = old.seal(kind, &42_u64)?;
            ensure!(
                rotated.open::<u64>(kind, &token)? == 42,
                "previous key opens"
            );
            ensure!(
                Sealer::new(&next, Some(&previous)).open::<u64>(kind, &token)
                    == Err(SealError::BadMac),
                "absent key rejects"
            );
        }
        Ok(())
    }

    /// Previous keys are verification-only, never signing keys.
    ///
    /// # Errors
    /// Returns an error if sealing, opening or a signing-key assertion fails.
    #[test]
    fn seal_never_uses_previous() -> anyhow::Result<()> {
        let current = SecretString::from("a".repeat(32));
        let previous = SecretString::from("b".repeat(32));
        let rotating = Sealer::new(&current, Some(&previous));
        for kind in KINDS {
            let token = rotating.seal(kind, &42_u64)?;
            ensure!(
                Sealer::new(&current, None).open::<u64>(kind, &token)? == 42,
                "current signs"
            );
            ensure!(
                Sealer::new(&previous, None).open::<u64>(kind, &token) == Err(SealError::BadMac),
                "previous cannot open new token"
            );
        }
        Ok(())
    }

    /// Different secret domains cannot open each other's tokens.
    ///
    /// # Errors
    /// Returns an error if sealing or a secret-binding assertion fails.
    #[test]
    fn open_rejects_other_secret_both_directions() -> anyhow::Result<()> {
        let left = sealer();
        let right = Sealer::new(&SecretString::from("b".repeat(32)), None);
        for (writer, reader) in [(&left, &right), (&right, &left)] {
            for kind in SealKind::ALL {
                let token = writer.seal(kind, &42_u64)?;
                ensure!(
                    reader.open::<u64>(kind, &token) == Err(SealError::BadMac),
                    "secret binding"
                );
            }
        }
        Ok(())
    }

    /// Oversize rejection precedes even malformed encoding checks.
    ///
    /// # Errors
    /// Returns an error if the length-priority assertion fails.
    #[test]
    fn open_rejects_oversize_before_decode() -> anyhow::Result<()> {
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = "!".repeat(8193);
                let result = reader.open::<u64>(kind, &token);
                ensure!(result == Err(SealError::TooLong), "length gate first");
            }
        }
        Ok(())
    }

    /// Sealing refuses output beyond the wire limit.
    ///
    /// # Errors
    /// Returns an error if the output-cap assertion fails.
    #[test]
    fn seal_rejects_oversize() -> anyhow::Result<()> {
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                let result = reader.seal(kind, &"x".repeat(8192));
                ensure!(result == Err(SealError::TooLong), "output cap");
            }
        }
        Ok(())
    }

    /// A wrapped upstream refresh token of 4096 bytes fits.
    ///
    /// # Errors
    /// Returns an error if sealing, opening or the assertion fails.
    #[test]
    fn refresh_payload_fits() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let value = "x".repeat(4096);
                let token = signed(
                    secret,
                    kind,
                    &URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value)?),
                )?;
                ensure!(
                    reader.open::<String>(kind, &token)? == value,
                    "refresh round trip"
                );
            }
        }
        Ok(())
    }

    /// Version case, segment count, whitespace and invalid encoding fail closed.
    ///
    /// # Errors
    /// Returns an error if a malformed-input assertion fails.
    #[test]
    fn open_rejects_malformed_input() -> anyhow::Result<()> {
        for (reader, _secret) in verification_cases() {
            for kind in SealKind::ALL {
                for token in [
                    "v2.x.y", "v1.x", "v1.x.y.z", "v1.!.!", "V1.x.y", "v1.x.Y ", "", " v1.x.y",
                    "v1..",
                ] {
                    ensure!(
                        reader.open::<u64>(kind, token) == Err(SealError::Malformed),
                        "malformed syntax"
                    );
                }
            }
        }
        Ok(())
    }

    /// Incorrect MAC lengths never authenticate.
    ///
    /// # Errors
    /// Returns an error if fixture preparation or a MAC-length assertion fails.
    #[test]
    fn open_rejects_truncated_and_long_mac() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, "NDI")?;
                let (payload, mac) = parts(&token)?;
                for len in [0, 1, 31, 33, 64] {
                    let changed =
                        format!("v1.{payload}.{}", URL_SAFE_NO_PAD.encode(vec![0_u8; len]));
                    ensure!(
                        reader.open::<u64>(kind, &changed) == Err(SealError::BadMac),
                        "wrong MAC length"
                    );
                }
                ensure!(URL_SAFE_NO_PAD.decode(mac)?.len() == 32, "full SHA256 MAC");
            }
        }
        Ok(())
    }

    /// Authenticated JSON with the wrong type is a payload error.
    ///
    /// # Errors
    /// Returns an error if fixture preparation or the assertion fails.
    #[test]
    fn open_rejects_wrong_json_shape() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(
                    secret,
                    kind,
                    &URL_SAFE_NO_PAD.encode(br#"{"private":"fixture"}"#),
                )?;
                ensure!(
                    reader.open::<u64>(kind, &token) == Err(SealError::Payload),
                    "JSON shape"
                );
            }
        }
        Ok(())
    }

    /// Payload decoding occurs only after MAC verification.
    ///
    /// # Errors
    /// Returns an error if fixture preparation or a verification-order assertion fails.
    #[test]
    fn open_authenticates_before_payload_decode() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(secret, kind, "!")?;
                ensure!(
                    reader.open::<u64>(kind, &token) == Err(SealError::Malformed),
                    "authenticated invalid base64"
                );
                let (_, mac) = parts(&token)?;
                ensure!(
                    reader.open::<u64>(kind, &format!("v1.? .{mac}")) == Err(SealError::BadMac),
                    "unauthenticated payload not decoded"
                );
            }
        }
        Ok(())
    }

    /// Expiry fields remain caller-owned data, not primitive policy.
    ///
    /// # Errors
    /// Returns an error if sealing, opening or the assertion fails.
    #[test]
    fn open_preserves_expiry_without_enforcing_it() -> anyhow::Result<()> {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Payload {
            exp: u64,
        }
        let value = Payload { exp: 0 };
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let token = signed(
                    secret,
                    kind,
                    &URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value)?),
                )?;
                ensure!(
                    reader.open::<Payload>(kind, &token)? == value,
                    "no expiry policy"
                );
            }
        }
        Ok(())
    }

    /// Diagnostic rendering never exposes either secret.
    ///
    /// # Errors
    /// Returns an error if secret redaction fails.
    #[test]
    fn debug_redacts_keys() -> anyhow::Result<()> {
        let secret = "dummy-current-secret-not-for-production";
        let previous = "dummy-previous-secret-not-for-production";
        let rendered = format!(
            "{:?}",
            Sealer::new(
                &SecretString::from(secret),
                Some(&SecretString::from(previous))
            )
        );
        ensure!(
            !rendered.contains(secret) && !rendered.contains(previous),
            "redacted keys"
        );
        Ok(())
    }

    /// Compact and pretty diagnostics expose only the specified redaction marker.
    ///
    /// # Errors
    /// Returns an error if either key configuration exposes diagnostic key data.
    #[test]
    fn debug_has_exact_redacted_shape() -> anyhow::Result<()> {
        let secret = "dummy-current-secret-not-for-production";
        let previous = "dummy-previous-secret-not-for-production";
        let current = SecretString::from(secret);
        let previous_key = SecretString::from(previous);
        for previous_keys in [None, Some(&previous_key)] {
            let sealer = Sealer::new(&current, previous_keys); // Given
            let compact = format!("{sealer:?}"); // When
            let pretty = format!("{sealer:#?}");
            ensure!(
                compact == "Sealer { keys: \"<redacted>\" }",
                "compact Debug must expose only the redaction marker"
            ); // Then
            ensure!(
                pretty == "Sealer {\n    keys: \"<redacted>\",\n}",
                "pretty Debug must expose only the redaction marker"
            );
            for rendered in [&compact, &pretty] {
                ensure!(
                    !rendered.contains(secret) && !rendered.contains(previous),
                    "raw secrets remain redacted"
                );
            }
        }
        Ok(())
    }

    /// Error display never includes rejected payload data.
    ///
    /// # Errors
    /// Returns an error if fixture preparation or payload redaction fails.
    #[test]
    fn error_display_redacts_payload() -> anyhow::Result<()> {
        for (reader, secret) in verification_cases() {
            for kind in SealKind::ALL {
                let value = "private-payload-fixture";
                let token = signed(
                    secret,
                    kind,
                    &URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?),
                )?;
                let error = reader
                    .open::<u64>(kind, &token)
                    .err()
                    .context("wrong shape")?;
                ensure!(!error.to_string().contains(value), "payload redaction");
            }
        }
        Ok(())
    }

    /// SHA256 base64url matches the RFC 7636 appendix B vector.
    ///
    /// # Errors
    /// Returns an error if the known-vector assertion fails.
    #[test]
    fn sha256_matches_pkce_vector() -> anyhow::Result<()> {
        ensure!(
            sha256_b64("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "SHA256 vector"
        );
        Ok(())
    }

    /// Hashing preserves every whitespace and multi-byte UTF-8 input byte.
    ///
    /// # Errors
    /// Returns an error if either independent digest oracle disagrees.
    #[test]
    fn sha256_matches_exact_utf8_vectors() -> anyhow::Result<()> {
        // Given: hex and base64url literals generated with Python hashlib.sha256.
        for (value, hex, encoded) in [
            (
                " a",
                "7de598b3ff8a99638e1f9bf49260baa0d98e069dde32d1f2e153adb5ce478242",
                "feWYs_-KmWOOH5v0kmC6oNmOBp3eMtHy4VOttc5HgkI",
            ),
            (
                "a ",
                "6583dcd6056fd32aadd0d2d0be920de99f6ff08b80065e4b9142aaa4169391cb",
                "ZYPc1gVv0yqt0NLQvpIN6Z9v8IuABl5LkUKqpBaTkcs",
            ),
            (
                "\ta\n",
                "4d955296a78bc4a2060138b0bab4a6eda53356944dee4b4c303eaa4f19c2b19f",
                "TZVSlqeLxKIGATiwurSm7aUzVpRN7ktMMD6qTxnCsZ8",
            ),
            (
                "a\u{a0}",
                "f79deee4d7890fed7c0bd0948c0e1f039689bd29087c0b62232aa0a75ad5a3a1",
                "953u5NeJD-18C9CUjA4fA5aJvSkIfAtiIyqgp1rVo6E",
            ),
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            ),
            (
                "\u{e9}\u{1f680}\u{6c34}",
                "7eacf8377b60136bb07744a03ebf1261566eb4aa36506cae8e6be5774df06a2c",
                "fqz4N3tgE2uwd0SgPr8SYVZutKo2UGyujmvld03waiw",
            ),
        ] {
            let independent = Sha256::digest(value.as_bytes());
            let expected_bytes = hex
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(str::from_utf8(pair)?, 16).map_err(Into::into))
                .collect::<anyhow::Result<Vec<_>>>()?;
            ensure!(
                independent.as_slice() == expected_bytes,
                "Python hex oracle"
            );
            ensure!(
                URL_SAFE_NO_PAD.encode(independent) == encoded,
                "Python base64url oracle"
            );
            let result = sha256_b64(value); // When
            ensure!(result == encoded, "exact input bytes for {value:?}"); // Then
        }
        Ok(())
    }

    /// Unix time is bounded by adjacent system-time samples.
    ///
    /// # Errors
    /// Returns an error if the system clock predates the epoch or the assertion fails.
    #[test]
    fn now_unix_tracks_system_time() -> anyhow::Result<()> {
        let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let actual = now_unix();
        let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        ensure!((before..=after).contains(&actual), "Unix seconds");
        Ok(())
    }
}
