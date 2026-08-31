use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

/// Generic MCP server error type.
///
/// Application crates should define their own error types and convert
/// from/into `RmcpServerKitError` where needed.
///
/// # Client-facing message invariant
///
/// The `String` payloads of [`Auth`](Self::Auth), [`Rbac`](Self::Rbac),
/// [`RateLimited`](Self::RateLimited), and the `message` field of
/// [`RateLimitedFor`](Self::RateLimitedFor) are rendered **verbatim to the
/// HTTP client** by [`IntoResponse`]. Construction sites MUST keep these
/// client-safe: no internal error text, source-error chains, file paths, IPs,
/// SQL, or dependency details. Internal-only variants (`Config`, `Io`, `Json`,
/// `Toml`, `Tls`, `Startup`, `Internal`, `Metrics`) are collapsed to a generic
/// `"internal server error"` body and their detail is logged server-side only.
/// Use [`client_message`](Self::client_message) to obtain the exact body that
/// will be sent to the client for any variant.
///
/// The recurring mistake is interpolating an upstream error into one of these
/// variants - `map_err(|e| Auth(format!("... {e}")))`. That publishes a
/// dependency's error chain to unauthenticated callers, and usually attaches
/// the wrong status besides (a crypto or I/O fault is a `500`, not a `401`).
/// Route such failures to [`Internal`](Self::Internal) instead. A heuristic
/// regression test in this module's test suite scans `src/` for that specific
/// shape; it is a tripwire, not a proof, so the invariant still rests on
/// review.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RmcpServerKitError {
    /// Configuration parsing or validation failed.
    #[error("configuration error: {0}")]
    Config(String),

    /// Authentication failed (bad/missing credential).
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Authorization (RBAC) denied the request.
    #[error("authorization denied: {0}")]
    Rbac(String),

    /// Request was rejected by a rate limiter.
    #[error("rate limited: {0}")]
    RateLimited(String),

    /// Request was rejected by a rate limiter that knows the wait time.
    ///
    /// Renders as HTTP 429 with a `Retry-After` header (RFC 9110
    /// delta-seconds: the duration is rounded **up** to whole seconds,
    /// minimum `1`) and the message as a plain-text body. The legacy
    /// [`RateLimited`](Self::RateLimited) variant remains headerless.
    #[error("rate limited: {message} (retry after {retry_after:?})")]
    RateLimitedFor {
        /// Plain-text client-facing message (response body).
        message: String,
        /// Best-effort wait until the next request could be admitted.
        retry_after: std::time::Duration,
    },

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// TOML parse error (configuration loading).
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    /// TLS configuration failure (certificate load, key parse, rustls config).
    #[error("TLS error: {0}")]
    Tls(String),

    /// Server startup failure (binding, listener, runtime initialization).
    #[error("server startup error: {0}")]
    Startup(String),

    /// Internal failure with no client-actionable cause.
    ///
    /// Detail is logged server-side and collapsed to `"internal server error"`
    /// on the wire. Use this for runtime faults that are neither configuration
    /// nor startup problems -- e.g. a cryptographic primitive failing -- rather
    /// than reaching for a client-facing variant.
    #[error("internal error: {0}")]
    Internal(String),

    /// Metrics registration failure (e.g. Prometheus duplicate or invalid metric).
    #[cfg(feature = "metrics")]
    #[error("metrics error: {0}")]
    Metrics(String),
}

/// Deprecated compatibility alias for the pre-rename public error type.
#[deprecated(
    since = "3.7.0",
    note = "renamed to `RmcpServerKitError`; the `mcpx` name predates the crate rename"
)]
pub type McpxError = RmcpServerKitError;

/// Render a wait [`Duration`](std::time::Duration) as RFC 9110
/// `Retry-After` delta-seconds: rounded **up** to whole seconds, never
/// below `1` (a `0` would invite an immediate retry storm).
fn retry_after_secs(wait: std::time::Duration) -> u64 {
    let mut secs = wait.as_secs();
    if wait.subsec_nanos() > 0 {
        secs = secs.saturating_add(1);
    }
    secs.max(1)
}

impl RmcpServerKitError {
    /// The exact body this error sends to the HTTP client.
    ///
    /// Client-facing variants ([`Auth`](Self::Auth), [`Rbac`](Self::Rbac),
    /// [`RateLimited`](Self::RateLimited), [`RateLimitedFor`](Self::RateLimitedFor))
    /// return their message verbatim; all internal variants return the generic
    /// `"internal server error"` so implementation detail never leaks on the
    /// wire. This is the single source of truth for the client body - the
    /// [`IntoResponse`] impl uses it - so callers can assert or reuse the
    /// client-safe text without duplicating the mapping.
    ///
    /// See the type-level "Client-facing message invariant" for the contract
    /// construction sites must uphold.
    #[must_use]
    pub fn client_message(&self) -> std::borrow::Cow<'_, str> {
        use std::borrow::Cow;
        match self {
            Self::Auth(msg) | Self::Rbac(msg) | Self::RateLimited(msg) => Cow::Borrowed(msg),
            Self::RateLimitedFor { message, .. } => Cow::Borrowed(message),
            // Internal variants: never leak detail to the client.
            Self::Config(_)
            | Self::Io(_)
            | Self::Json(_)
            | Self::Toml(_)
            | Self::Tls(_)
            | Self::Startup(_)
            | Self::Internal(_) => Cow::Borrowed("internal server error"),
            #[cfg(feature = "metrics")]
            Self::Metrics(_) => Cow::Borrowed("internal server error"),
        }
    }
}

impl IntoResponse for RmcpServerKitError {
    fn into_response(self) -> Response {
        let (status, client_msg) = match self {
            Self::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Rbac(msg) => (StatusCode::FORBIDDEN, msg),
            Self::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            Self::RateLimitedFor {
                message,
                retry_after,
            } => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(
                        axum::http::header::RETRY_AFTER,
                        retry_after_secs(retry_after).to_string(),
                    )],
                    message,
                )
                    .into_response();
            }
            // All remaining variants are internal - return a generic 500
            // to avoid leaking implementation details.
            other @ (Self::Config(_)
            | Self::Io(_)
            | Self::Json(_)
            | Self::Toml(_)
            | Self::Tls(_)
            | Self::Startup(_)
            | Self::Internal(_)) => {
                tracing::error!(error = %other, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
            #[cfg(feature = "metrics")]
            other @ Self::Metrics(_) => {
                tracing::error!(error = %other, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
        };
        (status, client_msg).into_response()
    }
}

/// Convenience `Result` alias bound to [`RmcpServerKitError`].
pub type Result<T> = std::result::Result<T, RmcpServerKitError>;

#[cfg(test)]
mod tests {
    use axum::{http::StatusCode, response::IntoResponse};
    use http_body_util::BodyExt;

    use super::*;

    async fn status_of(err: RmcpServerKitError) -> (StatusCode, String) {
        let resp = err.into_response();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn auth_error_returns_401() {
        let (status, body) = status_of(RmcpServerKitError::Auth("bad token".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("bad token"));
    }

    #[tokio::test]
    async fn rbac_error_returns_403() {
        let (status, body) = status_of(RmcpServerKitError::Rbac("denied".into())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("denied"));
    }

    #[tokio::test]
    async fn rate_limited_error_returns_429() {
        let (status, body) = status_of(RmcpServerKitError::RateLimited("slow down".into())).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(body.contains("slow down"));
    }

    #[tokio::test]
    async fn legacy_rate_limited_has_no_retry_after_header() {
        let resp = RmcpServerKitError::RateLimited("slow down".into()).into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            !resp.headers().contains_key(axum::http::header::RETRY_AFTER),
            "legacy variant must stay headerless"
        );
    }

    #[tokio::test]
    async fn rate_limited_for_sets_retry_after_header() {
        let resp = RmcpServerKitError::RateLimitedFor {
            message: "slow down".into(),
            retry_after: std::time::Duration::from_millis(1500),
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let header = resp
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .expect("Retry-After present")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(header, "2", "1.5s must round UP to 2");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"slow down");
    }

    #[test]
    fn retry_after_secs_rounds_up_and_never_zero() {
        use std::time::Duration;
        assert_eq!(retry_after_secs(Duration::ZERO), 1, "zero floors to 1");
        assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(999)), 1);
        assert_eq!(retry_after_secs(Duration::from_secs(1)), 1, "exact stays");
        assert_eq!(retry_after_secs(Duration::from_millis(1001)), 2, "ceil");
        assert_eq!(retry_after_secs(Duration::from_secs(60)), 60);
    }

    #[tokio::test]
    async fn config_error_returns_500() {
        let (status, body) = status_of(RmcpServerKitError::Config("bad".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[tokio::test]
    async fn io_error_returns_500() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let (status, body) = status_of(RmcpServerKitError::from(io_err)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[tokio::test]
    async fn tls_error_returns_500() {
        let (status, body) = status_of(RmcpServerKitError::Tls("bad cert".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[tokio::test]
    async fn startup_error_returns_500() {
        let (status, body) = status_of(RmcpServerKitError::Startup("bind failed".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn metrics_error_returns_500() {
        let (status, body) = status_of(RmcpServerKitError::Metrics("dup metric".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[test]
    fn display_preserves_message() {
        let err = RmcpServerKitError::Auth("unauthorized".into());
        assert_eq!(err.to_string(), "authentication failed: unauthorized");

        let err = RmcpServerKitError::Rbac("forbidden".into());
        assert_eq!(err.to_string(), "authorization denied: forbidden");

        let err = RmcpServerKitError::RateLimited("throttled".into());
        assert_eq!(err.to_string(), "rate limited: throttled");
    }

    #[test]
    fn client_message_exposes_client_facing_text_and_hides_internal_detail() {
        // Client-facing variants: message passes through verbatim.
        assert_eq!(
            RmcpServerKitError::Auth("bad token".into()).client_message(),
            "bad token"
        );
        assert_eq!(
            RmcpServerKitError::Rbac("nope".into()).client_message(),
            "nope"
        );
        assert_eq!(
            RmcpServerKitError::RateLimited("slow down".into()).client_message(),
            "slow down"
        );
        assert_eq!(
            RmcpServerKitError::RateLimitedFor {
                message: "too many".into(),
                retry_after: std::time::Duration::from_secs(1),
            }
            .client_message(),
            "too many"
        );

        // Internal variants: detail is hidden behind a generic body.
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "secret/path/leak");
        assert_eq!(
            RmcpServerKitError::from(io_err).client_message(),
            "internal server error"
        );
        assert_eq!(
            RmcpServerKitError::Tls("private key /etc/certs/server.key".into()).client_message(),
            "internal server error"
        );
        assert_eq!(
            RmcpServerKitError::Config("bind 10.0.0.5:8443 failed".into()).client_message(),
            "internal server error"
        );
    }

    #[tokio::test]
    async fn client_message_matches_into_response_body() {
        // The accessor and the wire body must agree for every variant we test.
        for err in [
            RmcpServerKitError::Auth("a".into()),
            RmcpServerKitError::Rbac("b".into()),
            RmcpServerKitError::RateLimited("c".into()),
            RmcpServerKitError::Config("d".into()),
            RmcpServerKitError::Tls("e".into()),
            RmcpServerKitError::Internal("f".into()),
        ] {
            let expected = err.client_message().into_owned();
            let (_status, body) = status_of(err).await;
            assert_eq!(body, expected, "client_message must equal the wire body");
        }
    }

    #[tokio::test]
    async fn internal_variant_is_500_and_leaks_nothing() {
        let (status, body) = status_of(RmcpServerKitError::Internal(
            "argon2id hashing failed: oom".into(),
        ))
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, "internal server error");
        assert!(
            !body.contains("argon2"),
            "upstream error detail must never reach the client body"
        );
    }

    #[test]
    fn internal_client_message_is_generic() {
        assert_eq!(
            RmcpServerKitError::Internal("salt encoding failed: bad length".into())
                .client_message(),
            "internal server error"
        );
    }

    // -----------------------------------------------------------------
    // Heuristic regression guard for the client-facing message invariant.
    //
    // This is a TRIPWIRE, NOT A PROOF. It catches one specific shape: an
    // upstream error interpolated into a client-facing variant, which is
    // the defect that actually shipped (`generate_api_key` embedded a
    // `password_hash::Error` chain in `Auth`).
    //
    // It does NOT catch: an error bound to a differently-named variable;
    // an error stringified first (`let s = e.to_string()`); a non-error
    // internal detail such as a file path or upstream URL; or anything
    // constructed by a downstream crate. Do not read a pass here as the
    // invariant being enforced -- it is still upheld by review.
    // -----------------------------------------------------------------

    /// Variant constructors whose payload reaches the HTTP client verbatim.
    /// `RateLimited` also substring-matches `RateLimitedFor`, which is
    /// intended -- its `message` field has the same exposure.
    const CLIENT_FACING_CTORS: &[&str] = &[
        "RmcpServerKitError::Auth",
        "RmcpServerKitError::Rbac",
        "RmcpServerKitError::RateLimited",
    ];

    /// Binding names that conventionally hold an upstream error. Kept
    /// deliberately narrow: broadening to `cause`/`detail`/`msg` would
    /// produce false positives on legitimate caller-known echoes.
    const ERROR_BINDINGS: &[&str] = &["e", "err", "error", "source"];

    /// Drop comment lines and everything from the `#[cfg(test)]` test
    /// module onward.
    ///
    /// Comments are stripped so documenting the anti-pattern cannot make
    /// this guard flag its own prose. The test-module cut anchors on
    /// `#[cfg(test)]` *followed by* `mod tests`, because `config.rs`
    /// applies `#[cfg(test)]` to several consts near the top of the file
    /// and cutting at the first occurrence would silently skip the module.
    fn production_source(src: &str) -> String {
        let lines: Vec<&str> = src.lines().collect();
        let mut out = String::with_capacity(src.len());
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed == "#[cfg(test)]"
                && lines
                    .get(i + 1)
                    .is_some_and(|next| next.trim_start().starts_with("mod tests"))
            {
                break;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Return a snippet for every client-facing construction that
    /// interpolates an error-shaped binding.
    fn find_error_interpolations(src: &str) -> Vec<String> {
        let scanned = production_source(src);
        let mut hits = Vec::new();
        for ctor in CLIENT_FACING_CTORS {
            let mut from = 0_usize;
            while let Some(rel) = scanned.get(from..).and_then(|s| s.find(ctor)) {
                let start = from + rel;
                let rest = scanned.get(start..).unwrap_or_default();
                // The construction ends at the statement terminator; cap the
                // window so a missing `;` cannot bleed into later code.
                let end = rest.find(';').map_or(400, |i| i.min(400));
                let window = rest.get(..end).unwrap_or(rest);
                if ERROR_BINDINGS.iter().any(|b| {
                    window.contains(&format!("{{{b}}}"))
                        || window.contains(&format!("{{{b}:"))
                        || window.contains(&format!(", {b})"))
                }) {
                    hits.push(window.split_whitespace().collect::<Vec<_>>().join(" "));
                }
                from = start + ctor.len();
            }
        }
        hits
    }

    #[test]
    fn client_facing_variants_do_not_interpolate_upstream_errors() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let entries = std::fs::read_dir(&src_dir).expect("src/ is readable");
        let mut offenders: Vec<String> = Vec::new();
        let mut scanned_files = 0_usize;
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("source file is readable");
            scanned_files += 1;
            for hit in find_error_interpolations(&src) {
                offenders.push(format!("{}: {hit}", path.display()));
            }
        }
        assert!(
            scanned_files > 10,
            "guard scanned only {scanned_files} files; the walk is broken"
        );
        assert!(
            offenders.is_empty(),
            "client-facing error variants must not carry upstream error text \
             (see the invariant on RmcpServerKitError); use Internal instead:\n{}",
            offenders.join("\n")
        );
    }

    #[test]
    #[allow(
        clippy::literal_string_with_formatting_args,
        reason = "the format-shaped text is the fixture under test, not a format call"
    )]
    fn guard_detects_a_synthetic_violation() {
        // Without this, a broken matcher would be indistinguishable from a
        // clean codebase and the guard would rot into a no-op.
        let offending = "fn f() { RmcpServerKitError::Auth(format!(\"hashing failed: {e}\")); }";
        assert_eq!(find_error_interpolations(offending).len(), 1);

        let positional = "fn f() { RmcpServerKitError::Rbac(format!(\"bad: {}\", err)); }";
        assert_eq!(find_error_interpolations(positional).len(), 1);

        let debug_spec = "fn f() { RmcpServerKitError::RateLimited(format!(\"x {error:?}\")); }";
        assert_eq!(find_error_interpolations(debug_spec).len(), 1);
    }

    #[test]
    fn guard_allows_caller_known_interpolation() {
        // The five real rbac.rs sites echo caller-supplied names on purpose.
        let allowed = "fn f() { RmcpServerKitError::Rbac(format!(\"{tool_name} denied for role '{role}'\")); }";
        assert!(find_error_interpolations(allowed).is_empty());

        let arg = "fn f() { RmcpServerKitError::Rbac(format!(\"argument '{arg_key}' must be a string for tool '{tool_name}'\")); }";
        assert!(find_error_interpolations(arg).is_empty());
    }

    #[test]
    fn guard_ignores_comments_and_test_modules() {
        let in_comment = "/// BAD: RmcpServerKitError::Auth(format!(\"{e}\"))\nfn f() {}";
        assert!(find_error_interpolations(in_comment).is_empty());

        let in_tests = "fn ok() {}\n#[cfg(test)]\nmod tests {\n    RmcpServerKitError::Auth(format!(\"{e}\"));\n}";
        assert!(find_error_interpolations(in_tests).is_empty());

        // A `#[cfg(test)]` const must NOT truncate the scan (config.rs shape).
        let const_then_code = "#[cfg(test)]\nconst X: &[&str] = &[];\nfn f() { RmcpServerKitError::Auth(format!(\"{e}\")); }";
        assert_eq!(find_error_interpolations(const_then_code).len(), 1);
    }
}
