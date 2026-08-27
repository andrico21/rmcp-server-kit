//! Process-global diagnostic-exposure switches.
//!
//! Several types in this crate carry material that must never reach logs by
//! accident: OAuth access tokens, JWT claim values, and MCP tool-call
//! arguments. Their [`Debug`] implementations and the corresponding
//! `tracing` call sites therefore redact by default.
//!
//! Redaction is nevertheless a debugging obstacle, so each category can be
//! switched to plaintext. [`Debug::fmt`](std::fmt::Debug::fmt) receives only
//! `&self` and a formatter -- it cannot see an
//! [`ObservabilityConfig`](crate::config::ObservabilityConfig) -- so the
//! switches live here as process-global atomics rather than as per-server
//! state.
//!
//! # ⚠️ These switches are process-wide, not per-server
//!
//! A process hosting more than one `rmcp-server-kit` server shares one set of
//! switches. Enabling a switch for one server enables it for **every**
//! `rmcp-server-kit` `Debug` output and gated log site in the process. There
//! is deliberately no per-server override: a `Debug` impl has no request or
//! server context to key off.
//!
//! # ⚠️ Enabling a switch writes secrets to your logs
//!
//! Every switch defaults to the safe (redacted) state and is intended for
//! short-lived local debugging. Never enable one in production.
//!
//! # Setting the switches
//!
//! Consumers loading TOML get this for free: the three
//! `observability.log_*` keys are applied by
//! [`init_tracing_from_config_strict`](crate::observability::init_tracing_from_config_strict).
//! Builder-only consumers that never touch TOML can call
//! [`set_diagnostic_exposure`](crate::diagnostics::set_diagnostic_exposure) directly.
//!
//! ```
//! use rmcp_server_kit::diagnostics::{DiagnosticExposure, set_diagnostic_exposure};
//!
//! // Default is fully redacted.
//! let exposure = DiagnosticExposure::default();
//! set_diagnostic_exposure(&exposure);
//! ```

use std::sync::atomic::{AtomicBool, Ordering};

/// Plaintext OAuth access tokens in `Debug` output.
static PLAINTEXT_OAUTH_TOKENS: AtomicBool = AtomicBool::new(false);
/// Plaintext JWT claim values in exchange/validation logs.
static OAUTH_CLAIM_VALUES: AtomicBool = AtomicBool::new(false);
/// Plaintext tool-call arguments and identity fields in `Debug` output.
static TOOL_CALL_ARGUMENTS: AtomicBool = AtomicBool::new(false);

/// Which categories of sensitive material may be rendered in plaintext.
///
/// Every field defaults to `false`, meaning **redacted**. Enabling a field
/// causes secrets to appear in logs and [`Debug`] output for the entire
/// process; see the [module docs](self) for the full warning.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DiagnosticExposure {
    /// Render OAuth access tokens in plaintext instead of `[REDACTED]`.
    ///
    /// Affects the [`Debug`] implementation of
    /// [`ExchangedToken`](crate::oauth::ExchangedToken).
    pub plaintext_oauth_tokens: bool,
    /// Render JWT claim values (`sub`, `aud`, `azp`, `iss`) in plaintext.
    ///
    /// These are identity, tenant, and deployment-topology identifiers and
    /// may be personally identifying.
    pub oauth_claim_values: bool,
    /// Render tool-call arguments and identity fields in plaintext.
    ///
    /// Affects the [`Debug`] implementation of
    /// [`ToolCallContext`](crate::tool_hooks::ToolCallContext). Tool
    /// arguments routinely carry credentials supplied by the caller.
    pub tool_call_arguments: bool,
}

/// Apply `exposure` to the process-global diagnostic switches.
///
/// Call this before serving. TOML-driven consumers do not need to call it:
/// [`init_tracing_from_config_strict`](crate::observability::init_tracing_from_config_strict)
/// applies the `observability.log_*` keys automatically.
///
/// # ⚠️ Process-wide effect
///
/// This affects every `rmcp-server-kit` server in the process, not just the
/// one you are about to start. See the [module docs](self).
pub fn set_diagnostic_exposure(exposure: &DiagnosticExposure) {
    // Relaxed is sufficient: each flag is an independent boolean that
    // synchronizes no other data, and callers set them during startup before
    // request handling begins.
    PLAINTEXT_OAUTH_TOKENS.store(exposure.plaintext_oauth_tokens, Ordering::Relaxed);
    OAUTH_CLAIM_VALUES.store(exposure.oauth_claim_values, Ordering::Relaxed);
    TOOL_CALL_ARGUMENTS.store(exposure.tool_call_arguments, Ordering::Relaxed);
}

/// Whether OAuth access tokens may be rendered in plaintext.
pub(crate) fn plaintext_oauth_tokens() -> bool {
    PLAINTEXT_OAUTH_TOKENS.load(Ordering::Relaxed)
}

/// Whether JWT claim values may be rendered in plaintext.
#[cfg_attr(
    not(feature = "oauth"),
    allow(
        dead_code,
        reason = "only consumed by the oauth module; kept unconditional so the \
                  switch set is uniform across feature combinations"
    )
)]
pub(crate) fn oauth_claim_values() -> bool {
    OAUTH_CLAIM_VALUES.load(Ordering::Relaxed)
}

/// Whether tool-call arguments may be rendered in plaintext.
pub(crate) fn tool_call_arguments() -> bool {
    TOOL_CALL_ARGUMENTS.load(Ordering::Relaxed)
}

/// Serializes tests that mutate the process-global switches and restores the
/// prior state on drop.
///
/// The switches are process-global, so two tests toggling them concurrently
/// would observe each other's writes. Every test that calls
/// [`set_diagnostic_exposure`] must hold this guard for its whole body.
///
/// The lock is **not** reentrant: acquiring a second guard while one is held
/// on the same thread deadlocks. Never nest guards.
#[cfg(test)]
pub(crate) struct ExposureTestGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    previous: DiagnosticExposure,
}

#[cfg(test)]
impl ExposureTestGuard {
    /// Acquire the global test lock and snapshot the current switch state.
    pub(crate) fn acquire() -> Self {
        static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self {
            _lock: lock,
            previous: DiagnosticExposure {
                plaintext_oauth_tokens: plaintext_oauth_tokens(),
                oauth_claim_values: oauth_claim_values(),
                tool_call_arguments: tool_call_arguments(),
            },
        }
    }
}

#[cfg(test)]
impl Drop for ExposureTestGuard {
    fn drop(&mut self) {
        set_diagnostic_exposure(&self.previous);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DiagnosticExposure, ExposureTestGuard, oauth_claim_values, plaintext_oauth_tokens,
        set_diagnostic_exposure, tool_call_arguments,
    };

    #[test]
    fn default_exposure_is_fully_redacted() {
        let _guard = ExposureTestGuard::acquire();
        set_diagnostic_exposure(&DiagnosticExposure::default());

        assert!(!plaintext_oauth_tokens(), "tokens must default to redacted");
        assert!(!oauth_claim_values(), "claims must default to redacted");
        assert!(!tool_call_arguments(), "arguments must default to redacted");
    }

    #[test]
    fn each_switch_is_independently_settable() {
        let _guard = ExposureTestGuard::acquire();

        set_diagnostic_exposure(&DiagnosticExposure {
            plaintext_oauth_tokens: true,
            ..DiagnosticExposure::default()
        });
        assert!(plaintext_oauth_tokens());
        assert!(!oauth_claim_values());
        assert!(!tool_call_arguments());

        set_diagnostic_exposure(&DiagnosticExposure {
            oauth_claim_values: true,
            ..DiagnosticExposure::default()
        });
        assert!(!plaintext_oauth_tokens());
        assert!(oauth_claim_values());
        assert!(!tool_call_arguments());

        set_diagnostic_exposure(&DiagnosticExposure {
            tool_call_arguments: true,
            ..DiagnosticExposure::default()
        });
        assert!(!plaintext_oauth_tokens());
        assert!(!oauth_claim_values());
        assert!(tool_call_arguments());
    }

    #[test]
    fn guard_restores_previous_state_on_drop() {
        let guard = ExposureTestGuard::acquire();
        set_diagnostic_exposure(&DiagnosticExposure {
            plaintext_oauth_tokens: true,
            oauth_claim_values: true,
            tool_call_arguments: true,
        });
        assert!(plaintext_oauth_tokens());
        drop(guard);

        let _reacquired = ExposureTestGuard::acquire();
        assert!(
            !plaintext_oauth_tokens() && !oauth_claim_values() && !tool_call_arguments(),
            "dropping the guard must restore the pre-acquire state"
        );
    }
}
