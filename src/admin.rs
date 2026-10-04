//! Admin diagnostic endpoints.
//!
//! When enabled, the server exposes a small `/admin/*` surface that returns
//! read-only diagnostic JSON: uptime, active auth configuration (no
//! secrets), auth counters, and an RBAC policy summary.
//!
//! The admin router is always wrapped in the existing auth + RBAC stack
//! and additionally requires the caller's role to match the `role` field
//! on [`crate::admin::AdminConfig`]. Configuration validation refuses to
//! enable admin without auth.
//!
//! # Cancel safety
//!
//! Admin handlers are cancel-safe with respect to admin state: they only
//! read in-memory `Arc` / `ArcSwap` state and build JSON responses.
//! [`crate::admin::require_admin_role`] performs its role check before
//! `next.run(req).await` and holds no guard, lock, or permit across that
//! await; downstream route cancel safety is inherited from Axum and the
//! selected route.

extern crate alloc;

use alloc::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::{Next, from_fn},
    response::{IntoResponse as _, Response},
    routing::get,
};
use serde::Serialize;

use crate::{
    auth::{AuthIdentity, AuthState},
    rbac::RbacPolicy,
};

/// Admin endpoint configuration.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
pub struct AdminConfig {
    /// RBAC role required to access the admin endpoints.
    pub role: String,
}

impl Default for AdminConfig {
    #[inline]
    fn default() -> Self {
        Self {
            role: "admin".to_owned(),
        }
    }
}

/// Shared state used by admin endpoint handlers.
#[derive(Clone)]
#[non_exhaustive]
pub(crate) struct AdminState {
    /// Server start instant, used for uptime.
    pub started_at: Instant,
    /// Server name for /admin/status.
    pub name: String,
    /// Server version for /admin/status.
    pub version: String,
    /// Shared auth state (optional for test constructions).
    pub auth: Option<Arc<AuthState>>,
    /// Shared RBAC policy for diagnostics.
    pub rbac: Arc<ArcSwap<RbacPolicy>>,
}

/// `/admin/status` response body.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "public API frozen until the next major release"
)]
pub struct AdminStatus {
    /// Server name.
    pub name: String,
    /// Server version string.
    pub version: String,
    /// Seconds since the server process started.
    pub uptime_seconds: u64,
    /// Wall-clock UNIX epoch at startup.
    pub started_at_epoch: u64,
}

/// Build the `/admin/status` response body from the live state.
fn admin_status(state: &AdminState) -> AdminStatus {
    let started_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
        .saturating_sub(state.started_at.elapsed().as_secs());
    AdminStatus {
        name: state.name.clone(),
        version: state.version.clone(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        started_at_epoch: started_epoch,
    }
}

/// `/admin/status` handler.
///
/// # Cancel safety
///
/// Reads only in-memory state and builds a JSON response; holds no guard
/// across an await.
async fn status_handler(State(state): State<AdminState>) -> Json<AdminStatus> {
    Json(admin_status(&state))
}

/// `/admin/auth/keys` handler (metadata only, never the hashes).
///
/// # Cancel safety
///
/// Reads only in-memory state and builds a JSON response; holds no guard
/// across an await.
async fn auth_keys_handler(State(state): State<AdminState>) -> Response {
    state.auth.as_ref().map_or_else(
        || not_available("auth is not configured"),
        |auth| Json(auth.api_key_summaries()).into_response(),
    )
}

/// `/admin/auth/counters` handler.
///
/// # Cancel safety
///
/// Reads only in-memory state and builds a JSON response; holds no guard
/// across an await.
async fn auth_counters_handler(State(state): State<AdminState>) -> Response {
    state.auth.as_ref().map_or_else(
        || not_available("auth is not configured"),
        |auth| Json(auth.counters_snapshot()).into_response(),
    )
}

/// `/admin/rbac` handler.
///
/// # Cancel safety
///
/// Reads only in-memory state and builds a JSON response; holds no guard
/// across an await.
async fn rbac_handler(State(state): State<AdminState>) -> Response {
    Json(state.rbac.load().summary()).into_response()
}

/// Build the `503` body shared by the not-configured admin handlers.
fn not_available(reason: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "unavailable",
            "error_description": reason,
        })),
    )
        .into_response()
}

/// Role-check middleware for admin routes.
///
/// Reads the caller's role from the `AuthIdentity` request extension
/// (populated by the outer auth middleware) and rejects requests whose
/// role does not match `expected_role`.
///
/// # Cancel safety
///
/// Performs its role check before `next.run(req).await` and holds no guard,
/// lock, or permit across that await.
#[inline]
pub async fn require_admin_role(
    expected_role: Arc<str>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let role = req
        .extensions()
        .get::<AuthIdentity>()
        .map_or("", |identity| identity.role.as_str());
    if role != expected_role.as_ref() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "error_description": "admin role required",
            })),
        )
            .into_response();
    }
    next.run(req).await
}

/// Build the `/admin` router layered with the admin role check.
///
/// The caller is expected to merge this router on top of their top-level
/// router *after* the auth + RBAC middleware has been installed, so that
/// by the time a request reaches this router the task-local role is set.
pub(crate) fn admin_router(state: AdminState, config: &AdminConfig) -> Router {
    let role: Arc<str> = Arc::from(config.role.as_str());
    Router::new()
        .route("/admin/status", get(status_handler))
        .route("/admin/auth/keys", get(auth_keys_handler))
        .route("/admin/auth/counters", get(auth_counters_handler))
        .route("/admin/rbac", get(rbac_handler))
        .with_state(state)
        .layer(from_fn(move |req, next| {
            let role_for_check = Arc::clone(&role);
            require_admin_role(role_for_check, req, next)
        }))
}

#[cfg_attr(
    all(test, target_os = "linux"),
    expect(clippy::indexing_slicing, reason = "lint-migration: src/admin.rs")
)]
#[cfg_attr(
    all(test, target_os = "linux"),
    expect(clippy::unwrap_used, reason = "lint-migration: src/admin.rs")
)]
#[cfg_attr(
    all(test, target_os = "linux"),
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(test, expect(unused_results, reason = "lint-migration: src/admin.rs"))]
#[cfg_attr(
    test,
    expect(redundant_imports, reason = "lint-migration: src/admin.rs")
)]
#[cfg(test)]
mod tests {

    use axum::http::Request;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        auth::{ApiKeyEntry, AuthCounters, AuthIdentity, AuthMethod, AuthState},
        rbac::{RbacConfig, RbacPolicy, RoleConfig},
    };

    fn make_auth_state() -> Arc<AuthState> {
        Arc::new(AuthState {
            api_keys: ArcSwap::from_pointee(vec![ApiKeyEntry::new(
                "test-key",
                "argon2id-hash",
                "admin",
            )]),
            rate_limiter: None,
            pre_auth_limiter: None,
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: crate::auth::SeenIdentitySet::new(),
            counters: AuthCounters::default(),
            resource_metadata_url: None,
            log_context: crate::auth::AuthLogContext::default(),
        })
    }

    fn make_state() -> AdminState {
        AdminState {
            started_at: Instant::now(),
            name: "test".into(),
            version: "0.0.0".into(),
            auth: Some(make_auth_state()),
            rbac: Arc::new(ArcSwap::from_pointee(RbacPolicy::new(
                &RbacConfig::with_roles(vec![RoleConfig::new(
                    "admin",
                    vec!["*".into()],
                    vec!["*".into()],
                )]),
            ))),
        }
    }

    fn admin_req(uri: &str, role: Option<&str>) -> Request<Body> {
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        if let Some(r) = role {
            req.extensions_mut().insert(AuthIdentity {
                name: "tester".into(),
                role: r.to_owned(),
                method: AuthMethod::BearerToken,
                raw_token: None,
                sub: None,
            });
        }
        req
    }

    #[tokio::test]
    async fn keys_endpoint_omits_hash() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app
            .oneshot(admin_req("/admin/auth/keys", Some("admin")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "test-key");
        assert!(arr[0].get("hash").is_none());
    }

    #[tokio::test]
    async fn wrong_role_gets_403() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app
            .oneshot(admin_req("/admin/status", Some("viewer")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn no_identity_gets_403() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app.oneshot(admin_req("/admin/status", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn status_returns_uptime() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app
            .oneshot(admin_req("/admin/status", Some("admin")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rbac_summary_includes_role_list() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app
            .oneshot(admin_req("/admin/rbac", Some("admin")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["roles"][0]["name"], "admin");
    }
}
