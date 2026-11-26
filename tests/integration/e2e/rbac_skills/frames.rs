//! Frame readers and expected error frames shared by the B4 cases.

use super::*;

/// The exact legacy-protocol error frame for JSON-RPC id 9.
pub(super) fn error_frame(code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 9_u32, "error": { "code": code, "message": message }
    })
}

/// Legacy peers receive resource-not-found as `-32002` (plan G7).
pub(super) fn not_found() -> serde_json::Value {
    error_frame(-32_002, "resource not found")
}

pub(super) fn unknown_skill() -> serde_json::Value {
    error_frame(-32_602, "unknown skill")
}

/// The URIs of a listing frame, in order.
pub(super) fn listed_uris(frame: &serde_json::Value) -> anyhow::Result<Vec<String>> {
    let listed: ListResourcesResult = frame_result(frame)?;
    Ok(listed
        .resources
        .into_iter()
        .map(|entry| entry.uri)
        .collect())
}

/// The cache scope of a result frame.
pub(super) fn cache_scope(frame: &serde_json::Value) -> anyhow::Result<Option<CacheScope>> {
    Ok(frame
        .pointer("/result/cacheScope")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?)
}

pub(super) fn uri_params(uri: &str) -> serde_json::Value {
    serde_json::json!({ "uri": uri })
}

/// The `Config` variant of a failed `validate`, or an error naming the result.
pub(super) fn expect_config_error(config: &RbacConfig) -> anyhow::Result<()> {
    match config.validate() {
        Err(RmcpServerKitError::Config(_)) => Ok(()),
        other => anyhow::bail!("validate must return Config, got {other:?}"),
    }
}
