//! B4 assertions 7, 9 and 10: `subscriptions/listen`, reload and the TOML
//! path.

use super::*;

/// What rmcp 3.11 answers when the handler accepts nothing: HTTP 404 with
/// a single JSON-RPC `-32601` frame and no acknowledgement.
fn listen_refused() -> (u16, Vec<serde_json::Value>) {
    (
        404,
        vec![serde_json::json!({
            "jsonrpc": "2.0", "id": 1_u32,
            "error": { "code": -32_601_i64, "message": "subscriptions/listen" }
        })],
    )
}

/// Assertion 7, restrict mode: an existing denied URI, an absent URI and a
/// skill URI all reach the consumer as the same empty request and get the
/// same refusal with no acknowledgement.
#[tokio::test]
async fn rbac_skills_listen_in_restrict_mode_cannot_reveal_existence() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&main_rbac(&["acme/billing"]))?).await?;

    let mut outcomes = Vec::new();
    for uris in [[PRIV], ["file:///priv/nope.txt"], [BILLING_MD]] {
        outcomes.push(server.listen(&server.analyst, &uris).await?);
    }

    assert_eq!(
        outcomes,
        vec![listen_refused(), listen_refused(), listen_refused()]
    );
    assert_eq!(
        server.handler.calls(),
        vec!["accepted_subscription_filter None".to_owned(); 3]
    );
    Ok(())
}

/// The second server of assertion 7: restrict mode off and `resources`
/// unset for every role.
fn open_rbac() -> RbacConfig {
    RbacConfig::with_roles(vec![
        RoleConfig::new("analyst", vec![], vec!["*".into()]).with_skills(owned(&["acme/billing"])),
        RoleConfig::new("legacy", vec![], vec!["*".into()]),
    ])
    .with_skill_roots(owned(&["file:///srv/skills/"]))
}

/// The acknowledgement rmcp sends for subscription id 1 accepting `uris`.
fn acknowledgement(uris: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/subscriptions/acknowledged",
        "params": {
            "_meta": { "io.modelcontextprotocol/subscriptionId": 1_u32 },
            "notifications": { "resourceSubscriptions": uris }
        }
    })
}

/// Assertion 7, restrict mode off: the consumer's own answer decides, an
/// existing URI is acknowledged, an absent one is refused, and a skill URI
/// never appears in an acknowledgement.
#[tokio::test]
async fn rbac_skills_listen_without_restrict_mode_is_the_consumer_answer() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&open_rbac())?).await?;

    let existing = server.listen(&server.analyst, &[PUB]).await?;
    let absent = server
        .listen(&server.analyst, &["file:///pub/nope.txt"])
        .await?;
    let with_skill = server.listen(&server.analyst, &[PUB, BILLING_MD]).await?;

    let completed = serde_json::json!({
        "jsonrpc": "2.0", "id": 1_u32,
        "result": {
            "_meta": {
                "io.modelcontextprotocol/serverInfo":
                    serde_json::to_value(server.handler.get_info().server_info)?,
                "io.modelcontextprotocol/subscriptionId": 1_u32
            },
            "resultType": "complete"
        }
    });
    assert_eq!(
        existing,
        (200, vec![acknowledgement(&[PUB]), completed.clone()])
    );
    assert_eq!(absent, listen_refused());
    assert_eq!(with_skill, (200, vec![acknowledgement(&[PUB]), completed]));
    Ok(())
}

/// Assertion 9: `ReloadHandle::reload_rbac` grants and revokes `acme/*`
/// without a restart, and deleting `analyst` in restrict mode leaves both
/// ordinary resources denied for a credential that still carries the role.
#[tokio::test]
async fn rbac_skills_reload_grants_revokes_and_deletion_does_not_widen() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&main_rbac(&["acme/billing"]))?).await?;
    let session = server.session(&server.analyst).await?;
    let auth = (server.analyst.as_str(), session.as_str());

    server
        .reload
        .reload_rbac(validated(&main_rbac(&["acme/*"]))?);
    let granted: ReadResourceResult = frame_result(
        &server
            .call(auth, "resources/read", uri_params(HR_MD))
            .await?,
    )?;
    server
        .reload
        .reload_rbac(validated(&main_rbac(&["acme/billing"]))?);
    let revoked = server
        .call(auth, "resources/read", uri_params(HR_MD))
        .await?;
    let deleted = RbacConfig::with_roles(vec![RoleConfig::new("legacy", vec![], vec!["*".into()])])
        .with_skill_roots(owned(&["file:///srv/skills/"]))
        .with_restrict_resources(true);
    server.reload.reload_rbac(validated(&deleted)?);
    let mut after_delete = Vec::new();
    for uri in [PRIV, PUB] {
        after_delete.push(server.call(auth, "resources/read", uri_params(uri)).await?);
    }

    assert_eq!(
        granted.contents,
        vec![ResourceContents::text(format!("body of {HR_MD}"), HR_MD)]
    );
    assert_eq!(revoked, not_found());
    assert_eq!(after_delete, vec![not_found(), not_found()]);
    assert_eq!(
        server.handler.calls(),
        vec![format!("read_resource {HR_MD}")]
    );
    Ok(())
}

/// The main `[rbac]` as an operator writes it in TOML.
const MAIN_RBAC_TOML: &str = r#"
enabled = true
skill_roots = ["file:///srv/skills/"]
restrict_resources = true

[[roles]]
name = "analyst"
skills = ["acme/billing"]
resources = ["file:///pub/*"]

[[roles]]
name = "legacy"
"#;

/// Assertion 10: the TOML form of the main `[rbac]`, after `validate`,
/// lists exactly what the programmatic one lists for `analyst`.
#[tokio::test]
async fn rbac_skills_toml_policy_matches_the_programmatic_one() -> anyhow::Result<()> {
    let config: RbacConfig = toml::from_str(MAIN_RBAC_TOML).context("[rbac] parses")?;
    let server = RbacSkillsServer::start(validated(&config)?).await?;

    let frame = server
        .call_current(&server.analyst, "skills/list", serde_json::json!({}))
        .await?;

    let listed: ListSkillsResult = frame_result(&frame)?;
    assert_eq!(
        listed.skills,
        vec![skill_in("skill://acme/billing/", "billing")]
    );
    assert_eq!(cache_scope(&frame)?, Some(CacheScope::Private));
    Ok(())
}

/// Assertion 10: `validate` rejects an invalid `skills` pattern and a
/// `resources` setting without `restrict_resources = true`.
#[test]
fn rbac_skills_toml_validate_rejects_invalid_settings() -> anyhow::Result<()> {
    let invalid_pattern = MAIN_RBAC_TOML.replace(
        r#"skills = ["acme/billing"]"#,
        r#"skills = ["skill://acme/billing"]"#,
    );
    let unrestricted =
        MAIN_RBAC_TOML.replace("restrict_resources = true", "restrict_resources = false");
    for text in [invalid_pattern, unrestricted] {
        let config: RbacConfig = toml::from_str(&text).context("[rbac] parses")?;
        expect_config_error(&config)?;
    }
    Ok(())
}
