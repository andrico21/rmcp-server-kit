//! B4 assertions 1-6 and 8 on the main server.

use super::*;

/// Assertion 1: `analyst` lists exactly `acme/billing`, marked private.
#[tokio::test]
async fn rbac_skills_analyst_lists_only_the_granted_skill() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&main_rbac(&["acme/billing"]))?).await?;
    let session = server.session(&server.analyst).await?;

    let frame = server
        .call(
            (&server.analyst, &session),
            "skills/list",
            serde_json::json!({}),
        )
        .await?;

    let listed: ListSkillsResult = frame_result(&frame)?;
    assert_eq!(
        listed.skills,
        vec![skill_in("skill://acme/billing/", "billing")]
    );
    assert_eq!(cache_scope(&frame)?, Some(CacheScope::Private));
    assert_eq!(server.handler.calls(), owned(&["list_skills"]));
    Ok(())
}

/// Assertion 2: a denied existing skill, a missing skill and a skill under
/// the extra root give byte-identical "unknown skill" responses.
#[tokio::test]
async fn rbac_skills_get_of_denied_and_missing_skills_is_byte_identical() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&main_rbac(&["acme/billing"]))?).await?;
    let session = server.session(&server.analyst).await?;
    let auth = (server.analyst.as_str(), session.as_str());

    let mut responses = Vec::new();
    for uri in [HR_MD, "skill://acme/nope/SKILL.md", HR2_MD] {
        responses.push(
            server
                .call_text(auth, "skills/get", uri_params(uri))
                .await?,
        );
    }

    let [denied_existing, missing, extra_root] = <[String; 3]>::try_from(responses)
        .map_err(|got| anyhow::anyhow!("expected three responses, got {got:?}"))?;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&denied_existing)?,
        unknown_skill()
    );
    assert_eq!(missing, denied_existing);
    assert_eq!(extra_root, denied_existing);
    assert_eq!(server.handler.calls(), Vec::<String>::new());
    Ok(())
}

/// Assertion 3: reads follow the role's grants, and lexically unsafe URIs
/// are refused before the handler.
#[tokio::test]
async fn rbac_skills_resource_reads_follow_grants_and_canonical_form() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&main_rbac(&["acme/billing"]))?).await?;
    let session = server.session(&server.analyst).await?;
    let auth = (server.analyst.as_str(), session.as_str());

    let mut granted = Vec::new();
    for uri in [BILLING_MD, PUB] {
        let read: ReadResourceResult =
            frame_result(&server.call(auth, "resources/read", uri_params(uri)).await?)?;
        granted.push(read.contents);
    }
    let mut denied = Vec::new();
    for uri in [
        HR_MD,
        PRIV,
        "file:///pub/../priv/b.txt",
        "file:///pub/%2e%2e/priv/b.txt",
    ] {
        denied.push(server.call(auth, "resources/read", uri_params(uri)).await?);
    }

    assert_eq!(
        granted,
        [BILLING_MD, PUB]
            .map(|uri| vec![ResourceContents::text(format!("body of {uri}"), uri)])
            .to_vec()
    );
    assert_eq!(
        denied,
        vec![not_found(), not_found(), not_found(), not_found()]
    );
    assert_eq!(
        server.handler.calls(),
        vec![
            format!("read_resource {BILLING_MD}"),
            format!("read_resource {PUB}")
        ]
    );
    Ok(())
}

/// Assertion 4: `analyst` lists exactly the permitted URIs.
#[tokio::test]
async fn rbac_skills_resource_list_holds_exactly_the_permitted_uris() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&main_rbac(&["acme/billing"]))?).await?;
    let session = server.session(&server.analyst).await?;

    let frame = server
        .call(
            (&server.analyst, &session),
            "resources/list",
            serde_json::json!({}),
        )
        .await?;

    assert_eq!(
        listed_uris(&frame)?,
        owned(&[BILLING_MD, BILLING_NOTES, PUB])
    );
    assert_eq!(cache_scope(&frame)?, Some(CacheScope::Private));
    assert_eq!(server.handler.calls(), owned(&["list_resources"]));
    Ok(())
}

/// Assertion 5: a directory read lists a granted skill's files and refuses
/// another skill's directory.
#[tokio::test]
async fn rbac_skills_directory_read_is_per_skill() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&main_rbac(&["acme/billing"]))?).await?;
    let session = server.session(&server.analyst).await?;
    let auth = (server.analyst.as_str(), session.as_str());

    let billing = server
        .call(
            auth,
            "resources/directory/read",
            uri_params("skill://acme/billing/"),
        )
        .await?;
    let hr = server
        .call(
            auth,
            "resources/directory/read",
            uri_params("skill://acme/hr/"),
        )
        .await?;

    assert_eq!(listed_uris(&billing)?, owned(&[BILLING_MD, BILLING_NOTES]));
    assert_eq!(hr, not_found());
    assert_eq!(
        server.handler.calls(),
        owned(&["read_resource_directory skill://acme/billing/"])
    );
    Ok(())
}

/// Assertion 6: legacy `resources/subscribe` is gated per role.
#[tokio::test]
async fn rbac_skills_legacy_subscribe_is_gated_per_role() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&main_rbac(&["acme/billing"]))?).await?;
    let session = server.session(&server.analyst).await?;
    let auth = (server.analyst.as_str(), session.as_str());

    let denied = server
        .call(auth, "resources/subscribe", uri_params(PRIV))
        .await?;
    let allowed = server
        .call(auth, "resources/subscribe", uri_params(PUB))
        .await?;

    assert_eq!(denied, not_found());
    assert_eq!(
        allowed,
        serde_json::json!({ "jsonrpc": "2.0", "id": 9_u32, "result": {} })
    );
    assert_eq!(server.handler.calls(), vec![format!("subscribe {PUB}")]);
    Ok(())
}

/// Assertion 8: `legacy` (no `skills`, no `resources`) is denied every skills
/// method and reads and lists both ordinary resources but no skill URI.
#[tokio::test]
async fn rbac_skills_role_without_settings_is_skill_denied_resource_open() -> anyhow::Result<()> {
    let server = RbacSkillsServer::start(validated(&main_rbac(&["acme/billing"]))?).await?;
    let session = server.session(&server.legacy).await?;
    let auth = (server.legacy.as_str(), session.as_str());

    let mut refused = Vec::new();
    for (method, params) in [
        ("skills/list", serde_json::json!({})),
        ("skills/get", uri_params(BILLING_MD)),
        (
            "resources/directory/read",
            uri_params("skill://acme/billing/"),
        ),
    ] {
        refused.push(server.call(auth, method, params).await?);
    }
    let mut reads = Vec::new();
    for uri in [PUB, PRIV] {
        let read: ReadResourceResult =
            frame_result(&server.call(auth, "resources/read", uri_params(uri)).await?)?;
        reads.push(read.contents);
    }
    let listing = server
        .call(auth, "resources/list", serde_json::json!({}))
        .await?;

    assert_eq!(
        refused,
        ["skills/list", "skills/get", "resources/directory/read"]
            .map(|method| error_frame(-32_601, method))
            .to_vec()
    );
    assert_eq!(
        reads,
        [PUB, PRIV]
            .map(|uri| vec![ResourceContents::text(format!("body of {uri}"), uri)])
            .to_vec()
    );
    assert_eq!(listed_uris(&listing)?, owned(&[PUB, PRIV]));
    assert_eq!(
        server.handler.calls(),
        vec![
            format!("read_resource {PUB}"),
            format!("read_resource {PRIV}"),
            "list_resources".to_owned(),
        ]
    );
    Ok(())
}
