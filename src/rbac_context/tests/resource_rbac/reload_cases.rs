//! Case 10 of plan B3: policy reload on one handler.

use super::*;

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 10: one handler follows grant, revoke and grant, and deleting a role in restrict mode never widens access for a caller still carrying it.
async fn resources_and_skills_follow_reload_on_one_handler() -> anyhow::Result<()> {
    let rbac = shared(analyst_policy(true, &["acme/billing"]));
    let probe = ResourceProbe::new(Script::default());
    let mut session = Session::start(probe.clone(), Arc::clone(&rbac), false);
    let analyst = Some("analyst");
    let granted = Arc::new(analyst_policy(true, &["acme/billing"]));
    let revoked = Arc::new(analyst_policy(true, &[]));
    let deleted = Arc::new(RbacPolicy::new(
        &RbacConfig::with_roles(vec![RoleConfig::new(
            "legacy",
            vec![],
            vec!["*".to_owned()],
        )])
        .with_restrict_resources(true),
    ));

    let mut listings = Vec::new();
    let mut skills = Vec::new();
    for (id, installed) in [(1, &granted), (3, &revoked), (5, &granted)] {
        rbac.store(Arc::clone(installed));
        listings.push(uris(&expect_listing(
            session
                .exchange(sent_as(list_resources_request(), id, analyst)?)
                .await?,
        )?));
        let frame = session
            .exchange(sent_as(list_skills_request(), id + 1, analyst)?)
            .await?;
        skills.push(match frame {
            ServerJsonRpcMessage::Response(_) => Ok(expect_skills(frame)?.skills),
            other @ (ServerJsonRpcMessage::Error(_)
            | ServerJsonRpcMessage::Request(_)
            | ServerJsonRpcMessage::Notification(_)) => Err(expect_error(other)?),
        });
    }
    rbac.store(Arc::clone(&deleted));
    let after_delete = uris(&expect_listing(
        session
            .exchange(sent_as(list_resources_request(), 7, analyst)?)
            .await?,
    )?);
    let read_pub = expect_error(
        session
            .exchange(sent_as(read_request(PUB_FILE), 8, analyst)?)
            .await?,
    )?;
    let read_priv = expect_error(
        session
            .exchange(sent_as(read_request(PRIV_FILE), 9, analyst)?)
            .await?,
    )?;
    session.finish().await?;

    let granted_skills = Ok(vec![skill(BILLING_SKILL, "billing")]);
    assert_eq!(
        listings,
        vec![
            owned(&[BILLING_SKILL, PUB_FILE]),
            owned(&[PUB_FILE]),
            owned(&[BILLING_SKILL, PUB_FILE])
        ]
    );
    assert_eq!(
        skills,
        vec![
            granted_skills.clone(),
            Err(ErrorData::method_not_found::<ListSkillsRequestMethod>()),
            granted_skills,
        ]
    );
    assert_eq!(after_delete, Vec::<String>::new());
    assert_eq!((read_pub, read_priv), (not_found(), not_found()));
    assert_eq!(
        probe.seen(),
        [
            "list_resources",
            "list_skills",
            "list_resources",
            "list_resources",
            "list_skills",
            "list_resources"
        ]
        .map(|method| seen_as(method, analyst))
        .to_vec()
    );
    Ok(())
}
