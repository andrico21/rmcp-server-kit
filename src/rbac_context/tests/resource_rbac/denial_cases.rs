//! Cases 4-6 of plan B3: pre-call denials and the content and manifest checks.

use super::*;

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 4: every pre-call denial returns its exact B-D4 error and never reaches the consumer.
async fn pre_call_denials_never_reach_the_consumer() -> anyhow::Result<()> {
    let rows: [(Option<&str>, ClientRequest, ErrorData); 13] = [
        (
            Some("legacy"),
            list_skills_request(),
            ErrorData::method_not_found::<ListSkillsRequestMethod>(),
        ),
        (
            None,
            list_skills_request(),
            ErrorData::method_not_found::<ListSkillsRequestMethod>(),
        ),
        (
            Some("legacy"),
            get_skill_at(BILLING_SKILL),
            ErrorData::method_not_found::<GetSkillRequestMethod>(),
        ),
        (
            None,
            get_skill_at(BILLING_SKILL),
            ErrorData::method_not_found::<GetSkillRequestMethod>(),
        ),
        (
            Some("legacy"),
            directory_request("skill://acme/billing/"),
            ErrorData::method_not_found::<ReadResourceDirectoryRequestMethod>(),
        ),
        (Some("analyst"), get_skill_at(HR_SKILL), unknown_skill()),
        (
            Some("analyst"),
            get_skill_at(UNREGISTERED_MANIFEST),
            unknown_skill(),
        ),
        (Some("analyst"), read_request(PRIV_FILE), not_found()),
        (Some("analyst"), read_request(HR_SKILL), not_found()),
        (
            Some("analyst"),
            read_request("file:///pub/../priv/b.txt"),
            not_found(),
        ),
        (Some("analyst"), subscribe_request(PRIV_FILE), not_found()),
        (
            Some("analyst"),
            directory_request("skill://acme/hr/"),
            not_found(),
        ),
        (None, directory_request("file:///pub/"), not_found()),
    ];
    for (role, request, expected) in rows {
        let probe = ResourceProbe::new(Script::default());
        let label = format!("{request:?} as {role:?}");
        let frame = dispatch(
            &probe,
            shared(analyst_policy(true, &["acme/billing"])),
            sent_as(request, 1, role)?,
        )
        .await?;
        assert_eq!(expect_error(frame)?, expected, "{label}");
        assert_eq!(probe.seen(), Vec::<SkillCall>::new(), "{label}");
    }
    Ok(())
}

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 5: a read returning one allowed and one denied content entry is not-found, and no body reaches the wire.
async fn read_with_a_denied_content_entry_is_not_found_without_bodies() -> anyhow::Result<()> {
    let probe = ResourceProbe::new(Script {
        read: ReadResourceResponse::Complete(ReadResourceResult::new(vec![
            text_contents(PUB_FILE),
            text_contents(PRIV_FILE),
        ])),
        ..Script::default()
    });
    let frame = dispatch(
        &probe,
        shared(analyst_policy(true, &["acme/billing"])),
        sent_as(read_request(PUB_FILE), 1, Some("analyst"))?,
    )
    .await?;
    assert_eq!(serde_json::to_value(&frame)?, error_frame(1, &not_found())?);
    assert_eq!(
        probe.seen(),
        vec![seen_as("read_resource", Some("analyst"))]
    );
    Ok(())
}

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 6: a manifest listing a denied file is an unknown skill for `skills/get` and is dropped from `skills/list`.
async fn manifest_with_a_denied_file_is_unknown_and_dropped() -> anyhow::Result<()> {
    let script = Script {
        skills: vec![skill(BILLING_SKILL, "billing"), manifest_with_denied_file()],
        skill: manifest_with_denied_file(),
        ..Script::default()
    };
    let probe = ResourceProbe::new(script);
    let mut session = Session::start(
        probe.clone(),
        shared(analyst_policy(true, &["acme/billing"])),
        false,
    );
    let fetched = session
        .exchange(sent_as(
            get_skill_at("skill://acme/billing/x/SKILL.md"),
            1,
            Some("analyst"),
        )?)
        .await?;
    let listed = expect_skills(
        session
            .exchange(sent_as(list_skills_request(), 2, Some("analyst"))?)
            .await?,
    )?;
    session.finish().await?;
    assert_eq!(expect_error(fetched)?, unknown_skill());
    assert_eq!(listed.skills, vec![skill(BILLING_SKILL, "billing")]);
    assert_eq!(
        probe.seen(),
        vec![
            seen_as("get_skill", Some("analyst")),
            seen_as("list_skills", Some("analyst"))
        ]
    );
    Ok(())
}
