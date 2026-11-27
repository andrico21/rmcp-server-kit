//! Cases 1-3 of plan B3: forwarding with RBAC disabled and filtered
//! listings.

use super::*;

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 1: with RBAC disabled every method forwards unchanged inside the identity scope, cache scope untouched.
async fn rbac_disabled_forwards_every_resource_and_skill_method_unchanged() -> anyhow::Result<()> {
    // Given
    let probe = ResourceProbe::new(Script::default());
    let mut session = Session::start(probe.clone(), disabled_policy(), true);
    let analyst = Some("analyst");
    let listen_filter = SubscriptionFilter::builder()
        .resource_subscriptions(owned(&[PRIV_FILE, HR_SKILL]))
        .build();

    // When
    let listed = expect_listing(
        session
            .exchange(sent_as(list_resources_request(), 1, analyst)?)
            .await?,
    )?;
    let directory = expect_listing(
        session
            .exchange(sent_as(directory_request("file:///pub/"), 2, analyst)?)
            .await?,
    )?;
    let skills = expect_skills(
        session
            .exchange(sent_as(list_skills_request(), 3, analyst)?)
            .await?,
    )?;
    let fetched_result = expect_response(
        session
            .exchange(sent_as(get_skill_at(BILLING_SKILL), 4, analyst)?)
            .await?,
    )?;
    let read_result = expect_response(
        session
            .exchange(sent_as(read_request(PRIV_FILE), 5, analyst)?)
            .await?,
    )?;
    let subscribed = session
        .exchange(sent_as(subscribe_request(PRIV_FILE), 6, analyst)?)
        .await?;
    let acknowledged = session
        .exchange(listen_as(listen_filter.clone(), 7, "analyst")?)
        .await?;
    let listen_frame = session.next_frame().await?;
    session.finish().await?;

    // Then
    for listing in [&listed, &directory] {
        assert_eq!(uris(listing), uris(&probe.listing()));
        assert_eq!(listing.next_cursor.as_deref(), Some(CURSOR));
        assert_eq!(listing.cache_scope, None);
    }
    assert_eq!(skills.skills, probe.script.skills);
    assert_eq!(skills.next_cursor.as_deref(), Some(CURSOR));
    assert_eq!(skills.cache_scope, None);
    let ServerResult::GetSkillResult(fetched) = fetched_result else {
        anyhow::bail!("expected a skills/get result, got {fetched_result:?}")
    };
    assert_eq!(fetched.skill, probe.script.skill);
    assert_eq!(fetched.cache_scope, None);
    let ServerResult::ReadResourceResult(read) = read_result else {
        anyhow::bail!("expected a resources/read result, got {read_result:?}")
    };
    assert_eq!(read.contents, vec![text_contents(PUB_FILE)]);
    assert_eq!(read.cache_scope, None);
    assert_eq!(
        serde_json::to_value(&subscribed)?,
        serde_json::json!({ "jsonrpc": "2.0", "id": 6_i64, "result": {} })
    );
    assert_eq!(expect_acknowledgement(acknowledged)?, listen_filter);
    let ServerJsonRpcMessage::Response(listen_done) = listen_frame else {
        anyhow::bail!("expected the listen result, got {listen_frame:?}")
    };
    assert_eq!(listen_done.id, NumberOrString::Number(7));
    assert_eq!(probe.filters(), vec![listen_filter]);
    assert_eq!(
        probe.seen(),
        [
            "list_resources",
            "read_resource_directory",
            "list_skills",
            "get_skill",
            "read_resource",
            "subscribe",
            "listen",
        ]
        .map(|method| seen_as(method, analyst))
        .to_vec()
    );
    Ok(())
}

/// Row: (filtering flag, role, request, expected URIs, expected log method).
type ListingRow = (
    bool,
    Option<&'static str>,
    fn() -> ClientRequest,
    Vec<String>,
    &'static str,
);

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 2: restrict mode filters `resources/list` and ordinary directory reads per role, consumer called, cursor kept, private.
async fn listings_are_filtered_per_role_in_restrict_mode() -> anyhow::Result<()> {
    let granted = owned(&[BILLING_SKILL, PUB_FILE]);
    let rows: [ListingRow; 5] = [
        (
            false,
            Some("analyst"),
            list_resources_request,
            granted.clone(),
            "list_resources",
        ),
        (
            true,
            Some("analyst"),
            list_resources_request,
            granted.clone(),
            "list_resources",
        ),
        (
            false,
            Some("analyst"),
            || directory_request("file:///pub/"),
            granted.clone(),
            "read_resource_directory",
        ),
        (
            true,
            Some("analyst"),
            || directory_request("file:///pub/"),
            granted,
            "read_resource_directory",
        ),
        (
            false,
            None,
            list_resources_request,
            Vec::new(),
            "list_resources",
        ),
    ];
    for (filtering, role, request, expected, method) in rows {
        let probe = ResourceProbe::new(Script {
            public_ttl: Some(5_000),
            ..Script::default()
        });
        let mut session = Session::start(
            probe.clone(),
            shared(analyst_policy(true, &["acme/billing"])),
            filtering,
        );
        let listed = expect_listing(
            session
                .exchange(sent_as_current(request(), 1, role)?)
                .await?,
        )?;
        session.finish().await?;
        assert_eq!(
            uris(&listed),
            expected,
            "{method} as {role:?}, filtering {filtering}"
        );
        assert_eq!(listed.next_cursor.as_deref(), Some(CURSOR));
        assert_eq!(listed.cache_scope, Some(CacheScope::Private));
        assert_eq!(probe.seen(), vec![seen_as(method, role)]);
    }

    // A granted role whose page filters to nothing still gets the cursor.
    let probe = ResourceProbe::new(Script {
        listing: [HR_SKILL, PRIV_FILE].map(resource).to_vec(),
        public_ttl: Some(5_000),
        ..Script::default()
    });
    let frame = dispatch(
        &probe,
        shared(analyst_policy(true, &["acme/billing"])),
        sent_as_current(list_resources_request(), 1, Some("analyst"))?,
    )
    .await?;
    let listed = expect_listing(frame)?;
    assert_eq!(uris(&listed), Vec::<String>::new());
    assert_eq!(listed.next_cursor.as_deref(), Some(CURSOR));
    assert_eq!(listed.cache_scope, Some(CacheScope::Private));
    assert_eq!(
        probe.seen(),
        vec![seen_as("list_resources", Some("analyst"))]
    );
    Ok(())
}

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 3: `skills/list` keeps only granted, safe, registered skills, with the cursor kept and private.
async fn skills_list_keeps_only_granted_safe_registered_skills() -> anyhow::Result<()> {
    let probe = ResourceProbe::new(Script {
        skills: vec![
            skill(BILLING_SKILL, "billing"),
            skill(HR_SKILL, "hr"),
            skill(UNSAFE_SKILL, "b"),
            skill(UNREGISTERED_MANIFEST, "y"),
        ],
        public_ttl: Some(5_000),
        ..Script::default()
    });
    let frame = dispatch(
        &probe,
        shared(analyst_policy(true, &["acme/billing"])),
        sent_as_current(list_skills_request(), 1, Some("analyst"))?,
    )
    .await?;
    let listed = expect_skills(frame)?;
    assert_eq!(listed.skills, vec![skill(BILLING_SKILL, "billing")]);
    assert_eq!(listed.next_cursor.as_deref(), Some(CURSOR));
    assert_eq!(listed.cache_scope, Some(CacheScope::Private));
    assert_eq!(probe.seen(), vec![seen_as("list_skills", Some("analyst"))]);
    Ok(())
}
