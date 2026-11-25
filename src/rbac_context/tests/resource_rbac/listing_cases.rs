//! Cases 1-7 and 12 of plan B3: forwarding with RBAC disabled, filtered
//! listings, pre-call denials, content and manifest checks, the cache
//! override, and the existence oracle.

use rmcp::model::InputRequiredResult;

use super::*;

/// The exact JSON-RPC error frame for `error` answering id `id`.
fn error_frame(id: i64, error: &ErrorData) -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": serde_json::to_value(error)?,
    }))
}

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
        let probe = ResourceProbe::new(Script::default());
        let mut session = Session::start(
            probe.clone(),
            shared(analyst_policy(true, &["acme/billing"])),
            filtering,
        );
        let listed = expect_listing(session.exchange(sent_as(request(), 1, role)?).await?)?;
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
        ..Script::default()
    });
    let frame = dispatch(
        &probe,
        shared(analyst_policy(true, &["acme/billing"])),
        sent_as(list_resources_request(), 1, Some("analyst"))?,
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
        ..Script::default()
    });
    let frame = dispatch(
        &probe,
        shared(analyst_policy(true, &["acme/billing"])),
        sent_as(list_skills_request(), 1, Some("analyst"))?,
    )
    .await?;
    let listed = expect_skills(frame)?;
    assert_eq!(listed.skills, vec![skill(BILLING_SKILL, "billing")]);
    assert_eq!(listed.next_cursor.as_deref(), Some(CURSOR));
    assert_eq!(listed.cache_scope, Some(CacheScope::Private));
    assert_eq!(probe.seen(), vec![seen_as("list_skills", Some("analyst"))]);
    Ok(())
}

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

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 7: an explicit `Public` becomes `Private` under RBAC with the TTL kept, stays `Public` with RBAC disabled, and `InputRequired` passes through.
async fn cache_scope_is_forced_private_only_under_rbac() -> anyhow::Result<()> {
    let ttl = 5_000_u64;
    let rows = [
        (
            shared(analyst_policy(false, &["acme/billing"])),
            CacheScope::Private,
        ),
        (disabled_policy(), CacheScope::Public),
    ];
    for (rbac, expected) in rows {
        let probe = ResourceProbe::new(Script {
            public_ttl: Some(ttl),
            ..Script::default()
        });
        let mut session = Session::start(probe.clone(), rbac, false);
        let fetched_result = expect_response(
            session
                .exchange(sent_as(get_skill_at(BILLING_SKILL), 1, Some("analyst"))?)
                .await?,
        )?;
        let read_result = expect_response(
            session
                .exchange(sent_as(read_request(PUB_FILE), 2, Some("analyst"))?)
                .await?,
        )?;
        session.finish().await?;
        let ServerResult::GetSkillResult(fetched) = fetched_result else {
            anyhow::bail!("expected a skills/get result, got {fetched_result:?}")
        };
        let ServerResult::ReadResourceResult(read) = read_result else {
            anyhow::bail!("expected a resources/read result, got {read_result:?}")
        };
        assert_eq!(
            (fetched.cache_scope, fetched.ttl_ms),
            (Some(expected), Some(ttl))
        );
        assert_eq!((read.cache_scope, read.ttl_ms), (Some(expected), Some(ttl)));
        assert_eq!(
            probe.seen(),
            vec![
                seen_as("get_skill", Some("analyst")),
                seen_as("read_resource", Some("analyst"))
            ]
        );
    }

    // `InputRequired` is not a completed body: it passes through unchanged.
    let input_required = InputRequiredResult::from_request_state("probe-state");
    let mut frames = Vec::new();
    for rbac in [
        shared(analyst_policy(false, &["acme/billing"])),
        disabled_policy(),
    ] {
        let probe = ResourceProbe::new(Script {
            read: ReadResourceResponse::InputRequired(input_required.clone()),
            public_ttl: Some(ttl),
            ..Script::default()
        });
        let mut message = sent_as(read_request(PUB_FILE), 1, Some("analyst"))?;
        attach_meta(&mut message, coverage_meta())?;
        frames.push(serde_json::to_value(
            dispatch(&probe, rbac, message).await?,
        )?);
        assert_eq!(
            probe.seen(),
            vec![seen_as("read_resource", Some("analyst"))]
        );
    }
    let expected = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1_i64,
        "result": serde_json::to_value(&input_required)?,
    });
    assert_eq!(frames, vec![expected.clone(), expected]);
    Ok(())
}

/// Row: (request builder, denied existing URI, denied missing URI, expected error).
type OraclePair = (
    fn(&str) -> ClientRequest,
    &'static str,
    &'static str,
    ErrorData,
);

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 12: a denied existing and a denied missing resource or skill give byte-identical JSON-RPC errors.
async fn denied_existing_and_missing_errors_are_byte_identical() -> anyhow::Result<()> {
    let pairs: [OraclePair; 3] = [
        (
            get_skill_at,
            HR_SKILL,
            "skill://acme/nope/SKILL.md",
            unknown_skill(),
        ),
        (
            read_request,
            PRIV_FILE,
            "file:///priv/nope.txt",
            not_found(),
        ),
        (
            subscribe_request,
            PRIV_FILE,
            "file:///priv/nope.txt",
            not_found(),
        ),
    ];
    for (request, existing, missing, error) in pairs {
        let mut wire = Vec::new();
        for uri in [existing, missing] {
            let probe = ResourceProbe::new(Script::default());
            let frame = dispatch(
                &probe,
                shared(analyst_policy(true, &["acme/billing"])),
                sent_as(request(uri), 1, Some("analyst"))?,
            )
            .await?;
            assert_eq!(
                serde_json::to_value(&frame)?,
                error_frame(1, &error)?,
                "{uri}"
            );
            wire.push(serde_json::to_string(&frame)?);
            assert_eq!(probe.seen(), Vec::<SkillCall>::new(), "{uri}");
        }
        let [denied_existing, denied_missing] = <[String; 2]>::try_from(wire)
            .map_err(|got| anyhow::anyhow!("expected two frames, got {got:?}"))?;
        assert_eq!(denied_existing, denied_missing);
    }
    Ok(())
}
