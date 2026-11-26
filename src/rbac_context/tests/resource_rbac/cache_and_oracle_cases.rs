//! Cases 7 and 12 of plan B3: the cache override and the existence oracle.

use rmcp::model::InputRequiredResult;

use super::*;

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
