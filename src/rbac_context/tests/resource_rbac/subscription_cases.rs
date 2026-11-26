//! Cases 8-9 of plan B3: subscription filter sanitization and the `listen`
//! second boundary.

use super::*;

fn requested(uris: &[&str], tools: bool) -> SubscriptionFilter {
    let builder = SubscriptionFilter::builder().resource_subscriptions(owned(uris));
    if tools {
        builder.tools_list_changed().build()
    } else {
        builder.build()
    }
}

fn tools_only() -> SubscriptionFilter {
    SubscriptionFilter::builder().tools_list_changed().build()
}

/// Row: (policy, probe answer, request, filter the probe receives, returned filter).
type FilterRow = (
    Arc<ArcSwap<RbacPolicy>>,
    Accept,
    SubscriptionFilter,
    SubscriptionFilter,
    Option<SubscriptionFilter>,
);

#[expect(
    clippy::unnecessary_wraps,
    reason = "deliberate: src/rbac_context/tests/resource_rbac/subscription_cases.rs::accepted_subscription_filter_sanitizes_inputs_and_outputs keeps the uniform test signature while it cannot fail"
)]
#[test]
/// Case 8: the consumer sees only universally allowed URIs, and its answer is intersected with the sanitized request and filtered again.
fn accepted_subscription_filter_sanitizes_inputs_and_outputs() -> anyhow::Result<()> {
    let mixed = requested(&[BILLING_SKILL, PUB_FILE], true);
    let rows: [FilterRow; 7] = [
        (
            shared(analyst_policy(false, &["acme/billing"])),
            Accept::Echo,
            mixed.clone(),
            requested(&[PUB_FILE], true),
            Some(requested(&[PUB_FILE], true)),
        ),
        (
            shared(analyst_policy(true, &["acme/billing"])),
            Accept::Echo,
            mixed.clone(),
            tools_only(),
            Some(tools_only()),
        ),
        // Existence oracle: denied existing and denied absent reach the
        // consumer identically, so its answer cannot tell them apart.
        (
            shared(analyst_policy(true, &["acme/billing"])),
            Accept::ExistingOnly(&[PRIV_FILE]),
            requested(&[PRIV_FILE], false),
            SubscriptionFilter::default(),
            None,
        ),
        (
            shared(analyst_policy(true, &["acme/billing"])),
            Accept::ExistingOnly(&[PRIV_FILE]),
            requested(&["file:///priv/nope.txt"], false),
            SubscriptionFilter::default(),
            None,
        ),
        (
            shared(analyst_policy(false, &["acme/billing"])),
            Accept::EchoPlus("file:///pub/extra.txt"),
            requested(&[PUB_FILE], false),
            requested(&[PUB_FILE], false),
            Some(requested(&[PUB_FILE], false)),
        ),
        (
            shared(analyst_policy(false, &["acme/billing"])),
            Accept::EchoPlus(BILLING_SKILL),
            requested(&[PUB_FILE], false),
            requested(&[PUB_FILE], false),
            Some(requested(&[PUB_FILE], false)),
        ),
        (
            disabled_policy(),
            Accept::Echo,
            mixed.clone(),
            mixed.clone(),
            Some(mixed),
        ),
    ];
    for (rbac, accept, request, received, returned) in rows {
        let probe = ResourceProbe::new(Script {
            accept,
            ..Script::default()
        });
        let handler = RbacContextHandler::new(probe.clone(), rbac, false);
        let answer = handler.accepted_subscription_filter(&request);
        assert_eq!(probe.filters(), vec![received], "{request:?}");
        assert_eq!(answer, returned, "{request:?}");
    }
    Ok(())
}

// cancel-safe: test body only; no state outlives an await.
#[tokio::test]
/// Case 9: `listen` forwards an allowed subscription, and re-checks a policy reloaded after acknowledgement without calling the consumer.
async fn listen_rechecks_a_policy_reloaded_after_acknowledgement() -> anyhow::Result<()> {
    let subscription = requested(&[PUB_FILE], false);

    // Control: no reload, so the subscription reaches the consumer.
    let probe = ResourceProbe::new(Script::default());
    let mut session = Session::start(probe.clone(), shared(analyst_policy(false, &[])), false);
    let acknowledged = expect_acknowledgement(
        session
            .exchange(listen_as(subscription.clone(), 1, "analyst")?)
            .await?,
    )?;
    let done_frame = session.next_frame().await?;
    session.finish().await?;
    assert_eq!(acknowledged, subscription);
    let ServerJsonRpcMessage::Response(done) = done_frame else {
        anyhow::bail!("expected the listen result, got {done_frame:?}")
    };
    assert_eq!(done.id, NumberOrString::Number(1));
    assert_eq!(probe.seen(), vec![seen_as("listen", Some("analyst"))]);
    listen_refuses_a_policy_revoked_after_acceptance(subscription).await
}

// cancel-safe: in-memory test code; no lock, permit or state outlives an await.
/// The race half of case 9: the policy is replaced between acceptance and
/// `listen`, so `listen` refuses after the acknowledgement without calling
/// the consumer.
async fn listen_refuses_a_policy_revoked_after_acceptance(
    subscription: SubscriptionFilter,
) -> anyhow::Result<()> {
    let rbac = shared(analyst_policy(false, &[]));
    let revoked = RbacPolicy::new(
        &RbacConfig::with_roles(vec![
            RoleConfig::new("analyst", vec![], vec!["*".to_owned()]).with_resources(vec![]),
        ])
        .with_restrict_resources(true),
    );
    let probe = ResourceProbe::new(Script {
        reload_on_accept: Some((Arc::clone(&rbac), Arc::new(revoked))),
        ..Script::default()
    });
    let mut session = Session::start(probe.clone(), rbac, false);
    let acknowledged = expect_acknowledgement(
        session
            .exchange(listen_as(subscription.clone(), 1, "analyst")?)
            .await?,
    )?;
    let refused = session.next_frame().await?;
    session.finish().await?;
    assert_eq!(acknowledged, subscription);
    // rmcp sends resource-not-found as -32602 to 2026-07-28 peers (plan G7).
    assert_eq!(
        serde_json::to_value(&refused)?,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1_i64,
            "error": serde_json::to_value(ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                "resource not found",
                None,
            ))?,
        })
    );
    assert_eq!(probe.filters(), vec![subscription]);
    assert_eq!(probe.seen(), Vec::<SkillCall>::new());
    Ok(())
}
