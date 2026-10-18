/// Generate close unequal inputs without relying only on unrelated foreign values.
fn fix12_near_misses(value: &str) -> Vec<String> {
    vec![
        value.to_uppercase(),
        format!("{value}/"),
        value
            .get(..value.len().saturating_sub(1))
            .unwrap_or_default()
            .into(),
        format!("{value}x"),
        format!(" {value}"),
        format!("{value} "),
        format!(
            "%{:02X}{}",
            value.as_bytes().first().copied().unwrap_or(b'x'),
            value.get(1..).unwrap_or_default()
        ),
    ]
}

/// Every authenticated grant field rejects near misses independently of sibling bindings.
#[test]
fn fix12_grant_binding_near_miss_table() -> anyhow::Result<()> {
    // Given
    let context = state(false)?;
    let original = grant_fixture(&context)?;
    let client = param(&original, "client_id").context("client")?;
    let code = param(&original, "code").context("code")?;
    let expected: CodeWrap = context.sealer.open(SealKind::Code, code)?;
    for field in ["cid", "ru", "cc"] {
        let expected_value = match field {
            "cid" => &expected.cid,
            "ru" => &expected.ru,
            "cc" => &expected.cc,
            _ => anyhow::bail!("fixture field"),
        };
        for miss in fix12_near_misses(expected_value) {
            let mut payload: CodeWrap = context.sealer.open(SealKind::Code, code)?;
            match field {
                "cid" => payload.cid = miss,
                "ru" => payload.ru = miss,
                "cc" => payload.cc = miss,
                _ => anyhow::bail!("fixture field"),
            }
            let sealed = context.sealer.seal(SealKind::Code, &payload)?;
            let mut pairs = original.clone();
            for (key, value) in &mut pairs {
                if key == "code" {
                    *value = sealed.clone();
                }
            }
            // When / Then
            ensure!(
                token_form(&context, &pairs) == Err("invalid_grant"),
                "near miss rejected for {field}"
            );
        }
    }
    for redirect in fix12_near_misses(&expected.ru) {
        let mut pairs = original.clone();
        for (key, value) in &mut pairs {
            if key == "redirect_uri" {
                *value = redirect.clone();
            }
        }
        ensure!(
            token_form(&context, &pairs) == Err("invalid_grant"),
            "request redirect near miss"
        );
    }
    for miss in fix12_near_misses(&sha256_b64(client)) {
        let refresh = context.sealer.seal(
            SealKind::Refresh,
            &RefreshWrap {
                rt: "raw-refresh-binding-near-miss".into(),
                cid: miss,
            },
        )?;
        let pairs = vec![
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh),
            ("client_id".into(), client.into()),
        ];
        ensure!(
            token_form(&context, &pairs) == Err("invalid_grant"),
            "refresh cid near miss"
        );
    }
    Ok(())
}

/// State digest equality and all approved handoff fields stay distinct across transactions.
#[tokio::test]
// cancel-safe: test invokes synchronous callback processing with no persistent state.
async fn fix12_state_binding_and_handoff_table() -> anyhow::Result<()> {
    use core::iter::once;
    // Given
    let context = Arc::new(state(false)?);
    let nonce = "nonce-Q0123456789abcdefghijklmnopqrstuvwxyz";
    for ordinal in [17_u64, 29] {
        let flow = FlowState {
            cid: sha256_b64(&format!("owner-{ordinal}")),
            ru: format!("https://callback.example/return-{ordinal}?prior={ordinal}"),
            st: Some(format!("client-state-{ordinal}")),
            cc: sha256_b64(&format!("approved-verifier-{ordinal}")),
            nh: sha256_b64(nonce),
            exp: now_unix().saturating_add(ordinal.saturating_add(500)),
        };
        let cookie_name = context.cookie_name("state", Some(&sha256_b64(nonce)));
        for nh in once(flow.nh.clone()).chain(fix12_near_misses(&flow.nh)) {
            let accepted = nh == flow.nh;
            let candidate = FlowState {
                cid: flow.cid.clone(),
                ru: flow.ru.clone(),
                st: flow.st.clone(),
                cc: flow.cc.clone(),
                nh,
                exp: flow.exp,
            };
            let sealed = context.sealer.seal(SealKind::State, &candidate)?;
            let mut headers = HeaderMap::new();
            let _cookie = headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("{cookie_name}={sealed}"))?,
            );
            let raw = form_urlencoded::Serializer::new(String::new())
                .extend_pairs([("state", nonce), ("code", "callback-code-unique")])
                .finish();
            let before = now_unix();
            // When
            let response =
                callback(State(Arc::clone(&context)), headers, RawQuery(Some(raw))).await;
            // Then
            ensure!(
                response.status() == if accepted { 302 } else { 400 },
                "nonce near miss verdict"
            );
            if accepted {
                let url = Url::parse(
                    response
                        .headers()
                        .get(header::LOCATION)
                        .context("location")?
                        .to_str()?,
                )?;
                assert_callback_code(&context, &url, &flow, before)?;
                ensure!(
                    url.query_pairs()
                        .any(|(key, value)| key == "state"
                            && Some(value.as_ref()) == flow.st.as_deref()),
                    "distinct client state carried"
                );
                ensure!(
                    url.path() == format!("/return-{ordinal}"),
                    "distinct redirect carried"
                );
            } else {
                ensure!(
                    !response.headers().contains_key(header::LOCATION),
                    "bad nonce never redirects"
                );
            }
        }
    }
    Ok(())
}
