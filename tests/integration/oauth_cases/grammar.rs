//! Section-scoped case fences with ordered, self-contained exchanges.

use alloc::collections::BTreeMap;

use anyhow::{Context as _, ensure};

use super::compare::Message;

#[derive(Debug)]
pub(super) struct Case {
    pub id: String,
    pub toml: String,
    pub env: Vec<String>,
    pub exchanges: Vec<Exchange>,
}

#[derive(Debug)]
pub(super) enum Exchange {
    Http {
        request: String,
        response: String,
        upstream: Option<String>,
    },
    Library {
        snippet: String,
        upstream: String,
    },
}

fn section_fences(markdown: &str) -> anyhow::Result<Vec<super::case_info::Fence>> {
    super::case_info::validate_document(markdown)?;
    Ok(super::case_info::document_fences(markdown)?
        .into_iter()
        .filter(|fence| fence.heading.starts_with("## 7. "))
        .collect())
}

pub(super) fn parse_cases(markdown: &str) -> anyhow::Result<Vec<Case>> {
    let mut cases = BTreeMap::<String, Case>::new();
    let mut pending: Option<(String, String)> = None;
    let mut previous: Option<(String, usize)> = None;
    let mut snippet = None;
    for fence in section_fences(markdown)? {
        if let Some((id, _)) = &pending {
            ensure!(
                fence.info == format!("http,case={id},response"),
                "case {id}: request interrupted by fence {:?}",
                fence.info
            );
        }
        if fence.info == "rust,ignore" {
            snippet = Some(fence.body);
            previous = None;
            continue;
        }
        if !fence.info.to_ascii_lowercase().contains("case") {
            previous = None;
            snippet = None;
            continue;
        }
        let parts: Vec<_> = fence.info.split(',').collect();
        let id = parts
            .get(1)
            .and_then(|part| part.strip_prefix("case="))
            .with_context(|| {
                format!(
                    "invalid case fence {:?}: case ID must be second",
                    fence.info
                )
            })?;
        let result = assemble(
            &mut cases,
            id,
            &parts,
            &fence.body,
            &mut pending,
            &mut previous,
            &mut snippet,
        );
        result.with_context(|| format!("case {id}: invalid fence {}", fence.info))?;
    }
    if let Some((id, _)) = pending {
        anyhow::bail!("case {id}: request without response");
    }
    ensure!(!cases.is_empty(), "section 7 contains zero cases");
    for case in cases.values() {
        ensure!(
            !case.env.is_empty(),
            "case {}: missing main sh fence",
            case.id
        );
        ensure!(
            !case.exchanges.is_empty(),
            "case {}: zero exchanges",
            case.id
        );
    }
    Ok(cases.into_values().collect())
}

fn assemble(
    cases: &mut BTreeMap<String, Case>,
    id: &str,
    parts: &[&str],
    body: &str,
    pending: &mut Option<(String, String)>,
    previous: &mut Option<(String, usize)>,
    snippet: &mut Option<String>,
) -> anyhow::Result<()> {
    match parts {
        ["toml", _] => {
            ensure!(pending.is_none(), "request must be followed by response");
            ensure!(!cases.contains_key(id), "duplicate TOML case {id}");
            let _previous_case = cases.insert(
                id.to_owned(),
                Case {
                    id: id.to_owned(),
                    toml: body.to_owned(),
                    env: Vec::new(),
                    exchanges: Vec::new(),
                },
            );
            *previous = None;
        }
        ["sh", _] | ["sh", _, "alt"] => {
            ensure!(pending.is_none(), "request must be followed by response");
            let case = cases.get_mut(id).context("env before TOML")?;
            ensure!(
                (parts.len() == 2 && case.env.is_empty())
                    || (parts.len() == 3 && case.env.len() == 1),
                "duplicate or out-of-order env block"
            );
            case.env.push(body.to_owned());
            *previous = None;
        }
        ["http", _, "request"] => {
            ensure!(pending.is_none(), "request must be followed by response");
            ensure!(cases.contains_key(id), "request before TOML");
            let _target = Message::parse(body)?.request_target()?;
            *pending = Some((id.to_owned(), body.to_owned()));
            *previous = None;
        }
        ["http", _, "response"] => {
            let (request_id, request) = pending.take().context("response without request")?;
            ensure!(
                request_id == id,
                "response case differs from request case {request_id}"
            );
            let _status = Message::parse(body)?.status()?;
            let case = cases.get_mut(id).context("response before TOML")?;
            case.exchanges.push(Exchange::Http {
                request,
                response: body.to_owned(),
                upstream: None,
            });
            *previous = Some((id.to_owned(), case.exchanges.len().saturating_sub(1)));
        }
        ["http", _, "upstream"] => {
            ensure!(pending.is_none(), "upstream before response");
            let case = cases.get_mut(id).context("upstream before TOML")?;
            if let Some(code) = snippet.take() {
                case.exchanges.push(Exchange::Library {
                    snippet: code,
                    upstream: body.to_owned(),
                });
            } else {
                let (previous_id, position) = previous
                    .take()
                    .context("upstream without preceding response or rust,ignore")?;
                ensure!(previous_id == id, "upstream case differs from response");
                match case
                    .exchanges
                    .get_mut(position)
                    .context("missing exchange")?
                {
                    Exchange::Http {
                        upstream,
                        request: _,
                        response: _,
                    } => {
                        *upstream = Some(body.to_owned());
                    }
                    Exchange::Library {
                        snippet: _,
                        upstream: _,
                    } => anyhow::bail!("duplicate library upstream"),
                }
            }
        }
        _ => anyhow::bail!("unknown case fence grammar"),
    }
    if !matches!(parts, ["http", _, "upstream"]) {
        *snippet = None;
    }
    Ok(())
}
