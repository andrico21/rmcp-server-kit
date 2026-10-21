//! Matrix cells, links and settings lines compared with each case config.

use alloc::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, bail, ensure};

use super::{
    environment::{lookup, parse_env},
    grammar::Case,
    matrix::{Cell, Kind, Matrix, PROXY, RESOURCE, parse_cell, parse_table, proxy_env},
};

const PROXY_TABLE: &str = "server.auth.oauth.proxy";

/// GitHub-style heading anchor for ASCII headings.
pub(super) fn slug(heading: &str) -> String {
    heading
        .trim_start_matches('#')
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ' ' | '-' | '_')
        })
        .map(|character| if character == ' ' { '-' } else { character })
        .collect()
}

/// Level-three subsection of each case and the first non-blank line of each subsection.
struct Layout {
    case_heading: BTreeMap<String, String>,
    first_line: Vec<(String, String)>,
    first_subsection: Option<usize>,
}

fn layout(section: &str) -> Layout {
    let mut result = Layout {
        case_heading: BTreeMap::new(),
        first_line: Vec::new(),
        first_subsection: None,
    };
    let (mut fenced, mut heading, mut awaiting) = (false, String::new(), false);
    for (index, line) in section.split('\n').enumerate() {
        let delimiter = line.starts_with("```");
        if delimiter {
            if let Some(id) = line.strip_prefix("```toml,case=") {
                let _previous = result
                    .case_heading
                    .insert(id.trim().to_owned(), heading.clone());
            }
            fenced = !fenced;
        }
        if !delimiter && !fenced && line.starts_with("### ") {
            heading = line.to_owned();
            awaiting = true;
            result.first_subsection = result.first_subsection.or(Some(index));
            continue;
        }
        if awaiting && !line.trim().is_empty() {
            result.first_line.push((heading.clone(), line.to_owned()));
            awaiting = false;
        }
    }
    result
}

fn is_proxy(config: &toml::Value) -> bool {
    lookup(config, PROXY_TABLE).is_some()
}

fn derive(
    kind: Kind,
    config: &toml::Value,
    env: &BTreeMap<String, String>,
) -> anyhow::Result<Cell> {
    let cell = match kind {
        Kind::Value(path) => {
            lookup(config, path).map_or(Cell::Absent, |value| Cell::Value(value.clone()))
        }
        Kind::RolesFrom => {
            match (
                lookup(config, "server.auth.oauth.scopes"),
                lookup(config, "server.auth.oauth.role_claim"),
            ) {
                (Some(_), Some(_)) => bail!("both scopes and role_claim are configured"),
                (Some(_), None) => Cell::Scopes,
                (None, Some(claim)) => Cell::Value(claim.clone()),
                (None, None) => Cell::Absent,
            }
        }
        Kind::Secret(path, variable) => {
            let named = |suffix: &str| {
                variable
                    .is_some_and(|name| env.contains_key(&proxy_env(&format!("{name}{suffix}"))))
            };
            if named("_FILE") {
                Cell::SetFile
            } else if lookup(config, path).is_some() || named("") {
                Cell::Set
            } else {
                Cell::Absent
            }
        }
        Kind::Table(path) => match lookup(config, path) {
            Some(toml::Value::Table(_)) => Cell::Table,
            Some(_) => bail!("{path} is not a table"),
            None => Cell::Absent,
        },
        Kind::Case | Kind::Text => Cell::Text,
    };
    Ok(cell)
}

fn row_id(cell: &str) -> anyhow::Result<(&str, &str)> {
    cell.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(')'))
        .and_then(|rest| rest.split_once("](#"))
        .with_context(|| format!("case cell {cell:?} must be [ID](#anchor)"))
}

/// Compare every checked cell of one matrix with the case configs; return the checked-cell count.
pub(super) fn check_matrix(
    section: &str,
    matrix: &Matrix,
    cases: &[Case],
) -> anyhow::Result<usize> {
    let rows = parse_table(section, matrix)?;
    let headings = layout(section).case_heading;
    let mut expected = BTreeMap::new();
    for case in cases {
        let config = toml::Value::Table(toml::from_str::<toml::Table>(&case.toml)?);
        if !matrix.proxy_only || is_proxy(&config) {
            let _previous = expected.insert(case.id.as_str(), (case, config));
        }
    }
    let (mut seen, mut checked) = (BTreeSet::new(), 0_usize);
    for row in &rows {
        let (id, anchor) = row_id(row.first().context("empty row")?)?;
        let (case, config) = expected
            .get(id)
            .with_context(|| format!("{}: unknown row {id}", matrix.heading))?;
        ensure!(seen.insert(id), "{}: duplicate row {id}", matrix.heading);
        let heading = headings
            .get(id)
            .with_context(|| format!("case {id}: no subsection"))?;
        ensure!(
            anchor == slug(heading),
            "case {id}: link #{anchor} is not {heading:?}"
        );
        let env = parse_env(case.env.first().context("main env block")?)?;
        let mut columns = Vec::new();
        for (column, raw) in matrix.columns.iter().zip(row).skip(1) {
            let context = || format!("case {id} column {}", column.header);
            let cell = parse_cell(column.kind, raw).with_context(context)?;
            if cell != Cell::Text {
                let want = derive(column.kind, config, &env).with_context(context)?;
                ensure!(
                    cell == want,
                    "{}: matrix cell {raw} but the case config gives {want:?}",
                    context()
                );
                columns.push(column.header);
                checked = checked.saturating_add(1);
            }
        }
        tracing::info!(
            matrix = matrix.heading,
            case = id,
            columns = columns.join(" "),
            "matrix row checked"
        );
    }
    if let Some(missing) = expected.keys().find(|id| !seen.contains(*id)) {
        bail!("{}: case {missing} has no row", matrix.heading);
    }
    Ok(checked)
}

/// Matrices precede the first case subsection; every case subsection opens with its settings line.
pub(super) fn check_layout(section: &str, cases: &[Case]) -> anyhow::Result<()> {
    let found = layout(section);
    let first = found
        .first_subsection
        .context("section has no case subsection")?;
    for matrix in [&RESOURCE, &PROXY] {
        let position = section.split('\n').position(|line| line == matrix.heading);
        ensure!(
            position.is_some_and(|line| line < first),
            "{} must precede the first case subsection",
            matrix.heading
        );
    }
    for case in cases {
        let heading = found
            .case_heading
            .get(&case.id)
            .with_context(|| format!("case {}: no subsection", case.id))?;
        let line = found
            .first_line
            .iter()
            .find(|(name, _)| name == heading)
            .map(|(_, line)| line.as_str())
            .unwrap_or_default();
        let proxy = is_proxy(&toml::Value::Table(toml::from_str::<toml::Table>(
            &case.toml,
        )?));
        let words: BTreeSet<_> = line
            .split(|character: char| !character.is_ascii_alphanumeric())
            .collect();
        ensure!(
            line.starts_with("Settings: ")
                && words.contains(case.id.as_str())
                && line.contains(&format!("(#{})", RESOURCE.anchor))
                && line.contains(&format!("(#{})", PROXY.anchor)) == proxy,
            "case {}: subsection must open with a Settings: line linking its matrix rows, found {line:?}",
            case.id
        );
    }
    Ok(())
}
