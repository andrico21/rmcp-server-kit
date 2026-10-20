//! Settings-matrix tables in section seven and their closed cell vocabulary.

use anyhow::{Context as _, bail, ensure};

/// Rule groups exercised by the matrix tables with paired controls.
pub(super) const RULES: &[&str] = &[
    "row-set",
    "header",
    "layout",
    "vocabulary",
    "value",
    "absent",
    "roles",
    "secret",
    "table",
    "link",
    "settings",
    "placement",
];

/// How one matrix column relates to a case config.
#[derive(Clone, Copy, Debug)]
pub(super) enum Kind {
    /// Row identifier linked to the case subsection.
    Case,
    /// TOML value at the dotted path, or `-` when the key is absent.
    Value(&'static str),
    /// `scopes` for a scope table array, otherwise the `role_claim` value.
    RolesFrom,
    /// Secret at the dotted path, optionally delivered by the env var or its `_FILE` form.
    Secret(&'static str, Option<&'static str>),
    /// Table at the dotted path.
    Table(&'static str),
    /// Unchecked prose.
    Text,
}

/// One column: its exact header text and how its cells are checked.
pub(super) struct Column {
    pub header: &'static str,
    pub kind: Kind,
}

/// One settings matrix: heading, anchor, row scope and ordered columns.
pub(super) struct Matrix {
    pub heading: &'static str,
    pub anchor: &'static str,
    pub proxy_only: bool,
    pub columns: &'static [Column],
}

const fn column(header: &'static str, kind: Kind) -> Column {
    Column { header, kind }
}

const ENV: &str = "RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__";

/// Resource-server settings for every case.
pub(super) const RESOURCE: Matrix = Matrix {
    heading: "#### Settings matrix: resource server",
    anchor: "settings-matrix-resource-server",
    proxy_only: false,
    columns: &[
        column("Case", Kind::Case),
        column("`public_url`", Kind::Value("server.public_url")),
        column("`audience`", Kind::Value("server.auth.oauth.audience")),
        column(
            "`audience_validation_mode`",
            Kind::Value("server.auth.oauth.audience_validation_mode"),
        ),
        column(
            "`accept_resource_audience`",
            Kind::Value("server.auth.oauth.accept_resource_audience"),
        ),
        column(
            "`additional_audiences`",
            Kind::Value("server.auth.oauth.additional_audiences"),
        ),
        column("Roles from", Kind::RolesFrom),
        column(
            "`challenge_scopes`",
            Kind::Value("server.auth.oauth.challenge_scopes"),
        ),
        column(
            "`insufficient_scope_challenge`",
            Kind::Value("server.auth.oauth.insufficient_scope_challenge"),
        ),
        column(
            "`omit_error_on_missing_credential`",
            Kind::Value("server.auth.oauth.omit_error_on_missing_credential"),
        ),
        column(
            "`token_exchange`",
            Kind::Table("server.auth.oauth.token_exchange"),
        ),
        column(
            "`authorization_servers`",
            Kind::Value("server.auth.oauth.authorization_servers"),
        ),
        column("Keycloak side", Kind::Text),
    ],
};

/// Proxy settings for every case with a proxy table.
pub(super) const PROXY: Matrix = Matrix {
    heading: "#### Settings matrix: proxy",
    anchor: "settings-matrix-proxy",
    proxy_only: true,
    columns: &[
        column("Case", Kind::Case),
        column("`mode`", Kind::Value("server.auth.oauth.proxy.mode")),
        column(
            "`client_secret`",
            Kind::Secret("server.auth.oauth.proxy.client_secret", None),
        ),
        column(
            "`strip_resource_param`",
            Kind::Value("server.auth.oauth.proxy.strip_resource_param"),
        ),
        column(
            "`sealing_secret`",
            Kind::Secret(
                "server.auth.oauth.proxy.sealing_secret",
                Some("SEALING_SECRET"),
            ),
        ),
        column(
            "`sealing_secret_previous`",
            Kind::Secret(
                "server.auth.oauth.proxy.sealing_secret_previous",
                Some("SEALING_SECRET_PREVIOUS"),
            ),
        ),
        column(
            "`consent_ttl`",
            Kind::Value("server.auth.oauth.proxy.consent_ttl"),
        ),
        column(
            "`expose_admin_endpoints`",
            Kind::Value("server.auth.oauth.proxy.expose_admin_endpoints"),
        ),
        column("Keycloak redirect URIs", Kind::Text),
    ],
};

/// Full env var name for a proxy secret suffix.
pub(super) fn proxy_env(suffix: &str) -> String {
    format!("{ENV}{suffix}")
}

/// A parsed matrix cell in the closed vocabulary.
#[derive(Debug, PartialEq)]
pub(super) enum Cell {
    Absent,
    Value(toml::Value),
    Scopes,
    Set,
    SetFile,
    Table,
    Text,
}

/// Parse one cell for its column kind; anything outside the vocabulary is an error.
pub(super) fn parse_cell(kind: Kind, raw: &str) -> anyhow::Result<Cell> {
    let literal = raw
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .filter(|inner| !inner.is_empty() && !inner.contains('`'));
    let cell = match (kind, raw, literal) {
        (Kind::Text, _, _) => Cell::Text,
        (Kind::Value(_) | Kind::RolesFrom | Kind::Secret(..) | Kind::Table(_), "-", _) => {
            Cell::Absent
        }
        (Kind::Secret(..), "set", _) => Cell::Set,
        (Kind::Secret(..), "set (file)", _) => Cell::SetFile,
        (Kind::Table(_), "table", _) => Cell::Table,
        (Kind::RolesFrom, "scopes", _) => Cell::Scopes,
        (Kind::Value(_) | Kind::RolesFrom, _, Some(inner)) => {
            let parsed: toml::Table = toml::from_str(&format!("value = {inner}"))
                .with_context(|| format!("cell {raw:?} is not a TOML value"))?;
            let value = parsed.get("value").context("parsed cell value")?.clone();
            ensure!(
                matches!(kind, Kind::Value(_)) || value.is_str(),
                "cell {raw:?}: role_claim must be a string"
            );
            Cell::Value(value)
        }
        (
            Kind::Case | Kind::Value(_) | Kind::RolesFrom | Kind::Secret(..) | Kind::Table(_),
            _,
            _,
        ) => {
            bail!("cell {raw:?} is outside the matrix vocabulary for {kind:?}")
        }
    };
    Ok(cell)
}

fn cells(line: &str) -> anyhow::Result<Vec<String>> {
    let inner = line
        .trim()
        .strip_prefix('|')
        .and_then(|rest| rest.strip_suffix('|'))
        .with_context(|| format!("table line {line:?} must start and end with |"))?;
    Ok(inner
        .split('|')
        .map(|cell| cell.trim().to_owned())
        .collect())
}

/// Body rows of the single table that follows the matrix heading, after exact header checks.
pub(super) fn parse_table(section: &str, matrix: &Matrix) -> anyhow::Result<Vec<Vec<String>>> {
    let heading = matrix.heading;
    let mut parts = section.split('\n').skip_while(|line| *line != heading);
    ensure!(parts.next().is_some(), "missing heading {heading:?}");
    ensure!(
        section.split('\n').filter(|line| *line == heading).count() == 1,
        "duplicate heading {heading:?}"
    );
    let mut lines = parts
        .skip_while(|line| !line.starts_with('|') && !line.starts_with('#'))
        .take_while(|line| line.starts_with('|'));
    let headers = cells(
        lines
            .next()
            .with_context(|| format!("{heading}: no table"))?,
    )?;
    let separator = cells(
        lines
            .next()
            .with_context(|| format!("{heading}: no separator"))?,
    )?;
    ensure!(
        separator.len() == headers.len()
            && separator.iter().all(|cell| !cell.is_empty()
                && cell
                    .chars()
                    .all(|character| character == '-' || character == ':')),
        "{heading}: malformed separator row"
    );
    let rows = lines.map(cells).collect::<anyhow::Result<Vec<_>>>()?;
    for row in &rows {
        ensure!(
            row.len() == headers.len(),
            "{heading}: row {:?} has {} cells, expected {}",
            row.first(),
            row.len(),
            headers.len()
        );
    }
    let expected: Vec<_> = matrix.columns.iter().map(|column| column.header).collect();
    for (index, (found, wanted)) in headers.iter().zip(&expected).enumerate() {
        ensure!(
            found == wanted,
            "{heading}: column {} header {found:?}, expected {wanted:?}",
            index.saturating_add(1)
        );
    }
    ensure!(
        headers.len() == expected.len(),
        "{heading}: {} columns, expected {}",
        headers.len(),
        expected.len()
    );
    Ok(rows)
}
