//! Independent accepted and rejected edits of the matrix fixture, one group per rule.

use super::matrix_tables::{
    A1_ROW, B2_ROW, P_ROW, Row,
    Target::{Section, Toml},
    edit, row,
};

const A1: usize = 0;
const B2: usize = 1;

fn structure() -> Vec<Row> {
    let swapped = format!("{B2_ROW}\n{A1_ROW}");
    let duplicate = format!("{A1_ROW}\n{A1_ROW}");
    let extra = format!("{P_ROW}\n| [A1](#a1---first) | - | - | - | - | - | - | - | x |");
    let ab = format!("{A1_ROW}\n{B2_ROW}");
    vec![
        row("row-set", vec![edit(Section, &ab, &swapped)], &[]),
        row(
            "row-set",
            vec![edit(Section, &format!("\n{B2_ROW}"), "")],
            &["case B2 has no row"],
        ),
        row(
            "row-set",
            vec![edit(Section, A1_ROW, &duplicate)],
            &["duplicate row A1"],
        ),
        row(
            "row-set",
            vec![edit(Section, "[A1](#a1---first)", "[Z9](#a1---first)")],
            &["unknown row Z9"],
        ),
        row(
            "row-set",
            vec![edit(Section, P_ROW, &extra)],
            &["proxy", "unknown row A1"],
        ),
        row(
            "header",
            vec![edit(Section, "| `audience` |", "|   `audience`   |")],
            &[],
        ),
        row(
            "header",
            vec![edit(
                Section,
                "| `challenge_scopes` |",
                "| `challenge_scope` |",
            )],
            &["column 8 header"],
        ),
        row(
            "header",
            vec![edit(
                Section,
                "| `mode` | `client_secret` |",
                "| `client_secret` | `mode` |",
            )],
            &["column 2 header"],
        ),
    ]
}

fn layout() -> Vec<Row> {
    vec![
        row("layout", vec![edit(Section, "| --- |", "| :--- |")], &[]),
        row(
            "layout",
            vec![edit(Section, "| --- |", "| -x- |")],
            &["malformed separator"],
        ),
        row(
            "layout",
            vec![edit(Section, " groups mapper |", "")],
            &["has 12 cells, expected 13"],
        ),
        row(
            "layout",
            vec![edit(
                Section,
                " Keycloak redirect URIs |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
                "\n| --- | --- | --- | --- | --- | --- | --- | --- |",
            )],
            &["has 9 cells, expected 8"],
        ),
        row(
            "layout",
            vec![edit(
                Section,
                "#### Settings matrix: proxy",
                "#### Settings matrix: proxies",
            )],
            &["missing heading"],
        ),
        row(
            "layout",
            vec![edit(
                Section,
                "### B2",
                "#### Settings matrix: resource server\n\n### B2",
            )],
            &["duplicate heading"],
        ),
        row(
            "placement",
            vec![edit(
                Section,
                "Preamble prose.",
                "Preamble prose.\n\nMore prose.",
            )],
            &[],
        ),
        row(
            "placement",
            vec![edit(
                Section,
                "\n#### Settings matrix: resource server",
                "\n### Intro\n\n#### Settings matrix: resource server",
            )],
            &["must precede"],
        ),
    ]
}

fn vocabulary() -> Vec<Row> {
    vec![
        row(
            "vocabulary",
            vec![edit(Section, "`\"groups\"`", "`'groups'`")],
            &[],
        ),
        row(
            "vocabulary",
            vec![edit(
                Section,
                "| `\"mcp-example\"` | - |",
                "| `\"mcp-example\"` | n/a |",
            )],
            &["case A1 column `audience_validation_mode`", "vocabulary"],
        ),
        row(
            "vocabulary",
            vec![edit(Section, "| `true` |", "| true |")],
            &["case B2 column `accept_resource_audience`", "vocabulary"],
        ),
        row(
            "vocabulary",
            vec![edit(Section, "| `\"30d\"` |", "| set |")],
            &["case B2 column `consent_ttl`", "vocabulary"],
        ),
        row(
            "vocabulary",
            vec![edit(Section, "| set | - |", "| table | - |")],
            &["case B2 column `client_secret`", "vocabulary"],
        ),
        row(
            "vocabulary",
            vec![edit(Section, "`[\"mcp:read\"]`", "`[\"mcp:read\"`")],
            &["case A1 column `challenge_scopes`", "not a TOML value"],
        ),
        row(
            "vocabulary",
            vec![edit(Section, "| scopes |", "| `scopes` |")],
            &["case B2 column Roles from", "not a TOML value"],
        ),
        row(
            "vocabulary",
            vec![edit(Section, "`\"groups\"`", "`true`")],
            &["case A1 column Roles from", "must be a string"],
        ),
    ]
}

fn values() -> Vec<Row> {
    vec![
        row(
            "value",
            vec![edit(Section, "`[\"mcp:read\"]`", "`[ \"mcp:read\" ]`")],
            &[],
        ),
        row(
            "value",
            vec![edit(Section, "`[\"mcp:read\"]`", "`[\"mcp:admin\"]`")],
            &["case A1 column `challenge_scopes`"],
        ),
        row(
            "value",
            vec![edit(Section, "| `true` |", "| `\"true\"` |")],
            &["case B2 column `accept_resource_audience`"],
        ),
        row(
            "value",
            vec![edit(
                Toml(A1),
                "[\"mcp:read\"]",
                "[\"mcp:read\", \"mcp:admin\"]",
            )],
            &["case A1 column `challenge_scopes`"],
        ),
        row(
            "absent",
            vec![
                edit(Toml(B2), "accept_resource_audience = true\n", ""),
                edit(Section, "| `true` |", "| - |"),
            ],
            &[],
        ),
        row(
            "absent",
            vec![edit(Section, "| `true` |", "| - |")],
            &["case B2 column `accept_resource_audience`"],
        ),
        row(
            "absent",
            vec![edit(
                Section,
                "| `\"mcp-example\"` | - |",
                "| `\"mcp-example\"` | `\"strict\"` |",
            )],
            &["case A1 column `audience_validation_mode`"],
        ),
        row(
            "absent",
            vec![edit(
                Section,
                "| [B2](#b2---second-case) | - |",
                "| [B2](#b2---second-case) | `\"https://mcp.example\"` |",
            )],
            &["case B2 column `public_url`"],
        ),
    ]
}

/// Every fixture variant, grouped by the rule it exercises.
pub(super) fn rows() -> Vec<Row> {
    [
        structure(),
        layout(),
        vocabulary(),
        values(),
        super::matrix_rows_cells::sources(),
        super::matrix_rows_cells::links(),
    ]
    .into_iter()
    .flatten()
    .collect()
}
