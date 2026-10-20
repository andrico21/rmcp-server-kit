//! Accepted and rejected fixture edits for secrets, roles, tables, links and settings lines.

use super::matrix_tables::{
    Row,
    Target::{Env, Section, Toml},
    edit, row,
};

const A1: usize = 0;
const B2: usize = 1;
const PREVIOUS: &str =
    "\nRMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__SEALING_SECRET_PREVIOUS=fake-previous";
const FILE: &str = "SEALING_SECRET_FILE=/run/fake";
const EXCHANGE: &str =
    "[server.auth.oauth.token_exchange]\ntoken_url = \"https://idp.example/token\"\n";

fn secrets() -> Vec<Row> {
    vec![
        row(
            "secret",
            vec![
                edit(Env(B2), FILE, "SEALING_SECRET=fake-value"),
                edit(Section, "| set (file) |", "| set |"),
            ],
            &[],
        ),
        row(
            "secret",
            vec![
                edit(
                    Toml(B2),
                    "consent_ttl",
                    "sealing_secret = \"fake-sealing-value\"\nconsent_ttl",
                ),
                edit(
                    Env(B2),
                    &format!("RMCP_SERVER_KIT__SERVER__AUTH__OAUTH__PROXY__{FILE}\n"),
                    "",
                ),
                edit(Section, "| set (file) |", "| set |"),
            ],
            &[],
        ),
        row(
            "secret",
            vec![edit(Section, "| set (file) |", "| set |")],
            &["case B2 column `sealing_secret`"],
        ),
        row(
            "secret",
            vec![edit(Env(B2), FILE, "SEALING_SECRET=fake-value")],
            &["case B2 column `sealing_secret`"],
        ),
        row(
            "secret",
            vec![edit(Env(B2), PREVIOUS, "")],
            &["case B2 column `sealing_secret_previous`"],
        ),
        row(
            "secret",
            vec![edit(Section, "| set | - |", "| - | - |")],
            &["case B2 column `client_secret`"],
        ),
    ]
}

/// Roles, secrets and tables rows.
pub(super) fn sources() -> Vec<Row> {
    let mut rows = vec![
        row(
            "roles",
            vec![
                edit(
                    Toml(A1),
                    "role_claim = \"groups\"",
                    "[[server.auth.oauth.scopes]]\nscope = \"x\"\nrole = \"y\"",
                ),
                edit(Section, "`\"groups\"`", "scopes"),
            ],
            &[],
        ),
        row(
            "roles",
            vec![edit(Section, "`\"groups\"`", "`\"roles\"`")],
            &["case A1 column Roles from"],
        ),
        row(
            "roles",
            vec![edit(Section, "| scopes |", "| `\"groups\"` |")],
            &["case B2 column Roles from"],
        ),
        row(
            "roles",
            vec![edit(Section, "| scopes |", "| - |")],
            &["case B2 column Roles from"],
        ),
        row(
            "roles",
            vec![edit(
                Toml(B2),
                "accept_resource_audience = true",
                "accept_resource_audience = true\nrole_claim = \"groups\"",
            )],
            &["case B2 column Roles from", "both scopes and role_claim"],
        ),
        row(
            "table",
            vec![
                edit(Toml(B2), EXCHANGE, ""),
                edit(Section, "| table |", "| - |"),
            ],
            &[],
        ),
        row(
            "table",
            vec![edit(Section, "| table |", "| - |")],
            &["case B2 column `token_exchange`"],
        ),
        row(
            "table",
            vec![edit(
                Section,
                "| - | - | groups mapper |",
                "| table | - | groups mapper |",
            )],
            &["case A1 column `token_exchange`"],
        ),
    ];
    rows.extend(secrets());
    rows
}

pub(super) fn links() -> Vec<Row> {
    vec![
        row(
            "link",
            vec![
                edit(Section, "### A1 - First", "### A1 - First, again"),
                edit(Section, "(#a1---first)", "(#a1---first-again)"),
            ],
            &[],
        ),
        row(
            "link",
            vec![edit(Section, "(#a1---first)", "(#b2---second-case)")],
            &["case A1", "link #b2---second-case"],
        ),
        row(
            "link",
            vec![edit(Section, "[A1](#a1---first)", "A1")],
            &["must be [ID](#anchor)"],
        ),
        row(
            "settings",
            vec![edit(Section, "row A1.", "row A1. More prose.")],
            &[],
        ),
        row(
            "settings",
            vec![edit(
                Section,
                &format!("{}\n\n", super::matrix_tables::SETTINGS_A1),
                "",
            )],
            &["case A1", "Settings:"],
        ),
        row(
            "settings",
            vec![edit(Section, " and [proxy](#settings-matrix-proxy)", "")],
            &["case B2", "Settings:"],
        ),
        row(
            "settings",
            vec![edit(
                Section,
                "row A1.",
                "row A1, [proxy](#settings-matrix-proxy).",
            )],
            &["case A1", "Settings:"],
        ),
        row(
            "settings",
            vec![edit(Section, "row A1.", "row A2.")],
            &["case A1", "Settings:"],
        ),
    ]
}
