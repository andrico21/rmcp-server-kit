//! Skill fixtures and the `[rbac]` builders shared by the B4 cases.

use super::*;

/// The four skill directories and their skill names.
pub(super) const SKILL_DIRS: [(&str, &str); 4] = [
    ("skill://acme/billing/", "billing"),
    ("skill://acme/hr/", "hr"),
    ("skill://other/x/", "x"),
    ("file:///srv/skills/hr2/", "hr2"),
];
pub(super) const BILLING_MD: &str = "skill://acme/billing/SKILL.md";
pub(super) const BILLING_NOTES: &str = "skill://acme/billing/notes.md";
pub(super) const HR_MD: &str = "skill://acme/hr/SKILL.md";
pub(super) const HR2_MD: &str = "file:///srv/skills/hr2/SKILL.md";
pub(super) const PUB: &str = "file:///pub/a.txt";
pub(super) const PRIV: &str = "file:///priv/b.txt";

/// A skill with a manifest listing its `SKILL.md` and `notes.md`.
pub(super) fn skill_in(dir: &str, name: &str) -> Skill {
    let digest = format!("sha256:{}", "a".repeat(64));
    let entry = format!("{dir}SKILL.md");
    Skill::new(
        entry.clone(),
        SkillFrontmatter::new(name, "rbac skills e2e"),
        SkillResources::Files(vec![
            SkillResource::new(entry, digest.clone(), 1),
            SkillResource::new(format!("{dir}notes.md"), digest, 1),
        ]),
    )
}

pub(super) fn all_skills() -> Vec<Skill> {
    SKILL_DIRS
        .iter()
        .map(|(dir, name)| skill_in(dir, name))
        .collect()
}

/// Every URI the handler can resolve, in its listing order.
pub(super) fn all_files() -> Vec<String> {
    let mut files: Vec<String> = SKILL_DIRS
        .iter()
        .flat_map(|(dir, _)| [format!("{dir}SKILL.md"), format!("{dir}notes.md")])
        .collect();
    files.extend([PUB.to_owned(), PRIV.to_owned()]);
    files
}

pub(super) fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|uri| (*uri).to_owned()).collect()
}

/// The main `[rbac]`: extra root `file:///srv/skills/`, restrict mode on,
/// `analyst` with `analyst_skills` and `resources = ["file:///pub/*"]`, and
/// `legacy` with neither setting.
pub(super) fn main_rbac(analyst_skills: &[&str]) -> RbacConfig {
    RbacConfig::with_roles(vec![
        RoleConfig::new("analyst", vec![], vec!["*".into()])
            .with_skills(owned(analyst_skills))
            .with_resources(owned(&["file:///pub/*"])),
        RoleConfig::new("legacy", vec![], vec!["*".into()]),
    ])
    .with_skill_roots(owned(&["file:///srv/skills/"]))
    .with_restrict_resources(true)
}

/// `config` after `RbacConfig::validate`, as a policy.
pub(super) fn validated(config: &RbacConfig) -> anyhow::Result<RbacPolicy> {
    config.validate().context("rbac config validates")?;
    Ok(RbacPolicy::new(config))
}
