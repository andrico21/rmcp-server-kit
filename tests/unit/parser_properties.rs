//! Property-based tests for the RBAC JSON-RPC/argument parsing surface that
//! is reachable through the crate's public API.
//!
//! The crate-private parsers (forwarded-header resolution, session/task
//! binding) have in-module `proptest!` blocks next to the code they pin; this
//! target covers the public `RbacPolicy` matcher that `tools/call` parsing
//! funnels into. Every property feeds generator-produced strings - including
//! glob metacharacters, unbalanced shell quoting and non-ASCII text - and
//! asserts an invariant that must hold for *all* of them, so a regression in
//! the matcher is caught probabilistically rather than by hand-picked examples.
//!
//! Targets:
//!
//! 1. **Wildcard allow admits everything** - a role whose allowlist is `*`
//!    must allow any operation, on any host, for any argument value, without
//!    panicking in the glob/host matchers.
//! 2. **Unknown role is denied** - a role name not configured must be denied
//!    by every entry point.
//! 3. **Malformed shell quoting fails closed** - a value with an unbalanced
//!    double quote must never pass an argument allowlist.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rmcp_server_kit::rbac::{
        ArgumentAllowlist, RbacConfig, RbacDecision, RbacPolicy, RoleConfig,
    };

    /// Build an enabled policy from one role.
    fn enabled_policy(role: RoleConfig) -> RbacPolicy {
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        RbacPolicy::new(&config)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// A role whose allowlist is `*` allows any operation on any host and
        /// imposes no argument allowlist, for arbitrary input strings.
        #[test]
        fn prop_wildcard_allow_admits_arbitrary_operations(
            operation in ".{0,40}",
            host in ".{0,40}",
            value in ".{0,40}",
        ) {
            let policy = enabled_policy(RoleConfig::new(
                "editor",
                vec!["*".to_owned()],
                vec!["*".to_owned()],
            ));
            prop_assert_eq!(
                policy.check_operation("editor", &operation),
                RbacDecision::Allow,
                "a `*` allowlist must admit operation {:?}",
                operation
            );
            prop_assert_eq!(
                policy.check("editor", &operation, &host),
                RbacDecision::Allow,
                "a `*` allowlist must admit operation {:?} on host {:?}",
                operation,
                host
            );
            prop_assert!(
                policy.argument_allowed("editor", "run", "cmd", &value),
                "with no argument allowlist, value {:?} must pass",
                value
            );
        }

        /// A role name that is not configured must be denied by every entry
        /// point, whatever the operation, host or argument value.
        #[test]
        fn prop_unknown_role_is_denied(
            role in "[A-Z][A-Z0-9_]{2,15}",
            operation in "[a-z_]{1,16}",
            host in "[a-z0-9.]{1,20}",
        ) {
            let policy = enabled_policy(RoleConfig::new(
                "editor",
                vec!["*".to_owned()],
                vec!["*".to_owned()],
            ));
            prop_assert_eq!(
                policy.check_operation(&role, &operation),
                RbacDecision::Deny,
                "unknown role {:?} must not perform {:?}",
                role,
                operation
            );
            prop_assert_eq!(
                policy.check(&role, &operation, &host),
                RbacDecision::Deny,
                "unknown role {:?} must not reach host {:?}",
                role,
                host
            );
            prop_assert!(
                !policy.argument_allowed(&role, "run", "cmd", "ls"),
                "unknown role {:?} must not pass an argument allowlist",
                role
            );
        }

        /// A value carrying an unbalanced double quote must fail closed rather
        /// than be normalized into an allowlisted command.
        #[test]
        fn prop_unbalanced_quote_argument_is_denied(
            prefix in "[a-z ]{0,8}",
            suffix in "[a-z ]{0,8}",
        ) {
            let policy = enabled_policy(
                RoleConfig::new("editor", vec!["run".to_owned()], vec!["*".to_owned()])
                    .with_argument_allowlists(vec![ArgumentAllowlist::new(
                        "run",
                        "cmd",
                        vec!["ls".to_owned()],
                    )]),
            );
            let value = format!("{prefix}\"ls{suffix}");
            prop_assert!(
                !policy.argument_allowed("editor", "run", "cmd", &value),
                "unbalanced quote must be denied: {:?}",
                value
            );
        }
    }
}
