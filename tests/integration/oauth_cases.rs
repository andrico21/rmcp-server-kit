//! Executable OAuth documentation contracts, restricted to section seven.

extern crate alloc;

#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[cfg(test)]
#[path = "oauth_cases"]
mod tests {
    mod case_info;
    mod catalogue;
    mod compare;
    mod comparison_tables;
    mod configuration;
    mod env_tests;
    mod environment;
    mod fence_tables;
    mod fixtures;
    mod grammar;
    mod grammar_tables;
    mod identity;
    mod library;
    mod library_rows;
    mod library_tables;
    mod mock;
    mod network;
    mod runtime;
    mod runtime_tables;
    mod self_tests;
    mod wildcard_tables;
}
