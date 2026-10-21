//! Process-independent TLS setup shared by every harness network constructor.

use core::time::Duration;
use std::sync::Once;

use reqwest::{Client, redirect::Policy};
use rustls::crypto::ring;

pub(super) fn install_provider() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| drop(ring::default_provider().install_default()));
}

pub(super) fn client() -> anyhow::Result<Client> {
    install_provider();
    Ok(Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?)
}

/// A client constructor installs TLS support without relying on sibling network fixtures.
#[test]
fn client_builds_when_no_other_network_helper_has_run() -> anyhow::Result<()> {
    let _client = client()?;
    Ok(())
}
