//! Dual-stack loopback IdP, adapted from the e2e target's `DualStackMock`.

use core::net::{Ipv4Addr, Ipv6Addr};
use std::{io::ErrorKind, net::TcpListener};

use anyhow::Context as _;
use wiremock::{Mock, MockServer, Request};

pub(super) struct DualStackMock {
    v4: MockServer,
    v6: Option<MockServer>,
}

impl DualStackMock {
    // cancel-safe: local listeners and started mocks drop when the future is dropped.
    pub(super) async fn start() -> anyhow::Result<Self> {
        super::network::install_provider();
        for _ in 0..16_u8 {
            let v4_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = v4_listener.local_addr()?.port();
            match TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
                Ok(v6_listener) => {
                    let v4 = MockServer::builder().listener(v4_listener).start().await;
                    let v6 = MockServer::builder().listener(v6_listener).start().await;
                    return Ok(Self { v4, v6: Some(v6) });
                }
                Err(error) if error.kind() == ErrorKind::AddrInUse => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::AddrNotAvailable | ErrorKind::Unsupported
                    ) =>
                {
                    let v4 = MockServer::builder().listener(v4_listener).start().await;
                    return Ok(Self { v4, v6: None });
                }
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("no shared IPv4/IPv6 mock port after 16 attempts")
    }

    pub(super) fn base(&self) -> String {
        format!("http://localhost:{}", self.v4.address().port())
    }

    // cancel-safe: partially mounted mocks are owned by this fixture and dropped together.
    pub(super) async fn mount<Build>(&self, build: Build)
    where
        Build: Fn() -> Mock,
    {
        build().mount(&self.v4).await;
        if let Some(v6) = &self.v6 {
            build().mount(v6).await;
        }
    }

    // cancel-safe: reading recordings changes no mock state.
    pub(super) async fn requests(&self) -> anyhow::Result<Vec<Request>> {
        let mut requests = Vec::new();
        for server in [Some(&self.v4), self.v6.as_ref()].into_iter().flatten() {
            requests.extend(
                server
                    .received_requests()
                    .await
                    .context("mock recording disabled")?,
            );
        }
        Ok(requests)
    }

    // cancel-safe: reading each independent recording changes no mock state.
    pub(super) async fn offsets(&self) -> anyhow::Result<Vec<usize>> {
        let mut offsets = Vec::new();
        for server in [Some(&self.v4), self.v6.as_ref()].into_iter().flatten() {
            offsets.push(
                server
                    .received_requests()
                    .await
                    .context("mock recording disabled")?
                    .len(),
            );
        }
        Ok(offsets)
    }

    // cancel-safe: recordings are copied per address family without resetting shared state.
    pub(super) async fn requests_since(&self, offsets: &[usize]) -> anyhow::Result<Vec<Request>> {
        let mut requests = Vec::new();
        for (server, offset) in [Some(&self.v4), self.v6.as_ref()]
            .into_iter()
            .flatten()
            .zip(offsets)
        {
            requests.extend(
                server
                    .received_requests()
                    .await
                    .context("mock recording disabled")?
                    .into_iter()
                    .skip(*offset),
            );
        }
        Ok(requests)
    }
}
