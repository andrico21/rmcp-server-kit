//! Custom `reqwest::dns::Resolve` implementation that closes the
//! TOCTOU window between pre-flight allowlist screening and the actual
//! connect-time DNS lookup performed by `reqwest`.
//!
//! Without this resolver the pre-flight check in `oauth::screen_oauth_target`
//! and `mtls_revocation::CrlSet` could pass for a hostname whose DNS
//! record is then re-resolved (with a different answer) inside
//! `reqwest`'s connector. By installing this resolver via
//! `ClientBuilder::dns_resolver(...)` every DNS answer that ultimately
//! drives a connect call is re-screened against the same
//! `CompiledSsrfAllowlist` using the same `ip_block_reason` helper.
//!
//! Semantics intentionally mirror the pre-flight path
//! (`screen_oauth_target_with_test_override`) line-for-line:
//!
//! - **Cloud-metadata short-circuits** before allowlist consultation
//!   (unbypassable).
//! - **Fail-any-blocked**: if any returned address is blocked and not
//!   covered by the allowlist, the whole resolution fails. Returning a
//!   filtered subset would let `reqwest` happy-eyeballs into the
//!   blocked address on the next attempt.
//! - **Empty input** is treated as a DNS failure (no usable addresses).
//! - **Errors are returned as `Err`**, not as an empty `Addrs`. Returning
//!   `Ok(empty)` would yield `reqwest::Error::Connect` with an opaque
//!   "no addresses" message; an explicit `Err` lets us prefix the
//!   diagnostic with `"ssrf:"` for log forensics.

extern crate alloc;

use alloc::sync::Arc;
#[cfg(any(test, feature = "test-helpers"))]
use core::sync::atomic::{AtomicBool, Ordering};
use core::{
    error::Error,
    net::{IpAddr, SocketAddr},
};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::net::lookup_host;

use crate::ssrf::{CompiledSsrfAllowlist, ip_block_reason};

/// Test-only loopback bypass.
///
/// Shared via `Arc<AtomicBool>` so that the `__test_allow_loopback_ssrf`
/// setter on a client struct flips the flag for every already-built
/// `reqwest::Client` whose resolver captured a clone of the same `Arc`.
/// A per-client `bool` snapshot was rejected by Oracle review B1 (stale
/// flag in cached `OauthHttpClient`s).
#[cfg(any(test, feature = "test-helpers"))]
pub(crate) type TestLoopbackBypass = Arc<AtomicBool>;

/// Production builds carry no bypass state. The `()` placeholder keeps
/// the `SsrfScreeningResolver` field layout uniform across feature
/// combinations without paying for an atomic load on every resolve.
#[cfg(not(any(test, feature = "test-helpers")))]
#[expect(
    clippy::cfg_not_test,
    reason = "deliberate: src/ssrf_resolver.rs::TestLoopbackBypass keeps the test-helpers alias arm cfg-gated"
)]
pub(crate) type TestLoopbackBypass = ();

/// `reqwest::dns::Resolve` implementor that forwards to the system
/// resolver via `tokio::net::lookup_host` and then re-applies the SSRF
/// allowlist on the returned addresses.
#[derive(Clone)]
pub(crate) struct SsrfScreeningResolver {
    /// Compiled allowlist shared with the pre-flight path. `Arc` so the
    /// resolver can be cheaply cloned into each `reqwest` connection
    /// without re-validating the policy.
    allowlist: Arc<CompiledSsrfAllowlist>,
    /// Test-only loopback bypass; see `TestLoopbackBypass` doc.
    #[cfg_attr(
        not(any(test, feature = "test-helpers")),
        expect(
            dead_code,
            reason = "`TestLoopbackBypass` aliases to `()` outside test/test-helpers \
                      builds, so this field is never read there; it is retained so the \
                      resolver has one construction shape across every cfg"
        )
    )]
    test_bypass: TestLoopbackBypass,
}

impl SsrfScreeningResolver {
    /// Build a resolver that screens DNS answers against `allowlist`.
    /// The `test_bypass` argument has no runtime cost in production
    /// builds (it is the unit type `()`).
    pub(crate) const fn new(
        allowlist: Arc<CompiledSsrfAllowlist>,
        test_bypass: TestLoopbackBypass,
    ) -> Self {
        Self {
            allowlist,
            test_bypass,
        }
    }
}

impl Resolve for SsrfScreeningResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allowlist = Arc::clone(&self.allowlist);
        // Capture the bypass holder, not a snapshot of the bool, so that
        // the resolver observes the current value at resolve time.
        #[cfg(any(test, feature = "test-helpers"))]
        let test_bypass = Arc::clone(&self.test_bypass);
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // Port 0 is the conventional placeholder when the DNS
            // resolver does not know the target port. `reqwest` will
            // overwrite the port with the URL's actual port before
            // connecting (see `reqwest::dns::Resolve` rustdoc). We only
            // need IP screening here.
            let raw: Vec<SocketAddr> = lookup_host((host.as_str(), 0)).await?.collect();

            #[cfg(any(test, feature = "test-helpers"))]
            let bypass_loopback = test_bypass.load(Ordering::Relaxed);
            #[cfg(not(any(test, feature = "test-helpers")))]
            #[expect(
                clippy::cfg_not_test,
                reason = "deliberate: src/ssrf_resolver.rs::SsrfScreeningResolver::resolve keeps the test-helpers alias arm cfg-gated"
            )]
            let bypass_loopback = false;

            match screen_addrs(&raw, &allowlist, &host, bypass_loopback) {
                Ok(addrs) => {
                    let iter: Addrs = Box::new(addrs.into_iter());
                    Ok(iter)
                }
                Err(diag) => {
                    let err: Box<dyn Error + Send + Sync> = format!("ssrf: {diag}").into();
                    Err(err)
                }
            }
        })
    }
}

/// Pure, sync screening core extracted for unit-testing without DNS.
///
/// Returns `Err(diagnostic)` on any blocked address (fail-any-blocked
/// matches the pre-flight `screen_oauth_target_with_test_override`
/// behaviour). The diagnostic embeds the host and the offending IP +
/// reason; the caller (`SsrfScreeningResolver::resolve`) re-prefixes
/// it with `"ssrf:"` before handing it to `reqwest`.
///
/// `bypass_loopback`: when true, `loopback` block reasons are demoted
/// so test fixtures bound to `127.0.0.1` can be reached. Cloud-metadata
/// remains unbypassable in every code path.
///
/// # Errors
///
/// Returns `Err` when `addrs` is empty, or when any resolved address is
/// blocked and not permitted by the allowlist. Cloud-metadata is never
/// bypassable, so it fails the whole resolution even when the host is
/// allowlisted.
pub(crate) fn screen_addrs(
    addrs: &[SocketAddr],
    allowlist: &CompiledSsrfAllowlist,
    host: &str,
    bypass_loopback: bool,
) -> Result<Vec<SocketAddr>, String> {
    if addrs.is_empty() {
        return Err(format!("DNS resolution for {host:?} returned no addresses"));
    }

    // Mirror screen_oauth_target's host-allowlist short-circuit so
    // operator policy semantics stay identical between pre-flight and
    // connect-time screening.
    let host_allowed = !allowlist.is_empty() && allowlist.host_allowed(host);

    for addr in addrs {
        let ip: IpAddr = addr.ip();
        let Some(reason) = ip_block_reason(ip) else {
            continue;
        };

        // Cloud-metadata is unbypassable -- short-circuit BEFORE
        // consulting the allowlist or the loopback-bypass flag. This
        // ordering is the security invariant Oracle review S2 requires.
        if reason == "cloud_metadata" {
            return Err(format!(
                "{host:?} resolved to blocked IP {ip} (cloud_metadata)"
            ));
        }

        // Test-only loopback bypass. Production builds compile this as
        // `false` (see resolver) so the branch folds away.
        if bypass_loopback && reason == "loopback" {
            continue;
        }

        // Allowlist consultation. Empty allowlist preserves the
        // historical strict-deny behaviour; a configured allowlist
        // permits hosts or per-IP CIDRs.
        if allowlist.is_empty() {
            return Err(format!("{host:?} resolved to blocked IP {ip} ({reason})"));
        }
        if host_allowed || allowlist.ip_allowed(ip) {
            continue;
        }
        return Err(format!("{host:?} resolved to blocked IP {ip} ({reason})"));
    }

    Ok(addrs.to_vec())
}

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::ssrf::CidrEntry;

    /// Build a port-0 `SocketAddr` for tests.
    fn socket_addr(addr: IpAddr) -> SocketAddr {
        SocketAddr::new(addr, 0)
    }

    fn empty_allowlist() -> CompiledSsrfAllowlist {
        CompiledSsrfAllowlist::default()
    }

    /// Build a compiled allowlist from host and CIDR strings for tests.
    fn allowlist_with(hosts: &[&str], cidrs: &[&str]) -> anyhow::Result<CompiledSsrfAllowlist> {
        let host_names = hosts.iter().map(|host| (*host).to_lowercase()).collect();
        let cidr_entries = cidrs
            .iter()
            .map(|cidr| {
                CidrEntry::parse(cidr)
                    .map_err(|reason| anyhow::anyhow!("test CIDR parses: {reason}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(CompiledSsrfAllowlist::new(host_names, cidr_entries))
    }

    #[test]
    /// Pins that an empty resolution is rejected as having no addresses.
    fn rejects_empty_addrs() -> anyhow::Result<()> {
        let err = screen_addrs(&[], &empty_allowlist(), "example.com", false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("empty resolution must error"))?;
        assert!(err.contains("returned no addresses"), "{err}");
        Ok(())
    }

    #[test]
    /// Pins that a public IPv4 address passes an empty allowlist.
    fn allows_public_ipv4() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))];
        let out = screen_addrs(&addrs, &empty_allowlist(), "dns.google", false)
            .map_err(|diag| anyhow::anyhow!("public IPv4 must pass: {diag}"))?;
        assert_eq!(out, addrs);
        Ok(())
    }

    #[test]
    /// Pins that loopback is blocked under an empty allowlist.
    fn rejects_loopback_under_empty_allowlist() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "localhost", false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("loopback must be blocked"))?;
        assert!(err.contains("loopback"), "{err}");
        Ok(())
    }

    #[test]
    /// Pins that private RFC1918 space is blocked under an empty allowlist.
    fn rejects_private_under_empty_allowlist() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "internal", false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("private RFC1918 must be blocked"))?;
        assert!(err.contains("private_rfc1918"), "{err}");
        Ok(())
    }

    #[test]
    /// Pins that cloud-metadata stays blocked even with a full allowlist.
    fn rejects_cloud_metadata_even_with_full_allowlist() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))];
        let allowlist = allowlist_with(&["meta.example"], &["169.254.0.0/16"])?;
        let err = screen_addrs(&addrs, &allowlist, "meta.example", false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("cloud_metadata must be unbypassable"))?;
        assert!(err.contains("cloud_metadata"), "{err}");
        Ok(())
    }

    #[test]
    /// Pins that NAT64-wrapped cloud-metadata stays blocked even when the transition prefix is allowlisted.
    fn rejects_nat64_embedded_metadata_even_with_transition_allowlist() -> anyhow::Result<()> {
        // NAT64-wrapped 169.254.169.254 must stay blocked even when the
        // transition prefix is allowlisted (M2 regression).
        let addrs = vec![socket_addr(IpAddr::V6(Ipv6Addr::new(
            0x0064, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe,
        )))];
        let allowlist = allowlist_with(&[], &["64:ff9b::/96"])?;
        let err = screen_addrs(&addrs, &allowlist, "nat64.example", false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("nat64-embedded metadata must be unbypassable"))?;
        assert!(err.contains("cloud_metadata"), "{err}");
        Ok(())
    }

    #[test]
    /// Pins that cloud-metadata survives the test-only loopback bypass.
    fn rejects_cloud_metadata_even_with_loopback_bypass() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "meta", true)
            .err()
            .ok_or_else(|| anyhow::anyhow!("cloud_metadata must survive loopback bypass"))?;
        assert!(err.contains("cloud_metadata"), "{err}");
        Ok(())
    }

    #[test]
    /// Pins that a mixed answer with any blocked address fails the whole resolution.
    fn fails_any_blocked_when_mixed() -> anyhow::Result<()> {
        // Mixed answer with one public and one private IP must fail
        // entirely; returning only the public subset would let
        // happy-eyeballs reach the private IP on the next attempt.
        let addrs = vec![
            socket_addr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            socket_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        ];
        let err = screen_addrs(&addrs, &empty_allowlist(), "split-horizon", false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("any blocked address must fail the whole resolution"))?;
        assert!(err.contains("private_rfc1918"), "{err}");
        Ok(())
    }

    #[test]
    /// Pins that a host allowlist permits a private IP.
    fn host_allowlist_permits_private() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))];
        let allowlist = allowlist_with(&["internal.corp"], &[])?;
        let out = screen_addrs(&addrs, &allowlist, "internal.corp", false)
            .map_err(|diag| anyhow::anyhow!("host allowlist must permit private IP: {diag}"))?;
        assert_eq!(out, addrs);
        Ok(())
    }

    #[test]
    /// Pins that a CIDR allowlist permits an IP inside its range.
    fn cidr_allowlist_permits_private() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))];
        let allowlist = allowlist_with(&[], &["10.0.0.0/8"])?;
        let out = screen_addrs(&addrs, &allowlist, "internal", false)
            .map_err(|diag| anyhow::anyhow!("CIDR allowlist must permit IP in range: {diag}"))?;
        assert_eq!(out, addrs);
        Ok(())
    }

    #[test]
    /// Pins that a CIDR allowlist rejects an IP outside its range.
    fn cidr_allowlist_rejects_out_of_range() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        let allowlist = allowlist_with(&[], &["10.0.0.0/8"])?;
        let err = screen_addrs(&addrs, &allowlist, "elsewhere", false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("non-allowlisted private IP must fail"))?;
        assert!(err.contains("private_rfc1918"), "{err}");
        Ok(())
    }

    #[test]
    /// Pins that the loopback bypass does not permit non-loopback private IPs.
    fn loopback_bypass_permits_only_loopback() -> anyhow::Result<()> {
        // Loopback bypass must NOT permit non-loopback private IPs.
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "internal", true)
            .err()
            .ok_or_else(|| anyhow::anyhow!("loopback bypass must not allow RFC1918"))?;
        assert!(err.contains("private_rfc1918"), "{err}");
        Ok(())
    }

    #[test]
    /// Pins that the loopback bypass permits `127.0.0.1`.
    fn loopback_bypass_permits_127_0_0_1() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let out = screen_addrs(&addrs, &empty_allowlist(), "localhost", true)
            .map_err(|diag| anyhow::anyhow!("loopback bypass must permit 127.0.0.1: {diag}"))?;
        assert_eq!(out, addrs);
        Ok(())
    }

    #[test]
    /// Pins that IPv6 loopback is blocked without the bypass.
    fn ipv6_loopback_blocked_without_bypass() -> anyhow::Result<()> {
        let addrs = vec![socket_addr(IpAddr::V6(Ipv6Addr::LOCALHOST))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "localhost", false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("IPv6 loopback must be blocked"))?;
        assert!(err.contains("loopback"), "{err}");
        Ok(())
    }
}
