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

#[cfg(any(test, feature = "test-helpers"))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::net::lookup_host;

use crate::ssrf::{CompiledSsrfAllowlist, ip_block_reason};

/// Test-only loopback bypass. Shared via `Arc<AtomicBool>` so that the
/// `__test_allow_loopback_ssrf` setter on a client struct flips the
/// flag for every already-built `reqwest::Client` whose resolver
/// captured a clone of the same `Arc`. A per-client `bool` snapshot
/// was rejected by Oracle review B1 (stale flag in cached
/// `OauthHttpClient`s).
#[cfg(any(test, feature = "test-helpers"))]
pub(crate) type TestLoopbackBypass = Arc<AtomicBool>;

/// Production builds carry no bypass state. The `()` placeholder keeps
/// the `SsrfScreeningResolver` field layout uniform across feature
/// combinations without paying for an atomic load on every resolve.
#[cfg(not(any(test, feature = "test-helpers")))]
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
    #[cfg_attr(not(any(test, feature = "test-helpers")), allow(dead_code))]
    test_bypass: TestLoopbackBypass,
}

impl SsrfScreeningResolver {
    /// Build a resolver that screens DNS answers against `allowlist`.
    /// The `test_bypass` argument has no runtime cost in production
    /// builds (it is the unit type `()`).
    pub(crate) fn new(
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
            let bypass_loopback = false;

            match screen_addrs(&raw, &allowlist, &host, bypass_loopback) {
                Ok(addrs) => {
                    let iter: Addrs = Box::new(addrs.into_iter());
                    Ok(iter)
                }
                Err(diag) => {
                    let err: Box<dyn std::error::Error + Send + Sync> =
                        format!("ssrf: {diag}").into();
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::ssrf::{CidrEntry, CompiledSsrfAllowlist};

    fn sa(ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, 0)
    }

    fn empty_allowlist() -> CompiledSsrfAllowlist {
        CompiledSsrfAllowlist::default()
    }

    fn allowlist_with(hosts: &[&str], cidrs: &[&str]) -> CompiledSsrfAllowlist {
        let hosts = hosts.iter().map(|h| (*h).to_lowercase()).collect();
        let cidrs = cidrs
            .iter()
            .map(|c| CidrEntry::parse(c).expect("test CIDR parses"))
            .collect();
        CompiledSsrfAllowlist::new(hosts, cidrs)
    }

    #[test]
    fn rejects_empty_addrs() {
        let err = screen_addrs(&[], &empty_allowlist(), "example.com", false)
            .expect_err("empty resolution must error");
        assert!(err.contains("returned no addresses"), "{err}");
    }

    #[test]
    fn allows_public_ipv4() {
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))];
        let out = screen_addrs(&addrs, &empty_allowlist(), "dns.google", false)
            .expect("public IPv4 must pass");
        assert_eq!(out, addrs);
    }

    #[test]
    fn rejects_loopback_under_empty_allowlist() {
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "localhost", false)
            .expect_err("loopback must be blocked");
        assert!(err.contains("loopback"), "{err}");
    }

    #[test]
    fn rejects_private_under_empty_allowlist() {
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "internal", false)
            .expect_err("private RFC1918 must be blocked");
        assert!(err.contains("private_rfc1918"), "{err}");
    }

    #[test]
    fn rejects_cloud_metadata_even_with_full_allowlist() {
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))];
        let allowlist = allowlist_with(&["meta.example"], &["169.254.0.0/16"]);
        let err = screen_addrs(&addrs, &allowlist, "meta.example", false)
            .expect_err("cloud_metadata must be unbypassable");
        assert!(err.contains("cloud_metadata"), "{err}");
    }

    #[test]
    fn rejects_cloud_metadata_even_with_loopback_bypass() {
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "meta", true)
            .expect_err("cloud_metadata must survive loopback bypass");
        assert!(err.contains("cloud_metadata"), "{err}");
    }

    #[test]
    fn fails_any_blocked_when_mixed() {
        // Mixed answer with one public and one private IP must fail
        // entirely; returning only the public subset would let
        // happy-eyeballs reach the private IP on the next attempt.
        let addrs = vec![
            sa(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            sa(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        ];
        let err = screen_addrs(&addrs, &empty_allowlist(), "split-horizon", false)
            .expect_err("any blocked address must fail the whole resolution");
        assert!(err.contains("private_rfc1918"), "{err}");
    }

    #[test]
    fn host_allowlist_permits_private() {
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))];
        let allowlist = allowlist_with(&["internal.corp"], &[]);
        let out = screen_addrs(&addrs, &allowlist, "internal.corp", false)
            .expect("host allowlist must permit private IP");
        assert_eq!(out, addrs);
    }

    #[test]
    fn cidr_allowlist_permits_private() {
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))];
        let allowlist = allowlist_with(&[], &["10.0.0.0/8"]);
        let out = screen_addrs(&addrs, &allowlist, "internal", false)
            .expect("CIDR allowlist must permit IP in range");
        assert_eq!(out, addrs);
    }

    #[test]
    fn cidr_allowlist_rejects_out_of_range() {
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        let allowlist = allowlist_with(&[], &["10.0.0.0/8"]);
        let err = screen_addrs(&addrs, &allowlist, "elsewhere", false)
            .expect_err("non-allowlisted private IP must fail");
        assert!(err.contains("private_rfc1918"), "{err}");
    }

    #[test]
    fn loopback_bypass_permits_only_loopback() {
        // Loopback bypass must NOT permit non-loopback private IPs.
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "internal", true)
            .expect_err("loopback bypass must not allow RFC1918");
        assert!(err.contains("private_rfc1918"), "{err}");
    }

    #[test]
    fn loopback_bypass_permits_127_0_0_1() {
        let addrs = vec![sa(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let out = screen_addrs(&addrs, &empty_allowlist(), "localhost", true)
            .expect("loopback bypass must permit 127.0.0.1");
        assert_eq!(out, addrs);
    }

    #[test]
    fn ipv6_loopback_blocked_without_bypass() {
        let addrs = vec![sa(IpAddr::V6(Ipv6Addr::LOCALHOST))];
        let err = screen_addrs(&addrs, &empty_allowlist(), "localhost", false)
            .expect_err("IPv6 loopback must be blocked");
        assert!(err.contains("loopback"), "{err}");
    }
}
