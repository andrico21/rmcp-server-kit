use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

/// AWS / GCP / Azure metadata endpoint. Always blocked even if private
/// IPs are otherwise allowed -- this address is unique to cloud-VM
/// privilege-escalation pivots.
pub(crate) const CLOUD_METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Alibaba Cloud / Tencent Cloud instance metadata endpoint. Lives
/// inside the 100.64.0.0/10 CGNAT range but is treated as cloud-metadata
/// so it cannot be re-allowed via a CGNAT-wide operator allowlist.
pub(crate) const CLOUD_METADATA_V4_ALIBABA: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);

/// AWS IPv6 instance metadata endpoint (`fd00:ec2::254`, IMDSv2 over IPv6).
/// Lives inside `fc00::/7` (unique-local) but is treated as cloud-metadata
/// so it cannot be re-allowed via a `fd00::/8` operator allowlist.
///
/// Source: <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html>
pub(crate) const CLOUD_METADATA_V6_AWS: Ipv6Addr =
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// GCP IPv6 instance metadata endpoint (`fd20:ce::254`). Lives inside
/// `fc00::/7` (unique-local) but is treated as cloud-metadata so it
/// cannot be re-allowed via a `fc00::/7` operator allowlist.
///
/// Source: <https://cloud.google.com/compute/docs/metadata/overview>
pub(crate) const CLOUD_METADATA_V6_GCP: Ipv6Addr =
    Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254);

/// Validate scheme of a parsed CDP URL.
///
/// Accepts only `https`, plus `http` when `allow_http` is true. Rejects
/// anything else (`file`, `ldap`, `ftp`, ...). Scheme is matched
/// case-insensitively per RFC 3986 §3.1, but `Url::parse` already
/// lowercases it.
pub(crate) fn check_scheme(url: &Url, allow_http: bool) -> Result<(), &'static str> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        "http" => Err("http_scheme_disallowed"),
        _ => Err("invalid_scheme"),
    }
}

/// Check whether an IP address must be rejected before any TCP connect.
/// Returns `Some(reason)` if blocked, `None` if permitted.
///
/// Blocked classes:
/// - Cloud metadata service (IPv4 `169.254.169.254`, Alibaba/Tencent
///   `100.100.100.200`, AWS IPv6 `fd00:ec2::254`, GCP IPv6 `fd20:ce::254`).
/// - IPv4 loopback (127.0.0.0/8), unspecified (0.0.0.0), broadcast.
/// - IPv4 RFC 1918 private (10/8, 172.16/12, 192.168/16).
/// - IPv4 link-local (169.254/16).
/// - IPv4 CGNAT (100.64/10).
/// - IPv4 documentation (192.0.2/24, 198.51.100/24, 203.0.113/24).
/// - IPv4 benchmarking (198.18/15).
/// - IPv4 multicast (224/4) and reserved future use (240/4).
/// - IPv6 loopback (`::1`), unspecified (`::`).
/// - IPv6 link-local (`fe80::/10`).
/// - IPv6 unique local (`fc00::/7`).
/// - IPv6 multicast (`ff00::/8`).
/// - IPv6 documentation (`2001:db8::/32`).
/// - IPv4-mapped IPv6 inheriting any of the above.
///
/// **Cloud-metadata addresses are checked BEFORE the generic buckets** so
/// that an operator allowlist (see [`CompiledSsrfAllowlist`]) covering
/// e.g. `fd00::/8` or `100.64.0.0/10` cannot silently re-allow them.
pub(crate) fn ip_block_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => block_reason_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return block_reason_v4(mapped);
            }
            block_reason_v6(v6)
        }
    }
}

fn block_reason_v4(v4: Ipv4Addr) -> Option<&'static str> {
    // Cloud-metadata MUST be checked first so it wins over CGNAT
    // (Alibaba metadata sits inside 100.64.0.0/10) and link-local
    // (AWS metadata sits inside 169.254.0.0/16).
    if v4 == CLOUD_METADATA_V4 || v4 == CLOUD_METADATA_V4_ALIBABA {
        return Some("cloud_metadata");
    }
    if v4.is_loopback() {
        return Some("loopback");
    }
    if v4.is_unspecified() {
        return Some("unspecified");
    }
    if v4.is_broadcast() {
        return Some("broadcast");
    }
    if v4.is_private() {
        return Some("private_rfc1918");
    }
    if v4.is_link_local() {
        return Some("link_local");
    }
    if v4.is_multicast() {
        return Some("multicast");
    }
    let octets = v4.octets();
    // CGNAT 100.64.0.0/10 (RFC 6598).
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000 {
        return Some("cgnat");
    }
    // Documentation 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return Some("documentation");
    }
    // Benchmarking 198.18.0.0/15 (RFC 2544).
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return Some("benchmarking");
    }
    // Reserved 240.0.0.0/4.
    if octets[0] >= 240 {
        return Some("reserved");
    }
    None
}

fn block_reason_v6(v6: Ipv6Addr) -> Option<&'static str> {
    // Cloud-metadata MUST be checked first so it wins over the generic
    // unique-local bucket (AWS `fd00:ec2::254` and GCP `fd20:ce::254`
    // both sit inside `fc00::/7`).
    if v6 == CLOUD_METADATA_V6_AWS || v6 == CLOUD_METADATA_V6_GCP {
        return Some("cloud_metadata");
    }
    if v6.is_loopback() {
        return Some("loopback");
    }
    if v6.is_unspecified() {
        return Some("unspecified");
    }
    if v6.is_multicast() {
        return Some("multicast");
    }
    let segments = v6.segments();
    // Link-local fe80::/10.
    if (segments[0] & 0xffc0) == 0xfe80 {
        return Some("link_local");
    }
    // Unique local fc00::/7.
    if (segments[0] & 0xfe00) == 0xfc00 {
        return Some("unique_local");
    }
    // Documentation 2001:db8::/32.
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some("documentation");
    }
    None
}

/// Sync pre-DNS literal-IP check. Any literal IPv4 or IPv6 host is
/// rejected at URL-validation time, regardless of whether the address
/// falls in a private or public range. OAuth operators must use DNS
/// hostnames; post-DNS runtime checks remain the responsibility of the
/// fetch path.
#[cfg(feature = "oauth")]
pub(crate) fn check_url_literal_ip(url: &Url) -> Option<&'static str> {
    match url.host()? {
        url::Host::Ipv4(_) => Some("literal IPv4 addresses are forbidden; use a DNS hostname"),
        url::Host::Ipv6(_) => Some("literal IPv6 addresses are forbidden; use a DNS hostname"),
        url::Host::Domain(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Operator SSRF allowlist (CIDR + host) for OAuth/JWKS targets
// ---------------------------------------------------------------------------

/// Single CIDR entry as parsed from operator config. Stores the network
/// address (host bits cleared at parse time) and the prefix length so a
/// candidate `IpAddr` can be matched against it without re-parsing on
/// every request.
#[cfg(feature = "oauth")]
#[derive(Debug, Clone)]
pub(crate) struct CidrEntry {
    network: IpAddr,
    prefix_len: u8,
}

#[cfg(feature = "oauth")]
impl CidrEntry {
    /// Parse a CIDR like `10.0.0.0/8` or `fd00::/8`. Validates the
    /// prefix length, that the IP family is consistent, and that the
    /// host bits are zero (e.g. `10.0.0.1/8` is rejected so operator
    /// typos surface at config time).
    ///
    /// Rejects:
    /// - Missing `/` separator.
    /// - Non-numeric prefix.
    /// - Prefix > 32 (IPv4) or > 128 (IPv6).
    /// - **Prefix `0`** (`0.0.0.0/0` / `::/0`) -- would defeat the entire
    ///   guard by allowing every address.
    /// - **IPv4-mapped IPv6 CIDRs** (`::ffff:127.0.0.0/104`) -- write the
    ///   IPv4 form instead. This matches `ip_block_reason`'s normalization
    ///   so the runtime check and the allowlist agree on family.
    /// - IPv6 zone identifiers (`fe80::1%eth0/64`) -- rejected by
    ///   `IpAddr::from_str` directly.
    /// - Non-zero host bits (`10.0.0.1/8`).
    ///
    /// Uses `std::net` only -- no new dependencies.
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let Some((addr_str, prefix_str)) = raw.split_once('/') else {
            return Err(format!("CIDR {raw:?} missing '/' prefix length"));
        };
        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|e| format!("CIDR {raw:?}: invalid prefix length {prefix_str:?}: {e}"))?;
        let addr: IpAddr = addr_str
            .parse()
            .map_err(|e| format!("CIDR {raw:?}: invalid address {addr_str:?}: {e}"))?;
        if prefix_len == 0 {
            return Err(format!(
                "CIDR {raw:?}: prefix length 0 is forbidden (would allow every address)"
            ));
        }
        match addr {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return Err(format!(
                        "CIDR {raw:?}: IPv4 prefix length {prefix_len} exceeds 32"
                    ));
                }
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - prefix_len))
                    .unwrap_or(0);
                let bits = u32::from_be_bytes(v4.octets());
                if bits & !mask != 0 {
                    return Err(format!(
                        "CIDR {raw:?}: address {addr_str} has non-zero host bits for /{prefix_len}"
                    ));
                }
                Ok(Self {
                    network: IpAddr::V4(v4),
                    prefix_len,
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return Err(format!(
                        "CIDR {raw:?}: IPv6 prefix length {prefix_len} exceeds 128"
                    ));
                }
                if v6.to_ipv4_mapped().is_some() {
                    return Err(format!(
                        "CIDR {raw:?}: IPv4-mapped IPv6 CIDRs are forbidden; write the IPv4 form"
                    ));
                }
                let bits = u128::from_be_bytes(v6.octets());
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - prefix_len))
                    .unwrap_or(0);
                if bits & !mask != 0 {
                    return Err(format!(
                        "CIDR {raw:?}: address {addr_str} has non-zero host bits for /{prefix_len}"
                    ));
                }
                Ok(Self {
                    network: IpAddr::V6(v6),
                    prefix_len,
                })
            }
        }
    }

    /// Returns true iff `ip` falls within this CIDR. Family-strict: an
    /// IPv4 entry never matches an IPv6 candidate, and vice versa.
    /// Callers that want IPv4-mapped IPv6 to inherit must normalize the
    /// candidate via [`ip_block_reason`]'s `to_ipv4_mapped()` path before
    /// calling.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - self.prefix_len))
                    .unwrap_or(0);
                let net_bits = u32::from_be_bytes(net.octets());
                let cand_bits = u32::from_be_bytes(candidate.octets());
                (net_bits & mask) == (cand_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - self.prefix_len))
                    .unwrap_or(0);
                let net_bits = u128::from_be_bytes(net.octets());
                let cand_bits = u128::from_be_bytes(candidate.octets());
                (net_bits & mask) == (cand_bits & mask)
            }
            _ => false,
        }
    }
}

/// Compiled, validated form of `crate::oauth::OAuthSsrfAllowlist`. Built
/// once at `OAuthConfig::validate` time (or at `OauthHttpClient::build` /
/// `JwksCache::new` time when no separate validate call is made) and
/// cached on the runtime types for SSRF screening.
///
/// **Cloud-metadata addresses are never allowed**, regardless of whether
/// they fall within an allowlisted host or CIDR. The runtime callers
/// (`screen_oauth_target`, `redirect_target_reason_with_allowlist`)
/// short-circuit on a `"cloud_metadata"` block reason BEFORE consulting
/// this struct.
#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Default)]
pub(crate) struct CompiledSsrfAllowlist {
    /// Lowercased hostname strings. `host_allowed` does an
    /// ASCII-case-insensitive equality check.
    hosts: Vec<String>,
    /// Parsed CIDR entries (network address with host bits cleared,
    /// plus prefix length).
    cidrs: Vec<CidrEntry>,
}

#[cfg(feature = "oauth")]
impl CompiledSsrfAllowlist {
    /// Construct a compiled allowlist from already-validated host
    /// entries (lowercased) and CIDR entries.
    pub(crate) fn new(hosts: Vec<String>, cidrs: Vec<CidrEntry>) -> Self {
        Self { hosts, cidrs }
    }

    /// Returns true iff `host` matches any allowlisted hostname
    /// (case-insensitive ASCII compare; allowlist hosts are stored
    /// lowercased). Returns false for empty input.
    pub(crate) fn host_allowed(&self, host: &str) -> bool {
        if host.is_empty() {
            return false;
        }
        self.hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    }

    /// Returns true iff `ip` falls within any allowlisted CIDR.
    pub(crate) fn ip_allowed(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    /// Returns true iff both `hosts` and `cidrs` are empty -- i.e. the
    /// allowlist is a no-op and the default SSRF guard should apply
    /// unchanged.
    pub(crate) fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.cidrs.is_empty()
    }

    /// Number of allowlisted hosts (for diagnostic logging).
    pub(crate) fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Number of allowlisted CIDR entries (for diagnostic logging).
    pub(crate) fn cidr_count(&self) -> usize {
        self.cidrs.len()
    }
}

/// Sync combined redirect-target check, allowlist-aware variant.
///
/// Behaves like [`redirect_target_reason`] but consults the operator
/// allowlist for literal-IP redirect targets. **Cloud-metadata
/// addresses remain unbypassable**: even if the IP would otherwise be
/// covered by an allowlist CIDR, a `Some("cloud_metadata")` is returned
/// so the redirect is refused.
///
/// Like the non-allowlist variant, this does NOT perform DNS resolution.
/// Redirect targets with DNS hostnames are passed through (the closure
/// will let `reqwest` follow them, and the post-DNS guard on the next
/// fetch -- if any -- would catch a hostname resolving into blocked
/// space).
#[cfg(feature = "oauth")]
pub(crate) fn redirect_target_reason_with_allowlist(
    url: &Url,
    allowlist: &CompiledSsrfAllowlist,
) -> Option<&'static str> {
    if !url.username().is_empty() || url.password().is_some() {
        return Some("userinfo (credentials in URL) forbidden");
    }
    let ip = match url.host()? {
        url::Host::Ipv4(ip) => IpAddr::V4(ip),
        url::Host::Ipv6(ip) => IpAddr::V6(ip),
        url::Host::Domain(_) => return None,
    };
    let reason = ip_block_reason(ip)?;
    // Cloud-metadata is unbypassable.
    if reason == "cloud_metadata" {
        return Some(reason);
    }
    if allowlist.ip_allowed(ip) {
        return None;
    }
    Some(reason)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use url::Url;

    use super::{check_scheme, ip_block_reason};

    #[test]
    fn https_always_allowed() {
        let url = Url::parse("https://crl.example/ca.crl").expect("parse");
        assert!(check_scheme(&url, false).is_ok());
        assert!(check_scheme(&url, true).is_ok());
    }

    #[test]
    fn http_gated_by_flag() {
        let url = Url::parse("http://crl.example/ca.crl").expect("parse");
        assert_eq!(check_scheme(&url, false), Err("http_scheme_disallowed"));
        assert!(check_scheme(&url, true).is_ok());
    }

    #[test]
    fn other_schemes_rejected() {
        for raw in ["ldap://x/", "file:///etc/passwd", "ftp://x/", "gopher://x/"] {
            let url = Url::parse(raw).expect("parse");
            assert_eq!(check_scheme(&url, true), Err("invalid_scheme"));
        }
    }

    #[test]
    fn cloud_metadata_blocked() {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
            Some("cloud_metadata")
        );
    }

    #[test]
    fn loopback_blocked() {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some("loopback")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some("loopback")
        );
    }

    #[test]
    fn rfc1918_blocked() {
        for raw in [[10, 0, 0, 1], [172, 16, 0, 1], [192, 168, 1, 1]] {
            let ip = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]));
            assert_eq!(ip_block_reason(ip), Some("private_rfc1918"), "{ip}");
        }
    }

    #[test]
    fn link_local_blocked_v4_v6() {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))),
            Some("link_local")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
            Some("link_local")
        );
    }

    #[test]
    fn cgnat_blocked() {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            Some("cgnat")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))),
            Some("cgnat")
        );
    }

    #[test]
    fn documentation_and_benchmarking_blocked() {
        for raw in [[192, 0, 2, 1], [198, 51, 100, 1], [203, 0, 113, 1]] {
            let ip = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]));
            assert_eq!(ip_block_reason(ip), Some("documentation"), "{ip}");
        }
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
            Some("benchmarking")
        );
    }

    #[test]
    fn unique_local_v6_blocked() {
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
            Some("unique_local")
        );
    }

    #[test]
    fn ipv4_mapped_v6_inherits_block() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        assert_eq!(ip_block_reason(mapped), Some("loopback"));
    }

    #[test]
    fn public_ips_allowed() {
        assert_eq!(ip_block_reason(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
        assert_eq!(ip_block_reason(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))), None);
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
            ))),
            None
        );
    }

    // -----------------------------------------------------------------
    // Cloud-metadata classification (Oracle finding #1, pre-work)
    // -----------------------------------------------------------------

    #[test]
    fn block_reason_classifies_aws_ipv6_metadata_as_cloud_metadata() {
        // fd00:ec2::254 sits inside fc00::/7 (unique-local) but MUST be
        // labelled cloud_metadata so a fd00::/8 operator allowlist
        // cannot re-allow it.
        assert_eq!(
            ip_block_reason(IpAddr::V6(super::CLOUD_METADATA_V6_AWS)),
            Some("cloud_metadata")
        );
    }

    #[test]
    fn block_reason_classifies_gcp_ipv6_metadata_as_cloud_metadata() {
        // fd20:ce::254 -- GCP IPv6 metadata. Same reasoning as AWS.
        assert_eq!(
            ip_block_reason(IpAddr::V6(super::CLOUD_METADATA_V6_GCP)),
            Some("cloud_metadata")
        );
    }

    #[test]
    fn block_reason_classifies_alibaba_metadata_as_cloud_metadata() {
        // 100.100.100.200 sits inside 100.64.0.0/10 (CGNAT) but MUST be
        // labelled cloud_metadata so a 100.64.0.0/10 operator allowlist
        // cannot re-allow it.
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200))),
            Some("cloud_metadata")
        );
    }

    // -----------------------------------------------------------------
    // CIDR parser (oauth feature)
    // -----------------------------------------------------------------

    #[cfg(feature = "oauth")]
    mod cidr {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        use url::Url;

        use super::super::{
            CidrEntry, CompiledSsrfAllowlist, redirect_target_reason_with_allowlist,
        };

        #[test]
        fn cidr_parse_ipv4_valid() {
            let entry = CidrEntry::parse("10.0.0.0/8").expect("parses");
            assert!(entry.contains(IpAddr::V4(Ipv4Addr::new(10, 5, 6, 7))));
        }

        #[test]
        fn cidr_parse_ipv6_valid() {
            let entry = CidrEntry::parse("fd00::/8").expect("parses");
            assert!(entry.contains(IpAddr::V6(Ipv6Addr::new(0xfd11, 0, 0, 0, 0, 0, 0, 1))));
        }

        #[test]
        fn cidr_parse_rejects_host_bits_set() {
            let err = CidrEntry::parse("10.0.0.1/8").expect_err("must reject");
            assert!(err.contains("non-zero host bits"), "got {err}");
        }

        #[test]
        fn cidr_parse_rejects_bad_prefix() {
            assert!(CidrEntry::parse("10.0.0.0/33").is_err());
            assert!(CidrEntry::parse("fd00::/129").is_err());
            assert!(CidrEntry::parse("10.0.0.0/abc").is_err());
        }

        #[test]
        fn cidr_parse_rejects_no_slash() {
            assert!(CidrEntry::parse("10.0.0.0").is_err());
        }

        #[test]
        fn cidr_parse_rejects_zero_prefix_v4() {
            // 0.0.0.0/0 would allow every IPv4 address -- defeats the
            // entire SSRF guard. Operators must enumerate.
            let err = CidrEntry::parse("0.0.0.0/0").expect_err("must reject");
            assert!(err.contains("prefix length 0"), "got {err}");
        }

        #[test]
        fn cidr_parse_rejects_zero_prefix_v6() {
            let err = CidrEntry::parse("::/0").expect_err("must reject");
            assert!(err.contains("prefix length 0"), "got {err}");
        }

        #[test]
        fn cidr_parse_rejects_ipv4_mapped_v6() {
            // ::ffff:127.0.0.0/104 would map to 127.0.0.0/8 on the
            // candidate side; ip_block_reason normalises mapped v6 ->
            // v4 but contains() is family-strict, so allow only the
            // IPv4 form to avoid the asymmetry.
            let err = CidrEntry::parse("::ffff:127.0.0.0/104").expect_err("must reject");
            assert!(err.contains("IPv4-mapped"), "got {err}");
        }

        #[test]
        fn cidr_parse_rejects_ipv6_zone_id() {
            // IpAddr::from_str rejects zone identifiers; the parser
            // surfaces the parse error verbatim.
            assert!(CidrEntry::parse("fe80::1%eth0/64").is_err());
        }

        #[test]
        fn cidr_contains_ipv4_inside_and_outside() {
            let entry = CidrEntry::parse("10.0.0.0/8").expect("parses");
            assert!(entry.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            assert!(entry.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
            assert!(!entry.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
            assert!(!entry.contains(IpAddr::V4(Ipv4Addr::new(9, 255, 255, 255))));
        }

        #[test]
        fn cidr_contains_ipv6_inside_and_outside() {
            let entry = CidrEntry::parse("fd00::/8").expect("parses");
            assert!(entry.contains(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))));
            assert!(entry.contains(IpAddr::V6(Ipv6Addr::new(0xfdff, 0xffff, 0, 0, 0, 0, 0, 0))));
            assert!(!entry.contains(IpAddr::V6(Ipv6Addr::new(0xfe00, 0, 0, 0, 0, 0, 0, 1))));
        }

        #[test]
        fn cidr_contains_rejects_family_mismatch() {
            let v4 = CidrEntry::parse("10.0.0.0/8").expect("parses");
            assert!(!v4.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
            let v6 = CidrEntry::parse("fd00::/8").expect("parses");
            assert!(!v6.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        }

        #[test]
        fn compiled_allowlist_host_allowed_case_insensitive() {
            let allow =
                CompiledSsrfAllowlist::new(vec!["keycloak.svc.cluster.local".into()], Vec::new());
            assert!(allow.host_allowed("keycloak.svc.cluster.local"));
            assert!(allow.host_allowed("KEYCLOAK.SVC.CLUSTER.LOCAL"));
            assert!(!allow.host_allowed("other.svc.cluster.local"));
            assert!(!allow.host_allowed(""));
        }

        #[test]
        fn compiled_allowlist_empty_is_empty() {
            let allow = CompiledSsrfAllowlist::default();
            assert!(allow.is_empty());
            assert_eq!(allow.host_count(), 0);
            assert_eq!(allow.cidr_count(), 0);
        }

        #[test]
        fn redirect_target_reason_with_allowlist_allows_listed_cidr() {
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("10.0.0.0/8").expect("parses")],
            );
            let url = Url::parse("https://10.97.137.37/realms/x").expect("parses");
            assert_eq!(redirect_target_reason_with_allowlist(&url, &allow), None);
        }

        #[test]
        fn redirect_target_reason_with_allowlist_blocks_unlisted_private() {
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("10.0.0.0/8").expect("parses")],
            );
            let url = Url::parse("https://192.168.1.1/").expect("parses");
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("private_rfc1918")
            );
        }

        #[test]
        fn redirect_target_reason_with_allowlist_never_allows_cloud_metadata_v4() {
            // Even when 169.254.169.254 is listed via a /16 CIDR, the
            // cloud-metadata short-circuit fires first.
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("169.254.0.0/16").expect("parses")],
            );
            let url = Url::parse("https://169.254.169.254/latest/meta-data/").expect("parses");
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("cloud_metadata")
            );
        }

        #[test]
        fn redirect_with_fd00_8_allowlist_still_blocks_aws_v6_metadata() {
            // Pins the strongest invariant in this patch: an operator
            // allowlist matching the issue's exact example
            // (`fd00::/8`) MUST NOT re-allow AWS IPv6 metadata.
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("fd00::/8").expect("parses")],
            );
            let url = Url::parse("https://[fd00:ec2::254]/latest/meta-data/").expect("parses");
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("cloud_metadata")
            );
        }

        #[test]
        fn redirect_with_fd20_16_allowlist_still_blocks_gcp_v6_metadata() {
            // Pins the GCP IPv6 metadata invariant: an operator
            // allowlist matching the enclosing /16 (or any other
            // legitimate ULA prefix) MUST NOT re-allow GCP IPv6
            // metadata at `fd20:ce::254`.
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("fd20::/16").expect("parses")],
            );
            let url = Url::parse("https://[fd20:ce::254]/computeMetadata/v1/").expect("parses");
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("cloud_metadata")
            );
        }

        #[test]
        fn redirect_with_cgnat_allowlist_still_blocks_alibaba_metadata() {
            // Same invariant for Alibaba/Tencent IPv4 metadata
            // (sits inside 100.64.0.0/10 CGNAT).
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("100.64.0.0/10").expect("parses")],
            );
            let url = Url::parse("https://100.100.100.200/latest/meta-data/").expect("parses");
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("cloud_metadata")
            );
        }

        #[test]
        fn redirect_target_reason_with_allowlist_rejects_userinfo() {
            let allow = CompiledSsrfAllowlist::default();
            let url = Url::parse("https://user:pass@example.com/").expect("parses");
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("userinfo (credentials in URL) forbidden")
            );
        }
    }
}
