//! SSRF guards for outbound HTTP: scheme/userinfo validation, literal-IP
//! rejection, cloud-metadata blocking, and the operator host/CIDR allowlist
//! shared by the OAuth/JWKS and CRL fetch paths.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
///
/// Lives inside `fc00::/7` (unique-local) but is treated as cloud-metadata
/// so it cannot be re-allowed via a `fd00::/8` operator allowlist.
///
/// Source: <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html>.
pub(crate) const CLOUD_METADATA_V6_AWS: Ipv6Addr =
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// GCP IPv6 instance metadata endpoint (`fd20:ce::254`). Lives inside
/// `fc00::/7` (unique-local) but is treated as cloud-metadata so it
/// cannot be re-allowed via a `fc00::/7` operator allowlist.
///
/// Source: <https://cloud.google.com/compute/docs/metadata/overview>.
pub(crate) const CLOUD_METADATA_V6_GCP: Ipv6Addr =
    Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254);

/// Validate scheme of a parsed CDP URL and reject embedded credentials.
///
/// Accepts only `https`, plus `http` when `allow_http` is true. Rejects
/// anything else (`file`, `ldap`, `ftp`, ...). Scheme is matched
/// case-insensitively per RFC 3986 §3.1, but `Url::parse` already
/// lowercases it.
///
/// URLs carrying userinfo (`https://user:pass@host/...`) are rejected
/// with `userinfo_forbidden` so embedded credentials can never reach
/// the fetch machinery, error strings, or logs. This mirrors the
/// userinfo rule already enforced on OAuth redirect targets by
/// [`redirect_target_reason_with_allowlist`].
///
/// # Errors
///
/// Returns `invalid_scheme` for any scheme other than `https` (or `http`
/// when `allow_http` is true), `http_scheme_disallowed` for `http` when
/// `allow_http` is false, and `userinfo_forbidden` when the URL carries
/// embedded credentials.
pub(crate) fn check_scheme(url: &Url, allow_http: bool) -> Result<(), &'static str> {
    match url.scheme() {
        "https" => {}
        "http" if allow_http => {}
        "http" => return Err("http_scheme_disallowed"),
        _ => return Err("invalid_scheme"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("userinfo_forbidden");
    }
    Ok(())
}

/// Authority-only rendering of a URL for logs: scheme + host + port.
///
/// Strips userinfo, path, query, and fragment - any of which can carry
/// credentials or other secrets - so rejection sites can name the
/// offending target without echoing what they rejected. Tolerates
/// hostless URLs (renders `<no-host>`) without panicking; the port is
/// included only when explicitly present in the URL.
pub(crate) fn sanitized_url_for_log(url: &Url) -> String {
    let host = url.host_str().unwrap_or("<no-host>");
    url.port().map_or_else(
        || format!("{}://{host}", url.scheme()),
        |port| format!("{}://{host}:{port}", url.scheme()),
    )
}

/// Check whether an IP address must be rejected before any TCP connect.
/// Returns `Some(reason)` if blocked, `None` if permitted.
///
/// Blocked classes:
/// - Cloud metadata service (IPv4 `169.254.169.254`, Alibaba/Tencent
///   `100.100.100.200`, AWS IPv6 `fd00:ec2::254`, GCP IPv6 `fd20:ce::254`).
/// - IPv4 "this network" / unspecified (0.0.0.0/8, RFC 1122 3.2.1.3):
///   the WHOLE prefix, not just `0.0.0.0`. Linux (>= 5.3) treats nonzero
///   `0/8` as valid unicast and will route it, so the prefix cannot be
///   assumed unreachable-by-construction.
/// - IPv4 loopback (127.0.0.0/8), broadcast.
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
/// - IPv6 Teredo tunneling (`2001::/32`), blocked outright.
/// - IPv6 NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) when the
///   embedded IPv4 address is itself blocked by any rule above; embedded
///   cloud-metadata is re-labelled `cloud_metadata` so an operator
///   allowlist covering the transition prefix cannot re-allow it.
/// - IPv6 IPv4-compatible (`::a.b.c.d`, deprecated `::/96`): the whole
///   prefix is blocked, inheriting any IPv4 rule for the embedded address.
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

/// Classify an IPv4 address against the blocked ranges, cloud-metadata first.
fn block_reason_v4(v4: Ipv4Addr) -> Option<&'static str> {
    // Cloud-metadata MUST be checked first so it wins over CGNAT
    // (Alibaba metadata sits inside 100.64.0.0/10) and link-local
    // (AWS metadata sits inside 169.254.0.0/16).
    if v4 == CLOUD_METADATA_V4 || v4 == CLOUD_METADATA_V4_ALIBABA {
        return Some("cloud_metadata");
    }
    let octets = v4.octets();
    // SECURITY: reject the whole 0.0.0.0/8 "this network" prefix (RFC 1122
    // 3.2.1.3), not just the unspecified address. `Ipv4Addr::is_unspecified`
    // matches ONLY 0.0.0.0, and Linux >= 5.3 accepts nonzero 0/8 as valid
    // unicast, so 0.1.2.3 would otherwise pass screening and be routed.
    if octets[0] == 0 {
        return Some("this_network");
    }
    if v4.is_loopback() {
        return Some("loopback");
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

/// Classify an IPv6 address, delegating embedded IPv4 forms to the IPv4 rules.
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
    // Deprecated IPv4-compatible IPv6 `::a.b.c.d` (`::/96`, RFC 4291 §2.5.5.1).
    // `::` (unspecified) and `::1` (loopback) are already handled above, so any
    // remaining address whose top 96 bits are zero embeds an IPv4 address.
    // Classify it through the IPv4 rules so loopback / private / link-local /
    // cloud-metadata are inherited (metadata wins first inside `block_reason_v4`),
    // and block the rest of the deprecated prefix as defence in depth.
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        return block_reason_v4(embedded_v4(segments[6], segments[7])).or(Some("ipv4_compatible"));
    }
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
    // Teredo tunneling 2001:0::/32 (RFC 4380). Obsolete tunneling
    // protocol that is never a legitimate OAuth/JWKS/CRL dependency;
    // blocked outright as defense in depth (the embedded client IPv4 is
    // XOR-obfuscated and attacker-chosen, so it cannot be trusted).
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return Some("teredo");
    }
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): the trailing 32
    // bits embed an IPv4 address. On DNS64/NAT64 egress networks EVERY
    // public host maps into this prefix, so blocking it wholesale would
    // break all outbound fetches there; instead, delegate to the IPv4
    // classifier and block only when the embedded target would itself be
    // blocked (e.g. `64:ff9b::10.0.0.1` reaching internal RFC 1918 space).
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        if let Some(reason) = block_reason_v4(embedded_v4(segments[6], segments[7])) {
            // Preserve the unbypassable cloud-metadata classification: an
            // operator allowlist covering `64:ff9b::/96` must not re-allow
            // metadata wrapped in a NAT64 address
            // (e.g. `64:ff9b::169.254.169.254`).
            if reason == "cloud_metadata" {
                return Some("cloud_metadata");
            }
            return Some("nat64_embedded");
        }
        return None;
    }
    // 6to4 2002::/16 (RFC 3056): segments 1-2 embed the IPv4 address of
    // the originating site. Same embedded-target policy as NAT64.
    if segments[0] == 0x2002 {
        if let Some(reason) = block_reason_v4(embedded_v4(segments[1], segments[2])) {
            // Same unbypassable-metadata rule as the NAT64 arm above.
            if reason == "cloud_metadata" {
                return Some("cloud_metadata");
            }
            return Some("6to4_embedded");
        }
        return None;
    }
    None
}

/// Reassemble an IPv4 address embedded in two adjacent IPv6 segments
/// (`hi` carries the first two octets, `lo` the last two).
const fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    let [hi_hi, hi_lo] = hi.to_be_bytes();
    let [lo_hi, lo_lo] = lo.to_be_bytes();
    Ipv4Addr::new(hi_hi, hi_lo, lo_hi, lo_lo)
}

/// Sync pre-DNS literal-IP check.
///
/// Any literal IPv4 or IPv6 host is rejected at URL-validation time,
/// regardless of whether the address falls in a private or public range.
/// OAuth operators must use DNS hostnames; post-DNS runtime checks remain
/// the responsibility of the fetch path.
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

/// Single CIDR entry as parsed from operator config.
///
/// Stores the network address (host bits cleared at parse time) and the
/// prefix length so a candidate `IpAddr` can be matched against it without
/// re-parsing on every request.
#[derive(Debug, Clone)]
pub(crate) struct CidrEntry {
    /// Network address with host bits cleared at parse time.
    network: IpAddr,
    /// Prefix length in bits (`1..=32` for IPv4, `1..=128` for IPv6).
    prefix_len: u8,
}

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
    ///
    /// # Errors
    ///
    /// Returns `Err` when the string lacks a `/`, has a non-numeric or
    /// out-of-range prefix (`0`, `> 32` for IPv4, `> 128` for IPv6), a
    /// malformed address, non-zero host bits, or an IPv4-mapped IPv6 CIDR.
    #[cfg_attr(
        all(not(test), not(feature = "oauth")),
        expect(dead_code, reason = "consumer is feature-gated")
    )]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "invariant: src/ssrf.rs::CidrEntry::parse bounds prefix_len to 1..=32 (IPv4) / 1..=128 (IPv6), so the mask shift subtraction cannot underflow"
    )]
    pub(crate) fn parse(spec: &str) -> Result<Self, String> {
        let raw = spec.trim();
        let Some((addr_str, prefix_str)) = raw.split_once('/') else {
            return Err(format!("CIDR {raw:?} missing '/' prefix length"));
        };
        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|err| format!("CIDR {raw:?}: invalid prefix length {prefix_str:?}: {err}"))?;
        let addr: IpAddr = addr_str
            .parse()
            .map_err(|err| format!("CIDR {raw:?}: invalid address {addr_str:?}: {err}"))?;
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
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "invariant: src/ssrf.rs::CidrEntry::parse bounds prefix_len to 1..=32 (IPv4) / 1..=128 (IPv6), so the mask shift subtraction cannot underflow"
    )]
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

/// Compiled, validated form of `crate::oauth::OAuthSsrfAllowlist`.
///
/// Built once at `OAuthConfig::validate` time (or at `OauthHttpClient::build` /
/// `JwksCache::new` time when no separate validate call is made) and
/// cached on the runtime types for SSRF screening.
///
/// **Cloud-metadata addresses are never allowed**, regardless of whether
/// they fall within an allowlisted host or CIDR. The runtime callers
/// (`screen_oauth_target`, `redirect_target_reason_with_allowlist`)
/// short-circuit on a `"cloud_metadata"` block reason BEFORE consulting
/// this struct.
#[derive(Debug, Clone, Default)]
pub(crate) struct CompiledSsrfAllowlist {
    /// Lowercased hostname strings. `host_allowed` does an
    /// ASCII-case-insensitive equality check.
    hosts: Vec<String>,
    /// Parsed CIDR entries (network address with host bits cleared,
    /// plus prefix length).
    cidrs: Vec<CidrEntry>,
}

impl CompiledSsrfAllowlist {
    /// Construct a compiled allowlist from already-validated host
    /// entries (lowercased) and CIDR entries.
    #[cfg_attr(
        all(not(test), not(feature = "oauth")),
        expect(dead_code, reason = "consumer is feature-gated")
    )]
    pub(crate) const fn new(hosts: Vec<String>, cidrs: Vec<CidrEntry>) -> Self {
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
    pub(crate) const fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.cidrs.is_empty()
    }

    /// Number of allowlisted hosts (for diagnostic logging).
    #[cfg_attr(
        not(feature = "oauth"),
        expect(dead_code, reason = "consumer is feature-gated")
    )]
    pub(crate) const fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Number of allowlisted CIDR entries (for diagnostic logging).
    #[cfg_attr(
        not(feature = "oauth"),
        expect(dead_code, reason = "consumer is feature-gated")
    )]
    pub(crate) const fn cidr_count(&self) -> usize {
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

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use url::Url;

    use super::{check_scheme, ip_block_reason, sanitized_url_for_log};

    #[test]
    /// Pins that `https` URLs are accepted regardless of the `allow_http` flag.
    fn https_always_allowed() -> anyhow::Result<()> {
        let url = Url::parse("https://crl.example/ca.crl")?;
        let Ok(()) = check_scheme(&url, false) else {
            anyhow::bail!("https must be accepted when allow_http is false");
        };
        let Ok(()) = check_scheme(&url, true) else {
            anyhow::bail!("https must be accepted when allow_http is true");
        };
        Ok(())
    }

    #[test]
    /// Pins that `http` is rejected unless `allow_http` is true.
    fn http_gated_by_flag() -> anyhow::Result<()> {
        let url = Url::parse("http://crl.example/ca.crl")?;
        assert_eq!(check_scheme(&url, false), Err("http_scheme_disallowed"));
        let Ok(()) = check_scheme(&url, true) else {
            anyhow::bail!("http must be accepted when allow_http is true");
        };
        Ok(())
    }

    #[test]
    /// Pins that other schemes are rejected even when `http` is allowed.
    fn other_schemes_rejected() -> anyhow::Result<()> {
        for raw in ["ldap://x/", "file:///etc/passwd", "ftp://x/", "gopher://x/"] {
            let url = Url::parse(raw)?;
            assert_eq!(check_scheme(&url, true), Err("invalid_scheme"));
        }
        Ok(())
    }

    #[cfg(feature = "oauth")]
    #[expect(
        clippy::too_long_first_doc_paragraph,
        reason = "test code is not rendered API documentation"
    )]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::numeric_ipv4_literal_forms_never_pass_as_hostnames keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Numeric IPv4 literals must never reach the fetch path as an allowed
    /// DNS name. The WHATWG URL parser normalizes decimal, hex, and octal
    /// forms to `Host::Ipv4` before `check_url_literal_ip` sees them, so the
    /// literal-IP guard covers them -- but nothing in this crate pins that,
    /// and it is exactly the shape an SSRF filter bypass takes.
    ///
    /// The invariant asserted is "not reachable as a `Domain`": either the
    /// URL fails to parse at all, or the literal-IP guard rejects it.
    fn numeric_ipv4_literal_forms_never_pass_as_hostnames() -> anyhow::Result<()> {
        for raw in [
            "https://127.0.0.1/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://0177.0.0.1/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::1]/",
        ] {
            match Url::parse(raw) {
                Err(_) => {}
                Ok(url) => assert!(
                    super::check_url_literal_ip(&url).is_some(),
                    "{raw} was accepted as a DNS hostname; the literal-IP guard did not fire"
                ),
            }
        }
        Ok(())
    }

    #[cfg(feature = "oauth")]
    #[test]
    /// Pins that a DNS hostname still passes the literal-IP guard.
    fn dns_hostname_still_passes_the_literal_ip_guard() -> anyhow::Result<()> {
        let url = Url::parse("https://idp.example.com/realms/main")?;
        assert!(super::check_url_literal_ip(&url).is_none());
        Ok(())
    }

    #[test]
    /// Pins that embedded credentials are rejected on accepted schemes.
    fn userinfo_rejected_on_accepted_schemes() -> anyhow::Result<()> {
        for raw in ["https://user:pass@host/", "https://user@host/"] {
            let url = Url::parse(raw)?;
            assert_eq!(check_scheme(&url, false), Err("userinfo_forbidden"));
            assert_eq!(check_scheme(&url, true), Err("userinfo_forbidden"));
        }
        let url = Url::parse("http://user:pass@host/")?;
        assert_eq!(check_scheme(&url, true), Err("userinfo_forbidden"));
        // Scheme rejection still wins when the scheme itself is refused.
        assert_eq!(check_scheme(&url, false), Err("http_scheme_disallowed"));
        Ok(())
    }

    #[test]
    /// Pins that sanitized log rendering strips userinfo, path and query.
    fn sanitized_url_strips_credentials_path_and_query() -> anyhow::Result<()> {
        let url = Url::parse("https://u:p@h:8443/secret?token=x#frag")?;
        let sanitized = sanitized_url_for_log(&url);
        assert_eq!(sanitized, "https://h:8443");
        assert!(!sanitized.contains("u:p"));
        assert!(!sanitized.contains("secret"));
        assert!(!sanitized.contains("token"));
        Ok(())
    }

    #[test]
    /// Pins default-port omission and hostless rendering for sanitized logs.
    fn sanitized_url_default_port_and_hostless() -> anyhow::Result<()> {
        let url = Url::parse("https://crl.example/ca.crl")?;
        assert_eq!(sanitized_url_for_log(&url), "https://crl.example");
        // Hostless URL must not panic and must signal the missing host.
        let hostless = Url::parse("data:text/plain,hello")?;
        assert_eq!(sanitized_url_for_log(&hostless), "data://<no-host>");
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::cloud_metadata_blocked keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the IPv4 cloud-metadata address is blocked.
    fn cloud_metadata_blocked() -> anyhow::Result<()> {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
            Some("cloud_metadata")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::loopback_blocked keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that IPv4 and IPv6 loopback addresses are blocked.
    fn loopback_blocked() -> anyhow::Result<()> {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some("loopback")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some("loopback")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::rfc1918_blocked keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the RFC 1918 private ranges are blocked.
    fn rfc1918_blocked() -> anyhow::Result<()> {
        for raw in [[10, 0, 0, 1], [172, 16, 0, 1], [192, 168, 1, 1]] {
            let [first, second, third, fourth] = raw;
            let ip = IpAddr::V4(Ipv4Addr::new(first, second, third, fourth));
            assert_eq!(ip_block_reason(ip), Some("private_rfc1918"), "{ip}");
        }
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::transition_prefix_classification keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins the classification of NAT64, 6to4 and Teredo transition prefixes.
    fn transition_prefix_classification() -> anyhow::Result<()> {
        // NAT64 64:ff9b::/96 embedding private 10.0.0.1 -> blocked.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001
            ))),
            Some("nat64_embedded")
        );
        // NAT64 embedding public 8.8.8.8 -> allowed (DNS64 networks map
        // every public host into this prefix).
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x0064, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808
            ))),
            None
        );
        // NAT64 embedding the IPv4 cloud-metadata address -> re-labelled
        // cloud_metadata (M2) so a NAT64-prefix allowlist cannot re-allow it.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x0064, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe
            ))),
            Some("cloud_metadata")
        );
        // 6to4 2002::/16 embedding private 10.0.0.1 -> blocked.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 0
            ))),
            Some("6to4_embedded")
        );
        // 6to4 embedding public 8.8.8.8 -> allowed.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 0
            ))),
            None
        );
        // Teredo 2001:0::/32 -> blocked outright.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1))),
            Some("teredo")
        );
        // Documentation 2001:db8::/32 still classified as before.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))),
            Some("documentation")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::nat64_embedded_metadata_is_cloud_metadata keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that NAT64-wrapped cloud metadata stays `cloud_metadata`.
    fn nat64_embedded_metadata_is_cloud_metadata() -> anyhow::Result<()> {
        // 64:ff9b::169.254.169.254 - NAT64-wrapped AWS metadata (M2).
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x0064, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe
            ))),
            Some("cloud_metadata")
        );
        // 64:ff9b::100.100.100.200 - NAT64-wrapped Alibaba/Tencent metadata.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x0064, 0xff9b, 0, 0, 0, 0, 0x6464, 0x64c8
            ))),
            Some("cloud_metadata")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::sixto4_embedded_metadata_is_cloud_metadata keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that 6to4-wrapped cloud metadata stays `cloud_metadata`.
    fn sixto4_embedded_metadata_is_cloud_metadata() -> anyhow::Result<()> {
        // 2002:a9fe:a9fe:: - 6to4-wrapped 169.254.169.254 (M2).
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x2002, 0xa9fe, 0xa9fe, 0, 0, 0, 0, 0
            ))),
            Some("cloud_metadata")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::nat64_embedded_private_keeps_transition_label keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that non-metadata NAT64 embeds keep the transition label.
    fn nat64_embedded_private_keeps_transition_label() -> anyhow::Result<()> {
        // Non-metadata embedded blocks keep their (allowlist-bypassable) label.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001
            ))),
            Some("nat64_embedded")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::ipv4_compatible_ipv6_blocked keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that deprecated IPv4-compatible IPv6 addresses are blocked.
    fn ipv4_compatible_ipv6_blocked() -> anyhow::Result<()> {
        // Deprecated ::a.b.c.d (::/96) inherits IPv4 classification (M3).
        // ::127.0.0.1
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x7f00, 0x0001))),
            Some("loopback")
        );
        // ::10.0.0.1
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0a00, 0x0001))),
            Some("private_rfc1918")
        );
        // ::169.254.169.254 - metadata wins first.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe))),
            Some("cloud_metadata")
        );
        // ::8.8.8.8 - public embedded still blocked as deprecated prefix.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0808, 0x0808))),
            Some("ipv4_compatible")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::unspecified_and_loopback_v6_carveouts_intact keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that `::` and `::1` keep their own classifications.
    fn unspecified_and_loopback_v6_carveouts_intact() -> anyhow::Result<()> {
        // :: and ::1 must NOT be swallowed by the IPv4-compatible arm.
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Some("unspecified")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some("loopback")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::this_network_v4_prefix_blocked_not_just_unspecified keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the whole 0.0.0.0/8 prefix is blocked, not just `0.0.0.0`.
    fn this_network_v4_prefix_blocked_not_just_unspecified() -> anyhow::Result<()> {
        // Regression: `Ipv4Addr::is_unspecified` matches ONLY 0.0.0.0, so the
        // rest of 0.0.0.0/8 used to pass screening. Linux >= 5.3 routes
        // nonzero 0/8 as valid unicast, so the whole prefix must be blocked.
        for ip in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(0, 255, 255, 255),
        ] {
            assert_eq!(
                ip_block_reason(IpAddr::V4(ip)),
                Some("this_network"),
                "{ip} must be blocked as this_network"
            );
        }
        // The first address outside the prefix stays reachable.
        assert_eq!(ip_block_reason(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))), None);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::this_network_blocked_through_ipv4_mapped_v6 keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that `this_network` is inherited through IPv4-mapped IPv6.
    fn this_network_blocked_through_ipv4_mapped_v6() -> anyhow::Result<()> {
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0xffff, 0x0001, 0x0203
            ))),
            Some("this_network")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::link_local_blocked_v4_v6 keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that IPv4 and IPv6 link-local addresses are blocked.
    fn link_local_blocked_v4_v6() -> anyhow::Result<()> {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))),
            Some("link_local")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
            Some("link_local")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::cgnat_blocked keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that the CGNAT 100.64.0.0/10 range is blocked.
    fn cgnat_blocked() -> anyhow::Result<()> {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            Some("cgnat")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))),
            Some("cgnat")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::documentation_and_benchmarking_blocked keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that documentation and benchmarking ranges are blocked.
    fn documentation_and_benchmarking_blocked() -> anyhow::Result<()> {
        for raw in [[192, 0, 2, 1], [198, 51, 100, 1], [203, 0, 113, 1]] {
            let [first, second, third, fourth] = raw;
            let ip = IpAddr::V4(Ipv4Addr::new(first, second, third, fourth));
            assert_eq!(ip_block_reason(ip), Some("documentation"), "{ip}");
        }
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
            Some("benchmarking")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::unique_local_v6_blocked keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that IPv6 unique-local addresses are blocked.
    fn unique_local_v6_blocked() -> anyhow::Result<()> {
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
            Some("unique_local")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::ipv4_mapped_v6_inherits_block keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that IPv4-mapped IPv6 inherits the embedded IPv4 block.
    fn ipv4_mapped_v6_inherits_block() -> anyhow::Result<()> {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        assert_eq!(ip_block_reason(mapped), Some("loopback"));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::public_ips_allowed keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that public IPv4 and IPv6 addresses are not blocked.
    fn public_ips_allowed() -> anyhow::Result<()> {
        assert_eq!(ip_block_reason(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
        assert_eq!(ip_block_reason(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))), None);
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
            ))),
            None
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // Cloud-metadata classification (Oracle finding #1, pre-work)
    // -----------------------------------------------------------------

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::block_reason_classifies_aws_ipv6_metadata_as_cloud_metadata keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that AWS IPv6 metadata is labelled `cloud_metadata`.
    fn block_reason_classifies_aws_ipv6_metadata_as_cloud_metadata() -> anyhow::Result<()> {
        // fd00:ec2::254 sits inside fc00::/7 (unique-local) but MUST be
        // labelled cloud_metadata so a fd00::/8 operator allowlist
        // cannot re-allow it.
        assert_eq!(
            ip_block_reason(IpAddr::V6(super::CLOUD_METADATA_V6_AWS)),
            Some("cloud_metadata")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::block_reason_classifies_gcp_ipv6_metadata_as_cloud_metadata keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that GCP IPv6 metadata is labelled `cloud_metadata`.
    fn block_reason_classifies_gcp_ipv6_metadata_as_cloud_metadata() -> anyhow::Result<()> {
        // fd20:ce::254 -- GCP IPv6 metadata. Same reasoning as AWS.
        assert_eq!(
            ip_block_reason(IpAddr::V6(super::CLOUD_METADATA_V6_GCP)),
            Some("cloud_metadata")
        );
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "deliberate: src/ssrf.rs::block_reason_classifies_alibaba_metadata_as_cloud_metadata keeps the uniform test signature while it cannot fail"
    )]
    #[test]
    /// Pins that Alibaba/Tencent metadata is labelled `cloud_metadata`.
    fn block_reason_classifies_alibaba_metadata_as_cloud_metadata() -> anyhow::Result<()> {
        // 100.100.100.200 sits inside 100.64.0.0/10 (CGNAT) but MUST be
        // labelled cloud_metadata so a 100.64.0.0/10 operator allowlist
        // cannot re-allow it.
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200))),
            Some("cloud_metadata")
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // CIDR parser (oauth feature)
    // -----------------------------------------------------------------

    #[cfg(feature = "oauth")]
    mod cidr {
        use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        use anyhow::Error;
        use url::Url;

        use super::super::{
            CidrEntry, CompiledSsrfAllowlist, redirect_target_reason_with_allowlist,
        };

        #[test]
        /// Pins that a valid IPv4 CIDR parses and matches inside addresses.
        fn cidr_parse_ipv4_valid() -> anyhow::Result<()> {
            let entry = CidrEntry::parse("10.0.0.0/8").map_err(Error::msg)?;
            assert!(entry.contains(IpAddr::V4(Ipv4Addr::new(10, 5, 6, 7))));
            Ok(())
        }

        #[test]
        /// Pins that a valid IPv6 CIDR parses and matches inside addresses.
        fn cidr_parse_ipv6_valid() -> anyhow::Result<()> {
            let entry = CidrEntry::parse("fd00::/8").map_err(Error::msg)?;
            assert!(entry.contains(IpAddr::V6(Ipv6Addr::new(0xfd11, 0, 0, 0, 0, 0, 0, 1))));
            Ok(())
        }

        #[test]
        /// Pins that a CIDR with non-zero host bits is rejected.
        fn cidr_parse_rejects_host_bits_set() -> anyhow::Result<()> {
            let Err(err) = CidrEntry::parse("10.0.0.1/8") else {
                anyhow::bail!("must reject");
            };
            assert!(err.contains("non-zero host bits"), "got {err}");
            Ok(())
        }

        #[test]
        /// Pins that out-of-range and non-numeric prefixes are rejected.
        fn cidr_parse_rejects_bad_prefix() -> anyhow::Result<()> {
            let Err(_) = CidrEntry::parse("10.0.0.0/33") else {
                anyhow::bail!("IPv4 prefix above 32 must be rejected");
            };
            let Err(_) = CidrEntry::parse("fd00::/129") else {
                anyhow::bail!("IPv6 prefix above 128 must be rejected");
            };
            let Err(_) = CidrEntry::parse("10.0.0.0/abc") else {
                anyhow::bail!("non-numeric prefix must be rejected");
            };
            Ok(())
        }

        #[test]
        /// Pins that a CIDR without a `/` separator is rejected.
        fn cidr_parse_rejects_no_slash() -> anyhow::Result<()> {
            let Err(_) = CidrEntry::parse("10.0.0.0") else {
                anyhow::bail!("a CIDR without a prefix length must be rejected");
            };
            Ok(())
        }

        #[test]
        /// Pins that a zero IPv4 prefix is rejected.
        fn cidr_parse_rejects_zero_prefix_v4() -> anyhow::Result<()> {
            // 0.0.0.0/0 would allow every IPv4 address -- defeats the
            // entire SSRF guard. Operators must enumerate.
            let Err(err) = CidrEntry::parse("0.0.0.0/0") else {
                anyhow::bail!("must reject");
            };
            assert!(err.contains("prefix length 0"), "got {err}");
            Ok(())
        }

        #[test]
        /// Pins that a zero IPv6 prefix is rejected.
        fn cidr_parse_rejects_zero_prefix_v6() -> anyhow::Result<()> {
            let Err(err) = CidrEntry::parse("::/0") else {
                anyhow::bail!("must reject");
            };
            assert!(err.contains("prefix length 0"), "got {err}");
            Ok(())
        }

        #[test]
        /// Pins that IPv4-mapped IPv6 CIDRs are rejected.
        fn cidr_parse_rejects_ipv4_mapped_v6() -> anyhow::Result<()> {
            // ::ffff:127.0.0.0/104 would map to 127.0.0.0/8 on the
            // candidate side; ip_block_reason normalises mapped v6 ->
            // v4 but contains() is family-strict, so allow only the
            // IPv4 form to avoid the asymmetry.
            let Err(err) = CidrEntry::parse("::ffff:127.0.0.0/104") else {
                anyhow::bail!("must reject");
            };
            assert!(err.contains("IPv4-mapped"), "got {err}");
            Ok(())
        }

        #[test]
        /// Pins that IPv6 zone identifiers are rejected.
        fn cidr_parse_rejects_ipv6_zone_id() -> anyhow::Result<()> {
            // IpAddr::from_str rejects zone identifiers; the parser
            // surfaces the parse error verbatim.
            let Err(_) = CidrEntry::parse("fe80::1%eth0/64") else {
                anyhow::bail!("a zone identifier must be rejected");
            };
            Ok(())
        }

        #[test]
        /// Pins IPv4 inside/outside matching for a CIDR entry.
        fn cidr_contains_ipv4_inside_and_outside() -> anyhow::Result<()> {
            let entry = CidrEntry::parse("10.0.0.0/8").map_err(Error::msg)?;
            assert!(entry.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            assert!(entry.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
            assert!(!entry.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
            assert!(!entry.contains(IpAddr::V4(Ipv4Addr::new(9, 255, 255, 255))));
            Ok(())
        }

        #[test]
        /// Pins IPv6 inside/outside matching for a CIDR entry.
        fn cidr_contains_ipv6_inside_and_outside() -> anyhow::Result<()> {
            let entry = CidrEntry::parse("fd00::/8").map_err(Error::msg)?;
            assert!(entry.contains(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))));
            assert!(entry.contains(IpAddr::V6(Ipv6Addr::new(0xfdff, 0xffff, 0, 0, 0, 0, 0, 0))));
            assert!(!entry.contains(IpAddr::V6(Ipv6Addr::new(0xfe00, 0, 0, 0, 0, 0, 0, 1))));
            Ok(())
        }

        #[test]
        /// Pins that a CIDR entry never matches the other IP family.
        fn cidr_contains_rejects_family_mismatch() -> anyhow::Result<()> {
            let v4 = CidrEntry::parse("10.0.0.0/8").map_err(Error::msg)?;
            assert!(!v4.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
            let v6 = CidrEntry::parse("fd00::/8").map_err(Error::msg)?;
            assert!(!v6.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            Ok(())
        }

        #[expect(
            clippy::unnecessary_wraps,
            reason = "deliberate: src/ssrf.rs::tests::cidr::compiled_allowlist_host_allowed_case_insensitive keeps the uniform test signature while it cannot fail"
        )]
        #[test]
        /// Pins case-insensitive hostname matching in the compiled allowlist.
        fn compiled_allowlist_host_allowed_case_insensitive() -> anyhow::Result<()> {
            let allow =
                CompiledSsrfAllowlist::new(vec!["keycloak.svc.cluster.local".into()], Vec::new());
            assert!(allow.host_allowed("keycloak.svc.cluster.local"));
            assert!(allow.host_allowed("KEYCLOAK.SVC.CLUSTER.LOCAL"));
            assert!(!allow.host_allowed("other.svc.cluster.local"));
            assert!(!allow.host_allowed(""));
            Ok(())
        }

        #[expect(
            clippy::unnecessary_wraps,
            reason = "deliberate: src/ssrf.rs::tests::cidr::compiled_allowlist_empty_is_empty keeps the uniform test signature while it cannot fail"
        )]
        #[test]
        /// Pins that a default compiled allowlist reports empty.
        fn compiled_allowlist_empty_is_empty() -> anyhow::Result<()> {
            let allow = CompiledSsrfAllowlist::default();
            assert!(allow.is_empty());
            assert_eq!(allow.host_count(), 0);
            assert_eq!(allow.cidr_count(), 0);
            Ok(())
        }

        #[test]
        /// Pins that an allowlisted CIDR is accepted for a literal-IP target.
        fn redirect_target_reason_with_allowlist_allows_listed_cidr() -> anyhow::Result<()> {
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("10.0.0.0/8").map_err(Error::msg)?],
            );
            let url = Url::parse("https://10.97.137.37/realms/x")?;
            assert_eq!(redirect_target_reason_with_allowlist(&url, &allow), None);
            Ok(())
        }

        #[test]
        /// Pins that a private target outside the allowlist stays blocked.
        fn redirect_target_reason_with_allowlist_blocks_unlisted_private() -> anyhow::Result<()> {
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("10.0.0.0/8").map_err(Error::msg)?],
            );
            let url = Url::parse("https://192.168.1.1/")?;
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("private_rfc1918")
            );
            Ok(())
        }

        #[test]
        /// Pins that an allowlist cannot re-allow IPv4 cloud metadata.
        fn redirect_target_reason_with_allowlist_never_allows_cloud_metadata_v4()
        -> anyhow::Result<()> {
            // Even when 169.254.169.254 is listed via a /16 CIDR, the
            // cloud-metadata short-circuit fires first.
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("169.254.0.0/16").map_err(Error::msg)?],
            );
            let url = Url::parse("https://169.254.169.254/latest/meta-data/")?;
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("cloud_metadata")
            );
            Ok(())
        }

        #[test]
        /// Pins that an `fd00::/8` allowlist cannot re-allow AWS v6 metadata.
        fn redirect_with_fd00_8_allowlist_still_blocks_aws_v6_metadata() -> anyhow::Result<()> {
            // Pins the strongest invariant in this patch: an operator
            // allowlist matching the issue's exact example
            // (`fd00::/8`) MUST NOT re-allow AWS IPv6 metadata.
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("fd00::/8").map_err(Error::msg)?],
            );
            let url = Url::parse("https://[fd00:ec2::254]/latest/meta-data/")?;
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("cloud_metadata")
            );
            Ok(())
        }

        #[test]
        /// Pins that an `fd20::/16` allowlist cannot re-allow GCP v6 metadata.
        fn redirect_with_fd20_16_allowlist_still_blocks_gcp_v6_metadata() -> anyhow::Result<()> {
            // Pins the GCP IPv6 metadata invariant: an operator
            // allowlist matching the enclosing /16 (or any other
            // legitimate ULA prefix) MUST NOT re-allow GCP IPv6
            // metadata at `fd20:ce::254`.
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("fd20::/16").map_err(Error::msg)?],
            );
            let url = Url::parse("https://[fd20:ce::254]/computeMetadata/v1/")?;
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("cloud_metadata")
            );
            Ok(())
        }

        #[test]
        /// Pins that a CGNAT allowlist cannot re-allow Alibaba metadata.
        fn redirect_with_cgnat_allowlist_still_blocks_alibaba_metadata() -> anyhow::Result<()> {
            // Same invariant for Alibaba/Tencent IPv4 metadata
            // (sits inside 100.64.0.0/10 CGNAT).
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("100.64.0.0/10").map_err(Error::msg)?],
            );
            let url = Url::parse("https://100.100.100.200/latest/meta-data/")?;
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("cloud_metadata")
            );
            Ok(())
        }

        #[test]
        /// Pins that a NAT64-prefix allowlist cannot re-allow wrapped metadata.
        fn allowlist_cannot_bypass_transition_metadata() -> anyhow::Result<()> {
            // An allowlist over the NAT64 prefix must NOT re-allow metadata
            // wrapped in a NAT64 address: 64:ff9b::169.254.169.254 (M2 regression).
            let allow = CompiledSsrfAllowlist::new(
                Vec::new(),
                vec![CidrEntry::parse("64:ff9b::/96").map_err(Error::msg)?],
            );
            let url = Url::parse("https://[64:ff9b::a9fe:a9fe]/latest/meta-data/")?;
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("cloud_metadata")
            );
            Ok(())
        }

        #[test]
        /// Pins that embedded userinfo is rejected before allowlist checks.
        fn redirect_target_reason_with_allowlist_rejects_userinfo() -> anyhow::Result<()> {
            let allow = CompiledSsrfAllowlist::default();
            let url = Url::parse("https://user:pass@example.com/")?;
            assert_eq!(
                redirect_target_reason_with_allowlist(&url, &allow),
                Some("userinfo (credentials in URL) forbidden")
            );
            Ok(())
        }
    }
}
