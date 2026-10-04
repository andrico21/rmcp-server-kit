//! Trusted-forwarder client-IP resolution (`X-Forwarded-For` / RFC 7239
//! `Forwarded`).
//!
//! Implements the **rightmost-untrusted** algorithm used by nginx
//! `real_ip` and Envoy: when (and only when) the direct socket peer is
//! one of the operator's trusted proxies, walk the forwarding chain from
//! the right, skip addresses that are themselves trusted proxies, and
//! take the first address that is not - that is the real client. Headers
//! arriving from untrusted peers are ignored entirely (the leftmost-trust
//! anti-pattern is never used: anything left of the trusted suffix is
//! attacker-controlled).
//!
//! Every ambiguous input - malformed entries, RFC 7239 obfuscated
//! identifiers, chains that exhaust into trusted space, header bombs -
//! falls back to the **direct peer**, never to a header value. Raw header
//! contents are never logged; callers receive a [`FallbackReason`] code.
use core::net::IpAddr;

use axum::http::{HeaderMap, HeaderName};
use ipnet::IpNet;

use crate::transport::ForwardedHeaderMode;

/// Hard cap on forwarding-chain entries scanned per request. Chains
/// longer than this are treated as hostile (header bomb) and resolution
/// falls back to the direct peer.
pub(crate) const MAX_SCANNED_ENTRIES: usize = 16;

/// Hard ceiling on the operator-configurable scan cap.
///
/// [`MAX_SCANNED_ENTRIES`] exists to close header-bomb scanning, so exposing
/// the knob without a ceiling would let an operator disable the protection.
/// 64 is four times the default -- ample for any real proxy chain -- while
/// keeping per-request parsing work finite.
pub(crate) const MAX_CONFIGURABLE_SCANNED_ENTRIES: usize = 64;

/// Why trusted-forwarder resolution fell back to the direct peer.
///
/// Logged (as a code only - never the raw header contents, which are
/// attacker-controlled) at `debug` level by the peer-normalization
/// middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum FallbackReason {
    /// The configured forwarding header is absent on the request.
    NoHeader,
    /// An entry at the decision point failed to parse as an IP address.
    MalformedEntry,
    /// RFC 7239 obfuscated identifier (`unknown` / `_…`) at the decision
    /// point - the chain cannot be verified past it.
    Obfuscated,
    /// Every scanned entry was inside the trusted-proxy set. Conservative
    /// divergence from nginx `real_ip` (which would use the leftmost
    /// address): we refuse to trust a chain with no untrusted hop.
    AllEntriesTrusted,
    /// The chain exceeded [`MAX_SCANNED_ENTRIES`].
    TooManyEntries,
}

/// Resolve the client IP for a request whose direct peer is `direct`.
///
/// - Direct peer **not** in `trusted` → `Ok(direct)` (headers ignored -
///   the normal path for clients connecting directly).
/// - Direct peer trusted → rightmost-untrusted walk over the **last**
///   instance of the configured header; `Ok(client)` on success,
///   `Err(reason)` when the caller must fall back to `direct`.
///
/// # Errors
///
/// Returns a [`FallbackReason`] code when resolution must fall back to
/// `direct`: the configured header is absent, its last instance is not
/// valid UTF-8, a scanned entry is malformed or obfuscated, every scanned
/// entry is a trusted proxy, or the chain exceeds the scan cap.
pub(crate) fn resolve_client_ip(
    direct: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpNet],
    mode: ForwardedHeaderMode,
    max_scanned_entries: usize,
) -> Result<IpAddr, FallbackReason> {
    if !is_trusted(direct, trusted) {
        return Ok(direct);
    }

    let header_name = match mode {
        ForwardedHeaderMode::XForwardedFor => HeaderName::from_static("x-forwarded-for"),
        ForwardedHeaderMode::Forwarded => HeaderName::from_static("forwarded"),
    };
    // Multiple header instances: only the LAST one can have been appended
    // by the trusted proxy closest to us; earlier instances are as
    // attacker-controlled as any other client input.
    let Some(value) = headers.get_all(&header_name).iter().next_back() else {
        return Err(FallbackReason::NoHeader);
    };
    let Ok(text) = value.to_str() else {
        return Err(FallbackReason::MalformedEntry);
    };

    let mut scanned = 0_usize;
    for raw_entry in text.split(',').rev() {
        scanned = scanned.saturating_add(1);
        if scanned > max_scanned_entries {
            return Err(FallbackReason::TooManyEntries);
        }
        let candidate = match mode {
            ForwardedHeaderMode::XForwardedFor => parse_xff_entry(raw_entry)?,
            ForwardedHeaderMode::Forwarded => parse_forwarded_entry(raw_entry)?,
        };
        if is_trusted(candidate, trusted) {
            continue;
        }
        return Ok(candidate);
    }
    Err(FallbackReason::AllEntriesTrusted)
}

/// Return whether `ip` falls inside any trusted-proxy network in `trusted`.
pub(crate) fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&ip))
}

/// Parse one `X-Forwarded-For` list entry: an IP, optionally with a port
/// (`1.2.3.4:5678`, `[2001:db8::1]:443`) and surrounded by OWS.
///
/// # Errors
///
/// Returns [`FallbackReason::MalformedEntry`] when the trimmed entry is
/// empty or is not a valid node identifier.
fn parse_xff_entry(raw: &str) -> Result<IpAddr, FallbackReason> {
    let token = raw.trim();
    if token.is_empty() {
        return Err(FallbackReason::MalformedEntry);
    }
    parse_node_identifier(token)
}

/// Parse one RFC 7239 `Forwarded` stanza and extract its `for=` node.
///
/// Stanza shape: `for=X;by=Y;proto=Z` - parameters separated by `;`,
/// names case-insensitive, values optionally double-quoted.
///
/// # Errors
///
/// Returns [`FallbackReason::MalformedEntry`] when the stanza is empty, the
/// `for=` value is neither a token nor a balanced quoted-string, or the
/// node identifier is invalid; returns [`FallbackReason::Obfuscated`] for
/// RFC 7239 obfuscated or `unknown` identifiers.
fn parse_forwarded_entry(raw: &str) -> Result<IpAddr, FallbackReason> {
    let stanza = raw.trim();
    if stanza.is_empty() {
        return Err(FallbackReason::MalformedEntry);
    }
    for param in stanza.split(';') {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("for") {
            continue;
        }
        // RFC 7239 §4: a parameter value is `token / quoted-string`, and a
        // quoted-string requires BALANCED `DQUOTE`. Strip the pair atomically
        // rather than trimming each end independently: `"1.2.3.4`, `1.2.3.4"`
        // and `"""1.2.3.4"""` are all malformed, and normalizing them into a
        // valid address would create a parser differential with the upstream
        // proxy whose decision we are supposed to be mirroring.
        let trimmed = value.trim();
        let Some(node) = (match trimmed.strip_circumfix("\"", "\"") {
            Some(inner) => Some(inner),
            // Bare token: legitimately unquoted, so no `"` may appear at all.
            None if !trimmed.contains('"') => Some(trimmed),
            // Unbalanced or repeated quotes: neither token nor quoted-string.
            None => None,
        }) else {
            return Err(FallbackReason::MalformedEntry);
        };
        // RFC 7239 §6: obfuscated identifiers start with '_'; "unknown"
        // means the previous hop could not be identified. Either way the
        // chain cannot be verified past this point.
        if node.eq_ignore_ascii_case("unknown") || node.starts_with('_') {
            return Err(FallbackReason::Obfuscated);
        }
        return parse_node_identifier(node);
    }
    // A stanza without a `for=` parameter cannot identify the hop.
    Err(FallbackReason::MalformedEntry)
}

/// Parse a node identifier: bare IPv4/IPv6, `v4:port`, or `[v6]:port`.
///
/// # Errors
///
/// Returns [`FallbackReason::MalformedEntry`] when the token is empty, a
/// bracketed or `host:port` form carries an invalid port, or the address
/// fails to parse.
fn parse_node_identifier(token: &str) -> Result<IpAddr, FallbackReason> {
    if token.is_empty() {
        return Err(FallbackReason::MalformedEntry);
    }
    // Bracketed IPv6, optionally with a port: [2001:db8::1] / [2001:db8::1]:443
    if let Some(rest) = token.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return Err(FallbackReason::MalformedEntry);
        };
        let after_ok = after.is_empty() || after.strip_prefix(':').is_some_and(is_valid_port);
        if !after_ok {
            return Err(FallbackReason::MalformedEntry);
        }
        return inner
            .parse::<IpAddr>()
            .map_err(|_error| FallbackReason::MalformedEntry);
    }
    // Bare address first: covers IPv4 and unbracketed IPv6 (which contains
    // multiple colons and must NOT be split on ':').
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Ok(ip);
    }
    // v4:port - exactly one colon and a v4 on the left. The port must be a
    // non-empty decimal u16, else the node identifier is ambiguous.
    if let Some((host, port)) = token.rsplit_once(':')
        && !host.contains(':')
    {
        if !is_valid_port(port) {
            return Err(FallbackReason::MalformedEntry);
        }
        return host
            .parse::<IpAddr>()
            .map_err(|_error| FallbackReason::MalformedEntry);
    }
    Err(FallbackReason::MalformedEntry)
}

/// A forwarding-node port must be a non-empty decimal `u16`.
///
/// An empty or non-numeric port marks the entry malformed so resolution
/// falls back to the direct peer rather than trusting an ambiguous node
/// identifier.
fn is_valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
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

    use anyhow::Context as _;
    use axum::http::HeaderValue;
    use proptest::{collection, prelude::*};

    use super::*;

    /// Strategy for an arbitrary IPv4 or IPv6 address.
    fn prop_ip_strategy() -> impl Strategy<Value = IpAddr> {
        prop_oneof![
            any::<[u8; 4]>().prop_map(|octets| IpAddr::from(Ipv4Addr::from(octets))),
            any::<[u8; 16]>().prop_map(|octets| IpAddr::from(Ipv6Addr::from(octets))),
        ]
    }

    /// Parse a CIDR fixture for the trusted-proxy set.
    fn nets(specs: &[&str]) -> anyhow::Result<Vec<IpNet>> {
        specs
            .iter()
            .map(|spec| spec.parse::<IpNet>().context("test CIDR must parse"))
            .collect()
    }

    /// Parse an IP fixture for a request peer or header value.
    fn ip(addr: &str) -> anyhow::Result<IpAddr> {
        addr.parse::<IpAddr>().context("test IP must parse")
    }

    #[test]
    /// Pins that the scan cap comes from the parameter, not the constant.
    fn scan_cap_is_honoured_from_the_parameter_not_the_constant() -> anyhow::Result<()> {
        // 3 entries, cap of 2: the walk aborts and the caller falls back to
        // the direct peer rather than trusting a truncated chain.
        let headers = xff(&["1.1.1.1, 10.0.0.2, 10.0.0.3"])?;
        let got = resolve_client_ip(ip("10.0.0.1")?, &headers, &nets(&["10.0.0.0/8"])?, XFF, 2);
        assert_eq!(got, Err(FallbackReason::TooManyEntries));

        // Same chain, cap of 3: the untrusted client IP is resolved.
        let found = resolve_client_ip(ip("10.0.0.1")?, &headers, &nets(&["10.0.0.0/8"])?, XFF, 3);
        assert_eq!(found, Ok(ip("1.1.1.1")?));
        Ok(())
    }

    /// Build an `X-Forwarded-For` header map from fixture values.
    fn xff(values: &[&str]) -> anyhow::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        for value in values {
            let header = HeaderValue::from_str(value).context("bad header value")?;
            let _appended = headers.append("x-forwarded-for", header);
        }
        Ok(headers)
    }

    /// Build a `Forwarded` header map from fixture values.
    fn fwd(values: &[&str]) -> anyhow::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        for value in values {
            let header = HeaderValue::from_str(value).context("bad header value")?;
            let _appended = headers.append("forwarded", header);
        }
        Ok(headers)
    }

    const XFF: ForwardedHeaderMode = ForwardedHeaderMode::XForwardedFor;
    const FWD: ForwardedHeaderMode = ForwardedHeaderMode::Forwarded;

    #[test]
    /// Pins that a direct peer outside the trusted set ignores the header.
    fn untrusted_direct_peer_ignores_header() -> anyhow::Result<()> {
        let headers = xff(&["203.0.113.7"])?;
        let got = resolve_client_ip(
            ip("198.51.100.9")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("198.51.100.9")?), "header must be ignored");
        Ok(())
    }

    #[test]
    /// Pins that a single untrusted header entry resolves for a trusted peer.
    fn trusted_peer_single_entry_resolves() -> anyhow::Result<()> {
        let headers = xff(&["203.0.113.7"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("203.0.113.7")?));
        Ok(())
    }

    #[test]
    /// Pins that a multi-hop chain skips trusted proxies right to left.
    fn multi_hop_chain_skips_trusted_right_to_left() -> anyhow::Result<()> {
        // client -> proxy A (10.0.0.2) -> proxy B (10.0.0.1) -> us
        let headers = xff(&["203.0.113.7, 10.0.0.2"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("203.0.113.7")?));
        Ok(())
    }

    #[test]
    /// Pins that a chain with no untrusted hop falls back to the peer.
    fn all_entries_trusted_falls_back() -> anyhow::Result<()> {
        let headers = xff(&["10.0.0.3, 10.0.0.2"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Err(FallbackReason::AllEntriesTrusted));
        Ok(())
    }

    #[test]
    /// Pins that an absent header falls back with `NoHeader`.
    fn missing_header_falls_back() -> anyhow::Result<()> {
        let headers = HeaderMap::new();
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Err(FallbackReason::NoHeader));
        Ok(())
    }

    #[test]
    /// Pins that a malformed entry at the decision point falls back.
    fn malformed_entry_at_decision_point_falls_back() -> anyhow::Result<()> {
        let headers = xff(&["not-an-ip"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Err(FallbackReason::MalformedEntry));
        Ok(())
    }

    #[test]
    /// Pins that empty and whitespace-only list entries fall back.
    fn empty_and_whitespace_tokens_fall_back() -> anyhow::Result<()> {
        for value in ["203.0.113.7,,10.0.0.2", "203.0.113.7,   ,10.0.0.2"] {
            let headers = xff(&[value])?;
            let got = resolve_client_ip(
                ip("10.0.0.1")?,
                &headers,
                &nets(&["10.0.0.0/8"])?,
                XFF,
                MAX_SCANNED_ENTRIES,
            );
            // Rightmost-first walk hits 10.0.0.2 (trusted, skipped), then
            // the empty token at the decision point.
            assert_eq!(got, Err(FallbackReason::MalformedEntry), "value: {value:?}");
        }
        Ok(())
    }

    #[test]
    /// Pins that optional whitespace around entries is trimmed.
    fn ows_around_entries_is_trimmed() -> anyhow::Result<()> {
        let headers = xff(&["  203.0.113.7  ,  10.0.0.2  "])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("203.0.113.7")?));
        Ok(())
    }

    #[test]
    /// Pins that an `X-Forwarded-For` IPv4 entry may carry a port.
    fn xff_v4_with_port_parses() -> anyhow::Result<()> {
        let headers = xff(&["203.0.113.7:5678"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("203.0.113.7")?));
        Ok(())
    }

    #[test]
    /// Pins that an empty port marks the entry malformed.
    fn xff_empty_port_falls_back() -> anyhow::Result<()> {
        let headers = xff(&["203.0.113.7:"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Err(FallbackReason::MalformedEntry));
        Ok(())
    }

    #[test]
    /// Pins that non-numeric and out-of-range ports are rejected.
    fn xff_nonnumeric_port_falls_back() -> anyhow::Result<()> {
        for value in [
            "[2001:db8::1]:notaport",
            "203.0.113.7:notaport",
            "203.0.113.7:99999",
            "203.0.113.7:+443",
            "[2001:db8::1]:+443",
        ] {
            let headers = xff(&[value])?;
            let got = resolve_client_ip(
                ip("10.0.0.1")?,
                &headers,
                &nets(&["10.0.0.0/8"])?,
                XFF,
                MAX_SCANNED_ENTRIES,
            );
            assert_eq!(got, Err(FallbackReason::MalformedEntry), "value: {value:?}");
        }
        Ok(())
    }

    #[test]
    /// Pins that bracketed IPv6 with a port and bare IPv6 both parse.
    fn xff_bracketed_v6_with_port_and_bare_v6_parse() -> anyhow::Result<()> {
        let bracketed_headers = xff(&["[2001:db8::1]:443"])?;
        let bracketed = resolve_client_ip(
            ip("10.0.0.1")?,
            &bracketed_headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(bracketed, Ok(ip("2001:db8::1")?));

        let bare_headers = xff(&["2001:db8::2"])?;
        let bare = resolve_client_ip(
            ip("10.0.0.1")?,
            &bare_headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(bare, Ok(ip("2001:db8::2")?));
        Ok(())
    }

    #[test]
    /// Pins that only the last `X-Forwarded-For` instance is trusted.
    fn multiple_xff_header_instances_last_wins() -> anyhow::Result<()> {
        // The first instance is attacker-supplied; only the last was
        // appended by our trusted proxy.
        let headers = xff(&["6.6.6.6", "203.0.113.7"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("203.0.113.7")?));
        Ok(())
    }

    #[test]
    /// Pins that only the last `Forwarded` instance is trusted.
    fn multiple_forwarded_header_instances_last_wins() -> anyhow::Result<()> {
        let headers = fwd(&["for=6.6.6.6", "for=203.0.113.9"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            FWD,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("203.0.113.9")?));
        Ok(())
    }

    #[test]
    /// Pins that a chain longer than the scan cap is treated as hostile.
    fn chain_longer_than_cap_falls_back() -> anyhow::Result<()> {
        let mut entries: Vec<String> = (0_u8..17).map(|idx| format!("10.0.{idx}.1")).collect();
        entries.insert(0, "203.0.113.7".into());
        let headers = xff(&[entries.join(", ").as_str()])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            XFF,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Err(FallbackReason::TooManyEntries));
        Ok(())
    }

    #[test]
    /// Pins that a quoted bracketed IPv6 `for=` value resolves.
    fn forwarded_quoted_bracketed_v6_resolves() -> anyhow::Result<()> {
        let headers = fwd(&[r#"for="[2001:db8::1]:443";proto=https"#])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            FWD,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("2001:db8::1")?));
        Ok(())
    }

    #[test]
    /// Pins that RFC 7239 obfuscated or `unknown` identifiers fall back.
    fn forwarded_obfuscated_identifiers_fall_back() -> anyhow::Result<()> {
        for value in ["for=_hidden", "for=unknown", "For=UNKNOWN"] {
            let headers = fwd(&[value])?;
            let got = resolve_client_ip(
                ip("10.0.0.1")?,
                &headers,
                &nets(&["10.0.0.0/8"])?,
                FWD,
                MAX_SCANNED_ENTRIES,
            );
            assert_eq!(got, Err(FallbackReason::Obfuscated), "value: {value:?}");
        }
        Ok(())
    }

    #[test]
    /// Pins that the `Forwarded` parameter name is case-insensitive.
    fn forwarded_param_name_is_case_insensitive() -> anyhow::Result<()> {
        let headers = fwd(&["By=10.0.0.1;FOR=203.0.113.9;proto=https"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            FWD,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("203.0.113.9")?));
        Ok(())
    }

    #[test]
    /// Pins that a stanza without a `for=` parameter falls back.
    fn forwarded_stanza_without_for_falls_back() -> anyhow::Result<()> {
        let headers = fwd(&["by=10.0.0.1;proto=https"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            FWD,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Err(FallbackReason::MalformedEntry));
        Ok(())
    }

    #[test]
    /// Pins that a multi-stanza `Forwarded` value skips trusted hops.
    fn forwarded_multi_stanza_skips_trusted() -> anyhow::Result<()> {
        let headers = fwd(&["for=203.0.113.9, for=10.0.0.2"])?;
        let got = resolve_client_ip(
            ip("10.0.0.1")?,
            &headers,
            &nets(&["10.0.0.0/8"])?,
            FWD,
            MAX_SCANNED_ENTRIES,
        );
        assert_eq!(got, Ok(ip("203.0.113.9")?));
        Ok(())
    }

    #[test]
    /// Pins that unbalanced quotes are rejected instead of normalized.
    fn forwarded_unbalanced_quotes_fall_back() -> anyhow::Result<()> {
        // RFC 7239 §4: a value is `token / quoted-string`; a quoted-string
        // needs balanced DQUOTE. Trimming each end independently would
        // normalize all of these into a valid address, producing a parser
        // differential with the upstream proxy.
        for value in [
            r#"for="203.0.113.9"#,
            r#"for=203.0.113.9""#,
            r#"for="""203.0.113.9""""#,
            r#"for="[2001:db8::1]:443"#,
            r#"for=2"03.0.113.9"#,
        ] {
            let headers = fwd(&[value])?;
            let got = resolve_client_ip(
                ip("10.0.0.1")?,
                &headers,
                &nets(&["10.0.0.0/8"])?,
                FWD,
                MAX_SCANNED_ENTRIES,
            );
            assert_eq!(
                got,
                Err(FallbackReason::MalformedEntry),
                "unbalanced-quote value must not resolve: {value:?}"
            );
        }
        Ok(())
    }

    #[test]
    /// Pins that balanced quoted and bare `for=` values still resolve.
    fn forwarded_balanced_quotes_still_resolve() -> anyhow::Result<()> {
        for (value, want) in [
            (r#"for="203.0.113.9""#, ip("203.0.113.9")?),
            ("for=203.0.113.9", ip("203.0.113.9")?),
            (r#"for="203.0.113.9:443""#, ip("203.0.113.9")?),
            (r#"for="[2001:db8::1]""#, ip("2001:db8::1")?),
        ] {
            let headers = fwd(&[value])?;
            let got = resolve_client_ip(
                ip("10.0.0.1")?,
                &headers,
                &nets(&["10.0.0.0/8"])?,
                FWD,
                MAX_SCANNED_ENTRIES,
            );
            assert_eq!(got, Ok(want), "well-formed value must resolve: {value:?}");
        }
        Ok(())
    }

    #[test]
    /// Pins that a quoted obfuscated identifier is still detected.
    fn forwarded_quoted_obfuscated_still_detected() -> anyhow::Result<()> {
        // The quote strip must run before the obfuscation check, so a quoted
        // `unknown` / `_secret` still reports Obfuscated rather than being
        // misclassified as a malformed entry.
        for value in [r#"for="unknown""#, r#"for="_secret""#] {
            let headers = fwd(&[value])?;
            let got = resolve_client_ip(
                ip("10.0.0.1")?,
                &headers,
                &nets(&["10.0.0.0/8"])?,
                FWD,
                MAX_SCANNED_ENTRIES,
            );
            assert_eq!(got, Err(FallbackReason::Obfuscated), "value: {value:?}");
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// Arbitrary peers, chains, trusted sets and scan caps must never
        /// panic, and an `Ok` result must never name a trusted address.
        #[test]
        fn prop_resolution_returns_only_untrusted_clients(
            direct in prop_ip_strategy(),
            direct_trusted in any::<bool>(),
            entries in collection::vec((prop_ip_strategy(), any::<bool>()), 1..6),
            scan_cap in 0_usize..8,
        ) {
            let mut trusted: Vec<IpNet> = Vec::new();
            for (addr, flag) in &entries {
                if *flag {
                    trusted.push(IpNet::from(*addr));
                }
            }
            if direct_trusted {
                trusted.push(IpNet::from(direct));
            }
            let header_text = entries
                .iter()
                .map(|(addr, _flag)| addr.to_string())
                .collect::<Vec<String>>()
                .join(", ");
            let mut headers = HeaderMap::new();
            let _replaced = headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(&header_text).map_err(|error| {
                    TestCaseError::fail(format!("ip list must be a valid header value: {error}"))
                })?,
            );

            let resolved = resolve_client_ip(direct, &headers, &trusted, XFF, scan_cap);
            if let Ok(client) = resolved {
                prop_assert!(
                    !is_trusted(client, &trusted),
                    "resolved client {} must not be trusted (direct {})",
                    client,
                    direct
                );
            }

            let expected = if is_trusted(direct, &trusted) {
                let mut scanned: usize = 0;
                let mut outcome = Err(FallbackReason::AllEntriesTrusted);
                for (addr, _flag) in entries.iter().rev() {
                    scanned = scanned.saturating_add(1);
                    if scanned > scan_cap {
                        outcome = Err(FallbackReason::TooManyEntries);
                        break;
                    }
                    if !is_trusted(*addr, &trusted) {
                        outcome = Ok(*addr);
                        break;
                    }
                }
                outcome
            } else {
                Ok(direct)
            };
            prop_assert_eq!(
                resolved,
                expected,
                "resolution must follow the rightmost-untrusted rule"
            );
        }

        /// Arbitrary header text must never panic the parser, and any `Ok`
        /// result must still be an untrusted address.
        #[test]
        fn prop_arbitrary_header_text_never_panics(
            direct in prop_ip_strategy(),
            header_text in ".{0,80}",
            trusted in collection::vec(prop_ip_strategy().prop_map(IpNet::from), 0..4),
            scan_cap in 0_usize..8,
        ) {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(&header_text) {
                let _replaced = headers.insert("x-forwarded-for", value);
            }
            if let Ok(client) = resolve_client_ip(direct, &headers, &trusted, XFF, scan_cap) {
                prop_assert!(
                    !is_trusted(client, &trusted),
                    "resolved client {} must not be trusted",
                    client
                );
            }
        }
    }
}
