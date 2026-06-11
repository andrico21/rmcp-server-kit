//! Trusted-forwarder client-IP resolution (`X-Forwarded-For` / RFC 7239
//! `Forwarded`).
//!
//! Implements the **rightmost-untrusted** algorithm used by nginx
//! `real_ip` and Envoy: when (and only when) the direct socket peer is
//! one of the operator's trusted proxies, walk the forwarding chain from
//! the right, skip addresses that are themselves trusted proxies, and
//! take the first address that is not — that is the real client. Headers
//! arriving from untrusted peers are ignored entirely (the leftmost-trust
//! anti-pattern is never used: anything left of the trusted suffix is
//! attacker-controlled).
//!
//! Every ambiguous input — malformed entries, RFC 7239 obfuscated
//! identifiers, chains that exhaust into trusted space, header bombs —
//! falls back to the **direct peer**, never to a header value. Raw header
//! contents are never logged; callers receive a [`FallbackReason`] code.

use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderName};
use ipnet::IpNet;

use crate::transport::ForwardedHeaderMode;

/// Hard cap on forwarding-chain entries scanned per request. Chains
/// longer than this are treated as hostile (header bomb) and resolution
/// falls back to the direct peer.
const MAX_SCANNED_ENTRIES: usize = 16;

/// Why trusted-forwarder resolution fell back to the direct peer.
///
/// Logged (as a code only — never the raw header contents, which are
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
    /// point — the chain cannot be verified past it.
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
/// - Direct peer **not** in `trusted` → `Ok(direct)` (headers ignored —
///   the normal path for clients connecting directly).
/// - Direct peer trusted → rightmost-untrusted walk over the **last**
///   instance of the configured header; `Ok(client)` on success,
///   `Err(reason)` when the caller must fall back to `direct`.
pub(crate) fn resolve_client_ip(
    direct: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpNet],
    mode: ForwardedHeaderMode,
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
    let Ok(value) = value.to_str() else {
        return Err(FallbackReason::MalformedEntry);
    };

    let mut scanned = 0_usize;
    for raw_entry in value.split(',').rev() {
        scanned += 1;
        if scanned > MAX_SCANNED_ENTRIES {
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

fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&ip))
}

/// Parse one `X-Forwarded-For` list entry: an IP, optionally with a port
/// (`1.2.3.4:5678`, `[2001:db8::1]:443`) and surrounded by OWS.
fn parse_xff_entry(raw: &str) -> Result<IpAddr, FallbackReason> {
    let token = raw.trim();
    if token.is_empty() {
        return Err(FallbackReason::MalformedEntry);
    }
    parse_node_identifier(token)
}

/// Parse one RFC 7239 `Forwarded` stanza and extract its `for=` node.
///
/// Stanza shape: `for=X;by=Y;proto=Z` — parameters separated by `;`,
/// names case-insensitive, values optionally double-quoted.
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
        let value = value.trim().trim_matches('"');
        // RFC 7239 §6: obfuscated identifiers start with '_'; "unknown"
        // means the previous hop could not be identified. Either way the
        // chain cannot be verified past this point.
        if value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
            return Err(FallbackReason::Obfuscated);
        }
        return parse_node_identifier(value);
    }
    // A stanza without a `for=` parameter cannot identify the hop.
    Err(FallbackReason::MalformedEntry)
}

/// Parse a node identifier: bare IPv4/IPv6, `v4:port`, or `[v6]:port`.
fn parse_node_identifier(token: &str) -> Result<IpAddr, FallbackReason> {
    if token.is_empty() {
        return Err(FallbackReason::MalformedEntry);
    }
    // Bracketed IPv6, optionally with a port: [2001:db8::1] / [2001:db8::1]:443
    if let Some(rest) = token.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return Err(FallbackReason::MalformedEntry);
        };
        if !(after.is_empty() || after.starts_with(':')) {
            return Err(FallbackReason::MalformedEntry);
        }
        return inner
            .parse::<IpAddr>()
            .map_err(|_| FallbackReason::MalformedEntry);
    }
    // Bare address first: covers IPv4 and unbracketed IPv6 (which contains
    // multiple colons and must NOT be split on ':').
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Ok(ip);
    }
    // v4:port — exactly one colon and a v4 on the left.
    if let Some((host, _port)) = token.rsplit_once(':')
        && !host.contains(':')
    {
        return host
            .parse::<IpAddr>()
            .map_err(|_| FallbackReason::MalformedEntry);
    }
    Err(FallbackReason::MalformedEntry)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "unit tests use unwrap/expect for brevity"
    )]

    use axum::http::HeaderValue;

    use super::*;

    fn nets(specs: &[&str]) -> Vec<IpNet> {
        specs.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn fwd(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("forwarded", HeaderValue::from_str(v).unwrap());
        }
        h
    }

    const XFF: ForwardedHeaderMode = ForwardedHeaderMode::XForwardedFor;
    const FWD: ForwardedHeaderMode = ForwardedHeaderMode::Forwarded;

    #[test]
    fn untrusted_direct_peer_ignores_header() {
        let headers = xff(&["203.0.113.7"]);
        let got = resolve_client_ip(ip("198.51.100.9"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Ok(ip("198.51.100.9")), "header must be ignored");
    }

    #[test]
    fn trusted_peer_single_entry_resolves() {
        let headers = xff(&["203.0.113.7"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Ok(ip("203.0.113.7")));
    }

    #[test]
    fn multi_hop_chain_skips_trusted_right_to_left() {
        // client -> proxy A (10.0.0.2) -> proxy B (10.0.0.1) -> us
        let headers = xff(&["203.0.113.7, 10.0.0.2"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Ok(ip("203.0.113.7")));
    }

    #[test]
    fn all_entries_trusted_falls_back() {
        let headers = xff(&["10.0.0.3, 10.0.0.2"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Err(FallbackReason::AllEntriesTrusted));
    }

    #[test]
    fn missing_header_falls_back() {
        let headers = HeaderMap::new();
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Err(FallbackReason::NoHeader));
    }

    #[test]
    fn malformed_entry_at_decision_point_falls_back() {
        let headers = xff(&["not-an-ip"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Err(FallbackReason::MalformedEntry));
    }

    #[test]
    fn empty_and_whitespace_tokens_fall_back() {
        for value in ["203.0.113.7,,10.0.0.2", "203.0.113.7,   ,10.0.0.2"] {
            let headers = xff(&[value]);
            let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
            // Rightmost-first walk hits 10.0.0.2 (trusted, skipped), then
            // the empty token at the decision point.
            assert_eq!(got, Err(FallbackReason::MalformedEntry), "value: {value:?}");
        }
    }

    #[test]
    fn ows_around_entries_is_trimmed() {
        let headers = xff(&["  203.0.113.7  ,  10.0.0.2  "]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Ok(ip("203.0.113.7")));
    }

    #[test]
    fn xff_v4_with_port_parses() {
        let headers = xff(&["203.0.113.7:5678"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Ok(ip("203.0.113.7")));
    }

    #[test]
    fn xff_bracketed_v6_with_port_and_bare_v6_parse() {
        let headers = xff(&["[2001:db8::1]:443"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Ok(ip("2001:db8::1")));

        let headers = xff(&["2001:db8::2"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Ok(ip("2001:db8::2")));
    }

    #[test]
    fn multiple_xff_header_instances_last_wins() {
        // The first instance is attacker-supplied; only the last was
        // appended by our trusted proxy.
        let headers = xff(&["6.6.6.6", "203.0.113.7"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Ok(ip("203.0.113.7")));
    }

    #[test]
    fn multiple_forwarded_header_instances_last_wins() {
        let headers = fwd(&["for=6.6.6.6", "for=203.0.113.9"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), FWD);
        assert_eq!(got, Ok(ip("203.0.113.9")));
    }

    #[test]
    fn chain_longer_than_cap_falls_back() {
        let mut entries: Vec<String> = (0..17).map(|i| format!("10.0.{i}.1")).collect();
        entries.insert(0, "203.0.113.7".into());
        let headers = xff(&[entries.join(", ").as_str()]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, Err(FallbackReason::TooManyEntries));
    }

    #[test]
    fn forwarded_quoted_bracketed_v6_resolves() {
        let headers = fwd(&[r#"for="[2001:db8::1]:443";proto=https"#]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), FWD);
        assert_eq!(got, Ok(ip("2001:db8::1")));
    }

    #[test]
    fn forwarded_obfuscated_identifiers_fall_back() {
        for value in ["for=_hidden", "for=unknown", "For=UNKNOWN"] {
            let headers = fwd(&[value]);
            let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), FWD);
            assert_eq!(got, Err(FallbackReason::Obfuscated), "value: {value:?}");
        }
    }

    #[test]
    fn forwarded_param_name_is_case_insensitive() {
        let headers = fwd(&["By=10.0.0.1;FOR=203.0.113.9;proto=https"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), FWD);
        assert_eq!(got, Ok(ip("203.0.113.9")));
    }

    #[test]
    fn forwarded_stanza_without_for_falls_back() {
        let headers = fwd(&["by=10.0.0.1;proto=https"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), FWD);
        assert_eq!(got, Err(FallbackReason::MalformedEntry));
    }

    #[test]
    fn forwarded_multi_stanza_skips_trusted() {
        let headers = fwd(&["for=203.0.113.9, for=10.0.0.2"]);
        let got = resolve_client_ip(ip("10.0.0.1"), &headers, &nets(&["10.0.0.0/8"]), FWD);
        assert_eq!(got, Ok(ip("203.0.113.9")));
    }
}
