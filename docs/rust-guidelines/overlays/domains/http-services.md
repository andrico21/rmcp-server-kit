# Overlay: HTTP services

**Load this overlay for** any crate that serves HTTP. That includes:
- full web services and MCP-over-HTTP transports;
- small listeners such as an OAuth loopback redirect endpoint or an ACME HTTP-01
  challenge responder.

The rules below apply to every response such a listener sends.

Rules for HTTP services built with axum, tower, or similar frameworks.
Based on [OWASP Top 10](https://owasp.org/www-project-top-ten/),
[OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/),
and the [owasp-headers](https://docs.rs/owasp-headers) crate.

## Rules

### DO: Set OWASP-recommended HTTP response headers on every response

Add these headers via a tower middleware layer so they apply uniformly.
The definitive list is maintained at
`https://owasp.org/www-project-secure-headers/ci/headers_add.json`.

Required headers (defaults from OSHP):

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `deny` |
| `Content-Security-Policy` | `default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), microphone=()` (trim to what you actually need) |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Cache-Control` | `no-store, max-age=0` (for API responses; static assets may differ) |
| `X-DNS-Prefetch-Control` | `off` |
| `X-Permitted-Cross-Domain-Policies` | `none` |

```rust
// tower middleware example (axum)
use axum::http::header;
use tower_http::set_header::SetResponseHeaderLayer;

let app = Router::new()
    .route("/mcp", post(handler))
    .layer(SetResponseHeaderLayer::overriding(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("deny"),
    ));
// Or use the `owasp-headers` crate to get all at once:
//   headers.extend(owasp_headers::headers());
```

### DO: Strip server-fingerprinting headers

Remove headers that leak technology stack details. The full removal list is at
`https://owasp.org/www-project-secure-headers/ci/headers_remove.json`.

At minimum, suppress:
- `Server` (web server name/version)
- `X-Powered-By` (framework name)
- `X-AspNet-Version`, `X-AspNetMvc-Version`
- Any `X-*` header containing build hashes, internal hostnames, or tracing IDs

```rust
// Axum: do NOT set a Server header, or override it
use tower_http::set_header::SetResponseHeaderLayer;
app.layer(SetResponseHeaderLayer::overriding(
    HeaderName::from_static("server"),
    HeaderValue::from_static(""),
));
```

### DO: Strip delimiters atomically when resolving client IPs (extends core Section 10, `strip_circumfix`)

Directly applicable to `Forwarded` header parsing (RFC 7239), which uses
quoted strings for `for=` / `by=` values and square brackets around IPv6
literals - e.g. `for="[2001:db8::1]:4711"`. Stripping quotes and brackets
independently is how port-parsing and IP-parsing bugs get introduced into
client-IP resolution, which is security-relevant when that IP feeds rate
limiting or an allowlist.

### DO: Prevent SSRF (Server-Side Request Forgery)

When the server makes HTTP requests based on user-supplied URLs:

- Parse with a URL library, then validate the scheme (`https` only, or
  explicit allowlist).
- Reject private/loopback IPs (`127.0.0.0/8`, `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `::1`, `fe80::/10`, `169.254.0.0/16`).
- Reject hostnames ending in `.local`, `.internal`, `.localhost`.
- Use a DNS resolution allowlist when possible.

```rust
use std::net::IpAddr;

fn is_safe_target(ip: IpAddr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !matches!(ip, IpAddr::V4(v4) if v4.is_private()
            || v4.is_link_local()
            || v4.octets()[0] == 169 && v4.octets()[1] == 254)
}
```

### DON'T: Leak internal details in error responses

Error messages returned to clients must not contain:
- Stack traces or panic messages
- File paths, line numbers, or source code
- Internal hostnames, IPs, or port numbers
- SQL queries or ORM error strings
- Dependency version numbers

```rust
// BAD: Forwards internal error to the client
Err(e) => HttpResponse::InternalServerError().body(format!("{e:#}"))

// GOOD: Log the detail, return a generic message
Err(e) => {
    tracing::error!(error = %e, "request failed");
    HttpResponse::InternalServerError().body("internal server error")
}
```

MCP and JSON-RPC specifics: `overlays/domains/mcp-servers.md`.

### DO: Keep service accounting reproducible (extends core Section 4, `algebraic_*`)

For an HTTP/MCP server this rule is close to absolute. Metrics
that feed alerting, rate-limit accounting, and timing budgets must all be
reproducible; two replicas computing different values from the same inputs is a
debugging nightmare. Prefer integer or fixed-point arithmetic for anything
resembling accounting.

## Checklist (in addition to the core checklist)

- [ ] OWASP security headers set on all HTTP responses (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
- [ ] Server-fingerprinting headers stripped (Server, X-Powered-By)
- [ ] Error responses do not leak internals (stack traces, file paths, SQL, IPs)
- [ ] Outbound requests to user-influenced URLs pass the SSRF checks (scheme allowlist, private/loopback/link-local addresses rejected, DNS allowlist where possible)
- [ ] Every listener, however small (redirect endpoint, challenge responder), answers unknown paths with a generic response and no internals
