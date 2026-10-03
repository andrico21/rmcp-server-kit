# Overlay: MCP Servers (Model Context Protocol)

**Load this overlay for** MCP servers and MCP server frameworks, such as those built on the
`rmcp` SDK. An MCP server reachable over HTTP (Streamable HTTP, SSE) also loads
`http-services.md`.

## Errors on the wire (extends core Section 10 and `http-services.md`)

For structured JSON-RPC/MCP errors, use generic error codes and messages.
The detailed cause goes to the server log, never the wire.

Tool-level failures follow the same rule as HTTP error responses. The client sees a
generic, stable message. The cause is logged server-side with enough context to correlate
the two, for example a request id.

## Tool inputs are untrusted input (extends core Section 10 and Section 13)

Every tool argument is external input. Apply the boundary rules of core Section 10 to each
one: length limits, allowlists, validated newtypes, and no interpolation into paths,
queries, or commands.

For MCP tool input schemas, property-based tests are especially valuable:
generate random tool arguments and verify the handler either succeeds
or returns a well-formed error - never panics.

## SDK-mandated `async` signatures (extends core Section 9, "Clippy 1.98 new lints")

`unused_async_trait_impl` (pedantic, denied by the profile) fires on an `async fn` in a
trait impl that never awaits. When the trait comes from the SDK, as with
`rmcp::ServerHandler`, the signature is not yours to change. Put one
`#[expect(clippy::unused_async_trait_impl, reason = "async is mandated by the ServerHandler trait")]`
on that impl. Never relax the lint crate-wide.

## Checklist (in addition to the core and `http-services.md` checklists)

- [ ] Tool and JSON-RPC errors carry generic codes and messages; detailed causes only in the server log
- [ ] Every tool argument validated at the boundary (length, charset/allowlist, newtype) before use
- [ ] Property tests drive random tool arguments through each handler: well-formed error or success, never a panic
- [ ] `unused_async_trait_impl` exceptions scoped to SDK-mandated impls via `#[expect(..., reason)]`
