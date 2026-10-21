//! Small independent operator examples for executable boundary tables.

pub(super) const CONFIG: &str = "[server]\npublic_url='https://mcp.example'\n[server.auth]\nenabled=true\n[server.auth.oauth]\nissuer='https://idp.example/realms/example'\naudience='mcp-example'\njwks_uri='https://idp.example/custom/certs'\n[[server.auth.oauth.scopes]]\nscope='mcp:read'\nrole='viewer'\n[server.auth.oauth.proxy]\nauthorize_url='https://idp.example/authorize'\ntoken_url='https://idp.example/custom/token'\nclient_id='mcp-proxy'";
pub(super) const INIT: &str = "POST /mcp HTTP/1.1\nHost: mcp.example\nContent-Type: application/json\nAccept: application/json, text/event-stream\nAuthorization: Bearer <jwt {\"aud\":\"mcp-example\",\"scope\":\"mcp:read\"}>\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"inline\",\"version\":\"1\"}}}";
pub(super) const TOKEN: &str = "POST /token HTTP/1.1\nHost: mcp.example\nContent-Type: application/x-www-form-urlencoded\n\ngrant_type=authorization_code&code=first-code&client_id=external";
pub(super) const AUTHORIZE: &str = "GET /authorize?response_type=code&client_id=external&redirect_uri=http%3A%2F%2Flocalhost%2Fcb&state=s&code_challenge=abc&code_challenge_method=S256 HTTP/1.1\nHost: mcp.example";

pub(super) fn fence(info: &str, body: &str) -> String {
    format!("```{info}\n{body}\n```\n")
}

pub(super) fn exchange(request: &str, response: &str) -> String {
    format!(
        "{}prose\n{}",
        fence("http,case=X,request", request),
        fence("http,case=X,response", response)
    )
}

pub(super) fn document(exchanges: &str) -> String {
    super::fence_tables::complete_document(&format!(
        "## 7. Cases\n{}{}{exchanges}## 8. End\n",
        fence("toml,case=X", CONFIG),
        fence("sh,case=X", "# no overrides")
    ))
}
