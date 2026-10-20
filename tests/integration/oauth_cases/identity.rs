//! Per-run RSA signing material and typed placeholder substitution.

use anyhow::{Context as _, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::{
    pkcs8::{self, EncodePrivateKey as _},
    rand_core,
    traits::PublicKeyParts as _,
};
use serde_json::{Map, Value, json};

pub(super) const RULES: &[&str] = &["jwt-iat"];

pub(super) struct Identity {
    pub key: EncodingKey,
    pub jwks: Value,
}

impl Identity {
    pub(super) fn generate() -> anyhow::Result<Self> {
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048)?;
        let pem = private.to_pkcs8_pem(pkcs8::LineEnding::LF)?;
        let public = private.to_public_key();
        Ok(Self {
            key: EncodingKey::from_rsa_pem(pem.as_bytes())?,
            jwks: json!({"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"case-key", "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())}]}),
        })
    }

    pub(super) fn substitute(&self, text: &str, issuer: &str) -> anyhow::Result<String> {
        let mut remaining = text;
        let mut output = String::new();
        while let Some((before, after)) = remaining.split_once("<jwt") {
            output.push_str(before);
            let (raw, rest) = after.split_once('>').context("unclosed JWT placeholder")?;
            let overrides: Map<String, Value> = match raw.trim() {
                "" => Map::new(),
                json => {
                    serde_json::from_str(json).context("invalid JWT placeholder JSON object")?
                }
            };
            let now = jsonwebtoken::get_current_timestamp();
            let mut claims =
                json!({"iss":issuer,"sub":"user-1","iat":now,"exp":now.saturating_add(300)});
            claims
                .as_object_mut()
                .context("default JWT claims object")?
                .extend(overrides);
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some("case-key".to_owned());
            output.push_str(&jsonwebtoken::encode(&header, &claims, &self.key)?);
            remaining = rest;
        }
        ensure!(!remaining.contains("<jwt"), "incomplete JWT placeholder");
        output.push_str(remaining);
        Ok(output)
    }
}
