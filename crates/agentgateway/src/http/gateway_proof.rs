use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::http::jwt::Claims;
use crate::http::{HeaderName, HeaderValue, Request};

#[derive(Clone)]
pub struct GatewayProof {
	encoding_key: Arc<EncodingKey>,
	ttl_seconds: u64,
	header_name: HeaderName,
}

#[derive(Serialize)]
struct ProofPayload {
	sub: String,
	obo: String,
	cid: String,
	iby: String,
	#[serde(rename = "_auth_type")]
	auth_type: String,
	ent: EntClaim,
	iat: u64,
	exp: u64,
}

#[derive(Serialize)]
struct EntClaim {
	scopes: Vec<String>,
	roles: Vec<String>,
	accounts: Vec<String>,
}

impl GatewayProof {
	pub fn new(private_key_pem: &str, ttl_seconds: u64) -> Result<Self, anyhow::Error> {
		let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
		Ok(Self {
			encoding_key: Arc::new(encoding_key),
			ttl_seconds,
			header_name: HeaderName::from_static("x-gateway-proof"),
		})
	}

	pub fn apply(&self, req: &mut Request) -> Result<(), anyhow::Error> {
		let claims = match req.extensions().get::<Claims>() {
			Some(c) => c,
			None => return Ok(()),
		};

		let inner = &claims.inner;
		let sub = inner
			.get("sub")
			.and_then(|v| v.as_str())
			.unwrap_or("")
			.to_string();
		let scp = extract_scopes(inner);

		// obo: Phase 1 defaults to sub. Phase 2 (Policy Service) enriches from account relationships.
		let obo = sub.clone();
		let cid = sub.clone();

		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
		let payload = ProofPayload {
			sub: sub.clone(),
			obo,
			cid,
			iby: String::new(),
			auth_type: "okta_token".to_string(),
			ent: EntClaim {
				scopes: scp,
				roles: vec![],
				accounts: vec![],
			},
			iat: now,
			exp: now + self.ttl_seconds,
		};

		let header = Header::new(Algorithm::RS256);
		let token = encode(&header, &payload, &self.encoding_key)?;

		let headers = req.headers_mut();
		headers.insert(self.header_name.clone(), HeaderValue::from_str(&token)?);
		headers.insert(
			HeaderName::from_static("x-on-behalf-of"),
			HeaderValue::from_str(&payload.sub)?,
		);
		headers.insert(
			HeaderName::from_static("x-caller-id"),
			HeaderValue::from_str(&payload.sub)?,
		);

		Ok(())
	}
}

fn extract_scopes(claims: &Map<String, Value>) -> Vec<String> {
	match claims.get("scp") {
		Some(Value::Array(arr)) => arr
			.iter()
			.filter_map(|v| v.as_str().map(String::from))
			.collect(),
		Some(Value::String(s)) => s.split_whitespace().map(String::from).collect(),
		_ => vec![],
	}
}

impl std::fmt::Debug for GatewayProof {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("GatewayProof")
			.field("ttl_seconds", &self.ttl_seconds)
			.finish()
	}
}

impl serde::Serialize for GatewayProof {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		#[derive(serde::Serialize)]
		struct Serde {
			ttl_seconds: u64,
		}
		Serde {
			ttl_seconds: self.ttl_seconds,
		}
		.serialize(serializer)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use jsonwebtoken::{DecodingKey, Validation, decode};
	use serde_json::json;

	const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFVIAWtx0FRhiP
+8cHeEqVi3AqMQPGuju1JNNEU/eZKh6MVLp47SP4vq9jCu3mjUwJbLRyOh1jdmPC
JXWhiY9F0Il6KcuGihyMc/+Qv0p7yQqYcrzq4iSIweTa1VtRHr3RYKVQXEvhaIFj
UYFKxccVGjtnRuMZ3RNec8W3oVrJpCP2huC7RWpWorGvQ3jb0M0Zf+7HULMLVbd2
KhZgxRm/y2ljh1rHrFE4WSzao6iSHyVTqwA8we3JtdzTz7e3ztpXJJfpbHmYBhG7
evmVUHFGfOqTAF0xo+At8ILqtAFfoH3DiDEuuT1Frx4YD0unJxjxz9UERziRdQxP
oeFoqclZAgMBAAECggEAFGra2f7WXN5U2kkF3er/ZJvJ3kO2DVDlrqeByJcbjliC
UqjNpod66ljoksnlta43CN6biRokQk9UoRj5I9602Vdrch1y9pfBvnKeJd71GPvD
QeTVUURW3WOah13+FdWldE2YrUjvfQIwKROc2hy+rZtKPDRkeR+bynEWKxrh5u0L
KxjF0v0EZBttp9g6OzXYYaznvbXlDk/BVU/+QD3kkDWIUIa9O+jcZqUS73CI0/zR
BAw3tI9y/Z/Mdu56cHeglrM6h/t8e6g6xmhhTgaWN0y183WB2H5/CbbB2wRBCnUn
eNASco/fegQZRakfcN0AuRLjsB+haB/NHheYWlYxVQKBgQD2NhWmd7039LQV0O/t
R8O5iR54NqXdytT6YL69X2wK026lhlGuOlVsk6tU031hXaqT+FTABcZcagmHfesM
y9IvLzZionQH02RV+Tazg5KHgaoC5ri/BtU2j2iDIZN6sXvg09MpayFF5OQmi1zu
ubJbby4OqukCMt4Rk29Eu0G7EwKBgQDNLOhXAKP35i+gsMNw3ulXFWjsJBrQ3Wja
ytiBuzxpVjeFdPkNcDqHfRizDH4eQu2QiAbxK1lctMZ+FKiz3wkMnuVKLyXhgp0J
Kk6Nof+X7PUjFszVxtNcjvJ6Q3Dv1PuneHbN5zhMx06ZZ2He6PwF9FtzaAEE4ppB
OSG4RuzrYwKBgQCMxLNwL/mxamkkKAdlZKiVBb60AJqoynUmifXEFDCTp/sVDEzb
DmMU5wEISLrg1krWux7JgwO8hqvYGbgv4sDTVW0Ey9kHOGefeBM8Y7d9Xjcz3XI3
VdLFlQyuHJ5TgfJPwwxyG9w0N//xwbBqlSVSfaiZnkIGjcrFxcPSSjX0nQKBgFn7
ZfIyH7cqxpyMqUopGODOTPOzaedMEx5Rc96BhR8VZsgq4scX/zNIk7qCshUHeTS3
04OVZV2ZEqxc1xf7qvZUAW8lelGKfOB2I3lOINA6Zc/7wd3Hkw62ynUAetlT6QIr
fL8UtsZFap0wj+W4/D6ISks0w62my8vrCHTO9jzNAoGBAL9fs/T9YwxTPCmV5ug3
AdrvxmTQaoVieQAWuAv1GQ4FKbDPF6L57UQz+y9Gu0n6STWnjKEfQBc3vyIpqM0y
WrBMUrzRH8zKv/jQLvuD+D6ALP8eQWJTZOXUwC/Sg4yxSzwu4yTE1CP91ZEbMkMR
0sYO1EDIwP0H1pTnhVCMfwIB
-----END PRIVATE KEY-----";

	const TEST_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxVSAFrcdBUYYj/vHB3hK
lYtwKjEDxro7tSTTRFP3mSoejFS6eO0j+L6vYwrt5o1MCWy0cjodY3ZjwiV1oYmP
RdCJeinLhoocjHP/kL9Ke8kKmHK86uIkiMHk2tVbUR690WClUFxL4WiBY1GBSsXH
FRo7Z0bjGd0TXnPFt6FayaQj9obgu0VqVqKxr0N429DNGX/ux1CzC1W3dioWYMUZ
v8tpY4dax6xROFks2qOokh8lU6sAPMHtybXc08+3t87aVySX6Wx5mAYRu3r5lVBx
RnzqkwBdMaPgLfCC6rQBX6B9w4gxLrk9Ra8eGA9LpycY8c/VBEc4kXUMT6HhaKnJ
WQIDAQAB
-----END PUBLIC KEY-----";

	#[test]
	fn test_proof_round_trip() {
		let gp = GatewayProof::new(TEST_PRIV_PEM, 60).unwrap();

		let mut req = http::Request::builder()
			.uri("/mcp")
			.body(crate::http::Body::empty())
			.unwrap();
		let claims_map: serde_json::Map<String, serde_json::Value> =
			serde_json::from_str(r#"{"sub":"test@eg.money","scp":["flash:read"]}"#).unwrap();
		let claims = Claims {
			inner: claims_map,
			jwt: secrecy::SecretString::new("test-token".into()),
		};
		req.extensions_mut().insert(claims);

		gp.apply(&mut req).unwrap();

		let proof = req
			.headers()
			.get("x-gateway-proof")
			.unwrap()
			.to_str()
			.unwrap();
		let dk = DecodingKey::from_rsa_pem(TEST_PUB_PEM.as_bytes()).unwrap();
		let mut val = Validation::new(Algorithm::RS256);
		val.validate_aud = false;
		val.required_spec_claims = std::collections::HashSet::new();
		let decoded = decode::<serde_json::Value>(proof, &dk, &val).unwrap();
		assert_eq!(decoded.claims["sub"], "test@eg.money");
		assert_eq!(decoded.claims["ent"]["scopes"], json!(["flash:read"]));
		assert_eq!(decoded.claims["_auth_type"], "okta_token");

		assert!(req.headers().get("x-on-behalf-of").is_some());
		assert!(req.headers().get("x-caller-id").is_some());
	}

	#[test]
	fn test_no_claims_no_proof() {
		let gp = GatewayProof::new(TEST_PRIV_PEM, 60).unwrap();
		let mut req = http::Request::builder()
			.uri("/mcp")
			.body(crate::http::Body::empty())
			.unwrap();
		gp.apply(&mut req).unwrap();
		assert!(req.headers().get("x-gateway-proof").is_none());
	}
}
