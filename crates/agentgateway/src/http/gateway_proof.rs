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
		let inner = match req.extensions().get::<Claims>() {
			Some(c) => c.inner.clone(),
			None => return Ok(()),
		};
		self.sign_and_set_headers(req.headers_mut(), &inner)
	}

	pub fn apply_with_claims(
		&self,
		req: &mut Request,
		claims: &Claims,
	) -> Result<(), anyhow::Error> {
		self.sign_and_set_headers(req.headers_mut(), &claims.inner)
	}

	fn sign_and_set_headers(
		&self,
		headers: &mut http::HeaderMap,
		inner: &Map<String, Value>,
	) -> Result<(), anyhow::Error> {
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

	fn test_keypair() -> (String, String) {
		let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
		(kp.serialize_pem(), kp.public_key_pem())
	}

	#[test]
	fn test_proof_round_trip() {
		let (priv_pem, pub_pem) = test_keypair();
		let gp = GatewayProof::new(&priv_pem, 60).unwrap();

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
		let dk = DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap();
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
		let (priv_pem, _) = test_keypair();
		let gp = GatewayProof::new(&priv_pem, 60).unwrap();
		let mut req = http::Request::builder()
			.uri("/mcp")
			.body(crate::http::Body::empty())
			.unwrap();
		gp.apply(&mut req).unwrap();
		assert!(req.headers().get("x-gateway-proof").is_none());
	}
}
