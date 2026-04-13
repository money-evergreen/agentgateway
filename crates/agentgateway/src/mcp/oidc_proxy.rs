use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http::{Method, StatusCode, header};
use once_cell::sync::Lazy;
use rand::RngExt;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::http::oauth::{authorization_server_metadata_url, openid_configuration_metadata_url};
use crate::http::{Body, Request, Response};
use crate::json::from_body_with_limit;
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{McpAuthentication, McpIDP, OidcProxyConfig};

const TRANSACTION_TTL: Duration = Duration::from_secs(10 * 60);
const AUTH_CODE_TTL: Duration = Duration::from_secs(5 * 60);
const TOKEN_RESPONSE_BODY_LIMIT: usize = 64 * 1024;

static OIDC_PROXY_STORE: Lazy<RwLock<OidcProxyStore>> =
	Lazy::new(|| RwLock::new(OidcProxyStore::default()));

#[derive(Default)]
struct OidcProxyStore {
	transactions: HashMap<String, ProxyTransaction>,
	auth_codes: HashMap<String, ProxyAuthCode>,
}

struct ProxyTransaction {
	client_id: String,
	client_redirect_uri: String,
	client_state: String,
	client_code_challenge: String,
	idp_token_endpoint: String,
	gateway_pkce_verifier: String,
	#[allow(dead_code)]
	client_scope: Option<String>,
	expires_at: u64,
}

struct ProxyAuthCode {
	client_id: String,
	client_redirect_uri: String,
	client_code_challenge: String,
	token_response: serde_json::Value,
	expires_at: u64,
}

impl OidcProxyStore {
	fn gc_expired(&mut self) {
		let now = now_unix();
		self.transactions.retain(|_, t| t.expires_at > now);
		self.auth_codes.retain(|_, c| c.expires_at > now);
	}

	fn insert_transaction(&mut self, key: String, tx: ProxyTransaction) {
		self.gc_expired();
		self.transactions.insert(key, tx);
	}

	fn take_transaction(&mut self, key: &str) -> Option<ProxyTransaction> {
		let tx = self.transactions.remove(key)?;
		if tx.expires_at <= now_unix() {
			return None;
		}
		Some(tx)
	}

	fn insert_auth_code(&mut self, key: String, code: ProxyAuthCode) {
		self.auth_codes.insert(key, code);
	}

	fn take_auth_code(&mut self, key: &str) -> Option<ProxyAuthCode> {
		let code = self.auth_codes.remove(key)?;
		if code.expires_at <= now_unix() {
			return None;
		}
		Some(code)
	}

	fn revoke_by_client_id(&mut self, client_id: &str) -> (usize, usize) {
		let tx_before = self.transactions.len();
		self.transactions.retain(|_, t| t.client_id != client_id);
		let tx_removed = tx_before - self.transactions.len();

		let code_before = self.auth_codes.len();
		self.auth_codes.retain(|_, c| c.client_id != client_id);
		let code_removed = code_before - self.auth_codes.len();

		(tx_removed, code_removed)
	}
}

/// Purge all pending transactions and auth codes for a deactivated client.
/// Returns (transactions_removed, auth_codes_removed).
pub(super) fn revoke_client(client_id: &str) -> (usize, usize) {
	match OIDC_PROXY_STORE.write() {
		Ok(mut store) => store.revoke_by_client_id(client_id),
		Err(_) => {
			warn!(client_id = %client_id, "proxy store lock poisoned during revocation");
			(0, 0)
		},
	}
}

#[derive(serde::Deserialize)]
struct IdpMetadata {
	authorization_endpoint: String,
	token_endpoint: String,
}

pub(super) async fn proxy_authorize(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	let proxy_cfg = auth
		.oidc_proxy
		.as_ref()
		.ok_or_else(|| ProxyError::ProcessingString("OIDC proxy not configured".into()))?;

	if *req.method() != Method::GET {
		return build_error_response(
			StatusCode::METHOD_NOT_ALLOWED,
			"invalid_request",
			"authorize endpoint requires GET",
		);
	}

	let query = req.uri().query().unwrap_or_default();
	let params = parse_query(query);

	let client_id = required_param(&params, "client_id")?;
	let redirect_uri = required_param(&params, "redirect_uri")?;
	let response_type = required_param(&params, "response_type")?;
	let state = required_param(&params, "state")?;
	let code_challenge = required_param(&params, "code_challenge")?;
	let code_challenge_method = required_param(&params, "code_challenge_method")?;
	let scope = params.get("scope").cloned();

	if response_type != "code" {
		return build_error_response(
			StatusCode::BAD_REQUEST,
			"unsupported_response_type",
			"only response_type=code is supported",
		);
	}

	if code_challenge_method != "S256" {
		return build_error_response(
			StatusCode::BAD_REQUEST,
			"invalid_request",
			"code_challenge_method must be S256",
		);
	}

	let registration = super::auth::get_registered_client(&client_id);
	let registration = match registration {
		Some(r) if r.active => r,
		Some(_) => {
			warn!(client_id = %client_id, audit_event = "authorize_rejected_deactivated", "authorize rejected: client deactivated");
			return build_error_response(
				StatusCode::BAD_REQUEST,
				"invalid_client",
				"client registration is deactivated",
			);
		},
		None => {
			warn!(client_id = %client_id, audit_event = "authorize_rejected_unknown", "authorize rejected: unknown client");
			return build_error_response(
				StatusCode::BAD_REQUEST,
				"invalid_client",
				"unknown client_id",
			);
		},
	};

	if !registration.redirect_uris.iter().any(|u| u == &redirect_uri) {
		warn!(client_id = %client_id, audit_event = "authorize_rejected_redirect_uri", "authorize rejected: redirect_uri mismatch");
		return build_error_response(
			StatusCode::BAD_REQUEST,
			"invalid_request",
			"redirect_uri does not match any registered redirect URIs",
		);
	}

	let idp_metadata = fetch_idp_metadata(auth, client.clone()).await?;

	let gateway_state = random_token(32);
	let gateway_pkce_verifier = random_token(32);
	let gateway_code_challenge = {
		let digest = Sha256::digest(gateway_pkce_verifier.as_bytes());
		base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
	};

	let gateway_callback_url = derive_callback_url(req);

	let tx = ProxyTransaction {
		client_id,
		client_redirect_uri: redirect_uri,
		client_state: state,
		client_code_challenge: code_challenge,
		idp_token_endpoint: idp_metadata.token_endpoint,
		gateway_pkce_verifier,
		client_scope: scope.clone(),
		expires_at: now_unix().saturating_add(TRANSACTION_TTL.as_secs()),
	};

	let audit_client_id = tx.client_id.clone();

	OIDC_PROXY_STORE
		.write()
		.map_err(|_| ProxyError::ProcessingString("proxy store lock poisoned".into()))?
		.insert_transaction(gateway_state.clone(), tx);

	let mut idp_params = vec![
		("response_type", "code".to_string()),
		("client_id", proxy_cfg.client_id.clone()),
		("redirect_uri", gateway_callback_url),
		("state", gateway_state),
		("code_challenge", gateway_code_challenge),
		("code_challenge_method", "S256".to_string()),
	];
	if let Some(scope) = scope {
		idp_params.push(("scope", scope));
	}

	let idp_authorize_url = append_query(&idp_metadata.authorization_endpoint, &idp_params);

	info!(
		client_id = %audit_client_id,
		audit_event = "proxy_authorize_started",
		"OIDC proxy authorization flow started; redirecting to IDP"
	);

	build_redirect_response(&idp_authorize_url)
}

pub(super) async fn proxy_callback(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	let proxy_cfg = auth
		.oidc_proxy
		.as_ref()
		.ok_or_else(|| ProxyError::ProcessingString("OIDC proxy not configured".into()))?;

	let query = req.uri().query().unwrap_or_default();
	let params = parse_query(query);

	if let Some(error) = params.get("error") {
		let description = params
			.get("error_description")
			.cloned()
			.unwrap_or_else(|| "authorization denied by provider".into());
		warn!(error = %error, description = %description, "IDP returned error on callback");
		return build_error_response(StatusCode::BAD_REQUEST, error, &description);
	}

	let gateway_state = required_param(&params, "state")?;
	let code = required_param(&params, "code")?;

	let tx = OIDC_PROXY_STORE
		.write()
		.map_err(|_| ProxyError::ProcessingString("proxy store lock poisoned".into()))?
		.take_transaction(&gateway_state)
		.ok_or_else(|| {
			ProxyError::ProcessingString(
				"expired or replayed state parameter; transaction not found".into(),
			)
		})?;

	let gateway_callback_url = derive_callback_url(req);

	let token_response = exchange_code_at_idp(
		client,
		&tx.idp_token_endpoint,
		proxy_cfg,
		&gateway_callback_url,
		&code,
		&tx.gateway_pkce_verifier,
	)
	.await?;

	let proxy_code = random_token(32);
	let auth_code_entry = ProxyAuthCode {
		client_id: tx.client_id,
		client_redirect_uri: tx.client_redirect_uri.clone(),
		client_code_challenge: tx.client_code_challenge,
		token_response,
		expires_at: now_unix().saturating_add(AUTH_CODE_TTL.as_secs()),
	};

	let audit_callback_client_id = auth_code_entry.client_id.clone();

	OIDC_PROXY_STORE
		.write()
		.map_err(|_| ProxyError::ProcessingString("proxy store lock poisoned".into()))?
		.insert_auth_code(proxy_code.clone(), auth_code_entry);

	info!(
		client_id = %audit_callback_client_id,
		audit_event = "proxy_callback_success",
		"IDP code exchange succeeded; proxy auth code issued to client"
	);

	let redirect_params = [
		("code", proxy_code),
		("state", tx.client_state),
	];
	let redirect_url = append_query(&tx.client_redirect_uri, &redirect_params);

	build_redirect_response(&redirect_url)
}

pub(super) async fn proxy_token(
	req: &mut Request,
	auth: &McpAuthentication,
	_client: PolicyClient,
) -> Result<Response, ProxyError> {
	let _proxy_cfg = auth
		.oidc_proxy
		.as_ref()
		.ok_or_else(|| ProxyError::ProcessingString("OIDC proxy not configured".into()))?;

	if *req.method() != Method::POST {
		return build_error_response(
			StatusCode::METHOD_NOT_ALLOWED,
			"invalid_request",
			"token endpoint requires POST",
		);
	}

	let body_bytes = crate::http::read_body_with_limit(
		std::mem::take(req.body_mut()),
		crate::defaults::max_buffer_size(),
	)
	.await
	.map_err(|e| ProxyError::ProcessingString(format!("failed to read token request body: {e}")))?;

	let form_params = parse_form(&body_bytes);

	let (client_id, client_secret) = extract_client_credentials(req, &form_params)?;

	let registration = super::auth::get_registered_client(&client_id);
	let registration = match registration {
		Some(r) if r.active => r,
		Some(_) => {
			warn!(client_id = %client_id, audit_event = "token_rejected_deactivated", "token exchange rejected: client deactivated");
			return build_error_response(
				StatusCode::UNAUTHORIZED,
				"invalid_client",
				"client registration is deactivated",
			);
		},
		None => {
			warn!(client_id = %client_id, audit_event = "token_rejected_unknown", "token exchange rejected: unknown client");
			return build_error_response(
				StatusCode::UNAUTHORIZED,
				"invalid_client",
				"unknown client_id",
			);
		},
	};

	if !constant_time_eq(registration.client_secret.as_bytes(), client_secret.as_bytes()) {
		warn!(client_id = %client_id, audit_event = "token_rejected_bad_secret", "token exchange rejected: client authentication failed");
		return build_error_response(
			StatusCode::UNAUTHORIZED,
			"invalid_client",
			"client authentication failed",
		);
	}

	let grant_type = required_form_param(&form_params, "grant_type")?;
	if grant_type != "authorization_code" {
		return build_error_response(
			StatusCode::BAD_REQUEST,
			"unsupported_grant_type",
			"only grant_type=authorization_code is supported",
		);
	}

	let proxy_code = required_form_param(&form_params, "code")?;
	let redirect_uri = required_form_param(&form_params, "redirect_uri")?;
	let code_verifier = required_form_param(&form_params, "code_verifier")?;

	let auth_code = OIDC_PROXY_STORE
		.write()
		.map_err(|_| ProxyError::ProcessingString("proxy store lock poisoned".into()))?
		.take_auth_code(&proxy_code)
		.ok_or_else(|| {
			warn!(client_id = %client_id, audit_event = "token_rejected_expired_code", "token exchange rejected: expired or replayed authorization code");
			ProxyError::ProcessingString(
				"expired or replayed authorization code; code not found".into(),
			)
		})?;

	if auth_code.client_id != client_id {
		return build_error_response(
			StatusCode::BAD_REQUEST,
			"invalid_grant",
			"code was issued to a different client",
		);
	}

	if auth_code.client_redirect_uri != redirect_uri {
		return build_error_response(
			StatusCode::BAD_REQUEST,
			"invalid_grant",
			"redirect_uri does not match the value used during authorization",
		);
	}

	let expected_challenge = {
		let digest = Sha256::digest(code_verifier.as_bytes());
		base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
	};
	if !constant_time_eq(
		expected_challenge.as_bytes(),
		auth_code.client_code_challenge.as_bytes(),
	) {
		warn!(client_id = %client_id, audit_event = "token_rejected_pkce_mismatch", "token exchange rejected: PKCE code_verifier mismatch");
		return build_error_response(
			StatusCode::BAD_REQUEST,
			"invalid_grant",
			"code_verifier does not match code_challenge",
		);
	}

	info!(
		client_id = %client_id,
		audit_event = "proxy_token_issued",
		"proxy token exchange completed; tokens delivered to client"
	);

	let body = serde_json::to_vec(&auth_code.token_response)
		.map_err(|e| ProxyError::ProcessingString(format!("failed to serialize tokens: {e}")))?;

	::http::Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTENT_TYPE, "application/json")
		.header(header::CACHE_CONTROL, "no-store")
		.header(header::PRAGMA, "no-cache")
		.body(Body::from(Bytes::from(body)))
		.map_err(ProxyError::Http)
}

pub(super) fn rewrite_as_metadata(
	resp: &mut serde_json::Value,
	req: &Request,
	auth: &McpAuthentication,
) {
	if auth.oidc_proxy.is_none() {
		return;
	}

	let base_url = derive_as_base_url(req);

	if let Some(obj) = resp.as_object_mut() {
		obj.insert(
			"authorization_endpoint".into(),
			serde_json::Value::String(format!("{base_url}/authorize")),
		);
		obj.insert(
			"token_endpoint".into(),
			serde_json::Value::String(format!("{base_url}/token")),
		);
		obj.insert(
			"registration_endpoint".into(),
			serde_json::Value::String(format!("{base_url}/client-registration")),
		);
		obj.insert(
			"code_challenge_methods_supported".into(),
			serde_json::json!(["S256"]),
		);
		obj.insert(
			"grant_types_supported".into(),
			serde_json::json!(["authorization_code"]),
		);
		obj.insert(
			"response_types_supported".into(),
			serde_json::json!(["code"]),
		);
		obj.insert(
			"token_endpoint_auth_methods_supported".into(),
			serde_json::json!(["client_secret_basic", "client_secret_post"]),
		);
	}
}

async fn fetch_idp_metadata(
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<IdpMetadata, ProxyError> {
	let metadata_uri = match &auth.provider {
		Some(McpIDP::Keycloak { .. }) => openid_configuration_metadata_url(&auth.issuer),
		_ => authorization_server_metadata_url(&auth.issuer),
	};
	let ureq = ::http::Request::builder()
		.uri(metadata_uri)
		.body(Body::empty())?;
	let upstream = client.simple_call(ureq).await?;
	let limit = crate::http::response_buffer_limit(&upstream);
	let metadata: IdpMetadata =
		from_body_with_limit(upstream.into_body(), limit)
			.await
			.map_err(ProxyError::Body)?;
	Ok(metadata)
}

async fn exchange_code_at_idp(
	client: PolicyClient,
	token_endpoint: &str,
	proxy_cfg: &OidcProxyConfig,
	redirect_uri: &str,
	code: &str,
	pkce_verifier: &str,
) -> Result<serde_json::Value, ProxyError> {
	let form = [
		("grant_type", "authorization_code"),
		("code", code),
		("redirect_uri", redirect_uri),
		("code_verifier", pkce_verifier),
		("client_id", &proxy_cfg.client_id),
		("client_secret", proxy_cfg.client_secret.expose_secret()),
	];
	let body = serde_urlencoded::to_string(form)
		.map_err(|e| ProxyError::ProcessingString(format!("failed to encode token form: {e}")))?;

	let req = ::http::Request::builder()
		.method(Method::POST)
		.uri(token_endpoint)
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.header(header::ACCEPT, "application/json")
		.body(Body::from(body))?;

	let resp = client.simple_call(req).await?;
	let status = resp.status();
	let body = crate::http::read_body_with_limit(resp.into_body(), TOKEN_RESPONSE_BODY_LIMIT)
		.await
		.map_err(|e| ProxyError::ProcessingString(format!("failed to read IDP token response: {e}")))?;

	if status != StatusCode::OK {
		let error_body = String::from_utf8_lossy(&body);
		debug!(status = %status, body = %error_body, "IDP token exchange failed");
		return Err(ProxyError::ProcessingString(format!(
			"IDP token endpoint returned {status}"
		)));
	}

	serde_json::from_slice(&body).map_err(|e| {
		ProxyError::ProcessingString(format!("failed to parse IDP token response: {e}"))
	})
}

fn extract_client_credentials(
	req: &Request,
	form_params: &HashMap<String, String>,
) -> Result<(String, String), ProxyError> {
	if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
		let auth_str = auth_header
			.to_str()
			.map_err(|_| ProxyError::ProcessingString("invalid authorization header".into()))?;
		if let Some(encoded) = auth_str.strip_prefix("Basic ") {
			let decoded = base64::engine::general_purpose::STANDARD
				.decode(encoded.trim())
				.map_err(|_| {
					ProxyError::ProcessingString("invalid Basic auth encoding".into())
				})?;
			let decoded_str = String::from_utf8(decoded).map_err(|_| {
				ProxyError::ProcessingString("invalid Basic auth encoding".into())
			})?;
			if let Some((id, secret)) = decoded_str.split_once(':') {
				let id = url::form_urlencoded::parse(id.as_bytes())
					.map(|(k, _)| k.into_owned())
					.next()
					.unwrap_or_else(|| id.to_string());
				let secret = url::form_urlencoded::parse(secret.as_bytes())
					.map(|(k, _)| k.into_owned())
					.next()
					.unwrap_or_else(|| secret.to_string());
				return Ok((id, secret));
			}
		}
	}

	let client_id = form_params
		.get("client_id")
		.ok_or_else(|| ProxyError::ProcessingString("missing client_id".into()))?
		.clone();
	let client_secret = form_params
		.get("client_secret")
		.ok_or_else(|| ProxyError::ProcessingString("missing client_secret".into()))?
		.clone();
	Ok((client_id, client_secret))
}

fn derive_callback_url(req: &Request) -> String {
	let uri = req
		.extensions()
		.get::<crate::http::filters::OriginalUrl>()
		.map(|u| u.0.clone())
		.unwrap_or_else(|| req.uri().clone());

	let path = uri.path();
	let base = path
		.rsplit_once('/')
		.map(|(prefix, _)| prefix)
		.unwrap_or(path);

	let full = uri.to_string();
	full.replace(path, &format!("{base}/callback"))
}

fn derive_as_base_url(req: &Request) -> String {
	let uri = req
		.extensions()
		.get::<crate::http::filters::OriginalUrl>()
		.map(|u| u.0.clone())
		.unwrap_or_else(|| req.uri().clone());

	uri.to_string()
}

fn parse_query(query: &str) -> HashMap<String, String> {
	url::form_urlencoded::parse(query.as_bytes())
		.map(|(k, v)| (k.into_owned(), v.into_owned()))
		.collect()
}

fn parse_form(body: &[u8]) -> HashMap<String, String> {
	url::form_urlencoded::parse(body)
		.map(|(k, v)| (k.into_owned(), v.into_owned()))
		.collect()
}

fn required_param(params: &HashMap<String, String>, key: &str) -> Result<String, ProxyError> {
	params.get(key).cloned().ok_or_else(|| {
		ProxyError::ProcessingString(format!("missing required parameter: {key}"))
	})
}

fn required_form_param(
	params: &HashMap<String, String>,
	key: &str,
) -> Result<String, ProxyError> {
	params.get(key).cloned().ok_or_else(|| {
		ProxyError::ProcessingString(format!("missing required form parameter: {key}"))
	})
}

fn random_token(bytes: usize) -> String {
	let mut buf = vec![0u8; bytes];
	rand::rng().fill(buf.as_mut_slice());
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn now_unix() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or(Duration::ZERO)
		.as_secs()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

fn append_query(url: &str, params: &[(&str, String)]) -> String {
	let mut parsed = url::Url::parse(url).unwrap_or_else(|_| {
		url::Url::parse(&format!("https://invalid.example{url}")).expect("fallback url")
	});
	{
		let mut query = parsed.query_pairs_mut();
		for (key, value) in params {
			query.append_pair(key, value);
		}
	}
	parsed.to_string()
}

fn build_redirect_response(location: &str) -> Result<Response, ProxyError> {
	::http::Response::builder()
		.status(StatusCode::FOUND)
		.header(header::LOCATION, location)
		.header(header::CACHE_CONTROL, "no-store")
		.header(header::PRAGMA, "no-cache")
		.body(Body::empty())
		.map_err(ProxyError::Http)
}

fn build_error_response(
	status: StatusCode,
	error: &str,
	description: &str,
) -> Result<Response, ProxyError> {
	let body = serde_json::json!({
		"error": error,
		"error_description": description,
	});
	::http::Response::builder()
		.status(status)
		.header(header::CONTENT_TYPE, "application/json")
		.header(header::CACHE_CONTROL, "no-store")
		.body(Body::from(Bytes::from(
			serde_json::to_vec(&body)
				.map_err(|e| ProxyError::ProcessingString(e.to_string()))?,
		)))
		.map_err(ProxyError::Http)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn store_transaction_lifecycle() {
		let mut store = OidcProxyStore::default();
		let tx = ProxyTransaction {
			client_id: "client-1".into(),
			client_redirect_uri: "https://app.example/callback".into(),
			client_state: "client-state-1".into(),
			client_code_challenge: "challenge-abc".into(),
			idp_token_endpoint: "https://idp.example/token".into(),
			gateway_pkce_verifier: "verifier-xyz".into(),
			client_scope: Some("openid".into()),
			expires_at: now_unix() + 300,
		};
		store.insert_transaction("gw-state-1".into(), tx);
		assert!(store.transactions.contains_key("gw-state-1"));

		let taken = store.take_transaction("gw-state-1");
		assert!(taken.is_some());
		assert_eq!(taken.unwrap().client_id, "client-1");

		assert!(store.take_transaction("gw-state-1").is_none());
	}

	#[test]
	fn store_rejects_expired_transaction() {
		let mut store = OidcProxyStore::default();
		let tx = ProxyTransaction {
			client_id: "client-1".into(),
			client_redirect_uri: "https://app.example/callback".into(),
			client_state: "client-state-1".into(),
			client_code_challenge: "challenge-abc".into(),
			idp_token_endpoint: "https://idp.example/token".into(),
			gateway_pkce_verifier: "verifier-xyz".into(),
			client_scope: None,
			expires_at: now_unix().saturating_sub(1),
		};
		store.insert_transaction("expired-state".into(), tx);
		assert!(store.take_transaction("expired-state").is_none());
	}

	#[test]
	fn auth_code_lifecycle() {
		let mut store = OidcProxyStore::default();
		let code_entry = ProxyAuthCode {
			client_id: "client-1".into(),
			client_redirect_uri: "https://app.example/callback".into(),
			client_code_challenge: "challenge-abc".into(),
			token_response: serde_json::json!({"access_token": "tok", "token_type": "Bearer"}),
			expires_at: now_unix() + 300,
		};
		store.insert_auth_code("proxy-code-1".into(), code_entry);

		let taken = store.take_auth_code("proxy-code-1");
		assert!(taken.is_some());

		assert!(
			store.take_auth_code("proxy-code-1").is_none(),
			"auth code must be single-use"
		);
	}

	#[test]
	fn auth_code_rejects_expired() {
		let mut store = OidcProxyStore::default();
		let code_entry = ProxyAuthCode {
			client_id: "client-1".into(),
			client_redirect_uri: "https://app.example/callback".into(),
			client_code_challenge: "challenge-abc".into(),
			token_response: serde_json::json!({}),
			expires_at: now_unix().saturating_sub(1),
		};
		store.insert_auth_code("expired-code".into(), code_entry);
		assert!(store.take_auth_code("expired-code").is_none());
	}

	#[test]
	fn pkce_s256_verification_matches() {
		let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		let expected_challenge = {
			let digest = Sha256::digest(verifier.as_bytes());
			base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
		};
		assert!(constant_time_eq(
			expected_challenge.as_bytes(),
			expected_challenge.as_bytes()
		));

		let wrong_verifier = "wrong-verifier";
		let wrong_challenge = {
			let digest = Sha256::digest(wrong_verifier.as_bytes());
			base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
		};
		assert!(!constant_time_eq(
			expected_challenge.as_bytes(),
			wrong_challenge.as_bytes()
		));
	}

	#[test]
	fn revoke_by_client_id_purges_matching_entries() {
		let mut store = OidcProxyStore::default();
		store.insert_transaction(
			"tx-a".into(),
			ProxyTransaction {
				client_id: "target-client".into(),
				client_redirect_uri: "https://example.com/cb".into(),
				client_state: "s1".into(),
				client_code_challenge: "ch1".into(),
				idp_token_endpoint: "https://idp/token".into(),
				gateway_pkce_verifier: "v1".into(),
				client_scope: None,
				expires_at: now_unix() + 600,
			},
		);
		store.insert_transaction(
			"tx-b".into(),
			ProxyTransaction {
				client_id: "other-client".into(),
				client_redirect_uri: "https://example.com/cb".into(),
				client_state: "s2".into(),
				client_code_challenge: "ch2".into(),
				idp_token_endpoint: "https://idp/token".into(),
				gateway_pkce_verifier: "v2".into(),
				client_scope: None,
				expires_at: now_unix() + 600,
			},
		);
		store.insert_auth_code(
			"code-a".into(),
			ProxyAuthCode {
				client_id: "target-client".into(),
				client_redirect_uri: "https://example.com/cb".into(),
				client_code_challenge: "ch1".into(),
				token_response: serde_json::json!({}),
				expires_at: now_unix() + 300,
			},
		);
		store.insert_auth_code(
			"code-b".into(),
			ProxyAuthCode {
				client_id: "other-client".into(),
				client_redirect_uri: "https://example.com/cb".into(),
				client_code_challenge: "ch2".into(),
				token_response: serde_json::json!({}),
				expires_at: now_unix() + 300,
			},
		);

		let (tx_removed, code_removed) = store.revoke_by_client_id("target-client");
		assert_eq!(tx_removed, 1);
		assert_eq!(code_removed, 1);
		assert!(!store.transactions.contains_key("tx-a"));
		assert!(store.transactions.contains_key("tx-b"));
		assert!(!store.auth_codes.contains_key("code-a"));
		assert!(store.auth_codes.contains_key("code-b"));
	}

	#[test]
	fn revoke_nonexistent_client_is_noop() {
		let mut store = OidcProxyStore::default();
		store.insert_transaction(
			"tx-1".into(),
			ProxyTransaction {
				client_id: "existing".into(),
				client_redirect_uri: "https://example.com/cb".into(),
				client_state: "s1".into(),
				client_code_challenge: "ch1".into(),
				idp_token_endpoint: "https://idp/token".into(),
				gateway_pkce_verifier: "v1".into(),
				client_scope: None,
				expires_at: now_unix() + 600,
			},
		);

		let (tx_removed, code_removed) = store.revoke_by_client_id("nonexistent");
		assert_eq!(tx_removed, 0);
		assert_eq!(code_removed, 0);
		assert!(store.transactions.contains_key("tx-1"));
	}

	#[test]
	fn gc_removes_expired_entries() {
		let mut store = OidcProxyStore::default();
		store.insert_transaction(
			"expired".into(),
			ProxyTransaction {
				client_id: "c1".into(),
				client_redirect_uri: "https://example.com/cb".into(),
				client_state: "s1".into(),
				client_code_challenge: "ch1".into(),
				idp_token_endpoint: "https://idp/token".into(),
				gateway_pkce_verifier: "v1".into(),
				client_scope: None,
				expires_at: now_unix().saturating_sub(10),
			},
		);
		store.insert_transaction(
			"valid".into(),
			ProxyTransaction {
				client_id: "c2".into(),
				client_redirect_uri: "https://example.com/cb".into(),
				client_state: "s2".into(),
				client_code_challenge: "ch2".into(),
				idp_token_endpoint: "https://idp/token".into(),
				gateway_pkce_verifier: "v2".into(),
				client_scope: None,
				expires_at: now_unix() + 600,
			},
		);

		store.gc_expired();
		assert!(!store.transactions.contains_key("expired"));
		assert!(store.transactions.contains_key("valid"));
	}
}
