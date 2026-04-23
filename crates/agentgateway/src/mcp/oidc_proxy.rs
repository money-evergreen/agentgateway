use std::collections::HashMap;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http::{Method, StatusCode, header};
use rand::RngExt;
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::http::oauth::{authorization_server_metadata_url, openid_configuration_metadata_url};
use crate::http::{Body, Request, Response};
use crate::json::from_body_with_limit;
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{McpAuthentication, McpIDP, OidcProxyConfig, RedisStorageConfig};

const TOKEN_RESPONSE_BODY_LIMIT: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Redis-backed proxy store
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct ProxyTransaction {
	client_id: String,
	client_redirect_uri: String,
	client_state: String,
	client_code_challenge: String,
	idp_token_endpoint: String,
	gateway_pkce_verifier: String,
	#[allow(dead_code)]
	client_scope: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProxyAuthCode {
	client_id: String,
	client_redirect_uri: String,
	client_code_challenge: String,
	token_response: serde_json::Value,
}

pub struct RedisProxyStore {
	conn: redis::aio::ConnectionManager,
	key_prefix: String,
	transaction_ttl: Duration,
	auth_code_ttl: Duration,
}

impl std::fmt::Debug for RedisProxyStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("RedisProxyStore")
			.field("key_prefix", &self.key_prefix)
			.field("transaction_ttl", &self.transaction_ttl)
			.field("auth_code_ttl", &self.auth_code_ttl)
			.finish_non_exhaustive()
	}
}

impl RedisProxyStore {
	pub async fn connect(cfg: &RedisStorageConfig) -> anyhow::Result<Self> {
		let client = redis::Client::open(cfg.url.as_str())
			.map_err(|e| anyhow::anyhow!("invalid Redis URL '{}': {e}", cfg.url))?;

		let conn = tokio::time::timeout(
			Duration::from_millis(cfg.connect_timeout_ms),
			redis::aio::ConnectionManager::new(client),
		)
		.await
		.map_err(|_| {
			anyhow::anyhow!(
				"Redis connect timeout after {}ms to '{}'",
				cfg.connect_timeout_ms,
				cfg.url
			)
		})?
		.map_err(|e| anyhow::anyhow!("Redis connection failed to '{}': {e}", cfg.url))?;

		info!(
			redis_url = %cfg.url,
			key_prefix = %cfg.key_prefix,
			"OIDC proxy Redis store connected"
		);

		Ok(Self {
			conn,
			key_prefix: cfg.key_prefix.clone(),
			transaction_ttl: Duration::from_secs(cfg.transaction_ttl_seconds),
			auth_code_ttl: Duration::from_secs(cfg.auth_code_ttl_seconds),
		})
	}

	pub fn key_prefix(&self) -> &str {
		&self.key_prefix
	}

	pub fn conn(&self) -> redis::aio::ConnectionManager {
		self.conn.clone()
	}

	fn txn_key(&self, state: &str) -> String {
		format!("{}:txn:{}", self.key_prefix, state)
	}

	fn code_key(&self, code: &str) -> String {
		format!("{}:code:{}", self.key_prefix, code)
	}

	fn client_txn_index(&self, client_id: &str) -> String {
		format!("{}:idx:client:{}:txn", self.key_prefix, client_id)
	}

	fn client_code_index(&self, client_id: &str) -> String {
		format!("{}:idx:client:{}:code", self.key_prefix, client_id)
	}

	async fn insert_transaction(
		&self,
		state: &str,
		tx: &ProxyTransaction,
	) -> Result<(), ProxyError> {
		let key = self.txn_key(state);
		let idx_key = self.client_txn_index(&tx.client_id);
		let value = serde_json::to_string(tx)
			.map_err(|e| ProxyError::ProcessingString(format!("serialize transaction: {e}")))?;
		let ttl_secs = self.transaction_ttl.as_secs() as i64;

		let mut conn = self.conn.clone();
		redis::pipe()
			.atomic()
			.cmd("SET")
			.arg(&key)
			.arg(&value)
			.arg("EX")
			.arg(ttl_secs)
			.cmd("SADD")
			.arg(&idx_key)
			.arg(&key)
			.cmd("EXPIRE")
			.arg(&idx_key)
			.arg(ttl_secs * 2)
			.exec_async(&mut conn)
			.await
			.map_err(|e| ProxyError::ProcessingString(format!("Redis insert_transaction: {e}")))?;

		Ok(())
	}

	async fn take_transaction(&self, state: &str) -> Result<Option<ProxyTransaction>, ProxyError> {
		let key = self.txn_key(state);
		let mut conn = self.conn.clone();

		let value: Option<String> = redis::cmd("GETDEL")
			.arg(&key)
			.query_async(&mut conn)
			.await
			.map_err(|e| ProxyError::ProcessingString(format!("Redis take_transaction: {e}")))?;

		match value {
			Some(json) => {
				let tx: ProxyTransaction = serde_json::from_str(&json).map_err(|e| {
					ProxyError::ProcessingString(format!("deserialize transaction: {e}"))
				})?;
				let _: Result<(), _> = conn.srem(self.client_txn_index(&tx.client_id), &key).await;
				Ok(Some(tx))
			},
			None => Ok(None),
		}
	}

	async fn insert_auth_code(
		&self,
		code: &str,
		entry: &ProxyAuthCode,
	) -> Result<(), ProxyError> {
		let key = self.code_key(code);
		let idx_key = self.client_code_index(&entry.client_id);
		let value = serde_json::to_string(entry)
			.map_err(|e| ProxyError::ProcessingString(format!("serialize auth code: {e}")))?;
		let ttl_secs = self.auth_code_ttl.as_secs() as i64;

		let mut conn = self.conn.clone();
		redis::pipe()
			.atomic()
			.cmd("SET")
			.arg(&key)
			.arg(&value)
			.arg("EX")
			.arg(ttl_secs)
			.cmd("SADD")
			.arg(&idx_key)
			.arg(&key)
			.cmd("EXPIRE")
			.arg(&idx_key)
			.arg(ttl_secs * 2)
			.exec_async(&mut conn)
			.await
			.map_err(|e| ProxyError::ProcessingString(format!("Redis insert_auth_code: {e}")))?;

		Ok(())
	}

	async fn take_auth_code(&self, code: &str) -> Result<Option<ProxyAuthCode>, ProxyError> {
		let key = self.code_key(code);
		let mut conn = self.conn.clone();

		let value: Option<String> = redis::cmd("GETDEL")
			.arg(&key)
			.query_async(&mut conn)
			.await
			.map_err(|e| ProxyError::ProcessingString(format!("Redis take_auth_code: {e}")))?;

		match value {
			Some(json) => {
				let entry: ProxyAuthCode = serde_json::from_str(&json).map_err(|e| {
					ProxyError::ProcessingString(format!("deserialize auth code: {e}"))
				})?;
				let _: Result<(), _> = conn
					.srem(self.client_code_index(&entry.client_id), &key)
					.await;
				Ok(Some(entry))
			},
			None => Ok(None),
		}
	}

	pub async fn revoke_by_client_id(&self, client_id: &str) -> (usize, usize) {
		let txn_idx = self.client_txn_index(client_id);
		let code_idx = self.client_code_index(client_id);
		let mut conn = self.conn.clone();

		let txn_keys: Vec<String> = conn.smembers(&txn_idx).await.unwrap_or_default();
		let code_keys: Vec<String> = conn.smembers(&code_idx).await.unwrap_or_default();

		let txn_count = txn_keys.len();
		let code_count = code_keys.len();

		let mut keys_to_delete: Vec<String> = Vec::with_capacity(txn_count + code_count + 2);
		keys_to_delete.extend(txn_keys);
		keys_to_delete.extend(code_keys);
		keys_to_delete.push(txn_idx);
		keys_to_delete.push(code_idx);

		if !keys_to_delete.is_empty() {
			let _: Result<(), _> = conn.del(keys_to_delete).await;
		}

		(txn_count, code_count)
	}
}

/// Purge all pending transactions and auth codes for a deactivated client.
/// Returns (transactions_removed, auth_codes_removed).
pub(super) async fn revoke_client(store: &RedisProxyStore, client_id: &str) -> (usize, usize) {
	store.revoke_by_client_id(client_id).await
}

#[derive(serde::Deserialize)]
struct IdpMetadataRaw {
	authorization_endpoint: Option<String>,
	token_endpoint: Option<String>,
	#[allow(dead_code)]
	issuer: Option<String>,
}

struct IdpMetadata {
	authorization_endpoint: String,
	token_endpoint: String,
}

fn get_store(auth: &McpAuthentication) -> Result<&RedisProxyStore, ProxyError> {
	auth.oidc_proxy
		.as_ref()
		.map(|p| p.store.as_ref())
		.ok_or_else(|| ProxyError::ProcessingString("OIDC proxy not configured".into()))
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
	let store = get_store(auth)?;

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

	let registration = super::auth::get_registered_client(store, &client_id).await;
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
		client_id: client_id.clone(),
		client_redirect_uri: redirect_uri,
		client_state: state,
		client_code_challenge: code_challenge,
		idp_token_endpoint: idp_metadata.token_endpoint,
		gateway_pkce_verifier,
		client_scope: scope.clone(),
	};

	store.insert_transaction(&gateway_state, &tx).await?;

	let mut idp_params = vec![
		("response_type", "code".to_string()),
		("client_id", proxy_cfg.client_id.clone()),
		("redirect_uri", gateway_callback_url),
		("state", gateway_state),
		("code_challenge", gateway_code_challenge),
		("code_challenge_method", "S256".to_string()),
	];
	{
		let scope_value = match scope {
			Some(s) if s.split_whitespace().any(|t| t == "offline_access") => s,
			Some(s) => format!("{s} offline_access"),
			None => "offline_access".to_string(),
		};
		idp_params.push(("scope", scope_value));
	}

	let idp_authorize_url = append_query(&idp_metadata.authorization_endpoint, &idp_params);

	info!(
		client_id = %client_id,
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
	let store = get_store(auth)?;

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

	let tx = store
		.take_transaction(&gateway_state)
		.await?
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
		client_id: tx.client_id.clone(),
		client_redirect_uri: tx.client_redirect_uri.clone(),
		client_code_challenge: tx.client_code_challenge,
		token_response,
	};

	store.insert_auth_code(&proxy_code, &auth_code_entry).await?;

	info!(
		client_id = %tx.client_id,
		audit_event = "proxy_callback_success",
		"IDP code exchange succeeded; proxy auth code issued to client"
	);

	let redirect_params = [("code", proxy_code), ("state", tx.client_state)];
	let redirect_url = append_query(&tx.client_redirect_uri, &redirect_params);

	build_redirect_response(&redirect_url)
}

pub(super) async fn proxy_token(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	let proxy_cfg = auth
		.oidc_proxy
		.as_ref()
		.ok_or_else(|| ProxyError::ProcessingString("OIDC proxy not configured".into()))?;
	let store = get_store(auth)?;

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

	let registration = super::auth::get_registered_client(store, &client_id).await;
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

	match registration.token_endpoint_auth_method.as_str() {
		"none" => {
			// Public client: no secret required
		},
		_ => {
			// Confidential client: secret required
			let secret = match &client_secret {
				Some(s) => s,
				None => {
					warn!(client_id = %client_id, audit_event = "token_rejected_missing_secret", "token exchange rejected: client_secret required");
					return build_error_response(
						StatusCode::UNAUTHORIZED,
						"invalid_client",
						"client_secret is required for this client's token_endpoint_auth_method",
					);
				},
			};
			if !constant_time_eq(registration.client_secret.as_bytes(), secret.as_bytes()) {
				warn!(client_id = %client_id, audit_event = "token_rejected_bad_secret", "token exchange rejected: client authentication failed");
				return build_error_response(
					StatusCode::UNAUTHORIZED,
					"invalid_client",
					"client authentication failed",
				);
			}
		},
	}

	let grant_type = required_form_param(&form_params, "grant_type")?;
	match grant_type.as_str() {
		"authorization_code" => {
			let proxy_code = required_form_param(&form_params, "code")?;
			let redirect_uri = required_form_param(&form_params, "redirect_uri")?;
			let code_verifier = required_form_param(&form_params, "code_verifier")?;

			let auth_code = store
				.take_auth_code(&proxy_code)
				.await?
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
		},
		"refresh_token" => {
			let refresh_token = required_form_param(&form_params, "refresh_token")?;

			let idp_metadata = fetch_idp_metadata(auth, client.clone()).await?;

			let token_response = refresh_token_at_idp(
				client,
				&idp_metadata.token_endpoint,
				proxy_cfg,
				&refresh_token,
			)
			.await?;

			info!(
				client_id = %client_id,
				audit_event = "proxy_token_refreshed",
				"proxy token refresh completed; new tokens delivered to client"
			);

			let body = serde_json::to_vec(&token_response)
				.map_err(|e| ProxyError::ProcessingString(format!("failed to serialize tokens: {e}")))?;

			::http::Response::builder()
				.status(StatusCode::OK)
				.header(header::CONTENT_TYPE, "application/json")
				.header(header::CACHE_CONTROL, "no-store")
				.header(header::PRAGMA, "no-cache")
				.body(Body::from(Bytes::from(body)))
				.map_err(ProxyError::Http)
		},
		_ => {
			build_error_response(
				StatusCode::BAD_REQUEST,
				"unsupported_grant_type",
				"supported grant types: authorization_code, refresh_token",
			)
		},
	}
}

// rewrite_as_metadata is no longer needed — gateway AS metadata is built from scratch
// in build_gateway_as_metadata when oidc_proxy is configured.

async fn fetch_idp_metadata(
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<IdpMetadata, ProxyError> {
	let issuer = auth.issuer.trim_end_matches('/');
	let metadata_uri = match &auth.provider {
		Some(McpIDP::Keycloak { .. }) => openid_configuration_metadata_url(issuer),
		_ => authorization_server_metadata_url(issuer),
	};
	let ureq = ::http::Request::builder()
		.uri(&metadata_uri)
		.body(Body::empty())?;
	let upstream = client.simple_call(ureq).await?;
	let limit = crate::http::response_buffer_limit(&upstream);
	let raw: IdpMetadataRaw = from_body_with_limit(upstream.into_body(), limit)
		.await
		.map_err(ProxyError::Body)?;

	let authorization_endpoint = raw.authorization_endpoint.unwrap_or_else(|| {
		let fallback = match &auth.provider {
			Some(McpIDP::Okta { .. }) => format!("{issuer}/v1/authorize"),
			Some(McpIDP::Keycloak { .. }) => {
				format!("{issuer}/protocol/openid-connect/auth")
			},
			_ => format!("{issuer}/authorize"),
		};
		warn!(
			issuer = %issuer,
			fallback = %fallback,
			"IDP metadata missing authorization_endpoint; using issuer-derived fallback"
		);
		fallback
	});

	let token_endpoint = raw.token_endpoint.unwrap_or_else(|| {
		let fallback = match &auth.provider {
			Some(McpIDP::Okta { .. }) => format!("{issuer}/v1/token"),
			Some(McpIDP::Keycloak { .. }) => {
				format!("{issuer}/protocol/openid-connect/token")
			},
			_ => format!("{issuer}/token"),
		};
		warn!(
			issuer = %issuer,
			fallback = %fallback,
			"IDP metadata missing token_endpoint; using issuer-derived fallback"
		);
		fallback
	});

	Ok(IdpMetadata {
		authorization_endpoint,
		token_endpoint,
	})
}

async fn refresh_token_at_idp(
	client: PolicyClient,
	token_endpoint: &str,
	proxy_cfg: &OidcProxyConfig,
	refresh_token: &str,
) -> Result<serde_json::Value, ProxyError> {
	let form = [
		("grant_type", "refresh_token"),
		("refresh_token", refresh_token),
		("client_id", proxy_cfg.client_id.as_str()),
		("client_secret", proxy_cfg.client_secret.expose_secret()),
	];
	let body = serde_urlencoded::to_string(form)
		.map_err(|e| ProxyError::ProcessingString(format!("failed to encode refresh form: {e}")))?;

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
		.map_err(|e| {
			ProxyError::ProcessingString(format!("failed to read IDP refresh response: {e}"))
		})?;

	if !status.is_success() {
		let error_body = String::from_utf8_lossy(&body);
		debug!(status = %status, body = %error_body, "IDP token refresh failed");
		return Err(ProxyError::ProcessingString(format!(
			"IDP token endpoint returned {status}"
		)));
	}

	serde_json::from_slice(&body).map_err(|e| {
		ProxyError::ProcessingString(format!("failed to parse IDP refresh response: {e}"))
	})
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
		.map_err(|e| {
			ProxyError::ProcessingString(format!("failed to read IDP token response: {e}"))
		})?;

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
) -> Result<(String, Option<String>), ProxyError> {
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
				return Ok((id, Some(secret)));
			}
		}
	}

	let client_id = form_params
		.get("client_id")
		.ok_or_else(|| ProxyError::ProcessingString("missing client_id".into()))?
		.clone();
	let client_secret = form_params.get("client_secret").cloned();
	Ok((client_id, client_secret))
}

const CANONICAL_CALLBACK_PATH: &str = "/mcp/auth/callback";

fn derive_callback_url(req: &Request) -> String {
	let issuer = super::auth::derive_public_issuer_url(req);
	format!("{issuer}{CANONICAL_CALLBACK_PATH}")
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
	use crate::types::agent::RedisStorageConfig;

	#[test]
	fn redis_config_rejects_empty_url() {
		let cfg = RedisStorageConfig {
			url: "".into(),
			key_prefix: "agw:oidc:test".into(),
			transaction_ttl_seconds: 600,
			auth_code_ttl_seconds: 300,
			connect_timeout_ms: 5000,
			command_timeout_ms: 2000,
		};
		let err = cfg.validate().unwrap_err();
		assert!(err.to_string().contains("url"), "{err}");
	}

	#[test]
	fn redis_config_rejects_empty_prefix() {
		let cfg = RedisStorageConfig {
			url: "redis://localhost:6379".into(),
			key_prefix: "".into(),
			transaction_ttl_seconds: 600,
			auth_code_ttl_seconds: 300,
			connect_timeout_ms: 5000,
			command_timeout_ms: 2000,
		};
		let err = cfg.validate().unwrap_err();
		assert!(err.to_string().contains("keyPrefix"), "{err}");
	}

	#[test]
	fn redis_config_rejects_zero_ttl() {
		let cfg = RedisStorageConfig {
			url: "redis://localhost:6379".into(),
			key_prefix: "agw:oidc:test".into(),
			transaction_ttl_seconds: 0,
			auth_code_ttl_seconds: 300,
			connect_timeout_ms: 5000,
			command_timeout_ms: 2000,
		};
		let err = cfg.validate().unwrap_err();
		assert!(err.to_string().contains("transactionTtlSeconds"), "{err}");
	}

	#[test]
	fn redis_config_accepts_valid_values() {
		let cfg = RedisStorageConfig {
			url: "redis://localhost:6379".into(),
			key_prefix: "agw:oidc:local".into(),
			transaction_ttl_seconds: 600,
			auth_code_ttl_seconds: 300,
			connect_timeout_ms: 5000,
			command_timeout_ms: 2000,
		};
		cfg.validate().expect("valid config should pass");
	}

	#[tokio::test]
	async fn connect_fails_on_unreachable_redis() {
		let cfg = RedisStorageConfig {
			url: "redis://127.0.0.1:1".into(),
			key_prefix: "agw:oidc:test".into(),
			transaction_ttl_seconds: 600,
			auth_code_ttl_seconds: 300,
			connect_timeout_ms: 500,
			command_timeout_ms: 200,
		};
		let err = RedisProxyStore::connect(&cfg).await.unwrap_err();
		let msg = err.to_string();
		assert!(
			msg.contains("timeout") || msg.contains("connection") || msg.contains("Connection refused"),
			"should fail with connection error: {msg}"
		);
	}

	#[test]
	fn idp_metadata_parses_with_all_fields() {
		let json = r#"{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token"}"#;
		let raw: IdpMetadataRaw = serde_json::from_str(json).expect("parse");
		assert_eq!(raw.authorization_endpoint.as_deref(), Some("https://idp.example/authorize"));
		assert_eq!(raw.token_endpoint.as_deref(), Some("https://idp.example/token"));
	}

	#[test]
	fn idp_metadata_parses_with_missing_endpoints() {
		let json = r#"{"issuer":"https://idp.example"}"#;
		let raw: IdpMetadataRaw = serde_json::from_str(json).expect("parse");
		assert!(raw.authorization_endpoint.is_none());
		assert!(raw.token_endpoint.is_none());
	}

	#[test]
	fn idp_metadata_parses_empty_object() {
		let json = r#"{}"#;
		let raw: IdpMetadataRaw = serde_json::from_str(json).expect("parse");
		assert!(raw.authorization_endpoint.is_none());
		assert!(raw.token_endpoint.is_none());
	}

	#[test]
	fn key_format_matches_spec() {
		let prefix = "agw:oidc:local";
		assert_eq!(format!("{prefix}:txn:abc"), "agw:oidc:local:txn:abc");
		assert_eq!(format!("{prefix}:code:xyz"), "agw:oidc:local:code:xyz");
		assert_eq!(
			format!("{prefix}:idx:client:c1:txn"),
			"agw:oidc:local:idx:client:c1:txn"
		);
		assert_eq!(
			format!("{prefix}:idx:client:c1:code"),
			"agw:oidc:local:idx:client:c1:code"
		);
	}

	#[test]
	fn callback_url_is_always_canonical_path() {
		let req = ::http::Request::builder()
			.uri("https://gw.example/mcp/authorize?foo=bar")
			.header("host", "gw.example")
			.body(crate::http::Body::empty())
			.unwrap();
		let url = derive_callback_url(&req);
		assert_eq!(url, "https://gw.example/mcp/auth/callback");
	}

	#[test]
	fn callback_url_from_well_known_path_is_canonical() {
		let req = ::http::Request::builder()
			.uri("https://gw.example/.well-known/oauth-authorization-server/authorize")
			.header("host", "gw.example")
			.body(crate::http::Body::empty())
			.unwrap();
		let url = derive_callback_url(&req);
		assert_eq!(url, "https://gw.example/mcp/auth/callback");
		assert!(!url.contains(".well-known"), "callback must not use well-known path");
	}

	#[test]
	fn callback_url_respects_forwarded_proto() {
		let req = ::http::Request::builder()
			.uri("http://gw.fly.dev/mcp/authorize")
			.header("host", "gw.fly.dev")
			.header("x-forwarded-proto", "https")
			.body(crate::http::Body::empty())
			.unwrap();
		let url = derive_callback_url(&req);
		assert_eq!(url, "https://gw.fly.dev/mcp/auth/callback");
	}

	#[test]
	fn callback_url_never_contains_legacy_mcp_callback() {
		for path in ["/mcp/authorize", "/.well-known/oauth-authorization-server/authorize", "/x/y/authorize"] {
			let req = ::http::Request::builder()
				.uri(format!("https://gw.example{path}"))
				.header("host", "gw.example")
				.body(crate::http::Body::empty())
				.unwrap();
			let url = derive_callback_url(&req);
			assert!(!url.ends_with("/mcp/callback"), "must not use /mcp/callback: {url}");
			assert!(url.ends_with("/mcp/auth/callback"), "must use canonical path: {url}");
		}
	}

	#[test]
	fn extract_credentials_returns_none_secret_when_absent() {
		let req = ::http::Request::builder()
			.uri("https://gw.example/token")
			.body(crate::http::Body::empty())
			.unwrap();
		let mut params = HashMap::new();
		params.insert("client_id".into(), "cid".into());
		let (id, secret) = extract_client_credentials(&req, &params).unwrap();
		assert_eq!(id, "cid");
		assert!(secret.is_none(), "secret must be None when absent");
	}

	#[test]
	fn extract_credentials_returns_some_secret_when_present() {
		let req = ::http::Request::builder()
			.uri("https://gw.example/token")
			.body(crate::http::Body::empty())
			.unwrap();
		let mut params = HashMap::new();
		params.insert("client_id".into(), "cid".into());
		params.insert("client_secret".into(), "sec".into());
		let (id, secret) = extract_client_credentials(&req, &params).unwrap();
		assert_eq!(id, "cid");
		assert_eq!(secret.as_deref(), Some("sec"));
	}

	#[test]
	fn extract_credentials_from_basic_auth_returns_some_secret() {
		let encoded = base64::engine::general_purpose::STANDARD.encode("cid:sec");
		let req = ::http::Request::builder()
			.uri("https://gw.example/token")
			.header("authorization", format!("Basic {encoded}"))
			.body(crate::http::Body::empty())
			.unwrap();
		let params = HashMap::new();
		let (id, secret) = extract_client_credentials(&req, &params).unwrap();
		assert_eq!(id, "cid");
		assert_eq!(secret.as_deref(), Some("sec"));
	}
}
