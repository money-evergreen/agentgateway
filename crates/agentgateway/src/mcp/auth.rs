use axum::http::StatusCode;
use axum::response::Response;
use axum_core::response::IntoResponse;
use bytes::Bytes;
use http::Method;
use http::uri::PathAndQuery;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use tracing::{debug, info, warn};

use crate::http::jwt::Claims;
use crate::http::oauth::{authorization_server_metadata_url, openid_configuration_metadata_url};
use crate::http::*;
use crate::json;
use crate::json::from_body_with_limit;
use crate::mcp::oidc_proxy::RedisProxyStore;
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{McpAuthentication, McpIDP};


/// RFC 7591 Dynamic Client Registration request.
/// All standard metadata fields are accepted. Unknown extension fields are
/// captured in `extensions` so they never cause deserialization failures.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct LocalClientRegistrationRequest {
	redirect_uris: Vec<String>,
	#[serde(default)]
	client_name: Option<String>,
	#[serde(default)]
	token_endpoint_auth_method: Option<String>,
	#[serde(default)]
	grant_types: Option<Vec<String>>,
	#[serde(default)]
	response_types: Option<Vec<String>>,
	#[serde(default)]
	scope: Option<String>,
	#[serde(default)]
	client_uri: Option<String>,
	#[serde(default)]
	logo_uri: Option<String>,
	#[serde(default)]
	contacts: Option<Vec<String>>,
	#[serde(default)]
	tos_uri: Option<String>,
	#[serde(default)]
	policy_uri: Option<String>,
	#[serde(default)]
	jwks_uri: Option<String>,
	#[serde(default)]
	jwks: Option<serde_json::Value>,
	#[serde(default)]
	software_id: Option<String>,
	#[serde(default)]
	software_version: Option<String>,
	#[serde(flatten)]
	extensions: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(super) struct LocalClientRegistrationRecord {
	pub(super) client_id: String,
	pub(super) client_secret: String,
	pub(super) active: bool,
	pub(super) redirect_uris: Vec<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	client_name: Option<String>,
	pub(super) token_endpoint_auth_method: String,
	grant_types: Vec<String>,
	response_types: Vec<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	scope: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	client_uri: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	logo_uri: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	contacts: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	tos_uri: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	policy_uri: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	jwks_uri: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	software_id: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	software_version: Option<String>,
}

fn dcr_client_key(prefix: &str, client_id: &str) -> String {
	format!("{prefix}:dcr:client:{client_id}")
}

fn dcr_clients_set_key(prefix: &str) -> String {
	format!("{prefix}:dcr:clients")
}

async fn dcr_get(store: &RedisProxyStore, client_id: &str) -> Option<LocalClientRegistrationRecord> {
	let key = dcr_client_key(store.key_prefix(), client_id);
	let mut conn = store.conn();
	let value: Option<String> = conn.get(&key).await.ok()?;
	value.and_then(|json| serde_json::from_str(&json).ok())
}

async fn dcr_set(store: &RedisProxyStore, record: &LocalClientRegistrationRecord) -> Result<(), String> {
	let key = dcr_client_key(store.key_prefix(), &record.client_id);
	let idx_key = dcr_clients_set_key(store.key_prefix());
	let value = serde_json::to_string(record)
		.map_err(|e| format!("serialize DCR record: {e}"))?;
	let mut conn = store.conn();
	redis::pipe()
		.atomic()
		.cmd("SET").arg(&key).arg(&value)
		.cmd("SADD").arg(&idx_key).arg(&record.client_id)
		.exec_async(&mut conn)
		.await
		.map_err(|e| format!("Redis DCR set: {e}"))?;
	Ok(())
}

fn is_loopback_host(host: Option<&str>) -> bool {
	matches!(
		host,
		Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
	)
}

impl LocalClientRegistrationRequest {
	fn validate_and_normalize(mut self) -> Result<Self, String> {
		if self.redirect_uris.is_empty() {
			return Err("redirect_uris must contain at least one URI".into());
		}
		let mut normalized_redirects = BTreeSet::new();
		for uri in self.redirect_uris {
			let parsed = url::Url::parse(&uri)
				.map_err(|e| format!("redirect_uris must be absolute URLs: {e}"))?;
			let scheme = parsed.scheme();
			if scheme.is_empty() {
				return Err("redirect_uris must have a non-empty scheme".into());
			}
			if scheme == "http" && !is_loopback_host(parsed.host_str()) {
				return Err(format!(
					"http redirect_uris are only allowed for loopback addresses \
					 (localhost, 127.0.0.1, [::1]); got host '{}'",
					parsed.host_str().unwrap_or("<none>")
				));
			}
			normalized_redirects.insert(parsed.to_string());
		}
		self.redirect_uris = normalized_redirects.into_iter().collect();

		let auth_method = self
			.token_endpoint_auth_method
			.clone()
			.unwrap_or_else(|| "none".into());
		if !matches!(
			auth_method.as_str(),
			"client_secret_basic" | "client_secret_post" | "none"
		) {
			return Err(
				"token_endpoint_auth_method must be one of: client_secret_basic, client_secret_post, none"
					.into(),
			);
		}
		self.token_endpoint_auth_method = Some(auth_method);

		let mut grant_types = self
			.grant_types
			.take()
			.unwrap_or_else(|| vec!["authorization_code".into()]);
		grant_types.sort();
		grant_types.dedup();
		if grant_types.is_empty()
			|| !grant_types
				.iter()
				.all(|grant| matches!(grant.as_str(), "authorization_code" | "refresh_token"))
		{
			return Err(
				"grant_types must include supported values only: authorization_code, refresh_token"
					.into(),
			);
		}
		self.grant_types = Some(grant_types);

		let mut response_types = self
			.response_types
			.take()
			.unwrap_or_else(|| vec!["code".into()]);
		response_types.sort();
		response_types.dedup();
		if response_types != vec!["code".to_string()] {
			return Err("response_types must be exactly ['code']".into());
		}
		self.response_types = Some(response_types);

		if let Some(scope) = self.scope.as_mut() {
			*scope = scope.trim().to_string();
			if scope.is_empty() {
				self.scope = None;
			}
		}

		Ok(self)
	}

	fn deterministic_client_id(&self, issuer: &str) -> Result<String, String> {
		let canonical = serde_json::to_vec(&(issuer, self))
			.map_err(|e| format!("failed to canonicalize registration request: {e}"))?;
		let mut hasher = Sha256::new();
		hasher.update(canonical);
		let digest = hasher.finalize();
		let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
		Ok(format!("agw_{}", &digest_hex[..24]))
	}
}

fn build_new_record(
	issuer: &str,
	request: LocalClientRegistrationRequest,
) -> Result<LocalClientRegistrationRecord, String> {
	let request = request.validate_and_normalize()?;
	let client_id = request.deterministic_client_id(issuer)?;

	let mut hasher = Sha256::new();
	hasher.update(client_id.as_bytes());
	hasher.update(b":secret");
	let digest = hasher.finalize();
	let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
	let client_secret = format!("agw_secret_{}", &digest_hex[..32]);

	Ok(LocalClientRegistrationRecord {
		client_id,
		client_secret,
		active: true,
		redirect_uris: request.redirect_uris,
		client_name: request.client_name,
		token_endpoint_auth_method: request
			.token_endpoint_auth_method
			.unwrap_or_else(|| "none".into()),
		grant_types: request
			.grant_types
			.unwrap_or_else(|| vec!["authorization_code".into()]),
		response_types: request.response_types.unwrap_or_else(|| vec!["code".into()]),
		scope: request.scope,
		client_uri: request.client_uri,
		logo_uri: request.logo_uri,
		contacts: request.contacts,
		tos_uri: request.tos_uri,
		policy_uri: request.policy_uri,
		jwks_uri: request.jwks_uri,
		software_id: request.software_id,
		software_version: request.software_version,
	})
}

fn apply_update(
	existing: &mut LocalClientRegistrationRecord,
	request: LocalClientRegistrationRequest,
) -> Result<(), String> {
	let normalized = request.validate_and_normalize()?;
	if !existing.active {
		return Err("client registration is deactivated".into());
	}
	existing.redirect_uris = normalized.redirect_uris;
	existing.client_name = normalized.client_name;
	existing.token_endpoint_auth_method = normalized
		.token_endpoint_auth_method
		.unwrap_or_else(|| "none".into());
	existing.grant_types = normalized
		.grant_types
		.unwrap_or_else(|| vec!["authorization_code".into()]);
	existing.response_types = normalized.response_types.unwrap_or_else(|| vec!["code".into()]);
	existing.scope = normalized.scope;
	existing.client_uri = normalized.client_uri;
	existing.logo_uri = normalized.logo_uri;
	existing.contacts = normalized.contacts;
	existing.tos_uri = normalized.tos_uri;
	existing.policy_uri = normalized.policy_uri;
	existing.jwks_uri = normalized.jwks_uri;
	existing.software_id = normalized.software_id;
	existing.software_version = normalized.software_version;
	Ok(())
}

async fn dcr_register(
	store: &RedisProxyStore,
	issuer: &str,
	request: LocalClientRegistrationRequest,
) -> Result<(LocalClientRegistrationRecord, bool), String> {
	let record = build_new_record(issuer, request)?;
	if let Some(existing) = dcr_get(store, &record.client_id).await {
		if !existing.active {
			return Err("client registration exists but is deactivated".into());
		}
		return Ok((existing, false));
	}
	dcr_set(store, &record).await?;
	Ok((record, true))
}

async fn dcr_update(
	store: &RedisProxyStore,
	client_id: &str,
	request: LocalClientRegistrationRequest,
) -> Result<LocalClientRegistrationRecord, String> {
	let mut existing = dcr_get(store, client_id)
		.await
		.ok_or_else(|| "unknown client_id".to_string())?;
	apply_update(&mut existing, request)?;
	dcr_set(store, &existing).await?;
	Ok(existing)
}

async fn dcr_deactivate(
	store: &RedisProxyStore,
	client_id: &str,
) -> Result<LocalClientRegistrationRecord, String> {
	let mut existing = dcr_get(store, client_id)
		.await
		.ok_or_else(|| "unknown client_id".to_string())?;
	if !existing.active {
		return Err("client registration is already deactivated".into());
	}
	existing.active = false;
	dcr_set(store, &existing).await?;
	Ok(existing)
}

pub(super) async fn get_registered_client(
	store: &RedisProxyStore,
	client_id: &str,
) -> Option<LocalClientRegistrationRecord> {
	dcr_get(store, client_id).await
}

fn get_dcr_store(auth: &McpAuthentication) -> Result<&RedisProxyStore, ProxyError> {
	auth.oidc_proxy
		.as_ref()
		.map(|p| p.store.as_ref())
		.ok_or_else(|| {
			ProxyError::ProcessingString("DCR requires oidcProxy with Redis storage".into())
		})
}

pub(crate) fn is_well_known_endpoint(path: &str) -> bool {
	path.starts_with("/.well-known/oauth-protected-resource")
		|| path.starts_with("/.well-known/oauth-authorization-server")
}

/// Returns true for paths that are part of the OAuth bootstrap flow and must be
/// accessible without a pre-existing bearer JWT. This includes well-known discovery
/// endpoints AND OAuth flow entry points (registration, authorize, callback, token)
/// regardless of where they are mounted in the route tree.
///
/// Matching is intentionally broad: any path whose terminal or penultimate segment is an
/// OAuth flow keyword is exempt. This handles:
///   - `/.well-known/oauth-authorization-server/authorize`
///   - `/mcp/authorize`, `/mcp/authorize/`
///   - `/x/y/mcp/authorize?client_id=...`
///   - `/prefix/client-registration/some-client-id` (registration GET/DELETE)
pub(crate) fn is_oauth_bootstrap_path(path: &str) -> bool {
	if is_well_known_endpoint(path) {
		return true;
	}
	let normalized = path.trim_end_matches('/');
	if normalized.ends_with("/auth/callback") {
		return true;
	}
	for segment in normalized.rsplit('/').take(2) {
		if matches!(
			segment,
			"client-registration" | "register" | "authorize" | "token"
		) {
			return true;
		}
	}
	false
}

pub(super) async fn apply_token_validation(
	req: &mut Request,
	auth: &McpAuthentication,
) -> Result<(), ProxyError> {
	if is_oauth_bootstrap_path(req.uri().path()) {
		return Ok(());
	}
	let has_claims = req.extensions().get::<Claims>().is_some();

	if has_claims {
		// if mcp authn is configured but JWT already validated (claims exist from previous layer),
		// reject because we cannot validate MCP-specific auth requirements
		let err = ProxyError::ProcessingString(
			"MCP backend authentication configured but JWT token already validated and stripped by Gateway or Route level policy".to_string(),
		);
		return Err(create_auth_required_response(err, req, auth));
	}

	debug!(
		"MCP auth configured; validating Authorization header (mode={:?})",
		auth.mode
	);
	auth.jwt_validator.apply(None, req).await.map_err(|e| {
		create_auth_required_response(ProxyError::JwtAuthenticationFailure(e), req, auth)
	})?;
	Ok(())
}

pub(crate) async fn enforce_authentication(
	req: &mut Request,
	auth: &McpAuthentication,
	client: &PolicyClient,
) -> Result<Option<Response>, ProxyError> {
	let path = req.uri().path();
	let exempt = is_oauth_bootstrap_path(path);
	debug!(
		path = %path,
		bootstrap_exempt = exempt,
		"MCP auth: evaluating request"
	);
	if !exempt {
		apply_token_validation(req, auth).await?;
	}

	handle_mcp_request(req, auth, client).await
}

/// Handle OAuth bootstrap paths when no MCP authentication is configured.
/// Returns error responses for OAuth-specific paths; returns None for regular
/// MCP requests to let them through to the handler normally.
pub(crate) async fn handle_mcp_request_unauthenticated(
	req: &mut Request,
) -> Result<Option<Response>, ProxyError> {
	let path = req.uri().path().to_string();

	if is_oauth_bootstrap_path(&path) {
		return Ok(Some(build_json_response(
			StatusCode::BAD_REQUEST,
			serde_json::json!({
				"error": "invalid_request",
				"error_description": "OAuth/registration requires mcpAuthentication configuration"
			}),
		)?.into_response()));
	}

	Ok(None)
}

pub(crate) async fn handle_mcp_request(
	req: &mut Request,
	auth: &McpAuthentication,
	client: &PolicyClient,
) -> Result<Option<Response>, ProxyError> {
	let _ = client;
	let path = req.uri().path().to_string();
	let tail = path.rsplit('/').next().unwrap_or("");

	match path.as_str() {
		p if p.contains("/client-registration") || tail == "client-registration" || tail == "register" => Ok(Some(
			client_registration(req, auth, client.clone())
				.await
				.map_err(|e| {
					warn!("client_registration error: {}", e);
					StatusCode::INTERNAL_SERVER_ERROR
				})
				.into_response(),
		)),
		p if p.starts_with("/.well-known/oauth-protected-resource") => Ok(Some(
			protected_resource_metadata(req, auth).await.into_response(),
		)),
		p if (p.starts_with("/.well-known/oauth-authorization-server") && p.ends_with("/authorize"))
			|| tail == "authorize" =>
		{
			Ok(Some(
				super::oidc_proxy::proxy_authorize(req, auth, client.clone())
					.await
					.map_err(|e| {
						warn!("oidc proxy authorize error: {}", e);
						StatusCode::INTERNAL_SERVER_ERROR
					})
					.into_response(),
			))
		},
		p if p.ends_with("/auth/callback") =>
		{
			Ok(Some(
				super::oidc_proxy::proxy_callback(req, auth, client.clone())
					.await
					.map_err(|e| {
						warn!("oidc proxy callback error: {}", e);
						StatusCode::INTERNAL_SERVER_ERROR
					})
					.into_response(),
			))
		},
		p if (p.starts_with("/.well-known/oauth-authorization-server") && p.ends_with("/token"))
			|| tail == "token" =>
		{
			Ok(Some(
				super::oidc_proxy::proxy_token(req, auth, client.clone())
					.await
					.map_err(|e| {
						warn!("oidc proxy token error: {}", e);
						StatusCode::INTERNAL_SERVER_ERROR
					})
					.into_response(),
			))
		},
		p if p.starts_with("/.well-known/oauth-authorization-server") => Ok(Some(
			authorization_server_metadata(req, auth, client.clone())
				.await
				.map_err(|e| {
					warn!("authorization_server_metadata error: {}", e);
					StatusCode::INTERNAL_SERVER_ERROR
				})
				.into_response(),
		)),
		_ => {
			// Not handled by OAuth/MCP auth layer
			Ok(None)
		},
	}
}

pub(crate) fn create_auth_required_response(
	inner: ProxyError,
	req: &Request,
	auth: &McpAuthentication,
) -> ProxyError {
	let request_path = req.uri().path();
	// If the `resource` is explicitly configured, use that as the base. otherwise, derive it from the
	// the request URL
	let proxy_url = auth
		.resource_metadata
		.extra
		.get("resource")
		.and_then(|v| v.as_str())
		.and_then(|u| http::uri::Uri::try_from(u).ok())
		.and_then(|uri| {
			let mut parts = uri.into_parts();
			parts.path_and_query = Some(PathAndQuery::from_static(""));
			Uri::from_parts(parts).ok()
		})
		.and_then(|uri| uri.to_string().strip_suffix("/").map(ToString::to_string))
		.unwrap_or_else(|| get_redirect_url(req, request_path));
	let www_authenticate_value = format!(
		"Bearer resource_metadata=\"{proxy_url}/.well-known/oauth-protected-resource{request_path}\""
	);

	ProxyError::McpJwtAuthenticationFailure(Box::new(inner), www_authenticate_value)
}

pub(super) async fn protected_resource_metadata(
	req: &mut Request,
	auth: &McpAuthentication,
) -> Response {
	let new_uri = strip_oauth_protected_resource_prefix_public(req);

	let issuer = if auth.oidc_proxy.is_some() {
		derive_public_base_url_for_as(req)
	} else if auth.provider.is_some() {
		strip_oauth_protected_resource_prefix_public(req)
	} else {
		auth.issuer.clone()
	};

	let json_body = auth.resource_metadata.to_rfc_json(new_uri, issuer);

	::http::Response::builder()
		.status(StatusCode::OK)
		.header("content-type", "application/json")
		.header("access-control-allow-origin", "*")
		.header("access-control-allow-methods", "GET, OPTIONS")
		.header("access-control-allow-headers", "content-type")
		.body(axum::body::Body::from(Bytes::from(
			serde_json::to_string(&json_body).unwrap_or_default(),
		)))
		.unwrap_or_else(|_| {
			::http::Response::builder()
				.status(StatusCode::INTERNAL_SERVER_ERROR)
				.body(axum::body::Body::empty())
				.unwrap()
		})
}

fn get_redirect_url(req: &Request, strip_base: &str) -> String {
	let uri = req
		.extensions()
		.get::<filters::OriginalUrl>()
		.map(|u| u.0.clone())
		.unwrap_or_else(|| req.uri().clone());

	uri
		.path()
		.strip_suffix(strip_base)
		.map(|p| uri.to_string().replace(uri.path(), p))
		.unwrap_or(uri.to_string())
}

fn strip_oauth_protected_resource_prefix_public(req: &Request) -> String {
	let full = derive_public_base_url(req);
	const OAUTH_PREFIX: &str = "/.well-known/oauth-protected-resource";

	let uri = req
		.extensions()
		.get::<filters::OriginalUrl>()
		.map(|u| u.0.clone())
		.unwrap_or_else(|| req.uri().clone());
	let path = uri.path();

	if let Some(remaining_path) = path.strip_prefix(OAUTH_PREFIX) {
		full.replace(path, remaining_path)
	} else {
		full
	}
}

/// Derive the issuer URL for the protected-resource `authorization_servers` field.
/// Per RFC 8414, the issuer is the base URL (scheme + host), not the well-known path.
fn derive_public_base_url_for_as(req: &Request) -> String {
	derive_public_issuer_url(req)
}

pub(super) async fn authorization_server_metadata(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	let resp = if auth.oidc_proxy.is_some() {
		build_gateway_as_metadata(req, auth)
	} else {
		build_proxied_as_metadata(req, auth, client).await?
	};

	let response = ::http::Response::builder()
		.status(StatusCode::OK)
		.header("content-type", "application/json")
		.header("access-control-allow-origin", "*")
		.header("access-control-allow-methods", "GET, OPTIONS")
		.header("access-control-allow-headers", "content-type")
		.body(axum::body::Body::from(Bytes::from(
			serde_json::to_string(&resp).map_err(|e| ProxyError::Body(crate::http::Error::new(e)))?,
		)))?;

	Ok(response)
}

/// Build a clean RFC 8414 AS metadata document for the gateway itself.
/// No upstream IDP fields are merged — the gateway IS the authorization server.
fn build_gateway_as_metadata(
	req: &Request,
	auth: &McpAuthentication,
) -> serde_json::Value {
	let issuer = derive_public_issuer_url(req);
	let endpoint_base = derive_public_base_url(req);

	let mut scopes: Vec<String> = vec!["openid".into(), "profile".into(), "offline_access".into()];
	if let Some(serde_json::Value::Array(configured)) = auth.resource_metadata.extra.get("scopesSupported") {
		for s in configured {
			if let Some(scope_str) = s.as_str()
				&& !scopes.iter().any(|existing| existing == scope_str)
			{
				scopes.push(scope_str.to_string());
			}
		}
	}

	serde_json::json!({
		"issuer": issuer,
		"authorization_endpoint": format!("{endpoint_base}/authorize"),
		"token_endpoint": format!("{endpoint_base}/token"),
		"registration_endpoint": format!("{endpoint_base}/client-registration"),
		"code_challenge_methods_supported": ["S256"],
		"grant_types_supported": ["authorization_code", "refresh_token"],
		"response_types_supported": ["code"],
		"token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
		"scopes_supported": scopes,
		"jwks_uri": format!("{}/.well-known/jwks.json", auth.issuer.trim_end_matches('/')),
	})
}

/// Build AS metadata by proxying the upstream IDP's metadata and adapting fields.
async fn build_proxied_as_metadata(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<serde_json::Value, ProxyError> {
	let metadata_uri = match &auth.provider {
		Some(McpIDP::Keycloak { .. }) => openid_configuration_metadata_url(&auth.issuer),
		_ => authorization_server_metadata_url(&auth.issuer),
	};
	let ureq = ::http::Request::builder()
		.uri(metadata_uri)
		.body(Body::empty())?;
	let upstream = client.simple_call(ureq).await?;
	let limit = crate::http::response_buffer_limit(&upstream);
	let mut resp: serde_json::Value = from_body_with_limit(upstream.into_body(), limit)
		.await
		.map_err(ProxyError::Body)?;

	match &auth.provider {
		Some(McpIDP::Auth0 {}) | Some(McpIDP::Okta {}) => {
			if let Some(serde_json::Value::String(ae)) =
				json::traverse_mut(&mut resp, &["authorization_endpoint"])
			{
				if let Some(aud) = auth.audiences.first() {
					ae.push_str(&format!("?audience={}", aud));
				}
			} else {
				return Err(ProxyError::ProcessingString(
					"authorization_endpoint missing from IDP metadata".to_string(),
				));
			}
		},
		Some(McpIDP::Keycloak { .. }) => {
			let current_uri = req
				.extensions()
				.get::<filters::OriginalUrl>()
				.map(|u| u.0.clone())
				.unwrap_or_else(|| req.uri().clone());
			let Some(serde_json::Value::String(re)) =
				json::traverse_mut(&mut resp, &["registration_endpoint"])
			else {
				return Err(ProxyError::ProcessingString(
					"registration_endpoint missing".to_string(),
				));
			};
			*re = format!("{current_uri}/client-registration");
		},
		_ => {},
	}

	Ok(resp)
}

/// Derive the public-facing base URL from the request, respecting reverse-proxy
/// headers (X-Forwarded-Proto, X-Forwarded-Host, Forwarded) so that metadata
/// endpoints advertise HTTPS URLs when served behind TLS termination (e.g. Fly.io).
/// Derive the public-facing issuer base URL: `{scheme}://{host}` with NO path.
/// This is the RFC 8414 `issuer` value that clients use as the base for
/// constructing well-known and endpoint URLs.
pub(crate) fn derive_public_issuer_url(req: &Request) -> String {
	let (scheme, host) = derive_scheme_and_host(req);
	format!("{scheme}://{host}")
}

/// Derive the public-facing URL for the current request path.
/// Used for endpoint URLs that include the full well-known path prefix.
pub(crate) fn derive_public_base_url(req: &Request) -> String {
	let uri = req
		.extensions()
		.get::<filters::OriginalUrl>()
		.map(|u| u.0.clone())
		.unwrap_or_else(|| req.uri().clone());
	let (scheme, host) = derive_scheme_and_host(req);
	let path = uri.path();
	format!("{scheme}://{host}{path}")
}

fn derive_scheme_and_host(req: &Request) -> (String, String) {
	let uri = req
		.extensions()
		.get::<filters::OriginalUrl>()
		.map(|u| u.0.clone())
		.unwrap_or_else(|| req.uri().clone());

	let scheme = req
		.headers()
		.get("x-forwarded-proto")
		.and_then(|v| v.to_str().ok())
		.map(|s| s.to_string())
		.unwrap_or_else(|| uri.scheme_str().unwrap_or("http").to_string());

	let mut host = req
		.headers()
		.get("x-forwarded-host")
		.and_then(|v| v.to_str().ok())
		.or_else(|| req.headers().get("host").and_then(|v| v.to_str().ok()))
		.unwrap_or_else(|| uri.host().unwrap_or("localhost"))
		.to_string();

	if !host.contains(':') {
		let is_default_port = |s: &str, p: u16| {
			(s == "https" && p == 443) || (s == "http" && p == 80)
		};
		if let Some(port) = uri.port_u16()
			&& !is_default_port(&scheme, port)
		{
			host = format!("{host}:{port}");
		}
	}

	(scheme, host)
}

pub(super) async fn client_registration(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	let _ = client;
	let store = get_dcr_store(auth)?;
	let path = req.uri().path().to_string();
	let Some((_, suffix)) = path.split_once("/client-registration") else {
		return build_json_response(
			StatusCode::NOT_FOUND,
			serde_json::json!({ "error": "registration path not found" }),
		);
	};
	let client_id = suffix.trim_start_matches('/').trim();
	let body: serde_json::Value = from_body_with_limit(
		std::mem::take(req.body_mut()),
		crate::defaults::max_buffer_size(),
	)
	.await
	.map_err(ProxyError::Body)?;
	let method = req.method().clone();

	match method {
		Method::POST => {
			let request: LocalClientRegistrationRequest = match serde_json::from_value(body) {
				Ok(r) => r,
				Err(e) => {
					return build_json_response(
						StatusCode::BAD_REQUEST,
						serde_json::json!({
							"error": "invalid_client_metadata",
							"error_description": format!("invalid registration payload: {e}")
						}),
					);
				},
			};
			let (record, created) = match dcr_register(store, &auth.issuer, request).await {
				Ok(result) => result,
				Err(e) => {
					return build_json_response(
						StatusCode::BAD_REQUEST,
						serde_json::json!({
							"error": "invalid_client_metadata",
							"error_description": e
						}),
					);
				},
			};
			let status = if created {
				info!(
					client_id = %record.client_id,
					audit_event = "client_registered",
					"new MCP client registration created (Redis-backed)"
				);
				StatusCode::CREATED
			} else {
				debug!(
					client_id = %record.client_id,
					audit_event = "client_registration_idempotent",
					"MCP client registration already exists"
				);
				StatusCode::OK
			};
			build_json_response(status, serde_json::to_value(record).unwrap_or_default())
		},
		Method::GET => {
			if client_id.is_empty() {
				return build_json_response(
					StatusCode::BAD_REQUEST,
					serde_json::json!({ "error": "client_id path segment is required for GET" }),
				);
			}
			match dcr_get(store, client_id).await {
				Some(record) if record.active => {
					build_json_response(StatusCode::OK, serde_json::to_value(record).unwrap_or_default())
				},
				Some(_) => build_json_response(
					StatusCode::GONE,
					serde_json::json!({ "error": "client registration is deactivated" }),
				),
				None => build_json_response(
					StatusCode::NOT_FOUND,
					serde_json::json!({ "error": "client registration not found" }),
				),
			}
		},
		Method::PUT | Method::PATCH => {
			if client_id.is_empty() {
				return build_json_response(
					StatusCode::BAD_REQUEST,
					serde_json::json!({ "error": "client_id path segment is required for update" }),
				);
			}
			let request: LocalClientRegistrationRequest = match serde_json::from_value(body) {
				Ok(r) => r,
				Err(e) => {
					return build_json_response(
						StatusCode::BAD_REQUEST,
						serde_json::json!({
							"error": "invalid_client_metadata",
							"error_description": format!("invalid registration payload: {e}")
						}),
					);
				},
			};
			let updated = match dcr_update(store, client_id, request).await {
				Ok(result) => result,
				Err(e) => {
					return build_json_response(
						StatusCode::BAD_REQUEST,
						serde_json::json!({
							"error": "invalid_client_metadata",
							"error_description": e
						}),
					);
				},
			};
			info!(
				client_id = %updated.client_id,
				audit_event = "client_updated",
				"MCP client registration updated"
			);
			build_json_response(StatusCode::OK, serde_json::to_value(updated).unwrap_or_default())
		},
		Method::DELETE => {
			if client_id.is_empty() {
				return build_json_response(
					StatusCode::BAD_REQUEST,
					serde_json::json!({ "error": "client_id path segment is required for delete" }),
				);
			}
			let deactivated = match dcr_deactivate(store, client_id).await {
				Ok(r) => r,
				Err(e) => return Err(ProxyError::ProcessingString(e)),
			};
			let revoked = super::oidc_proxy::revoke_client(store, &deactivated.client_id).await;
			info!(
				client_id = %deactivated.client_id,
				transactions_revoked = revoked.0,
				auth_codes_revoked = revoked.1,
				audit_event = "client_deactivated",
				"MCP client deactivated; pending auth state purged"
			);
			build_json_response(
				StatusCode::OK,
				serde_json::json!({
					"client_id": deactivated.client_id,
					"active": deactivated.active
				}),
			)
		},
		_ => build_json_response(
			StatusCode::METHOD_NOT_ALLOWED,
			serde_json::json!({ "error": "method not allowed for client-registration endpoint" }),
		),
	}
}

fn build_json_response(status: StatusCode, body: serde_json::Value) -> Result<Response, ProxyError> {
	::http::Response::builder()
		.status(status)
		.header("content-type", "application/json")
		.header("access-control-allow-origin", "*")
		.header("access-control-allow-methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		.header("access-control-allow-headers", "content-type")
		.body(axum::body::Body::from(Bytes::from(
			serde_json::to_vec(&body).map_err(|e| ProxyError::ProcessingString(e.to_string()))?,
		)))
		.map_err(ProxyError::Http)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sample_request() -> LocalClientRegistrationRequest {
		serde_json::from_value(serde_json::json!({
			"redirect_uris": ["https://app.example/callback"],
			"client_name": "my app",
			"token_endpoint_auth_method": "client_secret_basic",
			"grant_types": ["authorization_code"],
			"response_types": ["code"],
			"scope": "openid profile"
		}))
		.expect("sample request")
	}

	#[test]
	fn deterministic_registration_produces_same_id() {
		let issuer = "https://issuer.example";
		let first = build_new_record(issuer, sample_request()).expect("build");
		let second = build_new_record(issuer, sample_request()).expect("build");
		assert_eq!(first.client_id, second.client_id);
		assert_eq!(first.client_secret, second.client_secret);
	}

	#[test]
	fn update_lifecycle_is_enforced() {
		let issuer = "https://issuer.example";
		let mut record = build_new_record(issuer, sample_request()).expect("build");

		let update_request: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["https://updated.example/callback"],
			"client_name": "updated",
			"token_endpoint_auth_method": "client_secret_post",
			"grant_types": ["authorization_code", "refresh_token"],
			"response_types": ["code"],
			"scope": "openid email"
		}))
		.expect("parse update");
		apply_update(&mut record, update_request).expect("update");
		assert_eq!(record.client_name.as_deref(), Some("updated"));
		assert_eq!(record.token_endpoint_auth_method, "client_secret_post");

		record.active = false;
		assert!(apply_update(&mut record, sample_request()).is_err());
	}

	#[test]
	fn deactivated_client_blocks_update() {
		let issuer = "https://issuer.example";
		let mut record = build_new_record(issuer, sample_request()).expect("build");
		record.active = false;

		let err = apply_update(&mut record, sample_request())
			.expect_err("update after deactivation must fail");
		assert!(err.contains("deactivated"));
	}

	#[test]
	fn malformed_or_unsupported_metadata_is_rejected() {
		let request: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["not-a-uri"],
			"token_endpoint_auth_method": "private_key_jwt",
			"grant_types": ["client_credentials"],
			"response_types": ["token"]
		}))
		.expect("parse");
		let err = build_new_record("https://issuer.example", request)
			.expect_err("invalid metadata should fail");
		assert!(err.contains("redirect_uris") || err.contains("token_endpoint_auth_method"));
	}

	#[test]
	fn oauth_bootstrap_paths_are_exempt_from_jwt() {
		let exempt = [
			// Well-known discovery paths
			"/.well-known/oauth-authorization-server",
			"/.well-known/oauth-authorization-server/authorize",
			"/.well-known/oauth-authorization-server/token",
			"/.well-known/oauth-authorization-server/client-registration",
			"/.well-known/oauth-protected-resource/mcp",
			// Custom-mounted OAuth flow endpoints
			"/mcp/authorize",
			"/mcp/token",
			"/mcp/client-registration",
			"/mcp/register",
			// Canonical callback path
			"/mcp/auth/callback",
			"/prefix/auth/callback",
			// Deeply nested
			"/any/prefix/authorize",
			"/any/prefix/token",
			"/x/y/mcp/authorize",
			// Trailing slash variants
			"/mcp/authorize/",
			"/mcp/token/",
			"/mcp/auth/callback/",
			// Registration sub-paths (GET/DELETE with client_id)
			"/mcp/client-registration/agw_abc123",
			"/.well-known/oauth-authorization-server/client-registration/agw_abc123",
		];
		for path in exempt {
			assert!(
				is_oauth_bootstrap_path(path),
				"path should be exempt from JWT: {path}"
			);
		}
	}

	fn test_auth_for_metadata(issuer: &str) -> McpAuthentication {
		McpAuthentication {
			issuer: issuer.into(),
			audiences: vec!["urn:test".into()],
			provider: None,
			resource_metadata: crate::types::agent::ResourceMetadata {
				extra: std::collections::BTreeMap::new(),
			},
			jwt_validator: std::sync::Arc::new(
				crate::http::jwt::Jwt::from_providers(vec![], crate::http::jwt::Mode::Strict),
			),
			mode: crate::types::agent::McpAuthenticationMode::Strict,
			oidc_proxy: None,
		}
	}

	#[test]
	fn gateway_as_metadata_issuer_is_base_url_not_well_known_path() {
		let req = ::http::Request::builder()
			.uri("https://gw.example/.well-known/oauth-authorization-server")
			.header("host", "gw.example")
			.body(crate::http::Body::empty())
			.unwrap();
		let auth = test_auth_for_metadata("https://idp.example");

		let metadata = build_gateway_as_metadata(&req, &auth);
		let obj = metadata.as_object().expect("must be object");

		let issuer = obj["issuer"].as_str().unwrap();
		assert_eq!(issuer, "https://gw.example", "issuer must be base URL without path");
		assert!(!issuer.contains(".well-known"), "issuer must NOT contain well-known path");

		let authz = obj["authorization_endpoint"].as_str().unwrap();
		assert!(authz.contains("/.well-known/oauth-authorization-server/authorize"), "endpoints keep full path: {authz}");

		let reg = obj["registration_endpoint"].as_str().unwrap();
		assert!(reg.contains("/client-registration"), "registration endpoint present: {reg}");

		assert!(obj.get("code_challenge_methods_supported").is_some());
		assert!(obj.get("grant_types_supported").is_some());
		assert!(obj.get("response_types_supported").is_some());
		assert!(obj.get("token_endpoint_auth_methods_supported").is_some());
		assert!(obj.get("errorCode").is_none(), "no Okta error envelope keys");
	}

	#[test]
	fn gateway_as_metadata_issuer_defaults_http_for_local() {
		let req = ::http::Request::builder()
			.uri("/.well-known/oauth-authorization-server")
			.header("host", "localhost:3100")
			.body(crate::http::Body::empty())
			.unwrap();
		let auth = test_auth_for_metadata("https://idp.example");

		let metadata = build_gateway_as_metadata(&req, &auth);
		let obj = metadata.as_object().unwrap();

		let issuer = obj["issuer"].as_str().unwrap();
		assert_eq!(issuer, "http://localhost:3100", "local issuer must be http with port");

		let endpoints = ["authorization_endpoint", "token_endpoint", "registration_endpoint"];
		for ep in endpoints {
			let v = obj[ep].as_str().unwrap();
			assert!(v.starts_with("http://localhost:3100/"), "endpoint {ep} must include port: {v}");
		}
	}

	#[test]
	fn gateway_as_metadata_issuer_adds_port_from_uri_when_host_header_omits_it() {
		let req = ::http::Request::builder()
			.uri("http://localhost:3100/.well-known/oauth-authorization-server")
			.header("host", "localhost")
			.body(crate::http::Body::empty())
			.unwrap();
		let auth = test_auth_for_metadata("https://idp.example");

		let metadata = build_gateway_as_metadata(&req, &auth);
		let obj = metadata.as_object().unwrap();

		let issuer = obj["issuer"].as_str().unwrap();
		assert_eq!(issuer, "http://localhost:3100", "port from URI must be preserved when host omits it");
	}

	#[test]
	fn gateway_as_metadata_issuer_omits_default_port() {
		let req = ::http::Request::builder()
			.uri("https://gw.example:443/.well-known/oauth-authorization-server")
			.header("host", "gw.example")
			.body(crate::http::Body::empty())
			.unwrap();
		let auth = test_auth_for_metadata("https://idp.example");

		let metadata = build_gateway_as_metadata(&req, &auth);
		let obj = metadata.as_object().unwrap();

		let issuer = obj["issuer"].as_str().unwrap();
		assert_eq!(issuer, "https://gw.example", "default port 443 must not appear in issuer");
	}

	#[test]
	fn gateway_as_metadata_respects_forwarded_proto_with_base_issuer() {
		let req = ::http::Request::builder()
			.uri("http://gw.fly.dev/.well-known/oauth-authorization-server")
			.header("host", "gw.fly.dev")
			.header("x-forwarded-proto", "https")
			.body(crate::http::Body::empty())
			.unwrap();
		let auth = test_auth_for_metadata("https://idp.example");

		let metadata = build_gateway_as_metadata(&req, &auth);
		let obj = metadata.as_object().unwrap();

		let issuer = obj["issuer"].as_str().unwrap();
		assert_eq!(issuer, "https://gw.fly.dev", "issuer = HTTPS base, no path");

		let authz = obj["authorization_endpoint"].as_str().unwrap();
		assert!(authz.starts_with("https://gw.fly.dev/"), "HTTPS endpoint: {authz}");

		let token = obj["token_endpoint"].as_str().unwrap();
		assert!(token.starts_with("https://gw.fly.dev/"), "HTTPS endpoint: {token}");

		let reg = obj["registration_endpoint"].as_str().unwrap();
		assert!(reg.starts_with("https://gw.fly.dev/"), "HTTPS endpoint: {reg}");
	}

	#[test]
	fn protected_mcp_paths_require_jwt() {
		let protected = [
			"/mcp",
			"/mcp/v1",
			"/some/tool/invoke",
			"/api/resources",
			"/health",
			"/",
			"/mcp/callback",
		];
		for path in protected {
			assert!(
				!is_oauth_bootstrap_path(path),
				"path should NOT be exempt from JWT: {path}"
			);
		}
	}

	#[test]
	fn rfc7591_full_metadata_payload_parses_successfully() {
		let payload = serde_json::json!({
			"redirect_uris": ["https://app.example/callback"],
			"token_endpoint_auth_method": "none",
			"grant_types": ["authorization_code"],
			"response_types": ["code"],
			"client_name": "rfc7591-full-smoke",
			"client_uri": "https://example.com",
			"logo_uri": "https://example.com/logo.png",
			"scope": "openid profile",
			"contacts": ["dev@example.com"],
			"tos_uri": "https://example.com/tos",
			"policy_uri": "https://example.com/policy",
			"jwks_uri": "https://example.com/jwks.json",
			"software_id": "example-software-id",
			"software_version": "1.0.0"
		});
		let request: LocalClientRegistrationRequest =
			serde_json::from_value(payload).expect("RFC 7591 full payload must parse");
		let normalized = request.validate_and_normalize().expect("must validate");
		assert_eq!(normalized.logo_uri.as_deref(), Some("https://example.com/logo.png"));
		assert_eq!(normalized.software_id.as_deref(), Some("example-software-id"));
		assert_eq!(normalized.contacts.as_ref().map(|c| c.len()), Some(1));
	}

	#[test]
	fn rfc7591_registration_stores_and_returns_metadata() {
		let request: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["https://app.example/callback"],
			"client_name": "with-metadata",
			"logo_uri": "https://example.com/logo.png",
			"client_uri": "https://example.com",
			"tos_uri": "https://example.com/tos",
			"policy_uri": "https://example.com/policy",
			"software_id": "sw-1",
			"software_version": "2.0.0",
			"contacts": ["a@b.com", "c@d.com"]
		}))
		.expect("parse");
		let record = build_new_record("https://issuer.example", request).expect("build");
		assert_eq!(record.logo_uri.as_deref(), Some("https://example.com/logo.png"));
		assert_eq!(record.software_version.as_deref(), Some("2.0.0"));
		assert_eq!(record.contacts.as_ref().map(|c| c.len()), Some(2));

		let json = serde_json::to_value(&record).expect("serialize");
		assert!(json.get("logo_uri").is_some(), "logo_uri in response");
		assert!(json.get("software_id").is_some(), "software_id in response");
	}

	#[test]
	fn unknown_extension_fields_do_not_crash() {
		let payload = serde_json::json!({
			"redirect_uris": ["https://app.example/callback"],
			"completely_unknown_field": "some value",
			"another_vendor_ext": 42,
			"x-custom": {"nested": true}
		});
		let request: LocalClientRegistrationRequest =
			serde_json::from_value(payload).expect("unknown fields must not crash");
		let normalized = request.validate_and_normalize().expect("must validate");
		assert_eq!(normalized.redirect_uris.len(), 1);
		assert!(normalized.extensions.contains_key("completely_unknown_field"));
	}

	#[test]
	fn invalid_metadata_returns_descriptive_error() {
		let request: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": []
		}))
		.expect("parse");
		let err = request.validate_and_normalize().unwrap_err();
		assert!(err.contains("redirect_uris"), "error mentions the invalid field: {err}");
	}

	#[test]
	fn redirect_uri_accepts_custom_scheme() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["cursor://oauth/callback"]
		}))
		.expect("parse");
		let normalized = req.validate_and_normalize().expect("custom scheme must be accepted");
		assert_eq!(normalized.redirect_uris, vec!["cursor://oauth/callback"]);
	}

	#[test]
	fn redirect_uri_accepts_vscode_scheme() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["vscode://extension.callback"]
		}))
		.expect("parse");
		req.validate_and_normalize().expect("vscode scheme must be accepted");
	}

	#[test]
	fn redirect_uri_accepts_https() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["https://app.example.com/callback"]
		}))
		.expect("parse");
		req.validate_and_normalize().expect("https must be accepted");
	}

	#[test]
	fn redirect_uri_accepts_localhost_http() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["http://localhost:7777/callback"]
		}))
		.expect("parse");
		req.validate_and_normalize().expect("localhost http must be accepted");
	}

	#[test]
	fn redirect_uri_accepts_loopback_ipv4_http() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["http://127.0.0.1:9999/callback"]
		}))
		.expect("parse");
		req.validate_and_normalize().expect("127.0.0.1 http must be accepted");
	}

	#[test]
	fn redirect_uri_rejects_non_loopback_http() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["http://evil.example.com/steal"]
		}))
		.expect("parse");
		let err = req.validate_and_normalize().unwrap_err();
		assert!(err.contains("loopback"), "must mention loopback restriction: {err}");
	}

	#[test]
	fn redirect_uri_rejects_malformed() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["not-a-valid-uri"]
		}))
		.expect("parse");
		let err = req.validate_and_normalize().unwrap_err();
		assert!(err.contains("redirect_uris"), "must mention redirect_uris: {err}");
	}

	#[test]
	fn dcr_response_omits_scope_when_absent() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["https://app.example/cb"]
		}))
		.expect("parse");
		let record = build_new_record("https://issuer.example", req).expect("build");
		let json = serde_json::to_value(&record).expect("serialize");
		assert!(json.get("scope").is_none(), "scope must be omitted, not null");
		assert!(json.get("client_name").is_none(), "client_name must be omitted, not null");
	}

	#[test]
	fn dcr_response_includes_scope_when_provided() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["https://app.example/cb"],
			"scope": "openid profile"
		}))
		.expect("parse");
		let record = build_new_record("https://issuer.example", req).expect("build");
		let json = serde_json::to_value(&record).expect("serialize");
		assert_eq!(json["scope"], "openid profile");
	}

	#[test]
	fn register_path_is_bootstrap_exempt() {
		assert!(is_oauth_bootstrap_path("/mcp/register"));
		assert!(is_oauth_bootstrap_path("/prefix/register"));
		assert!(is_oauth_bootstrap_path("/register"));
	}

	#[test]
	fn as_metadata_includes_none_auth_method_and_scopes() {
		let req = ::http::Request::builder()
			.uri("https://gw.example/.well-known/oauth-authorization-server")
			.header("host", "gw.example")
			.body(crate::http::Body::empty())
			.unwrap();
		let auth = test_auth_for_metadata("https://idp.example");
		let metadata = build_gateway_as_metadata(&req, &auth);
		let obj = metadata.as_object().unwrap();

		let methods = obj["token_endpoint_auth_methods_supported"]
			.as_array()
			.expect("array");
		let method_strs: Vec<&str> = methods.iter().filter_map(|v| v.as_str()).collect();
		assert!(method_strs.contains(&"none"), "must include 'none': {method_strs:?}");
		assert!(method_strs.contains(&"client_secret_basic"), "must include basic: {method_strs:?}");

		let scopes = obj["scopes_supported"].as_array().expect("scopes_supported array");
		assert!(!scopes.is_empty(), "scopes_supported must be non-empty");
	}

	#[test]
	fn registration_without_auth_method_defaults_to_none() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["https://app.example/cb"]
		}))
		.expect("parse");
		let record = build_new_record("https://issuer.example", req).expect("build");
		assert_eq!(
			record.token_endpoint_auth_method, "none",
			"absent token_endpoint_auth_method must default to none for public/native clients"
		);
	}

	#[test]
	fn registration_with_explicit_basic_stays_basic() {
		let req: LocalClientRegistrationRequest = serde_json::from_value(serde_json::json!({
			"redirect_uris": ["https://app.example/cb"],
			"token_endpoint_auth_method": "client_secret_basic"
		}))
		.expect("parse");
		let record = build_new_record("https://issuer.example", req).expect("build");
		assert_eq!(record.token_endpoint_auth_method, "client_secret_basic");
	}

	#[test]
	fn dcr_redis_key_format_matches_spec() {
		let prefix = "agw:oidc:dev";
		assert_eq!(
			dcr_client_key(prefix, "agw_abc123"),
			"agw:oidc:dev:dcr:client:agw_abc123"
		);
		assert_eq!(dcr_clients_set_key(prefix), "agw:oidc:dev:dcr:clients");
	}
}
