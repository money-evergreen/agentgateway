use axum::http::StatusCode;
use axum::response::Response;
use axum_core::response::IntoResponse;
use bytes::Bytes;
use http::Method;
use http::uri::PathAndQuery;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::sync::RwLock;
use tracing::{debug, info, warn};

use crate::http::jwt::Claims;
use crate::http::oauth::{authorization_server_metadata_url, openid_configuration_metadata_url};
use crate::http::*;
use crate::json;
use crate::json::from_body_with_limit;
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{McpAuthentication, McpIDP};

static LOCAL_CLIENT_REGISTRY: Lazy<RwLock<LocalClientRegistry>> =
	Lazy::new(|| RwLock::new(LocalClientRegistry::default()));

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
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
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(super) struct LocalClientRegistrationRecord {
	pub(super) client_id: String,
	pub(super) client_secret: String,
	pub(super) active: bool,
	pub(super) redirect_uris: Vec<String>,
	client_name: Option<String>,
	token_endpoint_auth_method: String,
	grant_types: Vec<String>,
	response_types: Vec<String>,
	scope: Option<String>,
}

#[derive(Default)]
struct LocalClientRegistry {
	by_id: HashMap<String, LocalClientRegistrationRecord>,
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
			if !matches!(parsed.scheme(), "http" | "https") {
				return Err("redirect_uris must use http or https".into());
			}
			normalized_redirects.insert(parsed.to_string());
		}
		self.redirect_uris = normalized_redirects.into_iter().collect();

		let auth_method = self
			.token_endpoint_auth_method
			.clone()
			.unwrap_or_else(|| "client_secret_basic".into());
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

impl LocalClientRegistry {
	fn register(
		&mut self,
		issuer: &str,
		request: LocalClientRegistrationRequest,
	) -> Result<(LocalClientRegistrationRecord, bool), String> {
		let request = request.validate_and_normalize()?;
		let client_id = request.deterministic_client_id(issuer)?;
		if let Some(existing) = self.by_id.get(&client_id) {
			if !existing.active {
				return Err("client registration exists but is deactivated".into());
			}
			return Ok((existing.clone(), false));
		}

		let mut hasher = Sha256::new();
		hasher.update(client_id.as_bytes());
		hasher.update(b":secret");
		let digest = hasher.finalize();
		let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
		let client_secret = format!("agw_secret_{}", &digest_hex[..32]);

		let record = LocalClientRegistrationRecord {
			client_id: client_id.clone(),
			client_secret,
			active: true,
			redirect_uris: request.redirect_uris,
			client_name: request.client_name,
			token_endpoint_auth_method: request
				.token_endpoint_auth_method
				.unwrap_or_else(|| "client_secret_basic".into()),
			grant_types: request
				.grant_types
				.unwrap_or_else(|| vec!["authorization_code".into()]),
			response_types: request.response_types.unwrap_or_else(|| vec!["code".into()]),
			scope: request.scope,
		};
		self.by_id.insert(client_id, record.clone());
		Ok((record, true))
	}

	fn get(&self, client_id: &str) -> Option<LocalClientRegistrationRecord> {
		self.by_id.get(client_id).cloned()
	}

	fn update(
		&mut self,
		client_id: &str,
		request: LocalClientRegistrationRequest,
	) -> Result<LocalClientRegistrationRecord, String> {
		let normalized = request.validate_and_normalize()?;
		let existing = self
			.by_id
			.get_mut(client_id)
			.ok_or_else(|| "unknown client_id".to_string())?;
		if !existing.active {
			return Err("client registration is deactivated".into());
		}
		existing.redirect_uris = normalized.redirect_uris;
		existing.client_name = normalized.client_name;
		existing.token_endpoint_auth_method = normalized
			.token_endpoint_auth_method
			.unwrap_or_else(|| "client_secret_basic".into());
		existing.grant_types = normalized
			.grant_types
			.unwrap_or_else(|| vec!["authorization_code".into()]);
		existing.response_types = normalized.response_types.unwrap_or_else(|| vec!["code".into()]);
		existing.scope = normalized.scope;
		Ok(existing.clone())
	}

	fn deactivate(&mut self, client_id: &str) -> Result<LocalClientRegistrationRecord, String> {
		let existing = self
			.by_id
			.get_mut(client_id)
			.ok_or_else(|| "unknown client_id".to_string())?;
		if !existing.active {
			return Err("client registration is already deactivated".into());
		}
		existing.active = false;
		Ok(existing.clone())
	}
}

pub(super) fn get_registered_client(client_id: &str) -> Option<LocalClientRegistrationRecord> {
	LOCAL_CLIENT_REGISTRY
		.read()
		.ok()
		.and_then(|registry| registry.get(client_id))
}

pub(crate) fn is_well_known_endpoint(path: &str) -> bool {
	path.starts_with("/.well-known/oauth-protected-resource")
		|| path.starts_with("/.well-known/oauth-authorization-server")
}

pub(super) async fn apply_token_validation(
	req: &mut Request,
	auth: &McpAuthentication,
) -> Result<(), ProxyError> {
	// skip well-known OAuth endpoints for authn
	if is_well_known_endpoint(req.uri().path()) {
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
	// skip well-known OAuth endpoints for authn
	if !is_well_known_endpoint(req.uri().path()) {
		apply_token_validation(req, auth).await?;
	}

	handle_mcp_request(req, auth, client).await
}

pub(crate) async fn handle_mcp_request(
	req: &mut Request,
	auth: &McpAuthentication,
	client: &PolicyClient,
) -> Result<Option<Response>, ProxyError> {
	let _ = client;
	let path = req.uri().path().to_string();
	match path.as_str() {
		// TODO: indicate this is a DirectResponse
		p if p.contains("/client-registration") => Ok(Some(
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
		p if p.starts_with("/.well-known/oauth-authorization-server") && p.ends_with("/authorize") =>
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
		p if p.starts_with("/.well-known/oauth-authorization-server") && p.ends_with("/callback") =>
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
		p if p.starts_with("/.well-known/oauth-authorization-server") && p.ends_with("/token") => {
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
			// Not handled
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
	let new_uri = strip_oauth_protected_resource_prefix(req);

	// Determine the issuer to use - either use the same request URL and path that it was initially with,
	// or else keep the auth.issuer
	let issuer = if auth.provider.is_some() {
		// When a provider is configured, use the same request URL with the well-known prefix stripped
		strip_oauth_protected_resource_prefix(req)
	} else {
		// No provider configured, use the original issuer
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

fn strip_oauth_protected_resource_prefix(req: &Request) -> String {
	let uri = req
		.extensions()
		.get::<filters::OriginalUrl>()
		.map(|u| u.0.clone())
		.unwrap_or_else(|| req.uri().clone());

	let path = uri.path();
	const OAUTH_PREFIX: &str = "/.well-known/oauth-protected-resource";

	// Remove the oauth-protected-resource prefix and keep the remaining path
	if let Some(remaining_path) = path.strip_prefix(OAUTH_PREFIX) {
		uri.to_string().replace(path, remaining_path)
	} else {
		// If the prefix is not found, return the original URI
		uri.to_string()
	}
}

pub(super) async fn authorization_server_metadata(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	// RFC 8414 URL for standard AS metadata. Keycloak does not implement RFC 8414; it only
	// exposes OpenID Provider Metadata at {issuer}/.well-known/openid-configuration (OIDC Discovery).
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
		Some(McpIDP::Auth0 {}) => {
			// Auth0 does not support RFC 8707. We can workaround this by prepending an audience
			let Some(serde_json::Value::String(ae)) =
				json::traverse_mut(&mut resp, &["authorization_endpoint"])
			else {
				return Err(ProxyError::ProcessingString(
					"authorization_endpoint missing".to_string(),
				));
			};
			// If the user provided multiple audiences with auth0, just prepend the first one
			if let Some(aud) = auth.audiences.first() {
				ae.push_str(&format!("?audience={}", aud));
			}
		},
		Some(McpIDP::Keycloak { .. }) => {
			// Keycloak does not support RFC 8707.
			// We do not currently have a workload :-(
			// users will have to hardcode the audience.
			// https://github.com/keycloak/keycloak/issues/10169 and https://github.com/keycloak/keycloak/issues/14355

			// Keycloak doesn't do CORS for client registrations
			// https://github.com/keycloak/keycloak/issues/39629
			// We can workaround this by proxying it

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

	super::oidc_proxy::rewrite_as_metadata(&mut resp, req, auth);

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

pub(super) async fn client_registration(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	let _ = client;
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
			let request: LocalClientRegistrationRequest = serde_json::from_value(body).map_err(|e| {
				ProxyError::ProcessingString(format!(
					"invalid client registration metadata payload: {e}"
				))
			})?;
		let (record, created) = LOCAL_CLIENT_REGISTRY
			.write()
			.map_err(|_| ProxyError::ProcessingString("local registry lock poisoned".into()))?
			.register(&auth.issuer, request)
			.map_err(ProxyError::ProcessingString)?;
		let status = if created {
			info!(
				client_id = %record.client_id,
				audit_event = "client_registered",
				"new MCP client registration created"
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
			let registry = LOCAL_CLIENT_REGISTRY
				.read()
				.map_err(|_| ProxyError::ProcessingString("local registry lock poisoned".into()))?;
			match registry.get(client_id) {
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
			let request: LocalClientRegistrationRequest = serde_json::from_value(body).map_err(|e| {
				ProxyError::ProcessingString(format!(
					"invalid client registration metadata payload: {e}"
				))
			})?;
		let updated = LOCAL_CLIENT_REGISTRY
			.write()
			.map_err(|_| ProxyError::ProcessingString("local registry lock poisoned".into()))?
			.update(client_id, request)
			.map_err(ProxyError::ProcessingString)?;
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
		let deactivated = LOCAL_CLIENT_REGISTRY
			.write()
			.map_err(|_| ProxyError::ProcessingString("local registry lock poisoned".into()))?
			.deactivate(client_id)
			.map_err(ProxyError::ProcessingString)?;
		let revoked = super::oidc_proxy::revoke_client(&deactivated.client_id);
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
		LocalClientRegistrationRequest {
			redirect_uris: vec!["https://app.example/callback".into()],
			client_name: Some("my app".into()),
			token_endpoint_auth_method: Some("client_secret_basic".into()),
			grant_types: Some(vec!["authorization_code".into()]),
			response_types: Some(vec!["code".into()]),
			scope: Some("openid profile".into()),
		}
	}

	#[test]
	fn deterministic_registration_is_idempotent() {
		let mut registry = LocalClientRegistry::default();
		let issuer = "https://issuer.example";
		let (first, created_first) = registry.register(issuer, sample_request()).expect("register");
		let (second, created_second) = registry.register(issuer, sample_request()).expect("register");
		assert!(created_first);
		assert!(!created_second);
		assert_eq!(first.client_id, second.client_id);
	}

	#[test]
	fn update_and_deactivate_lifecycle_is_enforced() {
		let mut registry = LocalClientRegistry::default();
		let issuer = "https://issuer.example";
		let (record, _) = registry.register(issuer, sample_request()).expect("register");

		let updated = registry
			.update(
				&record.client_id,
				LocalClientRegistrationRequest {
					redirect_uris: vec!["https://updated.example/callback".into()],
					client_name: Some("updated".into()),
					token_endpoint_auth_method: Some("client_secret_post".into()),
					grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
					response_types: Some(vec!["code".into()]),
					scope: Some("openid email".into()),
				},
			)
			.expect("update");
		assert_eq!(updated.client_name.as_deref(), Some("updated"));
		assert_eq!(updated.token_endpoint_auth_method, "client_secret_post");

		let deactivated = registry.deactivate(&record.client_id).expect("deactivate");
		assert!(!deactivated.active);
		assert!(registry.update(&record.client_id, sample_request()).is_err());
	}

	#[test]
	fn deactivated_client_blocks_re_registration_and_update() {
		let mut registry = LocalClientRegistry::default();
		let issuer = "https://issuer.example";
		let (record, _) = registry.register(issuer, sample_request()).expect("register");
		registry.deactivate(&record.client_id).expect("deactivate");

		let err = registry
			.register(issuer, sample_request())
			.expect_err("re-registration after deactivation must fail");
		assert!(err.contains("deactivated"));

		let err = registry
			.update(&record.client_id, sample_request())
			.expect_err("update after deactivation must fail");
		assert!(err.contains("deactivated"));
	}

	#[test]
	fn malformed_or_unsupported_metadata_is_rejected() {
		let mut registry = LocalClientRegistry::default();
		let err = registry
			.register(
				"https://issuer.example",
				LocalClientRegistrationRequest {
					redirect_uris: vec!["not-a-uri".into()],
					client_name: None,
					token_endpoint_auth_method: Some("private_key_jwt".into()),
					grant_types: Some(vec!["client_credentials".into()]),
					response_types: Some(vec!["token".into()]),
					scope: None,
				},
			)
			.expect_err("invalid metadata should fail");
		assert!(err.contains("redirect_uris") || err.contains("token_endpoint_auth_method"));
	}
}
