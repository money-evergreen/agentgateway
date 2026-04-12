use axum::http::StatusCode;
use axum::response::Response;
use axum_core::response::IntoResponse;
use bytes::Bytes;
use http::Method;
use http::uri::PathAndQuery;
use tracing::{debug, warn};

use crate::http::jwt::Claims;
use crate::http::oauth::{authorization_server_metadata_url, openid_configuration_metadata_url};
use crate::http::*;
use crate::json;
use crate::json::from_body_with_limit;
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{McpAuthentication, McpIDP};

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
	match req.uri().path() {
		// TODO: indicate this is a DirectResponse
		path if path.ends_with("client-registration") => Ok(Some(
			client_registration(req, auth, client.clone())
				.await
				.map_err(|e| {
					warn!("client_registration error: {}", e);
					StatusCode::INTERNAL_SERVER_ERROR
				})
				.into_response(),
		)),
		path if path.starts_with("/.well-known/oauth-protected-resource") => Ok(Some(
			protected_resource_metadata(req, auth).await.into_response(),
		)),
		path if path.starts_with("/.well-known/oauth-authorization-server") => Ok(Some(
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

	// authorization_servers must be the gateway origin (scheme + host + port).
	// Clients fetch /.well-known/oauth-authorization-server from this base.
	// Behind TLS-terminating proxies, use the resource URL's scheme.
	let issuer = if auth.provider.is_some() {
		auth.resource_metadata
			.extra
			.get("resource")
			.and_then(|v| v.as_str())
			.and_then(|r| url::Url::parse(r).ok())
			.map(|u| u.origin().ascii_serialization())
			.unwrap_or_else(|| strip_oauth_protected_resource_prefix(req))
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
	// RFC 8414 URL for standard AS metadata. Keycloak and Okta do not implement RFC 8414 at the
	// standard path; they expose metadata under the issuer path directly.
	let metadata_uri = match &auth.provider {
		Some(McpIDP::Keycloak { .. }) | Some(McpIDP::Okta { .. }) => {
			openid_configuration_metadata_url(&auth.issuer)
		},
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
		Some(McpIDP::Okta { .. }) => {
			// Okta custom authorization servers embed the audience in the server config,
			// so no authorization_endpoint patching is needed (unlike Auth0).
			// Proxy DCR through the gateway for CORS support.
			let current_uri = req
				.extensions()
				.get::<filters::OriginalUrl>()
				.map(|u| u.0.clone())
				.unwrap_or_else(|| req.uri().clone());
			if let Some(serde_json::Value::String(re)) =
				json::traverse_mut(&mut resp, &["registration_endpoint"])
			{
				*re = format!("{current_uri}/client-registration");
			}
		},
		_ => {},
	}

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
	let issuer = auth.issuer.trim_end_matches('/');
	let dcr_uri = match &auth.provider {
		Some(McpIDP::Okta { .. }) => {
			// Okta DCR is at {origin}/oauth2/v1/clients, not under the AS issuer path.
			match url::Url::parse(issuer) {
				Ok(parsed) => format!("{}/oauth2/v1/clients", parsed.origin().ascii_serialization()),
				Err(_) => format!("{issuer}/oauth2/v1/clients"),
			}
		},
		_ => format!("{issuer}/clients-registrations/openid-connect"),
	};
	let method = req.method().clone();
	let body = std::mem::take(req.body_mut());
	let mut builder = ::http::Request::builder()
		.uri(&dcr_uri)
		.method(&method)
		.header("Content-Type", "application/json");

	// Okta DCR requires an API token with okta.clients.register scope
	// and the request body must include application_type (not in RFC 7591).
	// Okta requires SSWS token on all DCR requests (GET and POST).
	if matches!(&auth.provider, Some(McpIDP::Okta { .. })) {
		let token = std::env::var("OKTA_DCR_TOKEN").map_err(|_| {
			ProxyError::ProcessingString(
				"OKTA_DCR_TOKEN environment variable is required for Okta DCR but not set".to_string(),
			)
		})?;
		builder = builder.header("Authorization", format!("SSWS {token}"));
	}

	// Only transform the body on POST (actual registration). GET is passthrough.
	let body = if matches!(&auth.provider, Some(McpIDP::Okta { .. })) && method == Method::POST {

		// Transform RFC 7591 body to Okta format: add application_type if missing
		let mut json_body: serde_json::Value = from_body_with_limit(body, 64 * 1024)
			.await
			.map_err(ProxyError::Body)?;

		if let Some(obj) = json_body.as_object_mut() {
			// Okta requires application_type; infer from token_endpoint_auth_method
			if !obj.contains_key("application_type") {
				let auth_method = obj
					.get("token_endpoint_auth_method")
					.and_then(|v| v.as_str())
					.unwrap_or("client_secret_basic");
				let app_type = if auth_method == "none" { "native" } else { "web" };
				obj.insert(
					"application_type".to_string(),
					serde_json::Value::String(app_type.to_string()),
				);
			}
			// Ensure client_name exists (Okta requires it)
			if !obj.contains_key("client_name") {
				obj.insert(
					"client_name".to_string(),
					serde_json::Value::String("MCP Client".to_string()),
				);
			}
		}

		Body::from(Bytes::from(serde_json::to_vec(&json_body).map_err(|e| {
			ProxyError::ProcessingString(format!("failed to serialize DCR body: {e}"))
		})?))
	} else {
		body
	};

	let ureq = builder.body(body)?;

	let mut upstream = client.simple_call(ureq).await?;

	// Add CORS headers to the response
	let headers = upstream.headers_mut();
	headers.insert("access-control-allow-origin", "*".parse().unwrap());
	headers.insert(
		"access-control-allow-methods",
		"POST, OPTIONS".parse().unwrap(),
	);
	headers.insert(
		"access-control-allow-headers",
		"content-type".parse().unwrap(),
	);

	Ok(upstream)
}
