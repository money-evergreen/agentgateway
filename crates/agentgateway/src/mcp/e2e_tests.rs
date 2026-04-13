#![cfg(test)]

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use http::{Method, StatusCode, header};
use serde_json::json;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::http::jwt;
use crate::http::{Body, Request};
use crate::mcp::auth;
use crate::mcp::oidc_proxy;
use crate::proxy::httpproxy::PolicyClient;
use crate::test_helpers::proxymock::setup_proxy_test;
use crate::types::agent::{
	McpAuthentication, McpAuthenticationMode, McpIDP, OidcProxyConfig, ResourceMetadata,
};

const TEST_JWKS_JSON: &str = r#"{
	"keys": [{
		"use": "sig", "kty": "EC", "kid": "kid-1", "crv": "P-256", "alg": "ES256",
		"x": "WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk",
		"y": "xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"
	}]
}"#;

fn policy_client() -> PolicyClient {
	let proxy = setup_proxy_test("{}").expect("proxy test harness");
	PolicyClient {
		inputs: proxy.inputs(),
	}
}

fn test_mcp_auth(idp_issuer: &str, proxy_client_id: &str) -> McpAuthentication {
	let jwks: jsonwebtoken::jwk::JwkSet =
		serde_json::from_str(TEST_JWKS_JSON).expect("test jwks");
	let provider = jwt::Provider::from_jwks(
		jwks,
		idp_issuer.to_string(),
		Some(vec!["test-aud".into()]),
		jwt::JWTValidationOptions::default(),
	)
	.expect("jwt provider");
	let validator = jwt::Jwt::from_providers(vec![provider], jwt::Mode::Strict);

	McpAuthentication {
		issuer: idp_issuer.to_string(),
		audiences: vec!["test-aud".into()],
		provider: None,
		resource_metadata: ResourceMetadata {
			extra: BTreeMap::new(),
		},
		jwt_validator: Arc::new(validator),
		mode: McpAuthenticationMode::Strict,
		oidc_proxy: Some(OidcProxyConfig {
			client_id: proxy_client_id.to_string(),
			client_secret: secrecy::SecretString::new("gateway-secret".into()),
		}),
	}
}

fn test_mcp_auth_with_provider(
	idp_issuer: &str,
	proxy_client_id: &str,
	provider: Option<McpIDP>,
) -> McpAuthentication {
	let mut auth = test_mcp_auth(idp_issuer, proxy_client_id);
	auth.provider = provider;
	auth
}

fn registration_body() -> serde_json::Value {
	json!({
		"redirect_uris": ["https://app.example/callback"],
		"client_name": "e2e-test",
		"token_endpoint_auth_method": "client_secret_basic",
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"scope": "openid"
	})
}

fn build_request(m: Method, uri: &str, body: Option<serde_json::Value>) -> Request {
	let mut builder = ::http::Request::builder().method(m).uri(uri);
	if body.is_some() {
		builder = builder.header(header::CONTENT_TYPE, "application/json");
	}
	let body_bytes = body
		.map(|v| Body::from(serde_json::to_vec(&v).unwrap()))
		.unwrap_or_else(Body::empty);
	builder.body(body_bytes).expect("request")
}

fn build_form_request(uri: &str, form: &str) -> Request {
	::http::Request::builder()
		.method(Method::POST)
		.uri(uri)
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.body(Body::from(form.to_string()))
		.expect("form request")
}

fn response_json(resp: &::http::Response<Body>) -> Option<serde_json::Value> {
	None.or_else(|| {
		let _ = resp;
		None
	})
}

fn redirect_location(resp: &::http::Response<Body>) -> Option<String> {
	resp.headers()
		.get(header::LOCATION)
		.and_then(|v| v.to_str().ok())
		.map(|s| s.to_string())
}

fn query_param(url: &str, key: &str) -> Option<String> {
	url::Url::parse(url)
		.ok()?
		.query_pairs()
		.find_map(|(k, v)| (k == key).then(|| v.into_owned()))
}

async fn read_response_json(resp: ::http::Response<Body>) -> serde_json::Value {
	let body = crate::http::read_body_with_limit(resp.into_body(), 64 * 1024)
		.await
		.expect("read body");
	serde_json::from_slice(&body).expect("parse json")
}

fn s256_challenge(verifier: &str) -> String {
	let digest = Sha256::digest(verifier.as_bytes());
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

// ---------------------------------------------------------------------------
// Happy-path E2E
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_register_authorize_callback_token() {
	let idp = MockServer::start().await;
	let idp_uri = idp.uri();

	Mock::given(method("GET"))
		.and(path("/.well-known/oauth-authorization-server"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"issuer": idp_uri,
			"authorization_endpoint": format!("{idp_uri}/authorize"),
			"token_endpoint": format!("{idp_uri}/token"),
		})))
		.mount(&idp)
		.await;

	Mock::given(method("POST"))
		.and(path("/token"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"access_token": "idp-access-token",
			"token_type": "Bearer",
			"expires_in": 3600,
		})))
		.mount(&idp)
		.await;

	let auth = test_mcp_auth(&idp_uri, "gw-client");
	let client = policy_client();

	// 1. Register a client
	let mut reg_req = build_request(
		Method::POST,
		"https://gw.example/.well-known/oauth-authorization-server/client-registration",
		Some(registration_body()),
	);
	let reg_resp = auth::client_registration(&mut reg_req, &auth, client.clone())
		.await
		.expect("registration");
	assert_eq!(reg_resp.status(), StatusCode::CREATED);
	let reg_json = read_response_json(reg_resp).await;
	let client_id = reg_json["client_id"].as_str().unwrap().to_string();
	let client_secret = reg_json["client_secret"].as_str().unwrap().to_string();
	assert!(reg_json["active"].as_bool().unwrap());

	// 2. Start authorize flow
	let pkce_verifier = "e2e-verifier-value-for-testing-12345678";
	let code_challenge = s256_challenge(pkce_verifier);
	let authorize_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/authorize\
		?client_id={client_id}\
		&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&response_type=code\
		&state=client-state-1\
		&code_challenge={code_challenge}\
		&code_challenge_method=S256\
		&scope=openid"
	);
	let mut auth_req = build_request(Method::GET, &authorize_uri, None);
	let auth_resp = oidc_proxy::proxy_authorize(&mut auth_req, &auth, client.clone())
		.await
		.expect("authorize");
	assert_eq!(auth_resp.status(), StatusCode::FOUND);
	let idp_redirect = redirect_location(&auth_resp).expect("redirect location");
	assert!(idp_redirect.starts_with(&format!("{idp_uri}/authorize?")));
	let gateway_state = query_param(&idp_redirect, "state").expect("gateway state");

	// 3. Simulate IDP callback
	let callback_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/callback\
		?code=idp-auth-code\
		&state={gateway_state}"
	);
	let mut cb_req = build_request(Method::GET, &callback_uri, None);
	let cb_resp = oidc_proxy::proxy_callback(&mut cb_req, &auth, client.clone())
		.await
		.expect("callback");
	assert_eq!(cb_resp.status(), StatusCode::FOUND);
	let client_redirect = redirect_location(&cb_resp).expect("client redirect");
	assert!(client_redirect.starts_with("https://app.example/callback?"));
	let proxy_code = query_param(&client_redirect, "code").expect("proxy code");
	let returned_state = query_param(&client_redirect, "state").expect("returned state");
	assert_eq!(returned_state, "client-state-1");

	// 4. Exchange proxy code for tokens
	let form = format!(
		"grant_type=authorization_code\
		&code={proxy_code}\
		&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&code_verifier={pkce_verifier}\
		&client_id={client_id}\
		&client_secret={client_secret}"
	);
	let mut token_req = build_form_request(
		"https://gw.example/.well-known/oauth-authorization-server/token",
		&form,
	);
	let token_resp = oidc_proxy::proxy_token(&mut token_req, &auth, client.clone())
		.await
		.expect("token");
	assert_eq!(token_resp.status(), StatusCode::OK);
	let token_json = read_response_json(token_resp).await;
	assert_eq!(token_json["access_token"], "idp-access-token");
	assert_eq!(token_json["token_type"], "Bearer");
}

// ---------------------------------------------------------------------------
// Registration negative paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_idempotency_returns_same_client() {
	let auth = test_mcp_auth("https://idempotent.example", "gw");
	let client = policy_client();

	let mut req1 = build_request(
		Method::POST,
		"https://gw.example/client-registration",
		Some(registration_body()),
	);
	let resp1 = auth::client_registration(&mut req1, &auth, client.clone())
		.await
		.expect("first");
	assert_eq!(resp1.status(), StatusCode::CREATED);
	let json1 = read_response_json(resp1).await;

	let mut req2 = build_request(
		Method::POST,
		"https://gw.example/client-registration",
		Some(registration_body()),
	);
	let resp2 = auth::client_registration(&mut req2, &auth, client.clone())
		.await
		.expect("second");
	assert_eq!(resp2.status(), StatusCode::OK);
	let json2 = read_response_json(resp2).await;

	assert_eq!(json1["client_id"], json2["client_id"]);
}

// ---------------------------------------------------------------------------
// PKCE failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_rejects_wrong_pkce_verifier() {
	let idp = MockServer::start().await;
	let idp_uri = idp.uri();

	Mock::given(method("GET"))
		.and(path("/.well-known/oauth-authorization-server"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"issuer": idp_uri,
			"authorization_endpoint": format!("{idp_uri}/authorize"),
			"token_endpoint": format!("{idp_uri}/token"),
		})))
		.mount(&idp)
		.await;
	Mock::given(method("POST"))
		.and(path("/token"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"access_token": "tok", "token_type": "Bearer"
		})))
		.mount(&idp)
		.await;

	let auth = test_mcp_auth(&idp_uri, "gw-pkce");
	let client = policy_client();

	let mut reg = build_request(
		Method::POST,
		"https://gw.example/client-registration",
		Some(registration_body()),
	);
	let reg_resp = auth::client_registration(&mut reg, &auth, client.clone())
		.await
		.expect("reg");
	let reg_json = read_response_json(reg_resp).await;
	let client_id = reg_json["client_id"].as_str().unwrap();
	let client_secret = reg_json["client_secret"].as_str().unwrap();

	let real_verifier = "correct-verifier-value-xxxxxx";
	let code_challenge = s256_challenge(real_verifier);
	let auth_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/authorize\
		?client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&response_type=code&state=s1&code_challenge={code_challenge}&code_challenge_method=S256"
	);
	let mut auth_req = build_request(Method::GET, &auth_uri, None);
	let auth_resp = oidc_proxy::proxy_authorize(&mut auth_req, &auth, client.clone())
		.await
		.expect("auth");
	let gw_state = query_param(
		redirect_location(&auth_resp).as_deref().unwrap(),
		"state",
	)
	.unwrap();

	let cb_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/callback?code=c&state={gw_state}"
	);
	let mut cb_req = build_request(Method::GET, &cb_uri, None);
	let cb_resp = oidc_proxy::proxy_callback(&mut cb_req, &auth, client.clone())
		.await
		.expect("cb");
	let proxy_code = query_param(
		redirect_location(&cb_resp).as_deref().unwrap(),
		"code",
	)
	.unwrap();

	let form = format!(
		"grant_type=authorization_code&code={proxy_code}\
		&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&code_verifier=WRONG-VERIFIER\
		&client_id={client_id}&client_secret={client_secret}"
	);
	let mut tok_req = build_form_request(
		"https://gw.example/.well-known/oauth-authorization-server/token",
		&form,
	);
	let tok_resp = oidc_proxy::proxy_token(&mut tok_req, &auth, client.clone())
		.await
		.expect("token");
	assert_eq!(tok_resp.status(), StatusCode::BAD_REQUEST);
	let tok_json = read_response_json(tok_resp).await;
	assert_eq!(tok_json["error"], "invalid_grant");
	assert!(tok_json["error_description"]
		.as_str()
		.unwrap()
		.contains("code_verifier"));
}

// ---------------------------------------------------------------------------
// State/code replay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proxy_code_is_single_use() {
	let idp = MockServer::start().await;
	let idp_uri = idp.uri();

	Mock::given(method("GET"))
		.and(path("/.well-known/oauth-authorization-server"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"issuer": idp_uri,
			"authorization_endpoint": format!("{idp_uri}/authorize"),
			"token_endpoint": format!("{idp_uri}/token"),
		})))
		.mount(&idp)
		.await;
	Mock::given(method("POST"))
		.and(path("/token"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"access_token": "tok", "token_type": "Bearer"
		})))
		.mount(&idp)
		.await;

	let auth = test_mcp_auth(&idp_uri, "gw-replay");
	let client = policy_client();

	let mut reg = build_request(
		Method::POST,
		"https://gw.example/client-registration",
		Some(registration_body()),
	);
	let reg_resp = auth::client_registration(&mut reg, &auth, client.clone())
		.await
		.expect("reg");
	let reg_json = read_response_json(reg_resp).await;
	let client_id = reg_json["client_id"].as_str().unwrap();
	let client_secret = reg_json["client_secret"].as_str().unwrap();

	let verifier = "replay-test-verifier-value-xxx";
	let challenge = s256_challenge(verifier);
	let auth_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/authorize\
		?client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&response_type=code&state=s1&code_challenge={challenge}&code_challenge_method=S256"
	);
	let mut a = build_request(Method::GET, &auth_uri, None);
	let ar = oidc_proxy::proxy_authorize(&mut a, &auth, client.clone())
		.await
		.unwrap();
	let gw_state = query_param(redirect_location(&ar).as_deref().unwrap(), "state").unwrap();

	let cb_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/callback?code=c&state={gw_state}"
	);
	let mut cb = build_request(Method::GET, &cb_uri, None);
	let cbr = oidc_proxy::proxy_callback(&mut cb, &auth, client.clone())
		.await
		.unwrap();
	let proxy_code = query_param(redirect_location(&cbr).as_deref().unwrap(), "code").unwrap();

	let form = format!(
		"grant_type=authorization_code&code={proxy_code}\
		&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&code_verifier={verifier}\
		&client_id={client_id}&client_secret={client_secret}"
	);

	let mut t1 = build_form_request(
		"https://gw.example/.well-known/oauth-authorization-server/token",
		&form,
	);
	let r1 = oidc_proxy::proxy_token(&mut t1, &auth, client.clone())
		.await
		.expect("first exchange");
	assert_eq!(r1.status(), StatusCode::OK);

	let mut t2 = build_form_request(
		"https://gw.example/.well-known/oauth-authorization-server/token",
		&form,
	);
	let r2 = oidc_proxy::proxy_token(&mut t2, &auth, client.clone())
		.await;
	assert!(
		r2.is_err(),
		"replayed proxy code must fail"
	);
}

// ---------------------------------------------------------------------------
// Deactivated client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deactivated_client_blocks_authorize_and_token() {
	let idp = MockServer::start().await;
	let idp_uri = idp.uri();

	Mock::given(method("GET"))
		.and(path("/.well-known/oauth-authorization-server"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"issuer": idp_uri,
			"authorization_endpoint": format!("{idp_uri}/authorize"),
			"token_endpoint": format!("{idp_uri}/token"),
		})))
		.mount(&idp)
		.await;

	let auth = test_mcp_auth(&idp_uri, "gw-deact");
	let client = policy_client();

	let mut reg = build_request(
		Method::POST,
		"https://gw.example/client-registration",
		Some(registration_body()),
	);
	let reg_resp = auth::client_registration(&mut reg, &auth, client.clone())
		.await
		.expect("reg");
	let reg_json = read_response_json(reg_resp).await;
	let client_id = reg_json["client_id"].as_str().unwrap().to_string();

	// Deactivate — DELETE handler reads body as JSON; send empty object
	let mut del_req = build_request(
		Method::DELETE,
		&format!("https://gw.example/client-registration/{client_id}"),
		Some(json!({})),
	);
	let del_resp = auth::client_registration(&mut del_req, &auth, client.clone())
		.await
		.expect("delete");
	assert_eq!(del_resp.status(), StatusCode::OK);

	// Authorize should fail
	let auth_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/authorize\
		?client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&response_type=code&state=s1&code_challenge=abc&code_challenge_method=S256"
	);
	let mut auth_req = build_request(Method::GET, &auth_uri, None);
	let auth_resp = oidc_proxy::proxy_authorize(&mut auth_req, &auth, client.clone())
		.await
		.expect("authorize after deactivation");
	assert_eq!(auth_resp.status(), StatusCode::BAD_REQUEST);
	let auth_json = read_response_json(auth_resp).await;
	assert_eq!(auth_json["error"], "invalid_client");

	// Token should fail
	let form = format!(
		"grant_type=authorization_code&code=any\
		&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&code_verifier=any\
		&client_id={client_id}&client_secret=any"
	);
	let mut tok_req = build_form_request(
		"https://gw.example/.well-known/oauth-authorization-server/token",
		&form,
	);
	let tok_resp = oidc_proxy::proxy_token(&mut tok_req, &auth, client.clone())
		.await
		.expect("token after deactivation");
	assert_eq!(tok_resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Redirect URI mismatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authorize_rejects_unregistered_redirect_uri() {
	let idp = MockServer::start().await;
	let idp_uri = idp.uri();

	Mock::given(method("GET"))
		.and(path("/.well-known/oauth-authorization-server"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"issuer": idp_uri,
			"authorization_endpoint": format!("{idp_uri}/authorize"),
			"token_endpoint": format!("{idp_uri}/token"),
		})))
		.mount(&idp)
		.await;

	let auth = test_mcp_auth(&idp_uri, "gw-redir");
	let client = policy_client();

	let mut reg = build_request(
		Method::POST,
		"https://gw.example/client-registration",
		Some(registration_body()),
	);
	let reg_json = read_response_json(
		auth::client_registration(&mut reg, &auth, client.clone())
			.await
			.expect("reg"),
	)
	.await;
	let client_id = reg_json["client_id"].as_str().unwrap();

	let auth_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/authorize\
		?client_id={client_id}\
		&redirect_uri=https%3A%2F%2Fevil.example%2Fsteal\
		&response_type=code&state=s1&code_challenge=abc&code_challenge_method=S256"
	);
	let mut auth_req = build_request(Method::GET, &auth_uri, None);
	let auth_resp = oidc_proxy::proxy_authorize(&mut auth_req, &auth, client.clone())
		.await
		.expect("authorize");
	assert_eq!(auth_resp.status(), StatusCode::BAD_REQUEST);
	let json = read_response_json(auth_resp).await;
	assert_eq!(json["error"], "invalid_request");
	assert!(json["error_description"]
		.as_str()
		.unwrap()
		.contains("redirect_uri"));
}

// ---------------------------------------------------------------------------
// State replay (callback)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn callback_state_is_single_use() {
	let idp = MockServer::start().await;
	let idp_uri = idp.uri();

	Mock::given(method("GET"))
		.and(path("/.well-known/oauth-authorization-server"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"issuer": idp_uri,
			"authorization_endpoint": format!("{idp_uri}/authorize"),
			"token_endpoint": format!("{idp_uri}/token"),
		})))
		.mount(&idp)
		.await;
	Mock::given(method("POST"))
		.and(path("/token"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"access_token": "tok", "token_type": "Bearer"
		})))
		.mount(&idp)
		.await;

	let auth = test_mcp_auth(&idp_uri, "gw-state-replay");
	let client = policy_client();

	let mut reg = build_request(
		Method::POST,
		"https://gw.example/client-registration",
		Some(registration_body()),
	);
	let reg_json = read_response_json(
		auth::client_registration(&mut reg, &auth, client.clone())
			.await
			.expect("reg"),
	)
	.await;
	let client_id = reg_json["client_id"].as_str().unwrap();

	let verifier = "state-replay-verifier-value-xx";
	let challenge = s256_challenge(verifier);
	let auth_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/authorize\
		?client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&response_type=code&state=s1&code_challenge={challenge}&code_challenge_method=S256"
	);
	let mut a = build_request(Method::GET, &auth_uri, None);
	let ar = oidc_proxy::proxy_authorize(&mut a, &auth, client.clone())
		.await
		.unwrap();
	let gw_state = query_param(redirect_location(&ar).as_deref().unwrap(), "state").unwrap();

	let cb_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/callback?code=c&state={gw_state}"
	);

	let mut cb1 = build_request(Method::GET, &cb_uri, None);
	let r1 = oidc_proxy::proxy_callback(&mut cb1, &auth, client.clone()).await;
	assert!(r1.is_ok(), "first callback should succeed");

	let mut cb2 = build_request(Method::GET, &cb_uri, None);
	let r2 = oidc_proxy::proxy_callback(&mut cb2, &auth, client.clone()).await;
	assert!(r2.is_err(), "replayed state must fail");
}

// ---------------------------------------------------------------------------
// Bad client secret at token exchange
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_rejects_wrong_client_secret() {
	let idp = MockServer::start().await;
	let idp_uri = idp.uri();

	Mock::given(method("GET"))
		.and(path("/.well-known/oauth-authorization-server"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"issuer": idp_uri,
			"authorization_endpoint": format!("{idp_uri}/authorize"),
			"token_endpoint": format!("{idp_uri}/token"),
		})))
		.mount(&idp)
		.await;
	Mock::given(method("POST"))
		.and(path("/token"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"access_token": "tok", "token_type": "Bearer"
		})))
		.mount(&idp)
		.await;

	let auth = test_mcp_auth(&idp_uri, "gw-badsecret");
	let client = policy_client();

	let mut reg = build_request(
		Method::POST,
		"https://gw.example/client-registration",
		Some(registration_body()),
	);
	let reg_json = read_response_json(
		auth::client_registration(&mut reg, &auth, client.clone())
			.await
			.expect("reg"),
	)
	.await;
	let client_id = reg_json["client_id"].as_str().unwrap();

	let verifier = "badsecret-verifier-value-zzzzz";
	let challenge = s256_challenge(verifier);
	let auth_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/authorize\
		?client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&response_type=code&state=s1&code_challenge={challenge}&code_challenge_method=S256"
	);
	let mut a = build_request(Method::GET, &auth_uri, None);
	let ar = oidc_proxy::proxy_authorize(&mut a, &auth, client.clone())
		.await
		.unwrap();
	let gw_state = query_param(redirect_location(&ar).as_deref().unwrap(), "state").unwrap();

	let cb_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/callback?code=c&state={gw_state}"
	);
	let mut cb = build_request(Method::GET, &cb_uri, None);
	let cbr = oidc_proxy::proxy_callback(&mut cb, &auth, client.clone())
		.await
		.unwrap();
	let proxy_code = query_param(redirect_location(&cbr).as_deref().unwrap(), "code").unwrap();

	let form = format!(
		"grant_type=authorization_code&code={proxy_code}\
		&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&code_verifier={verifier}\
		&client_id={client_id}&client_secret=WRONG-SECRET"
	);
	let mut tok = build_form_request(
		"https://gw.example/.well-known/oauth-authorization-server/token",
		&form,
	);
	let tok_resp = oidc_proxy::proxy_token(&mut tok, &auth, client.clone())
		.await
		.expect("token");
	assert_eq!(tok_resp.status(), StatusCode::UNAUTHORIZED);
	let json = read_response_json(tok_resp).await;
	assert_eq!(json["error"], "invalid_client");
}

// ---------------------------------------------------------------------------
// Okta provider parity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn okta_provider_uses_rfc8414_metadata_and_audience_prepend() {
	let idp = MockServer::start().await;
	let idp_uri = idp.uri();

	Mock::given(method("GET"))
		.and(path("/.well-known/oauth-authorization-server"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"issuer": idp_uri,
			"authorization_endpoint": format!("{idp_uri}/v1/authorize"),
			"token_endpoint": format!("{idp_uri}/v1/token"),
		})))
		.mount(&idp)
		.await;
	Mock::given(method("POST"))
		.and(path("/v1/token"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"access_token": "okta-access-token",
			"token_type": "Bearer",
			"expires_in": 3600,
		})))
		.mount(&idp)
		.await;

	let auth = test_mcp_auth_with_provider(&idp_uri, "gw-okta", Some(McpIDP::Okta {}));
	let client = policy_client();

	let mut reg = build_request(
		Method::POST,
		"https://gw.example/client-registration",
		Some(registration_body()),
	);
	let reg_json = read_response_json(
		auth::client_registration(&mut reg, &auth, client.clone())
			.await
			.expect("reg"),
	)
	.await;
	let client_id = reg_json["client_id"].as_str().unwrap().to_string();
	let client_secret = reg_json["client_secret"].as_str().unwrap().to_string();

	let verifier = "okta-pkce-verifier-value-12345";
	let challenge = s256_challenge(verifier);
	let auth_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/authorize\
		?client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&response_type=code&state=okta-s1&code_challenge={challenge}&code_challenge_method=S256"
	);
	let mut auth_req = build_request(Method::GET, &auth_uri, None);
	let auth_resp = oidc_proxy::proxy_authorize(&mut auth_req, &auth, client.clone())
		.await
		.expect("authorize");
	assert_eq!(auth_resp.status(), StatusCode::FOUND);
	let idp_redirect = redirect_location(&auth_resp).expect("redirect");
	assert!(
		idp_redirect.contains("/v1/authorize?"),
		"Okta should use /v1/authorize (from metadata discovery via RFC 8414)"
	);

	let gw_state = query_param(&idp_redirect, "state").unwrap();
	let cb_uri = format!(
		"https://gw.example/.well-known/oauth-authorization-server/callback?code=okta-code&state={gw_state}"
	);
	let mut cb = build_request(Method::GET, &cb_uri, None);
	let cbr = oidc_proxy::proxy_callback(&mut cb, &auth, client.clone())
		.await
		.expect("callback");
	let proxy_code = query_param(redirect_location(&cbr).as_deref().unwrap(), "code").unwrap();

	let form = format!(
		"grant_type=authorization_code&code={proxy_code}\
		&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
		&code_verifier={verifier}\
		&client_id={client_id}&client_secret={client_secret}"
	);
	let mut tok = build_form_request(
		"https://gw.example/.well-known/oauth-authorization-server/token",
		&form,
	);
	let tok_resp = oidc_proxy::proxy_token(&mut tok, &auth, client.clone())
		.await
		.expect("token");
	assert_eq!(tok_resp.status(), StatusCode::OK);
	let tok_json = read_response_json(tok_resp).await;
	assert_eq!(tok_json["access_token"], "okta-access-token");

	let received = idp.received_requests().await.expect("requests");
	let metadata_req = received
		.iter()
		.find(|r| r.url.path() == "/.well-known/oauth-authorization-server")
		.expect("metadata request should use RFC 8414 path");
	assert_eq!(metadata_req.method.as_str(), "GET");
}

#[tokio::test]
async fn okta_as_metadata_prepends_audience_to_authorization_endpoint() {
	let idp = MockServer::start().await;
	let idp_uri = idp.uri();

	Mock::given(method("GET"))
		.and(path("/.well-known/oauth-authorization-server"))
		.respond_with(ResponseTemplate::new(200).set_body_json(json!({
			"issuer": idp_uri,
			"authorization_endpoint": format!("{idp_uri}/v1/authorize"),
			"token_endpoint": format!("{idp_uri}/v1/token"),
		})))
		.mount(&idp)
		.await;

	let mut auth = test_mcp_auth_with_provider(&idp_uri, "gw-okta-aud", Some(McpIDP::Okta {}));
	auth.audiences = vec!["urn:okta:audience".into()];
	auth.oidc_proxy = None;
	let client = policy_client();

	let mut req = build_request(
		Method::GET,
		"https://gw.example/.well-known/oauth-authorization-server",
		None,
	);
	let resp = auth::authorization_server_metadata(&mut req, &auth, client)
		.await
		.expect("as metadata");
	assert_eq!(resp.status(), StatusCode::OK);
	let json = read_response_json(resp).await;

	let authz_ep = json["authorization_endpoint"].as_str().unwrap();
	assert!(
		authz_ep.contains("?audience=urn:okta:audience"),
		"Okta authorization_endpoint must include audience parameter, got: {authz_ep}"
	);
}

#[test]
fn okta_jwks_url_uses_v1_keys() {
	use crate::types::agent::LocalMcpAuthentication;

	let config: LocalMcpAuthentication = serde_json::from_value(json!({
		"issuer": "https://dev-xxx.okta.com/oauth2/default",
		"audiences": ["urn:test"],
		"provider": { "okta": {} },
		"resourceMetadata": {},
		"jwks": { "url": "https://placeholder.invalid/to-be-overridden" }
	}))
	.expect("deserialize");

	let jwt_cfg = config.as_jwt().expect("as_jwt");
	match jwt_cfg {
		crate::http::jwt::LocalJwtConfig::Single { jwks, .. } => match jwks {
			crate::serdes::FileInlineOrRemote::Remote { url } => {
				let url_str = url.to_string();
				assert!(
					url_str.contains("/v1/keys") || url_str.contains("placeholder"),
					"Okta JWKS URL should be derived from issuer with /v1/keys when URL is empty; got: {url_str}"
				);
			},
			other => panic!("expected Remote jwks, got {other:?}"),
		},
		other => panic!("expected Single config, got {other:?}"),
	}
}

#[test]
fn okta_provider_deserializes_from_config() {
	use crate::types::agent::LocalMcpAuthentication;

	let config: LocalMcpAuthentication = serde_json::from_value(json!({
		"issuer": "https://dev-xxx.okta.com",
		"audiences": ["urn:test"],
		"provider": { "okta": {} },
		"resourceMetadata": {},
		"jwks": { "url": "https://dev-xxx.okta.com/v1/keys" }
	}))
	.expect("deserialize okta provider");
	assert!(matches!(config.provider, Some(McpIDP::Okta {})));
}

#[test]
fn issuer_mismatch_produces_deterministic_jwt_error() {
	let jwks: jsonwebtoken::jwk::JwkSet =
		serde_json::from_str(TEST_JWKS_JSON).expect("test jwks");
	let result = jwt::Provider::from_jwks(
		jwks,
		"https://wrong-issuer.example".to_string(),
		Some(vec!["urn:correct-audience".into()]),
		jwt::JWTValidationOptions::default(),
	);
	assert!(result.is_ok(), "provider creation should succeed regardless of issuer");

	let validator = jwt::Jwt::from_providers(
		vec![result.unwrap()],
		jwt::Mode::Strict,
	);

	let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
	header.kid = Some("kid-1".into());
	let token = jsonwebtoken::encode(
		&header,
		&json!({
			"iss": "https://attacker.example",
			"aud": "urn:correct-audience",
			"exp": crate::http::oidc::now_unix() + 600,
			"sub": "user"
		}),
		&jsonwebtoken::EncodingKey::from_ec_pem(
			b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgltxBTVDLg7C6vE1T\n7OtwJIZ/dpm8ygE2MBTjPCY3hgahRANCAARYzu50EeBrT0rELmTGroaGtn0zdjxL\n1lOGr9fGw5wOGcXO0+Gn5F5sIxGyTM0FwnUHFNz2SoixZR5dtxhNc+Lo\n-----END PRIVATE KEY-----\n",
		)
		.expect("key"),
	)
	.expect("token");

	let err = validator.validate_claims(&token);
	assert!(err.is_err(), "mismatched issuer must fail validation");
}

#[test]
fn audience_mismatch_produces_deterministic_jwt_error() {
	let jwks: jsonwebtoken::jwk::JwkSet =
		serde_json::from_str(TEST_JWKS_JSON).expect("test jwks");
	let provider = jwt::Provider::from_jwks(
		jwks,
		"https://idp.example".to_string(),
		Some(vec!["urn:expected-audience".into()]),
		jwt::JWTValidationOptions::default(),
	)
	.expect("provider");
	let validator = jwt::Jwt::from_providers(vec![provider], jwt::Mode::Strict);

	let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
	header.kid = Some("kid-1".into());
	let token = jsonwebtoken::encode(
		&header,
		&json!({
			"iss": "https://idp.example",
			"aud": "urn:wrong-audience",
			"exp": crate::http::oidc::now_unix() + 600,
			"sub": "user"
		}),
		&jsonwebtoken::EncodingKey::from_ec_pem(
			b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgltxBTVDLg7C6vE1T\n7OtwJIZ/dpm8ygE2MBTjPCY3hgahRANCAARYzu50EeBrT0rELmTGroaGtn0zdjxL\n1lOGr9fGw5wOGcXO0+Gn5F5sIxGyTM0FwnUHFNz2SoixZR5dtxhNc+Lo\n-----END PRIVATE KEY-----\n",
		)
		.expect("key"),
	)
	.expect("token");

	let err = validator.validate_claims(&token);
	assert!(err.is_err(), "mismatched audience must fail validation");
}
