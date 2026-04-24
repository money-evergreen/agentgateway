use std::sync::Arc;

use jsonwebtoken::jwk::JwkSet;
use macro_rules_attribute::apply;
use secrecy::SecretString;

use super::{
	ClientConfig, CookieSecureMode, Error, OidcPolicy, PolicyId, Provider, ProviderEndpoint,
	RedirectUri, SameSiteMode, SessionConfig, dedupe_scopes, session,
};
use crate::client::Client;
use crate::http::oauth::{
	TokenEndpointAuth, openid_configuration_metadata_url, parse_token_endpoint_auth_methods,
};
use crate::schema_de;
use crate::serdes::FileInlineOrRemote;

#[derive(Debug, serde::Deserialize)]
struct OidcDiscoveryDocument {
	issuer: String,
	authorization_endpoint: String,
	token_endpoint: String,
	jwks_uri: String,
	#[serde(default)]
	token_endpoint_auth_methods_supported: Option<Vec<String>>,
	#[serde(default)]
	end_session_endpoint: Option<String>,
}

struct PreparedOidcProvider {
	issuer: String,
	authorization_endpoint: ProviderEndpoint,
	token_endpoint: ProviderEndpoint,
	token_endpoint_auth: TokenEndpointAuth,
	id_token_jwks: JwkSet,
	end_session_endpoint: Option<ProviderEndpoint>,
}

struct PreparedOidcPolicy {
	provider: PreparedOidcProvider,
	client_id: String,
	client_secret: SecretString,
	redirect_uri: RedirectUri,
	scopes: Vec<String>,
	logout_path: Option<String>,
	post_logout_redirect_uri: Option<String>,
	login_page: Option<String>,
	login_page_path: Option<String>,
}

/// Browser-based OIDC authentication policy.
///
/// Explicit mode is still OIDC: it supplies provider metadata manually instead of using discovery.
/// Unauthenticated non-callback requests always redirect to the provider login flow. Routes that
/// need non-redirect authentication behavior should use a different auth policy.
#[apply(schema_de!)]
pub struct LocalOidcConfig {
	/// Issuer used for discovery and ID token validation.
	pub issuer: String,

	/// Optional discovery document override. If omitted, discovery uses
	/// `${issuer}/.well-known/openid-configuration`.
	#[serde(default)]
	pub discovery: Option<FileInlineOrRemote>,

	/// Authorization endpoint used to start the browser login flow.
	#[serde(default)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	pub authorization_endpoint: Option<ProviderEndpoint>,

	/// Token endpoint used to exchange the authorization code.
	#[serde(default)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	pub token_endpoint: Option<ProviderEndpoint>,

	/// Token endpoint client authentication method for explicit provider configuration.
	///
	/// Discovery mode derives this from provider metadata. Explicit mode defaults to
	/// `clientSecretBasic` when omitted.
	#[serde(default)]
	pub token_endpoint_auth: Option<TokenEndpointAuth>,

	/// JWKS source used to validate returned ID tokens.
	#[serde(default)]
	pub jwks: Option<FileInlineOrRemote>,

	/// OAuth2 client identifier used for authorization and token exchange.
	pub client_id: String,

	/// OAuth2 client secret used for token exchange.
	#[serde(serialize_with = "crate::serdes::ser_redact")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	pub client_secret: SecretString,

	/// Absolute callback URI handled by the gateway.
	/// This policy always redirects unauthenticated non-callback requests back through this login
	/// flow.
	#[serde(rename = "redirectURI")]
	pub redirect_uri: String,

	/// Additional OAuth2 scopes to request. `openid` is always included.
	#[serde(default)]
	pub scopes: Vec<String>,

	/// Provider's end-session endpoint for RP-Initiated Logout.
	/// Discovered automatically; set explicitly only when using explicit provider config.
	#[serde(default)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	pub end_session_endpoint: Option<ProviderEndpoint>,

	/// Path that triggers logout. Defaults to deriving from redirectURI
	/// (e.g. redirectURI "/ui/oauth/callback" → logout path "/ui/logout").
	#[serde(default)]
	pub logout_path: Option<String>,

	/// Where to redirect after the provider clears its session.
	/// If omitted, defaults to "/".
	#[serde(default, rename = "postLogoutRedirectURI")]
	pub post_logout_redirect_uri: Option<String>,

	/// Optional HTML page served on a dedicated public path (see loginPagePath).
	/// The page should contain a link or button that navigates to an
	/// OIDC-protected path (e.g. /ui) to trigger the login redirect.
	#[serde(default)]
	pub login_page: Option<String>,

	/// Path where the login page is served. Defaults to "/signin".
	/// Only used when loginPage is configured.
	#[serde(default)]
	pub login_page_path: Option<String>,
}

struct DiscoveredProviderMetadata {
	authorization_endpoint: ProviderEndpoint,
	token_endpoint: ProviderEndpoint,
	token_endpoint_auth: TokenEndpointAuth,
	jwks: FileInlineOrRemote,
	end_session_endpoint: Option<ProviderEndpoint>,
}

impl LocalOidcConfig {
	pub(crate) async fn compile(
		self,
		client: Client,
		policy_id: PolicyId,
		oidc_cookie_encoder: &crate::http::sessionpersistence::Encoder,
	) -> Result<OidcPolicy, Error> {
		self
			.resolve(client)
			.await?
			.compile(policy_id, oidc_cookie_encoder)
	}

	async fn resolve(self, client: Client) -> Result<PreparedOidcPolicy, Error> {
		let LocalOidcConfig {
			issuer,
			discovery,
			authorization_endpoint,
			token_endpoint,
			token_endpoint_auth,
			jwks,
			client_id,
			client_secret,
			redirect_uri,
			scopes,
			end_session_endpoint,
			logout_path,
			post_logout_redirect_uri,
			login_page,
			login_page_path,
		} = self;
		let redirect_uri = RedirectUri::parse(redirect_uri)?;
		let explicit_field_count = usize::from(authorization_endpoint.is_some())
			+ usize::from(token_endpoint.is_some())
			+ usize::from(jwks.is_some());
		if token_endpoint_auth.is_some() && explicit_field_count != 3 {
			return Err(Error::Config(
				"tokenEndpointAuth must be omitted unless authorizationEndpoint, tokenEndpoint, and jwks are configured explicitly".into(),
			));
		}
		let provider = match explicit_field_count {
			0 => {
				let discovery = match discovery {
					Some(discovery) => discovery,
					None => FileInlineOrRemote::Remote {
						url: default_discovery_url(&issuer)?,
					},
				};
				let discovered = discover_provider_metadata(client.clone(), &issuer, discovery).await?;
				let id_token_jwks = load_jwks(client, discovered.jwks, "discovered jwks source").await?;

				PreparedOidcProvider {
					issuer,
					authorization_endpoint: discovered.authorization_endpoint,
					token_endpoint: discovered.token_endpoint,
					token_endpoint_auth: discovered.token_endpoint_auth,
					id_token_jwks,
					end_session_endpoint: end_session_endpoint
						.or(discovered.end_session_endpoint),
				}
			},
			3 => {
				if discovery.is_some() {
					return Err(Error::Config(
						"oidc discovery must be omitted when authorizationEndpoint, tokenEndpoint, and jwks are configured explicitly".into(),
					));
				}
				let mut provider = resolve_explicit_provider(
					client,
					issuer,
					authorization_endpoint.expect("checked above"),
					token_endpoint.expect("checked above"),
					token_endpoint_auth.unwrap_or_default(),
					jwks.expect("checked above"),
				)
				.await?;
				provider.end_session_endpoint = end_session_endpoint;
				provider
			},
			_ => {
				return Err(Error::Config(
					"authorizationEndpoint, tokenEndpoint, and jwks must either all be set or all be omitted"
						.into(),
				));
			},
		};

		Ok(PreparedOidcPolicy {
			provider,
			client_id,
			client_secret,
			redirect_uri,
			scopes,
			logout_path,
			post_logout_redirect_uri,
			login_page,
			login_page_path,
		})
	}
}

async fn discover_provider_metadata(
	client: Client,
	issuer: &str,
	discovery: FileInlineOrRemote,
) -> Result<DiscoveredProviderMetadata, Error> {
	let document = discovery
		.load::<OidcDiscoveryDocument>(client)
		.await
		.map_err(|e| {
			Error::Config(format!(
				"failed to decode oidc discovery response from {}: {e}",
				describe_file_inline_or_remote(&discovery)
			))
		})?;
	if document.issuer != issuer {
		return Err(Error::Config(format!(
			"oidc discovery issuer mismatch: expected {issuer}, got {}",
			document.issuer
		)));
	}

	let token_endpoint_auth =
		parse_token_endpoint_auth_methods(document.token_endpoint_auth_methods_supported)
			.map_err(Error::Config)?;
	let jwks = FileInlineOrRemote::Remote {
		url: document
			.jwks_uri
			.parse()
			.map_err(|e| Error::Config(format!("invalid jwks uri: {e}")))?,
	};
	let end_session_endpoint = document
		.end_session_endpoint
		.map(|ep| {
			ep.parse()
				.map_err(|e| Error::Config(format!("invalid end_session_endpoint: {e}")))
		})
		.transpose()?;
	Ok(DiscoveredProviderMetadata {
		authorization_endpoint: document
			.authorization_endpoint
			.parse()
			.map_err(|e| Error::Config(format!("invalid authorization endpoint: {e}")))?,
		token_endpoint: document
			.token_endpoint
			.parse()
			.map_err(|e| Error::Config(format!("invalid token endpoint: {e}")))?,
		token_endpoint_auth,
		jwks,
		end_session_endpoint,
	})
}

async fn resolve_explicit_provider(
	client: Client,
	issuer: String,
	authorization_endpoint: ProviderEndpoint,
	token_endpoint: ProviderEndpoint,
	token_endpoint_auth: TokenEndpointAuth,
	jwks: FileInlineOrRemote,
) -> Result<PreparedOidcProvider, Error> {
	let id_token_jwks = load_jwks(client, jwks, "explicit jwks source").await?;

	Ok(PreparedOidcProvider {
		issuer,
		authorization_endpoint,
		token_endpoint,
		token_endpoint_auth,
		id_token_jwks,
		end_session_endpoint: None,
	})
}

fn default_discovery_url(issuer: &str) -> Result<http::Uri, Error> {
	openid_configuration_metadata_url(issuer)
		.parse()
		.map_err(|e| {
			Error::Config(format!(
				"invalid discovery uri derived from issuer '{issuer}': {e}"
			))
		})
}

async fn load_jwks(
	client: Client,
	jwks: FileInlineOrRemote,
	source: &'static str,
) -> Result<JwkSet, Error> {
	let jwks = jwks.load::<JwkSet>(client).await.map_err(|e| {
		Error::Config(format!(
			"failed to load oidc jwks from {} {}: {e}",
			source,
			describe_file_inline_or_remote(&jwks)
		))
	})?;
	Ok(jwks)
}

impl PreparedOidcProvider {
	fn compile(self, client_id: String) -> Result<Provider, Error> {
		let provider = crate::http::jwt::Provider::from_jwks(
			self.id_token_jwks,
			self.issuer.clone(),
			Some(vec![client_id]),
			crate::http::jwt::JWTValidationOptions::default(),
		)
		.map_err(|e| Error::Config(format!("failed to create id token validator: {e}")))?;

		Ok(Provider {
			issuer: self.issuer,
			authorization_endpoint: self.authorization_endpoint,
			token_endpoint: self.token_endpoint,
			id_token_validator: crate::http::jwt::Jwt::from_providers(
				vec![provider],
				crate::http::jwt::Mode::Strict,
			),
		})
	}
}

impl PreparedOidcPolicy {
	fn compile(
		self,
		policy_id: PolicyId,
		oidc_cookie_encoder: &crate::http::sessionpersistence::Encoder,
	) -> Result<OidcPolicy, Error> {
		let (cookie_name, transaction_cookie_prefix) = session::derive_cookie_names(&policy_id);
		let PreparedOidcPolicy {
			provider,
			client_id,
			client_secret,
			redirect_uri,
			scopes,
			logout_path,
			post_logout_redirect_uri,
			login_page,
			login_page_path,
		} = self;
		let scopes = dedupe_scopes(scopes);
		let end_session_endpoint = provider.end_session_endpoint.clone();
		let token_endpoint_auth = provider.token_endpoint_auth;
		let provider = Arc::new(provider.compile(client_id.clone())?);

		let logout_path = match logout_path {
			Some(explicit) => {
				let parsed = explicit
					.parse::<http::uri::PathAndQuery>()
					.map_err(|e| Error::Config(format!("invalid logoutPath: {e}")))?;
				Some(parsed)
			},
			None => derive_logout_path(&redirect_uri),
		};

		let post_logout_redirect_uri =
			post_logout_redirect_uri.unwrap_or_else(|| "/".into());

		let login_page_path = match (&login_page, login_page_path) {
			(Some(_), Some(explicit)) => {
				let parsed = explicit
					.parse::<http::uri::PathAndQuery>()
					.map_err(|e| Error::Config(format!("invalid loginPagePath: {e}")))?;
				Some(parsed)
			},
			(Some(_), None) => Some("/signin".parse().expect("default login page path")),
			(None, _) => None,
		};

		Ok(OidcPolicy {
			policy_id,
			provider,
			client: ClientConfig {
				client_id,
				client_secret,
				token_endpoint_auth,
			},
			redirect_uri,
			session: SessionConfig {
				cookie_name,
				transaction_cookie_prefix,
				same_site: SameSiteMode::Lax,
				secure: CookieSecureMode::Auto,
				ttl: session::default_session_ttl(),
				transaction_ttl: session::default_transaction_ttl(),
				encoder: oidc_cookie_encoder.clone(),
			},
			scopes,
			end_session_endpoint,
			logout_path,
			post_logout_redirect_uri,
			login_page,
			login_page_path,
		})
	}
}

/// Derive a default logout path from the redirect URI.
/// Given a callback path like `/ui/oauth/callback`, extracts the first path segment
/// and appends `/logout` (e.g. `/ui/logout`).
fn derive_logout_path(redirect_uri: &RedirectUri) -> Option<http::uri::PathAndQuery> {
	let path = redirect_uri.callback_path.path();
	let first_segment = path
		.trim_start_matches('/')
		.split('/')
		.next()
		.filter(|s| !s.is_empty())?;
	let logout = format!("/{first_segment}/logout");
	logout.parse().ok()
}

fn describe_file_inline_or_remote(source: &FileInlineOrRemote) -> String {
	match source {
		FileInlineOrRemote::File { file } => format!("file '{}'", file.display()),
		FileInlineOrRemote::Inline(_) => "inline configuration".into(),
		FileInlineOrRemote::Remote { url } => format!("uri '{url}'"),
	}
}
