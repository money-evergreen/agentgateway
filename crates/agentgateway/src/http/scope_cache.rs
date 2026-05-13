use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::sync::RwLock;
use tracing::{info, info_span, warn, Instrument};

use crate::types::fallback::EnduserScopeSource;

#[derive(Debug, Clone)]
pub struct ScopeCache {
	scopes: Arc<RwLock<Vec<String>>>,
}

impl ScopeCache {
	pub async fn new(config: EnduserScopeSource) -> Self {
		let scopes = Arc::new(RwLock::new(Vec::new()));

		let initial = fetch_scopes(&config).await;
		match initial {
			Ok(s) => {
				info!(scopes_count = s.len(), "scope cache initialized");
				*scopes.write().await = s;
			},
			Err(e) => {
				warn!(error = %e, "scope cache initialization failed, starting with empty scopes");
			},
		}

		let scopes_clone = scopes.clone();
		let interval = Duration::from_secs(config.refresh_interval_secs);
		tokio::spawn(
			async move {
				let mut tick = tokio::time::interval(interval);
				tick.tick().await;
				loop {
					tick.tick().await;
					match fetch_scopes(&config).await {
						Ok(s) => {
							info!(scopes_count = s.len(), "scope cache refreshed");
							*scopes_clone.write().await = s;
						},
						Err(e) => {
							warn!(error = %e, "scope cache refresh failed");
						},
					}
				}
			}
			.instrument(info_span!("scope_cache_refresh")),
		);

		Self { scopes }
	}

	pub async fn get_scopes(&self) -> Vec<String> {
		self.scopes.read().await.clone()
	}
}

async fn fetch_scopes(config: &EnduserScopeSource) -> anyhow::Result<Vec<String>> {
	let client_id = std::env::var(&config.client_id_env)
		.map_err(|_| anyhow::anyhow!("env var {} not set", config.client_id_env))?;
	let client_secret = std::env::var(&config.client_secret_env)
		.map_err(|_| anyhow::anyhow!("env var {} not set", config.client_secret_env))?;

	let http = reqwest::Client::new();
	let mut params = vec![
		("grant_type".to_string(), "client_credentials".to_string()),
		("client_id".to_string(), client_id),
		("client_secret".to_string(), client_secret),
	];
	if !config.scopes.is_empty() {
		params.push(("scope".to_string(), config.scopes.join(" ")));
	}
	let resp = http
		.post(&config.token_endpoint)
		.form(&params)
		.send()
		.await?;

	if !resp.status().is_success() {
		anyhow::bail!(
			"token endpoint returned status {}",
			resp.status()
		);
	}

	let body: Map<String, Value> = resp.json().await?;

	let access_token = body
		.get("access_token")
		.and_then(|v| v.as_str())
		.ok_or_else(|| anyhow::anyhow!("no access_token in response"))?;

	extract_scopes_from_jwt(access_token)
}

fn extract_scopes_from_jwt(token: &str) -> anyhow::Result<Vec<String>> {
	let parts: Vec<&str> = token.split('.').collect();
	if parts.len() < 2 {
		anyhow::bail!("invalid JWT format");
	}

	use base64::Engine;
	let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
	let claims: Map<String, Value> = serde_json::from_slice(&payload_bytes)?;

	match claims.get("scp") {
		Some(Value::Array(arr)) => Ok(arr
			.iter()
			.filter_map(|v| v.as_str().map(String::from))
			.collect()),
		Some(Value::String(s)) => Ok(s.split_whitespace().map(String::from).collect()),
		_ => Ok(vec![]),
	}
}
