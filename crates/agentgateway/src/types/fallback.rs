use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackValidator {
	pub public_key_env: String,
	pub audiences: Vec<String>,
	pub claims_mapping: ClaimsMapping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimsMapping {
	pub sub: String,
	pub auth_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnduserScopeSource {
	pub token_endpoint: String,
	pub client_id_env: String,
	pub client_secret_env: String,
	#[serde(default)]
	pub scopes: Vec<String>,
	#[serde(default = "default_refresh_interval")]
	pub refresh_interval_secs: u64,
}

fn default_refresh_interval() -> u64 {
	300
}
