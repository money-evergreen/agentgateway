use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use agent_core::prelude::Strng;
use rmcp::model::ServerResult;

const DEFAULT_TTL: Duration = Duration::from_secs(300);

pub const TOOLS_LIST: &str = "tools/list";
pub const PROMPTS_LIST: &str = "prompts/list";
pub const RESOURCES_LIST: &str = "resources/list";
pub const RESOURCE_TEMPLATES_LIST: &str = "resources/templates/list";

#[derive(Debug, Clone)]
struct CachedEntry {
	raw_results: Vec<(Strng, ServerResult)>,
	cached_at: Instant,
}

#[derive(Debug)]
pub struct ListCache {
	entries: RwLock<HashMap<String, CachedEntry>>,
	ttl: Duration,
}

impl ListCache {
	pub fn new() -> Self {
		Self {
			entries: RwLock::new(HashMap::new()),
			ttl: DEFAULT_TTL,
		}
	}

	pub fn get_raw(&self, method: &str) -> Option<Vec<(Strng, ServerResult)>> {
		let entries = self.entries.read().ok()?;
		let entry = entries.get(method)?;
		if entry.cached_at.elapsed() < self.ttl {
			Some(entry.raw_results.clone())
		} else {
			None
		}
	}

	pub fn set_raw(&self, method: &str, raw_results: Vec<(Strng, ServerResult)>) {
		if let Ok(mut entries) = self.entries.write() {
			entries.insert(
				method.to_string(),
				CachedEntry {
					raw_results,
					cached_at: Instant::now(),
				},
			);
		}
	}

	#[allow(dead_code)]
	pub fn invalidate(&self, method: &str) {
		if let Ok(mut entries) = self.entries.write() {
			entries.remove(method);
		}
	}

	#[allow(dead_code)]
	pub fn invalidate_all(&self) {
		if let Ok(mut entries) = self.entries.write() {
			entries.clear();
		}
	}
}

/// Manages per-backend-group list caches, shared across all sessions.
#[derive(Debug, Clone)]
pub struct ListCacheManager {
	caches: Arc<RwLock<HashMap<String, Arc<ListCache>>>>,
}

impl ListCacheManager {
	pub fn new() -> Self {
		Self {
			caches: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	pub fn get_or_create(&self, backend_group: &str) -> Arc<ListCache> {
		if let Ok(caches) = self.caches.read() {
			if let Some(cache) = caches.get(backend_group) {
				return cache.clone();
			}
		}
		let mut caches = self.caches.write().expect("write lock");
		caches
			.entry(backend_group.to_string())
			.or_insert_with(|| Arc::new(ListCache::new()))
			.clone()
	}
}
