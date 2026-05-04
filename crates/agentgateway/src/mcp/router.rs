use std::sync::Arc;

use agent_core::prelude::Strng;
use axum::response::Response;
use tracing::{debug, info, warn};

use crate::ProxyInputs;
use crate::http::authorization::RuleSets;
use crate::http::gateway_proof::GatewayProof;
use crate::http::sessionpersistence::Encoder;
use crate::http::*;
use crate::mcp::FailureMode;
use crate::mcp::auth;
use crate::mcp::handler::RelayInputs;
use crate::mcp::list_cache::{self, ListCacheManager};
use crate::mcp::session::SessionManager;
use crate::mcp::sse::LegacySSEService;
use crate::mcp::streamablehttp::{StreamableHttpServerConfig, StreamableHttpService};
use crate::mcp::upstream::IncomingRequestContext;
use crate::mcp::{MCPInfo, McpAuthorizationSet};
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::{MustSnapshot, PolicyClient};
use crate::store::{BackendPolicies, Stores};
use crate::telemetry::log::RequestLog;
use crate::types::agent::{
	Backend, BackendTargetRef, McpBackend, McpTargetSpec, ResourceName, SimpleBackend,
	SimpleBackendReference,
};

#[derive(Debug, Clone)]
pub struct App {
	state: Stores,
	session: Arc<SessionManager>,
	list_cache_manager: ListCacheManager,
}

impl App {
	pub fn new(state: Stores, encoder: Encoder) -> Self {
		let session: Arc<SessionManager> = Arc::new(crate::mcp::session::SessionManager::new(encoder));
		Self {
			state,
			session,
			list_cache_manager: ListCacheManager::new(),
		}
	}

	pub fn should_passthrough(
		&self,
		backend_policies: &BackendPolicies,
		backend: &McpBackend,
		req: &Request,
	) -> Option<SimpleBackendReference> {
		if backend.targets.len() != 1 {
			return None;
		}

		if backend_policies.mcp_authentication.is_some() {
			return None;
		}
		if !req.uri().path().contains("/.well-known/") {
			return None;
		}
		match backend.targets.first().map(|t| &t.spec) {
			Some(McpTargetSpec::Mcp(s)) => Some(s.backend.clone()),
			Some(McpTargetSpec::Sse(s)) => Some(s.backend.clone()),
			_ => None,
		}
	}

	#[allow(clippy::too_many_arguments)]
	pub async fn serve(
		&self,
		pi: Arc<ProxyInputs>,
		backend_group_name: ResourceName,
		backend: McpBackend,
		backend_policies: BackendPolicies,
		mut req: MustSnapshot<'_>,
		mut log: &mut RequestLog,
		gateway_proof: Option<GatewayProof>,
	) -> Result<Response, ProxyError> {
		let backends = {
			let binds = self.state.read_binds();
			let nt = backend
				.targets
				.iter()
				.map(|t| {
					let be = t
						.spec
						.backend()
						.map(|b| crate::proxy::resolve_simple_backend_with_policies(b, &pi))
						.transpose()?;
					let inline_pols = be.as_ref().map(|pol| pol.inline_policies.as_slice());
					let sub_backend_target = BackendTargetRef::Backend {
						name: backend_group_name.name.as_ref(),
						namespace: backend_group_name.namespace.as_ref(),
						section: Some(t.name.as_ref()),
					};
					let backend_policies = backend_policies
						.clone()
						.merge(binds.sub_backend_policies(sub_backend_target, inline_pols));
					Ok::<_, ProxyError>(Arc::new(McpTarget {
						name: t.name.clone(),
						spec: t.spec.clone(),
						backend: be.map(|b| b.backend),
						backend_policies,
						always_use_prefix: backend.always_use_prefix,
					}))
				})
				.collect::<Result<Vec<_>, _>>()?;

			McpBackendGroup {
				targets: nt,
				stateful: backend.stateful,
				failure_mode: backend.failure_mode,
			}
		};
		let sm = self.session.clone();
		let client = PolicyClient { inputs: pi.clone() };
		let authorization_policies = backend_policies
			.mcp_authorization
			.unwrap_or_else(|| McpAuthorizationSet::new(RuleSets::from(Vec::new())));
		let authn = backend_policies.mcp_authentication;
		let list_cache = self
			.list_cache_manager
			.get_or_create(backend_group_name.name.as_ref());

		// Store an empty value, we will populate each field async
		let logy = log.mcp_status.clone();
		logy.store(Some(MCPInfo::default()));
		req.extensions_mut().insert(logy);
		let tracer = log.span_writer();
		req.extensions_mut().insert(tracer);

		authorization_policies.register(log.cel.ctx());
		log.cel.ctx().maybe_buffer_request_body(&mut req).await;

		// `response` is not valid here, since we run authz first
		// MCP context is added later. The context is inserted after
		// authentication so it can include verified claims

		if let Some(auth) = authn.as_ref() {
			if let Some(resp) = auth::enforce_authentication(&mut req, auth, &client).await? {
				return Ok(resp);
			}
		} else if let Some(resp) = auth::handle_mcp_request_unauthenticated(&mut req).await? {
			return Ok(resp);
		}

		// MCP requires CEL execution after the snapshot so we do not clear extensions
		let req = req.take_and_snapshot_without_clearing_extensions(Some(&mut log))?;
		if req.uri().path() == "/sse" {
			// Legacy handling
			// Assume this is streamable HTTP otherwise
			let sse = LegacySSEService::new(sm);
			Box::pin(sse.handle(
				req,
				RelayInputs {
					backend: backends.clone(),
					policies: authorization_policies.clone(),
					client: client.clone(),
					list_cache: list_cache.clone(),
					gateway_proof: gateway_proof.clone(),
				},
			))
			.await
		} else {
			let streamable = StreamableHttpService::new(
				sm,
				StreamableHttpServerConfig {
					stateful_mode: backend.stateful,
				},
			);
			Box::pin(streamable.handle(
				req,
				RelayInputs {
					backend: backends.clone(),
					policies: authorization_policies.clone(),
					client: client.clone(),
					list_cache: list_cache.clone(),
					gateway_proof: gateway_proof.clone(),
				},
			))
			.await
		}
	}

	/// Pre-warm list caches for all MCP backends found in the bind store.
	pub async fn warm_caches(&self, pi: Arc<ProxyInputs>) {
		let backends: Vec<(ResourceName, McpBackend)> = {
			let binds = self.state.read_binds();
			binds
				.all_backends()
				.into_iter()
				.filter_map(|bwp| match &bwp.backend {
					Backend::MCP(name, mcp) => Some((name.clone(), mcp.clone())),
					_ => None,
				})
				.collect()
		};

		if backends.is_empty() {
			info!("no MCP backends configured, skipping cache warming");
			return;
		}

		info!(
			count = backends.len(),
			"warming list caches for MCP backends"
		);

		for (name, mcp_backend) in backends {
			let backend_name = name.name.to_string();
			match tokio::time::timeout(
				std::time::Duration::from_secs(10),
				self.warm_single_backend(&pi, name, mcp_backend),
			)
			.await
			{
				Ok(Ok(())) => info!(backend = %backend_name, "cache warmed"),
				Ok(Err(e)) => warn!(backend = %backend_name, error = %e, "cache warming failed, will warm on first request"),
				Err(_) => warn!(backend = %backend_name, "cache warming timed out after 10s, will warm on first request"),
			}
		}
	}

	async fn warm_single_backend(
		&self,
		pi: &Arc<ProxyInputs>,
		backend_group_name: ResourceName,
		backend: McpBackend,
	) -> Result<(), anyhow::Error> {
		use rmcp::model::{
			ClientInfo, ClientRequest, Implementation, JsonRpcRequest, ProtocolVersion, RequestId,
		};

		let backends = {
			let binds = self.state.read_binds();
			let nt = backend
				.targets
				.iter()
				.map(|t| {
					let be = t
						.spec
						.backend()
						.map(|b| crate::proxy::resolve_simple_backend_with_policies(b, pi))
						.transpose()?;
					let inline_pols = be.as_ref().map(|pol| pol.inline_policies.as_slice());
					let sub_backend_target = BackendTargetRef::Backend {
						name: backend_group_name.name.as_ref(),
						namespace: backend_group_name.namespace.as_ref(),
						section: Some(t.name.as_ref()),
					};
					let backend_policies = BackendPolicies::default()
						.merge(binds.sub_backend_policies(sub_backend_target, inline_pols));
					Ok::<_, ProxyError>(Arc::new(McpTarget {
						name: t.name.clone(),
						spec: t.spec.clone(),
						backend: be.map(|b| b.backend),
						backend_policies,
						always_use_prefix: backend.always_use_prefix,
					}))
				})
				.collect::<Result<Vec<_>, _>>()?;

			McpBackendGroup {
				targets: nt,
				stateful: backend.stateful,
				failure_mode: backend.failure_mode,
			}
		};

		let list_cache = self
			.list_cache_manager
			.get_or_create(backend_group_name.name.as_ref());
		let client = PolicyClient { inputs: pi.clone() };
		let empty_policies = McpAuthorizationSet::new(RuleSets::from(Vec::new()));

		let relay = RelayInputs {
			backend: backends,
			policies: empty_policies,
			client,
			list_cache,
			gateway_proof: None,
		}
		.build_new_connections()?;

		let ctx = IncomingRequestContext::empty();

		let mut client_info = ClientInfo::default();
		client_info.protocol_version = ProtocolVersion::V_2025_06_18;
		client_info.client_info = Implementation::new("agentgateway-cache-warmer", "1.0");
		let init_request = JsonRpcRequest {
			jsonrpc: Default::default(),
			id: RequestId::Number(0),
			request: ClientRequest::InitializeRequest(
				rmcp::model::InitializeRequest::new(client_info),
			),
		};
		let _init_resp = relay
			.send_fanout_tolerant(init_request, ctx.clone(), relay.merge_initialize(ProtocolVersion::V_2025_06_18, relay.is_multiplexing()))
			.await
			.map_err(|e| anyhow::anyhow!("initialize failed: {e}"))?;

		let list_methods: &[&str] = &[
			list_cache::TOOLS_LIST,
			list_cache::PROMPTS_LIST,
			list_cache::RESOURCES_LIST,
			list_cache::RESOURCE_TEMPLATES_LIST,
		];

		for method in list_methods {
			let cel = crate::mcp::rbac::CelExecWrapper::empty();
			let (merge, request) = match *method {
				list_cache::TOOLS_LIST => (
					relay.merge_tools(cel),
					ClientRequest::ListToolsRequest(Default::default()),
				),
				list_cache::PROMPTS_LIST => (
					relay.merge_prompts(cel),
					ClientRequest::ListPromptsRequest(Default::default()),
				),
				list_cache::RESOURCES_LIST => (
					relay.merge_resources(cel),
					ClientRequest::ListResourcesRequest(Default::default()),
				),
				list_cache::RESOURCE_TEMPLATES_LIST => (
					relay.merge_resource_templates(cel),
					ClientRequest::ListResourceTemplatesRequest(Default::default()),
				),
				_ => unreachable!(),
			};
			let rpc_request = JsonRpcRequest {
				jsonrpc: Default::default(),
				id: RequestId::Number(1),
				request,
			};
			let caching = relay.caching_merge(method, merge);
			match relay
				.send_fanout_tolerant(rpc_request, ctx.clone(), caching)
				.await
			{
				Ok(_) => debug!(method, "cached list response"),
				Err(e) => warn!(method, error = %e, "failed to cache list response"),
			}
		}

		Ok(())
	}
}

#[derive(Debug, Clone)]
pub struct McpBackendGroup {
	pub targets: Vec<Arc<McpTarget>>,
	pub stateful: bool,
	pub failure_mode: FailureMode,
}

#[derive(Debug)]
pub struct McpTarget {
	pub name: Strng,
	pub spec: crate::types::agent::McpTargetSpec,
	pub backend_policies: BackendPolicies,
	pub backend: Option<SimpleBackend>,
	pub always_use_prefix: bool,
}
