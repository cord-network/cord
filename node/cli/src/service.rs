// This file is part of CORD – https://cord.network

// Copyright (C) Dhiway Networks Pvt. Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later

// CORD is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// CORD is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with CORD. If not, see <https://www.gnu.org/licenses/>.

//! Service and ServiceFactory implementation. Specialized wrapper over
//! substrate service.
#![allow(missing_docs)]
#![deny(unused_results)]

use crate::cli::Cli;

#[cfg(feature = "full-node")]
use {
	sc_client_api::BlockBackend,
	sc_consensus_grandpa::{self},
};

#[cfg(feature = "full-node")]
pub use {
	sc_client_api::AuxStore,
	sp_authority_discovery::AuthorityDiscoveryApi,
	sp_blockchain::{HeaderBackend, HeaderMetadata},
	sp_consensus_babe::BabeApi,
};

use sc_service::RpcHandlers;
use sc_telemetry::TelemetryWorker;
use std::{path::Path, sync::Arc};

#[cfg(feature = "full-node")]
use sc_telemetry::Telemetry;

pub use crate::{
	chain_spec::{BraidChainSpec, GenericChainSpec, LoomChainSpec, WeaveChainSpec},
	fake_runtime_api::{GetLastTimestamp, RuntimeApi},
};
pub use cord_primitives::Block;
use frame_benchmarking_cli::SUBSTRATE_REFERENCE_HARDWARE;
use sc_client_api::Backend as BackendT;
pub use sc_consensus::{BlockImport, LongestChain};
pub use sc_executor::NativeExecutionDispatch;
use sc_executor::{HeapAllocStrategy, WasmExecutor, DEFAULT_HEAP_ALLOC_STRATEGY};
pub use sc_service::{
	config::{DatabaseSource, PrometheusConfig},
	ChainSpec, Configuration, Error as ServiceError, PruningMode, Role, TFullBackend,
	TFullCallExecutor, TFullClient, TaskManager, TransactionPoolOptions,
};
use sc_statement_store::Store as StatementStore;
pub use sp_api::{ApiRef, ConstructRuntimeApi, Core as CoreApi, ProvideRuntimeApi};
pub use sp_consensus::{Proposal, SelectChain};
use sp_consensus_beefy::ecdsa_crypto::AuthorityId;
pub use sp_runtime::{
	generic,
	traits::{self as runtime_traits, BlakeTwo256, Block as BlockT, Header as HeaderT, NumberFor},
};

use futures::prelude::*;
use sc_consensus_babe::{self, SlotProportion};
use sc_network::{
	event::Event, service::traits::NetworkService, NetworkBackend, NetworkEventStream,
};
use sc_network_sync::{strategy::warp::WarpSyncConfig, SyncingService};
use sc_transaction_pool::TransactionPoolHandle;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;

pub use sp_runtime::{OpaqueExtrinsic, SaturatedConversion};

#[cfg(feature = "braid-native")]
pub use {cord_braid_runtime, cord_braid_runtime_constants};
#[cfg(feature = "loom-native")]
pub use {cord_loom_runtime, cord_loom_runtime_constants};
#[cfg(feature = "weave-native")]
pub use {cord_weave_runtime, cord_weave_runtime_constants};

/// The minimum period of blocks on which justifications will be
/// imported and generated.
const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;

/// Provides the header and block number for a hash.
///
/// Decouples `sc_client_api::Backend` and `sp_blockchain::HeaderBackend`.
pub trait HeaderProvider<Block, Error = sp_blockchain::Error>: Send + Sync + 'static
where
	Block: BlockT,
	Error: std::fmt::Debug + Send + Sync + 'static,
{
	/// Obtain the header for a hash.
	fn header(
		&self,
		hash: <Block as BlockT>::Hash,
	) -> Result<Option<<Block as BlockT>::Header>, Error>;
	/// Obtain the block number for a hash.
	fn number(
		&self,
		hash: <Block as BlockT>::Hash,
	) -> Result<Option<<<Block as BlockT>::Header as HeaderT>::Number>, Error>;
}

impl<Block, T> HeaderProvider<Block> for T
where
	Block: BlockT,
	T: sp_blockchain::HeaderBackend<Block> + 'static,
{
	fn header(
		&self,
		hash: Block::Hash,
	) -> sp_blockchain::Result<Option<<Block as BlockT>::Header>> {
		<Self as sp_blockchain::HeaderBackend<Block>>::header(self, hash)
	}
	fn number(
		&self,
		hash: Block::Hash,
	) -> sp_blockchain::Result<Option<<<Block as BlockT>::Header as HeaderT>::Number>> {
		<Self as sp_blockchain::HeaderBackend<Block>>::number(self, hash)
	}
}

/// Decoupling the provider.
///
/// Mandated since `trait HeaderProvider` can only be
/// implemented once for a generic `T`.
pub trait HeaderProviderProvider<Block>: Send + Sync + 'static
where
	Block: BlockT,
{
	type Provider: HeaderProvider<Block> + 'static;

	fn header_provider(&self) -> &Self::Provider;
}

impl<Block, T> HeaderProviderProvider<Block> for T
where
	Block: BlockT,
	T: sc_client_api::Backend<Block> + 'static,
{
	type Provider = <T as sc_client_api::Backend<Block>>::Blockchain;

	fn header_provider(&self) -> &Self::Provider {
		self.blockchain()
	}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error(transparent)]
	Io(#[from] std::io::Error),

	#[error(transparent)]
	AddrFormatInvalid(#[from] std::net::AddrParseError),

	#[error(transparent)]
	Sub(#[from] ServiceError),

	#[error(transparent)]
	Blockchain(#[from] sp_blockchain::Error),

	#[error(transparent)]
	Consensus(#[from] sp_consensus::Error),

	#[error(transparent)]
	Prometheus(#[from] prometheus_endpoint::PrometheusError),

	#[error(transparent)]
	Telemetry(#[from] sc_telemetry::Error),

	#[cfg(feature = "full-node")]
	#[error("Creating a custom database is required for validators")]
	DatabasePathRequired,

	#[cfg(feature = "full-node")]
	#[error("Expected at least one of braid, loom or weave runtime feature")]
	NoRuntime,
}

/// Identifies the variant of the chain.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Chain {
	/// Braid
	Braid,
	/// Loom.
	Loom,
	/// Weave
	Weave,
	/// Unknown chain?
	Unknown,
}

pub trait IdentifyVariant {
	/// Returns `true` if this is a configuration for braid network.
	fn is_braid(&self) -> bool;

	/// Returns `true` if this is a configuration for loom network.
	fn is_loom(&self) -> bool;

	/// Returns `true` if this is a configuration for weave network.
	fn is_weave(&self) -> bool;

	/// Returns true if this configuration is for a development network.
	fn is_dev(&self) -> bool;

	/// Identifies the variant of the chain.
	fn identify_chain(&self) -> Chain;
}

impl IdentifyVariant for Box<dyn ChainSpec> {
	fn is_braid(&self) -> bool {
		self.id().starts_with("braid")
	}
	fn is_loom(&self) -> bool {
		self.id().starts_with("loom")
	}
	fn is_weave(&self) -> bool {
		self.id().starts_with("weave")
	}
	fn is_dev(&self) -> bool {
		self.id().ends_with("dev")
	}
	fn identify_chain(&self) -> Chain {
		if self.is_braid() {
			Chain::Braid
		} else if self.is_loom() {
			Chain::Loom
		} else if self.is_weave() {
			Chain::Weave
		} else {
			Chain::Unknown
		}
	}
}

/// Host functions required for runtime and node.
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions =
	(sp_io::SubstrateHostFunctions, sp_statement_store::runtime_api::HostFunctions);

/// Host functions required for runtime and node.
#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions = (
	sp_io::SubstrateHostFunctions,
	sp_statement_store::runtime_api::HostFunctions,
	frame_benchmarking::benchmarking::HostFunctions,
);

/// A specialized `WasmExecutor` intended to use across substrate node. It provides all required
/// HostFunctions.
pub type RuntimeExecutor = sc_executor::WasmExecutor<HostFunctions>;

/// The full client type definition.
#[cfg(feature = "full-node")]
pub type FullClient = sc_service::TFullClient<Block, RuntimeApi, RuntimeExecutor>;
#[cfg(feature = "full-node")]
type FullBackend = sc_service::TFullBackend<Block>;
#[cfg(feature = "full-node")]
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
#[cfg(feature = "full-node")]
type FullGrandpaBlockImport =
	sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>;
#[cfg(feature = "full-node")]
type FullBeefyBlockImport<InnerBlockImport> = sc_consensus_beefy::import::BeefyBlockImport<
	Block,
	FullBackend,
	FullClient,
	InnerBlockImport,
	AuthorityId,
>;
/// The transaction pool type defintion.
pub type TransactionPool = sc_transaction_pool::TransactionPoolHandle<Block, FullClient>;

/// Creates PartialComponents for a node.
/// Enables chain operations for cases when full node is unnecessary.
#[cfg(feature = "full-node")]
pub fn new_partial(
	config: &Configuration,
) -> Result<
	sc_service::PartialComponents<
		FullClient,
		FullBackend,
		FullSelectChain,
		sc_consensus::DefaultImportQueue<Block>,
		sc_transaction_pool::TransactionPoolHandle<Block, FullClient>,
		(
			impl Fn(
				sc_rpc::SubscriptionTaskExecutor,
			) -> Result<jsonrpsee::RpcModule<()>, sc_service::Error>,
			(
				sc_consensus_babe::BabeBlockImport<
					Block,
					FullClient,
					FullBeefyBlockImport<FullGrandpaBlockImport>,
				>,
				sc_consensus_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
				sc_consensus_babe::BabeLink<Block>,
				sc_consensus_beefy::BeefyVoterLinks<
					Block,
					sp_consensus_beefy::ecdsa_crypto::AuthorityId,
				>,
			),
			sc_consensus_grandpa::SharedVoterState,
			Option<Telemetry>,
			Arc<StatementStore>,
		),
	>,
	ServiceError,
> {
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let heap_pages = config
		.executor
		.default_heap_pages
		.map_or(DEFAULT_HEAP_ALLOC_STRATEGY, |h| HeapAllocStrategy::Static { extra_pages: h as _ });

	let executor = WasmExecutor::builder()
		.with_execution_method(config.executor.wasm_method)
		.with_onchain_heap_alloc_strategy(heap_pages)
		.with_offchain_heap_alloc_strategy(heap_pages)
		.with_max_runtime_instances(config.executor.max_runtime_instances)
		.with_runtime_cache_size(config.executor.runtime_cache_size)
		.build();

	// let executor = sc_service::new_wasm_executor(config);

	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, _>(
			config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;

	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = Arc::from(
		sc_transaction_pool::Builder::new(
			task_manager.spawn_essential_handle(),
			client.clone(),
			config.role.is_authority().into(),
		)
		.with_options(config.transaction_pool.clone())
		.with_prometheus(config.prometheus_registry())
		.build(),
	);

	// #[allow(clippy::redundant_clone)]
	let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
		client.clone(),
		GRANDPA_JUSTIFICATION_PERIOD,
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;
	let justification_import = grandpa_block_import.clone();

	let (beefy_block_import, beefy_voter_links, beefy_rpc_links) =
		sc_consensus_beefy::beefy_block_import_and_links(
			grandpa_block_import,
			backend.clone(),
			client.clone(),
			config.prometheus_registry().cloned(),
		);

	let babe_config = sc_consensus_babe::configuration(&*client)?;
	let (block_import, babe_link) =
		sc_consensus_babe::block_import(babe_config, beefy_block_import, client.clone())?;

	let slot_duration = babe_link.config().slot_duration();
	let (import_queue, babe_worker_handle) =
		sc_consensus_babe::import_queue(sc_consensus_babe::ImportQueueParams {
			link: babe_link.clone(),
			block_import: block_import.clone(),
			justification_import: Some(Box::new(justification_import)),
			client: client.clone(),
			select_chain: select_chain.clone(),
			create_inherent_data_providers: move |_, ()| async move {
				let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

				let slot =
				sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
					*timestamp,
					slot_duration,
				);

				Ok((slot, timestamp))
			},
			spawner: &task_manager.spawn_essential_handle(),
			registry: config.prometheus_registry(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool.clone()),
		})?;

	let import_setup = (block_import, grandpa_link, babe_link, beefy_voter_links);

	let statement_store = sc_statement_store::Store::new_shared(
		&config.data_path,
		Default::default(),
		client.clone(),
		keystore_container.local_keystore(),
		config.prometheus_registry(),
		&task_manager.spawn_handle(),
	)
	.map_err(|e| ServiceError::Other(format!("Statement store error: {:?}", e)))?;

	let (rpc_extensions_builder, rpc_setup) = {
		let (_, grandpa_link, _, _) = &import_setup;

		let justification_stream = grandpa_link.justification_stream();
		let shared_authority_set = grandpa_link.shared_authority_set().clone();
		let shared_voter_state = sc_consensus_grandpa::SharedVoterState::empty();
		let shared_voter_state2 = shared_voter_state.clone();

		let finality_proof_provider = sc_consensus_grandpa::FinalityProofProvider::new_for_service(
			backend.clone(),
			Some(shared_authority_set.clone()),
		);

		let client = client.clone();
		let pool = transaction_pool.clone();
		let select_chain = select_chain.clone();
		let keystore = keystore_container.keystore();
		let chain_spec = config.chain_spec.cloned_box();

		let rpc_backend = backend.clone();
		let rpc_statement_store = statement_store.clone();
		let rpc_extensions_builder =
			move |subscription_executor: cord_node_rpc::SubscriptionTaskExecutor| {
				let deps = cord_node_rpc::FullDeps {
					client: client.clone(),
					pool: pool.clone(),
					select_chain: select_chain.clone(),
					chain_spec: chain_spec.cloned_box(),
					babe: cord_node_rpc::BabeDeps {
						keystore: keystore.clone(),
						babe_worker_handle: babe_worker_handle.clone(),
					},
					grandpa: cord_node_rpc::GrandpaDeps {
						shared_voter_state: shared_voter_state.clone(),
						shared_authority_set: shared_authority_set.clone(),
						justification_stream: justification_stream.clone(),
						subscription_executor: subscription_executor.clone(),
						finality_provider: finality_proof_provider.clone(),
					},
					beefy: cord_node_rpc::BeefyDeps::<
						sp_consensus_beefy::ecdsa_crypto::AuthorityId,
					> {
						beefy_finality_proof_stream: beefy_rpc_links
							.from_voter_justif_stream
							.clone(),
						beefy_best_block_stream: beefy_rpc_links
							.from_voter_best_beefy_stream
							.clone(),
						subscription_executor,
					},
					statement_store: rpc_statement_store.clone(),
					backend: rpc_backend.clone(),
				};

				cord_node_rpc::create_full(deps).map_err(Into::into)
			};

		(rpc_extensions_builder, shared_voter_state2)
	};

	Ok(sc_service::PartialComponents {
		client,
		backend,
		task_manager,
		keystore_container,
		select_chain,
		import_queue,
		transaction_pool,
		other: (rpc_extensions_builder, import_setup, rpc_setup, telemetry, statement_store),
	})
}

/// Result of [`new_full_base`].
#[cfg(feature = "full-node")]
pub struct NewFullBase {
	/// The task manager of the node.
	pub task_manager: TaskManager,
	/// The client instance of the node.
	pub client: Arc<FullClient>,
	/// The networking service of the node.
	pub network: Arc<dyn NetworkService>,
	/// The syncing service of the node.
	pub sync: Arc<SyncingService<Block>>,
	/// The transaction pool of the node.
	pub transaction_pool: Arc<TransactionPoolHandle<Block, FullClient>>,
	/// The rpc handlers of the node.
	pub rpc_handlers: RpcHandlers,
}

/// Creates a full service from the configuration.
#[cfg(feature = "full-node")]
pub fn new_full_base<N: NetworkBackend<Block, <Block as BlockT>::Hash>>(
	config: Configuration,
	disable_hardware_benchmarks: bool,
	with_startup_data: impl FnOnce(
		&sc_consensus_babe::BabeBlockImport<
			Block,
			FullClient,
			FullBeefyBlockImport<FullGrandpaBlockImport>,
		>,
		&sc_consensus_babe::BabeLink<Block>,
	),
) -> Result<NewFullBase, ServiceError> {
	let is_offchain_indexing_enabled = config.offchain_worker.indexing_enabled;
	let role = config.role;
	let force_authoring = config.force_authoring;
	let backoff_authoring_blocks = if config.chain_spec.is_braid()
		|| config.chain_spec.is_loom()
		|| config.chain_spec.is_weave()
	{
		// the block authoring backoff is disabled on production networks
		None
	} else {
		let mut backoff = sc_consensus_slots::BackoffAuthoringOnFinalizedHeadLagging::default();
		if config.chain_spec.is_dev() {
			backoff.max_interval = 10;
		}
		Some(backoff)
	};
	let name = config.network.node_name.clone();
	let enable_grandpa = !config.disable_grandpa;
	let prometheus_registry = config.prometheus_registry().cloned();
	let enable_offchain_worker = config.offchain_worker.enabled;

	let hwbench = (!disable_hardware_benchmarks)
		.then(|| {
			config.database.path().map(|database_path| {
				let _ = std::fs::create_dir_all(&database_path);
				sc_sysinfo::gather_hwbench(Some(database_path), &SUBSTRATE_REFERENCE_HARDWARE)
			})
		})
		.flatten();

	let sc_service::PartialComponents {
		client,
		backend,
		mut task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		other: (rpc_builder, import_setup, rpc_setup, mut telemetry, statement_store),
	} = new_partial(&config)?;

	let metrics = N::register_notification_metrics(
		config.prometheus_config.as_ref().map(|cfg| &cfg.registry),
	);
	let shared_voter_state = rpc_setup;
	let auth_disc_publish_non_global_ips = config.network.allow_non_globals_in_dht;
	let auth_disc_public_addresses = config.network.public_addresses.clone();

	let mut net_config = sc_network::config::FullNetworkConfiguration::<_, _, N>::new(
		&config.network,
		config.prometheus_config.as_ref().map(|cfg| cfg.registry.clone()),
	);

	let genesis_hash = client.block_hash(0).ok().flatten().expect("Genesis block exists; qed");
	let peer_store_handle = net_config.peer_store_handle();

	let grandpa_protocol_name =
		sc_consensus_grandpa::protocol_standard_name(&genesis_hash, &config.chain_spec);
	let (grandpa_protocol_config, grandpa_notification_service) =
		sc_consensus_grandpa::grandpa_peers_set_config::<_, N>(
			grandpa_protocol_name.clone(),
			metrics.clone(),
			Arc::clone(&peer_store_handle),
		);
	net_config.add_notification_protocol(grandpa_protocol_config);

	let beefy_gossip_proto_name =
		sc_consensus_beefy::gossip_protocol_name(&genesis_hash, config.chain_spec.fork_id());
	// `beefy_on_demand_justifications_handler` is given to `beefy-gadget` task to be run,
	// while `beefy_req_resp_cfg` is added to `config.network.request_response_protocols`.
	let (beefy_on_demand_justifications_handler, beefy_req_resp_cfg) =
		sc_consensus_beefy::communication::request_response::BeefyJustifsRequestHandler::new::<_, N>(
			&genesis_hash,
			config.chain_spec.fork_id(),
			client.clone(),
			prometheus_registry.clone(),
		);

	let (beefy_notification_config, beefy_notification_service) =
		sc_consensus_beefy::communication::beefy_peers_set_config::<_, N>(
			beefy_gossip_proto_name.clone(),
			metrics.clone(),
			Arc::clone(&peer_store_handle),
		);

	net_config.add_notification_protocol(beefy_notification_config);
	net_config.add_request_response_protocol(beefy_req_resp_cfg);

	let (statement_handler_proto, statement_config) =
		sc_network_statement::StatementHandlerPrototype::new::<_, _, N>(
			genesis_hash,
			config.chain_spec.fork_id(),
			metrics.clone(),
			Arc::clone(&peer_store_handle),
		);
	net_config.add_notification_protocol(statement_config);

	let warp_sync = Arc::new(sc_consensus_grandpa::warp_proof::NetworkProvider::new(
		backend.clone(),
		import_setup.1.shared_authority_set().clone(),
		Vec::default(),
	));

	let (network, system_rpc_tx, tx_handler_controller, sync_service) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			net_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			block_announce_validator_builder: None,
			warp_sync_config: Some(WarpSyncConfig::WithProvider(warp_sync)),
			block_relay: None,
			metrics,
		})?;

	let rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		config,
		backend: backend.clone(),
		client: client.clone(),
		keystore: keystore_container.keystore(),
		network: network.clone(),
		rpc_builder: Box::new(rpc_builder),
		transaction_pool: transaction_pool.clone(),
		task_manager: &mut task_manager,
		system_rpc_tx,
		tx_handler_controller,
		sync_service: sync_service.clone(),
		telemetry: telemetry.as_mut(),
	})?;

	if let Some(hwbench) = hwbench {
		sc_sysinfo::print_hwbench(&hwbench);
		match SUBSTRATE_REFERENCE_HARDWARE.check_hardware(&hwbench, false) {
			Err(err) if role.is_authority() => {
				log::warn!(
					"⚠️  The hardware does not meet the minimal requirements {} for role 'Authority'.",
					err
				);
			},
			_ => {},
		}

		if let Some(ref mut telemetry) = telemetry {
			let telemetry_handle = telemetry.handle();
			task_manager.spawn_handle().spawn(
				"telemetry_hwbench",
				None,
				sc_sysinfo::initialize_hwbench_telemetry(telemetry_handle, hwbench),
			);
		}
	}

	let (block_import, grandpa_link, babe_link, beefy_links) = import_setup;

	(with_startup_data)(&block_import, &babe_link);

	if let sc_service::config::Role::Authority { .. } = &role {
		let proposer = sc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle()),
		);

		let client_clone = client.clone();
		let slot_duration = babe_link.config().slot_duration();
		let babe_config = sc_consensus_babe::BabeParams {
			keystore: keystore_container.keystore(),
			client: client.clone(),
			select_chain,
			env: proposer,
			block_import,
			sync_oracle: sync_service.clone(),
			justification_sync_link: sync_service.clone(),
			create_inherent_data_providers: move |parent, ()| {
				let client_clone = client_clone.clone();
				async move {
					let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

					let slot =
                        sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                            *timestamp,
                            slot_duration,
                        );

					let storage_proof =
						sp_transaction_storage_proof::registration::new_data_provider(
							&*client_clone,
							&parent,
						)?;

					Ok((slot, timestamp, storage_proof))
				}
			},
			force_authoring,
			backoff_authoring_blocks,
			babe_link,
			block_proposal_slot_portion: SlotProportion::new(0.5),
			max_block_proposal_slot_portion: None,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
		};

		let babe = sc_consensus_babe::start_babe(babe_config)?;
		task_manager.spawn_essential_handle().spawn_blocking(
			"babe-proposer",
			Some("block-authoring"),
			babe,
		);
	}

	// Spawn authority discovery module.
	if role.is_authority() {
		let authority_discovery_role =
			sc_authority_discovery::Role::PublishAndDiscover(keystore_container.keystore());
		let dht_event_stream =
			network.event_stream("authority-discovery").filter_map(|e| async move {
				match e {
					Event::Dht(e) => Some(e),
					_ => None,
				}
			});
		let (authority_discovery_worker, _service) =
			sc_authority_discovery::new_worker_and_service_with_config(
				sc_authority_discovery::WorkerConfig {
					publish_non_global_ips: auth_disc_publish_non_global_ips,
					public_addresses: auth_disc_public_addresses,
					..Default::default()
				},
				client.clone(),
				Arc::new(network.clone()),
				Box::pin(dht_event_stream),
				authority_discovery_role,
				prometheus_registry.clone(),
			);

		task_manager.spawn_handle().spawn(
			"authority-discovery-worker",
			Some("networking"),
			authority_discovery_worker.run(),
		);
	}

	// if the node isn't actively participating in consensus then it doesn't
	// need a keystore, regardless of which protocol we use below.
	let keystore = if role.is_authority() { Some(keystore_container.keystore()) } else { None };

	// beefy is enabled if its notification service exists
	let network_params = sc_consensus_beefy::BeefyNetworkParams {
		network: Arc::new(network.clone()),
		sync: sync_service.clone(),
		gossip_protocol_name: beefy_gossip_proto_name,
		justifications_protocol_name: beefy_on_demand_justifications_handler.protocol_name(),
		notification_service: beefy_notification_service,
		_phantom: core::marker::PhantomData::<Block>,
	};
	let beefy_params = sc_consensus_beefy::BeefyParams {
		client: client.clone(),
		backend: backend.clone(),
		payload_provider: sp_consensus_beefy::mmr::MmrRootProvider::new(client.clone()),
		runtime: client.clone(),
		key_store: keystore.clone(),
		network_params,
		min_block_delta: 8,
		prometheus_registry: prometheus_registry.clone(),
		links: beefy_links,
		on_demand_justifications_handler: beefy_on_demand_justifications_handler,
		is_authority: role.is_authority(),
	};

	let beefy_gadget =
		sc_consensus_beefy::start_beefy_gadget::<_, _, _, _, _, _, _, _>(beefy_params);
	// BEEFY is part of consensus, if it fails we'll bring the node down with it to make sure it
	// is noticed.
	task_manager
		.spawn_essential_handle()
		.spawn_blocking("beefy-gadget", None, beefy_gadget);
	// When offchain indexing is enabled, MMR gadget should also run.
	if is_offchain_indexing_enabled {
		task_manager.spawn_essential_handle().spawn_blocking(
			"mmr-gadget",
			None,
			mmr_gadget::MmrGadget::start(
				client.clone(),
				backend.clone(),
				sp_mmr_primitives::INDEXING_PREFIX.to_vec(),
			),
		);
	}

	let grandpa_config = sc_consensus_grandpa::Config {
		// FIXME #1578 make this available through chainspec
		gossip_duration: std::time::Duration::from_millis(333),
		justification_generation_period: GRANDPA_JUSTIFICATION_PERIOD,
		name: Some(name),
		observer_enabled: false,
		keystore,
		local_role: role,
		telemetry: telemetry.as_ref().map(|x| x.handle()),
		protocol_name: grandpa_protocol_name,
	};

	if enable_grandpa {
		// start the full GRANDPA voter
		// NOTE: non-authorities could run the GRANDPA observer protocol, but at
		// this point the full voter should provide better guarantees of block
		// and vote data availability than the observer. The observer has not
		// been tested extensively yet and having most nodes in a network run it
		// could lead to finality stalls.
		let grandpa_params = sc_consensus_grandpa::GrandpaParams {
			config: grandpa_config,
			link: grandpa_link,
			network: network.clone(),
			sync: Arc::new(sync_service.clone()),
			notification_service: grandpa_notification_service,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
			prometheus_registry: prometheus_registry.clone(),
			shared_voter_state,
			offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool.clone()),
		};

		// the GRANDPA voter task is considered infallible, i.e.
		// if it fails we take down the service with it.
		task_manager.spawn_essential_handle().spawn_blocking(
			"grandpa-voter",
			None,
			sc_consensus_grandpa::run_grandpa_voter(grandpa_params)?,
		);
	}

	// Spawn statement protocol worker
	let statement_protocol_executor = {
		let spawn_handle = task_manager.spawn_handle();
		Box::new(move |fut| {
			spawn_handle.spawn("network-statement-validator", Some("networking"), fut);
		})
	};
	let statement_handler = statement_handler_proto.build(
		network.clone(),
		sync_service.clone(),
		statement_store.clone(),
		prometheus_registry.as_ref(),
		statement_protocol_executor,
	)?;
	task_manager.spawn_handle().spawn(
		"network-statement-handler",
		Some("networking"),
		statement_handler.run(),
	);

	if enable_offchain_worker {
		let offchain_workers =
			sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
				runtime_api_provider: client.clone(),
				keystore: Some(keystore_container.keystore()),
				offchain_db: backend.offchain_storage(),
				transaction_pool: Some(OffchainTransactionPoolFactory::new(
					transaction_pool.clone(),
				)),
				network_provider: Arc::new(network.clone()),
				is_validator: role.is_authority(),
				enable_http_requests: true,
				custom_extensions: move |_| {
					vec![Box::new(statement_store.clone().as_statement_store_ext()) as Box<_>]
				},
			})?;
		task_manager.spawn_handle().spawn(
			"offchain-workers-runner",
			"offchain-work",
			offchain_workers.run(client.clone(), task_manager.spawn_handle()).boxed(),
		);
	}

	Ok(NewFullBase {
		task_manager,
		client,
		network,
		sync: sync_service,
		transaction_pool,
		rpc_handlers,
	})
}

#[cfg(feature = "full-node")]
pub trait RuntimeConfig {
	fn new_full(&self, config: Configuration, cli: Cli) -> Result<TaskManager, ServiceError>;
}

#[cfg(feature = "full-node")]
pub struct BraidRuntime;
#[cfg(feature = "full-node")]
impl RuntimeConfig for BraidRuntime {
	fn new_full(&self, config: Configuration, cli: Cli) -> Result<TaskManager, ServiceError> {
		let database_path = config.database.path().map(Path::to_path_buf);
		let task_manager = match config.network.network_backend {
			sc_network::config::NetworkBackendType::Libp2p => {
				let task_manager = new_full_base::<sc_network::NetworkWorker<_, _>>(
					config,
					cli.no_hardware_benchmarks,
					|_, _| (),
				)
				.map(|NewFullBase { task_manager, .. }| task_manager)?;
				task_manager
			},
			sc_network::config::NetworkBackendType::Litep2p => {
				let task_manager = new_full_base::<sc_network::Litep2pNetworkBackend>(
					config,
					cli.no_hardware_benchmarks,
					|_, _| (),
				)
				.map(|NewFullBase { task_manager, .. }| task_manager)?;
				task_manager
			},
		};

		if let Some(database_path) = database_path {
			sc_storage_monitor::StorageMonitorService::try_spawn(
				cli.storage_monitor,
				database_path,
				&task_manager.spawn_essential_handle(),
			)
			.map_err(|e| ServiceError::Application(e.into()))?;
		}

		Ok(task_manager)
	}
}

#[cfg(feature = "full-node")]
pub struct LoomRuntime;
#[cfg(feature = "full-node")]
impl RuntimeConfig for LoomRuntime {
	fn new_full(&self, config: Configuration, cli: Cli) -> Result<TaskManager, ServiceError> {
		let database_path = config.database.path().map(Path::to_path_buf);
		let task_manager = match config.network.network_backend {
			sc_network::config::NetworkBackendType::Libp2p => {
				let task_manager = new_full_base::<sc_network::NetworkWorker<_, _>>(
					config,
					cli.no_hardware_benchmarks,
					|_, _| (),
				)
				.map(|NewFullBase { task_manager, .. }| task_manager)?;
				task_manager
			},
			sc_network::config::NetworkBackendType::Litep2p => {
				let task_manager = new_full_base::<sc_network::Litep2pNetworkBackend>(
					config,
					cli.no_hardware_benchmarks,
					|_, _| (),
				)
				.map(|NewFullBase { task_manager, .. }| task_manager)?;
				task_manager
			},
		};

		if let Some(database_path) = database_path {
			sc_storage_monitor::StorageMonitorService::try_spawn(
				cli.storage_monitor,
				database_path,
				&task_manager.spawn_essential_handle(),
			)
			.map_err(|e| ServiceError::Application(e.into()))?;
		}

		Ok(task_manager)
	}
}

#[cfg(feature = "full-node")]
pub struct WeaveRuntime;
#[cfg(feature = "full-node")]
impl RuntimeConfig for WeaveRuntime {
	fn new_full(&self, config: Configuration, cli: Cli) -> Result<TaskManager, ServiceError> {
		let database_path = config.database.path().map(Path::to_path_buf);
		let task_manager = match config.network.network_backend {
			sc_network::config::NetworkBackendType::Libp2p => {
				let task_manager = new_full_base::<sc_network::NetworkWorker<_, _>>(
					config,
					cli.no_hardware_benchmarks,
					|_, _| (),
				)
				.map(|NewFullBase { task_manager, .. }| task_manager)?;
				task_manager
			},
			sc_network::config::NetworkBackendType::Litep2p => {
				let task_manager = new_full_base::<sc_network::Litep2pNetworkBackend>(
					config,
					cli.no_hardware_benchmarks,
					|_, _| (),
				)
				.map(|NewFullBase { task_manager, .. }| task_manager)?;
				task_manager
			},
		};

		if let Some(database_path) = database_path {
			sc_storage_monitor::StorageMonitorService::try_spawn(
				cli.storage_monitor,
				database_path,
				&task_manager.spawn_essential_handle(),
			)
			.map_err(|e| ServiceError::Application(e.into()))?;
		}

		Ok(task_manager)
	}
}

pub fn select_runtime(config: &Configuration) -> Box<dyn RuntimeConfig> {
	if config.chain_spec.is_braid() {
		Box::new(BraidRuntime)
	} else if config.chain_spec.is_loom() {
		Box::new(LoomRuntime)
	} else if config.chain_spec.is_weave() {
		Box::new(WeaveRuntime)
	} else {
		panic!("Unsupported runtime");
	}
}

pub fn new_full(config: Configuration, cli: Cli) -> Result<TaskManager, ServiceError> {
	let runtime = select_runtime(&config);
	runtime.new_full(config, cli)
}
