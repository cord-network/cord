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

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limits.
#![recursion_limit = "1024"]

extern crate alloc;

use codec::{Decode, Encode};
use scale_info::TypeInfo;

pub use cord_primitives::{AccountId, AccountPublic, Signature};
use cord_primitives::{AccountIndex, Balance, BlockNumber, DidIdentifier, Hash, Moment, Nonce};
use cord_runtime_common::{impl_runtime_weights, prod_or_fast, BlockHashCount, BlockLength};
use frame_support::{
	derive_impl,
	genesis_builder_helper::{build_state, get_preset},
	instances::{Instance1, Instance2},
	ord_parameter_types, parameter_types,
	traits::{
		fungible::{NativeFromLeft, NativeOrWithId, UnionOf},
		tokens::imbalance::ResolveAssetTo,
		AsEnsureOriginWithArg, ConstBool, ConstU128, ConstU32, Contains, KeyOwnerProofSystem,
		PrivilegeCmp, VariantCountOf,
	},
	weights::ConstantMultiplier,
	PalletId,
};
use frame_system::{EnsureRoot, EnsureSigned, EnsureSignedBy};
pub use identifier::Ss58Identifier;
use pallet_asset_conversion::{AccountIdConverter, Ascending, Chain, WithFirstAsset};
pub use pallet_balances::Call as BalancesCall;
use pallet_cord_identity::legacy::IdentityInfo;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use pallet_session::historical as pallet_session_historical;
use pallet_transaction_payment::{FeeDetails, FungibleAdapter, RuntimeDispatchInfo};
use sp_api::impl_runtime_apis;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_beefy::{
	ecdsa_crypto::{AuthorityId as BeefyId, Signature as BeefySignature},
	mmr::MmrLeafVersion,
};
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata};
use sp_inherents::{CheckInherentsResult, InherentData};
use sp_runtime::{
	create_runtime_str, generic,
	generic::Era,
	impl_opaque_keys,
	traits::{
		self, AccountIdConversion, BlakeTwo256, Block as BlockT, Keccak256, NumberFor, OpaqueKeys,
		SaturatedConversion, StaticLookup, Verify,
	},
	transaction_validity::{TransactionPriority, TransactionSource, TransactionValidity},
	ApplyExtrinsicResult, Perbill, Permill,
};
use sp_staking::SessionIndex;
use sp_std::{cmp::Ordering, prelude::*};

#[cfg(any(feature = "std", test))]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

#[cfg(any(feature = "std", test))]
pub use frame_system::Call as SystemCall;
#[cfg(any(feature = "std", test))]
pub use pallet_sudo::Call as SudoCall;
#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;

/// Constant values used within the runtime.
use cord_braid_runtime_constants::{currency::*, fee::WeightToFee, time::*};
use cord_runtime_common as runtime_common;
use runtime_common::{SlowAdjustingFeeUpdate, ToAuthor};

// CORD Pallets
pub use authority_membership;
pub use pallet_network_membership;
pub mod benchmark;
pub use benchmark::DummySignature;
pub use pallet_assets_runtime_api as assets_api;
use pallet_network_membership::RuntimeDispatchWeightInfo;

// Genesis preset configurations.
pub mod genesis_config_presets;

// Weights used in the runtime.
mod weights;

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Max size for serialized extrinsic params for this testing runtime.
/// This is a quite arbitrary but empirically battle tested value.
#[cfg(test)]
pub const CALL_PARAMS_MAX_SIZE: usize = 244;

/// Wasm binary unwrapped. If built with `SKIP_WASM_BUILD`, the function panics.
#[cfg(feature = "std")]
pub fn wasm_binary_unwrap() -> &'static [u8] {
	WASM_BINARY.expect(
		"Development wasm binary is not available. This means the client is \
  		 built with `SKIP_WASM_BUILD` flag and it is only usable for \
		 production chains. Please rebuild with the flag disabled.",
	)
}

/// Runtime version.
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("braid"),
	impl_name: create_runtime_str!("dhiway-cord"),
	authoring_version: 0,
	spec_version: 9500,
	impl_version: 0,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 2,
	state_version: 1,
};

impl_runtime_weights!(cord_braid_runtime_constants);

/// The BABE epoch configuration at genesis.
pub const BABE_GENESIS_EPOCH_CONFIG: sp_consensus_babe::BabeEpochConfiguration =
	sp_consensus_babe::BabeEpochConfiguration {
		c: PRIMARY_PROBABILITY,
		allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryVRFSlots,
	};

/// Native version.
#[cfg(any(feature = "std", test))]
pub fn native_version() -> NativeVersion {
	NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}

/// We currently allow all calls.
pub struct BaseFilter;
impl Contains<RuntimeCall> for BaseFilter {
	fn contains(_c: &RuntimeCall) -> bool {
		true
	}
}

parameter_types! {
  pub const Version: RuntimeVersion = VERSION;
  pub const SS58Prefix: u16 = 3893;
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
	type BaseCallFilter = BaseFilter;
	type BlockWeights = BlockWeights;
	type BlockLength = BlockLength;
	type DbWeight = RocksDbWeight;
	type Nonce = Nonce;
	type Hash = Hash;
	type AccountId = AccountId;
	type Lookup = Indices;
	type Block = Block;
	type BlockHashCount = BlockHashCount;
	type Version = Version;
	type AccountData = pallet_balances::AccountData<Balance>;
	type SystemWeightInfo = weights::frame_system::WeightInfo<Runtime>;
	type SS58Prefix = SS58Prefix;
	type MaxConsumers = frame_support::traits::ConstU32<16>;
	type MultiBlockMigrator = ();
}

parameter_types! {
	pub MaximumSchedulerWeight: Weight = Perbill::from_percent(80) * BlockWeights::get().max_block;
	pub const MaxScheduledPerBlock: u32 = 50;
	pub const NoPreimagePostponement: Option<u32> = Some(10);
}

/// Used the compare the privilege of an origin inside the scheduler.
pub struct OriginPrivilegeCmp;

impl PrivilegeCmp<OriginCaller> for OriginPrivilegeCmp {
	fn cmp_privilege(left: &OriginCaller, right: &OriginCaller) -> Option<Ordering> {
		if left == right {
			return Some(Ordering::Equal);
		}

		match (left, right) {
			// Root is greater than anything.
			(OriginCaller::system(frame_system::RawOrigin::Root), _) => Some(Ordering::Greater),
			// For every other origin we don't care, as they are not used for `ScheduleOrigin`.
			_ => None,
		}
	}
}

impl pallet_scheduler::Config for Runtime {
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeEvent = RuntimeEvent;
	type PalletsOrigin = OriginCaller;
	type RuntimeCall = RuntimeCall;
	type MaximumWeight = MaximumSchedulerWeight;
	type ScheduleOrigin = EnsureRoot<AccountId>;
	type MaxScheduledPerBlock = MaxScheduledPerBlock;
	type WeightInfo = weights::pallet_scheduler::WeightInfo<Runtime>;
	type OriginPrivilegeCmp = OriginPrivilegeCmp;
	type Preimages = ();
}

parameter_types! {
	pub EpochDuration: u64 = prod_or_fast!(
		EPOCH_DURATION_IN_SLOTS as u64,
		2 * MINUTES as u64,
		"CORD_EPOCH_DURATION"
	);
	pub const SessionsPerEra: SessionIndex = 6;
	pub const BondingDuration: sp_staking::EraIndex = 28;
	pub const ExpectedBlockTime: Moment = MILLISECS_PER_BLOCK;
	pub ReportLongevity: u64 =
		BondingDuration::get() as u64 * SessionsPerEra::get() as u64 * EpochDuration::get();
	pub const MaxAuthorities: u32 = 1_000;

}

impl pallet_babe::Config for Runtime {
	type EpochDuration = EpochDuration;
	type ExpectedBlockTime = ExpectedBlockTime;
	// session module is the trigger
	type EpochChangeTrigger = pallet_babe::ExternalTrigger;
	type DisabledValidators = Session;
	type WeightInfo = weights::pallet_babe::WeightInfo<Runtime>;
	type MaxAuthorities = MaxAuthorities;
	type MaxNominators = ConstU32<0>;
	type KeyOwnerProof =
		<Historical as KeyOwnerProofSystem<(KeyTypeId, pallet_babe::AuthorityId)>>::Proof;
	type EquivocationReportSystem =
		pallet_babe::EquivocationReportSystem<Self, Offences, Historical, ReportLongevity>;
}

parameter_types! {
	pub const IndexDeposit: Balance =  EXISTENTIAL_DEPOSIT;
}

impl pallet_indices::Config for Runtime {
	type AccountIndex = AccountIndex;
	type Currency = Balances;
	type Deposit = IndexDeposit;
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = weights::pallet_indices::WeightInfo<Runtime>;
}

parameter_types! {
	pub const ExistentialDeposit: Balance = EXISTENTIAL_DEPOSIT;
	pub const MaxLocks: u32 = 50;
	pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Runtime {
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type MaxLocks = MaxLocks;
	type MaxReserves = MaxReserves;
	type ReserveIdentifier = [u8; 8];
	type Balance = Balance;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = frame_system::Pallet<Runtime>;
	type FreezeIdentifier = RuntimeFreezeReason;
	type MaxFreezes = VariantCountOf<RuntimeFreezeReason>;
	type WeightInfo = weights::pallet_balances::WeightInfo<Runtime>;
}

parameter_types! {
	pub const TransactionByteFee: Balance = cord_braid_runtime_constants::fee::TRANSACTION_BYTE_FEE;
	/// This value increases the priority of `Operational` transactions by adding
	/// a "virtual tip" that's equal to the `OperationalFeeMultiplier * final_fee`.
	pub const OperationalFeeMultiplier: u8 = 5;
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = FungibleAdapter<Balances, ToAuthor<Self>>;
	type OperationalFeeMultiplier = OperationalFeeMultiplier;
	type WeightToFee = WeightToFee;
	type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
	type FeeMultiplierUpdate = SlowAdjustingFeeUpdate<Self>;
}

parameter_types! {
	pub const MinimumPeriod: Moment = SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
	type Moment = Moment;
	type OnTimestampSet = Babe;
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = weights::pallet_timestamp::WeightInfo<Runtime>;
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Babe>;
	type EventHandler = ImOnline;
}

impl_opaque_keys! {
	pub struct SessionKeys {
		pub babe: Babe,
		pub grandpa: Grandpa,
		pub im_online: ImOnline,
		pub authority_discovery: AuthorityDiscovery,
		pub beefy: Beefy,
	}
}

/// Special `ValidatorIdOf` implementation that is just returning the input as result.
pub struct ValidatorIdOf;
impl sp_runtime::traits::Convert<AccountId, Option<AccountId>> for ValidatorIdOf {
	fn convert(a: AccountId) -> Option<AccountId> {
		Some(a)
	}
}

impl pallet_session::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = AccountId;
	type ValidatorIdOf = ValidatorIdOf;
	type ShouldEndSession = Babe;
	type NextSessionRotation = Babe;
	type SessionManager = pallet_session::historical::NoteHistoricalRoot<Self, AuthorityMembership>;
	type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
	type Keys = SessionKeys;
	type WeightInfo = weights::pallet_session::WeightInfo<Runtime>;
}

pub struct FullIdentificationOf;
impl sp_runtime::traits::Convert<AccountId, Option<()>> for FullIdentificationOf {
	fn convert(_: AccountId) -> Option<()> {
		Some(Default::default())
	}
}

impl pallet_session::historical::Config for Runtime {
	type FullIdentification = ();
	type FullIdentificationOf = FullIdentificationOf;
}

parameter_types! {
	pub const AssetDeposit: Balance = 10 * UNITS;
	pub const ApprovalDeposit: Balance = CENTI;
	pub const StringLimit: u32 = 50;
	pub const MetadataDepositBase: Balance = 10 * MILLI;
	pub const MetadataDepositPerByte: Balance = 10 * MICRO;
}

impl pallet_assets::Config<Instance1> for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Balance = u128;
	type AssetId = u32;
	type AssetIdParameter = codec::Compact<u32>;
	type Currency = Balances;
	type CreateOrigin = AsEnsureOriginWithArg<EnsureSigned<AccountId>>;
	type ForceOrigin = EnsureRoot<AccountId>;
	type AssetDeposit = AssetDeposit;
	type AssetAccountDeposit = ConstU128<UNITS>;
	type MetadataDepositBase = MetadataDepositBase;
	type MetadataDepositPerByte = MetadataDepositPerByte;
	type ApprovalDeposit = ApprovalDeposit;
	type StringLimit = StringLimit;
	type Freezer = ();
	type Extra = ();
	type CallbackHandle = ();
	type WeightInfo = pallet_assets::weights::SubstrateWeight<Runtime>;
	type RemoveItemsLimit = ConstU32<1000>;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = ();
}

ord_parameter_types! {
	pub const AssetConversionOrigin: AccountId = AccountIdConversion::<AccountId>::into_account_truncating(&AssetConversionPalletId::get());
}

impl pallet_assets::Config<Instance2> for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Balance = u128;
	type AssetId = u32;
	type AssetIdParameter = codec::Compact<u32>;
	type Currency = Balances;
	type CreateOrigin = AsEnsureOriginWithArg<EnsureSignedBy<AssetConversionOrigin, AccountId>>;
	type ForceOrigin = EnsureRoot<AccountId>;
	type AssetDeposit = AssetDeposit;
	type AssetAccountDeposit = ConstU128<UNITS>;
	type MetadataDepositBase = MetadataDepositBase;
	type MetadataDepositPerByte = MetadataDepositPerByte;
	type ApprovalDeposit = ApprovalDeposit;
	type StringLimit = StringLimit;
	type Freezer = ();
	type Extra = ();
	type WeightInfo = pallet_assets::weights::SubstrateWeight<Runtime>;
	type RemoveItemsLimit = ConstU32<1000>;
	type CallbackHandle = ();
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = ();
}

parameter_types! {
	pub const AssetConversionPalletId: PalletId = PalletId(*b"py/ascon");
	pub const PoolSetupFee: Balance = 10 * UNITS; // should be more or equal to the existential deposit
	pub const MintMinLiquidity: Balance = 100;  // 100 is good enough when the main currency has 10-12 decimals.
	pub const LiquidityWithdrawalFee: Permill = Permill::from_percent(0);
	pub const Native: NativeOrWithId<u32> = NativeOrWithId::Native;
}

impl pallet_asset_conversion::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Balance = u128;
	type HigherPrecisionBalance = sp_core::U256;
	type AssetKind = NativeOrWithId<u32>;
	type Assets = UnionOf<Balances, Assets, NativeFromLeft, NativeOrWithId<u32>, AccountId>;
	type PoolId = (Self::AssetKind, Self::AssetKind);
	type PoolLocator = Chain<
		WithFirstAsset<
			Native,
			AccountId,
			NativeOrWithId<u32>,
			AccountIdConverter<AssetConversionPalletId, Self::PoolId>,
		>,
		Ascending<
			AccountId,
			NativeOrWithId<u32>,
			AccountIdConverter<AssetConversionPalletId, Self::PoolId>,
		>,
	>;
	type PoolAssetId = <Self as pallet_assets::Config<Instance2>>::AssetId;
	type PoolAssets = PoolAssets;
	type PoolSetupFee = PoolSetupFee;
	type PoolSetupFeeAsset = Native;
	type PoolSetupFeeTarget = ResolveAssetTo<AssetConversionOrigin, Self::Assets>;
	type PalletId = AssetConversionPalletId;
	type LPFee = ConstU32<3>; // means 0.3%
	type LiquidityWithdrawalFee = LiquidityWithdrawalFee;
	type WeightInfo = pallet_asset_conversion::weights::SubstrateWeight<Runtime>;
	type MaxSwapPathLength = ConstU32<4>;
	type MintMinLiquidity = MintMinLiquidity;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = ();
}

parameter_types! {
	pub const MaxSubAccounts: u32 = 100;
	pub const MaxRegistrars: u32 = 20;
	pub const MaxAdditionalFields: u32 = 20;
}

impl pallet_cord_identity::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type MaxSubAccounts = MaxSubAccounts;
	type IdentityInformation = IdentityInfo<MaxAdditionalFields>;
	type MaxRegistrars = MaxRegistrars;
	type RegistrarOrigin = EnsureRoot<AccountId>;
	type OffchainSignature = Signature;
	type SigningPublicKey = <Signature as Verify>::Signer;
	type UsernameAuthorityOrigin = EnsureRoot<AccountId>;
	type PendingUsernameExpiration = ConstU32<{ 7 * DAYS }>;
	type MaxSuffixLength = ConstU32<7>;
	type MaxUsernameLength = ConstU32<32>;
	type WeightInfo = weights::pallet_cord_identity::WeightInfo<Runtime>;
}

parameter_types! {
	pub const MaxRegistryEntryBlobSize: u32 = 4 * 1024; // 4KB in bytes
}

impl pallet_entries::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type MaxEncodedInputLength = MaxEncodedInputLength;
	type MaxRegistryEntryBlobSize = MaxRegistryEntryBlobSize;
	type WeightInfo = ();
}

impl pallet_cord_offences::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type IdentificationTuple = pallet_session::historical::IdentificationTuple<Self>;
	type OnOffenceHandler = AuthorityMembership;
}

impl pallet_authority_discovery::Config for Runtime {
	type MaxAuthorities = MaxAuthorities;
}

parameter_types! {
	pub const ImOnlineUnsignedPriority: TransactionPriority = TransactionPriority::max_value();
	pub const MaxPeerInHeartbeats: u32 = 10_000;
	pub const MaxPeerDataEncodingSize: u32 = 1_000;
	pub const MaxKeys: u32 = 100_000;
}

impl pallet_im_online::Config for Runtime {
	type AuthorityId = ImOnlineId;
	type RuntimeEvent = RuntimeEvent;
	type ValidatorSet = Historical;
	type NextSessionRotation = Babe;
	type ReportUnresponsiveness = Offences;
	type UnsignedPriority = ImOnlineUnsignedPriority;
	type WeightInfo = weights::pallet_im_online::WeightInfo<Runtime>;
	type MaxKeys = MaxKeys;
	type MaxPeerInHeartbeats = MaxPeerInHeartbeats;
}

parameter_types! {
	pub const MaxSetIdSessionEntries: u32 = BondingDuration::get() * SessionsPerEra::get();
}

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;

	type WeightInfo = ();
	type MaxAuthorities = MaxAuthorities;
	type MaxNominators = ();
	type MaxSetIdSessionEntries = MaxSetIdSessionEntries;
	type KeyOwnerProof = <Historical as KeyOwnerProofSystem<(KeyTypeId, GrandpaId)>>::Proof;
	type EquivocationReportSystem =
		pallet_grandpa::EquivocationReportSystem<Self, Offences, Historical, ReportLongevity>;
}

/// Submits a transaction with the node's public and signature type. Adheres to
/// the signed extension format of the chain.
impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where
	RuntimeCall: From<LocalCall>,
{
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: RuntimeCall,
		public: <Signature as Verify>::Signer,
		account: AccountId,
		nonce: Nonce,
	) -> Option<(RuntimeCall, <UncheckedExtrinsic as traits::Extrinsic>::SignaturePayload)> {
		let tip = 0;
		// take the biggest period possible.
		let period =
			BlockHashCount::get().checked_next_power_of_two().map(|c| c / 2).unwrap_or(2) as u64;
		let current_block = System::block_number()
			.saturated_into::<u64>()
			// The `System::block_number` is initialized with `n+1`,
			// so the actual block number is `n`.
			.saturating_sub(1);
		let era = Era::mortal(period, current_block);
		let tx_ext = (
			pallet_network_membership::CheckNetworkMembership::<Runtime>::new(),
			frame_system::CheckNonZeroSender::<Runtime>::new(),
			frame_system::CheckSpecVersion::<Runtime>::new(),
			frame_system::CheckTxVersion::<Runtime>::new(),
			frame_system::CheckGenesis::<Runtime>::new(),
			frame_system::CheckMortality::<Runtime>::from(era),
			frame_system::CheckNonce::<Runtime>::from(nonce),
			frame_system::CheckWeight::<Runtime>::new(),
			pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
			frame_metadata_hash_extension::CheckMetadataHash::new(false),
		);
		let raw_payload = SignedPayload::new(call, tx_ext)
			.map_err(|e| {
				log::warn!("Unable to create signed payload: {:?}", e);
			})
			.ok()?;
		let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
		let address = Indices::unlookup(account);
		let (call, tx_ext, _) = raw_payload.deconstruct();
		Some((call, (address, signature, tx_ext)))
	}
}

impl frame_system::offchain::SigningTypes for Runtime {
	type Public = <Signature as Verify>::Signer;
	type Signature = Signature;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
	RuntimeCall: From<C>,
{
	type Extrinsic = UncheckedExtrinsic;
	type OverarchingCall = RuntimeCall;
}

impl pallet_utility::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type PalletsOrigin = OriginCaller;
	type WeightInfo = weights::pallet_utility::WeightInfo<Runtime>;
}

parameter_types! {
	// One storage item; key size is 32; value is size 4+4+16+32 bytes = 56 bytes.
	pub const DepositBase: Balance = deposit(1, 88);
	// Additional storage item size of 32 bytes.
	pub const DepositFactor: Balance = deposit(0, 32);
	pub const MaxSignatories: u16 = 100;
}

impl pallet_multisig::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type DepositBase = DepositBase;
	type DepositFactor = DepositFactor;
	type MaxSignatories = MaxSignatories;
	type WeightInfo = weights::pallet_multisig::WeightInfo<Runtime>;
}

parameter_types! {
	pub const MaxProposalLength: u16 = 5;
}
impl authority_membership::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type IsMember = NetworkMembership;
	type MinAuthorities = ConstU32<3>;
	type AuthorityMembershipOrigin = EnsureRoot<AccountId>;
}

impl pallet_mmr::Config for Runtime {
	const INDEXING_PREFIX: &'static [u8] = b"mmr";
	type Hashing = Keccak256;
	type LeafData = pallet_mmr::ParentNumberAndHash<Self>;
	type OnNewRoot = pallet_beefy_mmr::DepositBeefyDigest<Runtime>;
	type BlockHashProvider = pallet_mmr::DefaultBlockHashProvider<Runtime>;
	type WeightInfo = ();
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = ();
}

parameter_types! {
	pub LeafVersion: MmrLeafVersion = MmrLeafVersion::new(0, 0);
}

impl pallet_beefy_mmr::Config for Runtime {
	type LeafVersion = LeafVersion;
	type BeefyAuthorityToMerkleLeaf = pallet_beefy_mmr::BeefyEcdsaToEthereum;
	type LeafExtra = Vec<u8>;
	type BeefyDataProvider = ();
	type WeightInfo = ();
}

parameter_types! {
	pub const MaxWellKnownNodes: u32 = 1_000;
	pub const MaxPeerIdLength: u32 = 128;
	pub const MaxNodeIdLength: u32 = 53;
}

impl pallet_cord_node_authorization::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type MaxWellKnownNodes = MaxWellKnownNodes;
	type MaxPeerIdLength = MaxPeerIdLength;
	type MaxNodeIdLength = MaxNodeIdLength;
	type NodeAuthorizationOrigin = EnsureRoot<AccountId>;
	type WeightInfo = ();
}

parameter_types! {
	pub const MembershipPeriod: BlockNumber = YEAR;
	pub const MaxMembersPerBlock: u32 = 1_000;
	pub const MaxEventsHistory: u32 = u32::MAX;
}

impl pallet_network_membership::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type NetworkMembershipOrigin = EnsureRoot<AccountId>;
	type MembershipPeriod = MembershipPeriod;
	type MaxMembersPerBlock = MaxMembersPerBlock;
	type WeightInfo = weights::pallet_network_membership::WeightInfo<Runtime>;
}

impl identifier::Config for Runtime {
	type MaxEventsHistory = MaxEventsHistory;
}

impl pallet_runtime_upgrade::Config for Runtime {
	type SetCodeOrigin = EnsureRoot<AccountId>;
}

parameter_types! {
	#[derive(Debug, Clone, Eq, PartialEq, TypeInfo, Decode, Encode)]
	pub const MaxNewKeyAgreementKeys: u32 = 10;
	#[derive(Clone)]
	pub const MaxPublicKeysPerDid: u32 = 20;
	#[derive(Debug, Clone, Eq, PartialEq)]
	pub const MaxTotalKeyAgreementKeys: u32 = 19;
	pub const MaxBlocksTxValidity: BlockNumber =  2 * HOURS;
	pub const MaxNumberOfServicesPerDid: u32 = 25;
	pub const MaxServiceIdLength: u32 = 50;
	pub const MaxServiceTypeLength: u32 = 50;
	pub const MaxServiceUrlLength: u32 = 200;
	pub const MaxNumberOfTypesPerService: u32 = 1;
	pub const MaxNumberOfUrlsPerService: u32 = 1;
}

impl pallet_did::Config for Runtime {
	type DidIdentifier = DidIdentifier;
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type RuntimeOrigin = RuntimeOrigin;

	#[cfg(not(feature = "runtime-benchmarks"))]
	type EnsureOrigin = pallet_did::EnsureDidOrigin<Self::DidIdentifier, AccountId>;
	#[cfg(not(feature = "runtime-benchmarks"))]
	type OriginSuccess = pallet_did::DidRawOrigin<AccountId, Self::DidIdentifier>;
	#[cfg(feature = "runtime-benchmarks")]
	type EnsureOrigin = EnsureSigned<Self::DidIdentifier>;
	#[cfg(feature = "runtime-benchmarks")]
	type OriginSuccess = Self::DidIdentifier;

	type MaxNewKeyAgreementKeys = MaxNewKeyAgreementKeys;
	type MaxPublicKeysPerDid = MaxPublicKeysPerDid;
	type MaxTotalKeyAgreementKeys = MaxTotalKeyAgreementKeys;
	type MaxBlocksTxValidity = MaxBlocksTxValidity;
	type MaxNumberOfServicesPerDid = MaxNumberOfServicesPerDid;
	type MaxServiceIdLength = MaxServiceIdLength;
	type MaxServiceTypeLength = MaxServiceTypeLength;
	type MaxServiceUrlLength = MaxServiceUrlLength;
	type MaxNumberOfTypesPerService = MaxNumberOfTypesPerService;
	type MaxNumberOfUrlsPerService = MaxNumberOfUrlsPerService;
	type WeightInfo = weights::pallet_did::WeightInfo<Runtime>;
}

parameter_types! {
	pub const MinNameLength: u32 = 3;
	pub const MaxNameLength: u32 = 64;
	pub const MaxPrefixLength: u32 = 54;
}

impl pallet_did_name::Config for Runtime {
	type BanOrigin = EnsureRoot<AccountId>;
	type EnsureOrigin = pallet_did::EnsureDidOrigin<DidIdentifier, AccountId>;
	type OriginSuccess = pallet_did::DidRawOrigin<AccountId, DidIdentifier>;
	type RuntimeEvent = RuntimeEvent;
	type MaxNameLength = MaxNameLength;
	type MinNameLength = MinNameLength;
	type MaxPrefixLength = MaxPrefixLength;
	type DidName = pallet_did_name::did_name::AsciiDidName<Runtime>;
	type DidNameOwner = DidIdentifier;
	type WeightInfo = weights::pallet_did_name::WeightInfo<Runtime>;
}

parameter_types! {
	pub const MaxEncodedSchemaLength: u32 = 15_360;
}

impl pallet_schema::Config for Runtime {
	type SchemaCreatorId = DidIdentifier;
	type EnsureOrigin = pallet_did::EnsureDidOrigin<DidIdentifier, AccountId>;
	type OriginSuccess = pallet_did::DidRawOrigin<AccountId, DidIdentifier>;
	type RuntimeEvent = RuntimeEvent;
	type MaxEncodedSchemaLength = MaxEncodedSchemaLength;
	type WeightInfo = weights::pallet_schema::WeightInfo<Runtime>;
}

impl pallet_schema_accounts::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type MaxEncodedSchemaLength = MaxEncodedSchemaLength;
	type WeightInfo = ();
}

parameter_types! {
	pub const MaxSpaceDelegates: u32 = 10_000;
}

impl pallet_chain_space::Config for Runtime {
	type SpaceCreatorId = DidIdentifier;
	type EnsureOrigin = pallet_did::EnsureDidOrigin<DidIdentifier, AccountId>;
	type OriginSuccess = pallet_did::DidRawOrigin<AccountId, DidIdentifier>;
	type RuntimeEvent = RuntimeEvent;
	type ChainSpaceOrigin = EnsureRoot<AccountId>;
	type NetworkPermission = NetworkParameters;
	type MaxSpaceDelegates = MaxSpaceDelegates;
	type WeightInfo = weights::pallet_chain_space::WeightInfo<Runtime>;
}

parameter_types! {
	pub const MaxRegistryBlobSize: u32 = 4 * 1024;
	pub const MaxEncodedInputLength: u32 = 30;
	pub const MaxRegistryDelegates: u32 = 10_000;
}

impl pallet_registries::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type MaxRegistryDelegates = MaxRegistryDelegates;
	type MaxRegistryBlobSize = MaxRegistryBlobSize;
	type MaxEncodedInputLength = MaxEncodedInputLength;
	type WeightInfo = ();
}

parameter_types! {
	pub const MaxDigestsPerBatch: u16 = 1_000;
	pub const MaxRemoveEntries: u16 = 1_000;
}

impl pallet_cord_statement::Config for Runtime {
	type EnsureOrigin = pallet_did::EnsureDidOrigin<DidIdentifier, AccountId>;
	type OriginSuccess = pallet_did::DidRawOrigin<AccountId, DidIdentifier>;
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = weights::pallet_cord_statement::WeightInfo<Runtime>;
	type MaxDigestsPerBatch = MaxDigestsPerBatch;
	type MaxRemoveEntries = MaxRemoveEntries;
}

impl pallet_remark::Config for Runtime {
	type WeightInfo = weights::pallet_remark::WeightInfo<Runtime>;
	type RuntimeEvent = RuntimeEvent;
}

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type WeightInfo = weights::pallet_sudo::WeightInfo<Runtime>;
}

impl pallet_network_score::Config for Runtime {
	type RatingProviderIdOf = DidIdentifier;
	type EnsureOrigin = pallet_did::EnsureDidOrigin<DidIdentifier, AccountId>;
	type OriginSuccess = pallet_did::DidRawOrigin<AccountId, DidIdentifier>;
	type RuntimeEvent = RuntimeEvent;
	type MaxEncodedValueLength = ConstU32<128>;
	type MaxRatingValue = ConstU32<50>;
	type WeightInfo = weights::pallet_network_score::WeightInfo<Runtime>;
}

impl pallet_config::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type CordIdentifier = IdentifierV2;
	type DefaultNetworkId = ConstU32<1000>;
}

impl cord_uri::Config for Runtime {}

impl pallet_insecure_randomness_collective_flip::Config for Runtime {}
impl pallet_root_testing::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
}

pub enum AllowBalancesCall {}

impl frame_support::traits::Contains<RuntimeCall> for AllowBalancesCall {
	fn contains(call: &RuntimeCall) -> bool {
		matches!(call, RuntimeCall::Balances(BalancesCall::transfer_allow_death { .. }))
	}
}

fn schedule<T: pallet_contracts::Config>() -> pallet_contracts::Schedule<T> {
	pallet_contracts::Schedule {
		limits: pallet_contracts::Limits {
			runtime_memory: 1024 * 1024 * 1024,
			..Default::default()
		},
		..Default::default()
	}
}

parameter_types! {
	pub const DepositPerItem: Balance = deposit(1, 0);
	pub const DepositPerByte: Balance = deposit(0, 1);
	pub Schedule: pallet_contracts::Schedule<Runtime> = schedule::<Runtime>();
	pub const DefaultDepositLimit: Balance = deposit(1024, 1024 * 1024);
	pub const CodeHashLockupDepositPercent: Perbill = Perbill::from_percent(20);
	pub const MaxDelegateDependencies: u32 = 32;
}

impl pallet_contracts::Config for Runtime {
	type Time = Timestamp;
	type Randomness = RandomnessCollectiveFlip;
	type Currency = Balances;
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type CallFilter = AllowBalancesCall;
	type DepositPerItem = DepositPerItem;
	type DepositPerByte = DepositPerByte;
	type CallStack = [pallet_contracts::Frame<Self>; 23];
	type WeightPrice = pallet_transaction_payment::Pallet<Self>;
	type WeightInfo = pallet_contracts::weights::SubstrateWeight<Self>;
	type ChainExtension = ();
	type Schedule = Schedule;
	type AddressGenerator = pallet_contracts::DefaultAddressGenerator;
	type MaxCodeLen = ConstU32<{ 128 * 1024 }>;
	type DefaultDepositLimit = DefaultDepositLimit;
	type MaxStorageKeyLen = ConstU32<128>;
	type MaxDebugBufferLen = ConstU32<{ 2 * 1024 * 1024 }>;
	type MaxTransientStorageSize = ConstU32<{ 1 * 1024 * 1024 }>;
	type UnsafeUnstableInterface = ConstBool<true>;
	type CodeHashLockupDepositPercent = CodeHashLockupDepositPercent;
	type MaxDelegateDependencies = MaxDelegateDependencies;
	type RuntimeHoldReason = RuntimeHoldReason;
	type Environment = ();
	type Debug = ();
	type ApiVersion = ();
	type Migrations = ();
	type Xcm = ();
	type UploadOrigin = EnsureSigned<Self::AccountId>;
	type InstantiateOrigin = EnsureSigned<Self::AccountId>;
}

parameter_types! {
	pub StatementCost: Balance = 1 * UNITS;
	pub StatementByteCost: Balance = 10 * MILLI;
	pub const MinAllowedStatements: u32 = 4;
	pub const MaxAllowedStatements: u32 = 10;
	pub const MinAllowedBytes: u32 = 1024;
	pub const MaxAllowedBytes: u32 = 4096;
}

impl pallet_statement::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type StatementCost = StatementCost;
	type ByteCost = StatementByteCost;
	type MinAllowedStatements = MinAllowedStatements;
	type MaxAllowedStatements = MaxAllowedStatements;
	type MinAllowedBytes = MinAllowedBytes;
	type MaxAllowedBytes = MaxAllowedBytes;
}

#[frame_support::runtime]
mod runtime {
	use super::*;

	#[runtime::runtime]
	#[runtime::derive(
		RuntimeCall,
		RuntimeEvent,
		RuntimeError,
		RuntimeOrigin,
		RuntimeFreezeReason,
		RuntimeHoldReason,
		RuntimeSlashReason,
		RuntimeLockId,
		RuntimeTask
	)]
	pub struct Runtime;

	#[runtime::pallet_index(0)]
	pub type System = frame_system::Pallet<Runtime>;

	#[runtime::pallet_index(1)]
	pub type Utility = pallet_utility::Pallet<Runtime>;

	#[runtime::pallet_index(2)]
	pub type Babe = pallet_babe::Pallet<Runtime>;

	#[runtime::pallet_index(3)]
	pub type Timestamp = pallet_timestamp::Pallet<Runtime>;

	#[runtime::pallet_index(4)]
	pub type AuthorityMembership = authority_membership::Pallet<Runtime>;

	#[runtime::pallet_index(5)]
	pub type Authorship = pallet_authorship::Pallet<Runtime>;

	#[runtime::pallet_index(6)]
	pub type Indices = pallet_indices::Pallet<Runtime>;

	#[runtime::pallet_index(7)]
	pub type Balances = pallet_balances::Pallet<Runtime>;

	#[runtime::pallet_index(8)]
	pub type TransactionPayment = pallet_transaction_payment::Pallet<Runtime>;

	#[runtime::pallet_index(12)]
	pub type Session = pallet_session::Pallet<Runtime>;

	#[runtime::pallet_index(20)]
	pub type Grandpa = pallet_grandpa::Pallet<Runtime>;

	#[runtime::pallet_index(23)]
	pub type ImOnline = pallet_im_online::Pallet<Runtime>;

	#[runtime::pallet_index(24)]
	pub type AuthorityDiscovery = pallet_authority_discovery::Pallet<Runtime>;

	#[runtime::pallet_index(25)]
	pub type Offences = pallet_cord_offences::Pallet<Runtime>;

	#[runtime::pallet_index(26)]
	pub type Historical = pallet_session_historical::Pallet<Runtime>;

	#[runtime::pallet_index(27)]
	pub type RandomnessCollectiveFlip = pallet_insecure_randomness_collective_flip::Pallet<Runtime>;

	#[runtime::pallet_index(28)]
	pub type Identity = pallet_cord_identity::Pallet<Runtime>;

	#[runtime::pallet_index(30)]
	pub type Scheduler = pallet_scheduler::Pallet<Runtime>;

	#[runtime::pallet_index(32)]
	pub type Multisig = pallet_multisig::Pallet<Runtime>;

	#[runtime::pallet_index(35)]
	pub type Beefy = pallet_beefy::Pallet<Runtime>;

	// MMR leaf construction must be after session in order to have a leaf's next_auth_set
	// refer to block<N>. See issue polkadot-fellows/runtimes#160 for details.
	#[runtime::pallet_index(36)]
	pub type Mmr = pallet_mmr::Pallet<Runtime>;

	#[runtime::pallet_index(37)]
	pub type MmrLeaf = pallet_beefy_mmr::Pallet<Runtime>;

	#[runtime::pallet_index(40)]
	pub type Assets = pallet_assets::Pallet<Runtime, Instance1>;

	#[runtime::pallet_index(41)]
	pub type PoolAssets = pallet_assets::Pallet<Runtime, Instance2>;

	#[runtime::pallet_index(42)]
	pub type AssetConversion = pallet_asset_conversion::Pallet<Runtime>;

	#[runtime::pallet_index(45)]
	pub type Statement = pallet_statement::Pallet<Runtime>;

	#[runtime::pallet_index(69)]
	pub type NodeAuthorization = pallet_cord_node_authorization::Pallet<Runtime>;

	#[runtime::pallet_index(70)]
	pub type Identifier = identifier::Pallet<Runtime>;

	#[runtime::pallet_index(71)]
	pub type NetworkMembership = pallet_network_membership::Pallet<Runtime>;

	#[runtime::pallet_index(72)]
	pub type Did = pallet_did::Pallet<Runtime>;

	#[runtime::pallet_index(73)]
	pub type Schema = pallet_schema::Pallet<Runtime>;

	#[runtime::pallet_index(74)]
	pub type ChainSpace = pallet_chain_space::Pallet<Runtime>;

	#[runtime::pallet_index(75)]
	pub type CordStatement = pallet_cord_statement::Pallet<Runtime>;

	#[runtime::pallet_index(76)]
	pub type DidName = pallet_did_name::Pallet<Runtime>;

	#[runtime::pallet_index(77)]
	pub type NetworkScore = pallet_network_score::Pallet<Runtime>;

	#[runtime::pallet_index(80)]
	pub type NetworkParameters = pallet_config::Pallet<Runtime>;

	#[runtime::pallet_index(81)]
	pub type Registries = pallet_registries::Pallet<Runtime>;

	#[runtime::pallet_index(82)]
	pub type Entries = pallet_entries::Pallet<Runtime>;

	#[runtime::pallet_index(83)]
	pub type SchemaAccounts = pallet_schema_accounts::Pallet<Runtime>;

	#[runtime::pallet_index(84)]
	pub type IdentifierV2 = cord_uri::Pallet<Runtime>;

	#[runtime::pallet_index(101)]
	pub type Contracts = pallet_contracts::Pallet<Runtime>;

	#[runtime::pallet_index(102)]
	pub type Remark = pallet_remark::Pallet<Runtime>;

	#[runtime::pallet_index(103)]
	pub type RuntimeUpgrade = pallet_runtime_upgrade::Pallet<Runtime>;

	#[runtime::pallet_index(104)]
	pub type RootTesting = pallet_root_testing::Pallet<Runtime>;

	#[runtime::pallet_index(255)]
	pub type Sudo = pallet_sudo::Pallet<Runtime>;
}

#[rustfmt::skip]
impl pallet_did::DeriveDidCallAuthorizationVerificationKeyRelationship for RuntimeCall {
	fn derive_verification_key_relationship(
		&self,
	) -> pallet_did::DeriveDidCallKeyRelationshipResult {
		fn single_key_relationship(
			calls: &[RuntimeCall],
		) -> pallet_did::DeriveDidCallKeyRelationshipResult {
			let init = calls
				.get(0)
				.ok_or(pallet_did::RelationshipDeriveError::InvalidCallParameter)?
				.derive_verification_key_relationship()?;
			calls
				.iter()
				.skip(1)
				.map(RuntimeCall::derive_verification_key_relationship)
				.try_fold(init, |acc, next| {
					if Ok(acc) == next {
						Ok(acc)
					} else {
						Err(pallet_did::RelationshipDeriveError::InvalidCallParameter)
					}
				})
		}
		match self {
			// DID creation is not allowed through the DID proxy.
			RuntimeCall::Did(pallet_did::Call::create { .. }) => {
				Err(pallet_did::RelationshipDeriveError::NotCallableByDid)
			},
			RuntimeCall::Did { .. } => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::DidName { .. } => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::Schema { .. } => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::CordStatement { .. } => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::NetworkScore { .. } => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::add_delegate { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::CapabilityDelegation)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::add_admin_delegate { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::CapabilityDelegation)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::add_delegator { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::CapabilityDelegation)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::remove_delegate { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::CapabilityDelegation)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::create { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::archive { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::restore { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::subspace_create { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::update_transaction_capacity { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::ChainSpace(pallet_chain_space::Call::update_transaction_capacity_sub { .. }) => {
				Ok(pallet_did::DidVerificationKeyRelationship::Authentication)
			},
			RuntimeCall::Utility(pallet_utility::Call::batch { calls }) => {
				single_key_relationship(&calls[..])
			},
			RuntimeCall::Utility(pallet_utility::Call::batch_all { calls }) => {
				single_key_relationship(&calls[..])
			},
			RuntimeCall::Utility(pallet_utility::Call::force_batch { calls }) => {
				single_key_relationship(&calls[..])
			},
			#[cfg(not(feature = "runtime-benchmarks"))]
			_ => Err(pallet_did::RelationshipDeriveError::NotCallableByDid),
			// By default, returns the authentication key
			#[cfg(feature = "runtime-benchmarks")]
			_ => Ok(pallet_did::DidVerificationKeyRelationship::Authentication),
		}
	}

	// Always return a System::remark() extrinsic call
	#[cfg(feature = "runtime-benchmarks")]
	fn get_call_for_did_call_benchmark() -> Self {
		RuntimeCall::System(frame_system::Call::remark { remark: vec![] })
	}
}

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, AccountIndex>;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;
/// `BlockId` type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;
/// The `SignedExtension` to the basic transaction logic.
pub type SignedExtra = (
	pallet_network_membership::CheckNetworkMembership<Runtime>,
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckMortality<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
	frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;
/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra>;

pub type Migrations = migrations::Unreleased;
/// The runtime migrations per release.
#[allow(deprecated, missing_docs)]
pub mod migrations {
	/// Unreleased migrations. Add new ones here:
	pub type Unreleased = ();
}

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
	Migrations,
>;

type EventRecord = frame_system::EventRecord<
	<Runtime as frame_system::Config>::RuntimeEvent,
	<Runtime as frame_system::Config>::Hash,
>;

parameter_types! {
	pub BeefySetIdSessionEntries: u32 = BondingDuration::get() * SessionsPerEra::get();
}

impl pallet_beefy::Config for Runtime {
	type BeefyId = BeefyId;
	type MaxAuthorities = MaxAuthorities;
	type MaxNominators = ConstU32<0>;
	type MaxSetIdSessionEntries = BeefySetIdSessionEntries;
	type OnNewValidatorSet = MmrLeaf;
	type AncestryHelper = MmrLeaf;
	type WeightInfo = ();
	type KeyOwnerProof = <Historical as KeyOwnerProofSystem<(KeyTypeId, BeefyId)>>::Proof;
	type EquivocationReportSystem =
		pallet_beefy::EquivocationReportSystem<Self, Offences, Historical, ReportLongevity>;
}

/// MMR helper types.
mod mmr {
	use super::*;
	pub use pallet_mmr::primitives::*;

	pub type Leaf = <<Runtime as pallet_mmr::Config>::LeafData as LeafDataProvider>::LeafData;
	pub type Hash = <Hashing as sp_runtime::traits::Hash>::Output;
	pub type Hashing = <Runtime as pallet_mmr::Config>::Hashing;
}

#[cfg(feature = "runtime-benchmarks")]
mod benches {
	frame_benchmarking::define_benchmarks!(
		[frame_benchmarking, BaselineBench::<Runtime>]
		[pallet_babe, Babe]
		[pallet_beefy_mmr, MmrLeaf]
		[pallet_balances, Balances]
		[pallet_contracts, Contracts]
		[pallet_grandpa, Grandpa]
		[pallet_cord_identity, Identity]
		[pallet_session, SessionBench::<Runtime>]
		[pallet_im_online, ImOnline]
		[pallet_indices, Indices]
		[pallet_mmr, Mmr]
		[pallet_multisig, Multisig]
		[pallet_remark, Remark]
		[pallet_scheduler, Scheduler]
		[frame_system, SystemBench::<Runtime>]
		[pallet_timestamp, Timestamp]
		[pallet_utility, Utility]
		[pallet_schema, Schema]
		[pallet_cord_statement, CordStatement]
		[pallet_chain_space, ChainSpace]
		[pallet_did, Did]
		[pallet_did_name, DidName]
		[pallet_network_membership, NetworkMembership]
		[pallet_network_score, NetworkScore]
		[pallet_sudo, Sudo]
	);
}

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
			Executive::execute_block(block);
		}

		fn initialize_block(header: &<Block as BlockT>::Header) -> sp_runtime::ExtrinsicInclusionMode {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> sp_std::vec::Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl sp_block_builder::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(block: Block, data: InherentData) -> CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
			block_hash: <Block as BlockT>::Hash,
		) -> TransactionValidity {
			Executive::validate_transaction(source, tx, block_hash)
		}
	}

	impl sp_statement_store::runtime_api::ValidateStatement<Block> for Runtime {
		fn validate_statement(
			source: sp_statement_store::runtime_api::StatementSource,
			statement: sp_statement_store::Statement,
		) -> Result<sp_statement_store::runtime_api::ValidStatement, sp_statement_store::runtime_api::InvalidStatement> {
			Statement::validate_statement(source, statement)
		}
	}

	impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
		fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
			Grandpa::grandpa_authorities()
		}

		fn current_set_id() -> sp_consensus_grandpa::SetId {
			Grandpa::current_set_id()
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			equivocation_proof: sp_consensus_grandpa::EquivocationProof<
				<Block as BlockT>::Hash,
				NumberFor<Block>,
			>,
			key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			let key_owner_proof = key_owner_proof.decode()?;

			Grandpa::submit_unsigned_equivocation_report(
				equivocation_proof,
				key_owner_proof,
			)
		}

		fn generate_key_ownership_proof(
			_set_id: sp_consensus_grandpa::SetId,
			authority_id: GrandpaId,
		) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
			use codec::Encode;

			Historical::prove((sp_consensus_grandpa::KEY_TYPE, authority_id))
				.map(|p| p.encode())
				.map(sp_consensus_grandpa::OpaqueKeyOwnershipProof::new)
		}
	}

	impl sp_consensus_babe::BabeApi<Block> for Runtime {
		fn configuration() -> sp_consensus_babe::BabeConfiguration {
			let epoch_config = Babe::epoch_config().unwrap_or(BABE_GENESIS_EPOCH_CONFIG);
			sp_consensus_babe::BabeConfiguration {
				slot_duration: Babe::slot_duration(),
				epoch_length: EpochDuration::get(),
				c: epoch_config.c,
				authorities: Babe::authorities().to_vec(),
				randomness: Babe::randomness(),
				allowed_slots: epoch_config.allowed_slots,
			}
		}

		fn current_epoch_start() -> sp_consensus_babe::Slot {
			Babe::current_epoch_start()
		}

		fn current_epoch() -> sp_consensus_babe::Epoch {
			Babe::current_epoch()
		}

		fn next_epoch() -> sp_consensus_babe::Epoch {
			Babe::next_epoch()
		}

		fn generate_key_ownership_proof(
			_slot: sp_consensus_babe::Slot,
			authority_id: sp_consensus_babe::AuthorityId,
		) -> Option<sp_consensus_babe::OpaqueKeyOwnershipProof> {
			use codec::Encode;

			Historical::prove((sp_consensus_babe::KEY_TYPE, authority_id))
				.map(|p| p.encode())
				.map(sp_consensus_babe::OpaqueKeyOwnershipProof::new)
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			equivocation_proof: sp_consensus_babe::EquivocationProof<<Block as BlockT>::Header>,
			key_owner_proof: sp_consensus_babe::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			let key_owner_proof = key_owner_proof.decode()?;

			Babe::submit_unsigned_equivocation_report(
				equivocation_proof,
				key_owner_proof,
			)
		}
	}

	impl sp_authority_discovery::AuthorityDiscoveryApi<Block> for Runtime {
		fn authorities() -> Vec<AuthorityDiscoveryId> {
			AuthorityDiscovery::authorities()
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
		fn account_nonce(account: AccountId) -> Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_assets_runtime_api::AssetsApi<
		Block,
		AccountId,
		Balance,
		u32,
	> for Runtime
	{
		fn account_balances(account: AccountId) -> Vec<(u32, Balance)> {
			Assets::account_balances(account)
		}
	}

	impl pallet_contracts::ContractsApi<Block, AccountId, Balance, BlockNumber, Hash, EventRecord> for Runtime
	{
		fn call(
			origin: AccountId,
			dest: AccountId,
			value: Balance,
			gas_limit: Option<Weight>,
			storage_deposit_limit: Option<Balance>,
			input_data: Vec<u8>,
		) -> pallet_contracts::ContractExecResult<Balance, EventRecord> {
			let gas_limit = gas_limit.unwrap_or(BlockWeights::get().max_block);
			Contracts::bare_call(
				origin,
				dest,
				value,
				gas_limit,
				storage_deposit_limit,
				input_data,
				pallet_contracts::DebugInfo::UnsafeDebug,
				pallet_contracts::CollectEvents::UnsafeCollect,
				pallet_contracts::Determinism::Enforced,
			)
		}

		fn instantiate(
			origin: AccountId,
			value: Balance,
			gas_limit: Option<Weight>,
			storage_deposit_limit: Option<Balance>,
			code: pallet_contracts::Code<Hash>,
			data: Vec<u8>,
			salt: Vec<u8>,
		) -> pallet_contracts::ContractInstantiateResult<AccountId, Balance, EventRecord>
		{
			let gas_limit = gas_limit.unwrap_or(BlockWeights::get().max_block);
			Contracts::bare_instantiate(
				origin,
				value,
				gas_limit,
				storage_deposit_limit,
				code,
				data,
				salt,
				pallet_contracts::DebugInfo::UnsafeDebug,
				pallet_contracts::CollectEvents::UnsafeCollect,
			)
		}

		fn upload_code(
			origin: AccountId,
			code: Vec<u8>,
			storage_deposit_limit: Option<Balance>,
			determinism: pallet_contracts::Determinism,
		) -> pallet_contracts::CodeUploadResult<Hash, Balance>
		{
			Contracts::bare_upload_code(
				origin,
				code,
				storage_deposit_limit,
				determinism,
			)
		}

		fn get_storage(
			address: AccountId,
			key: Vec<u8>,
		) -> pallet_contracts::GetStorageResult {
			Contracts::get_storage(
				address,
				key
			)
		}
	}

	impl pallet_did_runtime_api::DidApi<
		Block,
		DidIdentifier,
		AccountId,
		Hash,
		BlockNumber
	> for Runtime {
		fn query(did: DidIdentifier) -> Option<
			pallet_did_runtime_api::RawDidLinkedInfo<
				DidIdentifier,
				AccountId,
				Hash,
				BlockNumber
			>
		> {
			let details = pallet_did::Did::<Runtime>::get(&did)?;
			let name = pallet_did_name::Names::<Runtime>::get(&did).map(Into::into);
			let service_endpoints = pallet_did::ServiceEndpoints::<Runtime>::iter_prefix(&did).map(|e| From::from(e.1)).collect();

			Some(pallet_did_runtime_api::RawDidLinkedInfo {
				identifier: did.clone(),
				account: did,
				name,
				service_endpoints,
				details: details.into(),
			})
		}
		fn query_by_name(name: Vec<u8>) -> Option<pallet_did_runtime_api::RawDidLinkedInfo<
				DidIdentifier,
				AccountId,
				Hash,
				BlockNumber
			>
		> {
			let dname: pallet_did_name::did_name::AsciiDidName<Runtime> = name.try_into().ok()?;
			pallet_did_name::Owner::<Runtime>::get(&dname)
				.and_then(|owner_info| {
					pallet_did::Did::<Runtime>::get(&owner_info.owner).map(|details| (owner_info, details))
				})
				.map(|(owner_info, details)| {
					let service_endpoints = pallet_did::ServiceEndpoints::<Runtime>::iter_prefix(&owner_info.owner).map(|e| From::from(e.1)).collect();

					pallet_did_runtime_api::RawDidLinkedInfo{
						identifier: owner_info.owner.clone(),
						account: owner_info.owner,
						name: Some(dname.into()),
						service_endpoints,
						details: details.into(),
					}
			})
		}
	}

	impl pallet_transaction_weight_runtime_api::TransactionWeightApi<Block> for Runtime {
		fn query_weight_info(uxt: <Block as BlockT>::Extrinsic) -> RuntimeDispatchWeightInfo {
			NetworkMembership::query_weight_info(uxt)
		}
	}


	impl pallet_asset_conversion::AssetConversionApi<
		Block,
		Balance,
		NativeOrWithId<u32>
	> for Runtime
	{
		fn quote_price_exact_tokens_for_tokens(asset1: NativeOrWithId<u32>, asset2: NativeOrWithId<u32>, amount: Balance, include_fee: bool) -> Option<Balance> {
			AssetConversion::quote_price_exact_tokens_for_tokens(asset1, asset2, amount, include_fee)
		}

		fn quote_price_tokens_for_exact_tokens(asset1: NativeOrWithId<u32>, asset2: NativeOrWithId<u32>, amount: Balance, include_fee: bool) -> Option<Balance> {
			AssetConversion::quote_price_tokens_for_exact_tokens(asset1, asset2, amount, include_fee)
		}

		fn get_reserves(asset1: NativeOrWithId<u32>, asset2: NativeOrWithId<u32>) -> Option<(Balance, Balance)> {
			AssetConversion::get_reserves(asset1, asset2).ok()
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
		Block,
		Balance,
	> for Runtime {
		fn query_info(uxt: <Block as BlockT>::Extrinsic, len: u32) -> RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}
		fn query_fee_details(uxt: <Block as BlockT>::Extrinsic, len: u32) -> FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}
		fn query_weight_to_fee(weight: Weight) -> Balance {
			TransactionPayment::weight_to_fee(weight)
		}
		fn query_length_to_fee(length: u32) -> Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	#[api_version(5)]
	impl sp_consensus_beefy::BeefyApi<Block, BeefyId> for Runtime {
		fn beefy_genesis() -> Option<BlockNumber> {
			pallet_beefy::GenesisBlock::<Runtime>::get()
		}

		fn validator_set() -> Option<sp_consensus_beefy::ValidatorSet<BeefyId>> {
			Beefy::validator_set()
		}

		fn submit_report_double_voting_unsigned_extrinsic(
			equivocation_proof: sp_consensus_beefy::DoubleVotingProof<
				BlockNumber,
				BeefyId,
				BeefySignature,
			>,
			key_owner_proof: sp_consensus_beefy::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			let key_owner_proof = key_owner_proof.decode()?;

			Beefy::submit_unsigned_double_voting_report(
				equivocation_proof,
				key_owner_proof,
			)
		}

		fn submit_report_fork_voting_unsigned_extrinsic(
			equivocation_proof:
				sp_consensus_beefy::ForkVotingProof<
					<Block as BlockT>::Header,
					BeefyId,
					sp_runtime::OpaqueValue
				>,
			key_owner_proof: sp_consensus_beefy::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			Beefy::submit_unsigned_fork_voting_report(
				equivocation_proof.try_into()?,
				key_owner_proof.decode()?,
			)
		}

		fn submit_report_future_block_voting_unsigned_extrinsic(
			equivocation_proof: sp_consensus_beefy::FutureBlockVotingProof<BlockNumber, BeefyId>,
			key_owner_proof: sp_consensus_beefy::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			Beefy::submit_unsigned_future_block_voting_report(
				equivocation_proof,
				key_owner_proof.decode()?,
			)
		}

		fn generate_key_ownership_proof(
			_set_id: sp_consensus_beefy::ValidatorSetId,
			authority_id: BeefyId,
		) -> Option<sp_consensus_beefy::OpaqueKeyOwnershipProof> {
			Historical::prove((sp_consensus_beefy::KEY_TYPE, authority_id))
				.map(|p| p.encode())
				.map(sp_consensus_beefy::OpaqueKeyOwnershipProof::new)
		}

		fn generate_ancestry_proof(
			prev_block_number: BlockNumber,
			best_known_block_number: Option<BlockNumber>,
		) -> Option<sp_runtime::OpaqueValue> {
			use sp_consensus_beefy::AncestryHelper;

			MmrLeaf::generate_proof(prev_block_number, best_known_block_number)
				.map(|p| p.encode())
				.map(sp_runtime::OpaqueValue::new)
		}
	}

	impl pallet_mmr::primitives::MmrApi<
		Block,
		mmr::Hash,
		BlockNumber,
	> for Runtime {
		fn mmr_root() -> Result<mmr::Hash, mmr::Error> {
			Ok(pallet_mmr::RootHash::<Runtime>::get())
		}

		fn mmr_leaf_count() -> Result<mmr::LeafIndex, mmr::Error> {
			Ok(pallet_mmr::NumberOfLeaves::<Runtime>::get())
		}

		fn generate_proof(
			block_numbers: Vec<BlockNumber>,
			best_known_block_number: Option<BlockNumber>,
		) -> Result<(Vec<mmr::EncodableOpaqueLeaf>, mmr::LeafProof<mmr::Hash>), mmr::Error> {
			Mmr::generate_proof(block_numbers, best_known_block_number).map(
				|(leaves, proof)| {
					(
						leaves
							.into_iter()
							.map(|leaf| mmr::EncodableOpaqueLeaf::from_leaf(&leaf))
							.collect(),
						proof,
					)
				},
			)
		}

		fn verify_proof(leaves: Vec<mmr::EncodableOpaqueLeaf>, proof: mmr::LeafProof<mmr::Hash>)
			-> Result<(), mmr::Error>
		{
			let leaves = leaves.into_iter().map(|leaf|
				leaf.into_opaque_leaf()
				.try_decode()
				.ok_or(mmr::Error::Verify)).collect::<Result<Vec<mmr::Leaf>, mmr::Error>>()?;
			Mmr::verify_leaves(leaves, proof)
		}

		fn verify_proof_stateless(
			root: mmr::Hash,
			leaves: Vec<mmr::EncodableOpaqueLeaf>,
			proof: mmr::LeafProof<mmr::Hash>
		) -> Result<(), mmr::Error> {
			let nodes = leaves.into_iter().map(|leaf|mmr::DataOrHash::Data(leaf.into_opaque_leaf())).collect();
			pallet_mmr::verify_leaves_proof::<mmr::Hashing, _>(root, nodes, proof)
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
			SessionKeys::generate(seed)
		}

		fn decode_session_keys(
			encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
			SessionKeys::decode_into_raw_public_keys(&encoded)
		}
	}

	#[cfg(feature = "try-runtime")]
	impl frame_try_runtime::TryRuntime<Block> for Runtime {
	fn on_runtime_upgrade(checks: frame_try_runtime::UpgradeCheckSelect) -> (Weight, Weight) {
			log::info!("try-runtime::on_runtime_upgrade cord.");
			let weight = Executive::try_runtime_upgrade(checks).unwrap();
			(weight, BlockWeights::get().max_block)
		}

		fn execute_block(
			block: Block,
			state_root_check: bool,
			signature_check: bool,
			select: frame_try_runtime::TryStateSelect,
		) -> Weight {
			// NOTE: intentional unwrap: we don't want to propagate the error backwards, and want to
			// have a backtrace here.
			Executive::try_execute_block(block, state_root_check, signature_check, select).unwrap()
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	impl frame_benchmarking::Benchmark<Block> for Runtime {
		fn benchmark_metadata(extra: bool) -> (
			Vec<frame_benchmarking::BenchmarkList>,
			Vec<frame_support::traits::StorageInfo>,
		) {
			use frame_benchmarking::{baseline, Benchmarking, BenchmarkList};
			use frame_support::traits::StorageInfoTrait;

			use pallet_cord_session_benchmarking::Pallet as SessionBench;
			use frame_system_benchmarking::Pallet as SystemBench;
			use baseline::Pallet as BaselineBench;

			let mut list = Vec::<BenchmarkList>::new();
			list_benchmarks!(list, extra);

			let storage_info = AllPalletsWithSystem::storage_info();
			(list, storage_info)
		}

		fn dispatch_benchmark(
			config: frame_benchmarking::BenchmarkConfig,
		) -> Result<
			Vec<frame_benchmarking::BenchmarkBatch>,
			sp_runtime::RuntimeString,
		> {
			use frame_support::traits::WhitelistedStorageKeys;
			use frame_benchmarking::{baseline, Benchmarking, BenchmarkBatch };
			use sp_storage::TrackedStorageKey;

			use pallet_cord_session_benchmarking::Pallet as SessionBench;
			use frame_system_benchmarking::Pallet as SystemBench;
			use baseline::Pallet as BaselineBench;

			impl pallet_cord_session_benchmarking::Config for Runtime {}
			impl frame_system_benchmarking::Config for Runtime {}
			impl baseline::Config for Runtime {}

			let whitelist: Vec<TrackedStorageKey> = AllPalletsWithSystem::whitelisted_storage_keys();

			let mut batches = Vec::<BenchmarkBatch>::new();
			let params = (&config, &whitelist);
			add_benchmarks!(params, batches);
			Ok(batches)
		}
	}

	impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
		fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
			build_state::<RuntimeGenesisConfig>(config)
		}

		fn get_preset(id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
			get_preset::<RuntimeGenesisConfig>(id, |_| None)
		}

		fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
			vec![]
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use frame_system::offchain::CreateSignedTransaction;

	#[test]
	fn validate_transaction_submitter_bounds() {
		fn is_submit_signed_transaction<T>()
		where
			T: CreateSignedTransaction<RuntimeCall>,
		{
		}

		is_submit_signed_transaction::<Runtime>();
	}
	#[test]
	fn call_size() {
		let size = core::mem::size_of::<RuntimeCall>();
		assert!(
			size <= CALL_PARAMS_MAX_SIZE,
			"size of RuntimeCall {} is more than {CALL_PARAMS_MAX_SIZE} bytes.
			 Some calls have too big arguments, use Box to reduce the size of RuntimeCall.
			 If the limit is too strong, maybe consider increase the limit.",
			size,
		);
	}
}
