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

use crate as pallet_registries;
use cord_utilities::mock::{mock_origin, SubjectId};
use frame_support::{derive_impl, parameter_types};

use frame_system::EnsureRoot;
use pallet_namespace::IsPermissioned;
use sp_runtime::{
	traits::{IdentifyAccount, IdentityLookup, Verify},
	BuildStorage, MultiSignature,
};

type Signature = MultiSignature;
type AccountPublic = <Signature as Verify>::Signer;
pub type AccountId = <AccountPublic as IdentifyAccount>::AccountId;
pub(crate) type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		SchemaAccounts: pallet_schema_accounts,
		NameSpace: pallet_namespace,
		Registries: pallet_registries,
		Identifier: identifier,
		MockOrigin: mock_origin,
	}
);

parameter_types! {
	pub const SS58Prefix: u8 = 29;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Block = Block;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type SS58Prefix = SS58Prefix;
}

impl mock_origin::Config for Test {
	type RuntimeOrigin = RuntimeOrigin;
	type AccountId = AccountId;
	type SubjectId = SubjectId;
}

parameter_types! {
	pub const MaxEncodedSchemaLength: u32 = 15_360;
}

pub struct NetworkPermission;
impl IsPermissioned for NetworkPermission {
	fn is_permissioned() -> bool {
		true
	}
}

parameter_types! {
	#[derive(Debug, Clone)]
	pub const MaxNameSpaceDelegates: u32 = 5u32;
	pub const MaxNameSpaceBlobSize: u32 = 4u32 * 1024;
}

impl pallet_namespace::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type ChainSpaceOrigin = EnsureRoot<AccountId>;
	type NetworkPermission = NetworkPermission;
	type MaxNameSpaceDelegates = MaxNameSpaceDelegates;
	type MaxNameSpaceBlobSize = MaxNameSpaceBlobSize;
	type WeightInfo = ();
}

impl pallet_schema_accounts::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type MaxEncodedSchemaLength = MaxEncodedSchemaLength;
	type WeightInfo = ();
}

parameter_types! {
	#[derive(Debug, Clone)]
	pub const MaxRegistryDelegates: u32 = 5u32;
}

parameter_types! {
	pub const MaxRegistryBlobSize: u32 = 4 * 1024;
	pub const MaxEncodedInputLength: u32 = 30;
}

impl pallet_registries::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type MaxRegistryDelegates = MaxRegistryDelegates;
	type MaxEncodedInputLength = MaxEncodedInputLength;
	type MaxRegistryBlobSize = MaxRegistryBlobSize;
	type WeightInfo = ();
}

parameter_types! {
	pub const MaxEventsHistory: u32 = 6u32;
}

impl identifier::Config for Test {
	type MaxEventsHistory = MaxEventsHistory;
}

#[allow(dead_code)]
pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
	let t: sp_runtime::Storage =
		frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	#[cfg(feature = "runtime-benchmarks")]
	let keystore = sp_keystore::testing::MemoryKeystore::new();
	#[cfg(feature = "runtime-benchmarks")]
	ext.register_extension(sp_keystore::KeystoreExt(sp_std::sync::Arc::new(keystore)));
	ext.execute_with(|| System::set_block_number(1));
	ext
}
