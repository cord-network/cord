// This file is part of CORD – https://cord.network

// Copyright (C) 2019-2023 BOTLabs GmbH.
// Copyright (C) Dhiway Networks Pvt. Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted to meet the requirements of the CORD project.

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

#[cfg(test)]
pub use crate::mock::runtime::*;

// Mocks that are only used internally
#[cfg(test)]
pub(crate) mod runtime {
	use cord_utilities::mock::{mock_origin, SubjectId};
	use frame_support::parameter_types;
	use frame_system::EnsureRoot;
	use sp_runtime::{
		testing::Header,
		traits::{BlakeTwo256, IdentifyAccount, IdentityLookup, Verify},
		MultiSignature,
	};

	use crate::{
		self as pallet_did_names,
		did_name::{self, AsciiDidName},
	};

	type Index = u64;
	type BlockNumber = u64;
	pub(crate) type Balance = u128;

	type Hash = sp_core::H256;
	type Signature = MultiSignature;
	type AccountPublic = <Signature as Verify>::Signer;
	type AccountId = <AccountPublic as IdentifyAccount>::AccountId;

	type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
	type Block = frame_system::mocking::MockBlock<Test>;

	frame_support::construct_runtime!(
		pub enum Test where
			Block = Block,
			NodeBlock = Block,
			UncheckedExtrinsic = UncheckedExtrinsic,
		{
			System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
			DidNames: pallet_did_names::{Pallet, Storage, Call, Event<T>},
			MockOrigin: mock_origin::{Pallet, Origin<T>},
		}
	);

	parameter_types! {
		pub const SS58Prefix: u8 = 38;
		pub const BlockHashCount: BlockNumber = 2400;
	}

	impl frame_system::Config for Test {
		type BaseCallFilter = frame_support::traits::Everything;
		type BlockWeights = ();
		type BlockLength = ();
		type DbWeight = ();
		type RuntimeOrigin = RuntimeOrigin;
		type RuntimeCall = RuntimeCall;
		type Index = Index;
		type BlockNumber = BlockNumber;
		type Hash = Hash;
		type Hashing = BlakeTwo256;
		type AccountId = AccountId;
		type Lookup = IdentityLookup<Self::AccountId>;
		type Header = Header;
		type RuntimeEvent = RuntimeEvent;
		type BlockHashCount = BlockHashCount;
		type Version = ();
		type PalletInfo = PalletInfo;
		type AccountData = ();
		type OnNewAccount = ();
		type OnKilledAccount = ();
		type SystemWeightInfo = ();
		type SS58Prefix = SS58Prefix;
		type OnSetCode = ();
		type MaxConsumers = frame_support::traits::ConstU32<16>;
	}

	parameter_types! {
		pub const ExistentialDeposit: Balance = 10;
		pub const MaxLocks: u32 = 50;
		pub const MaxReserves: u32 = 50;
	}

	pub(crate) type TestDidName = AsciiDidName<Test>;
	pub(crate) type TestDidNameOwner = SubjectId;
	pub(crate) type TestDidNamePayer = AccountId;
	pub(crate) type TestOwnerOrigin =
		mock_origin::EnsureDoubleOrigin<TestDidNamePayer, TestDidNameOwner>;
	pub(crate) type TestOriginSuccess =
		mock_origin::DoubleOrigin<TestDidNamePayer, TestDidNameOwner>;
	pub(crate) type TestBanOrigin = EnsureRoot<AccountId>;

	parameter_types! {
		pub const MaxNameLength: u32 = 60;
		pub const MinNameLength: u32 = 3;
		pub const MaxPrefixLength: u32 = 50;
	}

	impl pallet_did_names::Config for Test {
		type BanOrigin = TestBanOrigin;
		type EnsureOrigin = TestOwnerOrigin;
		type OriginSuccess = TestOriginSuccess;
		type RuntimeEvent = RuntimeEvent;
		type MaxNameLength = MaxNameLength;
		type MinNameLength = MinNameLength;
		type MaxPrefixLength = MaxPrefixLength;
		type DidName = TestDidName;
		type DidNameOwner = TestDidNameOwner;
		type WeightInfo = ();
	}

	impl mock_origin::Config for Test {
		type RuntimeOrigin = RuntimeOrigin;
		type AccountId = AccountId;
		type SubjectId = SubjectId;
	}

	pub(crate) const ACCOUNT_00: TestDidNamePayer = AccountId::new([1u8; 32]);
	pub(crate) const ACCOUNT_01: TestDidNamePayer = AccountId::new([2u8; 32]);
	pub(crate) const DID_00: TestDidNameOwner = SubjectId(ACCOUNT_00);
	pub(crate) const DID_01: TestDidNameOwner = SubjectId(ACCOUNT_01);
	pub(crate) const DID_NAME_00_INPUT: &[u8; 16] = b"did.name.00@cord";
	pub(crate) const DID_NAME_01_INPUT: &[u8; 16] = b"did.name.01@cord";

	pub(crate) fn get_did_name(did_name_input: &[u8]) -> TestDidName {
		AsciiDidName::try_from(did_name_input.to_vec()).expect("Invalid did name input.")
	}

	#[derive(Clone, Default)]
	pub struct ExtBuilder {
		registered_did_names: Vec<(TestDidNameOwner, TestDidName)>,
		banned_did_names: Vec<TestDidName>,
	}

	impl ExtBuilder {
		#[must_use]
		pub fn with_did_names(mut self, did_names: Vec<(TestDidNameOwner, TestDidName)>) -> Self {
			self.registered_did_names = did_names;
			self
		}

		#[must_use]
		pub fn with_banned_did_names(mut self, did_names: Vec<TestDidName>) -> Self {
			self.banned_did_names = did_names;
			self
		}

		pub fn build(self) -> sp_io::TestExternalities {
			let storage = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
			let mut ext = sp_io::TestExternalities::new(storage);

			ext.execute_with(|| {
				for (owner, did_name) in self.registered_did_names {
					pallet_did_names::Pallet::<Test>::register_name(did_name, owner);
				}
				for did_name in self.banned_did_names {
					assert!(pallet_did_names::Owner::<Test>::get(&did_name).is_none());
					pallet_did_names::Pallet::<Test>::ban_name(&did_name);
				}
			});
			ext
		}

		#[cfg(feature = "runtime-benchmarks")]
		pub fn build_with_keystore(self) -> sp_io::TestExternalities {
			let mut ext = self.build();

			let keystore = sp_keystore::testing::KeyStore::new();
			ext.register_extension(sp_keystore::KeystoreExt(std::sync::Arc::new(keystore)));

			ext
		}
	}
}
