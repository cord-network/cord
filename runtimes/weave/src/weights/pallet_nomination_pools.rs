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

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_nomination_pools`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_nomination_pools::WeightInfo for WeightInfo<T> {
	/// Storage: `NominationPools::MinJoinBond` (r:1 w:0)
	/// Proof: `NominationPools::MinJoinBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::PoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::RewardPools` (r:1 w:1)
	/// Proof: `NominationPools::RewardPools` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::GlobalMaxCommission` (r:1 w:0)
	/// Proof: `NominationPools::GlobalMaxCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:2 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MaxPoolMembersPerPool` (r:1 w:0)
	/// Proof: `NominationPools::MaxPoolMembersPerPool` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MaxPoolMembers` (r:1 w:0)
	/// Proof: `NominationPools::MaxPoolMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForPoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::CounterForPoolMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:3 w:3)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:2 w:2)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::TotalValueLocked` (r:1 w:1)
	/// Proof: `NominationPools::TotalValueLocked` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	fn join() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `3391`
		//  Estimated: `8877`
		// Minimum execution time: 214_612_000 picoseconds.
		Weight::from_parts(216_482_000, 0)
			.saturating_add(Weight::from_parts(0, 8877))
			.saturating_add(T::DbWeight::get().reads(21))
			.saturating_add(T::DbWeight::get().writes(13))
	}
	/// Storage: `NominationPools::PoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::RewardPools` (r:1 w:1)
	/// Proof: `NominationPools::RewardPools` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::GlobalMaxCommission` (r:1 w:0)
	/// Proof: `NominationPools::GlobalMaxCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:3 w:2)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:3 w:3)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:2 w:2)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::TotalValueLocked` (r:1 w:1)
	/// Proof: `NominationPools::TotalValueLocked` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	fn bond_extra_transfer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `3401`
		//  Estimated: `8877`
		// Minimum execution time: 215_272_000 picoseconds.
		Weight::from_parts(217_201_000, 0)
			.saturating_add(Weight::from_parts(0, 8877))
			.saturating_add(T::DbWeight::get().reads(18))
			.saturating_add(T::DbWeight::get().writes(13))
	}
	/// Storage: `NominationPools::ClaimPermissions` (r:1 w:0)
	/// Proof: `NominationPools::ClaimPermissions` (`max_values`: None, `max_size`: Some(41), added: 2516, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::PoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::RewardPools` (r:1 w:1)
	/// Proof: `NominationPools::RewardPools` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::GlobalMaxCommission` (r:1 w:0)
	/// Proof: `NominationPools::GlobalMaxCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:3 w:3)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:3 w:3)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:2 w:2)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::TotalValueLocked` (r:1 w:1)
	/// Proof: `NominationPools::TotalValueLocked` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	fn bond_extra_other() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `3466`
		//  Estimated: `8877`
		// Minimum execution time: 254_422_000 picoseconds.
		Weight::from_parts(257_473_000, 0)
			.saturating_add(Weight::from_parts(0, 8877))
			.saturating_add(T::DbWeight::get().reads(19))
			.saturating_add(T::DbWeight::get().writes(14))
	}
	/// Storage: `NominationPools::ClaimPermissions` (r:1 w:0)
	/// Proof: `NominationPools::ClaimPermissions` (`max_values`: None, `max_size`: Some(41), added: 2516, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::PoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::RewardPools` (r:1 w:1)
	/// Proof: `NominationPools::RewardPools` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::GlobalMaxCommission` (r:1 w:0)
	/// Proof: `NominationPools::GlobalMaxCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn claim_payout() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1172`
		//  Estimated: `4182`
		// Minimum execution time: 85_151_000 picoseconds.
		Weight::from_parts(85_981_000, 0)
			.saturating_add(Weight::from_parts(0, 4182))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `NominationPools::PoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::RewardPools` (r:1 w:1)
	/// Proof: `NominationPools::RewardPools` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::GlobalMaxCommission` (r:1 w:0)
	/// Proof: `NominationPools::GlobalMaxCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:2 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:0)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinNominatorBond` (r:1 w:0)
	/// Proof: `Staking::MinNominatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:3 w:3)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:2 w:2)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::SubPoolsStorage` (r:1 w:1)
	/// Proof: `NominationPools::SubPoolsStorage` (`max_values`: None, `max_size`: Some(1197), added: 3672, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForSubPoolsStorage` (r:1 w:1)
	/// Proof: `NominationPools::CounterForSubPoolsStorage` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn unbond() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `3579`
		//  Estimated: `8877`
		// Minimum execution time: 197_201_000 picoseconds.
		Weight::from_parts(198_832_000, 0)
			.saturating_add(Weight::from_parts(0, 8877))
			.saturating_add(T::DbWeight::get().reads(21))
			.saturating_add(T::DbWeight::get().writes(13))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:0)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::ReversePoolIdLookup` (r:1 w:0)
	/// Proof: `NominationPools::ReversePoolIdLookup` (`max_values`: None, `max_size`: Some(44), added: 2519, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::TotalValueLocked` (r:1 w:1)
	/// Proof: `NominationPools::TotalValueLocked` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[0, 100]`.
	fn pool_withdraw_unbonded(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1871`
		//  Estimated: `4764`
		// Minimum execution time: 79_401_000 picoseconds.
		Weight::from_parts(80_825_411, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			// Standard Error: 528
			.saturating_add(Weight::from_parts(12_695, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(9))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `NominationPools::PoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::SubPoolsStorage` (r:1 w:1)
	/// Proof: `NominationPools::SubPoolsStorage` (`max_values`: None, `max_size`: Some(1197), added: 3672, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::ReversePoolIdLookup` (r:1 w:0)
	/// Proof: `NominationPools::ReversePoolIdLookup` (`max_values`: None, `max_size`: Some(44), added: 2519, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::TotalValueLocked` (r:1 w:1)
	/// Proof: `NominationPools::TotalValueLocked` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForPoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::CounterForPoolMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::ClaimPermissions` (r:0 w:1)
	/// Proof: `NominationPools::ClaimPermissions` (`max_values`: None, `max_size`: Some(41), added: 2516, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[0, 100]`.
	fn withdraw_unbonded_update(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2261`
		//  Estimated: `4764`
		// Minimum execution time: 155_791_000 picoseconds.
		Weight::from_parts(157_359_542, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			// Standard Error: 603
			.saturating_add(Weight::from_parts(12_679, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(13))
			.saturating_add(T::DbWeight::get().writes(9))
	}
	/// Storage: `NominationPools::PoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::SubPoolsStorage` (r:1 w:1)
	/// Proof: `NominationPools::SubPoolsStorage` (`max_values`: None, `max_size`: Some(1197), added: 3672, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:1)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::SlashingSpans` (r:1 w:0)
	/// Proof: `Staking::SlashingSpans` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:1)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:2 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:2 w:1)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:2 w:2)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:0)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::ReversePoolIdLookup` (r:1 w:1)
	/// Proof: `NominationPools::ReversePoolIdLookup` (`max_values`: None, `max_size`: Some(44), added: 2519, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::TotalValueLocked` (r:1 w:1)
	/// Proof: `NominationPools::TotalValueLocked` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForPoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::CounterForPoolMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForReversePoolIdLookup` (r:1 w:1)
	/// Proof: `NominationPools::CounterForReversePoolIdLookup` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::RewardPools` (r:1 w:1)
	/// Proof: `NominationPools::RewardPools` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForRewardPools` (r:1 w:1)
	/// Proof: `NominationPools::CounterForRewardPools` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForSubPoolsStorage` (r:1 w:1)
	/// Proof: `NominationPools::CounterForSubPoolsStorage` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::Metadata` (r:1 w:1)
	/// Proof: `NominationPools::Metadata` (`max_values`: None, `max_size`: Some(270), added: 2745, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForBondedPools` (r:1 w:1)
	/// Proof: `NominationPools::CounterForBondedPools` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:0 w:1)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::ClaimPermissions` (r:0 w:1)
	/// Proof: `NominationPools::ClaimPermissions` (`max_values`: None, `max_size`: Some(41), added: 2516, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[0, 100]`.
	fn withdraw_unbonded_kill(_s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2655`
		//  Estimated: `8538`
		// Minimum execution time: 273_932_000 picoseconds.
		Weight::from_parts(276_873_257, 0)
			.saturating_add(Weight::from_parts(0, 8538))
			.saturating_add(T::DbWeight::get().reads(25))
			.saturating_add(T::DbWeight::get().writes(21))
	}
	/// Storage: `NominationPools::LastPoolId` (r:1 w:1)
	/// Proof: `NominationPools::LastPoolId` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinNominatorBond` (r:1 w:0)
	/// Proof: `Staking::MinNominatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MinCreateBond` (r:1 w:0)
	/// Proof: `NominationPools::MinCreateBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MinJoinBond` (r:1 w:0)
	/// Proof: `NominationPools::MinJoinBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MaxPools` (r:1 w:0)
	/// Proof: `NominationPools::MaxPools` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForBondedPools` (r:1 w:1)
	/// Proof: `NominationPools::CounterForBondedPools` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::PoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MaxPoolMembersPerPool` (r:1 w:0)
	/// Proof: `NominationPools::MaxPoolMembersPerPool` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MaxPoolMembers` (r:1 w:0)
	/// Proof: `NominationPools::MaxPoolMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForPoolMembers` (r:1 w:1)
	/// Proof: `NominationPools::CounterForPoolMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:1)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:2 w:2)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:2 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:2 w:1)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::TotalValueLocked` (r:1 w:1)
	/// Proof: `NominationPools::TotalValueLocked` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::RewardPools` (r:1 w:1)
	/// Proof: `NominationPools::RewardPools` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForRewardPools` (r:1 w:1)
	/// Proof: `NominationPools::CounterForRewardPools` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::ReversePoolIdLookup` (r:1 w:1)
	/// Proof: `NominationPools::ReversePoolIdLookup` (`max_values`: None, `max_size`: Some(44), added: 2519, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForReversePoolIdLookup` (r:1 w:1)
	/// Proof: `NominationPools::CounterForReversePoolIdLookup` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:0 w:1)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	fn create() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1236`
		//  Estimated: `8538`
		// Minimum execution time: 199_592_000 picoseconds.
		Weight::from_parts(200_552_000, 0)
			.saturating_add(Weight::from_parts(0, 8538))
			.saturating_add(T::DbWeight::get().reads(25))
			.saturating_add(T::DbWeight::get().writes(17))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:0)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::PoolMembers` (r:1 w:0)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinNominatorBond` (r:1 w:0)
	/// Proof: `Staking::MinNominatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MinCreateBond` (r:1 w:0)
	/// Proof: `NominationPools::MinCreateBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MinJoinBond` (r:1 w:0)
	/// Proof: `NominationPools::MinJoinBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:1)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxNominatorsCount` (r:1 w:0)
	/// Proof: `Staking::MaxNominatorsCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:25 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:1 w:1)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForNominators` (r:1 w:1)
	/// Proof: `Staking::CounterForNominators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[1, 24]`.
	fn nominate(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2015 + n * (1 ±0)`
		//  Estimated: `4556 + n * (2520 ±0)`
		// Minimum execution time: 92_461_000 picoseconds.
		Weight::from_parts(91_544_266, 0)
			.saturating_add(Weight::from_parts(0, 4556))
			// Standard Error: 4_591
			.saturating_add(Weight::from_parts(1_799_225, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(15))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(n.into())))
			.saturating_add(T::DbWeight::get().writes(5))
			.saturating_add(Weight::from_parts(0, 2520).saturating_mul(n.into()))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	fn set_state() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1427`
		//  Estimated: `4556`
		// Minimum execution time: 37_980_000 picoseconds.
		Weight::from_parts(38_680_000, 0)
			.saturating_add(Weight::from_parts(0, 4556))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:0)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::Metadata` (r:1 w:1)
	/// Proof: `NominationPools::Metadata` (`max_values`: None, `max_size`: Some(270), added: 2745, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::CounterForMetadata` (r:1 w:1)
	/// Proof: `NominationPools::CounterForMetadata` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[1, 256]`.
	fn set_metadata(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `532`
		//  Estimated: `3735`
		// Minimum execution time: 14_650_000 picoseconds.
		Weight::from_parts(15_121_588, 0)
			.saturating_add(Weight::from_parts(0, 3735))
			// Standard Error: 61
			.saturating_add(Weight::from_parts(866, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `NominationPools::MinJoinBond` (r:0 w:1)
	/// Proof: `NominationPools::MinJoinBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MaxPoolMembers` (r:0 w:1)
	/// Proof: `NominationPools::MaxPoolMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MaxPoolMembersPerPool` (r:0 w:1)
	/// Proof: `NominationPools::MaxPoolMembersPerPool` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MinCreateBond` (r:0 w:1)
	/// Proof: `NominationPools::MinCreateBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::GlobalMaxCommission` (r:0 w:1)
	/// Proof: `NominationPools::GlobalMaxCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::MaxPools` (r:0 w:1)
	/// Proof: `NominationPools::MaxPools` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn set_configs() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 4_450_000 picoseconds.
		Weight::from_parts(4_530_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(6))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	fn update_roles() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `532`
		//  Estimated: `3719`
		// Minimum execution time: 18_231_000 picoseconds.
		Weight::from_parts(18_530_000, 0)
			.saturating_add(Weight::from_parts(0, 3719))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:0)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::PoolMembers` (r:1 w:0)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinNominatorBond` (r:1 w:0)
	/// Proof: `Staking::MinNominatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:1)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForNominators` (r:1 w:1)
	/// Proof: `Staking::CounterForNominators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:1 w:1)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn chill() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2195`
		//  Estimated: `4556`
		// Minimum execution time: 85_301_000 picoseconds.
		Weight::from_parts(86_281_000, 0)
			.saturating_add(Weight::from_parts(0, 4556))
			.saturating_add(T::DbWeight::get().reads(11))
			.saturating_add(T::DbWeight::get().writes(5))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::RewardPools` (r:1 w:1)
	/// Proof: `NominationPools::RewardPools` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::GlobalMaxCommission` (r:1 w:0)
	/// Proof: `NominationPools::GlobalMaxCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:0)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn set_commission() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `804`
		//  Estimated: `3719`
		// Minimum execution time: 37_991_000 picoseconds.
		Weight::from_parts(38_250_000, 0)
			.saturating_add(Weight::from_parts(0, 3719))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::GlobalMaxCommission` (r:1 w:0)
	/// Proof: `NominationPools::GlobalMaxCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn set_commission_max() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `572`
		//  Estimated: `3719`
		// Minimum execution time: 18_230_000 picoseconds.
		Weight::from_parts(18_510_000, 0)
			.saturating_add(Weight::from_parts(0, 3719))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	fn set_commission_change_rate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `532`
		//  Estimated: `3719`
		// Minimum execution time: 18_090_000 picoseconds.
		Weight::from_parts(18_460_000, 0)
			.saturating_add(Weight::from_parts(0, 3719))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:1)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	fn set_commission_claim_permission() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `532`
		//  Estimated: `3719`
		// Minimum execution time: 17_780_000 picoseconds.
		Weight::from_parts(18_061_000, 0)
			.saturating_add(Weight::from_parts(0, 3719))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `NominationPools::PoolMembers` (r:1 w:0)
	/// Proof: `NominationPools::PoolMembers` (`max_values`: None, `max_size`: Some(717), added: 3192, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::ClaimPermissions` (r:1 w:1)
	/// Proof: `NominationPools::ClaimPermissions` (`max_values`: None, `max_size`: Some(41), added: 2516, mode: `MaxEncodedLen`)
	fn set_claim_permission() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `542`
		//  Estimated: `4182`
		// Minimum execution time: 15_970_000 picoseconds.
		Weight::from_parts(16_120_000, 0)
			.saturating_add(Weight::from_parts(0, 4182))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:0)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::RewardPools` (r:1 w:1)
	/// Proof: `NominationPools::RewardPools` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `NominationPools::GlobalMaxCommission` (r:1 w:0)
	/// Proof: `NominationPools::GlobalMaxCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn claim_commission() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1002`
		//  Estimated: `3719`
		// Minimum execution time: 71_160_000 picoseconds.
		Weight::from_parts(72_120_000, 0)
			.saturating_add(Weight::from_parts(0, 3719))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `NominationPools::BondedPools` (r:1 w:0)
	/// Proof: `NominationPools::BondedPools` (`max_values`: None, `max_size`: Some(254), added: 2729, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:1)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:0)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	fn adjust_pool_deposit() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `981`
		//  Estimated: `4764`
		// Minimum execution time: 79_551_000 picoseconds.
		Weight::from_parts(80_181_000, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	fn apply_slash() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_110_000 picoseconds.
		Weight::from_parts(3_230_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn apply_slash_fail() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_210_000 picoseconds.
		Weight::from_parts(3_320_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn pool_migrate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_950_000 picoseconds.
		Weight::from_parts(3_110_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn migrate_delegation() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_860_000 picoseconds.
		Weight::from_parts(3_050_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
}
