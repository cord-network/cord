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

/// Weight functions for `pallet_fast_unstake`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_fast_unstake::WeightInfo for WeightInfo<T> {
	/// Storage: `FastUnstake::ErasToCheckPerBlock` (r:1 w:0)
	/// Proof: `FastUnstake::ErasToCheckPerBlock` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ValidatorCount` (r:1 w:0)
	/// Proof: `Staking::ValidatorCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::Head` (r:1 w:1)
	/// Proof: `FastUnstake::Head` (`max_values`: Some(1), `max_size`: Some(3191), added: 3686, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::CounterForQueue` (r:1 w:0)
	/// Proof: `FastUnstake::CounterForQueue` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `ElectionProviderMultiPhase::CurrentPhase` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::CurrentPhase` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::SlashingSpans` (r:64 w:0)
	/// Proof: `Staking::SlashingSpans` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::Bonded` (r:64 w:64)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:64 w:64)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:64 w:64)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:64 w:64)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:64 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:64 w:64)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:64 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:64 w:0)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:0 w:64)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// The range of component `b` is `[1, 64]`.
	fn on_idle_unstake(b: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1403 + b * (446 ±0)`
		//  Estimated: `4676 + b * (3774 ±0)`
		// Minimum execution time: 95_791_000 picoseconds.
		Weight::from_parts(32_155_100, 0)
			.saturating_add(Weight::from_parts(0, 4676))
			// Standard Error: 16_684
			.saturating_add(Weight::from_parts(60_670_837, 0).saturating_mul(b.into()))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().reads((9_u64).saturating_mul(b.into())))
			.saturating_add(T::DbWeight::get().writes(1))
			.saturating_add(T::DbWeight::get().writes((6_u64).saturating_mul(b.into())))
			.saturating_add(Weight::from_parts(0, 3774).saturating_mul(b.into()))
	}
	/// Storage: `FastUnstake::ErasToCheckPerBlock` (r:1 w:0)
	/// Proof: `FastUnstake::ErasToCheckPerBlock` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ValidatorCount` (r:1 w:0)
	/// Proof: `Staking::ValidatorCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::Head` (r:1 w:1)
	/// Proof: `FastUnstake::Head` (`max_values`: Some(1), `max_size`: Some(3191), added: 3686, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::CounterForQueue` (r:1 w:0)
	/// Proof: `FastUnstake::CounterForQueue` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `ElectionProviderMultiPhase::CurrentPhase` (r:1 w:0)
	/// Proof: `ElectionProviderMultiPhase::CurrentPhase` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasStakers` (r:1 w:0)
	/// Proof: `Staking::ErasStakers` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::ErasStakersPaged` (r:257 w:0)
	/// Proof: `Staking::ErasStakersPaged` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `v` is `[1, 256]`.
	/// The range of component `b` is `[1, 64]`.
	fn on_idle_check(v: u32, b: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1650 + b * (56 ±0) + v * (18503 ±0)`
		//  Estimated: `4985 + b * (56 ±0) + v * (20980 ±0)`
		// Minimum execution time: 2_056_559_000 picoseconds.
		Weight::from_parts(2_069_889_000, 0)
			.saturating_add(Weight::from_parts(0, 4985))
			// Standard Error: 14_958_656
			.saturating_add(Weight::from_parts(479_970_475, 0).saturating_mul(v.into()))
			// Standard Error: 59_851_284
			.saturating_add(Weight::from_parts(1_885_937_902, 0).saturating_mul(b.into()))
			.saturating_add(T::DbWeight::get().reads(8))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(v.into())))
			.saturating_add(T::DbWeight::get().writes(1))
			.saturating_add(Weight::from_parts(0, 56).saturating_mul(b.into()))
			.saturating_add(Weight::from_parts(0, 20980).saturating_mul(v.into()))
	}
	/// Storage: `FastUnstake::ErasToCheckPerBlock` (r:1 w:0)
	/// Proof: `FastUnstake::ErasToCheckPerBlock` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::Queue` (r:1 w:1)
	/// Proof: `FastUnstake::Queue` (`max_values`: None, `max_size`: Some(56), added: 2531, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::Head` (r:1 w:0)
	/// Proof: `FastUnstake::Head` (`max_values`: Some(1), `max_size`: Some(3191), added: 3686, mode: `MaxEncodedLen`)
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
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::CounterForQueue` (r:1 w:1)
	/// Proof: `FastUnstake::CounterForQueue` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn register_fast_unstake() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1945`
		//  Estimated: `4764`
		// Minimum execution time: 144_061_000 picoseconds.
		Weight::from_parts(145_561_000, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			.saturating_add(T::DbWeight::get().reads(16))
			.saturating_add(T::DbWeight::get().writes(9))
	}
	/// Storage: `FastUnstake::ErasToCheckPerBlock` (r:1 w:0)
	/// Proof: `FastUnstake::ErasToCheckPerBlock` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::Queue` (r:1 w:1)
	/// Proof: `FastUnstake::Queue` (`max_values`: None, `max_size`: Some(56), added: 2531, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::Head` (r:1 w:0)
	/// Proof: `FastUnstake::Head` (`max_values`: Some(1), `max_size`: Some(3191), added: 3686, mode: `MaxEncodedLen`)
	/// Storage: `FastUnstake::CounterForQueue` (r:1 w:1)
	/// Proof: `FastUnstake::CounterForQueue` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn deregister() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1246`
		//  Estimated: `4676`
		// Minimum execution time: 50_761_000 picoseconds.
		Weight::from_parts(51_261_000, 0)
			.saturating_add(Weight::from_parts(0, 4676))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `FastUnstake::ErasToCheckPerBlock` (r:0 w:1)
	/// Proof: `FastUnstake::ErasToCheckPerBlock` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn control() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_170_000 picoseconds.
		Weight::from_parts(2_260_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
