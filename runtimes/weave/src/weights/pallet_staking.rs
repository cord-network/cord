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

/// Weight functions for `pallet_staking`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_staking::WeightInfo for WeightInfo<T> {
	/// Storage: `Staking::Bonded` (r:1 w:1)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:0 w:1)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	fn bond() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `948`
		//  Estimated: `4764`
		// Minimum execution time: 55_830_000 picoseconds.
		Weight::from_parts(56_781_000, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(4))
	}
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
	fn bond_extra() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2016`
		//  Estimated: `8877`
		// Minimum execution time: 102_541_000 picoseconds.
		Weight::from_parts(104_601_000, 0)
			.saturating_add(Weight::from_parts(0, 8877))
			.saturating_add(T::DbWeight::get().reads(10))
			.saturating_add(T::DbWeight::get().writes(7))
	}
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:0)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinNominatorBond` (r:1 w:0)
	/// Proof: `Staking::MinNominatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
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
	fn unbond() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2227`
		//  Estimated: `8877`
		// Minimum execution time: 112_841_000 picoseconds.
		Weight::from_parts(114_381_000, 0)
			.saturating_add(Weight::from_parts(0, 8877))
			.saturating_add(T::DbWeight::get().reads(13))
			.saturating_add(T::DbWeight::get().writes(7))
	}
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
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
	/// The range of component `s` is `[0, 100]`.
	fn withdraw_unbonded_update(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1322`
		//  Estimated: `4764`
		// Minimum execution time: 58_191_000 picoseconds.
		Weight::from_parts(59_599_311, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			// Standard Error: 810
			.saturating_add(Weight::from_parts(15_599, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:1)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::SlashingSpans` (r:1 w:1)
	/// Proof: `Staking::SlashingSpans` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:1)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:1)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForNominators` (r:1 w:1)
	/// Proof: `Staking::CounterForNominators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:2 w:2)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:0 w:1)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Staking::SpanSlash` (r:0 w:100)
	/// Proof: `Staking::SpanSlash` (`max_values`: None, `max_size`: Some(76), added: 2551, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[0, 100]`.
	fn withdraw_unbonded_kill(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2222 + s * (4 ±0)`
		//  Estimated: `6248 + s * (4 ±0)`
		// Minimum execution time: 104_051_000 picoseconds.
		Weight::from_parts(108_879_864, 0)
			.saturating_add(Weight::from_parts(0, 6248))
			// Standard Error: 2_272
			.saturating_add(Weight::from_parts(1_438_190, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(14))
			.saturating_add(T::DbWeight::get().writes(12))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(s.into())))
			.saturating_add(Weight::from_parts(0, 4).saturating_mul(s.into()))
	}
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinValidatorBond` (r:1 w:0)
	/// Proof: `Staking::MinValidatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinCommission` (r:1 w:0)
	/// Proof: `Staking::MinCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:1)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxValidatorsCount` (r:1 w:0)
	/// Proof: `Staking::MaxValidatorsCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:0)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:1 w:1)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForValidators` (r:1 w:1)
	/// Proof: `Staking::CounterForValidators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn validate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1420`
		//  Estimated: `4556`
		// Minimum execution time: 61_500_000 picoseconds.
		Weight::from_parts(62_301_000, 0)
			.saturating_add(Weight::from_parts(0, 4556))
			.saturating_add(T::DbWeight::get().reads(11))
			.saturating_add(T::DbWeight::get().writes(5))
	}
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:128 w:128)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// The range of component `k` is `[1, 128]`.
	fn kick(k: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1910 + k * (825 ±0)`
		//  Estimated: `4556 + k * (3289 ±0)`
		// Minimum execution time: 36_950_000 picoseconds.
		Weight::from_parts(31_302_424, 0)
			.saturating_add(Weight::from_parts(0, 4556))
			// Standard Error: 11_143
			.saturating_add(Weight::from_parts(7_452_847, 0).saturating_mul(k.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(k.into())))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(k.into())))
			.saturating_add(Weight::from_parts(0, 3289).saturating_mul(k.into()))
	}
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinNominatorBond` (r:1 w:0)
	/// Proof: `Staking::MinNominatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:1)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxNominatorsCount` (r:1 w:0)
	/// Proof: `Staking::MaxNominatorsCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:25 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:2 w:2)
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
		//  Measured:  `1945 + n * (86 ±0)`
		//  Estimated: `6248 + n * (2520 ±0)`
		// Minimum execution time: 74_480_000 picoseconds.
		Weight::from_parts(75_848_084, 0)
			.saturating_add(Weight::from_parts(0, 6248))
			// Standard Error: 15_811
			.saturating_add(Weight::from_parts(3_742_516, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(12))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(n.into())))
			.saturating_add(T::DbWeight::get().writes(6))
			.saturating_add(Weight::from_parts(0, 2520).saturating_mul(n.into()))
	}
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:1)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForNominators` (r:1 w:1)
	/// Proof: `Staking::CounterForNominators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:2 w:2)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn chill() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1809`
		//  Estimated: `6248`
		// Minimum execution time: 65_990_000 picoseconds.
		Weight::from_parts(66_511_000, 0)
			.saturating_add(Weight::from_parts(0, 6248))
			.saturating_add(T::DbWeight::get().reads(9))
			.saturating_add(T::DbWeight::get().writes(6))
	}
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:0 w:1)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	fn set_payee() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `897`
		//  Estimated: `4556`
		// Minimum execution time: 25_140_000 picoseconds.
		Weight::from_parts(25_720_000, 0)
			.saturating_add(Weight::from_parts(0, 4556))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:1 w:1)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	fn update_payee() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `998`
		//  Estimated: `4556`
		// Minimum execution time: 29_220_000 picoseconds.
		Weight::from_parts(29_550_000, 0)
			.saturating_add(Weight::from_parts(0, 4556))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::Bonded` (r:1 w:1)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:2 w:2)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	fn set_controller() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `897`
		//  Estimated: `8122`
		// Minimum execution time: 28_641_000 picoseconds.
		Weight::from_parts(29_190_000, 0)
			.saturating_add(Weight::from_parts(0, 8122))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `Staking::ValidatorCount` (r:0 w:1)
	/// Proof: `Staking::ValidatorCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn set_validator_count() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_680_000 picoseconds.
		Weight::from_parts(2_790_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::ForceEra` (r:0 w:1)
	/// Proof: `Staking::ForceEra` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	fn force_no_eras() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 9_350_000 picoseconds.
		Weight::from_parts(9_730_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::ForceEra` (r:0 w:1)
	/// Proof: `Staking::ForceEra` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	fn force_new_era() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 9_401_000 picoseconds.
		Weight::from_parts(9_760_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::ForceEra` (r:0 w:1)
	/// Proof: `Staking::ForceEra` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	fn force_new_era_always() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 9_420_000 picoseconds.
		Weight::from_parts(9_760_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::Invulnerables` (r:0 w:1)
	/// Proof: `Staking::Invulnerables` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// The range of component `v` is `[0, 1000]`.
	fn set_invulnerables(v: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_860_000 picoseconds.
		Weight::from_parts(3_106_109, 0)
			.saturating_add(Weight::from_parts(0, 0))
			// Standard Error: 16
			.saturating_add(Weight::from_parts(10_700, 0).saturating_mul(v.into()))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::Ledger` (r:10338 w:10338)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:5169 w:5169)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:5169 w:0)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// The range of component `i` is `[0, 5169]`.
	fn deprecate_controller_batch(i: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1878 + i * (223 ±0)`
		//  Estimated: `990 + i * (7132 ±0)`
		// Minimum execution time: 5_320_000 picoseconds.
		Weight::from_parts(5_430_000, 0)
			.saturating_add(Weight::from_parts(0, 990))
			// Standard Error: 94_877
			.saturating_add(Weight::from_parts(34_818_298, 0).saturating_mul(i.into()))
			.saturating_add(T::DbWeight::get().reads((4_u64).saturating_mul(i.into())))
			.saturating_add(T::DbWeight::get().writes((3_u64).saturating_mul(i.into())))
			.saturating_add(Weight::from_parts(0, 7132).saturating_mul(i.into()))
	}
	/// Storage: `Staking::SlashingSpans` (r:1 w:1)
	/// Proof: `Staking::SlashingSpans` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::Bonded` (r:1 w:1)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:1 w:1)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:1)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForNominators` (r:1 w:1)
	/// Proof: `Staking::CounterForNominators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:2 w:2)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:0 w:1)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Staking::SpanSlash` (r:0 w:100)
	/// Proof: `Staking::SpanSlash` (`max_values`: None, `max_size`: Some(76), added: 2551, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[0, 100]`.
	fn force_unstake(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2222 + s * (4 ±0)`
		//  Estimated: `6248 + s * (4 ±0)`
		// Minimum execution time: 98_561_000 picoseconds.
		Weight::from_parts(103_075_186, 0)
			.saturating_add(Weight::from_parts(0, 6248))
			// Standard Error: 1_989
			.saturating_add(Weight::from_parts(1_432_161, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(14))
			.saturating_add(T::DbWeight::get().writes(13))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(s.into())))
			.saturating_add(Weight::from_parts(0, 4).saturating_mul(s.into()))
	}
	/// Storage: `Staking::UnappliedSlashes` (r:1 w:1)
	/// Proof: `Staking::UnappliedSlashes` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `s` is `[1, 1000]`.
	fn cancel_deferred_slash(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `66605`
		//  Estimated: `70070`
		// Minimum execution time: 138_691_000 picoseconds.
		Weight::from_parts(1_254_471_539, 0)
			.saturating_add(Weight::from_parts(0, 70070))
			// Standard Error: 81_027
			.saturating_add(Weight::from_parts(6_844_209, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::Bonded` (r:513 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:513 w:513)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasStakersClipped` (r:1 w:0)
	/// Proof: `Staking::ErasStakersClipped` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::ErasStakersOverview` (r:1 w:0)
	/// Proof: `Staking::ErasStakersOverview` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ClaimedRewards` (r:1 w:1)
	/// Proof: `Staking::ClaimedRewards` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::CurrentEra` (r:1 w:0)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasValidatorReward` (r:1 w:0)
	/// Proof: `Staking::ErasValidatorReward` (`max_values`: None, `max_size`: Some(28), added: 2503, mode: `MaxEncodedLen`)
	/// Storage: `Staking::VirtualStakers` (r:513 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:513 w:513)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:513 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:513 w:513)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasStakersPaged` (r:1 w:0)
	/// Proof: `Staking::ErasStakersPaged` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::ErasRewardPoints` (r:1 w:0)
	/// Proof: `Staking::ErasRewardPoints` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::ErasValidatorPrefs` (r:1 w:0)
	/// Proof: `Staking::ErasValidatorPrefs` (`max_values`: None, `max_size`: Some(57), added: 2532, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:513 w:0)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[0, 512]`.
	fn payout_stakers_alive_staked(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `58313 + n * (385 ±0)`
		//  Estimated: `53173 + n * (3774 ±2)`
		// Minimum execution time: 214_912_000 picoseconds.
		Weight::from_parts(155_147_782, 0)
			.saturating_add(Weight::from_parts(0, 53173))
			// Standard Error: 19_413
			.saturating_add(Weight::from_parts(61_628_967, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(15))
			.saturating_add(T::DbWeight::get().reads((7_u64).saturating_mul(n.into())))
			.saturating_add(T::DbWeight::get().writes(4))
			.saturating_add(T::DbWeight::get().writes((3_u64).saturating_mul(n.into())))
			.saturating_add(Weight::from_parts(0, 3774).saturating_mul(n.into()))
	}
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
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
	/// The range of component `l` is `[1, 32]`.
	fn rebond(l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2017 + l * (5 ±0)`
		//  Estimated: `8877`
		// Minimum execution time: 98_051_000 picoseconds.
		Weight::from_parts(99_357_800, 0)
			.saturating_add(Weight::from_parts(0, 8877))
			// Standard Error: 1_620
			.saturating_add(Weight::from_parts(87_532, 0).saturating_mul(l.into()))
			.saturating_add(T::DbWeight::get().reads(10))
			.saturating_add(T::DbWeight::get().writes(7))
	}
	/// Storage: `Staking::VirtualStakers` (r:1 w:1)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:1)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::SlashingSpans` (r:1 w:1)
	/// Proof: `Staking::SlashingSpans` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:1)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForNominators` (r:1 w:1)
	/// Proof: `Staking::CounterForNominators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:2 w:2)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Payee` (r:0 w:1)
	/// Proof: `Staking::Payee` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Staking::SpanSlash` (r:0 w:100)
	/// Proof: `Staking::SpanSlash` (`max_values`: None, `max_size`: Some(76), added: 2551, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[1, 100]`.
	fn reap_stash(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2222 + s * (4 ±0)`
		//  Estimated: `6248 + s * (4 ±0)`
		// Minimum execution time: 111_251_000 picoseconds.
		Weight::from_parts(111_078_623, 0)
			.saturating_add(Weight::from_parts(0, 6248))
			// Standard Error: 1_885
			.saturating_add(Weight::from_parts(1_434_488, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(13))
			.saturating_add(T::DbWeight::get().writes(12))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(s.into())))
			.saturating_add(Weight::from_parts(0, 4).saturating_mul(s.into()))
	}
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:0)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:166 w:0)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:110 w:0)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:110 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:110 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:110 w:0)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:11 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForValidators` (r:1 w:0)
	/// Proof: `Staking::CounterForValidators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ValidatorCount` (r:1 w:0)
	/// Proof: `Staking::ValidatorCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinimumValidatorCount` (r:1 w:0)
	/// Proof: `Staking::MinimumValidatorCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CurrentEra` (r:1 w:1)
	/// Proof: `Staking::CurrentEra` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasValidatorPrefs` (r:0 w:10)
	/// Proof: `Staking::ErasValidatorPrefs` (`max_values`: None, `max_size`: Some(57), added: 2532, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasStakersPaged` (r:0 w:10)
	/// Proof: `Staking::ErasStakersPaged` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Staking::ErasStakersOverview` (r:0 w:10)
	/// Proof: `Staking::ErasStakersOverview` (`max_values`: None, `max_size`: Some(92), added: 2567, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasTotalStake` (r:0 w:1)
	/// Proof: `Staking::ErasTotalStake` (`max_values`: None, `max_size`: Some(28), added: 2503, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ErasStartSessionIndex` (r:0 w:1)
	/// Proof: `Staking::ErasStartSessionIndex` (`max_values`: None, `max_size`: Some(16), added: 2491, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinimumActiveStake` (r:0 w:1)
	/// Proof: `Staking::MinimumActiveStake` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// The range of component `v` is `[1, 10]`.
	/// The range of component `n` is `[0, 100]`.
	fn new_era(v: u32, n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0 + n * (714 ±0) + v * (3592 ±0)`
		//  Estimated: `425452 + n * (3566 ±0) + v * (3566 ±0)`
		// Minimum execution time: 605_765_000 picoseconds.
		Weight::from_parts(609_305_000, 0)
			.saturating_add(Weight::from_parts(0, 425452))
			// Standard Error: 2_272_403
			.saturating_add(Weight::from_parts(74_003_619, 0).saturating_mul(v.into()))
			// Standard Error: 226_432
			.saturating_add(Weight::from_parts(21_911_461, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(172))
			.saturating_add(T::DbWeight::get().reads((5_u64).saturating_mul(v.into())))
			.saturating_add(T::DbWeight::get().reads((4_u64).saturating_mul(n.into())))
			.saturating_add(T::DbWeight::get().writes(3))
			.saturating_add(T::DbWeight::get().writes((3_u64).saturating_mul(v.into())))
			.saturating_add(Weight::from_parts(0, 3566).saturating_mul(n.into()))
			.saturating_add(Weight::from_parts(0, 3566).saturating_mul(v.into()))
	}
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:0)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:166 w:0)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:2000 w:0)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:2000 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:2000 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:2000 w:0)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1000 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinimumActiveStake` (r:0 w:1)
	/// Proof: `Staking::MinimumActiveStake` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// The range of component `v` is `[500, 1000]`.
	/// The range of component `n` is `[500, 1000]`.
	fn get_npos_voters(v: u32, n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `3182 + n * (1161 ±0) + v * (389 ±0)`
		//  Estimated: `425452 + n * (3566 ±0) + v * (3566 ±0)`
		// Minimum execution time: 44_305_240_000 picoseconds.
		Weight::from_parts(44_521_882_000, 0)
			.saturating_add(Weight::from_parts(0, 425452))
			// Standard Error: 492_585
			.saturating_add(Weight::from_parts(5_656_363, 0).saturating_mul(v.into()))
			// Standard Error: 492_585
			.saturating_add(Weight::from_parts(4_916_105, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(167))
			.saturating_add(T::DbWeight::get().reads((5_u64).saturating_mul(v.into())))
			.saturating_add(T::DbWeight::get().reads((4_u64).saturating_mul(n.into())))
			.saturating_add(T::DbWeight::get().writes(1))
			.saturating_add(Weight::from_parts(0, 3566).saturating_mul(n.into()))
			.saturating_add(Weight::from_parts(0, 3566).saturating_mul(v.into()))
	}
	/// Storage: `Staking::CounterForValidators` (r:1 w:0)
	/// Proof: `Staking::CounterForValidators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1001 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// The range of component `v` is `[500, 1000]`.
	fn get_npos_targets(v: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `912 + v * (50 ±0)`
		//  Estimated: `3510 + v * (2520 ±0)`
		// Minimum execution time: 3_230_008_000 picoseconds.
		Weight::from_parts(215_066_418, 0)
			.saturating_add(Weight::from_parts(0, 3510))
			// Standard Error: 7_619
			.saturating_add(Weight::from_parts(6_139_508, 0).saturating_mul(v.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(v.into())))
			.saturating_add(Weight::from_parts(0, 2520).saturating_mul(v.into()))
	}
	/// Storage: `Staking::MinCommission` (r:0 w:1)
	/// Proof: `Staking::MinCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinValidatorBond` (r:0 w:1)
	/// Proof: `Staking::MinValidatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxValidatorsCount` (r:0 w:1)
	/// Proof: `Staking::MaxValidatorsCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxStakedRewards` (r:0 w:1)
	/// Proof: `Staking::MaxStakedRewards` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ChillThreshold` (r:0 w:1)
	/// Proof: `Staking::ChillThreshold` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxNominatorsCount` (r:0 w:1)
	/// Proof: `Staking::MaxNominatorsCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinNominatorBond` (r:0 w:1)
	/// Proof: `Staking::MinNominatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	fn set_staking_configs_all_set() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 4_960_000 picoseconds.
		Weight::from_parts(5_180_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(7))
	}
	/// Storage: `Staking::MinCommission` (r:0 w:1)
	/// Proof: `Staking::MinCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinValidatorBond` (r:0 w:1)
	/// Proof: `Staking::MinValidatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxValidatorsCount` (r:0 w:1)
	/// Proof: `Staking::MaxValidatorsCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxStakedRewards` (r:0 w:1)
	/// Proof: `Staking::MaxStakedRewards` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ChillThreshold` (r:0 w:1)
	/// Proof: `Staking::ChillThreshold` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxNominatorsCount` (r:0 w:1)
	/// Proof: `Staking::MaxNominatorsCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinNominatorBond` (r:0 w:1)
	/// Proof: `Staking::MinNominatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	fn set_staking_configs_all_remove() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 4_570_000 picoseconds.
		Weight::from_parts(4_720_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(7))
	}
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Nominators` (r:1 w:1)
	/// Proof: `Staking::Nominators` (`max_values`: None, `max_size`: Some(814), added: 3289, mode: `MaxEncodedLen`)
	/// Storage: `Staking::ChillThreshold` (r:1 w:0)
	/// Proof: `Staking::ChillThreshold` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MaxNominatorsCount` (r:1 w:0)
	/// Proof: `Staking::MaxNominatorsCount` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::CounterForNominators` (r:1 w:1)
	/// Proof: `Staking::CounterForNominators` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::MinNominatorBond` (r:1 w:0)
	/// Proof: `Staking::MinNominatorBond` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:0)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:2 w:2)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn chill_other() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1932`
		//  Estimated: `6248`
		// Minimum execution time: 80_580_000 picoseconds.
		Weight::from_parts(81_291_000, 0)
			.saturating_add(Weight::from_parts(0, 6248))
			.saturating_add(T::DbWeight::get().reads(12))
			.saturating_add(T::DbWeight::get().writes(6))
	}
	/// Storage: `Staking::MinCommission` (r:1 w:0)
	/// Proof: `Staking::MinCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Validators` (r:1 w:1)
	/// Proof: `Staking::Validators` (`max_values`: None, `max_size`: Some(45), added: 2520, mode: `MaxEncodedLen`)
	fn force_apply_min_commission() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `624`
		//  Estimated: `3510`
		// Minimum execution time: 14_121_000 picoseconds.
		Weight::from_parts(14_330_000, 0)
			.saturating_add(Weight::from_parts(0, 3510))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::MinCommission` (r:0 w:1)
	/// Proof: `Staking::MinCommission` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	fn set_min_commission() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_750_000 picoseconds.
		Weight::from_parts(2_880_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Staking::VirtualStakers` (r:1 w:0)
	/// Proof: `Staking::VirtualStakers` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Locks` (r:1 w:1)
	/// Proof: `Balances::Locks` (`max_values`: None, `max_size`: Some(1299), added: 3774, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:1 w:1)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:1)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Freezes` (r:1 w:0)
	/// Proof: `Balances::Freezes` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `MaxEncodedLen`)
	fn restore_ledger() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1035`
		//  Estimated: `4764`
		// Minimum execution time: 53_880_000 picoseconds.
		Weight::from_parts(54_990_000, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(4))
	}
}
