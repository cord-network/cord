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

/// Weight functions for `pallet_bags_list`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_bags_list::WeightInfo for WeightInfo<T> {
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:4 w:4)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	fn rebag_non_terminal() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1717`
		//  Estimated: `11506`
		// Minimum execution time: 64_940_000 picoseconds.
		Weight::from_parts(66_231_000, 0)
			.saturating_add(Weight::from_parts(0, 11506))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(5))
	}
	/// Storage: `Staking::Bonded` (r:1 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:1 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListNodes` (r:3 w:3)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:2 w:2)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	fn rebag_terminal() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1614`
		//  Estimated: `8877`
		// Minimum execution time: 63_440_000 picoseconds.
		Weight::from_parts(64_541_000, 0)
			.saturating_add(Weight::from_parts(0, 8877))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(5))
	}
	/// Storage: `VoterList::ListNodes` (r:4 w:4)
	/// Proof: `VoterList::ListNodes` (`max_values`: None, `max_size`: Some(154), added: 2629, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Bonded` (r:2 w:0)
	/// Proof: `Staking::Bonded` (`max_values`: None, `max_size`: Some(72), added: 2547, mode: `MaxEncodedLen`)
	/// Storage: `Staking::Ledger` (r:2 w:0)
	/// Proof: `Staking::Ledger` (`max_values`: None, `max_size`: Some(1091), added: 3566, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::CounterForListNodes` (r:1 w:1)
	/// Proof: `VoterList::CounterForListNodes` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `VoterList::ListBags` (r:1 w:1)
	/// Proof: `VoterList::ListBags` (`max_values`: None, `max_size`: Some(82), added: 2557, mode: `MaxEncodedLen`)
	fn put_in_front_of() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1920`
		//  Estimated: `11506`
		// Minimum execution time: 74_851_000 picoseconds.
		Weight::from_parts(75_390_000, 0)
			.saturating_add(Weight::from_parts(0, 11506))
			.saturating_add(T::DbWeight::get().reads(10))
			.saturating_add(T::DbWeight::get().writes(6))
	}
}
