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

//! Autogenerated weights for `pallet_chain_space`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 32.0.0
//! DATE: 2024-05-09, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `cord-benchmark-8gb`, CPU: `AMD EPYC 7B12`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("dev")`, DB CACHE: 1024

// Executed Command:
// ./target/production/cord
// benchmark
// pallet
// --chain=dev
// --steps=50
// --repeat=20
// --pallet=pallet_chain_space
// --extrinsic=*
// --wasm-execution=compiled
// --heap-pages=4096
// --header=./HEADER-GPL3
// --output=./runtime/src/weights/

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_chain_space`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_chain_space::WeightInfo for WeightInfo<T> {
	/// Storage: `ChainSpace::Authorizations` (r:2 w:1)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Delegates` (r:1 w:1)
	/// Proof: `ChainSpace::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn add_delegate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `804`
		//  Estimated: `323533`
		// Minimum execution time: 40_490_000 picoseconds.
		Weight::from_parts(41_480_000, 0)
			.saturating_add(Weight::from_parts(0, 323533))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `ChainSpace::Authorizations` (r:2 w:1)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Delegates` (r:1 w:1)
	/// Proof: `ChainSpace::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn add_admin_delegate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `804`
		//  Estimated: `323533`
		// Minimum execution time: 40_700_000 picoseconds.
		Weight::from_parts(41_890_000, 0)
			.saturating_add(Weight::from_parts(0, 323533))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `ChainSpace::Authorizations` (r:2 w:1)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Delegates` (r:1 w:1)
	/// Proof: `ChainSpace::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn add_delegator() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `804`
		//  Estimated: `323533`
		// Minimum execution time: 40_730_000 picoseconds.
		Weight::from_parts(41_630_000, 0)
			.saturating_add(Weight::from_parts(0, 323533))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `ChainSpace::Authorizations` (r:2 w:1)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Delegates` (r:1 w:1)
	/// Proof: `ChainSpace::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn remove_delegate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1061`
		//  Estimated: `323533`
		// Minimum execution time: 41_229_000 picoseconds.
		Weight::from_parts(42_129_000, 0)
			.saturating_add(Weight::from_parts(0, 323533))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Delegates` (r:0 w:1)
	/// Proof: `ChainSpace::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Authorizations` (r:0 w:1)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	fn create() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `115`
		//  Estimated: `3671`
		// Minimum execution time: 27_740_000 picoseconds.
		Weight::from_parts(28_240_000, 0)
			.saturating_add(Weight::from_parts(0, 3671))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn approve() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `494`
		//  Estimated: `3671`
		// Minimum execution time: 22_040_000 picoseconds.
		Weight::from_parts(22_770_000, 0)
			.saturating_add(Weight::from_parts(0, 3671))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn archive() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `715`
		//  Estimated: `3671`
		// Minimum execution time: 31_051_000 picoseconds.
		Weight::from_parts(31_820_000, 0)
			.saturating_add(Weight::from_parts(0, 3671))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn restore() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `724`
		//  Estimated: `3671`
		// Minimum execution time: 30_690_000 picoseconds.
		Weight::from_parts(31_740_000, 0)
			.saturating_add(Weight::from_parts(0, 3671))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn update_transaction_capacity() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `3671`
		// Minimum execution time: 22_470_000 picoseconds.
		Weight::from_parts(23_480_000, 0)
			.saturating_add(Weight::from_parts(0, 3671))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn reset_transaction_count() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `3671`
		// Minimum execution time: 22_660_000 picoseconds.
		Weight::from_parts(23_580_000, 0)
			.saturating_add(Weight::from_parts(0, 3671))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn approval_revoke() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `3671`
		// Minimum execution time: 22_150_000 picoseconds.
		Weight::from_parts(22_790_000, 0)
			.saturating_add(Weight::from_parts(0, 3671))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn approval_restore() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `512`
		//  Estimated: `3671`
		// Minimum execution time: 22_190_000 picoseconds.
		Weight::from_parts(22_710_000, 0)
			.saturating_add(Weight::from_parts(0, 3671))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `ChainSpace::Spaces` (r:2 w:2)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Delegates` (r:0 w:1)
	/// Proof: `ChainSpace::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Authorizations` (r:0 w:1)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	fn subspace_create() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `6352`
		// Minimum execution time: 36_120_000 picoseconds.
		Weight::from_parts(37_229_000, 0)
			.saturating_add(Weight::from_parts(0, 6352))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(5))
	}
}
