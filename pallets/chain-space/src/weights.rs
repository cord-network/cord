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
//! DATE: 2024-05-17, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `cord-benchmark-16gb`, CPU: `AMD EPYC 7B13`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("dev")`, DB CACHE: `1024`

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
// --output=./pallets/chain-space/src/weights.rs
// --header=./HEADER-GPL3
// --template=./.maintain/frame-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for `pallet_chain_space`.
pub trait WeightInfo {
	fn add_delegate() -> Weight;
	fn add_admin_delegate() -> Weight;
	fn add_delegator() -> Weight;
	fn remove_delegate() -> Weight;
	fn create() -> Weight;
	fn approve() -> Weight;
	fn archive() -> Weight;
	fn restore() -> Weight;
	fn update_transaction_capacity() -> Weight;
	fn reset_transaction_count() -> Weight;
	fn approval_revoke() -> Weight;
	fn approval_restore() -> Weight;
	fn subspace_create() -> Weight;
}

/// Weights for `pallet_chain_space` using the CORD node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
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
		// Minimum execution time: 40_470_000 picoseconds.
		Weight::from_parts(41_550_000, 323533)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
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
		// Minimum execution time: 40_851_000 picoseconds.
		Weight::from_parts(41_909_000, 323533)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
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
		Weight::from_parts(41_720_000, 323533)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
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
		// Minimum execution time: 40_860_000 picoseconds.
		Weight::from_parts(41_970_000, 323533)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
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
		// Minimum execution time: 27_280_000 picoseconds.
		Weight::from_parts(27_960_000, 3671)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn approve() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `494`
		//  Estimated: `3671`
		// Minimum execution time: 22_331_000 picoseconds.
		Weight::from_parts(23_009_000, 3671)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
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
		// Minimum execution time: 31_040_000 picoseconds.
		Weight::from_parts(31_750_000, 3671)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
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
		// Minimum execution time: 30_580_000 picoseconds.
		Weight::from_parts(31_880_000, 3671)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn update_transaction_capacity() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `3671`
		// Minimum execution time: 22_570_000 picoseconds.
		Weight::from_parts(23_300_000, 3671)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn reset_transaction_count() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `3671`
		// Minimum execution time: 22_330_000 picoseconds.
		Weight::from_parts(23_040_000, 3671)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn approval_revoke() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `3671`
		// Minimum execution time: 22_000_000 picoseconds.
		Weight::from_parts(22_650_000, 3671)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn approval_restore() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `512`
		//  Estimated: `3671`
		// Minimum execution time: 22_150_000 picoseconds.
		Weight::from_parts(22_570_000, 3671)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
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
		// Minimum execution time: 36_090_000 picoseconds.
		Weight::from_parts(36_930_000, 6352)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
}

// For backwards compatibility and tests.
impl WeightInfo for () {
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
		// Minimum execution time: 40_470_000 picoseconds.
		Weight::from_parts(41_550_000, 323533)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
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
		// Minimum execution time: 40_851_000 picoseconds.
		Weight::from_parts(41_909_000, 323533)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
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
		Weight::from_parts(41_720_000, 323533)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
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
		// Minimum execution time: 40_860_000 picoseconds.
		Weight::from_parts(41_970_000, 323533)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
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
		// Minimum execution time: 27_280_000 picoseconds.
		Weight::from_parts(27_960_000, 3671)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn approve() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `494`
		//  Estimated: `3671`
		// Minimum execution time: 22_331_000 picoseconds.
		Weight::from_parts(23_009_000, 3671)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
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
		// Minimum execution time: 31_040_000 picoseconds.
		Weight::from_parts(31_750_000, 3671)
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
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
		// Minimum execution time: 30_580_000 picoseconds.
		Weight::from_parts(31_880_000, 3671)
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn update_transaction_capacity() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `3671`
		// Minimum execution time: 22_570_000 picoseconds.
		Weight::from_parts(23_300_000, 3671)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn reset_transaction_count() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `3671`
		// Minimum execution time: 22_330_000 picoseconds.
		Weight::from_parts(23_040_000, 3671)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn approval_revoke() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `503`
		//  Estimated: `3671`
		// Minimum execution time: 22_000_000 picoseconds.
		Weight::from_parts(22_650_000, 3671)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(206), added: 2681, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn approval_restore() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `512`
		//  Estimated: `3671`
		// Minimum execution time: 22_150_000 picoseconds.
		Weight::from_parts(22_570_000, 3671)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
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
		// Minimum execution time: 36_090_000 picoseconds.
		Weight::from_parts(36_930_000, 6352)
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().writes(5_u64))
	}
}
