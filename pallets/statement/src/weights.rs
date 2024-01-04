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

//! Autogenerated weights for `pallet_statement`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2024-01-04, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `smohan-dev-host`, CPU: `AMD EPYC 7B12`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("dev")`, DB CACHE: `1024`

// Executed Command:
// ./target/production/cord
// benchmark
// pallet
// --chain=dev
// --steps=50
// --repeat=20
// --pallet=pallet_statement
// --extrinsic=*
// --wasm-execution=compiled
// --heap-pages=4096
// --output=./pallets/statement/src/weights.rs
// --header=./HEADER-GPL3
// --template=./.maintain/frame-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for `pallet_statement`.
pub trait WeightInfo {
	fn register() -> Weight;
	fn update() -> Weight;
	fn revoke() -> Weight;
	fn restore() -> Weight;
	fn remove(l: u32, ) -> Weight;
	fn register_batch(l: u32, ) -> Weight;
	fn add_presentation() -> Weight;
	fn remove_presentation() -> Weight;
}

/// Weights for `pallet_statement` using the CORD node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:1)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Entries` (r:0 w:1)
	/// Proof: `Statement::Entries` (`max_values`: None, `max_size`: Some(138), added: 2613, mode: `MaxEncodedLen`)
	fn register() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `699`
		//  Estimated: `3664`
		// Minimum execution time: 40_060_000 picoseconds.
		Weight::from_parts(41_010_000, 3664)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:1)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::RevocationList` (r:1 w:1)
	/// Proof: `Statement::RevocationList` (`max_values`: None, `max_size`: Some(139), added: 2614, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Entries` (r:1 w:1)
	/// Proof: `Statement::Entries` (`max_values`: None, `max_size`: Some(138), added: 2613, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	fn update() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1100`
		//  Estimated: `3664`
		// Minimum execution time: 47_969_000 picoseconds.
		Weight::from_parts(48_900_000, 3664)
			.saturating_add(T::DbWeight::get().reads(6_u64))
			.saturating_add(T::DbWeight::get().writes(6_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:0)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::RevocationList` (r:1 w:1)
	/// Proof: `Statement::RevocationList` (`max_values`: None, `max_size`: Some(139), added: 2614, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn revoke() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `973`
		//  Estimated: `3664`
		// Minimum execution time: 37_650_000 picoseconds.
		Weight::from_parts(38_790_000, 3664)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:0)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::RevocationList` (r:1 w:1)
	/// Proof: `Statement::RevocationList` (`max_values`: None, `max_size`: Some(139), added: 2614, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn restore() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1141`
		//  Estimated: `3664`
		// Minimum execution time: 39_600_000 picoseconds.
		Weight::from_parts(40_170_000, 3664)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:1)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Entries` (r:2 w:1)
	/// Proof: `Statement::Entries` (`max_values`: None, `max_size`: Some(138), added: 2613, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	/// The range of component `l` is `[1, 5120]`.
	fn remove(_l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1142`
		//  Estimated: `6216`
		// Minimum execution time: 61_950_000 picoseconds.
		Weight::from_parts(64_288_145, 6216)
			.saturating_add(T::DbWeight::get().reads(6_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:3 w:3)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:3 w:3)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:3)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Entries` (r:0 w:3)
	/// Proof: `Statement::Entries` (`max_values`: None, `max_size`: Some(138), added: 2613, mode: `MaxEncodedLen`)
	/// The range of component `l` is `[1, 5120]`.
	fn register_batch(_l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `699`
		//  Estimated: `9012`
		// Minimum execution time: 73_189_000 picoseconds.
		Weight::from_parts(76_412_446, 9012)
			.saturating_add(T::DbWeight::get().reads(8_u64))
			.saturating_add(T::DbWeight::get().writes(13_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:0)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::RevocationList` (r:1 w:0)
	/// Proof: `Statement::RevocationList` (`max_values`: None, `max_size`: Some(139), added: 2614, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Presentations` (r:1 w:1)
	/// Proof: `Statement::Presentations` (`max_values`: None, `max_size`: Some(221), added: 2696, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	fn add_presentation() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `973`
		//  Estimated: `3686`
		// Minimum execution time: 41_960_000 picoseconds.
		Weight::from_parts(43_151_000, 3686)
			.saturating_add(T::DbWeight::get().reads(6_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Presentations` (r:1 w:1)
	/// Proof: `Statement::Presentations` (`max_values`: None, `max_size`: Some(221), added: 2696, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	fn remove_presentation() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1087`
		//  Estimated: `3686`
		// Minimum execution time: 40_230_000 picoseconds.
		Weight::from_parts(41_120_000, 3686)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
}

// For backwards compatibility and tests.
impl WeightInfo for () {
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:1)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Entries` (r:0 w:1)
	/// Proof: `Statement::Entries` (`max_values`: None, `max_size`: Some(138), added: 2613, mode: `MaxEncodedLen`)
	fn register() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `699`
		//  Estimated: `3664`
		// Minimum execution time: 40_060_000 picoseconds.
		Weight::from_parts(41_010_000, 3664)
			.saturating_add(RocksDbWeight::get().reads(4_u64))
			.saturating_add(RocksDbWeight::get().writes(5_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:1)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::RevocationList` (r:1 w:1)
	/// Proof: `Statement::RevocationList` (`max_values`: None, `max_size`: Some(139), added: 2614, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Entries` (r:1 w:1)
	/// Proof: `Statement::Entries` (`max_values`: None, `max_size`: Some(138), added: 2613, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	fn update() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1100`
		//  Estimated: `3664`
		// Minimum execution time: 47_969_000 picoseconds.
		Weight::from_parts(48_900_000, 3664)
			.saturating_add(RocksDbWeight::get().reads(6_u64))
			.saturating_add(RocksDbWeight::get().writes(6_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:0)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::RevocationList` (r:1 w:1)
	/// Proof: `Statement::RevocationList` (`max_values`: None, `max_size`: Some(139), added: 2614, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn revoke() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `973`
		//  Estimated: `3664`
		// Minimum execution time: 37_650_000 picoseconds.
		Weight::from_parts(38_790_000, 3664)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(3_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:0)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::RevocationList` (r:1 w:1)
	/// Proof: `Statement::RevocationList` (`max_values`: None, `max_size`: Some(139), added: 2614, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn restore() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1141`
		//  Estimated: `3664`
		// Minimum execution time: 39_600_000 picoseconds.
		Weight::from_parts(40_170_000, 3664)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(3_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:1)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Entries` (r:2 w:1)
	/// Proof: `Statement::Entries` (`max_values`: None, `max_size`: Some(138), added: 2613, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	/// The range of component `l` is `[1, 5120]`.
	fn remove(_l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1142`
		//  Estimated: `6216`
		// Minimum execution time: 61_950_000 picoseconds.
		Weight::from_parts(64_288_145, 6216)
			.saturating_add(RocksDbWeight::get().reads(6_u64))
			.saturating_add(RocksDbWeight::get().writes(5_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:3 w:3)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:3 w:3)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:3)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Entries` (r:0 w:3)
	/// Proof: `Statement::Entries` (`max_values`: None, `max_size`: Some(138), added: 2613, mode: `MaxEncodedLen`)
	/// The range of component `l` is `[1, 5120]`.
	fn register_batch(_l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `699`
		//  Estimated: `9012`
		// Minimum execution time: 73_189_000 picoseconds.
		Weight::from_parts(76_412_446, 9012)
			.saturating_add(RocksDbWeight::get().reads(8_u64))
			.saturating_add(RocksDbWeight::get().writes(13_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Statements` (r:1 w:0)
	/// Proof: `Statement::Statements` (`max_values`: None, `max_size`: Some(199), added: 2674, mode: `MaxEncodedLen`)
	/// Storage: `Statement::RevocationList` (r:1 w:0)
	/// Proof: `Statement::RevocationList` (`max_values`: None, `max_size`: Some(139), added: 2614, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Presentations` (r:1 w:1)
	/// Proof: `Statement::Presentations` (`max_values`: None, `max_size`: Some(221), added: 2696, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	fn add_presentation() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `973`
		//  Estimated: `3686`
		// Minimum execution time: 41_960_000 picoseconds.
		Weight::from_parts(43_151_000, 3686)
			.saturating_add(RocksDbWeight::get().reads(6_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Statement::Presentations` (r:1 w:1)
	/// Proof: `Statement::Presentations` (`max_values`: None, `max_size`: Some(221), added: 2696, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Statement::IdentifierLookup` (r:0 w:1)
	/// Proof: `Statement::IdentifierLookup` (`max_values`: None, `max_size`: Some(156), added: 2631, mode: `MaxEncodedLen`)
	fn remove_presentation() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1087`
		//  Estimated: `3686`
		// Minimum execution time: 40_230_000 picoseconds.
		Weight::from_parts(41_120_000, 3686)
			.saturating_add(RocksDbWeight::get().reads(4_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
	}
}
