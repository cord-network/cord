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

//! Autogenerated weights for `pallet_asset`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 32.0.0
//! DATE: 2024-03-05, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `benchmark-temporary`, CPU: `AMD EPYC 7B12`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("dev")`, DB CACHE: 1024

// Executed Command:
// ./target/production/cord
// benchmark
// pallet
// --chain=dev
// --steps=50
// --repeat=20
// --pallet=pallet_asset
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

/// Weight functions for `pallet_asset`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_asset::WeightInfo for WeightInfo<T> {
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Asset::Assets` (r:1 w:1)
	/// Proof: `Asset::Assets` (`max_values`: None, `max_size`: Some(3194), added: 5669, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Asset::AssetLookup` (r:0 w:1)
	/// Proof: `Asset::AssetLookup` (`max_values`: None, `max_size`: Some(98), added: 2573, mode: `MaxEncodedLen`)
	fn create() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `661`
		//  Estimated: `6659`
		// Minimum execution time: 36_810_000 picoseconds.
		Weight::from_parts(37_840_000, 0)
			.saturating_add(Weight::from_parts(0, 6659))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: `ChainSpace::Authorizations` (r:1 w:0)
	/// Proof: `ChainSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `ChainSpace::Spaces` (r:1 w:1)
	/// Proof: `ChainSpace::Spaces` (`max_values`: None, `max_size`: Some(148), added: 2623, mode: `MaxEncodedLen`)
	/// Storage: `Asset::Assets` (r:1 w:1)
	/// Proof: `Asset::Assets` (`max_values`: None, `max_size`: Some(3194), added: 5669, mode: `MaxEncodedLen`)
	/// Storage: `Asset::Distribution` (r:1 w:1)
	/// Proof: `Asset::Distribution` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:2 w:2)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Asset::Issuance` (r:0 w:1)
	/// Proof: `Asset::Issuance` (`max_values`: None, `max_size`: Some(3330), added: 5805, mode: `MaxEncodedLen`)
	/// Storage: `Asset::AssetLookup` (r:0 w:1)
	/// Proof: `Asset::AssetLookup` (`max_values`: None, `max_size`: Some(98), added: 2573, mode: `MaxEncodedLen`)
	fn issue() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `902`
		//  Estimated: `6659`
		// Minimum execution time: 50_380_000 picoseconds.
		Weight::from_parts(51_970_000, 0)
			.saturating_add(Weight::from_parts(0, 6659))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(7))
	}
	/// Storage: `Asset::Assets` (r:1 w:0)
	/// Proof: `Asset::Assets` (`max_values`: None, `max_size`: Some(3194), added: 5669, mode: `MaxEncodedLen`)
	/// Storage: `Asset::Issuance` (r:1 w:1)
	/// Proof: `Asset::Issuance` (`max_values`: None, `max_size`: Some(3330), added: 5805, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn transfer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `852`
		//  Estimated: `6795`
		// Minimum execution time: 29_670_000 picoseconds.
		Weight::from_parts(30_290_000, 0)
			.saturating_add(Weight::from_parts(0, 6795))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `Asset::Assets` (r:1 w:0)
	/// Proof: `Asset::Assets` (`max_values`: None, `max_size`: Some(3194), added: 5669, mode: `MaxEncodedLen`)
	/// Storage: `Asset::Issuance` (r:1 w:1)
	/// Proof: `Asset::Issuance` (`max_values`: None, `max_size`: Some(3330), added: 5805, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn status_change() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `852`
		//  Estimated: `6795`
		// Minimum execution time: 29_260_000 picoseconds.
		Weight::from_parts(29_970_000, 0)
			.saturating_add(Weight::from_parts(0, 6795))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
}
