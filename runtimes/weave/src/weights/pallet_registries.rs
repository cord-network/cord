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

//! Autogenerated weights for `pallet_registries`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 42.0.0
//! DATE: 2025-01-28, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `ns31311672`, CPU: `AMD Ryzen 5 3600X 6-Core Processor`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("dev")`, DB CACHE: 1024

// Executed Command:
// ./target/production/cord
// benchmark
// pallet
// --chain=dev
// --steps=50
// --repeat=20
// --pallet=pallet_registries
// --extrinsic=*
// --wasm-execution=compiled
// --heap-pages=4096
// --header=./HEADER-GPL3
// --output=./runtimes/weave/src/weights/

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_registries`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_registries::WeightInfo for WeightInfo<T> {
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:0)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:2 w:1)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:0)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Delegates` (r:1 w:1)
	/// Proof: `Registries::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn add_delegate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1464`
		//  Estimated: `503599`
		// Minimum execution time: 43_742_000 picoseconds.
		Weight::from_parts(44_242_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:0)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:2 w:1)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:0)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Delegates` (r:1 w:1)
	/// Proof: `Registries::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn add_admin_delegate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1464`
		//  Estimated: `503599`
		// Minimum execution time: 43_312_000 picoseconds.
		Weight::from_parts(43_972_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:0)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:2 w:1)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:0)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Delegates` (r:1 w:1)
	/// Proof: `Registries::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn add_delegator() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1464`
		//  Estimated: `503599`
		// Minimum execution time: 43_672_000 picoseconds.
		Weight::from_parts(44_262_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:0)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:2 w:1)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:0)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Delegates` (r:1 w:1)
	/// Proof: `Registries::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn remove_delegate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1721`
		//  Estimated: `503599`
		// Minimum execution time: 43_792_000 picoseconds.
		Weight::from_parts(44_352_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:1)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:1)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Delegates` (r:0 w:1)
	/// Proof: `Registries::Delegates` (`max_values`: None, `max_size`: Some(320068), added: 322543, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:0 w:1)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	fn create() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `779`
		//  Estimated: `503599`
		// Minimum execution time: 37_192_000 picoseconds.
		Weight::from_parts(37_522_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(5))
	}
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:0)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:1)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:1 w:0)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn update() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1375`
		//  Estimated: `503599`
		// Minimum execution time: 36_932_000 picoseconds.
		Weight::from_parts(37_492_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:0)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:1 w:0)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:1)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn revoke() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1375`
		//  Estimated: `503599`
		// Minimum execution time: 35_892_000 picoseconds.
		Weight::from_parts(36_272_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:0)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:1 w:0)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:1)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn reinstate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1384`
		//  Estimated: `503599`
		// Minimum execution time: 36_072_000 picoseconds.
		Weight::from_parts(36_351_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:0)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:1 w:0)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:1)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn archive() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1375`
		//  Estimated: `503599`
		// Minimum execution time: 36_082_000 picoseconds.
		Weight::from_parts(36_492_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `NameSpace::Authorizations` (r:1 w:0)
	/// Proof: `NameSpace::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `NameSpace::NameSpaces` (r:1 w:0)
	/// Proof: `NameSpace::NameSpaces` (`max_values`: None, `max_size`: Some(500134), added: 502609, mode: `MaxEncodedLen`)
	/// Storage: `Registries::Authorizations` (r:1 w:0)
	/// Proof: `Registries::Authorizations` (`max_values`: None, `max_size`: Some(184), added: 2659, mode: `MaxEncodedLen`)
	/// Storage: `Registries::RegistryInfo` (r:1 w:1)
	/// Proof: `Registries::RegistryInfo` (`max_values`: None, `max_size`: Some(233), added: 2708, mode: `MaxEncodedLen`)
	/// Storage: `Identifier::Identifiers` (r:1 w:1)
	/// Proof: `Identifier::Identifiers` (`max_values`: None, `max_size`: Some(4294967295), added: 2474, mode: `MaxEncodedLen`)
	fn restore() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1384`
		//  Estimated: `503599`
		// Minimum execution time: 36_022_000 picoseconds.
		Weight::from_parts(36_501_000, 0)
			.saturating_add(Weight::from_parts(0, 503599))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(2))
	}
}
