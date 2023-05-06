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

//! Autogenerated weights for pallet_registry
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-05-06, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `ip-172-31-3-249`, CPU: `Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("dev"), DB CACHE: 1024

// Executed Command:
// ./target/production/cord
// benchmark
// pallet
// --chain=dev
// --steps=50
// --repeat=20
// --pallet=pallet_registry
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=./pallets/registry/src/weights.rs
// --header=./HEADER-GPL3
// --template=./.maintain/frame-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for pallet_registry.
pub trait WeightInfo {
	fn create(l: u32, ) -> Weight;
	fn update(l: u32, ) -> Weight;
	fn add_admin_delegate() -> Weight;
	fn add_delegate() -> Weight;
	fn remove_delegate() -> Weight;
	fn archive() -> Weight;
	fn restore() -> Weight;
	fn transfer() -> Weight;
}

/// Weights for pallet_registry using the CORD node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: Registry Registries (r:1 w:1)
	/// Proof: Registry Registries (max_values: None, max_size: Some(15544), added: 18019, mode: MaxEncodedLen)
	/// Storage: Registry Commits (r:1 w:1)
	/// Proof: Registry Commits (max_values: None, max_size: Some(69068), added: 71543, mode: MaxEncodedLen)
	/// The range of component `l` is `[1, 15360]`.
	fn create(_l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `91542`
		// Minimum execution time: 74_032_000 picoseconds.
		Weight::from_parts(75_627_621, 91542)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: Registry Registries (r:1 w:1)
	/// Proof: Registry Registries (max_values: None, max_size: Some(15544), added: 18019, mode: MaxEncodedLen)
	/// Storage: Registry Commits (r:1 w:1)
	/// Proof: Registry Commits (max_values: None, max_size: Some(69068), added: 71543, mode: MaxEncodedLen)
	/// The range of component `l` is `[1, 15360]`.
	fn update(l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `15726`
		//  Estimated: `91542`
		// Minimum execution time: 60_378_000 picoseconds.
		Weight::from_parts(62_758_765, 91542)
			// Standard Error: 3
			.saturating_add(Weight::from_parts(4, 0).saturating_mul(l.into()))
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	// Dummy weights
	fn add_admin_delegate() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	fn add_delegate() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	fn remove_delegate() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	fn archive() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	fn restore() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	fn transfer() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	/// Storage: Registry Registries (r:1 w:1)
	/// Proof: Registry Registries (max_values: None, max_size: Some(15544), added: 18019, mode: MaxEncodedLen)
	/// Storage: Registry Commits (r:1 w:1)
	/// Proof: Registry Commits (max_values: None, max_size: Some(69068), added: 71543, mode: MaxEncodedLen)
	/// The range of component `l` is `[1, 15360]`.
	fn create(_l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `91542`
		// Minimum execution time: 74_032_000 picoseconds.
		Weight::from_parts(75_627_621, 91542)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}
	/// Storage: Registry Registries (r:1 w:1)
	/// Proof: Registry Registries (max_values: None, max_size: Some(15544), added: 18019, mode: MaxEncodedLen)
	/// Storage: Registry Commits (r:1 w:1)
	/// Proof: Registry Commits (max_values: None, max_size: Some(69068), added: 71543, mode: MaxEncodedLen)
	/// The range of component `l` is `[1, 15360]`.
	fn update(l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `15726`
		//  Estimated: `91542`
		// Minimum execution time: 60_378_000 picoseconds.
		Weight::from_parts(62_758_765, 91542)
			// Standard Error: 3
			.saturating_add(Weight::from_parts(4, 0).saturating_mul(l.into()))
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}
	// Dummy weights
	fn add_admin_delegate() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
	}
	fn add_delegate() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
	}
	fn remove_delegate() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
	}
	fn archive() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	fn restore() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
	}
	fn transfer() -> Weight {
		Weight::from_parts(322_000_000,0)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}

}
