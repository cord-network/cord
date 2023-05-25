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

//! Autogenerated weights for `pallet_did_names`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-05-25, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
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
// --pallet=pallet_did_names
// --extrinsic=*
// --execution=wasm
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

/// Weight functions for `pallet_did_names`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_did_names::WeightInfo for WeightInfo<T> {
	/// Storage: DidNames Names (r:1 w:1)
	/// Proof: DidNames Names (max_values: None, max_size: Some(114), added: 2589, mode: MaxEncodedLen)
	/// Storage: DidNames Owner (r:1 w:1)
	/// Proof: DidNames Owner (max_values: None, max_size: Some(118), added: 2593, mode: MaxEncodedLen)
	/// Storage: DidNames Banned (r:1 w:0)
	/// Proof: DidNames Banned (max_values: None, max_size: Some(82), added: 2557, mode: MaxEncodedLen)
	/// The range of component `n` is `[13, 64]`.
	fn register(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `76`
		//  Estimated: `3583`
		// Minimum execution time: 19_916_000 picoseconds.
		Weight::from_parts(20_564_115, 0)
			.saturating_add(Weight::from_parts(0, 3583))
			// Standard Error: 826
			.saturating_add(Weight::from_parts(13_345, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: DidNames Names (r:1 w:1)
	/// Proof: DidNames Names (max_values: None, max_size: Some(114), added: 2589, mode: MaxEncodedLen)
	/// Storage: DidNames Owner (r:1 w:1)
	/// Proof: DidNames Owner (max_values: None, max_size: Some(118), added: 2593, mode: MaxEncodedLen)
	fn release() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `348`
		//  Estimated: `3583`
		// Minimum execution time: 19_879_000 picoseconds.
		Weight::from_parts(20_427_000, 0)
			.saturating_add(Weight::from_parts(0, 3583))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: DidNames Banned (r:1 w:1)
	/// Proof: DidNames Banned (max_values: None, max_size: Some(82), added: 2557, mode: MaxEncodedLen)
	/// Storage: DidNames Owner (r:1 w:1)
	/// Proof: DidNames Owner (max_values: None, max_size: Some(118), added: 2593, mode: MaxEncodedLen)
	/// Storage: DidNames Names (r:0 w:1)
	/// Proof: DidNames Names (max_values: None, max_size: Some(114), added: 2589, mode: MaxEncodedLen)
	/// The range of component `n` is `[13, 64]`.
	fn ban(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `186 + n * (1 ±0)`
		//  Estimated: `3583`
		// Minimum execution time: 20_630_000 picoseconds.
		Weight::from_parts(21_124_498, 0)
			.saturating_add(Weight::from_parts(0, 3583))
			// Standard Error: 711
			.saturating_add(Weight::from_parts(33_745, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: DidNames Banned (r:1 w:1)
	/// Proof: DidNames Banned (max_values: None, max_size: Some(82), added: 2557, mode: MaxEncodedLen)
	/// The range of component `n` is `[13, 64]`.
	fn unban(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `114 + n * (1 ±0)`
		//  Estimated: `3547`
		// Minimum execution time: 14_679_000 picoseconds.
		Weight::from_parts(15_218_530, 0)
			.saturating_add(Weight::from_parts(0, 3547))
			// Standard Error: 598
			.saturating_add(Weight::from_parts(26_406, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
