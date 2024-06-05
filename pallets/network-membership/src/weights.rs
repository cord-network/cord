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

//! Autogenerated weights for `pallet_network_membership`
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
// --pallet=pallet_network_membership
// --extrinsic=*
// --wasm-execution=compiled
// --heap-pages=4096
// --output=./pallets/network-membership/src/weights.rs
// --header=./HEADER-GPL3
// --template=./.maintain/frame-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for `pallet_network_membership`.
pub trait WeightInfo {
	fn nominate() -> Weight;
	fn renew() -> Weight;
	fn revoke() -> Weight;
}

/// Weights for `pallet_network_membership` using the CORD node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: `NetworkMembership::Members` (r:1 w:1)
	/// Proof: `NetworkMembership::Members` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `NetworkMembership::CounterForMembers` (r:1 w:1)
	/// Proof: `NetworkMembership::CounterForMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `NetworkMembership::MembershipsExpiresOn` (r:1 w:1)
	/// Proof: `NetworkMembership::MembershipsExpiresOn` (`max_values`: None, `max_size`: Some(32022), added: 34497, mode: `MaxEncodedLen`)
	fn nominate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `224`
		//  Estimated: `35487`
		// Minimum execution time: 23_310_000 picoseconds.
		Weight::from_parts(23_770_000, 35487)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
	/// Storage: `NetworkMembership::MembershipsRenewsOn` (r:1 w:1)
	/// Proof: `NetworkMembership::MembershipsRenewsOn` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	fn renew() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `149`
		//  Estimated: `3513`
		// Minimum execution time: 10_280_000 picoseconds.
		Weight::from_parts(10_660_000, 3513)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `NetworkMembership::Members` (r:1 w:1)
	/// Proof: `NetworkMembership::Members` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `NetworkMembership::CounterForMembers` (r:1 w:1)
	/// Proof: `NetworkMembership::CounterForMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NetworkMembership::MembershipsExpiresOn` (r:1 w:1)
	/// Proof: `NetworkMembership::MembershipsExpiresOn` (`max_values`: None, `max_size`: Some(32022), added: 34497, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn revoke() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `514`
		//  Estimated: `35487`
		// Minimum execution time: 27_610_000 picoseconds.
		Weight::from_parts(28_060_000, 35487)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
}

// For backwards compatibility and tests.
impl WeightInfo for () {
	/// Storage: `NetworkMembership::Members` (r:1 w:1)
	/// Proof: `NetworkMembership::Members` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `NetworkMembership::CounterForMembers` (r:1 w:1)
	/// Proof: `NetworkMembership::CounterForMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `NetworkMembership::MembershipsExpiresOn` (r:1 w:1)
	/// Proof: `NetworkMembership::MembershipsExpiresOn` (`max_values`: None, `max_size`: Some(32022), added: 34497, mode: `MaxEncodedLen`)
	fn nominate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `224`
		//  Estimated: `35487`
		// Minimum execution time: 23_310_000 picoseconds.
		Weight::from_parts(23_770_000, 35487)
			.saturating_add(RocksDbWeight::get().reads(4_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
	}
	/// Storage: `NetworkMembership::MembershipsRenewsOn` (r:1 w:1)
	/// Proof: `NetworkMembership::MembershipsRenewsOn` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	fn renew() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `149`
		//  Estimated: `3513`
		// Minimum execution time: 10_280_000 picoseconds.
		Weight::from_parts(10_660_000, 3513)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
	/// Storage: `NetworkMembership::Members` (r:1 w:1)
	/// Proof: `NetworkMembership::Members` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `NetworkMembership::CounterForMembers` (r:1 w:1)
	/// Proof: `NetworkMembership::CounterForMembers` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `NetworkMembership::MembershipsExpiresOn` (r:1 w:1)
	/// Proof: `NetworkMembership::MembershipsExpiresOn` (`max_values`: None, `max_size`: Some(32022), added: 34497, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn revoke() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `514`
		//  Estimated: `35487`
		// Minimum execution time: 27_610_000 picoseconds.
		Weight::from_parts(28_060_000, 35487)
			.saturating_add(RocksDbWeight::get().reads(4_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
	}
}
