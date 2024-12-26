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

/// Weight functions for `pallet_treasury`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_nfts::WeightInfo for WeightInfo<T> {
	/// Storage: `Nfts::NextCollectionId` (r:1 w:1)
	/// Proof: `Nfts::NextCollectionId` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionRoleOf` (r:0 w:1)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:0 w:1)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionAccount` (r:0 w:1)
	/// Proof: `Nfts::CollectionAccount` (`max_values`: None, `max_size`: Some(68), added: 2543, mode: `MaxEncodedLen`)
	fn create() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `216`
		//  Estimated: `3549`
		// Minimum execution time: 34_863_000 picoseconds.
		Weight::from_parts(36_679_000, 3549)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// Storage: `Nfts::NextCollectionId` (r:1 w:1)
	/// Proof: `Nfts::NextCollectionId` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionRoleOf` (r:0 w:1)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:0 w:1)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionAccount` (r:0 w:1)
	/// Proof: `Nfts::CollectionAccount` (`max_values`: None, `max_size`: Some(68), added: 2543, mode: `MaxEncodedLen`)
	fn force_create() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `76`
		//  Estimated: `3549`
		// Minimum execution time: 19_631_000 picoseconds.
		Weight::from_parts(20_384_000, 3549)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemMetadataOf` (r:1 w:0)
	/// Proof: `Nfts::ItemMetadataOf` (`max_values`: None, `max_size`: Some(347), added: 2822, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:1)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Attribute` (r:1001 w:1000)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1000 w:1000)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionMetadataOf` (r:0 w:1)
	/// Proof: `Nfts::CollectionMetadataOf` (`max_values`: None, `max_size`: Some(294), added: 2769, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:0 w:1)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionAccount` (r:0 w:1)
	/// Proof: `Nfts::CollectionAccount` (`max_values`: None, `max_size`: Some(68), added: 2543, mode: `MaxEncodedLen`)
	/// The range of component `m` is `[0, 1000]`.
	/// The range of component `c` is `[0, 1000]`.
	/// The range of component `a` is `[0, 1000]`.
	fn destroy(_m: u32, _c: u32, a: u32) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `32204 + a * (366 ±0)`
		//  Estimated: `2523990 + a * (2954 ±0)`
		// Minimum execution time: 1_282_083_000 picoseconds.
		Weight::from_parts(1_249_191_963, 2523990)
			// Standard Error: 4_719
			.saturating_add(Weight::from_parts(6_470_227, 0).saturating_mul(a.into()))
			.saturating_add(T::DbWeight::get().reads(1004_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(a.into())))
			.saturating_add(T::DbWeight::get().writes(1005_u64))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(a.into())))
			.saturating_add(Weight::from_parts(0, 2954).saturating_mul(a.into()))
	}
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Item` (r:1 w:1)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:1)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Account` (r:0 w:1)
	/// Proof: `Nfts::Account` (`max_values`: None, `max_size`: Some(88), added: 2563, mode: `MaxEncodedLen`)
	fn mint() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `455`
		//  Estimated: `4326`
		// Minimum execution time: 49_055_000 picoseconds.
		Weight::from_parts(50_592_000, 4326)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Item` (r:1 w:1)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:1)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Account` (r:0 w:1)
	/// Proof: `Nfts::Account` (`max_values`: None, `max_size`: Some(88), added: 2563, mode: `MaxEncodedLen`)
	fn force_mint() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `455`
		//  Estimated: `4326`
		// Minimum execution time: 47_102_000 picoseconds.
		Weight::from_parts(48_772_000, 4326)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
	/// Storage: `Nfts::Attribute` (r:1 w:0)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:1)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Item` (r:1 w:1)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemMetadataOf` (r:1 w:0)
	/// Proof: `Nfts::ItemMetadataOf` (`max_values`: None, `max_size`: Some(347), added: 2822, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Account` (r:0 w:1)
	/// Proof: `Nfts::Account` (`max_values`: None, `max_size`: Some(88), added: 2563, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemPriceOf` (r:0 w:1)
	/// Proof: `Nfts::ItemPriceOf` (`max_values`: None, `max_size`: Some(89), added: 2564, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemAttributesApprovalsOf` (r:0 w:1)
	/// Proof: `Nfts::ItemAttributesApprovalsOf` (`max_values`: None, `max_size`: Some(681), added: 3156, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::PendingSwapOf` (r:0 w:1)
	/// Proof: `Nfts::PendingSwapOf` (`max_values`: None, `max_size`: Some(71), added: 2546, mode: `MaxEncodedLen`)
	fn burn() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `564`
		//  Estimated: `4326`
		// Minimum execution time: 52_968_000 picoseconds.
		Weight::from_parts(55_136_000, 4326)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(7_u64))
	}
	/// Storage: `Nfts::Collection` (r:1 w:0)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Attribute` (r:1 w:0)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:0)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Item` (r:1 w:1)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Account` (r:0 w:2)
	/// Proof: `Nfts::Account` (`max_values`: None, `max_size`: Some(88), added: 2563, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemPriceOf` (r:0 w:1)
	/// Proof: `Nfts::ItemPriceOf` (`max_values`: None, `max_size`: Some(89), added: 2564, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::PendingSwapOf` (r:0 w:1)
	/// Proof: `Nfts::PendingSwapOf` (`max_values`: None, `max_size`: Some(71), added: 2546, mode: `MaxEncodedLen`)
	fn transfer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `593`
		//  Estimated: `4326`
		// Minimum execution time: 41_140_000 picoseconds.
		Weight::from_parts(43_288_000, 4326)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// Storage: `Nfts::Collection` (r:1 w:0)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Item` (r:5000 w:5000)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// The range of component `i` is `[0, 5000]`.
	fn redeposit(i: u32) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `763 + i * (108 ±0)`
		//  Estimated: `3549 + i * (3336 ±0)`
		// Minimum execution time: 14_433_000 picoseconds.
		Weight::from_parts(14_664_000, 3549)
			// Standard Error: 23_078
			.saturating_add(Weight::from_parts(15_911_377, 0).saturating_mul(i.into()))
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(i.into())))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(i.into())))
			.saturating_add(Weight::from_parts(0, 3336).saturating_mul(i.into()))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:1)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	fn lock_item_transfer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `435`
		//  Estimated: `3534`
		// Minimum execution time: 18_307_000 picoseconds.
		Weight::from_parts(18_966_000, 3534)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:1)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	fn unlock_item_transfer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `435`
		//  Estimated: `3534`
		// Minimum execution time: 18_078_000 picoseconds.
		Weight::from_parts(18_593_000, 3534)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::Collection` (r:1 w:0)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:1)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	fn lock_collection() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `340`
		//  Estimated: `3549`
		// Minimum execution time: 15_175_000 picoseconds.
		Weight::from_parts(15_762_000, 3549)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::OwnershipAcceptance` (r:1 w:1)
	/// Proof: `Nfts::OwnershipAcceptance` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionAccount` (r:0 w:2)
	/// Proof: `Nfts::CollectionAccount` (`max_values`: None, `max_size`: Some(68), added: 2543, mode: `MaxEncodedLen`)
	fn transfer_ownership() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `562`
		//  Estimated: `3593`
		// Minimum execution time: 26_164_000 picoseconds.
		Weight::from_parts(27_117_000, 3593)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionRoleOf` (r:2 w:4)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	fn set_team() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `369`
		//  Estimated: `6078`
		// Minimum execution time: 38_523_000 picoseconds.
		Weight::from_parts(39_486_000, 6078)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionAccount` (r:0 w:2)
	/// Proof: `Nfts::CollectionAccount` (`max_values`: None, `max_size`: Some(68), added: 2543, mode: `MaxEncodedLen`)
	fn force_collection_owner() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `311`
		//  Estimated: `3549`
		// Minimum execution time: 15_733_000 picoseconds.
		Weight::from_parts(16_227_000, 3549)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// Storage: `Nfts::Collection` (r:1 w:0)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:0 w:1)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	fn force_collection_config() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `276`
		//  Estimated: `3549`
		// Minimum execution time: 12_042_000 picoseconds.
		Weight::from_parts(12_690_000, 3549)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:1)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	fn lock_item_properties() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `435`
		//  Estimated: `3534`
		// Minimum execution time: 17_165_000 picoseconds.
		Weight::from_parts(17_769_000, 3534)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:0)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Attribute` (r:1 w:1)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	fn set_attribute() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `539`
		//  Estimated: `3944`
		// Minimum execution time: 48_862_000 picoseconds.
		Weight::from_parts(50_584_000, 3944)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Attribute` (r:1 w:1)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	fn force_set_attribute() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `344`
		//  Estimated: `3944`
		// Minimum execution time: 24_665_000 picoseconds.
		Weight::from_parts(25_465_000, 3944)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `Nfts::Attribute` (r:1 w:1)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:0)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	fn clear_attribute() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `983`
		//  Estimated: `3944`
		// Minimum execution time: 44_617_000 picoseconds.
		Weight::from_parts(46_458_000, 3944)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `Nfts::Item` (r:1 w:0)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemAttributesApprovalsOf` (r:1 w:1)
	/// Proof: `Nfts::ItemAttributesApprovalsOf` (`max_values`: None, `max_size`: Some(681), added: 3156, mode: `MaxEncodedLen`)
	fn approve_item_attributes() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `381`
		//  Estimated: `4326`
		// Minimum execution time: 15_710_000 picoseconds.
		Weight::from_parts(16_191_000, 4326)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::Item` (r:1 w:0)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemAttributesApprovalsOf` (r:1 w:1)
	/// Proof: `Nfts::ItemAttributesApprovalsOf` (`max_values`: None, `max_size`: Some(681), added: 3156, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Attribute` (r:1001 w:1000)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[0, 1000]`.
	fn cancel_item_attributes_approval(n: u32) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `831 + n * (398 ±0)`
		//  Estimated: `4326 + n * (2954 ±0)`
		// Minimum execution time: 24_447_000 picoseconds.
		Weight::from_parts(25_144_000, 4326)
			// Standard Error: 4_872
			.saturating_add(Weight::from_parts(6_523_101, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(n.into())))
			.saturating_add(T::DbWeight::get().writes(2_u64))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(n.into())))
			.saturating_add(Weight::from_parts(0, 2954).saturating_mul(n.into()))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:0)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemMetadataOf` (r:1 w:1)
	/// Proof: `Nfts::ItemMetadataOf` (`max_values`: None, `max_size`: Some(347), added: 2822, mode: `MaxEncodedLen`)
	fn set_metadata() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `539`
		//  Estimated: `3812`
		// Minimum execution time: 39_990_000 picoseconds.
		Weight::from_parts(41_098_000, 3812)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemMetadataOf` (r:1 w:1)
	/// Proof: `Nfts::ItemMetadataOf` (`max_values`: None, `max_size`: Some(347), added: 2822, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:0)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	fn clear_metadata() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `849`
		//  Estimated: `3812`
		// Minimum execution time: 38_030_000 picoseconds.
		Weight::from_parts(39_842_000, 3812)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionMetadataOf` (r:1 w:1)
	/// Proof: `Nfts::CollectionMetadataOf` (`max_values`: None, `max_size`: Some(294), added: 2769, mode: `MaxEncodedLen`)
	fn set_collection_metadata() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `398`
		//  Estimated: `3759`
		// Minimum execution time: 36_778_000 picoseconds.
		Weight::from_parts(38_088_000, 3759)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionMetadataOf` (r:1 w:1)
	/// Proof: `Nfts::CollectionMetadataOf` (`max_values`: None, `max_size`: Some(294), added: 2769, mode: `MaxEncodedLen`)
	fn clear_collection_metadata() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `716`
		//  Estimated: `3759`
		// Minimum execution time: 36_887_000 picoseconds.
		Weight::from_parts(38_406_000, 3759)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `Nfts::Item` (r:1 w:1)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	fn approve_transfer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `410`
		//  Estimated: `4326`
		// Minimum execution time: 18_734_000 picoseconds.
		Weight::from_parts(19_267_000, 4326)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::Item` (r:1 w:1)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	fn cancel_approval() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `418`
		//  Estimated: `4326`
		// Minimum execution time: 16_080_000 picoseconds.
		Weight::from_parts(16_603_000, 4326)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::Item` (r:1 w:1)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	fn clear_all_transfer_approvals() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `418`
		//  Estimated: `4326`
		// Minimum execution time: 15_013_000 picoseconds.
		Weight::from_parts(15_607_000, 4326)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::OwnershipAcceptance` (r:1 w:1)
	/// Proof: `Nfts::OwnershipAcceptance` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	fn set_accept_ownership() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `76`
		//  Estimated: `3517`
		// Minimum execution time: 13_077_000 picoseconds.
		Weight::from_parts(13_635_000, 3517)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:1)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:0)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	fn set_collection_max_supply() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `340`
		//  Estimated: `3549`
		// Minimum execution time: 17_146_000 picoseconds.
		Weight::from_parts(17_453_000, 3549)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:1)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	fn update_mint_settings() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `323`
		//  Estimated: `3538`
		// Minimum execution time: 16_102_000 picoseconds.
		Weight::from_parts(16_629_000, 3538)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::Item` (r:1 w:0)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:0)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemPriceOf` (r:0 w:1)
	/// Proof: `Nfts::ItemPriceOf` (`max_values`: None, `max_size`: Some(89), added: 2564, mode: `MaxEncodedLen`)
	fn set_price() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `518`
		//  Estimated: `4326`
		// Minimum execution time: 22_118_000 picoseconds.
		Weight::from_parts(22_849_000, 4326)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::Item` (r:1 w:1)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemPriceOf` (r:1 w:1)
	/// Proof: `Nfts::ItemPriceOf` (`max_values`: None, `max_size`: Some(89), added: 2564, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:0)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Attribute` (r:1 w:0)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:0)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Account` (r:0 w:2)
	/// Proof: `Nfts::Account` (`max_values`: None, `max_size`: Some(88), added: 2563, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::PendingSwapOf` (r:0 w:1)
	/// Proof: `Nfts::PendingSwapOf` (`max_values`: None, `max_size`: Some(71), added: 2546, mode: `MaxEncodedLen`)
	fn buy_item() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `705`
		//  Estimated: `4326`
		// Minimum execution time: 50_369_000 picoseconds.
		Weight::from_parts(51_816_000, 4326)
			.saturating_add(T::DbWeight::get().reads(6_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// The range of component `n` is `[0, 10]`.
	fn pay_tips(n: u32) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_203_000 picoseconds.
		Weight::from_parts(3_710_869, 0)
			// Standard Error: 8_094
			.saturating_add(Weight::from_parts(2_201_869, 0).saturating_mul(n.into()))
	}
	/// Storage: `Nfts::Item` (r:2 w:0)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::PendingSwapOf` (r:0 w:1)
	/// Proof: `Nfts::PendingSwapOf` (`max_values`: None, `max_size`: Some(71), added: 2546, mode: `MaxEncodedLen`)
	fn create_swap() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `494`
		//  Estimated: `7662`
		// Minimum execution time: 18_893_000 picoseconds.
		Weight::from_parts(19_506_000, 7662)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::PendingSwapOf` (r:1 w:1)
	/// Proof: `Nfts::PendingSwapOf` (`max_values`: None, `max_size`: Some(71), added: 2546, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Item` (r:1 w:0)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	fn cancel_swap() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `513`
		//  Estimated: `4326`
		// Minimum execution time: 19_086_000 picoseconds.
		Weight::from_parts(19_609_000, 4326)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Nfts::Item` (r:2 w:2)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::PendingSwapOf` (r:1 w:2)
	/// Proof: `Nfts::PendingSwapOf` (`max_values`: None, `max_size`: Some(71), added: 2546, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:0)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Attribute` (r:2 w:0)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:2 w:0)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Account` (r:0 w:4)
	/// Proof: `Nfts::Account` (`max_values`: None, `max_size`: Some(88), added: 2563, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemPriceOf` (r:0 w:2)
	/// Proof: `Nfts::ItemPriceOf` (`max_values`: None, `max_size`: Some(89), added: 2564, mode: `MaxEncodedLen`)
	fn claim_swap() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `834`
		//  Estimated: `7662`
		// Minimum execution time: 84_103_000 picoseconds.
		Weight::from_parts(85_325_000, 7662)
			.saturating_add(T::DbWeight::get().reads(9_u64))
			.saturating_add(T::DbWeight::get().writes(10_u64))
	}
	/// Storage: `Nfts::CollectionRoleOf` (r:2 w:0)
	/// Proof: `Nfts::CollectionRoleOf` (`max_values`: None, `max_size`: Some(69), added: 2544, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Item` (r:1 w:1)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemConfigOf` (r:1 w:1)
	/// Proof: `Nfts::ItemConfigOf` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Attribute` (r:10 w:10)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemMetadataOf` (r:1 w:1)
	/// Proof: `Nfts::ItemMetadataOf` (`max_values`: None, `max_size`: Some(347), added: 2822, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Account` (r:0 w:1)
	/// Proof: `Nfts::Account` (`max_values`: None, `max_size`: Some(88), added: 2563, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[0, 10]`.
	fn mint_pre_signed(n: u32) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `629`
		//  Estimated: `6078 + n * (2954 ±0)`
		// Minimum execution time: 128_363_000 picoseconds.
		Weight::from_parts(139_474_918, 6078)
			// Standard Error: 79_252
			.saturating_add(Weight::from_parts(31_384_027, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(8_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(n.into())))
			.saturating_add(T::DbWeight::get().writes(6_u64))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(n.into())))
			.saturating_add(Weight::from_parts(0, 2954).saturating_mul(n.into()))
	}
	/// Storage: `Nfts::Item` (r:1 w:0)
	/// Proof: `Nfts::Item` (`max_values`: None, `max_size`: Some(861), added: 3336, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::ItemAttributesApprovalsOf` (r:1 w:1)
	/// Proof: `Nfts::ItemAttributesApprovalsOf` (`max_values`: None, `max_size`: Some(681), added: 3156, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::CollectionConfigOf` (r:1 w:0)
	/// Proof: `Nfts::CollectionConfigOf` (`max_values`: None, `max_size`: Some(73), added: 2548, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Collection` (r:1 w:1)
	/// Proof: `Nfts::Collection` (`max_values`: None, `max_size`: Some(84), added: 2559, mode: `MaxEncodedLen`)
	/// Storage: `Nfts::Attribute` (r:10 w:10)
	/// Proof: `Nfts::Attribute` (`max_values`: None, `max_size`: Some(479), added: 2954, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[0, 10]`.
	fn set_attributes_pre_signed(n: u32) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `659`
		//  Estimated: `4326 + n * (2954 ±0)`
		// Minimum execution time: 66_688_000 picoseconds.
		Weight::from_parts(79_208_379, 4326)
			// Standard Error: 74_020
			.saturating_add(Weight::from_parts(31_028_221, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(n.into())))
			.saturating_add(T::DbWeight::get().writes(2_u64))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(n.into())))
			.saturating_add(Weight::from_parts(0, 2954).saturating_mul(n.into()))
	}
}
