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

/// Weight functions for `pallet_beefy_mmr`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_beefy_mmr::WeightInfo for WeightInfo<T> {
	/// The range of component `n` is `[2, 512]`.
	fn n_leafs_proof_is_optimal(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 622_000 picoseconds.
		Weight::from_parts(1_166_954, 0)
			.saturating_add(Weight::from_parts(0, 0))
			// Standard Error: 65
			.saturating_add(Weight::from_parts(1_356, 0).saturating_mul(n.into()))
	}
	/// Storage: `System::BlockHash` (r:1 w:0)
	/// Proof: `System::BlockHash` (`max_values`: None, `max_size`: Some(44), added: 2519, mode: `MaxEncodedLen`)
	fn extract_validation_context() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `68`
		//  Estimated: `3509`
		// Minimum execution time: 6_272_000 picoseconds.
		Weight::from_parts(6_452_000, 0)
			.saturating_add(Weight::from_parts(0, 3509))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	/// Storage: `Mmr::Nodes` (r:1 w:0)
	/// Proof: `Mmr::Nodes` (`max_values`: None, `max_size`: Some(40), added: 2515, mode: `MaxEncodedLen`)
	fn read_peak() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `254`
		//  Estimated: `3505`
		// Minimum execution time: 6_576_000 picoseconds.
		Weight::from_parts(6_760_000, 0)
			.saturating_add(Weight::from_parts(0, 3505))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	/// Storage: `Mmr::RootHash` (r:1 w:0)
	/// Proof: `Mmr::RootHash` (`max_values`: Some(1), `max_size`: Some(32), added: 527, mode: `MaxEncodedLen`)
	/// Storage: `Mmr::NumberOfLeaves` (r:1 w:0)
	/// Proof: `Mmr::NumberOfLeaves` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[2, 512]`.
	fn n_items_proof_is_non_canonical(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `246`
		//  Estimated: `1517`
		// Minimum execution time: 12_538_000 picoseconds.
		Weight::from_parts(24_516_023, 0)
			.saturating_add(Weight::from_parts(0, 1517))
			// Standard Error: 1_923
			.saturating_add(Weight::from_parts(1_426_781, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(2))
	}
}
