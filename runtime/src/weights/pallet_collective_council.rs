// This file is part of CORD – https://cord.network

// Copyright (C) 2019-2022 Dhiway Networks Pvt. Ltd.
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

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `pallet_collective`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_collective::WeightInfo for WeightInfo<T> {
	// Storage: Instance1Collective Members (r:1 w:1)
	// Storage: Instance1Collective Proposals (r:1 w:0)
	// Storage: Instance1Collective Voting (r:100 w:100)
	// Storage: Instance1Collective Prime (r:0 w:1)
	fn set_members(m: u32, n: u32, p: u32, ) -> Weight {
		Weight::from_ref_time(0 as u64)
			// Standard Error: 6_000
			.saturating_add(Weight::from_ref_time(14_448_000 as u64).saturating_mul(m as u64))
			// Standard Error: 6_000
			.saturating_add(Weight::from_ref_time(85_000 as u64).saturating_mul(n as u64))
			// Standard Error: 6_000
			.saturating_add(Weight::from_ref_time(19_620_000 as u64).saturating_mul(p as u64))
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().reads((1 as u64).saturating_mul(p as u64)))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
			.saturating_add(T::DbWeight::get().writes((1 as u64).saturating_mul(p as u64)))
	}
	// Storage: Instance1Collective Members (r:1 w:0)
	fn execute(b: u32, m: u32, ) -> Weight {
		Weight::from_ref_time(22_536_000 as u64)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(3_000 as u64).saturating_mul(b as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(84_000 as u64).saturating_mul(m as u64))
			.saturating_add(T::DbWeight::get().reads(1 as u64))
	}
	// Storage: Instance1Collective Members (r:1 w:0)
	// Storage: Instance1Collective ProposalOf (r:1 w:0)
	fn propose_execute(b: u32, m: u32, ) -> Weight {
		Weight::from_ref_time(27_600_000 as u64)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(3_000 as u64).saturating_mul(b as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(161_000 as u64).saturating_mul(m as u64))
			.saturating_add(T::DbWeight::get().reads(2 as u64))
	}
	// Storage: Instance1Collective Members (r:1 w:0)
	// Storage: Instance1Collective ProposalOf (r:1 w:1)
	// Storage: Instance1Collective Proposals (r:1 w:1)
	// Storage: Instance1Collective ProposalCount (r:1 w:1)
	// Storage: Instance1Collective Voting (r:0 w:1)
	fn propose_proposed(b: u32, m: u32, p: u32, ) -> Weight {
		Weight::from_ref_time(42_192_000 as u64)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(4_000 as u64).saturating_mul(b as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(87_000 as u64).saturating_mul(m as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(361_000 as u64).saturating_mul(p as u64))
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(4 as u64))
	}
	// Storage: Instance1Collective Members (r:1 w:0)
	// Storage: Instance1Collective Voting (r:1 w:1)
	fn vote(m: u32, ) -> Weight {
		Weight::from_ref_time(32_307_000 as u64)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(199_000 as u64).saturating_mul(m as u64))
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Instance1Collective Voting (r:1 w:1)
	// Storage: Instance1Collective Members (r:1 w:0)
	// Storage: Instance1Collective Proposals (r:1 w:1)
	// Storage: Instance1Collective ProposalOf (r:0 w:1)
	fn close_early_disapproved(m: u32, p: u32, ) -> Weight {
		Weight::from_ref_time(41_436_000 as u64)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(170_000 as u64).saturating_mul(m as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(333_000 as u64).saturating_mul(p as u64))
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
	}
	// Storage: Instance1Collective Voting (r:1 w:1)
	// Storage: Instance1Collective Members (r:1 w:0)
	// Storage: Instance1Collective ProposalOf (r:1 w:1)
	// Storage: Instance1Collective Proposals (r:1 w:1)
	fn close_early_approved(b: u32, m: u32, p: u32, ) -> Weight {
		Weight::from_ref_time(57_836_000 as u64)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(2_000 as u64).saturating_mul(b as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(170_000 as u64).saturating_mul(m as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(339_000 as u64).saturating_mul(p as u64))
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
	}
	// Storage: Instance1Collective Voting (r:1 w:1)
	// Storage: Instance1Collective Members (r:1 w:0)
	// Storage: Instance1Collective Prime (r:1 w:0)
	// Storage: Instance1Collective Proposals (r:1 w:1)
	// Storage: Instance1Collective ProposalOf (r:0 w:1)
	fn close_disapproved(m: u32, p: u32, ) -> Weight {
		Weight::from_ref_time(45_551_000 as u64)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(172_000 as u64).saturating_mul(m as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(338_000 as u64).saturating_mul(p as u64))
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
	}
	// Storage: Instance1Collective Voting (r:1 w:1)
	// Storage: Instance1Collective Members (r:1 w:0)
	// Storage: Instance1Collective Prime (r:1 w:0)
	// Storage: Instance1Collective ProposalOf (r:1 w:1)
	// Storage: Instance1Collective Proposals (r:1 w:1)
	fn close_approved(b: u32, m: u32, p: u32, ) -> Weight {
		Weight::from_ref_time(61_497_000 as u64)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(2_000 as u64).saturating_mul(b as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(171_000 as u64).saturating_mul(m as u64))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(343_000 as u64).saturating_mul(p as u64))
			.saturating_add(T::DbWeight::get().reads(5 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
	}
	// Storage: Instance1Collective Proposals (r:1 w:1)
	// Storage: Instance1Collective Voting (r:0 w:1)
	// Storage: Instance1Collective ProposalOf (r:0 w:1)
	fn disapprove_proposal(p: u32, ) -> Weight {
		Weight::from_ref_time(25_573_000 as u64)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(335_000 as u64).saturating_mul(p as u64))
			.saturating_add(T::DbWeight::get().reads(1 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
	}
}
