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

/// Weight functions for `pallet_offences`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_contracts::WeightInfo for WeightInfo<T> {
	/// Storage: `Contracts::DeletionQueueCounter` (r:1 w:0)
	/// Proof: `Contracts::DeletionQueueCounter` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	fn on_process_deletion_queue_batch() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `142`
		//  Estimated: `1627`
		// Minimum execution time: 1_915_000 picoseconds.
		Weight::from_parts(1_986_000, 1627)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `k` is `[0, 1024]`.
	fn on_initialize_per_trie_key(k: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `452 + k * (69 ±0)`
		//  Estimated: `442 + k * (70 ±0)`
		// Minimum execution time: 11_103_000 picoseconds.
		Weight::from_parts(11_326_000, 442)
			// Standard Error: 2_291
			.saturating_add(Weight::from_parts(1_196_329, 0).saturating_mul(k.into()))
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(k.into())))
			.saturating_add(T::DbWeight::get().writes(2_u64))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(k.into())))
			.saturating_add(Weight::from_parts(0, 70).saturating_mul(k.into()))
	}
	/// Storage: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc553022fca90611ba8b7942f8bdb3b97f6580` (r:2 w:1)
	/// Proof: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc553022fca90611ba8b7942f8bdb3b97f6580` (r:2 w:1)
	/// The range of component `c` is `[0, 125952]`.
	fn v9_migration_step(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `211 + c * (1 ±0)`
		//  Estimated: `6149 + c * (1 ±0)`
		// Minimum execution time: 7_783_000 picoseconds.
		Weight::from_parts(4_462_075, 6149)
			// Standard Error: 5
			.saturating_add(Weight::from_parts(1_634, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(c.into()))
	}
	/// Storage: `Contracts::ContractInfoOf` (r:2 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:0)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	fn v10_migration_step() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `510`
		//  Estimated: `6450`
		// Minimum execution time: 15_971_000 picoseconds.
		Weight::from_parts(16_730_000, 6450)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Contracts::DeletionQueue` (r:1 w:1025)
	/// Proof: `Contracts::DeletionQueue` (`max_values`: None, `max_size`: Some(142), added: 2617, mode: `Measured`)
	/// Storage: `Contracts::DeletionQueueCounter` (r:0 w:1)
	/// Proof: `Contracts::DeletionQueueCounter` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	/// The range of component `k` is `[0, 1024]`.
	fn v11_migration_step(k: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `171 + k * (1 ±0)`
		//  Estimated: `3635 + k * (1 ±0)`
		// Minimum execution time: 3_149_000 picoseconds.
		Weight::from_parts(3_264_000, 3635)
			// Standard Error: 559
			.saturating_add(Weight::from_parts(1_111_209, 0).saturating_mul(k.into()))
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(k.into())))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(k.into()))
	}
	/// Storage: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc553053f13fd319a03c211337c76e0fe776df` (r:2 w:0)
	/// Proof: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc553053f13fd319a03c211337c76e0fe776df` (r:2 w:0)
	/// Storage: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc553022fca90611ba8b7942f8bdb3b97f6580` (r:1 w:1)
	/// Proof: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc553022fca90611ba8b7942f8bdb3b97f6580` (r:1 w:1)
	/// Storage: `System::Account` (r:1 w:0)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:0 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// The range of component `c` is `[0, 125952]`.
	fn v12_migration_step(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `325 + c * (1 ±0)`
		//  Estimated: `6263 + c * (1 ±0)`
		// Minimum execution time: 15_072_000 picoseconds.
		Weight::from_parts(15_721_891, 6263)
			// Standard Error: 2
			.saturating_add(Weight::from_parts(428, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(c.into()))
	}
	/// Storage: `Contracts::ContractInfoOf` (r:2 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	fn v13_migration_step() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `440`
		//  Estimated: `6380`
		// Minimum execution time: 12_047_000 picoseconds.
		Weight::from_parts(12_500_000, 6380)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Contracts::CodeInfoOf` (r:2 w:0)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	/// Storage: `Balances::Holds` (r:1 w:0)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `Measured`)
	fn v14_migration_step() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `352`
		//  Estimated: `6292`
		// Minimum execution time: 47_488_000 picoseconds.
		Weight::from_parts(48_482_000, 6292)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Contracts::ContractInfoOf` (r:2 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	/// Storage: `System::Account` (r:2 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	fn v15_migration_step() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `594`
		//  Estimated: `6534`
		// Minimum execution time: 52_801_000 picoseconds.
		Weight::from_parts(54_230_000, 6534)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `Contracts::ContractInfoOf` (r:2 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	fn v16_migration_step() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `409`
		//  Estimated: `6349`
		// Minimum execution time: 11_618_000 picoseconds.
		Weight::from_parts(12_068_000, 6349)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:1)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	fn migration_noop() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `142`
		//  Estimated: `1627`
		// Minimum execution time: 2_131_000 picoseconds.
		Weight::from_parts(2_255_000, 1627)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:1)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	/// Storage: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc55304e7b9012096b41c4eb3aaf947f6ea429` (r:1 w:1)
	/// Proof: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc55304e7b9012096b41c4eb3aaf947f6ea429` (r:1 w:1)
	fn migrate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `166`
		//  Estimated: `3631`
		// Minimum execution time: 10_773_000 picoseconds.
		Weight::from_parts(11_118_000, 3631)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc55304e7b9012096b41c4eb3aaf947f6ea429` (r:1 w:0)
	/// Proof: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc55304e7b9012096b41c4eb3aaf947f6ea429` (r:1 w:0)
	fn on_runtime_upgrade_noop() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `142`
		//  Estimated: `3607`
		// Minimum execution time: 4_371_000 picoseconds.
		Weight::from_parts(4_624_000, 3607)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	/// Storage: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc55304e7b9012096b41c4eb3aaf947f6ea429` (r:1 w:0)
	/// Proof: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc55304e7b9012096b41c4eb3aaf947f6ea429` (r:1 w:0)
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:0)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	fn on_runtime_upgrade_in_progress() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `167`
		//  Estimated: `3632`
		// Minimum execution time: 5_612_000 picoseconds.
		Weight::from_parts(5_838_000, 3632)
			.saturating_add(T::DbWeight::get().reads(2_u64))
	}
	/// Storage: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc55304e7b9012096b41c4eb3aaf947f6ea429` (r:1 w:0)
	/// Proof: UNKNOWN KEY `0x4342193e496fab7ec59d615ed0dc55304e7b9012096b41c4eb3aaf947f6ea429` (r:1 w:0)
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:1)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	fn on_runtime_upgrade() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `142`
		//  Estimated: `3607`
		// Minimum execution time: 5_487_000 picoseconds.
		Weight::from_parts(5_693_000, 3607)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:0)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	/// Storage: `Contracts::ContractInfoOf` (r:1 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:0)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:1 w:0)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	/// Storage: `Timestamp::Now` (r:1 w:0)
	/// Proof: `Timestamp::Now` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	/// The range of component `c` is `[0, 125952]`.
	fn call_with_code_per_byte(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `800 + c * (1 ±0)`
		//  Estimated: `4266 + c * (1 ±0)`
		// Minimum execution time: 247_545_000 picoseconds.
		Weight::from_parts(268_016_699, 4266)
			// Standard Error: 4
			.saturating_add(Weight::from_parts(700, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(6_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(c.into()))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:0)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Balances::Holds` (r:2 w:2)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `Measured`)
	/// Storage: `Contracts::Nonce` (r:1 w:1)
	/// Proof: `Contracts::Nonce` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	/// Storage: `Contracts::ContractInfoOf` (r:1 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	/// Storage: `Timestamp::Now` (r:1 w:0)
	/// Proof: `Timestamp::Now` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:0 w:1)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	/// The range of component `c` is `[0, 125952]`.
	/// The range of component `i` is `[0, 1048576]`.
	/// The range of component `s` is `[0, 1048576]`.
	fn instantiate_with_code(c: u32, i: u32, s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `323`
		//  Estimated: `6262`
		// Minimum execution time: 4_396_772_000 picoseconds.
		Weight::from_parts(235_107_907, 6262)
			// Standard Error: 185
			.saturating_add(Weight::from_parts(53_843, 0).saturating_mul(c.into()))
			// Standard Error: 22
			.saturating_add(Weight::from_parts(2_143, 0).saturating_mul(i.into()))
			// Standard Error: 22
			.saturating_add(Weight::from_parts(2_210, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(8_u64))
			.saturating_add(T::DbWeight::get().writes(7_u64))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:0)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:1 w:0)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	/// Storage: `Contracts::Nonce` (r:1 w:1)
	/// Proof: `Contracts::Nonce` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	/// Storage: `Contracts::ContractInfoOf` (r:1 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	/// Storage: `Timestamp::Now` (r:1 w:0)
	/// Proof: `Timestamp::Now` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `Measured`)
	/// The range of component `i` is `[0, 1048576]`.
	/// The range of component `s` is `[0, 1048576]`.
	fn instantiate(i: u32, s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `560`
		//  Estimated: `4017`
		// Minimum execution time: 2_240_868_000 picoseconds.
		Weight::from_parts(2_273_668_000, 4017)
			// Standard Error: 32
			.saturating_add(Weight::from_parts(934, 0).saturating_mul(i.into()))
			// Standard Error: 32
			.saturating_add(Weight::from_parts(920, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(8_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:0)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	/// Storage: `Contracts::ContractInfoOf` (r:1 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:0)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:1 w:0)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	/// Storage: `Timestamp::Now` (r:1 w:0)
	/// Proof: `Timestamp::Now` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	fn call() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `826`
		//  Estimated: `4291`
		// Minimum execution time: 165_067_000 picoseconds.
		Weight::from_parts(168_582_000, 4291)
			.saturating_add(T::DbWeight::get().reads(6_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:0)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:0 w:1)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	/// The range of component `c` is `[0, 125952]`.
	fn upload_code_determinism_enforced(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `142`
		//  Estimated: `3607`
		// Minimum execution time: 229_454_000 picoseconds.
		Weight::from_parts(251_495_551, 3607)
			// Standard Error: 71
			.saturating_add(Weight::from_parts(51_428, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:0)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:0 w:1)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	/// The range of component `c` is `[0, 125952]`.
	fn upload_code_determinism_relaxed(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `142`
		//  Estimated: `3607`
		// Minimum execution time: 240_390_000 picoseconds.
		Weight::from_parts(273_854_266, 3607)
			// Standard Error: 243
			.saturating_add(Weight::from_parts(51_836, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:0)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(193), added: 2668, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:0 w:1)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	fn remove_code() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `315`
		//  Estimated: `3780`
		// Minimum execution time: 39_374_000 picoseconds.
		Weight::from_parts(40_247_000, 3780)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// Storage: `Contracts::MigrationInProgress` (r:1 w:0)
	/// Proof: `Contracts::MigrationInProgress` (`max_values`: Some(1), `max_size`: Some(1026), added: 1521, mode: `Measured`)
	/// Storage: `Contracts::ContractInfoOf` (r:1 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:2 w:2)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	fn set_code() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `552`
		//  Estimated: `6492`
		// Minimum execution time: 24_473_000 picoseconds.
		Weight::from_parts(25_890_000, 6492)
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// The range of component `r` is `[0, 1600]`.
	fn noop_host_fn(r: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 8_528_000 picoseconds.
		Weight::from_parts(9_301_010, 0)
			// Standard Error: 98
			.saturating_add(Weight::from_parts(53_173, 0).saturating_mul(r.into()))
	}
	fn seal_caller() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 643_000 picoseconds.
		Weight::from_parts(678_000, 0)
	}
	/// Storage: `Contracts::ContractInfoOf` (r:1 w:0)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	fn seal_is_contract() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `354`
		//  Estimated: `3819`
		// Minimum execution time: 6_107_000 picoseconds.
		Weight::from_parts(6_235_000, 3819)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	/// Storage: `Contracts::ContractInfoOf` (r:1 w:0)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	fn seal_code_hash() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `447`
		//  Estimated: `3912`
		// Minimum execution time: 7_316_000 picoseconds.
		Weight::from_parts(7_653_000, 3912)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	fn seal_own_code_hash() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 721_000 picoseconds.
		Weight::from_parts(764_000, 0)
	}
	fn seal_caller_is_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 369_000 picoseconds.
		Weight::from_parts(417_000, 0)
	}
	fn seal_caller_is_root() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 318_000 picoseconds.
		Weight::from_parts(349_000, 0)
	}
	fn seal_address() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 590_000 picoseconds.
		Weight::from_parts(628_000, 0)
	}
	fn seal_gas_left() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 660_000 picoseconds.
		Weight::from_parts(730_000, 0)
	}
	fn seal_balance() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `140`
		//  Estimated: `0`
		// Minimum execution time: 4_361_000 picoseconds.
		Weight::from_parts(4_577_000, 0)
	}
	fn seal_value_transferred() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 560_000 picoseconds.
		Weight::from_parts(603_000, 0)
	}
	fn seal_minimum_balance() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 561_000 picoseconds.
		Weight::from_parts(610_000, 0)
	}
	fn seal_block_number() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 557_000 picoseconds.
		Weight::from_parts(583_000, 0)
	}
	fn seal_now() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 550_000 picoseconds.
		Weight::from_parts(602_000, 0)
	}
	/// Storage: `TransactionPayment::NextFeeMultiplier` (r:1 w:0)
	/// Proof: `TransactionPayment::NextFeeMultiplier` (`max_values`: Some(1), `max_size`: Some(16), added: 511, mode: `Measured`)
	fn seal_weight_to_fee() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `67`
		//  Estimated: `1552`
		// Minimum execution time: 4_065_000 picoseconds.
		Weight::from_parts(4_291_000, 1552)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	/// The range of component `n` is `[0, 1048572]`.
	fn seal_input(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 487_000 picoseconds.
		Weight::from_parts(517_000, 0)
			// Standard Error: 3
			.saturating_add(Weight::from_parts(301, 0).saturating_mul(n.into()))
	}
	/// The range of component `n` is `[0, 1048572]`.
	fn seal_return(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 318_000 picoseconds.
		Weight::from_parts(372_000, 0)
			// Standard Error: 10
			.saturating_add(Weight::from_parts(411, 0).saturating_mul(n.into()))
	}
	/// Storage: `Contracts::DeletionQueueCounter` (r:1 w:1)
	/// Proof: `Contracts::DeletionQueueCounter` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:33 w:33)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Contracts::DeletionQueue` (r:0 w:1)
	/// Proof: `Contracts::DeletionQueue` (`max_values`: None, `max_size`: Some(142), added: 2617, mode: `Measured`)
	/// The range of component `n` is `[0, 32]`.
	fn seal_terminate(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `319 + n * (78 ±0)`
		//  Estimated: `3784 + n * (2553 ±0)`
		// Minimum execution time: 13_251_000 picoseconds.
		Weight::from_parts(15_257_892, 3784)
			// Standard Error: 7_089
			.saturating_add(Weight::from_parts(3_443_907, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(n.into())))
			.saturating_add(T::DbWeight::get().writes(3_u64))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(n.into())))
			.saturating_add(Weight::from_parts(0, 2553).saturating_mul(n.into()))
	}
	/// Storage: `RandomnessCollectiveFlip::RandomMaterial` (r:1 w:0)
	/// Proof: `RandomnessCollectiveFlip::RandomMaterial` (`max_values`: Some(1), `max_size`: Some(2594), added: 3089, mode: `Measured`)
	fn seal_random() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `76`
		//  Estimated: `1561`
		// Minimum execution time: 3_434_000 picoseconds.
		Weight::from_parts(3_605_000, 1561)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	/// Storage: `System::EventTopics` (r:4 w:4)
	/// Proof: `System::EventTopics` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `t` is `[0, 4]`.
	/// The range of component `n` is `[0, 16384]`.
	fn seal_deposit_event(t: u32, n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `990 + t * (2475 ±0)`
		// Minimum execution time: 3_668_000 picoseconds.
		Weight::from_parts(3_999_591, 990)
			// Standard Error: 5_767
			.saturating_add(Weight::from_parts(2_011_090, 0).saturating_mul(t.into()))
			// Standard Error: 1
			.saturating_add(Weight::from_parts(12, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(t.into())))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(t.into())))
			.saturating_add(Weight::from_parts(0, 2475).saturating_mul(t.into()))
	}
	/// The range of component `i` is `[0, 1048576]`.
	fn seal_debug_message(i: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 443_000 picoseconds.
		Weight::from_parts(472_000, 0)
			// Standard Error: 10
			.saturating_add(Weight::from_parts(1_207, 0).saturating_mul(i.into()))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn get_storage_empty() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `16618`
		//  Estimated: `16618`
		// Minimum execution time: 13_752_000 picoseconds.
		Weight::from_parts(14_356_000, 16618)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn get_storage_full() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `26628`
		//  Estimated: `26628`
		// Minimum execution time: 43_444_000 picoseconds.
		Weight::from_parts(45_087_000, 26628)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn set_storage_empty() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `16618`
		//  Estimated: `16618`
		// Minimum execution time: 15_616_000 picoseconds.
		Weight::from_parts(16_010_000, 16618)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn set_storage_full() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `26628`
		//  Estimated: `26628`
		// Minimum execution time: 47_020_000 picoseconds.
		Weight::from_parts(50_152_000, 26628)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `n` is `[0, 16384]`.
	/// The range of component `o` is `[0, 16384]`.
	fn seal_set_storage(n: u32, o: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `250 + o * (1 ±0)`
		//  Estimated: `249 + o * (1 ±0)`
		// Minimum execution time: 8_824_000 picoseconds.
		Weight::from_parts(8_915_233, 249)
			// Standard Error: 1
			.saturating_add(Weight::from_parts(255, 0).saturating_mul(n.into()))
			// Standard Error: 1
			.saturating_add(Weight::from_parts(39, 0).saturating_mul(o.into()))
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(o.into()))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `n` is `[0, 16384]`.
	fn seal_clear_storage(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `248 + n * (1 ±0)`
		//  Estimated: `248 + n * (1 ±0)`
		// Minimum execution time: 7_133_000 picoseconds.
		Weight::from_parts(7_912_778, 248)
			// Standard Error: 1
			.saturating_add(Weight::from_parts(88, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(n.into()))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `n` is `[0, 16384]`.
	fn seal_get_storage(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `248 + n * (1 ±0)`
		//  Estimated: `248 + n * (1 ±0)`
		// Minimum execution time: 6_746_000 picoseconds.
		Weight::from_parts(7_647_236, 248)
			// Standard Error: 2
			.saturating_add(Weight::from_parts(603, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(n.into()))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `n` is `[0, 16384]`.
	fn seal_contains_storage(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `248 + n * (1 ±0)`
		//  Estimated: `248 + n * (1 ±0)`
		// Minimum execution time: 6_247_000 picoseconds.
		Weight::from_parts(6_952_661, 248)
			// Standard Error: 1
			.saturating_add(Weight::from_parts(77, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(n.into()))
	}
	/// Storage: `Skipped::Metadata` (r:0 w:0)
	/// Proof: `Skipped::Metadata` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `n` is `[0, 16384]`.
	fn seal_take_storage(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `248 + n * (1 ±0)`
		//  Estimated: `248 + n * (1 ±0)`
		// Minimum execution time: 7_428_000 picoseconds.
		Weight::from_parts(8_384_015, 248)
			// Standard Error: 2
			.saturating_add(Weight::from_parts(625, 0).saturating_mul(n.into()))
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
			.saturating_add(Weight::from_parts(0, 1).saturating_mul(n.into()))
	}
	fn set_transient_storage_empty() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 1_478_000 picoseconds.
		Weight::from_parts(1_533_000, 0)
	}
	fn set_transient_storage_full() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_485_000 picoseconds.
		Weight::from_parts(2_728_000, 0)
	}
	fn get_transient_storage_empty() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_195_000 picoseconds.
		Weight::from_parts(3_811_000, 0)
	}
	fn get_transient_storage_full() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_902_000 picoseconds.
		Weight::from_parts(4_118_000, 0)
	}
	fn rollback_transient_storage() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 1_571_000 picoseconds.
		Weight::from_parts(1_662_000, 0)
	}
	/// The range of component `n` is `[0, 16384]`.
	/// The range of component `o` is `[0, 16384]`.
	fn seal_set_transient_storage(n: u32, o: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 5_250_000 picoseconds.
		Weight::from_parts(2_465_568, 0)
			// Standard Error: 0
			.saturating_add(Weight::from_parts(201, 0).saturating_mul(n.into()))
			// Standard Error: 0
			.saturating_add(Weight::from_parts(223, 0).saturating_mul(o.into()))
	}
	/// The range of component `n` is `[0, 16384]`.
	fn seal_clear_transient_storage(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_012_000 picoseconds.
		Weight::from_parts(2_288_004, 0)
			// Standard Error: 3
			.saturating_add(Weight::from_parts(239, 0).saturating_mul(n.into()))
	}
	/// The range of component `n` is `[0, 16384]`.
	fn seal_get_transient_storage(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 1_906_000 picoseconds.
		Weight::from_parts(2_121_040, 0)
			// Standard Error: 0
			.saturating_add(Weight::from_parts(225, 0).saturating_mul(n.into()))
	}
	/// The range of component `n` is `[0, 16384]`.
	fn seal_contains_transient_storage(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 1_736_000 picoseconds.
		Weight::from_parts(1_954_728, 0)
			// Standard Error: 0
			.saturating_add(Weight::from_parts(111, 0).saturating_mul(n.into()))
	}
	/// The range of component `n` is `[0, 16384]`.
	fn seal_take_transient_storage(_n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 7_872_000 picoseconds.
		Weight::from_parts(8_125_644, 0)
	}
	fn seal_transfer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `140`
		//  Estimated: `0`
		// Minimum execution time: 8_489_000 picoseconds.
		Weight::from_parts(8_791_000, 0)
	}
	/// Storage: `Contracts::ContractInfoOf` (r:1 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:0)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:1 w:0)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	/// The range of component `t` is `[0, 1]`.
	/// The range of component `i` is `[0, 1048576]`.
	fn seal_call(t: u32, i: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `620 + t * (280 ±0)`
		//  Estimated: `4085 + t * (2182 ±0)`
		// Minimum execution time: 122_759_000 picoseconds.
		Weight::from_parts(120_016_020, 4085)
			// Standard Error: 173_118
			.saturating_add(Weight::from_parts(42_848_338, 0).saturating_mul(t.into()))
			// Standard Error: 0
			.saturating_add(Weight::from_parts(6, 0).saturating_mul(i.into()))
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(t.into())))
			.saturating_add(T::DbWeight::get().writes(1_u64))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(t.into())))
			.saturating_add(Weight::from_parts(0, 2182).saturating_mul(t.into()))
	}
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:0)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:1 w:0)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	fn seal_delegate_call() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `430`
		//  Estimated: `3895`
		// Minimum execution time: 111_566_000 picoseconds.
		Weight::from_parts(115_083_000, 3895)
			.saturating_add(T::DbWeight::get().reads(2_u64))
	}
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:1 w:0)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	/// Storage: `Contracts::Nonce` (r:1 w:0)
	/// Proof: `Contracts::Nonce` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	/// Storage: `Contracts::ContractInfoOf` (r:1 w:1)
	/// Proof: `Contracts::ContractInfoOf` (`max_values`: None, `max_size`: Some(1795), added: 4270, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `Measured`)
	/// The range of component `i` is `[0, 983040]`.
	/// The range of component `s` is `[0, 983040]`.
	fn seal_instantiate(i: u32, s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `676`
		//  Estimated: `4132`
		// Minimum execution time: 1_871_402_000 picoseconds.
		Weight::from_parts(1_890_038_000, 4132)
			// Standard Error: 24
			.saturating_add(Weight::from_parts(581, 0).saturating_mul(i.into()))
			// Standard Error: 24
			.saturating_add(Weight::from_parts(915, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// The range of component `n` is `[0, 1048576]`.
	fn seal_hash_sha2_256(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 966_000 picoseconds.
		Weight::from_parts(9_599_151, 0)
			// Standard Error: 1
			.saturating_add(Weight::from_parts(1_336, 0).saturating_mul(n.into()))
	}
	/// The range of component `n` is `[0, 1048576]`.
	fn seal_hash_keccak_256(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 1_416_000 picoseconds.
		Weight::from_parts(10_964_255, 0)
			// Standard Error: 1
			.saturating_add(Weight::from_parts(3_593, 0).saturating_mul(n.into()))
	}
	/// The range of component `n` is `[0, 1048576]`.
	fn seal_hash_blake2_256(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 821_000 picoseconds.
		Weight::from_parts(6_579_283, 0)
			// Standard Error: 0
			.saturating_add(Weight::from_parts(1_466, 0).saturating_mul(n.into()))
	}
	/// The range of component `n` is `[0, 1048576]`.
	fn seal_hash_blake2_128(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 773_000 picoseconds.
		Weight::from_parts(10_990_209, 0)
			// Standard Error: 1
			.saturating_add(Weight::from_parts(1_457, 0).saturating_mul(n.into()))
	}
	/// The range of component `n` is `[0, 125697]`.
	fn seal_sr25519_verify(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 43_195_000 picoseconds.
		Weight::from_parts(41_864_855, 0)
			// Standard Error: 9
			.saturating_add(Weight::from_parts(5_154, 0).saturating_mul(n.into()))
	}
	fn seal_ecdsa_recover() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 47_747_000 picoseconds.
		Weight::from_parts(49_219_000, 0)
	}
	fn seal_ecdsa_to_eth_address() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 12_854_000 picoseconds.
		Weight::from_parts(12_962_000, 0)
	}
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	/// Storage: `Contracts::PristineCode` (r:1 w:0)
	/// Proof: `Contracts::PristineCode` (`max_values`: None, `max_size`: Some(125988), added: 128463, mode: `Measured`)
	fn seal_set_code_hash() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `430`
		//  Estimated: `3895`
		// Minimum execution time: 17_868_000 picoseconds.
		Weight::from_parts(18_486_000, 3895)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `Measured`)
	fn lock_delegate_dependency() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `355`
		//  Estimated: `3820`
		// Minimum execution time: 8_393_000 picoseconds.
		Weight::from_parts(8_640_000, 3820)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: `Contracts::CodeInfoOf` (r:1 w:1)
	/// Proof: `Contracts::CodeInfoOf` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `MaxEncodedLen`)
	fn unlock_delegate_dependency() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `355`
		//  Estimated: `3558`
		// Minimum execution time: 7_489_000 picoseconds.
		Weight::from_parts(7_815_000, 3558)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	fn seal_reentrance_count() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 299_000 picoseconds.
		Weight::from_parts(339_000, 0)
	}
	fn seal_account_reentrance_count() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 324_000 picoseconds.
		Weight::from_parts(380_000, 0)
	}
	/// Storage: `Contracts::Nonce` (r:1 w:0)
	/// Proof: `Contracts::Nonce` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `Measured`)
	fn seal_instantiation_nonce() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `219`
		//  Estimated: `1704`
		// Minimum execution time: 2_768_000 picoseconds.
		Weight::from_parts(3_025_000, 1704)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	/// The range of component `r` is `[0, 5000]`.
	fn instr_i64_load_store(r: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 766_000 picoseconds.
		Weight::from_parts(722_169, 0)
			// Standard Error: 10
			.saturating_add(Weight::from_parts(7_191, 0).saturating_mul(r.into()))
	}
}
