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

//! Autogenerated weights for `pallet_did`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2024-01-04, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `smohan-dev-host`, CPU: `AMD EPYC 7B12`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("dev")`, DB CACHE: 1024

// Executed Command:
// ./target/production/cord
// benchmark
// pallet
// --chain=dev
// --steps=50
// --repeat=20
// --pallet=pallet_did
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

/// Weight functions for `pallet_did`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_did::WeightInfo for WeightInfo<T> {
	/// Storage: `Did::DidBlacklist` (r:1 w:0)
	/// Proof: `Did::DidBlacklist` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	/// Storage: `Did::DidEndpointsCount` (r:0 w:1)
	/// Proof: `Did::DidEndpointsCount` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `Did::ServiceEndpoints` (r:0 w:25)
	/// Proof: `Did::ServiceEndpoints` (`max_values`: None, `max_size`: Some(413), added: 2888, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[1, 10]`.
	/// The range of component `c` is `[1, 25]`.
	fn create_ed25519_keys(n: u32, c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `5649`
		// Minimum execution time: 102_990_000 picoseconds.
		Weight::from_parts(92_338_994, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			// Standard Error: 56_705
			.saturating_add(Weight::from_parts(726_106, 0).saturating_mul(n.into()))
			// Standard Error: 21_924
			.saturating_add(Weight::from_parts(6_720_657, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(c.into())))
	}
	/// Storage: `Did::DidBlacklist` (r:1 w:0)
	/// Proof: `Did::DidBlacklist` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	/// Storage: `Did::DidEndpointsCount` (r:0 w:1)
	/// Proof: `Did::DidEndpointsCount` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `Did::ServiceEndpoints` (r:0 w:25)
	/// Proof: `Did::ServiceEndpoints` (`max_values`: None, `max_size`: Some(413), added: 2888, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[1, 10]`.
	/// The range of component `c` is `[1, 25]`.
	fn create_sr25519_keys(n: u32, c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `5649`
		// Minimum execution time: 104_760_000 picoseconds.
		Weight::from_parts(84_176_099, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			// Standard Error: 107_032
			.saturating_add(Weight::from_parts(1_536_018, 0).saturating_mul(n.into()))
			// Standard Error: 41_381
			.saturating_add(Weight::from_parts(7_918_476, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(c.into())))
	}
	/// Storage: `Did::DidBlacklist` (r:1 w:0)
	/// Proof: `Did::DidBlacklist` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	/// Storage: `Did::DidEndpointsCount` (r:0 w:1)
	/// Proof: `Did::DidEndpointsCount` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `Did::ServiceEndpoints` (r:0 w:25)
	/// Proof: `Did::ServiceEndpoints` (`max_values`: None, `max_size`: Some(413), added: 2888, mode: `MaxEncodedLen`)
	/// The range of component `n` is `[1, 10]`.
	/// The range of component `c` is `[1, 25]`.
	fn create_ecdsa_keys(n: u32, c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `5649`
		// Minimum execution time: 88_351_000 picoseconds.
		Weight::from_parts(79_143_195, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			// Standard Error: 30_279
			.saturating_add(Weight::from_parts(706_567, 0).saturating_mul(n.into()))
			// Standard Error: 11_707
			.saturating_add(Weight::from_parts(6_389_399, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(c.into())))
	}
	/// Storage: `Did::DidEndpointsCount` (r:1 w:1)
	/// Proof: `Did::DidEndpointsCount` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `Did::ServiceEndpoints` (r:25 w:25)
	/// Proof: `Did::ServiceEndpoints` (`max_values`: None, `max_size`: Some(413), added: 2888, mode: `MaxEncodedLen`)
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	/// Storage: `Did::DidBlacklist` (r:0 w:1)
	/// Proof: `Did::DidBlacklist` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// The range of component `c` is `[1, 25]`.
	fn delete(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `364 + c * (105 ±0)`
		//  Estimated: `5649 + c * (2888 ±0)`
		// Minimum execution time: 24_940_000 picoseconds.
		Weight::from_parts(25_364_552, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			// Standard Error: 4_155
			.saturating_add(Weight::from_parts(1_250_144, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(c.into())))
			.saturating_add(T::DbWeight::get().writes(3))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(c.into())))
			.saturating_add(Weight::from_parts(0, 2888).saturating_mul(c.into()))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn submit_did_call_ed25519_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `233`
		//  Estimated: `5649`
		// Minimum execution time: 82_170_000 picoseconds.
		Weight::from_parts(84_610_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn submit_did_call_sr25519_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `233`
		//  Estimated: `5649`
		// Minimum execution time: 82_600_000 picoseconds.
		Weight::from_parts(83_660_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn submit_did_call_ecdsa_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `234`
		//  Estimated: `5649`
		// Minimum execution time: 67_880_000 picoseconds.
		Weight::from_parts(70_640_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn set_ed25519_authentication_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 25_130_000 picoseconds.
		Weight::from_parts(25_830_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn set_sr25519_authentication_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 25_210_000 picoseconds.
		Weight::from_parts(25_900_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn set_ecdsa_authentication_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1460`
		//  Estimated: `5649`
		// Minimum execution time: 24_320_000 picoseconds.
		Weight::from_parts(25_330_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn set_ed25519_delegation_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 24_700_000 picoseconds.
		Weight::from_parts(25_280_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn set_sr25519_delegation_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 24_971_000 picoseconds.
		Weight::from_parts(26_320_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn set_ecdsa_delegation_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1460`
		//  Estimated: `5649`
		// Minimum execution time: 24_010_000 picoseconds.
		Weight::from_parts(24_480_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn remove_ed25519_delegation_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 22_400_000 picoseconds.
		Weight::from_parts(22_960_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn remove_sr25519_delegation_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 22_340_000 picoseconds.
		Weight::from_parts(23_160_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn remove_ecdsa_delegation_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1460`
		//  Estimated: `5649`
		// Minimum execution time: 22_420_000 picoseconds.
		Weight::from_parts(22_800_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn set_ed25519_assertion_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 24_131_000 picoseconds.
		Weight::from_parts(25_190_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn set_sr25519_assertion_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 23_710_000 picoseconds.
		Weight::from_parts(24_880_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn set_ecdsa_assertion_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1460`
		//  Estimated: `5649`
		// Minimum execution time: 23_630_000 picoseconds.
		Weight::from_parts(24_710_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn remove_ed25519_assertion_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 22_350_000 picoseconds.
		Weight::from_parts(22_950_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn remove_sr25519_assertion_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 22_570_000 picoseconds.
		Weight::from_parts(23_120_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn remove_ecdsa_assertion_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1460`
		//  Estimated: `5649`
		// Minimum execution time: 22_600_000 picoseconds.
		Weight::from_parts(23_220_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn add_ed25519_key_agreement_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1355`
		//  Estimated: `5649`
		// Minimum execution time: 23_580_000 picoseconds.
		Weight::from_parts(24_230_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn add_sr25519_key_agreement_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1355`
		//  Estimated: `5649`
		// Minimum execution time: 23_740_000 picoseconds.
		Weight::from_parts(24_551_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn add_ecdsa_key_agreement_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1358`
		//  Estimated: `5649`
		// Minimum execution time: 23_710_000 picoseconds.
		Weight::from_parts(24_270_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn remove_ed25519_key_agreement_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 22_871_000 picoseconds.
		Weight::from_parts(23_251_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn remove_sr25519_key_agreement_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1457`
		//  Estimated: `5649`
		// Minimum execution time: 23_010_000 picoseconds.
		Weight::from_parts(23_620_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn remove_ecdsa_key_agreement_key() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1460`
		//  Estimated: `5649`
		// Minimum execution time: 22_790_000 picoseconds.
		Weight::from_parts(23_410_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	/// Storage: `Did::DidEndpointsCount` (r:1 w:1)
	/// Proof: `Did::DidEndpointsCount` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `Did::ServiceEndpoints` (r:1 w:1)
	/// Proof: `Did::ServiceEndpoints` (`max_values`: None, `max_size`: Some(413), added: 2888, mode: `MaxEncodedLen`)
	fn add_service_endpoint() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `905`
		//  Estimated: `5649`
		// Minimum execution time: 29_790_000 picoseconds.
		Weight::from_parts(30_760_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	/// Storage: `Did::ServiceEndpoints` (r:1 w:1)
	/// Proof: `Did::ServiceEndpoints` (`max_values`: None, `max_size`: Some(413), added: 2888, mode: `MaxEncodedLen`)
	/// Storage: `Did::DidEndpointsCount` (r:1 w:1)
	/// Proof: `Did::DidEndpointsCount` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	fn remove_service_endpoint() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1286`
		//  Estimated: `5649`
		// Minimum execution time: 28_530_000 picoseconds.
		Weight::from_parts(29_450_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `Did::Did` (r:1 w:0)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	/// The range of component `l` is `[1, 5242880]`.
	fn signature_verification_sr25519(l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1459`
		//  Estimated: `5649`
		// Minimum execution time: 72_510_000 picoseconds.
		Weight::from_parts(78_942_376, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			// Standard Error: 0
			.saturating_add(Weight::from_parts(4_785, 0).saturating_mul(l.into()))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	/// Storage: `Did::Did` (r:1 w:0)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	/// The range of component `l` is `[1, 5242880]`.
	fn signature_verification_ed25519(l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1459`
		//  Estimated: `5649`
		// Minimum execution time: 72_990_000 picoseconds.
		Weight::from_parts(71_306_207, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			// Standard Error: 0
			.saturating_add(Weight::from_parts(1_854, 0).saturating_mul(l.into()))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	/// Storage: `Did::Did` (r:1 w:0)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	/// The range of component `l` is `[1, 5242880]`.
	fn signature_verification_ecdsa(l: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1460`
		//  Estimated: `5649`
		// Minimum execution time: 59_220_000 picoseconds.
		Weight::from_parts(59_050_206, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			// Standard Error: 0
			.saturating_add(Weight::from_parts(1_056, 0).saturating_mul(l.into()))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	/// Storage: `Did::Did` (r:1 w:0)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn dispatch_as() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `234`
		//  Estimated: `5649`
		// Minimum execution time: 15_700_000 picoseconds.
		Weight::from_parts(16_330_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	/// Storage: `Did::DidBlacklist` (r:1 w:0)
	/// Proof: `Did::DidBlacklist` (`max_values`: None, `max_size`: Some(48), added: 2523, mode: `MaxEncodedLen`)
	/// Storage: `Did::Did` (r:1 w:1)
	/// Proof: `Did::Did` (`max_values`: None, `max_size`: Some(2184), added: 4659, mode: `MaxEncodedLen`)
	fn create_from_account() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `5649`
		// Minimum execution time: 13_760_000 picoseconds.
		Weight::from_parts(14_550_000, 0)
			.saturating_add(Weight::from_parts(0, 5649))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
