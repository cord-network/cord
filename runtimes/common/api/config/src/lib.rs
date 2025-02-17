// This file is part of CORD – https://cord.network

// Copyright (C) Dhiway Networks Pvt. Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted to meet the requirements of the CORD project.

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

//! Runtime API definition for CORD Config.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use pallet_config::DataNodeId;
use codec::Encode;
pub use cord_primitives::AccountId as CordAccountId;

sp_api::decl_runtime_apis! {
    pub trait ConfigApi<IdentifierOf>
    where
        IdentifierOf: Encode,
    {
        /// Returns the details of a storage node by its `identifier`.
        fn get_storage_node_details_by_identifier(identifier: &IdentifierOf) -> Option<(
            DataNodeId, Vec<CordAccountId>, bool
        )>;
    }
}
