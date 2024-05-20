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

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

pub mod types;

pub use crate::{pallet::*, types::*};
use frame_support::{ensure, traits::Get};
use identifier::{
	types::{CallTypeOf, IdentifierTypeOf, Timepoint},
	EventEntryOf,
};
use pallet_chain_space::AuthorizationIdOf;
use sp_runtime::traits::UniqueSaturatedInto;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	pub use cord_primitives::{CountOf, RatingOf};
	use cord_utilities::traits::CallSources;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	pub use identifier::{IdentifierCreator, IdentifierTimeline, IdentifierType, Ss58Identifier};
	use sp_runtime::BoundedVec;
	use sp_std::{prelude::Clone, str};

	/// Type of the identitiy.
	pub type AccountIdOf<T> = <T as frame_system::Config>::AccountId;

	// Type of a witness creator identifier.
	pub type WitnessCreatorOf<T> = pallet_chain_space::SpaceCreatorOf<T>;

	// Type of witnesses
	pub type WitnessesOf<T> = BoundedVec<WitnessCreatorOf<T>, <T as Config>::MaxWitnessCount>;

	// Type of a document identifier.
	pub type DocumentIdOf = Ss58Identifier;

	// Type of a witness identifier.
	pub type WitnessIdOf = Ss58Identifier;

	pub type WitnessSignersEntryOf<T> = WitnessSignersEntry<WitnessesOf<T>, BlockNumberFor<T>>;

	pub type WitnessEntryOf<T> =
		WitnessEntry<WitnessCreatorOf<T>, EntryHashOf<T>, WitnessStatusOf, BlockNumberFor<T>>;

	#[pallet::config]
	pub trait Config:
		frame_system::Config + pallet_chain_space::Config + identifier::Config
	{
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type EnsureOrigin: EnsureOrigin<
			<Self as frame_system::Config>::RuntimeOrigin,
			Success = <Self as Config>::OriginSuccess,
		>;
		type OriginSuccess: CallSources<AccountIdOf<Self>, WitnessCreatorOf<Self>>;
		#[pallet::constant]
		type MaxEncodedValueLength: Get<u32>;

		#[pallet::constant]
		type MaxWitnessCount: Get<u32>;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	/// Witness entry identifiers with details stored on chain.
	#[pallet::storage]
	pub type Witness<T> =
		StorageMap<_, Blake2_128Concat, DocumentIdOf, WitnessEntryOf<T>, OptionQuery>;

	/// Witnesses signatures entry for a document stored on chain.
	#[pallet::storage]
	pub type WitnessesSignatures<T> =
		StorageMap<_, Blake2_128Concat, DocumentIdOf, WitnessSignersEntryOf<T>, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new witness entry has been added.
		/// \[witness entry identifier, creator\]
		Create { identifier: WitnessIdOf, creator: WitnessCreatorOf<T> },

		/// A new signer has signed the document as a witness.
		/// \[witness entry identifier, signer, current_witness_count, required_witness_count,
		/// status\]
		Witness {
			identifier: WitnessIdOf,
			signer: WitnessCreatorOf<T>,
			current_witness_count: u32,
			required_witness_count: u32,
			status: WitnessStatusOf,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Invalid Identifer Length
		InvalidIdentifierLength,
		/// Unauthorized operation
		UnauthorizedOperation,
		/// Witness Id not found in the storage
		DocumentIdNotFound,
		/// Witness count should be less than 5 and greater than 0
		InvalidWitnessCount,
		/// Witness sign count has reached maximum
		MaxWitnessCountReached,
		/// Witness creation already added
		WitnessIdAlreadyExists,
		/// Witness Identifier is already approved,
		WitnessIdAlreadyApproved,
		/// Witness signer did cannot be same as witness creator did
		WitnessSignerCannotBeSameAsWitnessCreator,
		/// Witness signer has already part of witness party.
		SignerIsAlreadyWitness,
		/// Document digest should remain the same,
		DocumentDigestHasChanged,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight({0})]
		pub fn create(
			origin: OriginFor<T>,
			identifier: DocumentIdOf,
			digest: EntryHashOf<T>,
			witness_count: u32,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let creator = <T as Config>::EnsureOrigin::ensure_origin(origin)?.subject();

			let _space_id = pallet_chain_space::Pallet::<T>::ensure_authorization_origin(
				&authorization,
				&creator.clone(),
			)
			.map_err(<pallet_chain_space::Error<T>>::from)?;

			/* Valid range of witness count is in range [1,5] */
			ensure!(
				(witness_count >= 1) && (witness_count <= T::MaxWitnessCount::get()),
				Error::<T>::InvalidWitnessCount
			);

			ensure!(!<Witness<T>>::contains_key(&identifier), Error::<T>::WitnessIdAlreadyExists);

			let block_number = frame_system::Pallet::<T>::block_number();

			<Witness<T>>::insert(
				&identifier,
				WitnessEntryOf::<T> {
					witness_creator: creator.clone(),
					digest,
					required_witness_count: witness_count,
					current_witness_count: 0,
					witness_status: WitnessStatusOf::WITNESSAPRROVALPENDING,
					created_at: block_number,
				},
			);

			Self::update_activity(&identifier, CallTypeOf::Genesis).map_err(<Error<T>>::from)?;
			Self::deposit_event(Event::Create { identifier, creator });

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight({0})]
		pub fn witness(
			origin: OriginFor<T>,
			identifier: DocumentIdOf,
			digest: EntryHashOf<T>,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let signer = <T as Config>::EnsureOrigin::ensure_origin(origin)?.subject();

			let _space_id = pallet_chain_space::Pallet::<T>::ensure_authorization_origin(
				&authorization,
				&signer.clone(),
			)
			.map_err(<pallet_chain_space::Error<T>>::from)?;

			/* Ensure witness entry identifier exists to sign the document */
			let witness_entry =
				<Witness<T>>::get(&identifier).ok_or(Error::<T>::DocumentIdNotFound)?;

			/* Ensure witness entry is not already approved */
			ensure!(
				witness_entry.witness_status == WitnessStatusOf::WITNESSAPPROVALCOMPLETE,
				Error::<T>::WitnessIdAlreadyApproved
			);

			/* Ensure digest of the document hasn't changed */
			ensure!(witness_entry.digest == digest, Error::<T>::DocumentDigestHasChanged);

			/* Ensure witness signer is not same as witness entry creator */
			ensure!(
				witness_entry.witness_creator == signer,
				Error::<T>::WitnessSignerCannotBeSameAsWitnessCreator
			);

			let block_number = frame_system::Pallet::<T>::block_number();

			// Convert the Option to a Result, ensuring that there's a value
			let mut witness_signers =
				<WitnessesSignatures<T>>::get(&identifier).ok_or(Error::<T>::DocumentIdNotFound)?;

			// Iterate over the existing signers
			for existing_signer in &witness_signers.witnesses {
				// Check if the current signer already exists
				if existing_signer == &signer {
					// If the current signer already exists, throw an error
					return Err(Error::<T>::SignerIsAlreadyWitness.into());
				}
			}

			/* Append to list of witness signers, if current witness is not a part of party
			 * Handle error possiblity of breaching upper bound of Bounded Vector.
			 */
			if let Err(_) = witness_signers.witnesses.try_push(signer.clone()) {
				return Err(Error::<T>::MaxWitnessCountReached.into());
			}

			// Update the storage with the modified witness_signers
			<WitnessesSignatures<T>>::insert(
				&identifier,
				WitnessSignersEntryOf::<T> {
					witnesses: witness_signers.witnesses,
					created_at: block_number,
				},
			);

			let mut witness_status = WitnessStatusOf::WITNESSAPRROVALPENDING;
			let updated_current_witness_count = witness_entry.current_witness_count + 1;

			/* Update the storage by updating the witness count
			 * & witness status when all required witness sign the document
			 */
			if witness_entry.current_witness_count + 1 == witness_entry.required_witness_count {
				witness_status = WitnessStatusOf::WITNESSAPPROVALCOMPLETE;
				<Witness<T>>::insert(
					&identifier,
					WitnessEntryOf::<T> {
						current_witness_count: updated_current_witness_count,
						witness_status: witness_status.clone(),
						..witness_entry.clone()
					},
				)
			} else {
				/* Update the storage by updating the witness count */
				<Witness<T>>::insert(
					&identifier,
					WitnessEntryOf::<T> {
						current_witness_count: updated_current_witness_count,
						..witness_entry.clone()
					},
				);
			}

			Self::update_activity(&identifier, CallTypeOf::Genesis).map_err(<Error<T>>::from)?;
			Self::deposit_event(Event::Witness {
				identifier,
				signer,
				current_witness_count: updated_current_witness_count,
				required_witness_count: witness_entry.required_witness_count,
				status: witness_status,
			});

			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	// pub fn get_distributed_qty(asset_id: &AssetIdOf) -> u32 {
	// 	<Distribution<T>>::get(asset_id)
	// 		.map(|bounded_vec| bounded_vec.len() as u32)
	// 		.unwrap_or(0)
	// }

	pub fn update_activity(tx_id: &WitnessIdOf, tx_action: CallTypeOf) -> Result<(), Error<T>> {
		let tx_moment = Self::timepoint();

		let tx_entry = EventEntryOf { action: tx_action, location: tx_moment };
		let _ =
			IdentifierTimeline::update_timeline::<T>(tx_id, IdentifierTypeOf::Witness, tx_entry);
		Ok(())
	}

	pub fn timepoint() -> Timepoint {
		Timepoint {
			height: frame_system::Pallet::<T>::block_number().unique_saturated_into(),
			index: frame_system::Pallet::<T>::extrinsic_index().unwrap_or_default(),
		}
	}
}
