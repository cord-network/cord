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

//! # Scoring Pallet
//!
//! Scoring Pallet maintains aggregated scores for different entities,
//! updating them whenever a new journal entry is added,
//! associate it with their account id.
//!
//! - [`Config`]
//! - [`Call`]
//! - [`Pallet`]
//!
//! ### Terminology
//!
//! - **Scoring:**:
//!
//! ## Assumptions
//!
//! - The Scoring hash was created using CORD SDK.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

#[cfg(any(feature = "mock", test))]
pub mod mock;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

#[cfg(test)]
pub mod tests;

pub mod weights;

pub mod types;

pub use crate::{pallet::*, types::*, weights::WeightInfo};
use frame_support::ensure;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	pub use cord_primitives::{curi::Ss58Identifier, CountOf, RatingOf};
	use cord_utilities::traits::CallSources;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_std::{prelude::Clone, str};

	/// Registry Identifier
	pub type RegistryIdOf = Ss58Identifier;

	///Rating Identifier -- can remove later
	pub type RatingIdOf = Ss58Identifier;

	/// Authorization Identifier
	pub type AuthorizationIdOf = Ss58Identifier;

	/// Hash of the registry.
	pub type RatingHashOf<T> = <T as frame_system::Config>::Hash;

	/// Type of a creator identifier.
	pub type RatingCreatorIdOf<T> = pallet_registry::RegistryCreatorIdOf<T>;

	/// Hash of the Rating.
	pub type RatingEntryHashOf<T> = <T as frame_system::Config>::Hash;

	/// Type of a CORD account.
	pub type AccountIdOf<T> = <T as frame_system::Config>::AccountId;

	/// Type for a block number.
	pub type BlockNumberOf<T> = <T as frame_system::Config>::BlockNumber;

	/// Type for an Identifier
	pub type IdentifierOf = Ss58Identifier;

	/// Type for a Entity(Buisness) Identifier
	pub type EntityIdentifierOf<T> = <T as frame_system::Config>::AccountId;

	///Type for a Collector(Buyer) Identifier
	pub type CollectorIdentifierOf<T> = <T as frame_system::Config>::AccountId;

	pub type JournalIdentifierOf = IdentifierOf;
	pub type TransactionIdentifierOf<T> = BoundedVec<u8, <T as Config>::ValueLimit>;

	pub type RatingDetailsOf<T> = RatingEntryDetails<
		EntityIdentifierOf<T>,
		TransactionIdentifierOf<T>,
		CollectorIdentifierOf<T>,
		RatingTypeOf,
		RatingOf,
		RatingEntryType,
		CountOf,
	>;

	pub type RatingInputOf<T> =
		RatingInput<RatingDetailsOf<T>, RatingEntryHashOf<T>, RatingCreatorIdOf<T>>;

	pub type RatingEntryOf<T> = RatingEntry<
		RatingDetailsOf<T>,
		RatingEntryHashOf<T>,
		BlockNumberOf<T>,
		RegistryIdOf,
		RatingCreatorIdOf<T>,
	>;

	pub type ScoreEntryOf = ScoreEntry<CountOf, RatingOf>;

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_registry::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type EnsureOrigin: EnsureOrigin<
			<Self as frame_system::Config>::RuntimeOrigin,
			Success = <Self as Config>::OriginSuccess,
		>;
		type OriginSuccess: CallSources<AccountIdOf<Self>, RatingCreatorIdOf<Self>>;

		type RatingCreatorIdOf: Parameter + MaxEncodedLen;

		#[pallet::constant]
		type ValueLimit: Get<u32>;
		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	/// journal entry identifiers stored on chain.
	#[pallet::storage]
	#[pallet::getter(fn journal)]
	pub type Journal<T> = StorageDoubleMap<
		_,
		Twox64Concat,
		JournalIdentifierOf,
		Blake2_128Concat,
		RatingTypeOf,
		RatingEntryOf<T>,
		OptionQuery,
	>;

	/// network score - aggregated and mapped to an entity identifier.
	#[pallet::storage]
	#[pallet::getter(fn score)]
	pub type Scores<T> = StorageDoubleMap<
		_,
		Twox64Concat,
		EntityIdentifierOf<T>,
		Blake2_128Concat,
		RatingTypeOf,
		ScoreEntryOf,
		OptionQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn tid_entries)]
	pub type TransactionIdentifiers<T> = StorageDoubleMap<
		_,
		Twox64Concat,
		TransactionIdentifierOf<T>,
		Blake2_128Concat,
		RatingTypeOf,
		EntityIdentifierOf<T>,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new journal entry has been added.
		/// \[entry identifier, entity, author\]
		JournalEntry {
			identifier: JournalIdentifierOf,
			entity: EntityIdentifierOf<T>,
			author: RatingCreatorIdOf<T>,
		},
		/// Aggregate scores has been updated.
		/// \[entity identifier\]
		AggregateUpdated { entity: EntityIdentifierOf<T> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Invalid Identifer Length
		InvalidIdentifierLength,
		// Invalid digest
		InvalidDigest,
		// Invalid creator signature
		InvalidSignature,
		// Invalid Rating Identifier
		InvalidRatingIdentifier,
		// Transaction already rated
		TransactionAlreadyRated,
		// Invalid rating value - should be between 1 and 50
		InvalidRatingValue,
		// Exceeds the maximum allowed entries in a single transaction
		TooManyJournalEntries,
		// Invalid entity signature
		InvalidEntitySignature,
		//Stream digest is not unique
		DigestAlreadyAnchored,
		//If Rating and count value Zero
		CountCannotBeZero,
		//If Rating and count value Zero
		RatingCannotBeZero,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		///
		/// Create a new rating identifier and associates it with its
		/// controller. The controller (issuer) is the owner of the identifier.
		///
		/// * origin: the identity of the Transaction Author.
		/// * tx_journal: the incoming rating entry.
		/// * `authorization`: The authorization ID of the delegate who is
		///   allowed to perform this action.
		#[pallet::call_index(0)]
		#[pallet::weight({0})]
		pub fn add_rating(
			origin: OriginFor<T>,
			journal: RatingInputOf<T>,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let author = <T as Config>::EnsureOrigin::ensure_origin(origin)?.subject();

			let registry_id =
				pallet_registry::Pallet::<T>::is_a_delegate(&authorization, author.clone(), None)
					.map_err(<pallet_registry::Error<T>>::from)?;

			ensure!(
				(journal.entry.rating > 0 && journal.entry.count > 0),
				Error::<T>::InvalidRatingValue
			);

			let identifier = Ss58Identifier::to_scoring_id(&(journal.digest).encode()[..])
				.map_err(|_| Error::<T>::InvalidIdentifierLength)?;

			ensure!(
				!<TransactionIdentifiers<T>>::contains_key(
					&journal.entry.tid,
					&journal.entry.rating_type
				),
				Error::<T>::TransactionAlreadyRated
			);

			let block_number = frame_system::Pallet::<T>::block_number();

			Self::aggregate_score(&journal.entry)?;

			<Journal<T>>::insert(
				&identifier,
				&journal.entry.rating_type,
				RatingEntryOf::<T> {
					entry: journal.entry.clone(),
					digest: journal.digest,
					created_at: block_number,
					registry: registry_id,
					creator: author.clone(),
				},
			);
			<TransactionIdentifiers<T>>::insert(
				&journal.entry.tid,
				&journal.entry.rating_type,
				&journal.entry.entity,
			);

			Self::deposit_event(Event::JournalEntry {
				identifier,
				entity: journal.entry.entity.clone(),
				author,
			});

			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn aggregate_score(entry: &RatingDetailsOf<T>) -> Result<(), pallet::Error<T>> {
		ensure!(entry.count > 0, Error::<T>::CountCannotBeZero);
		ensure!(entry.rating > 0, Error::<T>::RatingCannotBeZero);

		if let Some(mut aggregate) = <Scores<T>>::get(&entry.entity, &entry.rating_type) {
			match entry.entry_type {
				RatingEntryType::Credit => {
					aggregate.count = aggregate.count.saturating_add(entry.count);
					aggregate.rating = aggregate.rating.saturating_add(entry.rating);
				},
				RatingEntryType::Debit => {
					aggregate.count = aggregate.count.saturating_sub(entry.count);
					aggregate.rating = aggregate.rating.saturating_sub(entry.rating);
				},
			};
			<Scores<T>>::insert(
				&entry.entity,
				&entry.rating_type,
				ScoreEntryOf { count: aggregate.count, rating: aggregate.rating },
			);
		} else {
			let new_score_entry = ScoreEntryOf { count: entry.count, rating: entry.rating };
			<Scores<T>>::insert(&entry.entity, &entry.rating_type, new_score_entry);
		}
		Self::deposit_event(Event::AggregateUpdated { entity: entry.entity.clone() });
		Ok(())
	}
}
