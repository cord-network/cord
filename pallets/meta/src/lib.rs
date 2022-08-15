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

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

pub use cord_primitives::{
	ss58identifier, IdentifierOf, MetaDataOf, StatusOf, SCHEMA_PREFIX, SPACE_INDEX, STREAM_PREFIX,
};
use frame_support::{
	ensure,
	storage::types::StorageMap,
	traits::{Currency, ReservableCurrency},
};
use sp_runtime::traits::{IdentifyAccount, Saturating, Verify};
use sp_std::{prelude::Clone, str, vec::Vec};
pub mod meta;
pub mod weights;

pub use crate::meta::*;
use crate::weights::WeightInfo;

use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {

	use super::*;

	/// Hash of the space.
	pub type HashOf<T> = <T as frame_system::Config>::Hash;
	/// Type of a CORD account.
	pub type CordAccountOf<T> = <T as frame_system::Config>::AccountId;
	/// Type for a cord signature.
	pub type SignatureOf<T> = <T as Config>::Signature;

	pub(crate) type BalanceOf<T> =
		<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

	pub(crate) type CurrencyOf<T> = <T as Config>::Currency;

	#[pallet::config]
	pub trait Config:
		frame_system::Config + pallet_space::Config + pallet_schema::Config + pallet_stream::Config
	{
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type EnsureOrigin: EnsureOrigin<
			Success = CordAccountOf<Self>,
			<Self as frame_system::Config>::Origin,
		>;
		type Signature: Verify<Signer = <Self as pallet::Config>::Signer>
			+ Parameter
			+ MaxEncodedLen
			+ TypeInfo;
		type Signer: IdentifyAccount<AccountId = CordAccountOf<Self>> + Parameter;
		type Currency: ReservableCurrency<Self::AccountId>;
		type BaseDeposit: Get<BalanceOf<Self>>;
		type ByteDeposit: Get<BalanceOf<Self>>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	/// registry entry metadata stored on chain.
	/// It maps from an identifier to metadata.
	#[pallet::storage]
	#[pallet::storage_prefix = "Metadata"]
	pub(super) type Metadata<T: Config> =
		StorageMap<_, Blake2_128Concat, IdentifierOf, MetadataEntry<T>>;

	/// metadata deposit stored on chain.
	/// It maps from an identifier to metadata author and deposit amount.
	#[pallet::storage]
	#[pallet::storage_prefix = "Deposit"]
	pub(super) type MetadataDeposit<T: Config> =
		StorageMap<_, Blake2_128Concat, IdentifierOf, MetaDeposit<T>>;

	/// registry entry hashes stored on chain.
	/// It maps from an entry hash to Id (resolve from hash).
	#[pallet::storage]
	#[pallet::storage_prefix = "Hashes"]
	pub type MetaHashes<T> = StorageMap<_, Blake2_128Concat, HashOf<T>, IdentifierOf, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A metedata entry has been added.
		/// \[identifier, controller\]
		MetadataSet { identifier: IdentifierOf, controller: CordAccountOf<T> },
		/// A metadata entry has been cleared.
		/// \[identifier, controller\]
		MetadataCleared { identifier: IdentifierOf, controller: CordAccountOf<T> },
		/// A registry entry has been removed.
		/// \[identifier, controller\]
		Remove { identifier: IdentifierOf, controller: CordAccountOf<T> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Only when the author is not the controller.
		UnauthorizedOperation,
		// Invalid Identifier
		InvalidIdentifier,
		// Invalid creator signature
		InvalidSignature,
		// Invalid transaction hash
		InvalidTransactionHash,
		// Metadata limit exceeded
		MetadataLimitExceeded,
		// Metadata already set for the entry
		MetadataAlreadySet,
		// Metadata not found for the entry
		MetadataNotFound,
		// Metadata deposit not found
		MetadataDepositNotFound,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Set metadata for an identifier.
		///
		/// This transaction can only be performed by the identifier controller
		/// or  delegates.
		///
		/// * origin: the identity of the space controller.
		/// * meta: metadata association parameters.
		/// * metadata: An opaque blob representing the metadata for the
		///   proposal. Could be JSON, a Hash, or raw text. Up to the community
		///   to decide how exactly to use this.
		/// * tx_signature: controller signature.
		#[pallet::weight(<T as pallet::Config>::WeightInfo::set_metadata())]
		pub fn set_metadata(
			origin: OriginFor<T>,
			meta: MetaParams<T>,
			metadata: Vec<u8>,
			tx_signature: SignatureOf<T>,
		) -> DispatchResult {
			let author = <T as Config>::EnsureOrigin::ensure_origin(origin)?;

			ensure!(
				!<MetaHashes<T>>::contains_key(&meta.digest),
				Error::<T>::InvalidTransactionHash
			);

			ensure!(
				tx_signature.verify(&(&meta.digest).encode()[..], &meta.controller),
				Error::<T>::InvalidSignature
			);

			ensure!(!<Metadata<T>>::contains_key(&meta.identifier), Error::<T>::MetadataAlreadySet);

			let bounded_metadata: MetaDataOf =
				metadata.try_into().map_err(|_| Error::<T>::MetadataLimitExceeded)?;

			MetaParams::<T>::add_to_identitifier(&meta.identifier, meta.controller.clone(), true)
				.map_err(Error::<T>::from)?;

			let length = bounded_metadata.len() as u32;
			let deposit = T::BaseDeposit::get()
				.saturating_add(T::ByteDeposit::get().saturating_mul(length.into()));

			CurrencyOf::<T>::reserve(&author, deposit)?;

			<MetadataDeposit<T>>::insert(&meta.identifier, MetaDeposit { author, deposit });

			<MetaHashes<T>>::insert(&meta.digest, &meta.identifier);

			Metadata::<T>::insert(
				meta.identifier.clone(),
				MetadataEntry {
					meta: bounded_metadata,
					digest: meta.digest,
					controller: meta.controller.clone(),
				},
			);

			Self::deposit_event(Event::MetadataSet {
				identifier: meta.identifier,
				controller: meta.controller,
			});

			Ok(())
		}
		/// Clear metadata for an identifier.
		///
		/// This transaction can only be performed by the identifier controller
		/// or  delegates.
		///
		/// * origin: the identity of the space controller.
		/// * meta: metadata association parameters.
		/// * tx_signature: controller signature.
		#[pallet::weight(<T as pallet::Config>::WeightInfo::clear_metadata())]
		pub fn clear_metadata(
			origin: OriginFor<T>,
			meta: MetaParams<T>,
			tx_signature: SignatureOf<T>,
		) -> DispatchResult {
			<T as Config>::EnsureOrigin::ensure_origin(origin)?;

			ensure!(
				!<MetaHashes<T>>::contains_key(&meta.digest),
				Error::<T>::InvalidTransactionHash
			);

			ensure!(
				tx_signature.verify(&(&meta.digest).encode()[..], &meta.controller),
				Error::<T>::InvalidSignature
			);

			ensure!(<Metadata<T>>::contains_key(&meta.identifier), Error::<T>::MetadataNotFound);

			let deposit_details = <MetadataDeposit<T>>::get(&meta.identifier)
				.ok_or(Error::<T>::MetadataDepositNotFound)?;

			MetaParams::<T>::add_to_identitifier(&meta.identifier, meta.controller.clone(), false)
				.map_err(|_| Error::<T>::InvalidIdentifier)?;

			CurrencyOf::<T>::unreserve(&deposit_details.author, deposit_details.deposit);

			<MetaHashes<T>>::insert(&meta.digest, &meta.identifier);

			Metadata::<T>::remove(meta.identifier.clone());
			MetadataDeposit::<T>::remove(meta.identifier.clone());

			Self::deposit_event(Event::MetadataCleared {
				identifier: meta.identifier,
				controller: meta.controller,
			});

			Ok(())
		}
	}
}
