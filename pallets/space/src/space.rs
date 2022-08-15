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

use crate::*;
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// An on-chain space details mapped to an identifier.
#[derive(Clone, Encode, Decode, PartialEq, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
#[codec(mel_bound())]
pub struct SpaceType<T: Config> {
	/// Space hash.
	pub digest: HashOf<T>,
	/// Space creator.
	pub controller: CordAccountOf<T>,
	/// \[OPTIONAL\] Schema Identifier
	pub schema: Option<IdentifierOf>,
}

impl<T: Config> sp_std::fmt::Debug for SpaceType<T> {
	fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}

/// An on-chain space details mapped to an identifier.
#[derive(Clone, Encode, Decode, PartialEq, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
#[codec(mel_bound())]
pub struct SpaceDetails<T: Config> {
	/// Space type.
	pub space: SpaceType<T>,
	/// The flag indicating the status of the space.
	pub archived: StatusOf,
	/// The flag indicating the status of the metadata.
	pub meta: StatusOf,
}

impl<T: Config> sp_std::fmt::Debug for SpaceDetails<T> {
	fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}

impl<T: Config> SpaceDetails<T> {
	pub fn from_space_identities(
		tx_ident: &IdentifierOf,
		requestor: CordAccountOf<T>,
	) -> Result<(), Error<T>> {
		ss58identifier::from_known_format(tx_ident, SPACE_INDEX)
			.map_err(|_| Error::<T>::InvalidSpaceIdentifier)?;

		let space_details = <Spaces<T>>::get(&tx_ident).ok_or(Error::<T>::SpaceNotFound)?;
		ensure!(!space_details.archived, Error::<T>::ArchivedSpace);

		Self::from_space_delegates(tx_ident, space_details.space.controller, requestor)
			.map_err(Error::<T>::from)?;

		Ok(())
	}

	pub fn set_space_metadata(
		tx_ident: &IdentifierOf,
		requestor: CordAccountOf<T>,
		status: bool,
	) -> Result<(), Error<T>> {
		let space_details = <Spaces<T>>::get(&tx_ident).ok_or(Error::<T>::SpaceNotFound)?;
		ensure!(!space_details.archived, Error::<T>::ArchivedSpace);

		Self::from_space_delegates(tx_ident, space_details.space.controller.clone(), requestor)
			.map_err(Error::<T>::from)?;

		<Spaces<T>>::insert(&tx_ident, SpaceDetails { meta: status, ..space_details });

		Ok(())
	}

	// pub fn set_space_schema(
	// 	tx_ident: &IdentifierOf,
	// 	requestor: CordAccountOf<T>,
	// 	tx_schema: IdentifierOf,
	// ) -> Result<(), Error<T>> {
	// 	let space_details =
	// <Spaces<T>>::get(&tx_ident).ok_or(Error::<T>::SpaceNotFound)?;
	// 	ensure!(!space_details.archived, Error::<T>::ArchivedSpace);

	// 	Self::from_space_delegates(tx_ident, space_details.space.controller.clone(),
	// requestor) 		.map_err(Error::<T>::from)?;

	// 	<Spaces<T>>::insert(&tx_ident, SpaceDetails { schema: Some(tx_schema),
	// ..space_details });

	// 	Ok(())
	// }

	pub fn from_space_delegates(
		tx_ident: &IdentifierOf,
		requestor: CordAccountOf<T>,
		controller: CordAccountOf<T>,
	) -> Result<(), Error<T>> {
		if controller != requestor {
			let delegates = <SpaceDelegates<T>>::get(tx_ident);
			ensure!(
				(delegates.iter().find(|&delegate| *delegate == requestor) == Some(&requestor)),
				Error::<T>::UnauthorizedOperation
			);
		}
		Ok(())
	}
}

/// An on-chain schema details mapped to an identifier.
#[derive(Clone, Encode, Decode, PartialEq, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
#[codec(mel_bound())]
pub struct SpaceParams<T: Config> {
	/// Space identifier
	pub identifier: IdentifierOf,
	/// Space Type.
	pub space: SpaceType<T>,
}

impl<T: Config> sp_std::fmt::Debug for SpaceParams<T> {
	fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}
