#![cfg(feature = "runtime-benchmarks")]

use super::*;
use codec::Encode;
use cord_primitives::curi::Ss58Identifier;
use cord_utilities::traits::GenerateBenchmarkOrigin;
use frame_benchmarking::{account, benchmarks};
use frame_support::{pallet_prelude::*, sp_runtime::traits::Hash};
use pallet_chain_space::{Authorizations, Permissions, SpaceAuthorizationOf, SpaceCodeOf};
use pallet_schema::SchemaHashOf;
use sp_std::convert::TryFrom;

const SEED: u32 = 0;
const MAX_PAYLOAD_BYTE_LENGTH: u32 = 5 * 1024;

/// Generates a statement ID from a statement digest.
pub fn generate_statement_id<T: Config>(digest: &StatementDigestOf<T>) -> StatementIdOf {
	Ss58Identifier::to_statement_id(&(digest).encode()[..]).unwrap()
}

/// Generates a schema ID from a schema digest.
pub fn generate_schema_id<T: Config>(digest: &SchemaHashOf<T>) -> SchemaIdOf {
	Ss58Identifier::to_schema_id(&(digest).encode()[..]).unwrap()
}

/// Generates a space ID from a digest.
pub fn generate_space_id<T: Config>(digest: &SpaceCodeOf<T>) -> SpaceIdOf {
	Ss58Identifier::to_space_id(&(digest).encode()[..]).unwrap()
}

/// Generates an authorization ID from a digest.
pub fn generate_authorization_id<T: Config>(digest: &SpaceCodeOf<T>) -> AuthorizationIdOf {
	Ss58Identifier::to_authorization_id(&(digest).encode()[..]).unwrap()
}

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
	frame_system::Pallet::<T>::assert_last_event(generic_event.into());
}

benchmarks! {
	where_clause {
		where
		<T as Config>::EnsureOrigin: GenerateBenchmarkOrigin<T::RuntimeOrigin, T::AccountId, T::RegistryCreatorId>,
		}
	register {

		let caller: T::AccountId = account("caller", 0, SEED);
		let did_0: T::SpaceCreatorId = account("did", 0, SEED);
		let did_1: T::SpaceCreatorId = account("did", 1, SEED);

		let statement = [77u8; 32].to_vec();

		let statement_digest = <T as frame_system::Config>::Hashing::hash(&statement[..]);

		let raw_space = [56u8; 256].to_vec();
		let space_digest = <T as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
		let space_id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);

		let space_id: SpaceIdOf = generate_space_id::<T>(&space_id_digest);
		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_statement_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&space_id.encode()[..], &did_1.encode()[..], &did_0.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();


		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller, did.clone());
		let chain_space_origin = RawOrigin::Root.into();


		Pallet::<T>::create(origin, space_digest )?;
		Pallet::<T>::approve(chain_space_origin, space_id, capacity ).expect("Approval should not fail.");

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id,
				delegate: did.clone(),
				schema: None,
				permissions: Permissions::all(),
			},
		);

		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller, did.clone());

		// <Attestations<T>>::insert(
		// 	identifier,
		// 	statement_digest,
		// 	AttestationDetailsOf::<T> {
		// 		creator: did.clone(),
		// 		revoked: false,
		// 	},
		// );
		//
	}: _<T::RuntimeOrigin>(origin, statement_digest, authorization_id, None)
	verify {
		assert_last_event::<T>(Event::Created { identifier, author: did}.into());
	}

	create_batch {
		let l in 1 .. MAX_PAYLOAD_BYTE_LENGTH;

		let caller: T::AccountId = account("caller", 0, SEED);
		let did: T::RegistryCreatorId = account("did", 0, SEED);
		let did1: T::RegistryCreatorId = account("did1", 0, SEED);

		let statement0 = [77u8; 32].to_vec();
		let statement1 = [87u8; 32].to_vec();
		let statement2 = [97u8; 32].to_vec();

		let statement_digest0 = <T as frame_system::Config>::Hashing::hash(&statement0[..]);
		let statement_digest1 = <T as frame_system::Config>::Hashing::hash(&statement1[..]);
		let statement_digest2 = <T as frame_system::Config>::Hashing::hash(&statement2[..]);

		let raw_registry = [56u8; 256].to_vec();

		let registry: InputRegistryOf<T> = BoundedVec::try_from(raw_registry).unwrap();

		let id_digest = <T as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &did.encode()[..]].concat()[..],
		);

		let registry_id: RegistryIdOf = generate_registry_id::<T>(&id_digest);

		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_statement_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&registry_id.encode()[..], &did1.encode()[..], &did.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id,
				delegate: did.clone(),
				schema: None,
				permissions: Permissions::all(),
			},
		);

		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller, did.clone());

		// <Attestations<T>>::insert(
		// 	identifier,
		// 	statement_digest,
		// 	AttestationDetailsOf::<T> {
		// 		creator: did.clone(),
		// 		revoked: false,
		// 	},
		// );

	}: _<T::RuntimeOrigin>(origin, vec![statement_digest0, statement_digest1, statement_digest2], authorization_id, None)
	verify {
		assert_last_event::<T>(Event::BatchCreate { successful: 3, falied: 0, indices: [], author: did}.into());
	}

	update {
		let l in 1 .. MAX_PAYLOAD_BYTE_LENGTH;

		let caller: T::AccountId = account("caller", 0, SEED);
		let did: T::RegistryCreatorId = account("did", 0, SEED);
		let did1: T::RegistryCreatorId = account("did1", 0, SEED);


		let raw_registry = [56u8; 256].to_vec();

		let registry: InputRegistryOf<T> = BoundedVec::try_from(raw_registry).unwrap();

		let id_digest = <T as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &did.encode()[..]].concat()[..],
		);

		let registry_id: RegistryIdOf = generate_registry_id::<T>(&id_digest);

		let statement = [77u8; 32].to_vec();

		let statement_digest = <T as frame_system::Config>::Hashing::hash(&statement[..]);

		let statement_id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]].concat()[..],
		);

		let statement_id = generate_statement_id::<T>(&statement_id_digest);

		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_statement_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&registry_id.encode()[..], &did1.encode()[..], &did.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id: registry_id.clone(),
				delegate: did1,
				schema: None,
				permissions: Permissions::all(),
			},
		);

		<Statements<T>>::insert(
			&statement_id,
			StatementDetailsOf::<T> {
				digest: statement_digest,
				schema: None,
				registry: registry_id,
			},
		);

		<Entries<T>>::insert(
			&statement_id,
			statement_digest,
			did.clone(),
		);

		let statement_update = [12u8; 32].to_vec();
		let update_digest = <T as frame_system::Config>::Hashing::hash(&statement_update[..]);

		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller, did.clone());


	}: _<T::RuntimeOrigin>(origin, statement_id, update_digest, authorization_id)
	verify {
		assert_last_event::<T>(Event::Updated { identifier,digest: update_digest, author: did}.into());
	}

	revoke {
		let l in 1 .. MAX_PAYLOAD_BYTE_LENGTH;

		let caller: T::AccountId = account("caller", 0, SEED);
		let did: T::RegistryCreatorId = account("did", 0, SEED);
		let did1: T::RegistryCreatorId = account("did1", 0, SEED);


		let raw_registry = [56u8; 256].to_vec();

		let registry: InputRegistryOf<T> = BoundedVec::try_from(raw_registry).unwrap();

		let id_digest = <T as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &did.encode()[..]].concat()[..],
		);

		let registry_id: RegistryIdOf = generate_registry_id::<T>(&id_digest);

		let statement = [77u8; 32].to_vec();

		let statement_digest = <T as frame_system::Config>::Hashing::hash(&statement[..]);

		let statement_id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]].concat()[..],
		);

		let statement_id = generate_statement_id::<T>(&statement_id_digest);

		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_statement_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&registry_id.encode()[..], &did1.encode()[..], &did.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id: registry_id.clone(),
				delegate: did1,
				schema: None,
				permissions: Permissions::all(),
			},
		);

			<Statements<T>>::insert(
			&statement_id,
			StatementDetailsOf::<T> {
				digest: statement_digest,
				schema: None,
				registry: registry_id,
			},
		);

		<Entries<T>>::insert(
			&statement_id,
			statement_digest,
			did.clone(),
		);


		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller, did.clone());

	}: _<T::RuntimeOrigin>(origin, statement_id.clone(), authorization_id)
	verify {
		assert_last_event::<T>(Event::Revoked { identifier:statement_id,author: did}.into());
	}

	restore {
		let l in 1 .. MAX_PAYLOAD_BYTE_LENGTH;

		let caller: T::AccountId = account("caller", 0, SEED);
		let did: T::RegistryCreatorId = account("did", 0, SEED);
		let did1: T::RegistryCreatorId = account("did1", 0, SEED);


		let raw_registry = [56u8; 256].to_vec();

		let registry: InputRegistryOf<T> = BoundedVec::try_from(raw_registry).unwrap();

		let id_digest = <T as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &did.encode()[..]].concat()[..],
		);

		let registry_id: RegistryIdOf = generate_registry_id::<T>(&id_digest);

		let statement = [77u8; 32].to_vec();

		let statement_digest = <T as frame_system::Config>::Hashing::hash(&statement[..]);

		let statement_id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]].concat()[..],
		);

		let statement_id = generate_statement_id::<T>(&statement_id_digest);

		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_statement_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&registry_id.encode()[..], &did1.encode()[..], &did.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id: registry_id.clone(),
				delegate: did1,
				schema: None,
				permissions: Permissions::all(),
			},
		);

			<Statements<T>>::insert(
			&statement_id,
			StatementDetailsOf::<T> {
				digest: statement_digest,
				schema: None,
				registry: registry_id,
			},
		);

		<Entries<T>>::insert(
			&statement_id,
			statement_digest,
			did.clone(),
		);

	<RevocationRegistry<T>>::insert(
			&statement_id,
			&statement_digest,
			StatementEntryStatusOf::<T> {
				creator: did.clone(),
				revoked: true,
			},
		);


		// let statement_update = [12u8; 32].to_vec();
		// let update_digest = <T as frame_system::Config>::Hashing::hash(&statement_update[..]);

		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller, did.clone());


	}: _<T::RuntimeOrigin>(origin, statement_id.clone(), authorization_id)
	verify {
		assert_last_event::<T>(Event::Restored {identifier:statement_id, author: did}.into());
	}


	remove {
		let l in 1 .. MAX_PAYLOAD_BYTE_LENGTH;

		let caller: T::AccountId = account("caller", 0, SEED);
		let did: T::RegistryCreatorId = account("did", 0, SEED);
		let did1: T::RegistryCreatorId = account("did1", 0, SEED);


		let raw_registry = [56u8; 256].to_vec();

		let registry: InputRegistryOf<T> = BoundedVec::try_from(raw_registry).unwrap();

		let id_digest = <T as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &did.encode()[..]].concat()[..],
		);

		let registry_id: RegistryIdOf = generate_registry_id::<T>(&id_digest);

		let statement = [77u8; 32].to_vec();

		let statement_digest = <T as frame_system::Config>::Hashing::hash(&statement[..]);

		let statement_id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]].concat()[..],
		);

		let statement_id = generate_statement_id::<T>(&statement_id_digest);

		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_statement_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&registry_id.encode()[..], &did1.encode()[..], &did.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id: registry_id.clone(),
				delegate: did1,
				schema: None,
				permissions: Permissions::all(),
			},
		);

		<Statements<T>>::insert(
			&statement_id,
			StatementEntryOf::<T> {
				digest: statement_digest,
				schema: None,
				registry: registry_id,
			},
		);

		// The operation which is expected in method is clear_prefix, but that gives
		// error. Better to setup weights on insert check only for now
		//let _ = <Attestations<T>>::clear_prefix(&statement_id, 0, None);
		<Attestations<T>>::insert(
			&statement_id,
			statement_digest,
			AttestationDetailsOf::<T> {
				creator: did.clone(),
				revoked: false,
			},
		);

		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller, did.clone());
	}: _<T::RuntimeOrigin>(origin, statement_id.clone(), authorization_id)
	verify {
		assert_last_event::<T>(Event::Remove { identifier:statement_id, author: did}.into());
	}

	digest{
		let l in 1 .. MAX_PAYLOAD_BYTE_LENGTH;

		let caller: T::AccountId = account("caller", 0, SEED);
		let did: T::RegistryCreatorId = account("did", 0, SEED);
		let did1: T::RegistryCreatorId = account("did1", 0, SEED);


		let raw_registry = [56u8; 256].to_vec();

		let registry: InputRegistryOf<T> = BoundedVec::try_from(raw_registry).unwrap();

		let id_digest = <T as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &did.encode()[..]].concat()[..],
		);

		let registry_id: RegistryIdOf = generate_registry_id::<T>(&id_digest);

		let statement = [77u8; 32].to_vec();

		let statement_digest = <T as frame_system::Config>::Hashing::hash(&statement[..]);

		let statement_id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]].concat()[..],
		);

		let statement_id = generate_statement_id::<T>(&statement_id_digest);

		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&statement_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_statement_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&registry_id.encode()[..], &did1.encode()[..], &did.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();
		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller, did.clone());

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id: registry_id.clone(),
				delegate: did1,
				schema: None,
				permissions: Permissions::all(),
			},
		);

		<Statements<T>>::insert(
			&statement_id,
			StatementEntryOf::<T> {
				digest: statement_digest,
				schema: None,
				registry: registry_id,
			},
		);

		<Attestations<T>>::insert(
			&statement_id,
			statement_digest,
			AttestationDetailsOf::<T> {
				creator: did.clone(),
				revoked: false,
			},
		);

	}: _<T::RuntimeOrigin>(origin, statement_id.clone(), statement_digest, authorization_id)
	verify {
		assert_last_event::<T>(Event::Digest { identifier:statement_id,digest: statement_digest, author: did}.into());
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);

}
