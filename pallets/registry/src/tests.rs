use super::*;
use crate::mock::*;
use codec::Encode;
use cord_utilities::mock::{mock_origin::DoubleOrigin, SubjectId};
use frame_support::{assert_err, assert_noop, assert_ok, BoundedVec};
use sp_core::H256;
use sp_runtime::{traits::Hash, AccountId32};
use sp_std::prelude::*;

const DEFAULT_REGISTRY_HASH_SEED: u64 = 1u64;
const ALTERNATIVE_REGISTRY_HASH_SEED: u64 = 2u64;

pub fn get_registry_hash<T>(default: bool) -> RegistryHashOf<T>
where
	T: Config,
	T::Hash: From<H256>,
{
	if default {
		H256::from_low_u64_be(DEFAULT_REGISTRY_HASH_SEED).into()
	} else {
		H256::from_low_u64_be(ALTERNATIVE_REGISTRY_HASH_SEED).into()
	}
}

pub fn generate_registry_id<T: Config>(digest: &RegistryHashOf<T>) -> RegistryIdOf {
	Ss58Identifier::to_registry_id(&(digest).encode()[..]).unwrap()
}

pub(crate) const DID_00: SubjectId = SubjectId(AccountId32::new([1u8; 32]));
pub(crate) const DID_01: SubjectId = SubjectId(AccountId32::new([2u8; 32]));
pub(crate) const ACCOUNT_00: AccountId = AccountId::new([1u8; 32]);
pub(crate) const ACCOUNT_01: AccountId = AccountId::new([2u8; 32]);

#[test]

fn add_admin_delegate_should_succeed() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let raw_registry = [2u8; 256].to_vec();
	let registry: InputRegistryOf<Test> = BoundedVec::try_from(raw_registry).unwrap();
	let id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let registry_id: RegistryIdOf = generate_registry_id::<Test>(&id_digest);
	new_test_ext().execute_with(|| {
		//Creating a registry
		assert_ok!(Registry::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			registry.clone(),
			None
		));

		//Admin should be able to add the delegate
		assert_ok!(Registry::add_admin_delegate(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			registry_id,
			DID_01,
		));
	});
}

#[test]
fn add_admin_delegate_should_fail_if_registry_is_not_created() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let raw_registry = [2u8; 256].to_vec();
	let registry: InputRegistryOf<Test> = BoundedVec::try_from(raw_registry).unwrap();
	let id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let registry_id: RegistryIdOf = generate_registry_id::<Test>(&id_digest);

	new_test_ext().execute_with(|| {
		//Should throw Error if registry is not created or found
		assert_err!(
			Registry::add_admin_delegate(
				DoubleOrigin(author.clone(), creator.clone()).into(),
				registry_id.clone(),
				SubjectId(AccountId32::new([1u8; 32])),
			),
			Error::<Test>::RegistryNotFound
		);
	});
}

#[test]
fn add_admin_delegate_should_fail_is_regisrty_an_archive_registry() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let raw_registry = [2u8; 256].to_vec();
	let registry: InputRegistryOf<Test> = BoundedVec::try_from(raw_registry).unwrap();
	let id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let registry_id: RegistryIdOf = generate_registry_id::<Test>(&id_digest);

	new_test_ext().execute_with(|| {
		//creating regisrty
		assert_ok!(Registry::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			registry.clone(),
			None
		));

		<Registries<Test>>::insert(
			&registry_id,
			RegistryEntryOf::<Test> {
				archive: true,
				..<Registries<Test>>::get(&registry_id).unwrap()
			},
		);

		//Admin should be able to add the delegate
		assert_err!(
			Registry::add_admin_delegate(
				DoubleOrigin(author.clone(), creator.clone()).into(),
				registry_id,
				DID_01,
			),
			Error::<Test>::ArchivedRegistry
		);
	});
}

#[test]
fn add_admin_delegate_should_fail_if_creator_is_not_a_authority() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let raw_registry = [2u8; 256].to_vec();
	let registry: InputRegistryOf<Test> = BoundedVec::try_from(raw_registry).unwrap();
	let id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let registry_id: RegistryIdOf = generate_registry_id::<Test>(&id_digest);
	new_test_ext().execute_with(|| {
		//creating regisrty
		assert_ok!(Registry::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			registry.clone(),
			None
		));

		//Checking whether registry creator and creator are different
		assert_ne!(<Registries<Test>>::get(&registry_id).unwrap().creator, DID_01);

		assert_err!(
			Registry::is_an_authority(&registry_id, DID_01),
			Error::<Test>::UnauthorizedOperation
		);
	});
}
