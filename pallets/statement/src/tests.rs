use super::*;
use crate::mock::*;
use codec::Encode;
use cord_utilities::mock::{mock_origin::DoubleOrigin, SubjectId};
use frame_support::{assert_err, assert_ok, BoundedVec};
use frame_system::RawOrigin;
use pallet_chain_space::SpaceCodeOf;
use pallet_schema::{InputSchemaOf, SchemaHashOf};
use sp_runtime::{traits::Hash, AccountId32};

/// Generates a statement ID from a statement digest.
pub fn generate_statement_id<T: Config>(digest: &StatementDigestOf<T>) -> StatementIdOf {
	Ss58Identifier::create_identifier(&(digest).encode()[..], IdentifierType::Statement).unwrap()
}

/// Generates a schema ID from a schema digest.
pub fn generate_schema_id<T: Config>(digest: &SchemaHashOf<T>) -> SchemaIdOf {
	Ss58Identifier::create_identifier(&(digest).encode()[..], IdentifierType::Schema).unwrap()
}

/// Generates a space ID from a digest.
pub fn generate_space_id<T: Config>(digest: &SpaceCodeOf<T>) -> SpaceIdOf {
	Ss58Identifier::create_identifier(&(digest).encode()[..], IdentifierType::Space).unwrap()
}

/// Generates an authorization ID from a digest.
pub fn generate_authorization_id<T: Config>(digest: &SpaceCodeOf<T>) -> AuthorizationIdOf {
	Ss58Identifier::create_identifier(&(digest).encode()[..], IdentifierType::Authorization)
		.unwrap()
}

pub(crate) const DID_00: SubjectId = SubjectId(AccountId32::new([1u8; 32]));
pub(crate) const DID_01: SubjectId = SubjectId(AccountId32::new([5u8; 32]));
pub(crate) const DID_02: SubjectId = SubjectId(AccountId32::new([6u8; 32]));
pub(crate) const ACCOUNT_00: AccountId = AccountId::new([1u8; 32]);

#[test]
fn register_statement_should_succeed() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 3u64;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author, creator).into(),
			statement_digest,
			authorization_id,
			Some(schema_id)
		));
	});
}

#[test]
fn trying_to_register_statement_to_a_non_existent_space_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let delegate = DID_01;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);
	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	new_test_ext().execute_with(|| {
		assert_err!(
			Statement::register(
				DoubleOrigin(author, delegate).into(),
				statement_digest,
				authorization_id,
				Some(schema_id)
			),
			pallet_chain_space::Error::<Test>::AuthorizationNotFound
		);
	});
}

#[test]
fn trying_to_register_statement_by_a_non_delegate_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let delegate = DID_01;
	let capacity = 3u64;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_err!(
			Statement::register(
				DoubleOrigin(author, delegate).into(),
				statement_digest,
				authorization_id,
				Some(schema_id)
			),
			pallet_chain_space::Error::<Test>::UnauthorizedOperation
		);
	});
}

#[test]
fn updating_a_registered_statement_should_succeed() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest: StatementDigestOf<Test> =
		<Test as frame_system::Config>::Hashing::hash(&statement[..]);
	let new_statement = [88u8; 32];
	let new_statement_digest = <Test as frame_system::Config>::Hashing::hash(&new_statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_ok!(Statement::update(
			DoubleOrigin(author, creator).into(),
			statement_id.clone(),
			new_statement_digest,
			authorization_id,
		));

		let revoked_statements = RevocationList::<Test>::get(statement_id, statement_digest)
			.expect("Old Statement digest should be present on the revoked list.");

		assert!(revoked_statements.revoked);
	});
}

#[test]
fn updating_a_registered_statement_by_a_space_delegate_should_succeed() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let delegate = DID_01;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);
	let new_statement = [88u8; 32];
	let new_statement_digest = <Test as frame_system::Config>::Hashing::hash(&new_statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	let delegate_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &delegate.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let delegate_authorization_id = generate_authorization_id::<Test>(&delegate_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id.clone(), capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Space::add_delegate(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_id,
			delegate.clone(),
			authorization_id.clone(),
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_ok!(Statement::update(
			DoubleOrigin(author, delegate).into(),
			statement_id,
			new_statement_digest,
			delegate_authorization_id,
		));
	});
}

#[test]
fn trying_to_update_a_registered_statement_by_a_non_space_delegate_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let delegate = DID_01;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);
	let new_statement = [88u8; 32];
	let new_statement_digest = <Test as frame_system::Config>::Hashing::hash(&new_statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	let delegate_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &delegate.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let delegate_authorization_id = generate_authorization_id::<Test>(&delegate_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id.clone(), capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_err!(
			Statement::update(
				DoubleOrigin(author, delegate).into(),
				statement_id,
				new_statement_digest,
				delegate_authorization_id,
			),
			pallet_chain_space::Error::<Test>::AuthorizationNotFound
		);
	});
}

#[test]
fn trying_to_update_a_non_registered_statement_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);
	let new_statement = [88u8; 32];
	let new_statement_digest = <Test as frame_system::Config>::Hashing::hash(&new_statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id.clone(), capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			new_statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_err!(
			Statement::update(
				DoubleOrigin(author, creator).into(),
				statement_id,
				statement_digest,
				authorization_id,
			),
			Error::<Test>::StatementNotFound
		);
	});
}

#[test]
fn revoking_a_registered_statement_should_succeed() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest: StatementDigestOf<Test> =
		<Test as frame_system::Config>::Hashing::hash(&statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_ok!(Statement::revoke(
			DoubleOrigin(author, creator).into(),
			statement_id.clone(),
			authorization_id,
		));

		let revoked_statements = RevocationList::<Test>::get(statement_id, statement_digest)
			.expect("Old Statement digest should be present on the revoked list.");

		assert!(revoked_statements.revoked);
	});
}

#[test]
fn revoking_a_registered_statement_by_a_non_delegate_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let delegate = DID_01;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest: StatementDigestOf<Test> =
		<Test as frame_system::Config>::Hashing::hash(&statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let new_raw_space = [4u8; 256].to_vec();
	let new_space_digest =
		<Test as frame_system::Config>::Hashing::hash(&new_raw_space.encode()[..]);
	let new_space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&new_space_digest.encode()[..], &delegate.encode()[..]].concat()[..],
	);
	let new_space_id: SpaceIdOf = generate_space_id::<Test>(&new_space_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	let delegate_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&new_space_id.encode()[..], &delegate.encode()[..], &delegate.encode()[..]].concat()[..],
	);
	let delegate_authorization_id = generate_authorization_id::<Test>(&delegate_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), delegate.clone()).into(),
			new_space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id.clone(), capacity));
		assert_ok!(Space::approve(RawOrigin::Root.into(), new_space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Space::add_delegate(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_id,
			delegate.clone(),
			authorization_id.clone(),
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_err!(
			Statement::revoke(
				DoubleOrigin(author, delegate).into(),
				statement_id.clone(),
				delegate_authorization_id,
			),
			Error::<Test>::UnauthorizedOperation
		);
	});
}

#[test]
fn restoring_a_revoked_statement_should_succeed() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest: StatementDigestOf<Test> =
		<Test as frame_system::Config>::Hashing::hash(&statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_ok!(Statement::revoke(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_id.clone(),
			authorization_id.clone(),
		));

		let revoked_statements =
			RevocationList::<Test>::get(statement_id.clone(), statement_digest)
				.expect("Old Statement digest should be present on the revoked list.");

		assert!(revoked_statements.revoked);

		assert_ok!(Statement::restore(
			DoubleOrigin(author, creator).into(),
			statement_id.clone(),
			authorization_id,
		));
	});
}

#[test]
fn trying_to_restore_a_non_revoked_statement_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest: StatementDigestOf<Test> =
		<Test as frame_system::Config>::Hashing::hash(&statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_err!(
			Statement::restore(
				DoubleOrigin(author, creator).into(),
				statement_id.clone(),
				authorization_id,
			),
			Error::<Test>::StatementNotRevoked
		);
	});
}

#[test]
fn trying_to_restore_a_revoked_statement_by_a_non_delegate_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let delegate = DID_01;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest: StatementDigestOf<Test> =
		<Test as frame_system::Config>::Hashing::hash(&statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let new_raw_space = [4u8; 256].to_vec();
	let new_space_digest =
		<Test as frame_system::Config>::Hashing::hash(&new_raw_space.encode()[..]);
	let new_space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&new_space_digest.encode()[..], &delegate.encode()[..]].concat()[..],
	);
	let new_space_id: SpaceIdOf = generate_space_id::<Test>(&new_space_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	let delegate_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&new_space_id.encode()[..], &delegate.encode()[..], &delegate.encode()[..]].concat()[..],
	);
	let delegate_authorization_id = generate_authorization_id::<Test>(&delegate_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), delegate.clone()).into(),
			new_space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id.clone(), capacity));
		assert_ok!(Space::approve(RawOrigin::Root.into(), new_space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Space::add_delegate(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_id,
			delegate.clone(),
			authorization_id.clone(),
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_ok!(Statement::revoke(
			DoubleOrigin(author.clone(), creator).into(),
			statement_id.clone(),
			authorization_id,
		));

		assert_err!(
			Statement::restore(
				DoubleOrigin(author, delegate).into(),
				statement_id.clone(),
				delegate_authorization_id,
			),
			Error::<Test>::UnauthorizedOperation
		);
	});
}

#[test]
fn registering_a_statement_again_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let delegate = DID_01;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id.clone(), capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Space::add_delegate(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_id,
			delegate.clone(),
			authorization_id.clone(),
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id.clone())
		));

		assert_err!(
			Statement::register(
				DoubleOrigin(author, creator).into(),
				statement_digest,
				authorization_id,
				Some(schema_id)
			),
			Error::<Test>::StatementAlreadyAnchored
		);
	});
}

#[test]
fn updating_a_registered_statement_again_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest: StatementDigestOf<Test> =
		<Test as frame_system::Config>::Hashing::hash(&statement[..]);
	let new_statement = [88u8; 32];
	let new_statement_digest = <Test as frame_system::Config>::Hashing::hash(&new_statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		assert_ok!(Statement::update(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_id.clone(),
			new_statement_digest,
			authorization_id.clone(),
		));

		assert_err!(
			Statement::update(
				DoubleOrigin(author, creator).into(),
				statement_id,
				new_statement_digest,
				authorization_id,
			),
			Error::<Test>::StatementDigestAlreadyAnchored
		);
	});
}

#[test]
fn removing_nonexistent_presentation_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);
	let presentation_digest = <Test as frame_system::Config>::Hashing::hash(&[99u8; 32][..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			None
		));

		assert_err!(
			Statement::remove_presentation(
				DoubleOrigin(author, creator).into(),
				statement_id,
				presentation_digest,
				authorization_id,
			),
			Error::<Test>::PresentationNotFound
		);
	});
}

#[test]
fn bulk_registering_statements_with_same_digest_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 10u64;

	let mut statement_digests = Vec::new();
	for _ in 0..5 {
		let statement = [77u8; 32];
		let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);
		statement_digests.push(statement_digest);
	}

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digests[0],
			authorization_id.clone(),
			Some(schema_id.clone())
		));

		assert_err!(
			Statement::register_batch(
				DoubleOrigin(author, creator).into(),
				statement_digests,
				authorization_id,
				Some(schema_id)
			),
			Error::<Test>::BulkTransactionFailed
		);
	});
}

#[test]
fn trying_to_update_or_revoke_or_add_presentation_for_revoked_statement_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);
	let new_statement = [88u8; 32];
	let new_statement_digest = <Test as frame_system::Config>::Hashing::hash(&new_statement[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);

	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			Some(schema_id)
		));

		// Revoke the statement
		assert_ok!(Statement::revoke(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_id.clone(),
			authorization_id.clone(),
		));

		// Try to update the revoked statement
		assert_err!(
			Statement::update(
				DoubleOrigin(author.clone(), creator.clone()).into(),
				statement_id.clone(),
				new_statement_digest,
				authorization_id.clone(),
			),
			Error::<Test>::StatementRevoked
		);

		// Try to revoke the already revoked statement
		assert_err!(
			Statement::revoke(
				DoubleOrigin(author.clone(), creator.clone()).into(),
				statement_id.clone(),
				authorization_id.clone(),
			),
			Error::<Test>::StatementRevoked
		);

		// Try to add a presentation for the revoked statement
		assert_err!(
			Statement::add_presentation(
				DoubleOrigin(author, creator).into(),
				statement_id,
				statement_digest,
				PresentationTypeOf::Other,
				authorization_id,
			),
			Error::<Test>::StatementRevoked
		);
	});
}

#[test]
fn nonexistent_presentation_should_fail() {
	let creator = DID_00;
	let author = ACCOUNT_00;
	let capacity = 5u64;
	let statement = [77u8; 32];
	let statement_digest = <Test as frame_system::Config>::Hashing::hash(&statement[..]);
	let presentation_digest = <Test as frame_system::Config>::Hashing::hash(&[99u8; 32][..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let statement_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let statement_id: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest);

	new_test_ext().execute_with(|| {
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id, capacity));

		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			statement_digest,
			authorization_id.clone(),
			None
		));

		assert_err!(
			Statement::remove_presentation(
				DoubleOrigin(author, creator).into(),
				statement_id,
				presentation_digest,
				authorization_id,
			),
			Error::<Test>::PresentationNotFound
		);
	});
}

#[test]
fn revoking_a_registered_statement_by_a_different_delegate_should_fail() {
	let creator = DID_00;
	let delegate_1 = DID_01;
	let author = ACCOUNT_00;
	let delegate_2 = DID_02;

	let capacity = 10u64;

	let statement_1 = [77u8; 32];
	let statement_digest_1 = <Test as frame_system::Config>::Hashing::hash(&statement_1[..]);

	let statement_2 = [77u8; 32];
	let statement_digest_2 = <Test as frame_system::Config>::Hashing::hash(&statement_2[..]);

	let new_statement_1 = [66u8; 32];
	let new_statement_digest_1 =
		<Test as frame_system::Config>::Hashing::hash(&new_statement_1[..]);

	let new_statement_2 = [66u8; 32];
	let new_statement_digest_2 =
		<Test as frame_system::Config>::Hashing::hash(&new_statement_2[..]);

	let raw_space = [2u8; 256].to_vec();
	let space_digest = <Test as frame_system::Config>::Hashing::hash(&raw_space.encode()[..]);
	let space_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_digest.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let space_id: SpaceIdOf = generate_space_id::<Test>(&space_id_digest);

	let auth_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest);

	let raw_schema = [11u8; 256].to_vec();
	let schema: InputSchemaOf<Test> = BoundedVec::try_from(raw_schema)
		.expect("Test Schema should fit into the expected input length of for the test runtime.");
	let schema_id_digest = <Test as frame_system::Config>::Hashing::hash(
		&[&schema.encode()[..], &space_id.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let schema_id: SchemaIdOf = generate_schema_id::<Test>(&schema_id_digest);

	let auth_digest_1 = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &delegate_1.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id_1: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest_1);

	let auth_digest_2 = <Test as frame_system::Config>::Hashing::hash(
		&[&space_id.encode()[..], &delegate_2.encode()[..], &creator.encode()[..]].concat()[..],
	);
	let authorization_id_2: Ss58Identifier = generate_authorization_id::<Test>(&auth_digest_2);

	let statement_id_digest_1 = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest_1.encode()[..], &space_id.encode()[..], &delegate_1.encode()[..]]
			.concat()[..],
	);

	let statement_id_1: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest_1);

	let statement_id_digest_2 = <Test as frame_system::Config>::Hashing::hash(
		&[&statement_digest_2.encode()[..], &space_id.encode()[..], &delegate_2.encode()[..]]
			.concat()[..],
	);

	let statement_id_2: StatementIdOf = generate_statement_id::<Test>(&statement_id_digest_2);

	new_test_ext().execute_with(|| {
		// Create a space with `creator`.
		assert_ok!(Space::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_digest,
		));

		// Approve the space with the `creator`.
		assert_ok!(Space::approve(RawOrigin::Root.into(), space_id.clone(), capacity));

		// Create a schema with the `creator`.
		assert_ok!(Schema::create(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			schema.clone(),
			authorization_id.clone()
		));

		// Add a delegate `delegate-1` using `creator` (admin) authorization-id.
		assert_ok!(Space::add_delegate(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_id.clone(),
			delegate_1.clone(),
			authorization_id.clone(),
		));

		// Add a delegate `delegate-2` using `creator` (admin) authorization-id.
		assert_ok!(Space::add_delegate(
			DoubleOrigin(author.clone(), creator.clone()).into(),
			space_id.clone(),
			delegate_2.clone(),
			authorization_id.clone(),
		));

		// Create a statement-1 with delegate-1 as the creator.
		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), delegate_1.clone()).into(),
			statement_digest_1,
			authorization_id_1.clone(),
			Some(schema_id.clone())
		));

		// Create a statement-2 with delegate-2 as the creator.
		assert_ok!(Statement::register(
			DoubleOrigin(author.clone(), delegate_2.clone()).into(),
			statement_digest_2,
			authorization_id_2.clone(),
			Some(schema_id)
		));

		// Update the statement-1 using delegate-2 authorization-id.
		// Ideally should below fail?
		assert_ok!(Statement::update(
			DoubleOrigin(author.clone(), delegate_1).into(),
			statement_id_1,
			new_statement_digest_1,
			authorization_id_1,
		));

		// Update the statement-2 using delegate-1 authorization-id.
		// Ideally should below fail?
		assert_ok!(Statement::update(
			DoubleOrigin(author, delegate_2).into(),
			statement_id_2,
			new_statement_digest_2,
			authorization_id_2,
		));
	});
}
