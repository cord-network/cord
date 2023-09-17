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
//

use super::*;
use crate::mock::{authorities, new_test_ext, Session, *};

use frame_support::{assert_err, assert_noop, assert_ok};
use frame_system::RawOrigin;
use sp_runtime::{testing::UintAuthorityId, traits::BadOrigin};
use sp_staking::offence::OffenceDetails;

const EMPTY: Vec<u64> = Vec::new();

#[test]
fn test_genesis_build() {
	new_test_ext().execute_with(|| {
		run_to_block(1);
		// Verify AuthorityMembers state
		assert_eq!(AuthorityMembership::incoming(), EMPTY);
		assert_eq!(AuthorityMembership::outgoing(), EMPTY);
		assert_eq!(AuthorityMembership::member(), vec![1u64, 2u64, 3u64]);
		// Verify Session state
		assert_eq!(Session::current_index(), 0);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
	});
}

#[test]
fn test_new_session_shoud_not_change_authorities_set() {
	new_test_ext().execute_with(|| {
		run_to_block(6);

		assert_eq!(Session::current_index(), 1);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
	});
}

/// tests nominate call
#[test]
fn test_go_online_with_a_new_authority_member() {
	new_test_ext().execute_with(|| {
		run_to_block(1);

		assert_ok!(NetworkMembership::nominate(RuntimeOrigin::root(), 1, true));
		assert_ok!(NetworkMembership::nominate(RuntimeOrigin::root(), 10, true));
		assert_noop!(AuthorityMembership::nominate(RuntimeOrigin::signed(5), 10), BadOrigin);
		assert_noop!(
			AuthorityMembership::nominate(RuntimeOrigin::root(), 1),
			Error::<Test>::MemberAlreadyExists
		);
		assert_ok!(Session::set_keys(
			RuntimeOrigin::signed(10),
			UintAuthorityId(10).into(),
			vec![]
		));
		assert_ok!(AuthorityMembership::nominate(RuntimeOrigin::root(), 10));

		// Verify state
		assert_eq!(AuthorityMembership::member(), vec![1u64, 2u64, 3u64, 10u64]);
		assert_eq!(AuthorityMembership::incoming(), vec![10]);
		assert_eq!(AuthorityMembership::outgoing(), EMPTY);

		// Member 10 should be "programmed" at the next session
		run_to_block(5);
		assert_eq!(AuthorityMembership::incoming(), EMPTY);
		assert_eq!(Session::current_index(), 1);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
		assert_eq!(Session::queued_keys().len(), 4);
		assert_eq!(Session::queued_keys()[0].0, 1);
		assert_eq!(Session::queued_keys()[1].0, 2);
		assert_eq!(Session::queued_keys()[2].0, 3);
		assert_eq!(Session::queued_keys()[3].0, 10);
		// Member 10 should be **effectively** in the authorities set in 2 sessions
		run_to_block(10);
		assert_eq!(Session::current_index(), 2);
		assert_eq!(Session::validators(), vec![1, 2, 3, 10]);
	});
}

/// tests go_offline call
#[test]
fn test_go_offline() {
	new_test_ext().execute_with(|| {
		run_to_block(1);

		// Member 3 should be able to go offline
		assert_ok!(AuthorityMembership::go_offline(RuntimeOrigin::signed(3)),);

		// Verify state
		assert_eq!(Session::current_index(), 0); // we are currently at session 0
		assert_eq!(Session::validators(), vec![1, 2, 3]);
		assert_eq!(AuthorityMembership::incoming(), EMPTY);
		assert_eq!(AuthorityMembership::outgoing(), vec![3]);
		assert_eq!(AuthorityMembership::blacklist(), EMPTY);
		assert_eq!(AuthorityMembership::member(), vec![1u64, 2u64, 3u64]);

		// Member 3 should be outgoing at the next session (session 1).
		// They should be out at session 2.
		run_to_block(5);
		assert_eq!(Session::current_index(), 1);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
		assert_eq!(Session::queued_keys().len(), 2);
		assert_eq!(Session::queued_keys()[0].0, 1);
		assert_eq!(Session::queued_keys()[1].0, 2);

		run_to_block(10);
		assert_eq!(Session::current_index(), 2);
		assert_eq!(Session::validators(), vec![1, 2]);
	});
}

/// test go_offline and go_online call
#[test]
fn test_go_offline_then_go_online() {
	new_test_ext().execute_with(|| {
		run_to_block(1);

		// Member 3 should be able to go offline
		assert_ok!(AuthorityMembership::go_offline(RuntimeOrigin::signed(3)),);
		assert_eq!(AuthorityMembership::outgoing(), vec![3]);

		run_to_block(10);
		assert_eq!(Session::current_index(), 2);
		assert_eq!(Session::validators(), vec![1, 2]);
		// Member 3 should be able to go online
		assert_ok!(AuthorityMembership::go_online(RuntimeOrigin::signed(3)),);
		assert_eq!(AuthorityMembership::incoming(), vec![3]);

		run_to_block(20);
		assert_eq!(Session::current_index(), 4);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
	});
}

#[test]
fn test_go_offline_then_go_online_in_same_session() {
	new_test_ext().execute_with(|| {
		run_to_block(1);

		// Member 3 should be able to go offline
		assert_ok!(AuthorityMembership::go_offline(RuntimeOrigin::signed(3)),);

		run_to_block(2);
		// Member 3 should be able to go online at the same session to "cancel" their
		// previous action
		assert_ok!(AuthorityMembership::go_online(RuntimeOrigin::signed(3)),);
		assert_eq!(AuthorityMembership::incoming(), vec![3]);
		assert_eq!(AuthorityMembership::outgoing(), vec![3]);

		run_to_block(5);
		assert_eq!(Session::current_index(), 1);
		assert_eq!(AuthorityMembership::incoming(), EMPTY);
		assert_eq!(AuthorityMembership::outgoing(), EMPTY);

		run_to_block(10);
		assert_eq!(Session::current_index(), 2);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
	});
}

/// tests remove call
#[test]
fn test_add_and_remove_an_authority_member() {
	new_test_ext().execute_with(|| {
		run_to_block(1);

		assert_ok!(NetworkMembership::nominate(RuntimeOrigin::root(), 10, true));
		assert_noop!(AuthorityMembership::nominate(RuntimeOrigin::signed(5), 10), BadOrigin);
		assert_ok!(Session::set_keys(
			RuntimeOrigin::signed(10),
			UintAuthorityId(10).into(),
			vec![]
		));
		assert_ok!(AuthorityMembership::nominate(RuntimeOrigin::root(), 10));
		assert_eq!(AuthorityMembership::member(), vec![1u64, 2u64, 3u64, 10u64]);
		assert_eq!(AuthorityMembership::incoming(), vec![10]);

		// Member 10 should be **effectively** in the authorities set in 2 sessions
		run_to_block(10);
		assert_eq!(Session::current_index(), 2);
		assert_eq!(Session::validators(), vec![1, 2, 3, 10]);
		assert_ok!(AuthorityMembership::remove(RuntimeOrigin::root(), 10));
		assert_eq!(AuthorityMembership::member(), vec![1u64, 2u64, 3u64]);
		assert_eq!(AuthorityMembership::outgoing(), vec![10]);

		run_to_block(15);
		assert_eq!(Session::current_index(), 3);
		assert_eq!(Session::validators(), vec![1, 2, 3, 10]);
		assert_eq!(Session::queued_keys().len(), 3);

		run_to_block(20);
		assert_eq!(Session::current_index(), 4);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
	});
}

/// tests go_online with a removed member
#[test]
fn test_go_online_with_a_removed_authority_member() {
	new_test_ext().execute_with(|| {
		run_to_block(1);

		assert_ok!(NetworkMembership::nominate(RuntimeOrigin::root(), 10, true));
		assert_noop!(AuthorityMembership::nominate(RuntimeOrigin::signed(5), 10), BadOrigin);
		assert_ok!(Session::set_keys(
			RuntimeOrigin::signed(10),
			UintAuthorityId(10).into(),
			vec![]
		));
		assert_ok!(AuthorityMembership::nominate(RuntimeOrigin::root(), 10));
		assert_eq!(AuthorityMembership::member(), vec![1u64, 2u64, 3u64, 10u64]);
		assert_eq!(AuthorityMembership::incoming(), vec![10]);

		// Member 10 should be **effectively** in the authorities set in 2 sessions
		run_to_block(10);
		assert_eq!(Session::current_index(), 2);
		assert_eq!(Session::validators(), vec![1, 2, 3, 10]);
		assert_ok!(AuthorityMembership::remove(RuntimeOrigin::root(), 10));
		assert_eq!(AuthorityMembership::member(), vec![1u64, 2u64, 3u64]);
		assert_eq!(AuthorityMembership::outgoing(), vec![10]);

		assert_err!(
			AuthorityMembership::go_online(RuntimeOrigin::signed(10)),
			Error::<Test>::MemberNotFound
		);
	});
}
