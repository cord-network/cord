#![cfg(test)]

use frame_support::{parameter_types, traits::{GenesisBuild, OnFinalize, OnInitialize}};
use frame_system::{self as system, pallet_prelude::*};
use pallet_network_authorization as pallet;
use sp_core::H256;
use sp_runtime::{traits::{BlakeTwo256, IdentityLookup}};
use frame_support::dispatch::DispatchResult;

#[cfg(test)]
pub mod mock {
    use super::*;
    
    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumPeerIdLength: usize = 64;
    }

    pub struct MockRuntime;

    impl frame_system::Config for MockRuntime {
        type BaseCallFilter = ();
        type BlockNumber = u64;
        type Call = ();
        type DbWeight = ();
        type Event = ();
        type Origin = ();
        type PalletInfo = ();
        type AccountData = ();
        type AccountId = u64;
        type BlockHashCount = BlockHashCount;
        type BlockWeights = ();
        type BlockLength = ();
        type CallFilter = ();
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type Header = ();
        type Index = u64;
        type Lookup = IdentityLookup<u64>;
        type MaxConsumers = ();
    }

    impl pallet::Config for MockRuntime {}

    #[test]
    fn test_peer_id_too_long() {
        use frame_support::{assert_err};

        let ext = sp_io::TestExternalities::new_empty();

        ext.execute_with(|| {
            let long_peer_id = vec![0u8; 65]; // 65 bytes, assuming max length is 64
            
            let result = pallet::Pallet::<MockRuntime>::authorize_network(Origin::signed(1), long_peer_id);
            
            assert_err!(result, pallet::Error::<MockRuntime>::PeerIdTooLong);
        });
    }
}
