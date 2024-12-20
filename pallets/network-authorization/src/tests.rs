#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_ok, assert_err};
    use sp_runtime::DispatchResult;

    pub struct ExtBuilder;

    impl ExtBuilder {
        fn build() -> sp_io::TestExternalities {
            sp_io::TestExternalities::new(Default::default())
        }
    }

    #[test]
    fn test_peer_id_too_long() {
        ExtBuilder::build().execute_with(|| {
            let long_peer_id = vec![0u8; 65]; // Assuming 64 is the max allowed length

            let result = Pallet::<Test>::authorize_network(long_peer_id);

            assert_err!(result, Error::<Test>::PeerIdTooLong);
        });
    }
}
