#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
	use frame_system::{self as system, pallet_prelude::*};
	use sp_std::vec::Vec;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::error]
	pub enum Error<T> {
		PeerIdTooLong,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(10_000)]
		pub fn authorize_network(origin: OriginFor<T>, peer_id: Vec<u8>) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			if peer_id.len() > 64 {
				return Err(Error::<T>::PeerIdTooLong.into());
			}

			Ok(())
		}
	}
}
