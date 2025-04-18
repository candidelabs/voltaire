use ssz_types::{FixedVector, typenum::U46};

#[macro_use]
extern crate lazy_static;

/// This crate provides the network server for Voltaire p2p.
pub mod error;
#[allow(clippy::mutable_key_type)] // PeerId in hashmaps are no longer permitted by clippy
pub mod service;

#[allow(clippy::mutable_key_type)] // PeerId in hashmaps are no longer permitted by clippy
mod metrics;
mod nat;

pub mod main_bundler;

pub type FV46 = FixedVector::<u8, U46>;

pub use p2p_voltaire_network::NetworkConfig;
pub use service::{
    NetworkMessage, NetworkReceivers, NetworkSenders, NetworkService//, ValidatorSubscriptionMessage,
};
