#![allow(clippy::non_snake_case)]

pub mod error;
mod globals;
mod pubsub;
mod subnet;
mod topics;
mod verified_useroperation;
mod optional;

pub type Enr = discv5::enr::Enr<discv5::enr::CombinedKey>;

pub use globals::NetworkGlobals;
pub use pubsub::{PubsubMessage, SnappyTransform};
pub use subnet::{Subnet, SubnetDiscovery};
pub use topics::{
    GossipEncoding, GossipKind,
    GossipTopic, 
};
pub use verified_useroperation::*;

use ethereum_types::H256;

pub type Hash256 = H256;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The provided bytes were an incorrect length.
    InvalidByteLength { got: usize, expected: usize },
    /// The provided secret key bytes were an incorrect length.
    InvalidSecretKeyLength { got: usize, expected: usize },
    /// The public key represents the point at infinity, which is invalid.
    InvalidInfinityPublicKey,
    /// The secret key is all zero bytes, which is invalid.
    InvalidZeroSecretKey,
}