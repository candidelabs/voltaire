pub mod error;
mod globals;
mod pubsub;
mod subnet;
mod topics;
mod user_ops_with_entry_point;


#[macro_use]
mod macros;


// pub type PublicKey = GenericPublicKey<milagro_bls::PublicKey>;
// pub type PublicKeyBytes = GenericPublicKeyBytes<PublicKey>;
// use types::{BitVector, EthSpec};

pub type MempoolNetsBitfield<T> = BitVector<<T as EthSpec>::MempoolNetsBitfieldLength>;
pub type EnrSyncCommitteeBitfield<T> = BitVector<<T as EthSpec>::SyncCommitteeSubnetCount>;

pub type Enr = discv5::enr::Enr<discv5::enr::CombinedKey>;

pub use globals::NetworkGlobals;
pub use pubsub::{PubsubMessage, SnappyTransform};
use ssz_types::BitVector;
pub use subnet::{Subnet, SubnetDiscovery};
// pub use sync_state::{BackFillState, SyncState};
pub use topics::{
    // core_topics_to_subscribe, fork_core_topics, 
    subnet_from_topic_hash, GossipEncoding, GossipKind,
    GossipTopic, 
    //LIGHT_CLIENT_GOSSIP_TOPICS,
};
pub use user_ops_with_entry_point::*;

use ethereum_types::{H160, H256};
use types::eth_spec::EthSpec;

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