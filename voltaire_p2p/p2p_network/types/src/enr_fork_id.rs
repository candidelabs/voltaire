// use crate::Epoch;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

/// Specifies a fork which allows nodes to identify each other on the network. This fork is used in
/// a nodes local ENR.
///
/// Spec v0.11
#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone,
    PartialEq,
    Default,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
)]
pub struct EnrForkId {
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub fork_digest: [u8; 4],
    // #[serde(with = "serde_utils::bytes_4_hex")]
    // pub next_fork_version: [u8; 4],
    // pub next_fork_epoch: Epoch,
}

