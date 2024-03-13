use ethereum_types::H256;
use p2p_voltaire_network::rpc::{StatusMessage, methods::MaxOpsPerRequest};
use ssz_types::{typenum::U32, FixedVector, VariableList};

/// Trait to produce a `StatusMessage` representing the state of the given `beacon_chain`.
///
/// NOTE: The purpose of this is simply to obtain a `StatusMessage` from the `BeaconChain` without
/// polluting/coupling the type with RPC concepts.
pub trait ToStatusMessage {
    fn status_message(&self) -> StatusMessage;
}

/// Build a `StatusMessage` representing the state of the given `beacon_chain`.
pub(crate) fn status_message(chain_id: u64, block_hash: H256,
    block_number: u64) -> StatusMessage {   
    StatusMessage { 
        chain_id,
        block_hash,
        block_number,
    }
}
