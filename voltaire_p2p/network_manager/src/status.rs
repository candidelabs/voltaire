use ethereum_types::H256;
use p2p_voltaire_network::rpc::StatusMessage;

/// Build a `StatusMessage`.
pub(crate) fn status_message(chain_id: u64, block_hash: H256,
    block_number: u64) -> StatusMessage {   
    StatusMessage { 
        chain_id,
        block_hash,
        block_number,
    }
}
