use p2p_voltaire_network::rpc::{StatusMessage, methods::MaxOpsPerRequest};
use ssz_types::VariableList;

use crate::FV46;
/// Trait to produce a `StatusMessage` representing the state of the given `beacon_chain`.
///
/// NOTE: The purpose of this is simply to obtain a `StatusMessage` from the `BeaconChain` without
/// polluting/coupling the type with RPC concepts.
pub trait ToStatusMessage {
    fn status_message(&self) -> StatusMessage;
}

/// Build a `StatusMessage` representing the state of the given `beacon_chain`.
pub(crate) fn status_message(topics: Vec<String>) -> StatusMessage {   
    let topics_as_bytes = topics.iter().map(
        |topic| FV46::new(topic.as_bytes().to_vec()).unwrap()
    ).collect::<Vec<_>>();

    let message:VariableList<FV46, MaxOpsPerRequest> = VariableList::<FV46, MaxOpsPerRequest>::from(topics_as_bytes);
    StatusMessage {
        supported_mempools: message,
    }
}
