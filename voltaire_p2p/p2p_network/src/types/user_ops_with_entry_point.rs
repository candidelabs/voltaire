
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

use ssz_types::typenum::U1000000;
use ethereum_types::U256;
use ethereum_types::Address;
use crate::rpc::methods::MaxOpsPerRequest;

type MaxCallDataSize = U1000000;
pub const MAX_CONTRACT_SIZE: usize = 24576;


#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    // arbitrary::Arbitrary,
)]
#[ssz(struct_behaviour = "container")]
pub struct UserOperation {
    /// The account making the operation.
    pub sender: Address,
    /// Anti-replay parameter (see "Semi-abstracted Nonce Support" ).
    pub nonce: U256,
    /// The initCode of the account (needed if and only if the account is not yet on-chain and needs to be created).
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub initCode: VariableList<u8, MaxCallDataSize>,
    /// The data to pass to the `sender` during the main execution call.
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub callData: VariableList<u8, MaxCallDataSize>,
    /// The amount of gas to allocate the main execution call.
    pub callGasLimit: U256,
    /// The amount of gas to allocate for the verification step.
    pub verificationGasLimit: U256,
    /// The amount of gas to pay for to compensate the bundler for pre-verification execution, calldata and any gas overhead that can't be tracked on-chain.
    pub preVerificationGas: U256,
    /// Maximum fee per gas.
    pub maxFeePerGas: U256,
    ///  Maximum priority fee per gas.
    pub maxPriorityFeePerGas: U256,
    /// Address of paymaster sponsoring the transaction, followed by extra data to send to the paymaster (empty for self-sponsored transaction).
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub paymasterAndData: VariableList<u8, MaxCallDataSize>,
    /// Data passed into the account along with the nonce during the verification step.
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub signature: VariableList<u8, MaxCallDataSize>,
}

/// A Validators signed aggregate proof to publish on the `beacon_aggregate_and_proof`
/// gossipsub topic.
///
/// Spec v0.12.1
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
)]
pub struct VerifiedUserOperation {
    /// The entrypoint contract address.
    pub entry_point: Address,
    //// The block where the useroperations are verified.
    pub verified_at_block_hash: U256,
    /// The user operations.
    pub user_operations: VariableList<UserOperation, MaxOpsPerRequest>,
}