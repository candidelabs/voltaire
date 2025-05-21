
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

use ssz_types::typenum::U1000000;
use ethereum_types::U256;
use ethereum_types::Address;
use ethereum_types::H256;

use super::optional::Optional;

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
pub struct UserOperationV06 {
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
pub struct VerifiedUserOperationV06 {
    /// The user operations.
    pub user_operation: UserOperationV06,
    /// The entrypoint contract address.
    pub entry_point_contract: Address,
    //// The block where the useroperations are verified.
    pub verified_at_block_hash: U256
}

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
pub struct Eip7702Auth {
    pub chain: U256,
    pub nonce: U256,
    pub address: Address,
    pub v: U256,
    pub r: H256,
    pub s: H256,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    // TreeHash,
    // arbitrary::Arbitrary,
)]
#[ssz(struct_behaviour = "container")]
pub struct UserOperationV07 {
    /// The account making the operation.
    pub sender: Address,
    /// Anti-replay parameter (see "Semi-abstracted Nonce Support" ).
    pub nonce: U256,
    /// Anti-replay parameter (see "Semi-abstracted Nonce Support" ).
    pub factory: Optional<Address>,
    /// Anti-replay parameter (see "Semi-abstracted Nonce Support" ).
    pub factoryData: Optional<VariableList<u8, MaxCallDataSize>>,
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
    /// Anti-replay parameter (see "Semi-abstracted Nonce Support" ).
    pub paymaster: Optional<Address>,
    /// Anti-replay parameter (see "Semi-abstracted Nonce Support" ).
    pub paymasterVerificationGasLimit: Optional<U256>,
    /// Anti-replay parameter (see "Semi-abstracted Nonce Support" ).
    pub paymasterPostOpGasLimit: Optional<U256>,
    /// Address of paymaster sponsoring the transaction, followed by extra data to send to the paymaster (empty for self-sponsored transaction).
    pub paymasterData: Optional<VariableList<u8, MaxCallDataSize>>,
    /// Data passed into the account along with the nonce during the verification step.
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub signature: VariableList<u8, MaxCallDataSize>,
    pub eip7702Auth: Optional<Eip7702Auth>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    // TreeHash,
)]
pub struct VerifiedUserOperationV07 {
    /// The user operations.
    pub user_operation: UserOperationV07,
    /// The entrypoint contract address.
    pub entry_point_contract: Address,
    //// The block where the useroperations are verified.
    pub verified_at_block_hash: U256
}