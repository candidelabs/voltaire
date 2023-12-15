//! Available RPC methods types and ids.

use crate::types::{Hash256, MempoolNetsBitfield, UserOperation};

use regex::bytes::Regex;
use serde::{Serialize, Deserialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{U1024, U256, U46,U4096, U66, U34, U32, U33},
    VariableList, FixedVector,
};
use types::eth_spec::EthSpec;
use std::{marker::PhantomData, fmt::{Debug, self}};
use std::ops::Deref;
use strum::IntoStaticStr;


/// Maximum number of blocks in a single request.
pub type MaxRequestBlocks = U1024;
pub const MAX_REQUEST_BLOCKS: u64 = 1024;

/// Maximum number of Useroperations per request.
pub type MaxOpsPerRequest = U4096;
pub const MAX_OPS_PER_REQUEST: u64 = 4096;

/// Maximum length of error message.
pub type MaxErrorLen = U256;
pub const MAX_ERROR_LEN: u64 = 256;

/// Wrapper over SSZ List to represent error message in rpc responses.
#[derive(Debug, Clone)]
pub struct ErrorType(pub VariableList<u8, MaxErrorLen>);

impl From<String> for ErrorType {
    fn from(s: String) -> Self {
        Self(VariableList::from(s.as_bytes().to_vec()))
    }
}

impl From<&str> for ErrorType {
    fn from(s: &str) -> Self {
        Self(VariableList::from(s.as_bytes().to_vec()))
    }
}

impl Deref for ErrorType {
    type Target = VariableList<u8, MaxErrorLen>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToString for ErrorType {
    fn to_string(&self) -> String {
        #[allow(clippy::invalid_regex)]
        let re = Regex::new("\\p{C}").expect("Regex is valid");
        String::from_utf8_lossy(&re.replace_all(self.0.deref(), &b""[..])).to_string()
    }
}

/* Request/Response data structures for RPC methods */

/* Requests */

/// The STATUS request/response handshake message.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
#[ssz(struct_behaviour = "transparent")]
pub struct StatusMessage {
    /// The fork version of the chain we are broadcasting.
    // pub supported_mempools: VariableList<VariableList<u8, MaxOpsPerRequest>,MaxOpsPerRequest>
    pub supported_mempools: VariableList<FixedVector<u8, U46>, MaxOpsPerRequest>
}

/// The PING request/response message.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct Ping {
    /// The metadata sequence number.
    pub data: u64,
}

/// The METADATA request structure.
// #[superstruct(
//     variants(V1, V2),
//     variant_attributes(derive(Clone, Debug, PartialEq, Serialize),)
// )]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MetadataRequest<T: EthSpec> {
    _phantom_data: PhantomData<T>,
}

impl<T: EthSpec> MetadataRequest<T> {
    pub fn new() -> Self {
        MetadataRequest {
            _phantom_data: PhantomData,
        }
    }
}

/// The METADATA response structure.
// #[superstruct(
//     variants(V1, V2),
//     variant_attributes(
//         derive(Encode, Decode, Clone, Debug, PartialEq, Serialize),
//         serde(bound = "T: EthSpec", deny_unknown_fields),
//     )
// )]
#[derive(Encode, Decode, Clone, Debug, PartialEq, Serialize)]
#[serde(bound = "T: EthSpec")]
pub struct MetaData<T: EthSpec> {
    /// A sequential counter indicating when data gets modified.
    pub seq_number: u64,
    /// The persistent mempool subnet bitfield.
    pub mempool_nets: MempoolNetsBitfield<T>,
}

impl<T: EthSpec> MetaData<T> {
    /// Returns a MetaData response from self.
    pub fn metadata(&self) -> Self {
       self.clone()
    }
}

/// The reason given for a `Goodbye` message.
///
/// Note: any unknown `u64::into(n)` will resolve to `Goodbye::Unknown` for any unknown `n`,
/// however `GoodbyeReason::Unknown.into()` will go into `0_u64`. Therefore de-serializing then
/// re-serializing may not return the same bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum GoodbyeReason {
    /// This node has shutdown.
    ClientShutdown = 1,

    /// Incompatible networks.
    IrrelevantNetwork = 2,

    /// Error/fault in the RPC.
    Fault = 3,

    ///  Not being able to verify a network.
    UnableToVerifyNetwork = 128,

    /// The node has too many connected peers.
    TooManyPeers = 129,

    /// Scored poorly.
    BadScore = 250,

    /// The peer is banned
    Banned = 251,

    /// The IP address the peer is using is banned.
    BannedIP = 252,

    /// Unknown reason.
    Unknown = 0,
}

impl From<u64> for GoodbyeReason {
    fn from(id: u64) -> GoodbyeReason {
        match id {
            1 => GoodbyeReason::ClientShutdown,
            2 => GoodbyeReason::IrrelevantNetwork,
            3 => GoodbyeReason::Fault,
            128 => GoodbyeReason::UnableToVerifyNetwork,
            129 => GoodbyeReason::TooManyPeers,
            250 => GoodbyeReason::BadScore,
            251 => GoodbyeReason::Banned,
            252 => GoodbyeReason::BannedIP,
            _ => GoodbyeReason::Unknown,
        }
    }
}

impl From<GoodbyeReason> for u64 {
    fn from(reason: GoodbyeReason) -> u64 {
        reason as u64
    }
}

impl ssz::Encode for GoodbyeReason {
    fn is_ssz_fixed_len() -> bool {
        <u64 as ssz::Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        0_u64.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let conv: u64 = self.clone().into();
        conv.ssz_append(buf)
    }
}

impl ssz::Decode for GoodbyeReason {
    fn is_ssz_fixed_len() -> bool {
        <u64 as ssz::Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        u64::from_ssz_bytes(bytes).map(|n| n.into())
    }
}

/// The STATUS request/response handshake message.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PooledUserOpHashes {
    /// A sequential counter indicating when data gets modified.
    pub more_flag: u64,

    /// The fork version of the chain we are broadcasting.
    pub hashes: VariableList<FixedVector<u8, U32>, MaxOpsPerRequest>,
}

/// Request a number of beacon block roots from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PooledUserOpHashesRequest {
    /// The starting slot to request blocks.
    pub mempool: FixedVector<u8, U46>,
    // pub mempool: Hash256,

    /// A sequential counter indicating when data gets modified.
    pub offset: u64,
}

impl PooledUserOpHashesRequest {
    pub fn new(mempool: FixedVector<u8, U46>, offset: u64) -> Self {
        Self{
            mempool,
            offset,
        }
    }
}

/// The STATUS request/response handshake message.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[ssz(struct_behaviour = "transparent")]
pub struct PooledUserOpsByHash {
    /// The fork version of the chain we are broadcasting.
    pub list: VariableList<UserOperation, MaxOpsPerRequest>,
}

/// Request a number of beacon block bodies from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PooledUserOpsByHashRequest {
    /// The list of beacon block bodies being requested.
    pub hashes: VariableList<FixedVector<u8, U32>, MaxOpsPerRequest>,
}

impl PooledUserOpsByHashRequest {
    pub fn new(hashes: VariableList<FixedVector<u8, U32>, MaxOpsPerRequest>) -> Self {
        Self { hashes }
    }
}

/* RPC Handling and Grouping */
// Collection of enums and structs used by the Codecs to encode/decode RPC messages

#[derive(Debug, Clone, PartialEq)]
pub enum RPCResponse<T: EthSpec> {
    /// A HELLO message.
    Status(StatusMessage),

    /// A PooledUserOpHashes response to a PooledUserOpHashes request.
    PooledUserOpHashes(PooledUserOpHashes),

    /// A PooledUserOpsByHash response to a PooledUserOpsByHash request.
    PooledUserOpsByHash(PooledUserOpsByHash),

    /// A PONG response to a PING request.
    Pong(Ping),

    /// A response to a META_DATA request.
    MetaData(MetaData<T>),
}

/// Indicates which response is being terminated by a stream termination response.
#[derive(Debug, Clone)]
pub enum ResponseTermination {
    /// PooledUserOpHashes stream termination.
    PooledUserOpHashes,

    /// PooledUserOpsByHash stream termination.
    PooledUserOpsByHash,
}

/// The structured response containing a result/code indicating success or failure
/// and the contents of the response
#[derive(Debug, Clone)]
pub enum RPCCodedResponse<T: EthSpec> {
    /// The response is a successful.
    Success(RPCResponse<T>),

    Error(RPCResponseErrorCode, ErrorType),

    /// Received a stream termination indicating which response is being terminated.
    StreamTermination(ResponseTermination),
}

/// The code assigned to an erroneous `RPCResponse`.
#[derive(Debug, Clone, Copy, PartialEq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RPCResponseErrorCode {
    RateLimited,
    InvalidRequest,
    ServerError,
    /// Error spec'd to indicate that a peer does not have blocks on a requested range.
    ResourceUnavailable,
    Unknown,
}

impl<T: EthSpec> RPCCodedResponse<T> {
    /// Used to encode the response in the codec.
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            RPCCodedResponse::Success(_) => Some(0),
            RPCCodedResponse::Error(code, _) => Some(code.as_u8()),
            RPCCodedResponse::StreamTermination(_) => None,
        }
    }

    /// Tells the codec whether to decode as an RPCResponse or an error.
    pub fn is_response(response_code: u8) -> bool {
        matches!(response_code, 0)
    }

    /// Builds an RPCCodedResponse from a response code and an ErrorMessage
    pub fn from_error(response_code: u8, err: ErrorType) -> Self {
        let code = match response_code {
            1 => RPCResponseErrorCode::InvalidRequest,
            2 => RPCResponseErrorCode::ServerError,
            3 => RPCResponseErrorCode::ResourceUnavailable,
            139 => RPCResponseErrorCode::RateLimited,
            _ => RPCResponseErrorCode::Unknown,
        };
        RPCCodedResponse::Error(code, err)
    }

    /// Specifies which response allows for multiple chunks for the stream handler.
    pub fn multiple_responses(&self) -> bool {
        match self {
            RPCCodedResponse::Success(resp) => match resp {
                RPCResponse::Status(_) => false,
                RPCResponse::PooledUserOpHashes(_) => false,
                RPCResponse::PooledUserOpsByHash(_) => false,
                RPCResponse::Pong(_) => false,
                RPCResponse::MetaData(_) => false,
            },
            RPCCodedResponse::Error(_, _) => true,
            // Stream terminations are part of responses that have chunks
            RPCCodedResponse::StreamTermination(_) => true,
        }
    }

    /// Returns true if this response always terminates the stream.
    pub fn close_after(&self) -> bool {
        !matches!(self, RPCCodedResponse::Success(_))
    }
}

impl RPCResponseErrorCode {
    fn as_u8(&self) -> u8 {
        match self {
            RPCResponseErrorCode::InvalidRequest => 1,
            RPCResponseErrorCode::ServerError => 2,
            RPCResponseErrorCode::ResourceUnavailable => 3,
            RPCResponseErrorCode::Unknown => 255,
            RPCResponseErrorCode::RateLimited => 139,
        }
    }
}

use super::Protocol;
impl<T: EthSpec> RPCResponse<T> {
    pub fn protocol(&self) -> Protocol {
        match self {
            RPCResponse::Status(_) => Protocol::Status,
            RPCResponse::PooledUserOpHashes(_) => Protocol::PooledUserOpHashes,
            RPCResponse::PooledUserOpsByHash(_) => Protocol::PooledUserOpsByHash,
            RPCResponse::Pong(_) => Protocol::Ping,
            RPCResponse::MetaData(_) => Protocol::MetaData,
        }
    }
}

impl std::fmt::Display for RPCResponseErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            RPCResponseErrorCode::InvalidRequest => "The request was invalid",
            RPCResponseErrorCode::ResourceUnavailable => "Resource unavailable",
            RPCResponseErrorCode::ServerError => "Server error occurred",
            RPCResponseErrorCode::Unknown => "Unknown error occurred",
            RPCResponseErrorCode::RateLimited => "Rate limited",
        };
        f.write_str(repr)
    }
}


impl std::fmt::Display for StatusMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let supported_mempools_string:Vec<String> = self.supported_mempools.to_vec().iter().map(
            |mempool| std::str::from_utf8(&mempool.to_vec()).unwrap().to_string()
        ).collect();
        let supported_mempools_string_joined = supported_mempools_string.join(",");
        write!(f, "Status Message: Supported mempools: {}", supported_mempools_string_joined)
    }
}

impl<T: EthSpec> std::fmt::Display for RPCResponse<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCResponse::Status(status) => write!(f, "{}", status),
            RPCResponse::PooledUserOpHashes(pooled_user_ops_hashes) => {
                write!(f, "PooledUserOpHashes: More Flag: {}, Hashes: {:?}", pooled_user_ops_hashes.more_flag, pooled_user_ops_hashes.hashes)
            }
            RPCResponse::PooledUserOpsByHash(pooled_user_ops_by_hash) => {
                write!(f, "PooledUserOpsByHash: List: {:?}", pooled_user_ops_by_hash.list)
            }
            RPCResponse::Pong(ping) => write!(f, "Pong: {}", ping.data),
            RPCResponse::MetaData(metadata) => write!(f, "Metadata: {}", metadata.seq_number),
        }
    }
}

impl<T: EthSpec> std::fmt::Display for RPCCodedResponse<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCCodedResponse::Success(res) => write!(f, "{}", res),
            RPCCodedResponse::Error(code, err) => write!(f, "{}: {}", code, err.to_string()),
            RPCCodedResponse::StreamTermination(_) => write!(f, "Stream Termination"),
        }
    }
}

impl std::fmt::Display for GoodbyeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoodbyeReason::ClientShutdown => write!(f, "Client Shutdown"),
            GoodbyeReason::IrrelevantNetwork => write!(f, "Irrelevant Network"),
            GoodbyeReason::Fault => write!(f, "Fault"),
            GoodbyeReason::UnableToVerifyNetwork => write!(f, "Unable to verify network"),
            GoodbyeReason::TooManyPeers => write!(f, "Too many peers"),
            GoodbyeReason::BadScore => write!(f, "Bad Score"),
            GoodbyeReason::Banned => write!(f, "Banned"),
            GoodbyeReason::BannedIP => write!(f, "BannedIP"),
            GoodbyeReason::Unknown => write!(f, "Unknown Reason"),
        }
    }
}

impl std::fmt::Display for PooledUserOpHashesRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Mempool: {:?}, Offset: {}",
            self.mempool,
            self.offset
        )
    }
}

impl std::fmt::Display for PooledUserOpsByHashRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Hashes: {:?}",
            self.hashes,
        )
    }
}

impl slog::KV for StatusMessage {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        use slog::Value;
        serializer.emit_arguments("supported_mempools", &format_args!("{:?}", self.supported_mempools))?;
        // Value::serialize(&self.supported_mempools, record, "supported_mempools", serializer)?;
        slog::Result::Ok(())
    }
}
