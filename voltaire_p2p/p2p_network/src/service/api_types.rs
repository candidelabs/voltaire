use libp2p::swarm::ConnectionId;
use types::eth_spec::EthSpec;


use crate::rpc::{
    methods::{
        RPCCodedResponse, RPCResponse, ResponseTermination, StatusMessage,
        PooledUserOpHashes,PooledUserOpsByHash, PooledUserOpHashesRequest, PooledUserOpsByHashRequest
    },
    OutboundRequest, SubstreamId,
};

/// Identifier of requests sent by a peer.
pub type PeerRequestId = (ConnectionId, SubstreamId);

/// Identifier of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestId<AppReqId> {
    Application(AppReqId),
    Internal,
}

/// The type of RPC requests the Behaviour informs it has received and allows for sending.
///
// NOTE: This is an application-level wrapper over the lower network level requests that can be
//       sent. The main difference is the absence of the Ping, Metadata and Goodbye protocols, which don't
//       leave the Behaviour. For all protocols managed by RPC see `RPCRequest`.
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    /// A Status message.
    Status(StatusMessage),
    // /// A blocks by range request.
    PooledUserOpHashes(PooledUserOpHashesRequest),
    // /// A request blocks root request.
    PooledUserOpsByHash(PooledUserOpsByHashRequest),
}

impl<TSpec: EthSpec> std::convert::From<Request> for OutboundRequest<TSpec> {
    fn from(req: Request) -> OutboundRequest<TSpec> {
        match req {
            Request::PooledUserOpHashes(r) => OutboundRequest::PooledUserOpHashes(r),
            Request::PooledUserOpsByHash(r) => OutboundRequest::PooledUserOpsByHash(r),
            Request::Status(s) => OutboundRequest::Status(s),
        }
    }
}

/// The type of RPC responses the Behaviour informs it has received, and allows for sending.
///
// NOTE: This is an application-level wrapper over the lower network level responses that can be
//       sent. The main difference is the absense of Pong and Metadata, which don't leave the
//       Behaviour. For all protocol reponses managed by RPC see `RPCResponse` and
//       `RPCCodedResponse`.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// A Status message.
    Status(StatusMessage),
    /// A response to a get PooledUserOpHashes request.
    PooledUserOpHashes(Option<PooledUserOpHashes>),
    /// A response to a get PooledUserOpsByHash request.
    PooledUserOpsByHash(Option<PooledUserOpsByHash>),
}

impl std::convert::From<Response> for RPCCodedResponse {
    fn from(resp: Response) -> RPCCodedResponse {
        match resp {
            Response::PooledUserOpHashes(r) => match r {
                Some(b) => RPCCodedResponse::Success(RPCResponse::PooledUserOpHashes(b)),
                None => RPCCodedResponse::StreamTermination(ResponseTermination::PooledUserOpHashes),
            },
            Response::PooledUserOpsByHash(r) => match r {
                Some(b) => RPCCodedResponse::Success(RPCResponse::PooledUserOpsByHash(b)),
                None => RPCCodedResponse::StreamTermination(ResponseTermination::PooledUserOpsByHash),
            },
            Response::Status(s) => RPCCodedResponse::Success(RPCResponse::Status(s)),
        }
    }
}

impl<AppReqId: std::fmt::Debug> slog::Value for RequestId<AppReqId> {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        match self {
            RequestId::Internal => slog::Value::serialize("Behaviour", record, key, serializer),
            RequestId::Application(ref id) => {
                slog::Value::serialize(&format_args!("{:?}", id), record, key, serializer)
            }
        }
    }
}
