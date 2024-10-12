use super::codec::OutboundCodec;
use super::methods::*;
use super::protocol::ProtocolId;
use super::protocol::SupportedProtocol;
use super::RPCError;
use crate::rpc::protocol::Encoding;
use crate::rpc::{
    codec::{base::BaseOutboundCodec, ssz_snappy::SSZSnappyOutboundCodec},
    methods::ResponseTermination,
};
use futures::future::BoxFuture;
use futures::prelude::{AsyncRead, AsyncWrite};
use futures::{FutureExt, SinkExt};
use libp2p::core::{OutboundUpgrade, UpgradeInfo};
use tokio_util::{
    codec::Framed,
    compat::{Compat, FuturesAsyncReadCompatExt},
};
// use types::{EthSpec, ForkContext};
/* Outbound request */

// Combines all the RPC requests into a single enum to implement `UpgradeInfo` and
// `OutboundUpgrade`

#[derive(Debug, Clone)]
pub struct OutboundRequestContainer {
    pub req: OutboundRequest,
    // pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutboundRequest {
    Status(StatusMessage),
    Goodbye(GoodbyeReason),
    PooledUserOpHashes(PooledUserOpHashesRequest),
    PooledUserOpsByHash(PooledUserOpsByHashRequest),
    Ping(Ping),
    MetaData(MetadataRequest),
}

impl UpgradeInfo for OutboundRequestContainer {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    // add further protocols as we support more encodings/versions
    fn protocol_info(&self) -> Self::InfoIter {
        self.req.supported_protocols()
    }
}

/// Implements the encoding per supported protocol for `RPCRequest`.
impl OutboundRequest {
    pub fn supported_protocols(&self) -> Vec<ProtocolId> {
        match self {
            // add more protocols when versions/encodings are supported
            OutboundRequest::Status(_) => vec![ProtocolId::new(
                SupportedProtocol::StatusV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::Goodbye(_) => vec![ProtocolId::new(
                SupportedProtocol::GoodbyeV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::PooledUserOpHashes(_) => vec![ProtocolId::new(
                SupportedProtocol::PooledUserOpHashesV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::PooledUserOpsByHash(_) => vec![ProtocolId::new(
                SupportedProtocol::PooledUserOpsByHashV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::Ping(_) => vec![ProtocolId::new(
                SupportedProtocol::PingV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::MetaData(_) => vec![
                // ProtocolId::new(SupportedProtocol::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::MetaDataV1, Encoding::SSZSnappy),
            ],
        }
    }
    /* These functions are used in the handler for stream management */

    /// Number of responses expected for this request.
    pub fn expected_responses(&self) -> u64 {
        match self {
            OutboundRequest::Status(_) => 1,
            OutboundRequest::Goodbye(_) => 0,
            OutboundRequest::PooledUserOpHashes(req) => 10,
            OutboundRequest::PooledUserOpsByHash(req) => 10,
            OutboundRequest::Ping(_) => 1,
            OutboundRequest::MetaData(_) => 1,
        }
    }

    /// Gives the corresponding `SupportedProtocol` to this request.
    pub fn versioned_protocol(&self) -> SupportedProtocol {
        match self {
            OutboundRequest::Status(_) => SupportedProtocol::StatusV1,
            OutboundRequest::Goodbye(_) => SupportedProtocol::GoodbyeV1,
            OutboundRequest::PooledUserOpHashes(_) => SupportedProtocol::PooledUserOpHashesV1,
            OutboundRequest::PooledUserOpsByHash(_) => SupportedProtocol::PooledUserOpsByHashV1,
            OutboundRequest::Ping(_) => SupportedProtocol::PingV1,
            OutboundRequest::MetaData(req) => SupportedProtocol::MetaDataV1,
        }
    }

    /// Returns the `ResponseTermination` type associated with the request if a stream gets
    /// terminated.
    pub fn stream_termination(&self) -> ResponseTermination {
        match self {
            // this only gets called after `multiple_responses()` returns true. Therefore, only
            // variants that have `multiple_responses()` can have values.
            OutboundRequest::PooledUserOpHashes(_) => ResponseTermination::PooledUserOpHashes,
            OutboundRequest::PooledUserOpsByHash(_) => ResponseTermination::PooledUserOpsByHash,
            OutboundRequest::Status(_) => unreachable!(),
            OutboundRequest::Goodbye(_) => unreachable!(),
            OutboundRequest::Ping(_) => unreachable!(),
            OutboundRequest::MetaData(_) => unreachable!(),
        }
    }
}

/* RPC Response type - used for outbound upgrades */

/* Outbound upgrades */

pub type OutboundFramed<TSocket> = Framed<Compat<TSocket>, OutboundCodec>;

impl<TSocket> OutboundUpgrade<TSocket> for OutboundRequestContainer
where
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = OutboundFramed<TSocket>;
    type Error = RPCError;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, socket: TSocket, protocol: Self::Info) -> Self::Future {
        // convert to a tokio compatible socket
        let socket = socket.compat();
        let codec = match protocol.encoding {
            Encoding::SSZSnappy => {
                let ssz_snappy_codec = BaseOutboundCodec::new(SSZSnappyOutboundCodec::new(
                    protocol,
                    self.max_rpc_size,
                    // self.fork_context.clone(),
                ));
                OutboundCodec::SSZSnappy(ssz_snappy_codec)
            }
        };

        let mut socket = Framed::new(socket, codec);

        async {
            socket.send(self.req).await?;
            socket.close().await?;
            Ok(socket)
        }
        .boxed()
    }
}

impl std::fmt::Display for OutboundRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundRequest::Status(status) => write!(f, "Status Message: {}", status),
            OutboundRequest::Goodbye(reason) => write!(f, "Goodbye: {}", reason),
            OutboundRequest::PooledUserOpHashes(req) => write!(f, "Pooled UserOp Hashes: {}", req),
            OutboundRequest::PooledUserOpsByHash(req) => write!(f, "Pooled UserOps By Hash: {:?}", req),
            OutboundRequest::Ping(ping) => write!(f, "Ping: {}", ping.data),
            OutboundRequest::MetaData(_) => write!(f, "MetaData request"),
        }
    }
}
