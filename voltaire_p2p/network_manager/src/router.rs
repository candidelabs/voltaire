//! This module handles incoming network messages.
//!
//! It routes the messages to appropriate services.
//! It handles requests at the application layer in its associated processor and directs
//! syncing-related responses to the Sync manager.
#![allow(clippy::unit_arg)]

use crate::error;
use crate::service::{NetworkMessage, RequestId};
use crate::status::status_message;
use futures::prelude::*;
use p2p_voltaire_network::rpc::*;
use p2p_voltaire_network::rpc::methods::{PooledUserOpHashes, PooledUserOpHashesRequest, PooledUserOpsByHash, PooledUserOpsByHashRequest};
use p2p_voltaire_network::{
    MessageId, NetworkGlobals, PeerId, PeerRequestId, PubsubMessage, Request, Response,
};

use slog::{debug, o, trace};
use slog::{error, warn};
use ssz_types::typenum::U32;
use ssz_types::FixedVector;
use types::eth_spec::EthSpec;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;


/// Handles messages from the network and routes them to the appropriate service to be handled.
pub struct Router {
    /// Access to the peer db and network information.
    network_globals: Arc<NetworkGlobals>,
    /// A network context to return and handle RPC requests.
    network: HandlerNetworkContext,
    /// The `Router` logger.
    log: slog::Logger,
}

/// Types of messages the router can receive.
#[derive(Debug)]
pub enum RouterMessage  {
    /// Peer has disconnected.
    PeerDisconnected(PeerId),
    /// An RPC request has been received.
    RPCRequestReceived {
        peer_id: PeerId,
        id: PeerRequestId,
        request: Request,
    },
    /// An RPC response has been received.
    RPCResponseReceived {
        peer_id: PeerId,
        request_id: RequestId,
        response: Response,
    },
    /// An RPC request failed
    RPCFailed {
        peer_id: PeerId,
        request_id: RequestId,
    },
    /// A gossip message has been received. The fields are: message id, the peer that sent us this
    /// message, the message itself and a bool which indicates if the message should be processed
    /// by the beacon chain after successful verification.
    PubsubMessage(MessageId, PeerId, PubsubMessage, bool),
    /// The peer manager has requested we re-status a peer.
    StatusPeer(PeerId),
    PooledUserOpHashesRequest(RequestId, PeerId, PooledUserOpHashesRequest),
    PooledUserOpsByHashRequest(RequestId, PeerId, PooledUserOpsByHashRequest),
}

impl Router {
    /// Initializes and runs the Router.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        network_globals: Arc<NetworkGlobals>,
        network_send: mpsc::UnboundedSender<NetworkMessage>,
        executor: task_executor::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<mpsc::UnboundedSender<RouterMessage>> {
        let message_handler_log = log.new(o!("service"=> "router"));
        trace!(message_handler_log, "Service starting");

        let (handler_send, handler_recv) = mpsc::unbounded_channel();

        let sync_logger = log.new(o!("service"=> "sync"));

        // generate the Message handler
        let mut handler = Router {
            network_globals,
            network: HandlerNetworkContext::new(network_send, log.clone()),
            log: message_handler_log,
        };

        // spawn handler task and move the message handler instance into the spawned thread
        executor.spawn(
            async move {
                debug!(log, "Network message router started");
                UnboundedReceiverStream::new(handler_recv)
                    .for_each(move |msg| future::ready(handler.handle_message(msg)))
                    .await;
            },
            "router",
        );

        Ok(handler_send)
    }

    /// Handle all messages incoming from the network service.
    fn handle_message(&mut self, message: RouterMessage) {
        match message {
            // we have initiated a connection to a peer or the peer manager has requested a
            // re-status
            RouterMessage::StatusPeer(peer_id) => {
                self.send_status(peer_id);
            }
            // A peer has disconnected
            RouterMessage::PeerDisconnected(peer_id) => {
                // self.send_to_sync(SyncMessage::Disconnect(peer_id));
            }
            RouterMessage::RPCRequestReceived {
                peer_id,
                id,
                request,
            } => {
                self.handle_rpc_request(peer_id, id, request);
            }
            RouterMessage::RPCResponseReceived {
                peer_id,
                request_id,
                response,
            } => {
                self.handle_rpc_response(peer_id, request_id, response);
            }
            RouterMessage::RPCFailed {
                peer_id,
                request_id,
            } => {
                self.on_rpc_error(peer_id, request_id);
            }
            RouterMessage::PubsubMessage(id, peer_id, gossip, should_process) => {
                self.handle_gossip(id, peer_id, gossip, should_process);
            }
            RouterMessage::PooledUserOpHashesRequest(id, peer_id, request) => {
                self.network.send_request(id, peer_id, Request::PooledUserOpHashes(request));
            }
            RouterMessage::PooledUserOpsByHashRequest(id, peer_id, request) => {
                self.network.send_request(id, peer_id, Request::PooledUserOpsByHash(request));
            }
        }
    }

    /* RPC - Related functionality */

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(&mut self, peer_id: PeerId, request_id: PeerRequestId, request: Request) {
        if !self.network_globals.peers.read().is_connected(&peer_id) {
            debug!(self.log, "Dropping request of disconnected peer"; "peer_id" => %peer_id, "request" => ?request);
            return;
        }
        match request {
            Request::Status(status_message) => {
                self.on_status_request(peer_id, request_id, status_message)
            }
            Request::PooledUserOpHashes(pooled_user_op_hashes_request) => {
                self.on_pooled_user_op_hashes_request(peer_id, request_id, pooled_user_op_hashes_request)
               
            },
            Request::PooledUserOpsByHash(pooled_user_ops_by_hash) => {
                self.on_pooled_user_ops_by_hash_request(peer_id, request_id, pooled_user_ops_by_hash)
            },
        }
    }

    /// An RPC response has been received from the network.
    fn handle_rpc_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        response: Response,
    ) {
        match response {
            Response::Status(status_message) => {
                debug!(self.log, "Received Status Response"; "peer_id" => %peer_id, 
                    "chain_id" => status_message.chain_id,
                    "block_hash" => std::str::from_utf8(&status_message.block_hash.to_vec()).unwrap(),
                    "block_number" => status_message.block_number,
                );
            }
            Response::PooledUserOpHashes(pooled_user_op_hashes) => { 
                self.on_pooled_user_op_hashes_response(
                    peer_id, 
                    request_id, 
                    pooled_user_op_hashes.unwrap()
                )
              
            },
            Response::PooledUserOpsByHash(pooled_user_ops_by_hash) => { 
                self.on_pooled_user_ops_by_hash_response(
                    peer_id, 
                    request_id,
                    pooled_user_ops_by_hash.unwrap()
                )
            },
        }
    }

    /// Handle RPC messages.
    /// Note: `should_process` is currently only useful for the `Attestation` variant.
    /// if `should_process` is `false`, we only propagate the message on successful verification,
    /// else, we propagate **and** import into the beacon chain.
    fn handle_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        gossip_message: PubsubMessage,
        should_process: bool,
    ) {

        // self.network.inform_network(NetworkMessage::SendGossibToBundler { peer_id,gossip_message } );

        // #[derive(
        //     Debug,
        //     Clone,
        //     PartialEq,
        //     Serialize,
        //     Deserialize,
        // )]
        // struct GossibMessageToSendToMainBundler {
        //     peer_id: String,
        //     useroperations_with_entrypoint: UserOperationsWithEntryPoint,
        // }
        // match gossip_message {
        //     PubsubMessage::UserOperationsWithEntryPoint(useroperations_with_entrypoint) =>{
        //         let message_to_send = GossibMessageToSendToMainBundler {
        //             peer_id:peer_id.to_string(), 
        //             useroperations_with_entrypoint:*useroperations_with_entrypoint
        //         };
        //         let serialized = serde_pickle::to_vec(&message_to_send, Default::default()).unwrap();
        //         let socket = Path::new(SOCKET_PATH);
        //         let mut stream = match UnixStream::connect(&socket) {
        //             Err(_) => panic!("server is not running"),
        //             Ok(stream) => stream,
        //         };

        //         let message_bytes = serialized.clone();
        //         let message_length = message_bytes.len() as u32;
        //         let mut message_length_as_bytes = [0;4];
        //         message_length_as_bytes.copy_from_slice(&message_length.to_le_bytes());
        //         let whole: Vec<u8> = message_length_as_bytes.iter().copied().chain(message_bytes.iter().copied()).collect();
        //         stream.write_all(&whole).unwrap();
        //     }
        // }
    }

    fn send_status(&mut self, peer_id: PeerId) {
        // let topics = self.network_globals.local_metadata.read().clone();
        let status_message = status_message(0, FixedVector::<u8, U32>::default(),0);

        // let supported_mempools_string:Vec<String> = status_message.supported_mempools.to_vec().iter().map(
        //     |mempool| std::str::from_utf8(&mempool.to_vec()).unwrap().to_string()
        // ).collect();
        // let supported_mempools_string_joined = supported_mempools_string.join(",");
        // debug!(self.log, "Sending Status Request"; "peer" => %peer_id, 
        //     "supported mempools" => &supported_mempools_string_joined
        // );

        self.network
            .send_processor_request(peer_id, Request::Status(status_message));
    }

    /// An error occurred during an RPC request. The state is maintained by the sync manager, so
    /// this function notifies the sync manager of the error.
    pub fn on_rpc_error(&mut self, peer_id: PeerId, request_id: RequestId) {
        error!(self.log, "An error occurred during an RPC request"; "peer" => peer_id.to_string());
    }

    /// Handle a `Status` request.
    ///
    /// Processes the `Status` from the remote peer and sends back our `Status`.
    pub fn on_status_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        status: StatusMessage,
    ) {
        debug!(self.log, "Received Status Request"; "peer_id" => %peer_id, &status);
        // let topics = self.network_globals.gossipsub_subscriptions.read().clone().iter().map(|topic| topic.clone().mempool_id).collect::<Vec<_>>();
        // Say status back.
        self.network.send_response(
            peer_id,
            Response::Status(status_message(0, FixedVector::<u8, U32>::default(),0)),
            request_id,
        );
    }

    pub fn on_pooled_user_op_hashes_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        pooled_user_op_hashes_request: PooledUserOpHashesRequest,
    ) {
        debug!(self.log, "Received PooledUserOpHashes Request"; "peer_id" => %peer_id);


        self.network.inform_network(NetworkMessage::PooledUserOpHashesRequestS {
            peer_id,
            request_id,
            pooled_user_op_hashes_request,
        })
    }

    pub fn on_pooled_user_op_hashes_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        pooled_user_op_hashes: PooledUserOpHashes,
    ) {
        debug!(self.log, "Received PooledUserOpHashes Response"; "peer_id" => %peer_id);

        self.network.inform_network(NetworkMessage::PooledUserOpHashesResponseS {
            peer_id,
            request_id,
            pooled_user_op_hashes,
        });
    }

    pub fn on_pooled_user_ops_by_hash_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        pooled_user_ops_by_hash_request: PooledUserOpsByHashRequest,
    ) {
        debug!(self.log, "Received PooledUserOpsByHash Request"; "peer_id" => %peer_id);

        self.network.inform_network(NetworkMessage::PooledUserOpsByHashRequestS {
            peer_id,
            request_id,
            pooled_user_ops_by_hash_request,
        });
    }

    pub fn on_pooled_user_ops_by_hash_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        pooled_user_ops_by_hash: PooledUserOpsByHash,
    ) {
        debug!(self.log, "Received PooledUserOpsByHash Response"; "peer_id" => %peer_id);

        self.network.inform_network(NetworkMessage::PooledUserOpsByHashResponseS {
            peer_id,
            request_id,
            pooled_user_ops_by_hash,
        });
    }
}

/// Wraps a Network Channel to employ various RPC related network functionality for the
/// processor.
#[derive(Clone)]
pub struct HandlerNetworkContext  {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage>,
    /// Logger for the `NetworkContext`.
    log: slog::Logger,
}

impl  HandlerNetworkContext {
    pub fn new(network_send: mpsc::UnboundedSender<NetworkMessage>, log: slog::Logger) -> Self {
        Self { network_send, log }
    }

    /// Sends a message to the network task.
    pub fn inform_network(&mut self, msg: NetworkMessage) {
        self.network_send.send(msg).unwrap_or_else(
            |e| warn!(self.log, "Could not send message to the network service"; "error" => %e),
        )
    }

    /// Sends a request to the network task.
    pub fn send_processor_request(&mut self, peer_id: PeerId, request: Request) {
        self.inform_network(NetworkMessage::SendRequest {
            peer_id,
            request_id: RequestId::Router,
            request,
        })
    }

    /// Sends a request to the network task.
    pub fn send_request(&mut self,request_id:RequestId,  peer_id: PeerId, request: Request) {
        self.inform_network(NetworkMessage::SendRequest {
            peer_id,
            request_id,
            request,
        })
    }

    /// Sends a response to the network task.
    pub fn send_response(&mut self, peer_id: PeerId, response: Response, id: PeerRequestId) {
        self.inform_network(NetworkMessage::SendResponse {
            peer_id,
            id,
            response,
        })
    }
}