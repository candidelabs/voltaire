use crate::main_bundler::{listen_to_main_bundler,GossibMessageToSendToMainBundlerV07, GossibMessageToSendToMainBundlerV06, BundlerGossibRequest, MessageTypeToBundler, MessageTypeFromBundler, broadcast_and_listen_for_response_from_main_bundler, broadcast_to_main_bundler, PooledUserOpHashesAndPeerId};
use crate::status::status_message;
use ethereum_types::H256;
use p2p_voltaire_network::rpc::methods::{PooledUserOpHashes, PooledUserOpHashesRequest, PooledUserOpsByHash, PooledUserOpsByHashRequest, PooledUserOpsByHashV06, PooledUserOpsByHashV07};
use p2p_voltaire_network::rpc::StatusMessage;
use p2p_voltaire_network::{PeerId, NetworkGlobals, MessageId, NetworkEvent};
use crate::nat::EstablishedUPnPMappings;
use crate::{error, metrics};
use crate::NetworkConfig;
use futures::channel::mpsc::Sender;
use futures::prelude::*;
use p2p_voltaire_network::service::Network;
use p2p_voltaire_network::MessageAcceptance;
use p2p_voltaire_network::{
    rpc::{GoodbyeReason, RPCResponseErrorCode},
    PeerAction, PeerRequestId, PubsubMessage, ReportSource, Request, Response,
};


use slog::{debug, error, info, o, trace, warn};
use std::str::FromStr;
use std::{sync::Arc, time::Duration};
use strum::IntoStaticStr;
use task_executor::ShutdownReason;
use tokio::sync::mpsc;

/// The interval (in seconds) that various network metrics will update.
const METRIC_UPDATE_INTERVAL: u64 = 5;


/// Application level requests sent to the network.
#[derive(Debug, Clone, Copy)]
pub enum RequestId {
    FromMainBundler(u128),
    Router,
}

/// Types of messages that the network service can receive.
#[derive(Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum NetworkMessage  {
    /// Subscribes the beacon node to the core gossipsub topics. We do this when we are either
    /// synced or close to the head slot.
    SubscribeCoreTopics,
    /// Send an RPC request to the libp2p service.
    SendRequest {
        peer_id: PeerId,
        request: Request,
        request_id: RequestId,
    },
    /// Send a successful Response to the libp2p service.
    SendResponse {
        peer_id: PeerId,
        response: Response,
        id: PeerRequestId,
    },
    /// Sends an error response to an RPC request.
    SendErrorResponse {
        peer_id: PeerId,
        error: RPCResponseErrorCode,
        reason: String,
        id: PeerRequestId,
    },
    /// Publish a list of messages to the gossipsub protocol.
    Publish { 
        messages: Vec<PubsubMessage>,
        mempool_ids: Vec<String>
     },
    /// Validates a received gossipsub message. This will propagate the message on the network.
    ValidationResult {
        /// The peer that sent us the message. We don't send back to this peer.
        propagation_source: PeerId,
        /// The id of the message we are validating and propagating.
        message_id: MessageId,
        /// The result of the validation
        validation_result: MessageAcceptance,
    },
    /// Called if  UPnP managed to establish an external port mapping.
    UPnPMappingEstablished {
        /// The mappings that were established.
        mappings: EstablishedUPnPMappings,
    },
    /// Reports a peer to the peer manager for performing an action.
    ReportPeer {
        peer_id: PeerId,
        action: PeerAction,
        source: ReportSource,
        msg: &'static str,
    },
    /// Disconnect an ban a peer, providing a reason.
    GoodbyePeer {
        peer_id: PeerId,
        reason: GoodbyeReason,
        source: ReportSource,
    },
    /// Send an RPC request to the libp2p service.
    PooledUserOpHashesRequestMessageToAllPeers {
        pooled_user_op_hashes_request: PooledUserOpHashesRequest,
    },
    /// Send an RPC request to the libp2p service.
    PooledUserOpHashesRequestMessage {
        id: u128,
        peer_id: String,
        pooled_user_op_hashes_request: PooledUserOpHashesRequest,
    },
    /// Send an RPC request to the libp2p service.
    PooledUserOpsByHashRequestMessage {
        id: u128,
        peer_id: String,
        pooled_user_ops_by_hash_request: PooledUserOpsByHashRequest,
    },
    PooledUserOpHashesRequest{
        peer_id: PeerId,
        request_id: PeerRequestId,
        pooled_user_op_hashes_request: PooledUserOpHashesRequest,
    },
    PooledUserOpsByHashRequest{
        peer_id: PeerId,
        request_id: PeerRequestId,
        pooled_user_ops_by_hash_request: PooledUserOpsByHashRequest,
    },
    PooledUserOpHashesResponse{
        peer_id: PeerId,
        request_id: RequestId,
        pooled_user_op_hashes: PooledUserOpHashes,
    },
    PooledUserOpsByHashResponseV07{
        peer_id: PeerId,
        request_id: RequestId,
        pooled_user_ops_by_hash: PooledUserOpsByHashV07,
    },
    PooledUserOpsByHashResponseV06{
        peer_id: PeerId,
        request_id: RequestId,
        pooled_user_ops_by_hash: PooledUserOpsByHashV06,
    },
    Status{
        peer_id: PeerId,
        request_id: PeerRequestId,
    },
}

#[derive(Clone)]
pub struct NetworkSenders {
    pub network_send: mpsc::UnboundedSender<NetworkMessage>,
}

pub struct NetworkReceivers {
    pub network_recv: mpsc::UnboundedReceiver<NetworkMessage>,
}

impl NetworkSenders {
    pub fn new() -> (Self, NetworkReceivers) {
        let (network_send, network_recv) = mpsc::unbounded_channel::<NetworkMessage>();

        let senders = Self {
            network_send,
        };
        let receivers = NetworkReceivers {
            network_recv,
        };
        (senders, receivers)
    }

    pub fn network_send(&self) -> mpsc::UnboundedSender<NetworkMessage> {
        self.network_send.clone()
    }
}

/// Service that handles communication between internal services and the `p2p_voltaire_network` network service.
pub struct NetworkService {
    /// The underlying libp2p service that drives all the network interactions.
    libp2p: Network<RequestId>,
    /// The receiver channel for voltaire to communicate with the network service.
    network_recv: mpsc::UnboundedReceiver<NetworkMessage>,
    network: HandlerNetworkContext,
    /// A collection of global variables, accessible outside of the network service.
    network_globals: Arc<NetworkGlobals>,
    /// Stores potentially created UPnP mappings to be removed on shutdown. (TCP port and UDP
    /// ports).
    upnp_mappings: EstablishedUPnPMappings,
    /// Whether metrics are enabled or not.
    metrics_enabled: bool,
    /// A timer for updating various network metrics.
    metrics_update: tokio::time::Interval,
    /// The logger for the network service.
    log: slog::Logger,
}

impl NetworkService {
    #[allow(clippy::type_complexity)]
    pub async fn start(
        config: &NetworkConfig,
        executor: task_executor::TaskExecutor,
    ) -> error::Result<Arc<NetworkGlobals>> {
        let network_log = executor.log().clone();
        // build the channels for external comms
        let (network_senders, network_recievers) = NetworkSenders::new();

        // try and construct UPnP port mappings if required.
        if let Some(upnp_config) = crate::nat::UPnPConfig::from_config(config) {
            let upnp_log = network_log.new(o!("service" => "UPnP"));
            let upnp_network_send = network_senders.network_send();
            if config.upnp_enabled {
                executor.spawn_blocking(
                    move || {
                        crate::nat::construct_upnp_mappings(
                            upnp_config,
                            upnp_network_send,
                            upnp_log,
                        )
                    },
                    "UPnP",
                );
            }
        }

        // launch libp2p service
        let (libp2p, network_globals) =
            Network::new(executor.clone(), /*service_context,*/ config.clone(),&network_log).await?;

        // // Repopulate the DHT with stored ENR's if discovery is not disabled.
        // if !config.disable_discovery {
        //     let enrs_to_load = load_dht::<T::EthSpec, T::HotStore, T::ColdStore>(store.clone());
        //     debug!(
        //         network_log,
        //         "Loading peers into the routing table"; "peers" => enrs_to_load.len()
        //     );
        //     for enr in enrs_to_load {
        //         libp2p.add_enr(enr.clone());
        //     }
        // }

        // router task
        // let router_send = Router::spawn(
        //     network_globals.clone(),
        //     network_senders.network_send(),
        //     executor.clone(),
        //     network_log.clone(),
        // ).await.unwrap();

        // create a timer for updating network metrics
        let metrics_update = tokio::time::interval(Duration::from_secs(METRIC_UPDATE_INTERVAL));

        // // create a timer for updating gossipsub parameters
        // let gossipsub_parameter_update = tokio::time::interval(Duration::from_secs(60));

        let NetworkReceivers {
            network_recv,
            // validator_subscription_recv,
        } = network_recievers;
        let network = HandlerNetworkContext::new(network_senders.network_send(), network_log.clone());
        // create the network service and spawn the task
        let network_log = network_log.new(o!("service" => "network"));
        let network_service:NetworkService = NetworkService {
            libp2p,
            network_recv,
            // router_send,
            network,
            network_globals: network_globals.clone(),
            upnp_mappings: EstablishedUPnPMappings::default(),
            metrics_enabled: config.metrics_enabled,
            metrics_update,
            log: network_log,
        };

        network_service.spawn_service(executor, network_senders.network_send());
        
        Ok(network_globals)
    }


    // fn send_to_router(&mut self, msg: RouterMessage) {
    //     if let Err(mpsc::error::SendError(msg)) = self.router_send.send(msg) {
    //         // debug!(self.log, "Failed to send msg to router"; "msg" => ?msg);
    //         debug!(self.log, "Failed to send msg to router");
    //     }
    // }

    fn spawn_service(mut self, executor: task_executor::TaskExecutor, network_send: mpsc::UnboundedSender<NetworkMessage>){//} -> impl Future{
        let mut shutdown_sender = executor.shutdown_sender();
        
        let service_fut = async move {
            loop {
                tokio::select! {
                    request= listen_to_main_bundler(&self.log) => {
                        match request{
                            Ok(result)=>{
                                match result {
                                    MessageTypeFromBundler::GossibMessageFromBundlerV07(gossib_message) => {
                                        let pubsub_message = PubsubMessage::VerifiedUserOperationV07(
                                            Box::new(gossib_message.verified_useroperation)
                                        );
                                
                                        let _ = network_send.send(NetworkMessage::Publish { 
                                            messages: vec![pubsub_message],
                                            mempool_ids: gossib_message.topics,
                                        });
                                    },
                                    MessageTypeFromBundler::GossibMessageFromBundlerV06(gossib_message) => {
                                        let pubsub_message = PubsubMessage::VerifiedUserOperationV06(
                                            Box::new(gossib_message.verified_useroperation)
                                        );
                                
                                        let _ = network_send.send(NetworkMessage::Publish { 
                                            messages: vec![pubsub_message],
                                            mempool_ids: gossib_message.topics,
                                        });
                                    },
                                    MessageTypeFromBundler::PooledUserOpHashesRequestFromBundler(pooled_user_op_hashes_request_message)=>{

                                        if pooled_user_op_hashes_request_message.peer_id == "" {
                                            debug!(
                                                self.log,
                                                "Sending PooledUserOpHashes Request to all peers";
                                            );

                                            let _ = network_send.send(NetworkMessage::PooledUserOpHashesRequestMessageToAllPeers{ 
                                                pooled_user_op_hashes_request:pooled_user_op_hashes_request_message.pooled_user_op_hashes_request  
                                            });
                                        }else{
                                            debug!(self.log, "Sending PooledUserOpHashes Request"; 
                                                "peer" => %pooled_user_op_hashes_request_message.peer_id,
                                            );

                                            let _ = network_send.send(NetworkMessage::PooledUserOpHashesRequestMessage{
                                                    id: pooled_user_op_hashes_request_message.id.parse::<u128>().unwrap(),
                                                    peer_id: pooled_user_op_hashes_request_message.peer_id, 
                                                    pooled_user_op_hashes_request:pooled_user_op_hashes_request_message.pooled_user_op_hashes_request  
                                                }
                                            );
                                        }
                                    },
                                    MessageTypeFromBundler::PooledUserOpsByHashRequestFromBundler(pooled_user_ops_by_hash_request_message)=>{
                                        debug!(self.log, "Sending PooledUserOpsByHash Request"; 
                                            "peer" => %pooled_user_ops_by_hash_request_message.peer_id,
                                        );

                                        let _ = network_send.send(NetworkMessage::PooledUserOpsByHashRequestMessage{ 
                                            id: pooled_user_ops_by_hash_request_message.id.parse::<u128>().unwrap(),
                                            peer_id: pooled_user_ops_by_hash_request_message.peer_id, 
                                            pooled_user_ops_by_hash_request:pooled_user_ops_by_hash_request_message.pooled_user_ops_by_hash_request
                                        }
                                    );
                                    }
                                }
                            },
                            Err(deserialized_error)=>{
                                error!(self.log, "From bundler deserialization error"; "error" => deserialized_error.to_string());
                            },
                        }
                    },
                   

                    _ = self.metrics_update.tick(), if self.metrics_enabled => {
                        // update various network metrics
                        metrics::update_gossip_metrics();
                      
                    }

                    // handle a message sent to the network
                    Some(msg) = self.network_recv.recv() => self.on_network_msg(msg, &mut shutdown_sender).await,

                    event = self.libp2p.next_event() => self.on_libp2p_event(event, &mut shutdown_sender).await,

                }
                metrics::update_bandwidth_metrics(self.libp2p.bandwidth.clone());
            } 
           
        };
        executor.spawn(service_fut, "network");
       
    }

    /// Handle an event received from the network.
    async fn on_libp2p_event(
        &mut self,
        ev: NetworkEvent<RequestId>,
        shutdown_sender: &mut Sender<ShutdownReason>,
    ) {
        match ev {
            NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                // self.send_to_router(RouterMessage::StatusPeer(peer_id));
                let status_message = status_message(0, H256::default(),0);
                self.network.send_processor_request(peer_id, Request::Status(status_message));
            }
            NetworkEvent::PeerConnectedIncoming(_) => {
                // No action required for this event.
            }
            NetworkEvent::PeerDisconnected(_peer_id) => {
                // self.send_to_router(RouterMessage::PeerDisconnected(peer_id));
                // self.network.send_to_sync(SyncMessage::Disconnect(peer_id));
            }
            NetworkEvent::RequestReceived {
                peer_id,
                id,
                request,
            } => {
                if !self.network_globals.peers.read().is_connected(&peer_id) {
                    debug!(self.log, "Dropping request of disconnected peer"; "peer_id" => %peer_id, "request" => ?request);
                    return;
                }
                match request {
                    Request::Status(status_message) => {
                        self.on_status_request(peer_id, id, status_message)
                    }
                    Request::PooledUserOpHashes(pooled_user_op_hashes_request) => {
                        self.on_pooled_user_op_hashes_request(peer_id, id, pooled_user_op_hashes_request)
                       
                    },
                    Request::PooledUserOpsByHash(pooled_user_ops_by_hash) => {
                        self.on_pooled_user_ops_by_hash_request(peer_id, id, pooled_user_ops_by_hash)
                    },
                }
            }
            NetworkEvent::ResponseReceived {
                peer_id,
                id,
                response,
            } => {
                // self.send_to_router(RouterMessage::RPCResponseReceived {
                //     peer_id,
                //     request_id: id,
                //     response,
                // });
                self.handle_rpc_response(peer_id, id, response);
            }
            NetworkEvent::RPCFailed { id, peer_id } => {
                // self.send_to_router(RouterMessage::RPCFailed {
                //     peer_id,
                //     request_id: id,
                // });
                self.on_rpc_error(peer_id, id);
            }
            NetworkEvent::StatusPeer(peer_id) => {
                //self.send_to_router(RouterMessage::StatusPeer(peer_id));
                self.send_status(peer_id);
            }
            NetworkEvent::PubsubMessage {
                id: _,
                source,
                message,
                topic
            } => {
                match message.clone() {
                    PubsubMessage::VerifiedUserOperationV07(verified_useroperation) =>{
                        let gossib_message = GossibMessageToSendToMainBundlerV07 {
                            peer_id:source.to_string(),
                            topic: topic.to_string(),
                            verified_useroperation:*verified_useroperation.clone()
                        };
                        let message_to_send = BundlerGossibRequest {
                            request_type:"p2p_received_gossib".to_string(), 
                            request_arguments:MessageTypeToBundler::GossibMessageToBundlerV07(gossib_message)
                        };

                        broadcast_to_main_bundler(message_to_send, &self.log).await;
                    },
                    PubsubMessage::VerifiedUserOperationV06(verified_useroperation) =>{
                        let gossib_message = GossibMessageToSendToMainBundlerV06 {
                            peer_id:source.to_string(),
                            topic: topic.to_string(),
                            verified_useroperation:*verified_useroperation.clone()
                        };
                        let message_to_send = BundlerGossibRequest {
                            request_type:"p2p_received_gossib".to_string(), 
                            request_arguments:MessageTypeToBundler::GossibMessageToBundlerV06(gossib_message)
                        };

                        broadcast_to_main_bundler(message_to_send, &self.log).await;
                    }
                }
            }
            NetworkEvent::NewListenAddr(multiaddr) => {
                self.network_globals
                    .listen_multiaddrs
                    .write()
                    .push(multiaddr);
            }
            NetworkEvent::ZeroListeners => {
                let _ = shutdown_sender
                    .send(ShutdownReason::Failure(
                        "All listeners are closed. Unable to listen",
                    ))
                    .await
                    .map_err(|e| {
                        warn!(
                            self.log,
                            "failed to send a shutdown signal";
                            "error" => %e
                        )
                    });
            }
            NetworkEvent::ResponseReceivedFromInternal { peer_id, response } => {
                self.handle_rpc_response(peer_id, RequestId::Router, response);
            },
        }
    }

    /// Handle a message sent to the network service.
    async fn on_network_msg(
        &mut self,
        msg: NetworkMessage,
        _shutdown_sender: &mut Sender<ShutdownReason>,
    ) {
        metrics::inc_counter_vec(&metrics::NETWORK_RECEIVE_EVENTS, &[(&msg).into()]);
        let _timer = metrics::start_timer_vec(&metrics::NETWORK_RECEIVE_TIMES, &[(&msg).into()]);
        match msg {
            NetworkMessage::SendRequest {
                peer_id,
                request,
                request_id,
            } => {
                self.libp2p.send_request(peer_id, request_id, request);
            }
            NetworkMessage::SendResponse {
                peer_id,
                response,
                id,
            } => {
                self.libp2p.send_response(peer_id, id, response);
            }
            NetworkMessage::SendErrorResponse {
                peer_id,
                error,
                id,
                reason,
            } => {
                self.libp2p.send_error_reponse(peer_id, id, error, reason);
            }
            NetworkMessage::UPnPMappingEstablished { mappings } => {
                self.upnp_mappings = mappings;
                // If there is an external TCP port update, modify our local ENR.
                if let Some(tcp_port) = self.upnp_mappings.tcp_port {
                    if let Err(e) = self.libp2p.discovery_mut().update_enr_tcp_port(tcp_port) {
                        warn!(self.log, "Failed to update ENR"; "error" => e);
                    }
                }
                // If there is an external QUIC port update, modify our local ENR.
                if let Some(quic_port) = self.upnp_mappings.udp_quic_port {
                    if let Err(e) = self.libp2p.discovery_mut().update_enr_quic_port(quic_port) {
                        warn!(self.log, "Failed to update ENR"; "error" => e);
                    }
                }
            }
            NetworkMessage::ValidationResult {
                propagation_source,
                message_id,
                validation_result,
            } => {
                trace!(self.log, "Propagating gossipsub message";
                    "propagation_peer" => ?propagation_source,
                    "message_id" => %message_id,
                    "validation_result" => ?validation_result
                );
                self.libp2p.report_message_validation_result(
                    &propagation_source,
                    message_id,
                    validation_result,
                );
            }
            NetworkMessage::Publish { messages, mempool_ids } => {
                let mut topic_kinds = Vec::new();
                for message in &messages {
                    if !topic_kinds.contains(&message.kind()) {
                        topic_kinds.push(message.kind());
                    }
                }
                debug!(
                    self.log,
                    "Sending pubsub messages";
                    "count" => messages.len(),
                    "topics" => ?topic_kinds
                );
                self.libp2p.publish(messages, mempool_ids);
            }
            NetworkMessage::ReportPeer {
                peer_id,
                action,
                source,
                msg,
            } => self.libp2p.report_peer(&peer_id, action, source, msg),
            NetworkMessage::GoodbyePeer {
                peer_id,
                reason,
                source,
            } => self.libp2p.goodbye_peer(&peer_id, reason, source),
            NetworkMessage::SubscribeCoreTopics => {
                // if self.subscribed_core_topics() {
                //     return;
                // }

                // let mut subscribed_topics: Vec<GossipTopic> = vec![];
                // let topic = GossipTopic::new(GossipKind::VerifiedUserOperation, GossipEncoding::default(), "Qmf7P3CuhzSbpJa8LqXPwRzfPqsvoQ6RG7aXvthYTzGxb2".to_string());
                // if self.libp2p.subscribe(topic.clone()) {
                //     subscribed_topics.push(topic);
                // } else {
                //     warn!(self.log, "Could not subscribe to topic"; "topic" => %topic);
                // }

                // if !subscribed_topics.is_empty() {
                //     info!(
                //         self.log,
                //         "Subscribed to topics";
                //         "topics" => ?subscribed_topics.into_iter().map(|topic| format!("{}", topic)).collect::<Vec<_>>()
                //     );
                // }
            }
            NetworkMessage::PooledUserOpHashesRequestMessageToAllPeers { pooled_user_op_hashes_request: _ } => {
                self.libp2p.send_outbound_pooled_user_op_hashes_request_to_all_peers()
            },
            NetworkMessage::PooledUserOpHashesRequestMessage { id, peer_id, pooled_user_op_hashes_request } => {
                // self.send_to_router(RouterMessage::PooledUserOpHashesRequest (
                //     RequestId::FromMainBundler(id),
                //     PeerId::from_str(&peer_id).unwrap() ,
                //     pooled_user_op_hashes_request
                // ));
                self.network.send_request(RequestId::FromMainBundler(id), PeerId::from_str(&peer_id).unwrap(), Request::PooledUserOpHashes(pooled_user_op_hashes_request));
            },
            NetworkMessage::PooledUserOpsByHashRequestMessage { id, peer_id, pooled_user_ops_by_hash_request } => {
                // self.send_to_router(RouterMessage::PooledUserOpsByHashRequest (
                //     RequestId::FromMainBundler(id),
                //     PeerId::from_str(&peer_id).unwrap() ,
                //     pooled_user_ops_by_hash_request
                // ));
                self.network.send_request(
                    RequestId::FromMainBundler(id), PeerId::from_str(&peer_id).unwrap(), Request::PooledUserOpsByHash(pooled_user_ops_by_hash_request));
            },
            NetworkMessage::PooledUserOpHashesRequest{
                peer_id,
                request_id,
                pooled_user_op_hashes_request
            } => {
                let message_to_send = BundlerGossibRequest {
                    request_type:"p2p_pooled_user_op_hashes_received".to_string(), 
                    request_arguments:MessageTypeToBundler::PooledUserOpHashesRequestToBundler(pooled_user_op_hashes_request),
                };
                
                let response = broadcast_and_listen_for_response_from_main_bundler(message_to_send, &self.log).await;
        
                let deserialized_result:Result<PooledUserOpHashes,serde_pickle::Error> = serde_pickle::from_slice(&response.unwrap(), Default::default());

                debug!(self.log, "Sending PooledUserOpHashes Response"; "peer" => %peer_id);
                self.libp2p.send_response(peer_id, request_id, Response::PooledUserOpHashes(Some(deserialized_result.unwrap())));
            },
            NetworkMessage::PooledUserOpsByHashRequest{
                peer_id,
                request_id,
                pooled_user_ops_by_hash_request} => {

                let message_to_send = BundlerGossibRequest {
                    request_type:"p2p_pooled_user_ops_by_hash_received".to_string(), 
                    request_arguments:MessageTypeToBundler::PooledUserOpsByHashRequestToBundler(pooled_user_ops_by_hash_request)
                };
                
                let response = broadcast_and_listen_for_response_from_main_bundler(message_to_send, &self.log).await;

                let deserialized_result:Result<PooledUserOpsByHash,serde_pickle::Error> = serde_pickle::from_slice(&response.unwrap(), Default::default());
              
                debug!(self.log, "Sending PooledUserOpsByHash Response"; "peer" => %peer_id);
                let deserialized_result_unwrap = deserialized_result.unwrap();
                match deserialized_result_unwrap {
                    PooledUserOpsByHash::PooledUserOpsByHashV07(pooled_userops_by_hash_v07)=>{
                        self.libp2p.send_response(peer_id, request_id,  Response::PooledUserOpsByHashV07(Some(pooled_userops_by_hash_v07)));
                    },
                    PooledUserOpsByHash::PooledUserOpsByHashV06(pooled_userops_by_hash_v06)=>{
                        self.libp2p.send_response(peer_id, request_id,  Response::PooledUserOpsByHashV06(Some(pooled_userops_by_hash_v06)));
                    },
                }
            },
            NetworkMessage::PooledUserOpHashesResponse { peer_id, request_id: _, pooled_user_op_hashes } => {
                let pooled_user_op_hashes_message = PooledUserOpHashesAndPeerId{
                    peer_id:peer_id.to_string(),
                    pooled_user_op_hashes,
                };
                let message_to_send = BundlerGossibRequest {
                    request_type:"p2p_received_pooled_user_op_hashes_response".to_string(), 
                    request_arguments:MessageTypeToBundler::PooledUserOpHashesResponseToBundler(pooled_user_op_hashes_message)
                };
                
                broadcast_to_main_bundler(message_to_send, &self.log).await;
                
            },
            NetworkMessage::PooledUserOpsByHashResponseV07 { peer_id: _, request_id: _, pooled_user_ops_by_hash } => {
                let message_to_send = BundlerGossibRequest {
                    request_type:"p2p_received_pooled_user_ops_by_hash_response".to_string(), 
                    request_arguments:MessageTypeToBundler::PooledUserOpsByHashResponseToBundlerV07(pooled_user_ops_by_hash)
                };
        
                broadcast_to_main_bundler(message_to_send, &self.log).await;
            },
            NetworkMessage::PooledUserOpsByHashResponseV06 { peer_id: _, request_id: _, pooled_user_ops_by_hash } => {
                let message_to_send = BundlerGossibRequest {
                    request_type:"p2p_received_pooled_user_ops_by_hash_response".to_string(), 
                    request_arguments:MessageTypeToBundler::PooledUserOpsByHashResponseToBundlerV06(pooled_user_ops_by_hash)
                };
        
                broadcast_to_main_bundler(message_to_send, &self.log).await;
            },
            NetworkMessage::Status{
                peer_id,
                request_id} => {

                let message_to_send = BundlerGossibRequest {
                    request_type:"p2p_status_received".to_string(), 
                    request_arguments:MessageTypeToBundler::Status()
                };
                
                let response = broadcast_and_listen_for_response_from_main_bundler(message_to_send, &self.log).await;

                let deserialized_result:Result<StatusMessage,serde_pickle::Error> = serde_pickle::from_slice(&response.unwrap(), Default::default());
              
                debug!(self.log, "Sending Status Response"; "peer" => %peer_id);
                self.libp2p.send_response(peer_id, request_id,  Response::Status(deserialized_result.unwrap()));
            },
        }
    }


     /* RPC - Related functionality */

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
                    "block_hash" => status_message.block_hash.to_string(),
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
            Response::PooledUserOpsByHashV07(pooled_user_ops_by_hash) => { 
                self.on_pooled_user_ops_by_hash_responseV07(
                    peer_id, 
                    request_id,
                    pooled_user_ops_by_hash.unwrap()
                )
            },
            Response::PooledUserOpsByHashV06(pooled_user_ops_by_hash) => { 
                self.on_pooled_user_ops_by_hash_responseV06(
                    peer_id, 
                    request_id,
                    pooled_user_ops_by_hash.unwrap()
                )
            },
        }
    }


    fn send_status(&mut self, peer_id: PeerId) {
        // let topics = self.network_globals.local_metadata.read().clone();
        let status_message = status_message(0, H256::default(),0);

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
    pub fn on_rpc_error(&mut self, peer_id: PeerId, _request_id: RequestId) {
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

        self.network.inform_network(NetworkMessage::Status {
            peer_id,
            request_id,
        });
    }

    pub fn on_pooled_user_op_hashes_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        pooled_user_op_hashes_request: PooledUserOpHashesRequest,
    ) {
        debug!(self.log, "Received PooledUserOpHashes Request"; "peer_id" => %peer_id);


        self.network.inform_network(NetworkMessage::PooledUserOpHashesRequest {
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

        self.network.inform_network(NetworkMessage::PooledUserOpHashesResponse {
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

        self.network.inform_network(NetworkMessage::PooledUserOpsByHashRequest {
            peer_id,
            request_id,
            pooled_user_ops_by_hash_request,
        });
    }

    pub fn on_pooled_user_ops_by_hash_responseV07(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        pooled_user_ops_by_hash: PooledUserOpsByHashV07,
    ) {
        debug!(self.log, "Received PooledUserOpsByHash Response"; "peer_id" => %peer_id);

        self.network.inform_network(NetworkMessage::PooledUserOpsByHashResponseV07 {
            peer_id,
            request_id,
            pooled_user_ops_by_hash,
        });
    }

    pub fn on_pooled_user_ops_by_hash_responseV06(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        pooled_user_ops_by_hash: PooledUserOpsByHashV06,
    ) {
        debug!(self.log, "Received PooledUserOpsByHash Response"; "peer_id" => %peer_id);

        self.network.inform_network(NetworkMessage::PooledUserOpsByHashResponseV06 {
            peer_id,
            request_id,
            pooled_user_ops_by_hash,
        });
    }
}


impl Drop for NetworkService {
    fn drop(&mut self) {
        // network thread is terminating
        let enrs = self.libp2p.enr_entries();
        debug!(
            self.log,
            "Persisting DHT to store";
            "Number of peers" => enrs.len(),
        );
        // if let Err(e) = clear_dht::<T::EthSpec, T::HotStore, T::ColdStore>(self.store.clone()) {
        //     error!(self.log, "Failed to clear old DHT entries"; "error" => ?e);
        // }
        // // Still try to update new entries
        // match persist_dht::<T::EthSpec, T::HotStore, T::ColdStore>(self.store.clone(), enrs) {
        //     Err(e) => error!(
        //         self.log,
        //         "Failed to persist DHT on drop";
        //         "error" => ?e
        //     ),
        //     Ok(_) => info!(
        //         self.log,
        //         "Saved DHT state";
        //     ),
        // }

        // attempt to remove port mappings
        crate::nat::remove_mappings(&self.upnp_mappings, &self.log);

        info!(self.log, "Network service shutdown");
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