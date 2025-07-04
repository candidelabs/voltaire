use self::behaviour::Behaviour;
use self::gossip_cache::GossipCache;
use crate::config::{gossipsub_config, GossipsubConfigParams, NetworkLoad};
use crate::discovery::{
    DiscoveredPeers, Discovery, FIND_NODE_QUERY_CLOSEST_PEERS,
};
use crate::peer_manager::{
    config::Config as PeerManagerCfg, peerdb::score::PeerAction, peerdb::score::ReportSource,
    ConnectionDirection, PeerManager, PeerManagerEvent,
};
use crate::peer_manager::{MIN_OUTBOUND_ONLY_FACTOR, PEER_EXCESS_FACTOR, PRIORITY_PEER_EXCESS};
use crate::rpc::methods::{MetadataRequest, PooledUserOpHashesRequest};
use crate::{rpc::*, NetworkConfig as Config};
use crate::service::behaviour::BehaviourEvent;
pub use crate::service::behaviour::Gossipsub;
use crate::types::{
    GossipEncoding, GossipKind, GossipTopic,
    SnappyTransform, Subnet, SubnetDiscovery,
};
use crate::EnrExt;
// use crate::Eth2Enr;
use crate::{error, metrics, Enr, NetworkGlobals, PubsubMessage, TopicHash};
use api_types::{PeerRequestId, Request, RequestId, Response};
use futures::stream::StreamExt;
use gossipsub_scoring_parameters::{voltaire_gossip_thresholds, PeerScoreSettings};
use libp2p::bandwidth::BandwidthSinks;
use libp2p::gossipsub::{
    self, IdentTopic as Topic, MessageAcceptance, MessageAuthenticity, MessageId, PublishError,
};
use libp2p::identify;
use libp2p::multiaddr::{Multiaddr, Protocol as MProtocol};
use libp2p::swarm::{Swarm, SwarmBuilder, SwarmEvent};
use libp2p::PeerId;
use slog::{crit, debug, info, o, trace, warn};
use ssz_types::{typenum::U32, FixedVector};
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
use std::{
    sync::Arc,
    task::{Context, Poll},
};

// // use types::ForkName;
// use types::{
//     consts::altair::SYNC_COMMITTEE_SUBNET_COUNT, EnrForkId, EthSpec, ForkContext, Slot, SubnetId,
// };
use utils::{build_transport, strip_peer_id, MAX_CONNECTIONS_PER_PEER};

pub mod api_types;
mod behaviour;
mod gossip_cache;
pub mod gossipsub_scoring_parameters;
pub mod utils;
/// The number of peers we target per subnet for discovery queries.
pub const TARGET_SUBNET_PEERS: usize = 6;

const MAX_IDENTIFY_ADDRESSES: usize = 10;

/// The types of events than can be obtained from polling the behaviour.
#[derive(Debug)]
pub enum NetworkEvent<AppReqId: ReqId> {
    /// We have successfully dialed and connected to a peer.
    PeerConnectedOutgoing(PeerId),
    /// A peer has successfully dialed and connected to us.
    PeerConnectedIncoming(PeerId),
    /// A peer has disconnected.
    PeerDisconnected(PeerId),
    /// An RPC Request that was sent failed.
    RPCFailed {
        /// The id of the failed request.
        id: AppReqId,
        /// The peer to which this request was sent.
        peer_id: PeerId,
    },
    RequestReceived {
        /// The peer that sent the request.
        peer_id: PeerId,
        /// Identifier of the request. All responses to this request must use this id.
        id: PeerRequestId,
        /// Request the peer sent.
        request: Request,
    },
    ResponseReceived {
        /// Peer that sent the response.
        peer_id: PeerId,
        /// Id of the request to which the peer is responding.
        id: AppReqId,
        /// Response the peer sent.
        response: Response,
    },
    ResponseReceivedFromInternal {
        /// Peer that sent the response.
        peer_id: PeerId,
        /// Response the peer sent.
        response: Response,
    },
    PubsubMessage {
        /// The gossipsub message id. Used when propagating blocks after validation.
        id: MessageId,
        /// The peer from which we received this message, not the peer that published it.
        source: PeerId,
        /// The topic that this message was sent on.
        topic: TopicHash,
        /// The message itself.
        message: PubsubMessage,
    },
    /// Inform the network to send a Status to this peer.
    StatusPeer(PeerId),
    NewListenAddr(Multiaddr),
    ZeroListeners,
}

/// Builds the network behaviour that manages the core protocols of eth2.
/// This core behaviour is managed by `Behaviour` which adds peer management to all core
/// behaviours.
pub struct Network<AppReqId: ReqId> {
    swarm: libp2p::swarm::Swarm<Behaviour<AppReqId>>,
    /* Auxiliary Fields */
    /// A collections of variables accessible outside the network service.
    network_globals: Arc<NetworkGlobals>,
    // /// Keeps track of the current EnrForkId for upgrading gossipsub topics.
    // // NOTE: This can be accessed via the network_globals ENR. However we keep it here for quick
    // // lookups for every gossipsub message send.
    // enr_fork_id: EnrForkId,
    /// Directory where metadata is stored.
    network_dir: PathBuf,
    // fork_context: Arc<ForkContext>,
    /// Gossipsub score parameters.
    score_settings: PeerScoreSettings,
    /// The interval for updating gossipsub scores
    update_gossipsub_scores: tokio::time::Interval,
    gossip_cache: GossipCache,
    /// The bandwidth logger for the underlying libp2p transport.
    pub bandwidth: Arc<BandwidthSinks>,
    /// This node's PeerId.
    pub local_peer_id: PeerId,
    /// Logger for behaviour actions.
    log: slog::Logger,
}

/// Implements the combined behaviour for the libp2p service.
impl<AppReqId: ReqId> Network<AppReqId> {
    pub async fn new(
        executor: task_executor::TaskExecutor,
        // ctx: ServiceContext<'_>,
        config: Config,
        log: &slog::Logger,
    ) -> error::Result<(Self, Arc<NetworkGlobals>)> {
        let log = log.new(o!("service"=> "libp2p"));
        // let mut config = ctx.config.clone();
        trace!(log, "Libp2p Service starting");
        // initialise the node's ID
        let local_keypair = utils::load_private_key(&config, &log);

        // let local_keypair = identity::Keypair::generate_secp256k1();
        // let local_peer_id = PeerId::from(id_keys.public());

        // set up a collection of variables accessible outside of the network crate
        let network_globals = {
            // Create an ENR or load from disk if appropriate
            let enr = crate::discovery::enr::build_or_load_enr(
                local_keypair.clone(),
                &config,
                &log,
            )?;
            // Construct the metadata
            let meta_data = utils::load_or_build_metadata(&config.network_dir, &log);
            
            let globals = NetworkGlobals::new(
                enr,
                meta_data.clone(),
                config
                    .trusted_peers
                    .iter()
                    .map(|x| PeerId::from(x.clone()))
                    .collect(),
                config.disable_peer_scoring,
                &log,
            );
            
            Arc::new(globals)
        };

        // // Grab our local ENR FORK ID
        // let enr_fork_id = network_globals
        //     .local_enr()
        //     .eth2()
        //     .expect("Local ENR must have a fork id");

        let score_settings = PeerScoreSettings::new(&config.gs_config);

        let gossip_cache = {
            let slot_duration = std::time::Duration::from_secs(10);
            let half_epoch = std::time::Duration::from_secs(
                // ctx.chain_spec.seconds_per_slot * TSpec::slots_per_epoch() / 2,
                100,
            );

            GossipCache::builder().build()
        };
        
        let local_peer_id = network_globals.local_peer_id();

        let (gossipsub, update_gossipsub_scores) = {
            let thresholds = voltaire_gossip_thresholds();

            // // Prepare scoring parameters
            // let params = {
            //     // Construct a set of gossipsub peer scoring parameters
            //     // We don't know the number of active validators and the current slot yet
            //     let active_validators = 1000;//TSpec::minimum_validator_count();
            //     // let current_slot = Slot::new(0);
            //     score_settings.get_peer_score_params(
            //         active_validators,
            //         &thresholds,
            //         &enr_fork_id,
            //         // current_slot,
            //     )?
            // };

            // trace!(log, "Using peer score params"; "params" => ?params);

            // Set up a scoring update interval
            let update_gossipsub_scores = tokio::time::interval(/*params.decay_interval*/Duration::new(1, 0));
            // let possible_fork_digests = ctx.fork_context.all_fork_digests();
            let filter: gossipsub::MaxCountSubscriptionFilter<gossipsub::WhitelistSubscriptionFilter> = gossipsub::MaxCountSubscriptionFilter {
                filter: utils::create_whitelist_filter(
                    config.clone().topics
                    // possible_fork_digests,
                    // ctx.chain_spec.attestation_subnet_count,
                    // 100,
                    // SYNC_COMMITTEE_SUBNET_COUNT,
                ),
                max_subscribed_topics: 200,
                max_subscriptions_per_request: 150, // 148 in theory = (64 attestation + 4 sync committee + 6 core topics) * 2
            };

            let gossipsub_config_params = GossipsubConfigParams {
                message_domain_valid_snappy: [1,0,0,0],//ctx.chain_spec.message_domain_valid_snappy,
                gossip_max_size: 10485760,//ctx.chain_spec.gossip_max_size as usize,
            };
            let mut config = config.clone();
            config.gs_config = gossipsub_config(
                config.network_load,
                gossipsub_config_params,
            );

            // config.gs_config = gossipsub_config(
            //     config.network_load,
            //     // ctx.fork_context.clone(),
            //     gossipsub_config_params,
            // );

            // // If metrics are enabled for gossipsub build the configuration
            // let gossipsub_metrics = ctx
            //     .gossipsub_registry
            //     .map(|registry| (registry, Default::default()));

            let snappy_transform = SnappyTransform::new(config.gs_config.max_transmit_size());
            let gossipsub = Gossipsub::new_with_subscription_filter_and_transform(
                MessageAuthenticity::Anonymous,
                // MessageAuthenticity::Signed(local_keypair.clone()),
                config.gs_config.clone(),
                None,
                filter,
                snappy_transform,
            )
            .map_err(|e| format!("Could not construct gossipsub: {:?}", e))?;

            // gossipsub
            //     .with_peer_score(params, thresholds)
            //     .expect("Valid score params and thresholds");

            (gossipsub, update_gossipsub_scores)
        };
        
        let network_params = NetworkParams {
            max_chunk_size: 1048576,//ctx.chain_spec.max_chunk_size as usize,
            ttfb_timeout: Duration::new(1000, 1000),//ctx.chain_spec.ttfb_timeout(),
            resp_timeout: Duration::new(1000, 1000),//ctx.chain_spec.resp_timeout(),
        };
        let eth2_rpc = RPC::new(
            // ctx.fork_context.clone(),
            // config.enable_light_client_server,
            config.inbound_rate_limiter_config.clone(),
            config.outbound_rate_limiter_config.clone(),
            log.clone(),
            network_params,
        );

        let discovery = {
            // Build and start the discovery sub-behaviour
            let mut discovery = Discovery::new(
                local_keypair.clone(),
                &config,
                network_globals.clone(),
                &log,
            )
            .await?;
            // start searching for peers
            discovery.discover_peers(FIND_NODE_QUERY_CLOSEST_PEERS);
            discovery
        };

        let identify = {
            let local_public_key = local_keypair.public();
            let identify_config = if config.private {
                identify::Config::new(
                    "".into(),
                    local_public_key, // Still send legitimate public key
                )
                .with_cache_size(0)
            } else {
                identify::Config::new("eth2/1.0.0".into(), local_public_key)
                    .with_agent_version(voltaire_version::version_with_platform())
                    .with_cache_size(0)
            };
            identify::Behaviour::new(identify_config)
        };

        let peer_manager = {
            let peer_manager_cfg = PeerManagerCfg {
                discovery_enabled: !config.disable_discovery,
                metrics_enabled: config.metrics_enabled,
                target_peer_count: config.target_peers,
                ..Default::default()
            };
            PeerManager::new(peer_manager_cfg, network_globals.clone(), &log)?
        };

        let connection_limits = {
            let limits = libp2p::connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(5))
                .with_max_pending_outgoing(Some(16))
                .with_max_established_incoming(Some(
                    (config.target_peers as f32
                        * (1.0 + PEER_EXCESS_FACTOR - MIN_OUTBOUND_ONLY_FACTOR))
                        .ceil() as u32,
                ))
                .with_max_established_outgoing(Some(
                    (config.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR)).ceil() as u32,
                ))
                .with_max_established(Some(
                    (config.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS))
                        .ceil() as u32,
                ))
                .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER));

            libp2p::connection_limits::Behaviour::new(limits)
        };

        let banned_peers = libp2p::allow_block_list::Behaviour::default();

        let behaviour = {
            Behaviour {
                banned_peers,
                gossipsub,
                eth2_rpc,
                discovery,
                identify,
                peer_manager,
                connection_limits,
            }
        };

        let (swarm, bandwidth) = {
            // Set up the transport - tcp/ws with noise and mplex
            let (transport, bandwidth) =
                build_transport(local_keypair.clone(), !config.disable_quic_support)
                    .map_err(|e| format!("Failed to build transport: {:?}", e))?;

            // use the executor for libp2p
            struct Executor(task_executor::TaskExecutor);
            impl libp2p::swarm::Executor for Executor {
                fn exec(&self, f: Pin<Box<dyn futures::Future<Output = ()> + Send>>) {
                    self.0.spawn(f, "libp2p");
                }
            }

            // sets up the libp2p connection limits

            (
                SwarmBuilder::with_executor(
                    transport,
                    behaviour,
                    local_peer_id,
                    Executor(executor),
                )
                .notify_handler_buffer_size(std::num::NonZeroUsize::new(7).expect("Not zero"))
                .per_connection_event_buffer_size(4)
                .build(),
                bandwidth,
            )
        };

        let mut network = Network {
            swarm,
            network_globals,
            // enr_fork_id,
            network_dir: config.network_dir.clone(),
            // fork_context: ctx.fork_context,
            score_settings,
            update_gossipsub_scores,
            gossip_cache,
            bandwidth,
            local_peer_id,
            log,
        };
        
        network.start(&config).await?;

        let network_globals = network.network_globals.clone();

        Ok((network, network_globals))
    }

    /// Starts the network:
    ///
    /// - Starts listening in the given ports.
    /// - Dials boot-nodes and libp2p peers.
    /// - Subscribes to starting gossipsub topics.
    async fn start(&mut self, config: &crate::NetworkConfig) -> error::Result<()> {
        let enr = self.network_globals.local_enr();
        info!(self.log, "Libp2p Starting"; "peer_id" => %enr.peer_id(), "bandwidth_config" => format!("{}-{}", config.network_load, NetworkLoad::from(config.network_load).name));
        debug!(self.log, "Attempting to open listening ports"; config.listen_addrs(), "discovery_enabled" => !config.disable_discovery, "quic_enabled" => !config.disable_quic_support);

        for listen_multiaddr in config.listen_addrs().libp2p_addresses() {
            // If QUIC is disabled, ignore listening on QUIC ports
            if config.disable_quic_support
                && listen_multiaddr.iter().any(|v| v == MProtocol::QuicV1)
            {
                continue;
            }

            match self.swarm.listen_on(listen_multiaddr.clone()) {
                Ok(_) => {
                    let mut log_address = listen_multiaddr;
                    log_address.push(MProtocol::P2p(enr.peer_id()));
                    info!(self.log, "Listening established"; "address" => %log_address);
                }
                Err(err) => {
                    crit!(
                        self.log,
                        "Unable to listen on libp2p address";
                        "error" => ?err,
                        "listen_multiaddr" => %listen_multiaddr,
                    );
                    return Err("Libp2p was unable to listen on the given listen address.".into());
                }
            };
            break;
        }

        // helper closure for dialing peers
        let mut dial = |mut multiaddr: Multiaddr| {
            // strip the p2p protocol if it exists
            strip_peer_id(&mut multiaddr);
            match self.swarm.dial(multiaddr.clone()) {
                Ok(()) => debug!(self.log, "Dialing libp2p peer"; "address" => %multiaddr),
                Err(err) => {
                    debug!(self.log, "Could not connect to peer"; "address" => %multiaddr, "error" => ?err)
                }
            };
        };

        // attempt to connect to user-input libp2p nodes
        for multiaddr in &config.libp2p_nodes {
            dial(multiaddr.clone());
        }

        // attempt to connect to any specified boot-nodes
        let mut boot_nodes = config.boot_nodes_enr.clone();
        boot_nodes.dedup();

        for bootnode_enr in boot_nodes {
            // If QUIC is enabled, attempt QUIC connections first
            if !config.disable_quic_support {
                for quic_multiaddr in &bootnode_enr.multiaddr_quic() {
                    if !self
                        .network_globals
                        .peers
                        .read()
                        .is_connected_or_dialing(&bootnode_enr.peer_id())
                    {
                        dial(quic_multiaddr.clone());
                    }
                }
            }

            for multiaddr in &bootnode_enr.multiaddr() {
                // ignore udp multiaddr if it exists
                let components = multiaddr.iter().collect::<Vec<_>>();
                if let MProtocol::Udp(_) = components[1] {
                    continue;
                }

                if !self
                    .network_globals
                    .peers
                    .read()
                    .is_connected_or_dialing(&bootnode_enr.peer_id())
                {
                    dial(multiaddr.clone());
                }
            }
        }

        for multiaddr in &config.boot_nodes_multiaddr {
            // check TCP support for dialing
            if multiaddr
                .iter()
                .any(|proto| matches!(proto, MProtocol::Tcp(_)))
            {
                dial(multiaddr.clone());
            }
        }

        let mut subscribed_topics: Vec<GossipKind> = vec![];

        for topic_kind in &config.topics {
            if self.subscribe_kind(GossipKind::VerifiedUserOperationV07, topic_kind.to_string()) {
                subscribed_topics.push(GossipKind::VerifiedUserOperationV07);
            }else if self.subscribe_kind(GossipKind::VerifiedUserOperationV06, topic_kind.to_string()) {
                subscribed_topics.push(GossipKind::VerifiedUserOperationV06);
            } else {
                warn!(self.log, "Could not subscribe to topic"; "topic" => %topic_kind);
            }
        }

        // if !subscribed_topics.is_empty() {
        //     info!(self.log, "Subscribed to topics"; "topics" => ?subscribed_topics);
        // }

        Ok(())
    }

    /* Public Accessible Functions to interact with the behaviour */

    /// The routing pub-sub mechanism for eth2.
    pub fn gossipsub_mut(&mut self) -> &mut Gossipsub {
        &mut self.swarm.behaviour_mut().gossipsub
    }
    /// The Eth2 RPC specified in the wire-0 protocol.
    pub fn eth2_rpc_mut(&mut self) -> &mut RPC<RequestId<AppReqId>> {
        &mut self.swarm.behaviour_mut().eth2_rpc
    }
    /// Discv5 Discovery protocol.
    pub fn discovery_mut(&mut self) -> &mut Discovery {
        &mut self.swarm.behaviour_mut().discovery
    }
    /// Provides IP addresses and peer information.
    pub fn identify_mut(&mut self) -> &mut identify::Behaviour {
        &mut self.swarm.behaviour_mut().identify
    }
    /// The peer manager that keeps track of peer's reputation and status.
    pub fn peer_manager_mut(&mut self) -> &mut PeerManager {
        &mut self.swarm.behaviour_mut().peer_manager
    }

    /// The routing pub-sub mechanism for eth2.
    pub fn gossipsub(&self) -> &Gossipsub {
        &self.swarm.behaviour().gossipsub
    }
    /// The Eth2 RPC specified in the wire-0 protocol.
    pub fn eth2_rpc(&self) -> &RPC<RequestId<AppReqId>> {
        &self.swarm.behaviour().eth2_rpc
    }
    /// Discv5 Discovery protocol.
    pub fn discovery(&self) -> &Discovery {
        &self.swarm.behaviour().discovery
    }
    /// Provides IP addresses and peer information.
    pub fn identify(&self) -> &identify::Behaviour {
        &self.swarm.behaviour().identify
    }
    /// The peer manager that keeps track of peer's reputation and status.
    pub fn peer_manager(&self) -> &PeerManager {
        &self.swarm.behaviour().peer_manager
    }

    /// Returns the local ENR of the node.
    pub fn local_enr(&self) -> Enr {
        self.network_globals.local_enr()
    }

    /* Pubsub behaviour functions */

    /// Subscribes to a gossipsub topic kind, letting the network service determine the
    /// encoding and fork version.
    pub fn subscribe_kind(&mut self, kind: GossipKind, mempool_id: String) -> bool {
        let gossip_topic = GossipTopic::new(
            kind,
            GossipEncoding::default(),
            // self.enr_fork_id.fork_digest,
            mempool_id
        );

        self.subscribe(gossip_topic)
    }

    // /// Unsubscribes from a gossipsub topic kind, letting the network service determine the
    // /// encoding and fork version.
    // pub fn unsubscribe_kind(&mut self, kind: GossipKind) -> bool {
    //     let gossip_topic = GossipTopic::new(
    //         kind,
    //         GossipEncoding::default(),
    //         self.enr_fork_id.fork_digest,
    //     );
    //     self.unsubscribe(gossip_topic)
    // }

    // /// Subscribe to all required topics for the `new_fork` with the given `new_fork_digest`.
    // pub fn subscribe_new_fork_topics(&mut self, new_fork: ForkName, new_fork_digest: [u8; 4]) {
    //     // Subscribe to existing topics with new fork digest
    //     let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
    //     for mut topic in subscriptions.into_iter() {
    //         topic.fork_digest = new_fork_digest;
    //         self.subscribe(topic);
    //     }

    //     // Subscribe to core topics for the new fork
    //     for kind in fork_core_topics(&new_fork) {
    //         let topic = GossipTopic::new(kind, GossipEncoding::default(), new_fork_digest);
    //         self.subscribe(topic);
    //     }
    // }

    // /// Unsubscribe from all topics that doesn't have the given fork_digest
    // pub fn unsubscribe_from_fork_topics_except(&mut self, except: [u8; 4]) {
    //     let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
    //     for topic in subscriptions
    //         .iter()
    //         .filter(|topic| topic.fork_digest != except)
    //         .cloned()
    //     {
    //         self.unsubscribe(topic);
    //     }
    // }

    /// Subscribes to a gossipsub topic.
    ///
    /// Returns `true` if the subscription was successful and `false` otherwise.
    pub fn subscribe(&mut self, topic: GossipTopic) -> bool {
        // update the network globals
        self.network_globals
            .gossipsub_subscriptions
            .write()
            .insert(topic.clone());

        let topic: Topic = topic.into();

        match self.gossipsub_mut().subscribe(&topic) {
            Err(e) => {
                warn!(self.log, "Failed to subscribe to topic"; "topic" => %topic, "error" => ?e);
                false
            }
            Ok(_) => {
                debug!(self.log, "Subscribed to topic"; "topic" => %topic);
                true
            }
        }
    }

    // /// Unsubscribe from a gossipsub topic.
    // pub fn unsubscribe(&mut self, topic: GossipTopic) -> bool {
    //     // update the network globals
    //     self.network_globals
    //         .gossipsub_subscriptions
    //         .write()
    //         .remove(&topic);

    //     // unsubscribe from the topic
    //     let libp2p_topic: Topic = topic.clone().into();

    //     match self.gossipsub_mut().unsubscribe(&libp2p_topic) {
    //         Err(_) => {
    //             warn!(self.log, "Failed to unsubscribe from topic"; "topic" => %libp2p_topic);
    //             false
    //         }
    //         Ok(v) => {
    //             // Inform the network
    //             debug!(self.log, "Unsubscribed to topic"; "topic" => %topic);
    //             v
    //         }
    //     }
    // }

    /// Publishes a list of messages on the pubsub (gossipsub) behaviour, choosing the encoding.
    pub fn publish(&mut self, messages: Vec<PubsubMessage>, mempool_ids: Vec<String>) {
        for message in messages {
            let topics: Vec<GossipTopic> = mempool_ids.iter().map(|mempool_id|GossipTopic::new(message.kind(), GossipEncoding::default(), mempool_id.clone())).collect();

            for topic in topics{//message.topics(GossipEncoding::default(), "Qmf7P3CuhzSbpJa8LqXPwRzfPqsvoQ6RG7aXvthYTzGxb2".to_string()) {
                let message_data = message.encode(GossipEncoding::default());
                if let Err(e) = self
                    .gossipsub_mut()
                    .publish(Topic::from(topic.clone()), message_data.clone())
                {
                    slog::warn!(self.log, "Could not publish message"; "error" => ?e);

                    // add to metrics
                    match topic.kind() {
                        // GossipKind::Attestation(subnet_id) => {
                        //     if let Some(v) = metrics::get_int_gauge(
                        //         &metrics::FAILED_ATTESTATION_PUBLISHES_PER_SUBNET,
                        //         &[subnet_id.as_ref()],
                        //     ) {
                        //         v.inc()
                        //     };
                        // }
                        kind => {
                            if let Some(v) = metrics::get_int_gauge(
                                &metrics::FAILED_PUBLISHES_PER_MAIN_TOPIC,
                                &[&format!("{:?}", kind)],
                            ) {
                                v.inc()
                            };
                        }
                    }

                    if let PublishError::InsufficientPeers = e {
                        self.gossip_cache.insert(topic, message_data);
                    }
                }
            }
        }
    }

    /// Informs the gossipsub about the result of a message validation.
    /// If the message is valid it will get propagated by gossipsub.
    pub fn report_message_validation_result(
        &mut self,
        propagation_source: &PeerId,
        message_id: MessageId,
        validation_result: MessageAcceptance,
    ) {
        if let Some(result) = match validation_result {
            MessageAcceptance::Accept => None,
            MessageAcceptance::Ignore => Some("ignore"),
            MessageAcceptance::Reject => Some("reject"),
        } {
            if let Some(client) = self
                .network_globals
                .peers
                .read()
                .peer_info(propagation_source)
                .map(|info| info.client().kind.as_ref())
            {
                metrics::inc_counter_vec(
                    &metrics::GOSSIP_UNACCEPTED_MESSAGES_PER_CLIENT,
                    &[client, result],
                )
            }
        }

        if let Err(e) = self.gossipsub_mut().report_message_validation_result(
            &message_id,
            propagation_source,
            validation_result,
        ) {
            warn!(self.log, "Failed to report message validation"; "message_id" => %message_id, "peer_id" => %propagation_source, "error" => ?e);
        }
    }

    // /// Updates the current gossipsub scoring parameters based on the validator count and current
    // /// slot.
    // pub fn update_gossipsub_parameters(
    //     &mut self,
    //     active_validators: usize,
    //     // current_slot: Slot,
    // ) -> error::Result<()> {
    //     // let (beacon_block_params, beacon_aggregate_proof_params, beacon_attestation_subnet_params) =
    //     //     self.score_settings
    //     //         .get_dynamic_topic_params(active_validators/*, current_slot*/)?;

    //     let fork_digest = self.enr_fork_id.fork_digest;
    //     let get_topic = |kind: GossipKind| -> Topic {
    //         GossipTopic::new(kind, GossipEncoding::default(), fork_digest).into()
    //     };

    //     debug!(self.log, "Updating gossipsub score parameters";
    //         "active_validators" => active_validators);
    //     // trace!(self.log, "Updated gossipsub score parameters";
    //     //     "beacon_block_params" => ?beacon_block_params,
    //     //     "beacon_aggregate_proof_params" => ?beacon_aggregate_proof_params,
    //     //     "beacon_attestation_subnet_params" => ?beacon_attestation_subnet_params,
    //     // );

    //     // self.gossipsub_mut()
    //     //     .set_topic_params(get_topic(GossipKind::BeaconBlock), beacon_block_params)?;

    //     // self.gossipsub_mut().set_topic_params(
    //     //     get_topic(GossipKind::BeaconAggregateAndProof),
    //     //     beacon_aggregate_proof_params,
    //     // )?;

    //     // for i in 0..self.score_settings.attestation_subnet_count() {
    //     //     self.gossipsub_mut().set_topic_params(
    //     //         get_topic(GossipKind::Attestation(SubnetId::new(i))),
    //     //         beacon_attestation_subnet_params.clone(),
    //     //     )?;
    //     // }

    //     Ok(())
    // }

    /* Eth2 RPC behaviour functions */

    /// Send a request to a peer over RPC.
    pub fn send_request(&mut self, peer_id: PeerId, request_id: AppReqId, request: Request) {
        self.eth2_rpc_mut().send_request(
            peer_id,
            RequestId::Application(request_id),
            request.into(),
        )
    }

     /// Get all peers on a subnet.
    pub fn get_all_peers(&mut self)->Vec<PeerId>{
        let peers = self
        .network_globals
        .peers
        .read();

        // let peers_on_subnet = peers.good_peers_on_subnet(subnet);
        let peers_and_peers_info = peers.peers();

        peers_and_peers_info.map(|(peer_id, _)|{
            *peer_id
        }).collect()
    }

    /// Send a request to all peers over RPC.
    pub fn send_outbound_pooled_user_op_hashes_request_to_all_peers(&mut self) {
       let peers_on_subnet = self.get_all_peers();

       let request = OutboundRequest::PooledUserOpHashes(
        PooledUserOpHashesRequest {cursor: FixedVector::<u8, U32>::default() }
        );

        for peer_id in peers_on_subnet {
            self.eth2_rpc_mut().send_request(
                peer_id,
                RequestId::Internal,
                request.clone().into(),
            );
        }
    }
     

    /// Send a successful response to a peer over RPC.
    pub fn send_response(&mut self, peer_id: PeerId, id: PeerRequestId, response: Response) {
        self.eth2_rpc_mut()
            .send_response(peer_id, id, response.into())
    }

    /// Inform the peer that their request produced an error.
    pub fn send_error_reponse(
        &mut self,
        peer_id: PeerId,
        id: PeerRequestId,
        error: RPCResponseErrorCode,
        reason: String,
    ) {
        self.eth2_rpc_mut().send_response(
            peer_id,
            id,
            RPCCodedResponse::Error(error, reason.into()),
        )
    }

    /* Peer management functions */

    pub fn testing_dial(&mut self, addr: Multiaddr) -> Result<(), libp2p::swarm::DialError> {
        self.swarm.dial(addr)
    }

    pub fn report_peer(
        &mut self,
        peer_id: &PeerId,
        action: PeerAction,
        source: ReportSource,
        msg: &'static str,
    ) {
        self.peer_manager_mut()
            .report_peer(peer_id, action, source, None, msg);
    }

    /// Disconnects from a peer providing a reason.
    ///
    /// This will send a goodbye, disconnect and then ban the peer.
    /// This is fatal for a peer, and should be used in unrecoverable circumstances.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason, source: ReportSource) {
        self.peer_manager_mut()
            .goodbye_peer(peer_id, reason, source);
    }

    /// Returns an iterator over all enr entries in the DHT.
    pub fn enr_entries(&self) -> Vec<Enr> {
        self.discovery().table_entries_enr()
    }

    /// Add an ENR to the routing table of the discovery mechanism.
    pub fn add_enr(&mut self, enr: Enr) {
        self.discovery_mut().add_enr(enr);
    }

    // /// Updates a subnet value to the ENR attnets/syncnets bitfield.
    // ///
    // /// The `value` is `true` if a subnet is being added and false otherwise.
    // pub fn update_enr_subnet(&mut self, subnet_id: Subnet, value: bool) {
    //     if let Err(e) = self.discovery_mut().update_enr_bitfield(subnet_id, value) {
    //         crit!(self.log, "Could not update ENR bitfield"; "error" => e);
    //     }
    //     // update the local meta data which informs our peers of the update during PINGS
    //     self.update_metadata_bitfields();
    // }

    /// Attempts to discover new peers for a given subnet. The `min_ttl` gives the time at which we
    /// would like to retain the peers for.
    pub fn discover_subnet_peers(&mut self, subnets_to_discover: Vec<SubnetDiscovery>) {
        // If discovery is not started or disabled, ignore the request
        if !self.discovery().started {
            return;
        }

        let filtered: Vec<SubnetDiscovery> = subnets_to_discover
            .into_iter()
            .filter(|s| {
                // // Extend min_ttl of connected peers on required subnets
                // if let Some(min_ttl) = s.min_ttl {
                //     self.network_globals
                //         .peers
                //         .write()
                //         .extend_peers_on_subnet(&s.subnet, min_ttl);
                //     if let Subnet::SyncCommittee(sync_subnet) = s.subnet {
                //         self.peer_manager_mut()
                //             .add_sync_subnet(sync_subnet, min_ttl);
                //     }
                // }
                // Already have target number of peers, no need for subnet discovery
                let peers_on_subnet = self
                    .network_globals
                    .peers
                    .read()
                    .good_peers_on_subnet(/*s.subnet*/)
                    .count();
                if peers_on_subnet >= TARGET_SUBNET_PEERS {
                    trace!(
                        self.log,
                        "Discovery query ignored";
                        "subnet" => ?s.subnet,
                        "reason" => "Already connected to desired peers",
                        "connected_peers_on_subnet" => peers_on_subnet,
                        "target_subnet_peers" => TARGET_SUBNET_PEERS,
                    );
                    false
                // Queue an outgoing connection request to the cached peers that are on `s.subnet_id`.
                // If we connect to the cached peers before the discovery query starts, then we potentially
                // save a costly discovery query.
                } else {
                    // self.dial_cached_enrs_in_subnet(s.subnet);
                    true
                }
            })
            .collect();

        // request the subnet query from discovery
        if !filtered.is_empty() {
            self.discovery_mut().discover_subnet_peers(filtered);
        }
    }

    // /// Updates the local ENR's "eth2" field with the latest EnrForkId.
    // pub fn update_fork_version(&mut self, enr_fork_id: EnrForkId) {
    //     self.discovery_mut().update_eth2_enr(enr_fork_id.clone());

    //     // update the local reference
    //     self.enr_fork_id = enr_fork_id;
    // }

    /* Private internal functions */

    // /// Updates the current meta data of the node to match the local ENR.
    // fn update_metadata_bitfields(&mut self) {
    //     let local_mempool_nets = self
    //         .discovery_mut()
    //         .local_enr()
    //         .mempools_bitfield::()
    //         .expect("Local discovery must have attestation bitfield");

    //     // let local_syncnets = self
    //     //     .discovery_mut()
    //     //     .local_enr()
    //     //     .sync_committee_bitfield::()
    //     //     .expect("Local discovery must have sync committee bitfield");

    //     {
    //         // write lock scope
    //         let mut meta_data = self.network_globals.local_metadata.write();

    //         meta_data.seq_number += 1;
    //         meta_data.mempool_nets = local_mempool_nets;
    //         // if let Ok(syncnets) = meta_data.syncnets_mut() {
    //         //     *syncnets = local_syncnets;
    //         // }
    //     }
    //     // Save the updated metadata to disk
    //     utils::save_metadata_to_disk(
    //         &self.network_dir,
    //         self.network_globals.local_metadata.read().clone(),
    //         &self.log,
    //     );
    // }

    /// Sends a Ping request to the peer.
    fn ping(&mut self, peer_id: PeerId) {
        let ping = crate::rpc::Ping {
            data: self.network_globals.local_metadata.read().seq_number,
        };
        trace!(self.log, "Sending Ping"; "peer_id" => %peer_id);
        let id = RequestId::Internal;
        self.eth2_rpc_mut()
            .send_request(peer_id, id, OutboundRequest::Ping(ping));
    }

    /// Sends a Pong response to the peer.
    fn pong(&mut self, id: PeerRequestId, peer_id: PeerId) {
        let ping = crate::rpc::Ping {
            data: self.network_globals.local_metadata.read().seq_number,
        };
        trace!(self.log, "Sending Pong"; "request_id" => id.1, "peer_id" => %peer_id);
        let event = RPCCodedResponse::Success(RPCResponse::Pong(ping));
        self.eth2_rpc_mut().send_response(peer_id, id, event);
    }

    /// Sends a METADATA request to a peer.
    fn send_meta_data_request(&mut self, peer_id: PeerId) {
        // We always prefer sending V2 requests
        let event = OutboundRequest::MetaData(MetadataRequest::new());
        self.eth2_rpc_mut()
            .send_request(peer_id, RequestId::Internal, event);
    }

    /// Sends a METADATA response to a peer.
    fn send_meta_data_response(
        &mut self,
        req: MetadataRequest,
        id: PeerRequestId,
        peer_id: PeerId,
    ) {
        let metadata = self.network_globals.local_metadata.read().clone();
        // let metadata = match req {
        //     MetadataRequest::V1(_) => metadata.metadata(),
        //     MetadataRequest::V2(_) => metadata,
        // };
        let event = RPCCodedResponse::Success(RPCResponse::MetaData(metadata));
        self.eth2_rpc_mut().send_response(peer_id, id, event);
    }

    // RPC Propagation methods
    /// Queues the response to be sent upwards as long at it was requested outside the Behaviour.
    #[must_use = "return the response"]
    fn build_response(
        &mut self,
        id: RequestId<AppReqId>,
        peer_id: PeerId,
        response: Response,
    ) -> Option<NetworkEvent<AppReqId>> {
        match id {
            RequestId::Application(id) => Some(NetworkEvent::ResponseReceived {
                peer_id,
                id,
                response,
            }),
            RequestId::Internal => {

                match response{
                    Response::Status(_) => {None},
                    Response::PooledUserOpHashes(_) => {
                        Some(NetworkEvent::ResponseReceivedFromInternal {
                            peer_id,
                            response,
                        })
                    },
                    Response::PooledUserOpsByHashV07(_) => {
                        Some(NetworkEvent::ResponseReceivedFromInternal {
                            peer_id,
                            response,
                        })
                    },
                    Response::PooledUserOpsByHashV06(_) => {
                        Some(NetworkEvent::ResponseReceivedFromInternal {
                            peer_id,
                            response,
                        })
                    },
                }    

                // Some(NetworkEvent::ResponseReceivedFromInternal {
                //     peer_id,
                //     response,
                // })
        
        },
        }
    }

    /// Convenience function to propagate a request.
    #[must_use = "actually return the event"]
    fn build_request(
        &mut self,
        id: PeerRequestId,
        peer_id: PeerId,
        request: Request,
    ) -> NetworkEvent<AppReqId> {
        // Increment metrics
        match &request {
            Request::Status(_) => {
                metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["status"])
            }
            Request::PooledUserOpHashes { .. } => {
                metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["pooled_user_op_hashes"])
            }
            Request::PooledUserOpsByHash { .. } => {
                metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["pooled_user_ops_by_hash"])
            }
        }
        NetworkEvent::RequestReceived {
            peer_id,
            id,
            request,
        }
    }

    /// Dial cached Enrs in discovery service that are in the given `subnet_id` and aren't
    /// in Connected, Dialing or Banned state.
    fn dial_cached_enrs_in_subnet(&mut self, subnet: Subnet) {
        // let predicate = subnet_predicate(vec![subnet], &self.log);
        let peers_to_dial: Vec<Enr> = self
            .discovery()
            .cached_enrs()
            .filter_map(|(_peer_id, enr)| {
                // if predicate(enr) {
                //     Some(enr.clone())
                // } else {
                //     None
                // }
                None
            })
            .collect();

        // Remove the ENR from the cache to prevent continual re-dialing on disconnects
        for enr in peers_to_dial {
            debug!(self.log, "Dialing cached ENR peer"; "peer_id" => %enr.peer_id());
            self.discovery_mut().remove_cached_enr(&enr.peer_id());
            self.peer_manager_mut().dial_peer(enr);
        }
    }

    /* Sub-behaviour event handling functions */

    /// Handle a gossipsub event.
    fn inject_gs_event(
        &mut self,
        event: gossipsub::Event,
    ) -> Option<NetworkEvent<AppReqId>> {
        let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
        let mut subscriptions_iter = subscriptions.iter();
        let topic_v07 = subscriptions_iter.next().unwrap();
        let topic_v06 = subscriptions_iter.next().unwrap();
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message_id: id,
                message: gs_msg,
            } => {
                // Note: We are keeping track here of the peer that sent us the message, not the
                // peer that originally published the message.
                match PubsubMessage::decode(&gs_msg.topic, &gs_msg.data, topic_v07, topic_v06) {
                    Err(e) => {
                        debug!(self.log, "Could not decode gossipsub message"; "topic" => ?gs_msg.topic,"error" => e);
                        //reject the message
                        if let Err(e) = self.gossipsub_mut().report_message_validation_result(
                            &id,
                            &propagation_source,
                            MessageAcceptance::Reject,
                        ) {
                            warn!(self.log, "Failed to report message validation"; "message_id" => %id, "peer_id" => %propagation_source, "error" => ?e);
                        }
                    }
                    Ok(msg) => {
                        // Notify the network
                        return Some(NetworkEvent::PubsubMessage {
                            id,
                            source: propagation_source,
                            topic: gs_msg.topic,
                            message: msg,
                        });
                    }
                }
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                if let Ok(topic) = GossipTopic::decode(topic.as_str(), topic_v07, topic_v06) {
                    // if let Some(subnet_id) = topic.subnet_id() {
                    //     self.network_globals
                    //         .peers
                    //         .write()
                    //         .add_subscription(&peer_id, subnet_id);
                    // }
                    // Try to send the cached messages for this topic
                    if let Some(msgs) = self.gossip_cache.retrieve(&topic) {
                        for data in msgs {
                            let topic_str: &str = topic.kind().as_ref();
                            match self
                                .swarm
                                .behaviour_mut()
                                .gossipsub
                                .publish(Topic::from(topic.clone()), data)
                            {
                                Ok(_) => {
                                    warn!(self.log, "Gossip message published on retry"; "topic" => topic_str);
                                    if let Some(v) = metrics::get_int_counter(
                                        &metrics::GOSSIP_LATE_PUBLISH_PER_TOPIC_KIND,
                                        &[topic_str],
                                    ) {
                                        v.inc()
                                    };
                                }
                                Err(e) => {
                                    warn!(self.log, "Gossip message publish failed on retry"; "topic" => topic_str, "error" => %e);
                                    if let Some(v) = metrics::get_int_counter(
                                        &metrics::GOSSIP_FAILED_LATE_PUBLISH_PER_TOPIC_KIND,
                                        &[topic_str],
                                    ) {
                                        v.inc()
                                    };
                                }
                            }
                        }
                    }
                }
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                // if let Some(subnet_id) = subnet_from_topic_hash(&topic) {
                //     self.network_globals
                //         .peers
                //         .write()
                //         .remove_subscription(&peer_id, &subnet_id);
                // }
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                debug!(self.log, "Peer does not support gossipsub"; "peer_id" => %peer_id);
                self.peer_manager_mut().report_peer(
                    &peer_id,
                    PeerAction::Fatal,
                    ReportSource::Gossipsub,
                    Some(GoodbyeReason::Unknown),
                    "does_not_support_gossipsub",
                );
            }
        }
        None
    }

    /// Handle an RPC event.
    fn inject_rpc_event(
        &mut self,
        event: RPCMessage<RequestId<AppReqId>>,
    ) -> Option<NetworkEvent<AppReqId>> {
        let peer_id = event.peer_id;

        if !self.peer_manager().is_connected(&peer_id) {
            debug!(
                self.log,
                "Ignoring rpc message of disconnecting peer";
                event
            );
            return None;
        }

        let handler_id = event.conn_id;
        // The METADATA and PING RPC responses are handled within the behaviour and not propagated
        match event.event {    
            Err(handler_err) => {
                match handler_err {
                    HandlerErr::Inbound {
                        id: _,
                        proto,
                        error,
                    } => {
                        // Inform the peer manager of the error.
                        // An inbound error here means we sent an error to the peer, or the stream
                        // timed out.
                        self.peer_manager_mut().handle_rpc_error(
                            &peer_id,
                            proto,
                            &error,
                            ConnectionDirection::Incoming,
                        );
                        None
                    }
                    HandlerErr::Outbound { id, proto, error } => {
                        // Inform the peer manager that a request we sent to the peer failed
                        self.peer_manager_mut().handle_rpc_error(
                            &peer_id,
                            proto,
                            &error,
                            ConnectionDirection::Outgoing,
                        );
                        // inform failures of requests comming outside the behaviour
                        if let RequestId::Application(id) = id {
                            Some(NetworkEvent::RPCFailed { peer_id, id })
                        } else {
                            None
                        }
                    }
                }
            }
            Ok(RPCReceived::Request(id, request)) => {
                let peer_request_id = (handler_id, id);
                match request {
                    /* Behaviour managed protocols: Ping and Metadata */
                    InboundRequest::Ping(ping) => {
                        // inform the peer manager and send the response
                        self.peer_manager_mut().ping_request(&peer_id, ping.data);
                        // send a ping response
                        self.pong(peer_request_id, peer_id);
                        None
                    }
                    InboundRequest::MetaData(req) => {
                        // send the requested meta-data
                        self.send_meta_data_response(req, (handler_id, id), peer_id);
                        None
                    }
                    InboundRequest::Goodbye(reason) => {
                        // queue for disconnection without a goodbye message
                        debug!(
                            self.log, "Peer sent Goodbye";
                            "peer_id" => %peer_id,
                            "reason" => %reason,
                            "client" => %self.network_globals.client(&peer_id),
                        );
                        // NOTE: We currently do not inform the application that we are
                        // disconnecting here. The RPC handler will automatically
                        // disconnect for us.
                        // The actual disconnection event will be relayed to the application.
                        None
                    }
                    /* Protocols propagated to the Network */
                    InboundRequest::Status(msg) => {
                        // inform the peer manager that we have received a status from a peer
                        self.peer_manager_mut().peer_statusd(&peer_id);
                        // propagate the STATUS message upwards
                        let event =
                            self.build_request(peer_request_id, peer_id, Request::Status(msg));
                        Some(event)
                    }
                    InboundRequest::PooledUserOpHashes(msg) => {
                        let event = self.build_request(
                            peer_request_id, peer_id, Request::PooledUserOpHashes(msg)
                        );
                        Some(event)
                    },
                    InboundRequest::PooledUserOpsByHash(msg) =>{
                        let event = self.build_request(
                            peer_request_id, peer_id, Request::PooledUserOpsByHash(msg)
                        );
                        Some(event)
                    },
                }
            }
            Ok(RPCReceived::Response(id, resp)) => {
                match resp {
                    /* Behaviour managed protocols */
                    RPCResponse::Pong(ping) => {
                        self.peer_manager_mut().pong_response(&peer_id, ping.data);
                        None
                    }
                    RPCResponse::MetaData(meta_data) => {
                        self.peer_manager_mut()
                            .meta_data_response(&peer_id, meta_data);
                        None
                    }
                    /* Network propagated protocols */
                    RPCResponse::Status(msg) => {
                        // inform the peer manager that we have received a status from a peer
                        self.peer_manager_mut().peer_statusd(&peer_id);
                        // propagate the STATUS message upwards
                        self.build_response(id, peer_id, Response::Status(msg))
                    }
                    RPCResponse::PooledUserOpHashes(pooled_user_op_hashes) => {
                        self.build_response(id, peer_id, Response::PooledUserOpHashes(Some(pooled_user_op_hashes)))
                    }
                    RPCResponse::PooledUserOpsByHashV07(resp) => {
                        self.build_response(id, peer_id, Response::PooledUserOpsByHashV07(Some(resp)))
                    }
                    RPCResponse::PooledUserOpsByHashV06(resp) => {
                        self.build_response(id, peer_id, Response::PooledUserOpsByHashV06(Some(resp)))
                    }
                }
            }
            Ok(RPCReceived::EndOfStream(id, termination)) => {

                let response = match termination {
                    ResponseTermination::PooledUserOpHashes => Response::PooledUserOpHashes(None),
                    ResponseTermination::PooledUserOpsByHashV07 => Response::PooledUserOpsByHashV07(None),
                    ResponseTermination::PooledUserOpsByHashV06 => Response::PooledUserOpsByHashV06(None),
                };
              
                self.build_response(id, peer_id, response)
            }
        }
    }

    /// Handle an identify event.
    fn inject_identify_event(
        &mut self,
        event: identify::Event,
    ) -> Option<NetworkEvent<AppReqId>> {
        match event {
            identify::Event::Received { peer_id, mut info } => {
                if info.listen_addrs.len() > MAX_IDENTIFY_ADDRESSES {
                    debug!(
                        self.log,
                        "More than 10 addresses have been identified, truncating"
                    );
                    info.listen_addrs.truncate(MAX_IDENTIFY_ADDRESSES);
                }
                // send peer info to the peer manager.
                self.peer_manager_mut().identify(&peer_id, &info);
            }
            identify::Event::Sent { .. } => {}
            identify::Event::Error { .. } => {}
            identify::Event::Pushed { .. } => {}
        }
        None
    }

    /// Handle a peer manager event.
    fn inject_pm_event(
        &mut self,
        event: PeerManagerEvent,
    ) -> Option<NetworkEvent<AppReqId>> {
        match event {
            PeerManagerEvent::PeerConnectedIncoming(peer_id) => {
                Some(NetworkEvent::PeerConnectedIncoming(peer_id))
            }
            PeerManagerEvent::PeerConnectedOutgoing(peer_id) => {
                Some(NetworkEvent::PeerConnectedOutgoing(peer_id))
            }
            PeerManagerEvent::PeerDisconnected(peer_id) => {
                Some(NetworkEvent::PeerDisconnected(peer_id))
            }
            PeerManagerEvent::Banned(peer_id, associated_ips) => {
                self.swarm.behaviour_mut().banned_peers.block_peer(peer_id);
                self.discovery_mut().ban_peer(&peer_id, associated_ips);
                None
            }
            PeerManagerEvent::UnBanned(peer_id, associated_ips) => {
                self.swarm
                    .behaviour_mut()
                    .banned_peers
                    .unblock_peer(peer_id);
                self.discovery_mut().unban_peer(&peer_id, associated_ips);
                None
            }
            PeerManagerEvent::Status(peer_id) => {
                // it's time to status. We don't keep a beacon chain reference here, so we inform
                // the network to send a status to this peer
                Some(NetworkEvent::StatusPeer(peer_id))
            }
            PeerManagerEvent::DiscoverPeers(peers_to_find) => {
                // Peer manager has requested a discovery query for more peers.
                self.discovery_mut().discover_peers(peers_to_find);
                None
            }
            PeerManagerEvent::DiscoverSubnetPeers(subnets_to_discover) => {
                // Peer manager has requested a subnet discovery query for more peers.
                self.discover_subnet_peers(subnets_to_discover);
                None
            }
            PeerManagerEvent::Ping(peer_id) => {
                // send a ping request to this peer
                self.ping(peer_id);
                None
            }
            PeerManagerEvent::MetaData(peer_id) => {
                self.send_meta_data_request(peer_id);
                None
            }
            PeerManagerEvent::DisconnectPeer(peer_id, reason) => {
                debug!(self.log, "Peer Manager disconnecting peer";
                       "peer_id" => %peer_id, "reason" => %reason);
                // send one goodbye
                self.eth2_rpc_mut()
                    .shutdown(peer_id, RequestId::Internal, reason);
                None
            }
        }
    }

    /* Networking polling */

    /// Poll the p2p networking stack.
    ///
    /// This will poll the swarm and do maintenance routines.
    pub fn poll_network(&mut self, cx: &mut Context) -> Poll<NetworkEvent<AppReqId>> {
        while let Poll::Ready(Some(swarm_event)) = self.swarm.poll_next_unpin(cx) {
            // println!("maybe_event {:?}", swarm_event);
            let maybe_event = match swarm_event {
                SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                    // Handle sub-behaviour events.
                    BehaviourEvent::BannedPeers(void) => void::unreachable(void),
                    BehaviourEvent::Gossipsub(ge) => self.inject_gs_event(ge),
                    BehaviourEvent::Eth2Rpc(re) => self.inject_rpc_event(re),
                    // Inform the peer manager about discovered peers.
                    //
                    // The peer manager will subsequently decide which peers need to be dialed and then dial
                    // them.
                    BehaviourEvent::Discovery(DiscoveredPeers { peers }) => {
                        self.peer_manager_mut().peers_discovered(peers);
                        None
                    }
                    BehaviourEvent::Identify(ie) => self.inject_identify_event(ie),
                    BehaviourEvent::PeerManager(pe) => self.inject_pm_event(pe),
                    BehaviourEvent::ConnectionLimits(le) => void::unreachable(le),
                },
                SwarmEvent::ConnectionEstablished { .. } => None,
                SwarmEvent::ConnectionClosed { .. } => None,
                SwarmEvent::IncomingConnection {
                    local_addr,
                    send_back_addr,
                    connection_id: _,
                } => {
                    trace!(self.log, "Incoming connection"; "our_addr" => %local_addr, "from" => %send_back_addr);
                    None
                }
                SwarmEvent::IncomingConnectionError {
                    local_addr,
                    send_back_addr,
                    error,
                    connection_id: _,
                } => {
                    let error_repr = match error {
                        libp2p::swarm::ListenError::Aborted => {
                            "Incoming connection aborted".to_string()
                        }
                        libp2p::swarm::ListenError::WrongPeerId { obtained, endpoint } => {
                            format!("Wrong peer id, obtained {obtained}, endpoint {endpoint:?}")
                        }
                        libp2p::swarm::ListenError::LocalPeerId { endpoint } => {
                            format!("Dialing local peer id {endpoint:?}")
                        }
                        libp2p::swarm::ListenError::Denied { cause } => {
                            format!("Connection was denied with cause: {cause:?}")
                        }
                        libp2p::swarm::ListenError::Transport(t) => match t {
                            libp2p::TransportError::MultiaddrNotSupported(m) => {
                                format!("Transport error: Multiaddr not supported: {m}")
                            }
                            libp2p::TransportError::Other(e) => {
                                format!("Transport error: other: {e}")
                            }
                        },
                    };
                    debug!(self.log, "Failed incoming connection"; "our_addr" => %local_addr, "from" => %send_back_addr, "error" => error_repr);
                    None
                }
                SwarmEvent::OutgoingConnectionError {
                    peer_id: _,
                    error: _,
                    connection_id: _,
                } => {
                    // The Behaviour event is more general than the swarm event here. It includes
                    // connection failures. So we use that log for now, in the peer manager
                    // behaviour implementation.
                    None
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    Some(NetworkEvent::NewListenAddr(address))
                }
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    debug!(self.log, "Listen address expired"; "address" => %address);
                    None
                }
                SwarmEvent::ListenerClosed {
                    addresses, reason, ..
                } => {
                    crit!(self.log, "Listener closed"; "addresses" => ?addresses, "reason" => ?reason);
                    if Swarm::listeners(&self.swarm).count() == 0 {
                        Some(NetworkEvent::ZeroListeners)
                    } else {
                        None
                    }
                }
                SwarmEvent::ListenerError { error, .. } => {
                    // this is non fatal, but we still check
                    warn!(self.log, "Listener error"; "error" => ?error);
                    if Swarm::listeners(&self.swarm).count() == 0 {
                        Some(NetworkEvent::ZeroListeners)
                    } else {
                        None
                    }
                }
                SwarmEvent::Dialing { .. } => None,
            };

            if let Some(ev) = maybe_event {
                return Poll::Ready(ev);
            }
        }

        // perform gossipsub score updates when necessary
        while self.update_gossipsub_scores.poll_tick(cx).is_ready() {
            let this = self.swarm.behaviour_mut();
            this.peer_manager.update_gossipsub_scores(&this.gossipsub);
        }

        // poll the gossipsub cache to clear expired messages
        while let Poll::Ready(Some(result)) = self.gossip_cache.poll_next_unpin(cx) {
            match result {
                Err(e) => warn!(self.log, "Gossip cache error"; "error" => e),
                Ok(expired_topic) => {
                    if let Some(v) = metrics::get_int_counter(
                        &metrics::GOSSIP_EXPIRED_LATE_PUBLISH_PER_TOPIC_KIND,
                        &[expired_topic.kind().as_ref()],
                    ) {
                        v.inc()
                    };
                }
            }
        }
        Poll::Pending
    }

    pub async fn next_event(&mut self) -> NetworkEvent<AppReqId> {
        futures::future::poll_fn(|cx| self.poll_network(cx)).await
    }
}
