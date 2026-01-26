use crate::multiaddr::Protocol;
use crate::rpc::MetaData;
use crate::types::{GossipEncoding, GossipKind};
use crate::{GossipTopic, NetworkConfig};
use futures::future::Either;
use libp2p::core::{multiaddr::Multiaddr, muxing::StreamMuxerBox, transport::Boxed};
use libp2p::gossipsub;
use libp2p::identity::{secp256k1, Keypair};
use libp2p::{core, noise, quic, yamux, PeerId, Transport};
use prometheus_client::registry::Registry;
use slog::{debug, warn};
use ssz::Decode;
use ssz::Encode;
use ssz_types::VariableList;
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::time::Duration;

pub const NETWORK_KEY_FILENAME: &str = "key";
/// The maximum simultaneous libp2p connections per peer.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 1;
/// The filename to store our local metadata.
pub const METADATA_FILENAME: &str = "metadata";

pub struct Context<'a> {
    pub config: &'a NetworkConfig,
    pub gossipsub_registry: Option<&'a mut Registry>,
}

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

/// The implementation supports TCP/IP, QUIC (experimental) over UDP, noise as the encryption layer, and
/// mplex/yamux as the multiplexing layer (when using TCP).
pub fn build_transport(
    local_private_key: Keypair,
    quic_support: bool,
) -> std::io::Result<BoxedTransport> {
    // mplex config
    let mut mplex_config = libp2p_mplex::Config::new();
    mplex_config.set_max_buffer_size(256);
    mplex_config.set_max_buffer_behaviour(libp2p_mplex::MaxBufferBehaviour::Block);

    // yamux config
    let yamux_config = yamux::Config::default();

    // Creates the TCP transport layer
    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true))
        .upgrade(core::upgrade::Version::V1)
        .authenticate(generate_noise_config(&local_private_key))
        .multiplex(core::upgrade::SelectUpgrade::new(
            yamux_config,
            mplex_config,
        ))
        .timeout(Duration::from_secs(10));

    let transport = if quic_support {
        // Enables Quic
        // The default quic configuration suits us for now.
        let quic_config = quic::Config::new(&local_private_key);
        tcp.or_transport(quic::tokio::Transport::new(quic_config))
            .map(|either_output, _| match either_output {
                Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
                Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            })
            .boxed()
    } else {
        tcp.map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer))).boxed()
    };

    let transport = libp2p::dns::tokio::Transport::system(transport)?.boxed();

    Ok(transport)
}

/// Loads a private key from disk. If this fails, a new key is
/// generated and is then saved to disk.
///
/// Currently only secp256k1 keys are allowed, as these are the only keys supported by discv5.
pub fn load_private_key(config: &NetworkConfig, log: &slog::Logger) -> Keypair {
    // check for key from disk
    let network_key_f = config.network_dir.join(NETWORK_KEY_FILENAME);
    if let Ok(mut network_key_file) = File::open(network_key_f.clone()) {
        let mut key_bytes: Vec<u8> = Vec::with_capacity(36);
        match network_key_file.read_to_end(&mut key_bytes) {
            Err(_) => debug!(log, "Could not read network key file"),
            Ok(_) => {
                // only accept secp256k1 keys for now
                if let Ok(secret_key) = secp256k1::SecretKey::try_from_bytes(&mut key_bytes) {
                    let kp: secp256k1::Keypair = secret_key.into();
                    debug!(log, "Loaded network key from disk.");
                    return kp.into();
                } else {
                    debug!(log, "Network key file is not a valid secp256k1 key");
                }
            }
        }
    }

    // if a key could not be loaded from disk, generate a new one and save it
    let local_private_key = secp256k1::Keypair::generate();
    let _ = std::fs::create_dir_all(&config.network_dir);
    match File::create(network_key_f.clone())
        .and_then(|mut f| f.write_all(&local_private_key.secret().to_bytes()))
    {
        Ok(_) => {
            debug!(log, "New network key generated and written to disk");
        }
        Err(e) => {
            warn!(
                log,
                "Could not write node key to file: {:?}. error: {}", network_key_f, e
            );
        }
    }
    local_private_key.into()
}

/// Generate authenticated XX Noise config from identity keys
fn generate_noise_config(identity_keypair: &Keypair) -> noise::Config {
    noise::Config::new(identity_keypair).expect("signing can fail only once during starting a node")
}

/// For a multiaddr that ends with a peer id, this strips this suffix. Rust-libp2p
/// only supports dialing to an address without providing the peer id.
pub fn strip_peer_id(addr: &mut Multiaddr) {
    let last = addr.pop();
    match last {
        Some(Protocol::P2p(_)) => {}
        Some(other) => addr.push(other),
        _ => {}
    }
}

/// Load metadata from persisted file. Return default metadata if loading fails.
pub fn load_or_build_metadata(
    network_dir: &std::path::Path,
    log: &slog::Logger,
) -> MetaData {
    // We load a V2 metadata version by default (regardless of current fork)
    // since a V2 metadata can be converted to V1. The RPC encoder is responsible
    // for sending the correct metadata version based on the negotiated protocol version.
    let mut meta_data = MetaData {
        seq_number: 0,
        supported_mempools: VariableList::empty(),
    };
    let metadata_path = network_dir.join(METADATA_FILENAME);
    if let Ok(mut metadata_file) = File::open(metadata_path) {
        let mut metadata_ssz = Vec::new();
        if metadata_file.read_to_end(&mut metadata_ssz).is_ok() {
            match MetaData::from_ssz_bytes(&metadata_ssz) {
                Ok(persisted_metadata) => {
                    meta_data.seq_number = persisted_metadata.seq_number;
                    if persisted_metadata.supported_mempools != meta_data.supported_mempools {
                        meta_data.seq_number += 1;
                    }
                    debug!(log, "Loaded metadata from disk");
                }
                Err(_) => {
                    match MetaData::from_ssz_bytes(&metadata_ssz) {
                        Ok(persisted_metadata) => {
                            meta_data.seq_number = persisted_metadata.seq_number + 1;
                            debug!(log, "Loaded metadata from disk");
                        }
                        Err(e) => {
                            debug!(
                                log,
                                "Metadata from file could not be decoded";
                                "error" => ?e,
                            );
                        }
                    }
                }
            }
        }
    };

    debug!(log, "Metadata sequence number"; "seq_num" => meta_data.seq_number);
    save_metadata_to_disk(network_dir, meta_data.clone(), log);
    meta_data
}

/// Creates a whitelist topic filter that covers all possible topics using the given set of
/// possible mempools.
pub(crate) fn create_whitelist_filter(
    possible_mempools: Vec<String>,
) -> gossipsub::WhitelistSubscriptionFilter {
    let mut possible_hashes = HashSet::new();

    for fork_digest in possible_mempools {
        let mut add = |kind| {
            let topic: gossipsub::IdentTopic =
                GossipTopic::new(kind, GossipEncoding::SSZSnappy, fork_digest.to_string()).into();
            possible_hashes.insert(topic.hash());
        };

        add(GossipKind::VerifiedUserOperationV07V08V09);
        add(GossipKind::VerifiedUserOperationV06);
    }
    gossipsub::WhitelistSubscriptionFilter(possible_hashes)
}

/// Persist metadata to disk
pub(crate) fn save_metadata_to_disk(
    dir: &Path,
    metadata: MetaData,
    log: &slog::Logger,
) {
    let _ = std::fs::create_dir_all(dir);
    let metadata_bytes = metadata.as_ssz_bytes();
    match File::create(dir.join(METADATA_FILENAME)).and_then(|mut f| f.write_all(&metadata_bytes)) {
        Ok(_) => {
            debug!(log, "Metadata written to disk");
        }
        Err(e) => {
            warn!(
                log,
                "Could not write metadata to disk";
                "file" => format!("{:?}{:?}", dir, METADATA_FILENAME),
                "error" => %e
            );
        }
    }
}
