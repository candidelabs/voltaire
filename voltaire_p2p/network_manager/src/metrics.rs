pub use lighthouse_metrics::*;
use p2p_voltaire_network::{
    peer_manager::peerdb::client::ClientKind, BandwidthSinks,
};
use std::sync::Arc;
use strum::IntoEnumIterator;

lazy_static! {

    pub static ref BEACON_BLOCK_MESH_PEERS_PER_CLIENT: Result<IntGaugeVec> =
    try_create_int_gauge_vec(
        "block_mesh_peers_per_client",
        "Number of mesh peers for BeaconBlock topic per client",
        &["Client"]
    );

    pub static ref BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "beacon_aggregate_and_proof_mesh_peers_per_client",
            "Number of mesh peers for BeaconAggregateAndProof topic per client",
            &["Client"]
        );


    /*
     * Network queue metrics
     */
    pub static ref NETWORK_RECEIVE_EVENTS: Result<IntCounterVec> = try_create_int_counter_vec(
        "network_receive_events",
        "Count of events received by the channel to the network service",
        &["type"]
    );
    pub static ref NETWORK_RECEIVE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "network_receive_times",
        "Time taken for network to handle an event sent to the network service.",
        &["type"]
    );
}

lazy_static! {

    /*
     * Bandwidth metrics
     */
    pub static ref INBOUND_LIBP2P_BYTES: Result<IntGauge> =
        try_create_int_gauge("libp2p_inbound_bytes", "The inbound bandwidth over libp2p");

    pub static ref OUTBOUND_LIBP2P_BYTES: Result<IntGauge> = try_create_int_gauge(
        "libp2p_outbound_bytes",
        "The outbound bandwidth over libp2p"
    );
    pub static ref TOTAL_LIBP2P_BANDWIDTH: Result<IntGauge> = try_create_int_gauge(
        "libp2p_total_bandwidth",
        "The total inbound/outbound bandwidth over libp2p"
    );

}

pub fn update_bandwidth_metrics(bandwidth: Arc<BandwidthSinks>) {
    set_gauge(&INBOUND_LIBP2P_BYTES, bandwidth.total_inbound() as i64);
    set_gauge(&OUTBOUND_LIBP2P_BYTES, bandwidth.total_outbound() as i64);
    set_gauge(
        &TOTAL_LIBP2P_BANDWIDTH,
        (bandwidth.total_inbound() + bandwidth.total_outbound()) as i64,
    );
}

pub fn update_gossip_metrics () {
    // Mesh peers per client
    // Reset the gauges
    for client_kind in ClientKind::iter() {
        set_gauge_vec(
            &BEACON_BLOCK_MESH_PEERS_PER_CLIENT,
            &[client_kind.as_ref()],
            0_i64,
        );
        set_gauge_vec(
            &BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT,
            &[client_kind.as_ref()],
            0_i64,
        );
    }
}
