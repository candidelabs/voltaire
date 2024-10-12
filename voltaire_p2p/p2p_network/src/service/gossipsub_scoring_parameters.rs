use crate::error;
use libp2p::gossipsub::{
    Config as GossipsubConfig, PeerScoreParams, PeerScoreThresholds,
};

const MAX_IN_MESH_SCORE: f64 = 10.0;
const MAX_FIRST_MESSAGE_DELIVERIES_SCORE: f64 = 40.0;
const BEACON_BLOCK_WEIGHT: f64 = 0.5;
const BEACON_AGGREGATE_PROOF_WEIGHT: f64 = 0.5;
const VOLUNTARY_EXIT_WEIGHT: f64 = 0.05;
const PROPOSER_SLASHING_WEIGHT: f64 = 0.05;
const ATTESTER_SLASHING_WEIGHT: f64 = 0.05;

/// The time window (seconds) that we expect messages to be forwarded to us in the mesh.
const MESH_MESSAGE_DELIVERIES_WINDOW: u64 = 2;

// Const as this is used in the peer manager to prevent gossip from disconnecting peers.
pub const GREYLIST_THRESHOLD: f64 = -16000.0;

/// Builds the peer score thresholds.
pub fn voltaire_gossip_thresholds() -> PeerScoreThresholds {
    PeerScoreThresholds {
        gossip_threshold: -4000.0,
        publish_threshold: -8000.0,
        graylist_threshold: GREYLIST_THRESHOLD,
        accept_px_threshold: 100.0,
        opportunistic_graft_threshold: 5.0,
    }
}

pub struct PeerScoreSettings {
    max_positive_score: f64,
}

impl PeerScoreSettings {
    pub fn new(gs_config: &GossipsubConfig) -> PeerScoreSettings {
        let max_positive_score = (MAX_IN_MESH_SCORE + MAX_FIRST_MESSAGE_DELIVERIES_SCORE)
            * (BEACON_BLOCK_WEIGHT
                + BEACON_AGGREGATE_PROOF_WEIGHT
                + VOLUNTARY_EXIT_WEIGHT
                + PROPOSER_SLASHING_WEIGHT
                + ATTESTER_SLASHING_WEIGHT);

        PeerScoreSettings {
            max_positive_score,
        }
    }

     pub fn get_peer_score_params(
        &self,
        active_validators: usize,
        thresholds: &PeerScoreThresholds,
    ) -> error::Result<PeerScoreParams> {

        let mut params = PeerScoreParams {
            topics: todo!(),
            topic_score_cap: todo!(),
            app_specific_weight: todo!(),
            ip_colocation_factor_weight: todo!(),
            ip_colocation_factor_threshold: todo!(),
            ip_colocation_factor_whitelist: todo!(),
            behaviour_penalty_weight: todo!(),
            behaviour_penalty_threshold: todo!(),
            behaviour_penalty_decay: todo!(),
            decay_interval: todo!(),
            decay_to_zero: todo!(),
            retain_score: todo!(),
        };

        Ok(params)
    }
   
}
