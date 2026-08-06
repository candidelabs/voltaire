pub use lighthouse_metrics::*;

lazy_static! {
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
