use super::config::RateLimiterConfig;
use crate::rpc::Protocol;
use fnv::FnvHashMap;
use libp2p::PeerId;
use serde_derive::{Deserialize, Serialize};
use std::convert::TryInto;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::time::Interval;
// use types::EthSpec;

/// Nanoseconds since a given time.
// Maintained as u64 to reduce footprint
// NOTE: this also implies that the rate limiter will manage checking if a batch is allowed for at
//       most <init time> + u64::MAX nanosecs, ~500 years. So it is realistic to assume this is fine.
type Nanosecs = u64;

/// User-friendly rate limiting parameters of the GCRA.
///
/// A quota of `max_tokens` tokens every `replenish_all_every` units of time means that:
/// 1. One token is replenished every `replenish_all_every`/`max_tokens` units of time.
/// 2. Instantaneous bursts (batches) of up to `max_tokens` tokens are allowed.
///
/// The above implies that if `max_tokens` is greater than 1, the perceived rate may be higher (but
/// bounded) than the defined rate when instantaneous bursts occur. For instance, for a rate of
/// 4T/2s a first burst of 4T is allowed with subsequent requests of 1T every 0.5s forever,
/// producing a perceived rate over the window of the first 2s of 8T. However, subsequent sliding
/// windows of 2s keep the limit.
///
/// In this scenario using the same rate as above, the sender is always maxing out their tokens,
/// except at seconds 1.5, 3, 3.5 and 4
///
/// ```ignore
///            x
///      used  x
///    tokens  x           x           x
///      at a  x  x  x     x  x        x
///     given  +--+--+--o--+--+--o--o--o--> seconds
///      time  |  |  |  |  |  |  |  |  |
///            0     1     2     3     4
///
///            4  1  1  1  2  1  1  2  3 <= available tokens when the batch is received
/// ```
///
/// For a sender to request a batch of `n`T, they would need to wait at least
/// n*`replenish_all_every`/`max_tokens` units of time since their last request.
///
/// To produce hard limits, set `max_tokens` to 1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// How often are `max_tokens` fully replenished.
    pub(super) replenish_all_every: Duration,
    /// Token limit. This translates on how large can an instantaneous batch of
    /// tokens be.
    pub(super) max_tokens: u64,
}

impl Quota {
    /// A hard limit of one token every `seconds`.
    pub const fn one_every(seconds: u64) -> Self {
        Quota {
            replenish_all_every: Duration::from_secs(seconds),
            max_tokens: 1,
        }
    }

    /// Allow `n` tokens to be use used every `seconds`.
    pub const fn n_every(n: u64, seconds: u64) -> Self {
        Quota {
            replenish_all_every: Duration::from_secs(seconds),
            max_tokens: n,
        }
    }
}

/// Manages rate limiting of requests per peer, with differentiated rates per protocol.
pub struct RPCRateLimiter {
    /// Interval to prune peers for which their timer ran out.
    prune_interval: Interval,
    /// Creation time of the rate limiter.
    init_time: Instant,
    /// Goodbye rate limiter.
    goodbye_rl: Limiter<PeerId>,
    /// Ping rate limiter.
    ping_rl: Limiter<PeerId>,
    /// MetaData rate limiter.
    metadata_rl: Limiter<PeerId>,
    /// Status rate limiter.
    status_rl: Limiter<PeerId>,
    /// pooled_user_op_hashes rate limiter.
    pooled_user_op_hashes_rl: Limiter<PeerId>,
    /// pooled_user_ops_by_hash rate limiter.
    pooled_user_ops_by_hash_rl: Limiter<PeerId>,
}

/// Error type for non conformant requests
#[derive(Debug)]
pub enum RateLimitedErr {
    /// Required tokens for this request exceed the maximum
    TooLarge,
    /// Request does not fit in the quota. Gives the earliest time the request could be accepted.
    TooSoon(Duration),
}

/// User-friendly builder of a `RPCRateLimiter`
#[derive(Default, Clone)]
pub struct RPCRateLimiterBuilder {
    /// Quota for the Goodbye protocol.
    goodbye_quota: Option<Quota>,
    /// Quota for the Ping protocol.
    ping_quota: Option<Quota>,
    /// Quota for the MetaData protocol.
    metadata_quota: Option<Quota>,
    /// Quota for the Status protocol.
    status_quota: Option<Quota>,
    /// Quota for the BlocksByRange protocol.
    pooled_user_op_hashes_quota: Option<Quota>,
    /// Quota for the BlocksByRoot protocol.
    pooled_user_ops_by_hash_quota: Option<Quota>,
}

impl RPCRateLimiterBuilder {
    /// Set a quota for a protocol.
    pub fn set_quota(mut self, protocol: Protocol, quota: Quota) -> Self {
        let q = Some(quota);
        match protocol {
            Protocol::Ping => self.ping_quota = q,
            Protocol::Status => self.status_quota = q,
            Protocol::MetaData => self.metadata_quota = q,
            Protocol::Goodbye => self.goodbye_quota = q,
            Protocol::PooledUserOpHashes => self.pooled_user_op_hashes_quota = q,
            Protocol::PooledUserOpsByHashV07 => self.pooled_user_ops_by_hash_quota = q,
            Protocol::PooledUserOpsByHashV06 => self.pooled_user_ops_by_hash_quota = q,
        }
        self
    }

    pub fn build(self) -> Result<RPCRateLimiter, &'static str> {
        // get our quotas
        let ping_quota = self.ping_quota.ok_or("Ping quota not specified")?;
        let metadata_quota = self.metadata_quota.ok_or("MetaData quota not specified")?;
        let status_quota = self.status_quota.ok_or("Status quota not specified")?;
        let goodbye_quota = self.goodbye_quota.ok_or("Goodbye quota not specified")?;
        let pooled_user_op_hashes_quota = self
            .pooled_user_op_hashes_quota
            .ok_or("pooled_user_op_hashes_quota quota not specified")?;
        let pooled_user_ops_by_hash_quota = self
            .pooled_user_ops_by_hash_quota
            .ok_or("pooled_user_ops_by_hash_quota quota not specified")?;

        // create the rate limiters
        let ping_rl = Limiter::from_quota(ping_quota)?;
        let metadata_rl = Limiter::from_quota(metadata_quota)?;
        let status_rl = Limiter::from_quota(status_quota)?;
        let goodbye_rl = Limiter::from_quota(goodbye_quota)?;
        let pooled_user_op_hashes_rl = Limiter::from_quota(pooled_user_op_hashes_quota)?;
        let pooled_user_ops_by_hash_rl = Limiter::from_quota(pooled_user_ops_by_hash_quota)?;
        // let lcbootstrap_rl = Limiter::from_quota(lcbootstrap_quote)?;

        // check for peers to prune every 30 seconds, starting in 30 seconds
        let prune_every = tokio::time::Duration::from_secs(30);
        let prune_start = tokio::time::Instant::now() + prune_every;
        let prune_interval = tokio::time::interval_at(prune_start, prune_every);
        Ok(RPCRateLimiter {
            prune_interval,
            ping_rl,
            metadata_rl,
            status_rl,
            goodbye_rl,
            pooled_user_op_hashes_rl,
            pooled_user_ops_by_hash_rl,
            // lcbootstrap_rl,
            init_time: Instant::now(),
        })
    }
}

pub trait RateLimiterItem {
    fn protocol(&self) -> Protocol;
    fn expected_responses(&self) -> u64;
}

impl RateLimiterItem for super::InboundRequest {
    fn protocol(&self) -> Protocol {
        self.versioned_protocol().protocol()
    }

    fn expected_responses(&self) -> u64 {
        self.expected_responses()
    }
}

impl RateLimiterItem for super::OutboundRequest {
    fn protocol(&self) -> Protocol {
        self.versioned_protocol().protocol()
    }

    fn expected_responses(&self) -> u64 {
        self.expected_responses()
    }
}
impl RPCRateLimiter {
    pub fn new_with_config(config: RateLimiterConfig) -> Result<Self, &'static str> {
        // Destructure to make sure every configuration value is used.
        let RateLimiterConfig {
            ping_quota,
            meta_data_quota,
            status_quota,
            goodbye_quota,
            pooled_user_op_hashes_quota,
            pooled_user_ops_by_hash_quota,
        } = config;

        Self::builder()
            .set_quota(Protocol::Ping, ping_quota)
            .set_quota(Protocol::MetaData, meta_data_quota)
            .set_quota(Protocol::Status, status_quota)
            .set_quota(Protocol::Goodbye, goodbye_quota)
            .set_quota(Protocol::PooledUserOpHashes, pooled_user_op_hashes_quota)
            .set_quota(Protocol::PooledUserOpsByHashV07, pooled_user_ops_by_hash_quota.clone())
            .set_quota(Protocol::PooledUserOpsByHashV06, pooled_user_ops_by_hash_quota)
            .build()
    }

    /// Get a builder instance.
    pub fn builder() -> RPCRateLimiterBuilder {
        RPCRateLimiterBuilder::default()
    }

    pub fn allows<Item: RateLimiterItem>(
        &mut self,
        peer_id: &PeerId,
        request: &Item,
    ) -> Result<(), RateLimitedErr> {
        let time_since_start = self.init_time.elapsed();
        let tokens = request.expected_responses().max(1);

        let check =
            |limiter: &mut Limiter<PeerId>| limiter.allows(time_since_start, peer_id, tokens);
        let limiter = match request.protocol() {
            Protocol::Ping => &mut self.ping_rl,
            Protocol::Status => &mut self.status_rl,
            Protocol::MetaData => &mut self.metadata_rl,
            Protocol::Goodbye => &mut self.goodbye_rl,
            Protocol::PooledUserOpHashes => &mut self.pooled_user_op_hashes_rl,
            Protocol::PooledUserOpsByHashV07 => &mut self.pooled_user_ops_by_hash_rl,
            Protocol::PooledUserOpsByHashV06 => &mut self.pooled_user_ops_by_hash_rl,
        };
        check(limiter)
    }

    pub fn prune(&mut self) {
        let time_since_start = self.init_time.elapsed();
        self.ping_rl.prune(time_since_start);
        self.status_rl.prune(time_since_start);
        self.metadata_rl.prune(time_since_start);
        self.goodbye_rl.prune(time_since_start);
        self.pooled_user_op_hashes_rl.prune(time_since_start);
        self.pooled_user_ops_by_hash_rl.prune(time_since_start);
    }
}

impl Future for RPCRateLimiter {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        while self.prune_interval.poll_tick(cx).is_ready() {
            self.prune();
        }

        Poll::Pending
    }
}

/// Per key rate limiter using the token bucket / leaky bucket as a meter rate limiting algorithm,
/// with the GCRA implementation.
pub struct Limiter<Key: Hash + Eq + Clone> {
    /// After how long is the bucket considered full via replenishing 1T every `t`.
    tau: Nanosecs,
    /// How often is 1T replenished.
    t: Nanosecs,
    /// Time when the bucket will be full for each peer. TAT (theoretical arrival time) from GCRA.
    tat_per_key: FnvHashMap<Key, Nanosecs>,
}

impl<Key: Hash + Eq + Clone> Limiter<Key> {
    pub fn from_quota(quota: Quota) -> Result<Self, &'static str> {
        if quota.max_tokens == 0 {
            return Err("Max number of tokens should be positive");
        }
        let tau = quota.replenish_all_every.as_nanos();
        if tau == 0 {
            return Err("Replenish time must be positive");
        }
        let t = (tau / quota.max_tokens as u128)
            .try_into()
            .map_err(|_| "total replenish time is too long")?;
        let tau = tau
            .try_into()
            .map_err(|_| "total replenish time is too long")?;
        Ok(Limiter {
            tau,
            t,
            tat_per_key: FnvHashMap::default(),
        })
    }

    pub fn allows(
        &mut self,
        time_since_start: Duration,
        key: &Key,
        tokens: u64,
    ) -> Result<(), RateLimitedErr> {
        let time_since_start = time_since_start.as_nanos() as u64;
        let tau = self.tau;
        let t = self.t;
        // how long does it take to replenish these tokens
        let additional_time = t * tokens;
        if additional_time > tau {
            // the time required to process this amount of tokens is longer than the time that
            // makes the bucket full. So, this batch can _never_ be processed
            return Err(RateLimitedErr::TooLarge);
        }
        // If the key is new, we consider their bucket full (which means, their request will be
        // allowed)
        let tat = self
            .tat_per_key
            .entry(key.clone())
            .or_insert(time_since_start);
        // check how soon could the request be made
        let earliest_time = (*tat + additional_time).saturating_sub(tau);
        // earliest_time is in the future
        if time_since_start < earliest_time {
            Err(RateLimitedErr::TooSoon(Duration::from_nanos(
                /* time they need to wait, i.e. how soon were they */
                earliest_time - time_since_start,
            )))
        } else {
            // calculate the new TAT
            *tat = time_since_start.max(*tat) + additional_time;
            Ok(())
        }
    }

    /// Removes keys for which their bucket is full by `time_limit`
    pub fn prune(&mut self, time_limit: Duration) {
        let lim = &mut (time_limit.as_nanos() as u64);
        // remove those for which tat < lim
        self.tat_per_key.retain(|_k, tat| tat >= lim)
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::rate_limiter::{Limiter, Quota};
    use std::time::Duration;

    #[test]
    fn it_works_a() {
        let mut limiter = Limiter::from_quota(Quota {
            replenish_all_every: Duration::from_secs(2),
            max_tokens: 4,
        })
        .unwrap();
        let key = 10;
        //        x
        //  used  x
        // tokens x           x
        //        x  x  x     x
        //        +--+--+--+--+----> seconds
        //        |  |  |  |  |
        //        0     1     2

        assert!(limiter
            .allows(Duration::from_secs_f32(0.0), &key, 4)
            .is_ok());
        limiter.prune(Duration::from_secs_f32(0.1));
        assert!(limiter
            .allows(Duration::from_secs_f32(0.1), &key, 1)
            .is_err());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.5), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(1.0), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(1.4), &key, 1)
            .is_err());
        assert!(limiter
            .allows(Duration::from_secs_f32(2.0), &key, 2)
            .is_ok());
    }

    #[test]
    fn it_works_b() {
        let mut limiter = Limiter::from_quota(Quota {
            replenish_all_every: Duration::from_secs(2),
            max_tokens: 4,
        })
        .unwrap();
        let key = 10;
        // if we limit to 4T per 2s, check that 4 requests worth 1 token can be sent before the
        // first half second, when one token will be available again. Check also that before
        // regaining a token, another request is rejected

        assert!(limiter
            .allows(Duration::from_secs_f32(0.0), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.1), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.2), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.3), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.4), &key, 1)
            .is_err());
    }
}
