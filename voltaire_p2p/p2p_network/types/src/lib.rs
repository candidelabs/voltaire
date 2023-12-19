pub mod eth_spec;
pub mod enr_fork_id;
pub mod chain_spec;
pub mod subnet_id;
pub mod sync_subnet_id;

pub use crate::eth_spec::EthSpecId;
pub use crate::enr_fork_id::EnrForkId;

pub const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;