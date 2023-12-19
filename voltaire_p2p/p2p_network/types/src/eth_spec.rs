use crate::*;
use crate::chain_spec::ChainSpec;

use safe_arith::SafeArith;
use serde_derive::{Deserialize, Serialize};
use ssz_types::typenum::{
    bit::B0, UInt, Unsigned, U0, U1024, U1048576, U1073741824, U1099511627776, U128, U16,
    U16777216, U2, U2048, U256, U32, U4, U4096, U512, U625, U64, U65536, U8, U8192,
};
use std::fmt::{self, Debug};
use std::str::FromStr;

pub type U5000 = UInt<UInt<UInt<U625, B0>, B0>, B0>; // 625 * 8 = 5000

const MAINNET: &str = "mainnet";
const MINIMAL: &str = "minimal";
pub const GNOSIS: &str = "gnosis";

/// Used to identify one of the `EthSpec` instances defined here.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EthSpecId {
    Mainnet,
    Minimal,
    Gnosis,
}

impl FromStr for EthSpecId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            MAINNET => Ok(EthSpecId::Mainnet),
            MINIMAL => Ok(EthSpecId::Minimal),
            GNOSIS => Ok(EthSpecId::Gnosis),
            _ => Err(format!("Unknown eth spec: {}", s)),
        }
    }
}

impl fmt::Display for EthSpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EthSpecId::Mainnet => MAINNET,
            EthSpecId::Minimal => MINIMAL,
            EthSpecId::Gnosis => GNOSIS,
        };
        write!(f, "{}", s)
    }
}

pub trait EthSpec:
    'static + Default + Sync + Send + Clone + Debug  + Eq + for<'a> arbitrary::Arbitrary<'a>
{
    /*
     * Constants
     */
    type GenesisEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MempoolNetsBitfieldLength: Unsigned + Clone + Sync + Send + Debug + PartialEq + Default;
    type SyncCommitteeSubnetCount: Unsigned + Clone + Sync + Send + Debug + PartialEq;


    fn default_spec() -> ChainSpec;

    fn spec_name() -> EthSpecId;
}

/// Ethereum Foundation specifications.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct MainnetEthSpec;

impl EthSpec for MainnetEthSpec {
    type GenesisEpoch = U0;
    type MempoolNetsBitfieldLength = U64;
    type SyncCommitteeSubnetCount = U4;

    fn default_spec() -> ChainSpec {
        ChainSpec::mainnet()
    }

    fn spec_name() -> EthSpecId {
        EthSpecId::Mainnet
    }
}

/// Ethereum Foundation minimal spec, as defined in the eth2.0-specs repo.
#[derive(Copy,Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct MinimalEthSpec;

impl EthSpec for MinimalEthSpec {
    type GenesisEpoch = U0;
    type MempoolNetsBitfieldLength = U64;
    type SyncCommitteeSubnetCount = U4;

    fn default_spec() -> ChainSpec {
        ChainSpec::minimal()
    }

    fn spec_name() -> EthSpecId {
        EthSpecId::Minimal
    }
}