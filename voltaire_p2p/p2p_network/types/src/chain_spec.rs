
#[derive(arbitrary::Arbitrary, PartialEq, Debug, Clone)]
pub struct ChainSpec {
    pub seconds_per_slot: u64,
}

impl ChainSpec {
     /// Ethereum Foundation minimal spec, as defined in the eth2.0-specs repo.
     pub fn minimal() -> Self {
        Self{
            seconds_per_slot: 6,
        }
     }

     /// Ethereum Foundation minimal spec, as defined in the eth2.0-specs repo.
     pub fn mainnet() -> Self {
        Self{
            seconds_per_slot: 6,
        }
     }
}