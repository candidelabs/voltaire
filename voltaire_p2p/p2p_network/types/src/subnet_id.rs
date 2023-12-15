//! Identifies each shard by an integer identifier.
use serde_derive::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use lazy_static::lazy_static;

const MAX_SUBNET_ID: usize = 64;

lazy_static! {
    static ref SUBNET_ID_TO_STRING: Vec<String> = {
        let mut v = Vec::with_capacity(MAX_SUBNET_ID);

        for i in 0..MAX_SUBNET_ID {
            v.push(i.to_string());
        }
        v
    };
}

#[derive(arbitrary::Arbitrary, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

pub fn subnet_id_to_string(i: u64) -> &'static str {
    if i < MAX_SUBNET_ID as u64 {
        SUBNET_ID_TO_STRING
            .get(i as usize)
            .expect("index below MAX_SUBNET_ID")
    } else {
        "subnet id out of range"
    }
}

impl SubnetId {
    pub fn new(id: u64) -> Self {
        id.into()
    }
}

impl Deref for SubnetId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SubnetId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<u64> for SubnetId {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Into<u64> for SubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl Into<u64> for &SubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl AsRef<str> for SubnetId {
    fn as_ref(&self) -> &str {
        subnet_id_to_string(self.0)
    }
}