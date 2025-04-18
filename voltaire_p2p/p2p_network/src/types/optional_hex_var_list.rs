//! Serialize `Option<VariableList<u8, N>>` as 0x-prefixed hex string.
use serde::{Deserializer, Serializer};
use serde_utils::hex::{self, PrefixedHexVisitor};
use ssz::Encode;
use ssz_types::{typenum::Unsigned, VariableList};

pub fn serialize<S, N>(bytes_optional: &Option<VariableList<u8, N>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    N: Unsigned,
{   
    match bytes_optional{
        Some(bytes_optional)=> {
            serializer.serialize_str(&hex::encode(&**bytes_optional))
        },
        None=> {
            serializer.serialize_none()
        }
    }
}

pub fn deserialize<'de, D, N>(deserializer: D) -> Result<Option<VariableList<u8, N>>, D::Error>
where
    D: Deserializer<'de>,
    N: Unsigned,
{ 
    let bytes = deserializer.deserialize_str(PrefixedHexVisitor).unwrap_or(vec![]);
    match VariableList::new(bytes){
        Ok(bytes)  => Ok(if bytes.len() > 0 {Some(bytes)} else {Option::None}),
        Err(e) => return Err(serde::de::Error::custom(format!("invalid variable list: {:?}", e)))
    }
}