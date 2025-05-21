/// https://github.com/sigp/ssz_types/pull/13

use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};


/// Emulates a SSZ `Optional` (distinct from a Rust `Option`).
///
/// This SSZ type is defined in EIP-6475.
///
/// This struct is backed by a Rust `Option` and its behaviour is defined by the variant.
///
/// If `Some`, it will serialize with a 1-byte identifying prefix with a value of 1 followed by the
/// serialized internal type.
/// If `None`, it will serialize as `null`.
///
/// `Optional` will Merklize in the following ways:
/// `if None`: Merklize as an empty `VariableList`
/// `if Some(T)`: Merklize as a `VariableList` of length 1 whose single value is `T`.
///
/// ## Example
///
/// ```
/// use ssz_types::{Optional, typenum::*, VariableList};
/// use tree_hash::TreeHash;
/// use ssz::Encode;
///
/// // Create an `Optional` from an `Option` that is `Some`.
/// let some: Option<u8> = Some(9);
/// let ssz: Optional<u8> = Optional::from(some);
/// let serialized: &[u8] = &ssz.as_ssz_bytes();
/// assert_eq!(serialized, &[1, 9]);
///
/// let root = ssz.tree_hash_root();
/// let equivalent_list: VariableList<u64, U1> = VariableList::from(vec![9; 1]);
/// assert_eq!(root, equivalent_list.tree_hash_root());
///
/// // Create an `Optional` from an `Option` that is `None`.
/// let none: Option<u8> = None;
/// let ssz: Optional<u8> = Optional::from(none);
/// let serialized: &[u8] = &ssz.as_ssz_bytes();
/// let null: &[u8] = &[];
/// assert_eq!(serialized, null);
///
/// let root = ssz.tree_hash_root();
/// let equivalent_list: VariableList<u8, U0> = VariableList::from(vec![]);
/// assert_eq!(root, equivalent_list.tree_hash_root());
///
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: std::hash::Hash"))]
#[serde(transparent)]
pub struct Optional<T> {
    optional: Option<T>,
}

impl<T> From<Option<T>> for Optional<T> {
    fn from(optional: Option<T>) -> Self {
        Self { optional }
    }
}

impl<T> From<Optional<T>> for Option<T> {
    fn from(val: Optional<T>) -> Option<T> {
        val.optional
    }
}

impl<T> Default for Optional<T> {
    fn default() -> Self {
        Self { optional: None }
    }
}


impl<T> ssz::Encode for Optional<T>
where
    T: ssz::Encode,
{
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        match &self.optional {
            None => 0,
            Some(val) => val.ssz_bytes_len() + 1,
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match &self.optional {
            None => (),
            Some(val) => {
                let mut optional_identifier = vec![1];
                buf.append(&mut optional_identifier);
                val.ssz_append(buf)
            }
        }
    }
}

impl<T> ssz::Decode for Optional<T>
where
    T: ssz::Decode,
{
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if let Some((first, rest)) = bytes.split_first() {
            if first == &0x01 {
                return Ok(Optional {
                    optional: Some(T::from_ssz_bytes(&rest)?),
                });
            } else {
                // An `Optional` must always contains `0x01` as the first byte.
                // Might be worth having an explicit error variant in ssz::DecodeError.
                return Err(ssz::DecodeError::BytesInvalid(
                    "Missing Optional identifier byte".to_string(),
                ));
            }
        } else {
            Ok(Optional { optional: None })
        }
    }
}