//! Handles the encoding and decoding of pubsub messages.

use crate::types::{GossipEncoding, GossipKind, GossipTopic};
use crate::TopicHash;
use libp2p::gossipsub;
use snap::raw::{decompress_len, Decoder, Encoder};
use ssz::{Decode, Encode};
use std::boxed::Box;
use std::io::{Error, ErrorKind};

use super::verified_useroperation::VerifiedUserOperationV06;
use super::verified_useroperation::VerifiedUserOperationV07;


#[derive(Debug, Clone, PartialEq)]
pub enum PubsubMessage {
    VerifiedUserOperationV07(Box<VerifiedUserOperationV07>),
    VerifiedUserOperationV06(Box<VerifiedUserOperationV06>),
}

// Implements the `DataTransform` trait of gossipsub to employ snappy compression
pub struct SnappyTransform {
    /// Sets the maximum size we allow gossipsub messages to decompress to.
    max_size_per_message: usize,
}

impl SnappyTransform {
    pub fn new(max_size_per_message: usize) -> Self {
        SnappyTransform {
            max_size_per_message,
        }
    }
}

impl gossipsub::DataTransform for SnappyTransform {
    // Provides the snappy decompression from RawGossipsubMessages
    fn inbound_transform(
        &self,
        raw_message: gossipsub::RawMessage,
    ) -> Result<gossipsub::Message, std::io::Error> {
        // check the length of the raw bytes
        let len = decompress_len(&raw_message.data)?;
        if len > self.max_size_per_message {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ssz_snappy decoded data > GOSSIP_MAX_SIZE",
            ));
        }

        let mut decoder = Decoder::new();
        let decompressed_data = decoder.decompress_vec(&raw_message.data)?;

        // Build the GossipsubMessage struct
        Ok(gossipsub::Message {
            source: raw_message.source,
            // data:raw_message.data,
            data: decompressed_data,
            sequence_number: raw_message.sequence_number,
            topic: raw_message.topic,
        })
    }

    /// Provides the snappy compression logic to gossipsub.
    fn outbound_transform(
        &self,
        _topic: &TopicHash,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, std::io::Error> {
        // Currently we are not employing topic-based compression. Everything is expected to be
        // snappy compressed.
        if data.len() > self.max_size_per_message {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ssz_snappy Encoded data > GOSSIP_MAX_SIZE",
            ));
        }
        let mut encoder = Encoder::new();
        encoder.compress_vec(&data).map_err(Into::into)
        // Result::Ok(data)
    }
}

impl PubsubMessage {
    /// Returns the topics that each pubsub message will be sent across, given a supported
    /// gossipsub encoding and mempool id.
    pub fn topics(&self, encoding: GossipEncoding, mempool_id: String) -> Vec<GossipTopic> {
        vec![GossipTopic::new(self.kind(), encoding, mempool_id)]
    }

    /// Returns the kind of gossipsub topic associated with the message.
    pub fn kind(&self) -> GossipKind {
        match self {
            PubsubMessage::VerifiedUserOperationV07(_) => GossipKind::VerifiedUserOperationV07,
            PubsubMessage::VerifiedUserOperationV06(_) => GossipKind::VerifiedUserOperationV06,
        }
    }

    /// This decodes `data` into a `PubsubMessage` given a topic.
    /* Note: This is assuming we are not hashing topics. If we choose to hash topics, these will
     * need to be modified.
     */
    pub fn decode(
        topic: &TopicHash,
        data: &[u8],
        topic_v07: &GossipTopic,
        topic_v06: &GossipTopic,
        // fork_context: &ForkContext,
    ) -> Result<Self, String> {
        match GossipTopic::decode(topic.as_str(), topic_v07, topic_v06) {
            Err(err) => Err(format!("Unknown gossipsub topic: {:?}, with error: {}", topic, err)),
            Ok(gossip_topic) => {
                // All topics are currently expected to be compressed and decompressed with snappy.
                // This is done in the `SnappyTransform` struct.
                // Therefore compression has already been handled for us by the time we are
                // decoding the objects here.

                // the ssz decoders
                match gossip_topic.kind() {
                    GossipKind::VerifiedUserOperationV07 => {
                        let verified_useroperation = VerifiedUserOperationV07::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::VerifiedUserOperationV07(Box::new(verified_useroperation)))
                    },
                    GossipKind::VerifiedUserOperationV06 => {
                        let verified_useroperation = VerifiedUserOperationV06::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::VerifiedUserOperationV06(Box::new(verified_useroperation)))
                    },
                }
            }
        }
    }

    /// Encodes a `PubsubMessage` based on the topic encodings. The first known encoding is used. If
    /// no encoding is known, and error is returned.
    pub fn encode(&self, _encoding: GossipEncoding) -> Vec<u8> {
        // Currently do not employ encoding strategies based on the topic. All messages are ssz
        // encoded.
        // Also note, that the compression is handled by the `SnappyTransform` struct. Gossipsub will compress the
        // messages for us.
        match &self {
            PubsubMessage::VerifiedUserOperationV07(data) => data.as_ssz_bytes(),
            PubsubMessage::VerifiedUserOperationV06(data) => data.as_ssz_bytes(),
        }
    }
}

impl std::fmt::Display for PubsubMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubsubMessage::VerifiedUserOperationV07(_data) => write!(f, "UserOperations With EntryPointv0.07"),
            PubsubMessage::VerifiedUserOperationV06(_data) => write!(f, "UserOperations With EntryPointv0.06"),
        }
    }
}
