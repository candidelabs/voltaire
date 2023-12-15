use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{Encoding, ProtocolId, RPCError, SupportedProtocol, 
    },
};
use crate::rpc::{InboundRequest, OutboundRequest, RPCCodedResponse, RPCResponse};
use libp2p::bytes::BytesMut;
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;
use ssz::{Decode, Encode};
use ssz_types::VariableList;
use types::eth_spec::EthSpec;
use std::io::Cursor;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio_util::codec::{Decoder, Encoder};
use unsigned_varint::codec::Uvi;

const CONTEXT_BYTES_LEN: usize = 4;
const ERROR_TYPE_MAX: usize = 100000;
const ERROR_TYPE_MIN: usize = 1;


/* Inbound Codec */

pub struct SSZSnappyInboundCodec<TSpec: EthSpec> {
    protocol: ProtocolId,
    inner: Uvi<usize>,
    len: Option<usize>,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
    // fork_context: Arc<ForkContext>,
    phantom: PhantomData<TSpec>,
}

impl<T: EthSpec> SSZSnappyInboundCodec<T> {
    pub fn new(
        protocol: ProtocolId,
        max_packet_size: usize,
        // fork_context: Arc<ForkContext>,
    ) -> Self {
        let uvi_codec = Uvi::default();
        // this encoding only applies to ssz_snappy.
        debug_assert_eq!(protocol.encoding, Encoding::SSZSnappy);

        SSZSnappyInboundCodec {
            inner: uvi_codec,
            protocol,
            len: None,
            phantom: PhantomData,
            // fork_context,
            max_packet_size,
        }
    }
}

// Encoder for inbound streams: Encodes RPC Responses sent to peers.
impl<TSpec: EthSpec> Encoder<RPCCodedResponse<TSpec>> for SSZSnappyInboundCodec<TSpec> {
    type Error = RPCError;

    fn encode(
        &mut self,
        item: RPCCodedResponse<TSpec>,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let bytes = match &item {
            RPCCodedResponse::Success(resp) => match &resp {
                RPCResponse::Status(res) => res.as_ssz_bytes(),
                RPCResponse::PooledUserOpHashes(res) => res.as_ssz_bytes(),
                RPCResponse::PooledUserOpsByHash(res) => res.as_ssz_bytes(),
                RPCResponse::Pong(res) => res.data.as_ssz_bytes(),
                RPCResponse::MetaData(res) =>
                // Encode the correct version of the MetaData response based on the negotiated version.
                {
                    match self.protocol.versioned_protocol {
                        SupportedProtocol::MetaDataV1 => res.metadata().as_ssz_bytes(),
                        // We always send V2 metadata responses from the behaviour
                        // No change required.
                        // SupportedProtocol::MetaDataV2 => res.metadata_v2().as_ssz_bytes(),
                        _ => unreachable!(
                            "We only send metadata responses on negotiating metadata requests"
                        ),
                    }
                }
            },
            RPCCodedResponse::Error(_, err) => err.as_ssz_bytes(),
            RPCCodedResponse::StreamTermination(_) => {
                unreachable!("Code error - attempting to encode a stream termination")
            }
        };
        // SSZ encoded bytes should be within `max_packet_size`
        if bytes.len() > self.max_packet_size {
            return Err(RPCError::InternalError(
                "attempting to encode data > max_packet_size",
            ));
        }

        // // Add context bytes if required
        // if let Some(ref context_bytes) = context_bytes(&self.protocol, &self.fork_context, &item) {
        //     dst.extend_from_slice(context_bytes);
        // }

        // Inserts the length prefix of the uncompressed bytes into dst
        // encoded as a unsigned varint
        self.inner
            .encode(bytes.len(), dst)
            .map_err(RPCError::from)?;

        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

        // Write compressed bytes to `dst`
        dst.extend_from_slice(writer.get_ref());
        Ok(())
    }
}

// Decoder for inbound streams: Decodes RPC requests from peers
impl<TSpec: EthSpec> Decoder for SSZSnappyInboundCodec<TSpec> {
    type Item = InboundRequest<TSpec>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.protocol.versioned_protocol == SupportedProtocol::MetaDataV1 {
            return Ok(Some(InboundRequest::MetaData(MetadataRequest::new())));
        }
        // if self.protocol.versioned_protocol == SupportedProtocol::MetaDataV2 {
        //     return Ok(Some(InboundRequest::MetaData(MetadataRequest::new_v2())));
        // }
        let length = match handle_length(&mut self.inner, &mut self.len, src)? {
            Some(len) => len,
            None => return Ok(None),
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `self.protocol`.
        let ssz_limits = self.protocol.rpc_request_limits();
        if ssz_limits.is_out_of_bounds(length, self.max_packet_size) {
            return Err(RPCError::InvalidData(format!(
                "RPC request length for protocol {:?} is out of bounds, length {}",
                self.protocol.versioned_protocol, length
            )));
        }
        // Calculate worst case compression length for given uncompressed length
        let max_compressed_len = snap::raw::max_compress_len(length) as u64;

        // Create a limit reader as a wrapper that reads only upto `max_compressed_len` from `src`.
        let limit_reader = Cursor::new(src.as_ref()).take(max_compressed_len);
        let mut reader = FrameDecoder::new(limit_reader);
        let mut decoded_buffer = vec![0; length];

        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);
                handle_rpc_request(self.protocol.versioned_protocol, &decoded_buffer)
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

/* Outbound Codec: Codec for initiating RPC requests */
pub struct SSZSnappyOutboundCodec<TSpec: EthSpec> {
    inner: Uvi<usize>,
    len: Option<usize>,
    protocol: ProtocolId,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
//     /// The fork name corresponding to the received context bytes.
//     fork_name: Option<ForkName>,
//     fork_context: Arc<ForkContext>,
    phantom: PhantomData<TSpec>,
}

impl<TSpec: EthSpec> SSZSnappyOutboundCodec<TSpec> {
    pub fn new(
        protocol: ProtocolId,
        max_packet_size: usize,
        // fork_context: Arc<ForkContext>,
    ) -> Self {
        let uvi_codec = Uvi::default();
        // this encoding only applies to ssz_snappy.
        debug_assert_eq!(protocol.encoding, Encoding::SSZSnappy);

        SSZSnappyOutboundCodec {
            inner: uvi_codec,
            protocol,
            max_packet_size,
            len: None,
            // fork_name: None,
            // fork_context,
            phantom: PhantomData,
        }
    }
}

// Encoder for outbound streams: Encodes RPC Requests to peers
impl<TSpec: EthSpec> Encoder<OutboundRequest<TSpec>> for SSZSnappyOutboundCodec<TSpec> {
    type Error = RPCError;

    fn encode(
        &mut self,
        item: OutboundRequest<TSpec>,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let bytes = match item {
            OutboundRequest::Status(req) => req.as_ssz_bytes(),
            OutboundRequest::Goodbye(req) => req.as_ssz_bytes(),
            OutboundRequest::PooledUserOpHashes(req) => req.as_ssz_bytes(),
            OutboundRequest::PooledUserOpsByHash(req) => req.as_ssz_bytes(),
            OutboundRequest::Ping(req) => req.as_ssz_bytes(),
            OutboundRequest::MetaData(_) => return Ok(()), // no metadata to encode
        };
        // SSZ encoded bytes should be within `max_packet_size`
        if bytes.len() > self.max_packet_size {
            return Err(RPCError::InternalError(
                "attempting to encode data > max_packet_size",
            ));
        }

        // Inserts the length prefix of the uncompressed bytes into dst
        // encoded as a unsigned varint
        self.inner
            .encode(bytes.len(), dst)
            .map_err(RPCError::from)?;

        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

        // Write compressed bytes to `dst`
        dst.extend_from_slice(writer.get_ref());
        Ok(())
    }
}

// Decoder for outbound streams: Decodes RPC responses from peers.
//
// The majority of the decoding has now been pushed upstream due to the changing specification.
// We prefer to decode blocks and attestations with extra knowledge about the chain to perform
// faster verification checks before decoding entire blocks/attestations.
impl<TSpec: EthSpec> Decoder for SSZSnappyOutboundCodec<TSpec> {
    type Item = RPCResponse<TSpec>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Read the context bytes if required
        if self.protocol.has_context_bytes() {//&& self.fork_name.is_none() {
            if src.len() >= CONTEXT_BYTES_LEN {
                let context_bytes = src.split_to(CONTEXT_BYTES_LEN);
                let mut result = [0; CONTEXT_BYTES_LEN];
                result.copy_from_slice(context_bytes.as_ref());
                // self.fork_name = Some(context_bytes_to_fork_name(
                //     result,
                //     self.fork_context.clone(),
                // )?);
            } else {
                return Ok(None);
            }
        }
        let length = match handle_length(&mut self.inner, &mut self.len, src)? {
            Some(len) => len,
            None => return Ok(None),
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `self.protocol`.
        let ssz_limits = self
            .protocol
            .rpc_response_limits::<TSpec>(/*&self.fork_context*/);
        if ssz_limits.is_out_of_bounds(length, self.max_packet_size) {
            return Err(RPCError::InvalidData(format!(
                "RPC response length is out of bounds, length {}",
                length
            )));
        }
        // Calculate worst case compression length for given uncompressed length
        let max_compressed_len = snap::raw::max_compress_len(length) as u64;
        // Create a limit reader as a wrapper that reads only upto `max_compressed_len` from `src`.
        let limit_reader = Cursor::new(src.as_ref()).take(max_compressed_len);
        let mut reader = FrameDecoder::new(limit_reader);

        let mut decoded_buffer = vec![0; length];

        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);
                // Safe to `take` from `self.fork_name` as we have all the bytes we need to
                // decode an ssz object at this point.
                // let fork_name = self.fork_name.take();
                handle_rpc_response(self.protocol.versioned_protocol, &decoded_buffer/*, fork_name*/)
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

impl<TSpec: EthSpec> OutboundCodec<OutboundRequest<TSpec>> for SSZSnappyOutboundCodec<TSpec> {
    type CodecErrorType = ErrorType;

    fn decode_error(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::CodecErrorType>, RPCError> {
        let length = match handle_length(&mut self.inner, &mut self.len, src)? {
            Some(len) => len,
            None => return Ok(None),
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `ErrorType`.
        if length > self.max_packet_size || length > ERROR_TYPE_MAX || length < ERROR_TYPE_MIN {
            return Err(RPCError::InvalidData(format!(
                "RPC Error length is out of bounds, length {}",
                length
            )));
        }

        // Calculate worst case compression length for given uncompressed length
        let max_compressed_len = snap::raw::max_compress_len(length) as u64;
        // Create a limit reader as a wrapper that reads only upto `max_compressed_len` from `src`.
        let limit_reader = Cursor::new(src.as_ref()).take(max_compressed_len);
        let mut reader = FrameDecoder::new(limit_reader);
        let mut decoded_buffer = vec![0; length];
        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);
                Ok(Some(ErrorType(VariableList::from_ssz_bytes(
                    &decoded_buffer,
                )?)))
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

/// Handle errors that we get from decoding an RPC message from the stream.
/// `num_bytes_read` is the number of bytes the snappy decoder has read from the underlying stream.
/// `max_compressed_len` is the maximum compressed size for a given uncompressed size.
fn handle_error<T>(
    err: std::io::Error,
    num_bytes: u64,
    max_compressed_len: u64,
) -> Result<Option<T>, RPCError> {
    match err.kind() {
        ErrorKind::UnexpectedEof => {
            // If snappy has read `max_compressed_len` from underlying stream and still can't fill buffer, we have a malicious message.
            // Report as `InvalidData` so that malicious peer gets banned.
            if num_bytes >= max_compressed_len {
                Err(RPCError::InvalidData(format!(
                    "Received malicious snappy message, num_bytes {}, max_compressed_len {}",
                    num_bytes, max_compressed_len
                )))
            } else {
                // Haven't received enough bytes to decode yet, wait for more
                Ok(None)
            }
        }
        _ => Err(err).map_err(RPCError::from),
    }
}

/// Decodes the length-prefix from the bytes as an unsigned protobuf varint.
///
/// Returns `Ok(Some(length))` by decoding the bytes if required.
/// Returns `Ok(None)` if more bytes are needed to decode the length-prefix.
/// Returns an `RPCError` for a decoding error.
fn handle_length(
    uvi_codec: &mut Uvi<usize>,
    len: &mut Option<usize>,
    bytes: &mut BytesMut,
) -> Result<Option<usize>, RPCError> {
    if let Some(length) = len {
        Ok(Some(*length))
    } else {
        // Decode the length of the uncompressed bytes from an unsigned varint
        // Note: length-prefix of > 10 bytes(uint64) would be a decoding error
        match uvi_codec.decode(bytes).map_err(RPCError::from)? {
            Some(length) => {
                *len = Some(length);
                Ok(Some(length))
            }
            None => Ok(None), // need more bytes to decode length
        }
    }
}

/// Decodes an `InboundRequest` from the byte stream.
/// `decoded_buffer` should be an ssz-encoded bytestream with
// length = length-prefix received in the beginning of the stream.
fn handle_rpc_request<T: EthSpec>(
    versioned_protocol: SupportedProtocol,
    decoded_buffer: &[u8],
) -> Result<Option<InboundRequest<T>>, RPCError> {
    match versioned_protocol {
        SupportedProtocol::StatusV1 => Ok(Some(InboundRequest::Status(
            StatusMessage::from_ssz_bytes(decoded_buffer)?,
        ))),
        SupportedProtocol::GoodbyeV1 => Ok(Some(InboundRequest::Goodbye(
            GoodbyeReason::from_ssz_bytes(decoded_buffer)?,
        ))),
        SupportedProtocol::PooledUserOpHashesV1 => Ok(Some(InboundRequest::PooledUserOpHashes(
            PooledUserOpHashesRequest::from_ssz_bytes(decoded_buffer)?,
        ))),
        SupportedProtocol::PooledUserOpsByHashV1 => Ok(Some(InboundRequest::PooledUserOpsByHash(
            PooledUserOpsByHashRequest::from_ssz_bytes(decoded_buffer)?,
        ))),
        SupportedProtocol::PingV1 => Ok(Some(InboundRequest::Ping(Ping {
            data: u64::from_ssz_bytes(decoded_buffer)?,
        }))),
        SupportedProtocol::MetaDataV1 => {
            if !decoded_buffer.is_empty() {
                Err(RPCError::InvalidData("Metadata request".to_string()))
            } else {
                Ok(Some(InboundRequest::MetaData(MetadataRequest::new())))
            }
        }
    }
}

/// Decodes a `RPCResponse` from the byte stream.
/// `decoded_buffer` should be an ssz-encoded bytestream with
/// length = length-prefix received in the beginning of the stream.
fn handle_rpc_response<T: EthSpec>(
    versioned_protocol: SupportedProtocol,
    decoded_buffer: &[u8],
    // fork_name: Option<ForkName>,
) -> Result<Option<RPCResponse<T>>, RPCError> {
    match versioned_protocol {
        SupportedProtocol::StatusV1 => Ok(Some(RPCResponse::Status(
            StatusMessage::from_ssz_bytes(decoded_buffer)?,
        ))),
        // This case should be unreachable as `Goodbye` has no response.
        SupportedProtocol::GoodbyeV1 => Err(RPCError::InvalidData(
            "Goodbye RPC message has no valid response".to_string(),
        )),
        SupportedProtocol::PingV1 => Ok(Some(RPCResponse::Pong(Ping {
            data: u64::from_ssz_bytes(decoded_buffer)?,
        }))),
        SupportedProtocol::MetaDataV1 => Ok(Some(RPCResponse::MetaData(
            MetaData::from_ssz_bytes(decoded_buffer)?,
        ))),
        SupportedProtocol::PooledUserOpHashesV1 => Ok(Some(RPCResponse::PooledUserOpHashes(
            PooledUserOpHashes::from_ssz_bytes(decoded_buffer)?,
        ))),
        SupportedProtocol::PooledUserOpsByHashV1 => Ok(Some(RPCResponse::PooledUserOpsByHash(
            PooledUserOpsByHash::from_ssz_bytes(decoded_buffer)?,
        ))),
    }
}