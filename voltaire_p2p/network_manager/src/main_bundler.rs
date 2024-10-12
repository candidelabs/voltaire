use std::{path::Path, fs};

use p2p_voltaire_network::{types::VerifiedUserOperation, rpc::methods::{PooledUserOpHashesRequest, PooledUserOpsByHashRequest, PooledUserOpHashes, PooledUserOpsByHash}};
use tokio::{net::{UnixListener, UnixStream}, io::{AsyncWriteExt, Interest}};
use serde::{Serialize, Deserialize};
use slog::error;

pub static BUNDLER_ENDPOINT_SOCKET_PATH: &'static str = "bundler_endpoint.ipc";
pub static P2P_ENDPOINT_SOCKET_PATH: &'static str = "p2p_endpoint.ipc";


#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
)]
pub struct GossibMessageToReceiveFromMainBundler {
    pub topics: Vec<String>,
    pub verified_useroperation: VerifiedUserOperation,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
)]
pub struct PooledUserOpHashesRequestFromBundler {
    pub id:String,
    pub peer_id: String,
    pub pooled_user_op_hashes_request: PooledUserOpHashesRequest,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
)]
pub struct PooledUserOpsByHashRequestFromBundler {
    pub id:String,
    pub peer_id: String,
    pub pooled_user_ops_by_hash_request: PooledUserOpsByHashRequest,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
)]
#[serde(untagged)] 
pub enum MessageTypeFromBundler  {
    GossibMessageFromBundler(GossibMessageToReceiveFromMainBundler),
    PooledUserOpHashesRequestFromBundler(PooledUserOpHashesRequestFromBundler),
    PooledUserOpsByHashRequestFromBundler(PooledUserOpsByHashRequestFromBundler),
}

pub async fn listen_to_main_bundler(log: &slog::Logger) -> Result<MessageTypeFromBundler,serde_pickle::Error>{
    let socket = Path::new(P2P_ENDPOINT_SOCKET_PATH);
    if socket.exists() {
        fs::remove_file(&socket).unwrap();
    }
    let listener = UnixListener::bind(socket).unwrap();

    let (stream, _addr)= listener.accept().await.unwrap();
    let message_length_read_result:[u8;4] = listen_to_stream(4,&stream, log).await.unwrap().try_into().unwrap();
    let message_length = usize::try_from(u32::from_le_bytes(message_length_read_result)).unwrap();

    let main_message_read_result = listen_to_stream(message_length,&stream, log).await.unwrap();

    let deserialized_message:Result<MessageTypeFromBundler,serde_pickle::Error> = serde_pickle::from_slice(&main_message_read_result, Default::default());
    deserialized_message
}

async fn listen_to_stream(result_length:usize, stream:&UnixStream, log: &slog::Logger)-> Result<Vec<u8>,std::io::Error>{
    let mut result:Vec<u8> = vec![0u8; result_length];
    loop{
        let stream_status_result = stream.ready(Interest::READABLE).await;
        match stream_status_result{
            Ok(stream_status)=>{
                if stream_status.is_readable() {
                    let number_of_bytes_read = stream.try_read(&mut result);
                    match number_of_bytes_read{
                        Ok(_)=>{ //don't care about number of bytes, just return the result if successful
                            return Ok(result);
                        },
                        Err(read_error)=>{
                            error!(log, "Listening to the bundler read error"; "error" => read_error);
                            continue; //TODO : should check if it is Would Block error
                        },
                    }
                }
            },
            Err(ready_error)=>{
                error!(log, "Listening to the bundler ready error"; "error" => ready_error);
                continue;
            },
        }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
)]
pub struct GossibMessageToSendToMainBundler {
    pub peer_id: String,
    pub topic: String,
    pub verified_useroperation: VerifiedUserOperation,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
)]
pub struct PooledUserOpHashesAndPeerId {
    pub peer_id: String,
    pub pooled_user_op_hashes: PooledUserOpHashes,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
#[serde(untagged)] 
pub enum MessageTypeToBundler  {
    GossibMessageToBundler(GossibMessageToSendToMainBundler),
    PooledUserOpHashesRequestToBundler(PooledUserOpHashesRequest),
    PooledUserOpsByHashRequestToBundler(PooledUserOpsByHashRequest),
    PooledUserOpHashesResponseToBundler(PooledUserOpHashesAndPeerId),
    PooledUserOpsByHashResponseToBundler(PooledUserOpsByHash),
    Status()
}


#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
pub struct BundlerGossibRequest {
    pub request_type: String,
    pub request_arguments:MessageTypeToBundler,
}

pub async fn broadcast_to_main_bundler(message_to_send:BundlerGossibRequest,_log: &slog::Logger) {//-> Result<String,serde_pickle::Error>{
    let socket = Path::new(BUNDLER_ENDPOINT_SOCKET_PATH);
    let mut stream = match UnixStream::connect(&socket).await {
        Err(_) => panic!("server is not running"),
        Ok(stream) => stream,
    };

    let serialized = serde_pickle::to_vec(&message_to_send, Default::default()).unwrap();
    let main_message_bytes = serialized.clone();
    let message_length = main_message_bytes.len() as u32;
    let mut message_length_as_bytes = [0;4];
    message_length_as_bytes.copy_from_slice(&message_length.to_le_bytes());
    let message_length_and_main_messge_concatinated: Vec<u8> = message_length_as_bytes.iter().copied().chain(main_message_bytes.iter().copied()).collect();
    stream.write_all(&message_length_and_main_messge_concatinated).await.unwrap();

}

pub async fn broadcast_and_listen_for_response_from_main_bundler(message_to_send:BundlerGossibRequest, log: &slog::Logger) -> Result<Vec<u8>,std::io::Error>{
    let socket = Path::new(BUNDLER_ENDPOINT_SOCKET_PATH);
    let mut stream = match UnixStream::connect(&socket).await {
        Err(_) => panic!("server is not running"),
        Ok(stream) => stream,
    };

    let serialized = serde_pickle::to_vec(&message_to_send, Default::default()).unwrap();
    let main_message_bytes = serialized.clone();
    let message_length = main_message_bytes.len() as u32;
    let mut message_length_as_bytes = [0;4];
    message_length_as_bytes.copy_from_slice(&message_length.to_le_bytes());
    let message_length_and_main_messge_concatinated: Vec<u8> = message_length_as_bytes.iter().copied().chain(main_message_bytes.iter().copied()).collect();
    stream.write_all(&message_length_and_main_messge_concatinated).await.unwrap();

    let result:[u8;4] = listen_to_stream(4,&stream, log).await.unwrap().try_into().unwrap();
    let result_length = usize::try_from(u32::from_le_bytes(result)).unwrap();

    listen_to_stream(result_length,&stream, log).await
}