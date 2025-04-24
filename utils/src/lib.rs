use std::{
    io::{Read, Write},
    net::TcpStream,
};
use tracing::{info, error};


pub fn get_data(mut stream: &TcpStream) -> Vec<u8>{
    let mut len = [0; 2];
    let mut data = Vec::new();
    loop {
        stream.read_exact(&mut len).unwrap();
        let len = u16::from_le_bytes(len);
        if len == 0{
            info!("Received null terminator.");
            break;
        }
        info!("Expecting {len} bytes...");
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).unwrap();
        info!("Received data: {:?}", &payload);
        data.append(&mut payload);
        if len != u16::MAX{
            break;
        }
        info!("Expecting another block...");
    }
    data
}

pub fn send_data(payload: &[u8], mut stream: &TcpStream){
    for block in payload.chunks(u16::MAX.into()){
        let message_len = block.len() as u16;
        info!("Sending block size: {message_len}");
        match stream.write_all(&message_len.to_le_bytes()){
            Ok(_) => {},
            Err(e) => {
                error!("Failed to send block length: {}", e);
                return;
            }
        }
        info!("Sending block: {block:?}");
        match stream.write_all(block){
            Ok(_) => {},
            Err(e) => {
                error!("Failed to send block: {}", e);
                return;
            }
        }
    }
    if payload.len() % u16::MAX as usize == 0 && !payload.is_empty(){
        info!("Sending null terminator");
        match stream.write_all(&0u16.to_le_bytes()){
            Ok(_) => {},
            Err(e) => {
                error!("Failed to send null terminator: {}", e);
            }
        }
    }
}