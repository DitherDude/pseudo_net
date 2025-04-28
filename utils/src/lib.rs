use std::{
    io::{Read, Write},
    net::TcpStream,
};
use tracing::{debug, error, trace};

pub fn receive_data(mut stream: &TcpStream) -> Vec<u8> {
    trace!("Started receiving data.");
    let mut len = [0; 2];
    let mut data = Vec::new();
    loop {
        match stream.read_exact(&mut len) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to read block length: {}", e);
                return data;
            }
        }
        let len = u16::from_le_bytes(len);
        if len == 0 {
            trace!("Received null terminator.");
            break;
        }
        trace!("Expecting {len} bytes...");
        let start = data.len();
        data.extend(std::iter::repeat_n(0, len as usize));
        stream.read_exact(&mut data[start..]).unwrap();
        trace!("Received data: {}", data.len() - start);
        if len != u16::MAX {
            break;
        }
        trace!("Expecting another block...");
    }
    debug!("Finished receiving data of size {}", data.len());
    data
}

pub fn send_data(payload: &[u8], mut stream: &TcpStream) {
    debug!("Started sending data of size {}", payload.len());
    for block in payload.chunks(u16::MAX.into()) {
        let message_len = block.len() as u16;
        trace!("Announcing {message_len} bytes");
        match stream.write_all(&message_len.to_le_bytes()) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to send block length: {}", e);
                return;
            }
        }
        trace!("Sending block of size {}...", block.len());
        match stream.write_all(block) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to send block: {}", e);
                return;
            }
        }
    }
    if payload.len() % u16::MAX as usize == 0 {
        trace!("Sending null terminator");
        match stream.write_all(&0u16.to_le_bytes()) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to send null terminator: {}", e);
            }
        }
    }
    trace!("Finished sending data.");
}
