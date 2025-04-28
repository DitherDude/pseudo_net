use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey};
use std::net::TcpStream;
use tracing::{error, info, trace};
use utils::{receive_data, send_data};
fn main() {
    tracing_subscriber::fmt().init();
    let server = "127.0.0.1:15496";
    let Ok(stream) = TcpStream::connect(server) else {
        error!("Failed to connect to server");
        return;
    };
    info!("Connected to {}", server);
    //
    trace!("Sending new session request");
    send_data(&[0], &stream);
    trace!("Awaiting public key...");
    let public_key =
        RsaPublicKey::from_public_key_pem(&String::from_utf8_lossy(&receive_data(&stream)))
            .unwrap();
    let cyphertext = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, &[0, 1, 2, 3, 4, 5])
        .unwrap();
    trace!("Sending dummy data...");
    send_data(&cyphertext, &stream);
}
