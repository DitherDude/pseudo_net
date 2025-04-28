use rand::rngs::OsRng;
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use std::{net::TcpStream, vec};
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
    trace!("Generating client secret... (Diffie-Hellman)");
    let client_secret = EphemeralSecret::random(&mut OsRng);
    let client_pk_bytes = EncodedPoint::from(client_secret.public_key());
    trace!("Sending new session request with Diffie-Hellman handshake...");
    let mut payload = vec![0];
    payload.extend(client_pk_bytes.as_bytes());
    trace!("Sending client public key...");
    send_data(&payload, &stream);
    trace!("Awaiting server public key bytes...");
    let server_public = PublicKey::from_sec1_bytes(receive_data(&stream).as_ref())
    .expect("Invalid server public key!");
    let shared_secret = client_secret.diffie_hellman(&server_public);
    trace!("Shared secret derived!");
    //println!("{:?}", shared_secret.raw_secret_bytes());
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
