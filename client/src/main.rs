use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey};
use sha3::{Digest, Sha3_256, digest::generic_array::GenericArray};
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
    trace!("Awaiting server public key (65b), nonce (12b), and encrypted RSA-2048 public key...");
    let payload = receive_data(&stream);
    let server_public =
        PublicKey::from_sec1_bytes(&payload[0..65]).expect("Invalid server public key!");
    let shared_secret = client_secret.diffie_hellman(&server_public);
    trace!("Shared secret derived!");
    trace!("Awaiting public key...");
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    let key = &hasher.finalize();
    let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(key);
    let cipher = Aes256GcmSiv::new(key);
    let nonce = Nonce::from_slice(&payload[65..77]);
    let cleartext = cipher.decrypt(nonce, &payload[77..]).unwrap();
    let public_key =
        RsaPublicKey::from_public_key_pem(&String::from_utf8_lossy(&cleartext)).unwrap();
    trace!("Sending dummy data...");
    let ciphertext = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, &[0, 7, 7, 3, 4])
        .unwrap();
    send_data(&ciphertext, &stream);
}
