use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use console::Term;
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, rand_core::RngCore};
use sha3::{Digest, Sha3_256, digest::generic_array::GenericArray};
use srp6::prelude::*;
use std::{
    io::{self, BufRead, Write},
    net::TcpStream,
    vec,
};
use tracing::{debug, error, info, trace};
use utils::{block_encrypt, receive_data, send_data};
fn main() {
    tracing_subscriber::fmt().init();
    let server = "127.0.0.1:15496";
    let Ok(stream) = TcpStream::connect(server) else {
        error!("Failed to connect to server");
        return;
    };
    info!("Connected to {}", server);
    //
    new_session(&stream);
    //resume_session(&stream);
}

fn new_session(stream: &TcpStream) {
    let mut rng = OsRng;
    debug!("New session requested");
    trace!("Generating client secret... (Diffie-Hellman)");
    let client_secret = EphemeralSecret::random(&mut OsRng);
    let client_pk_bytes = EncodedPoint::from(client_secret.public_key());
    trace!("Sending new session request with Diffie-Hellman handshake...");
    let mut payload = vec![0];
    payload.extend(client_pk_bytes.as_bytes());
    trace!("Sending client public key...");
    send_data(&payload, stream);
    trace!("Getting username, salt, and verifier...");
    let (username, salt, verifier) = register();
    trace!("Awaiting server public key (65b), nonce (12b), and encrypted RSA-2048 public key...");
    let payload = receive_data(stream);
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
        RsaPublicKey::from_public_key_pem(&String::from_utf8_lossy(&cleartext[12..])).unwrap();
    trace!("Sending nextnonce (12b), salt (512b), verifier (512b), and username (?b)...");
    let mut nextnonce = [0; 12];
    rng.try_fill_bytes(&mut nextnonce).unwrap();
    let mut payload = Vec::new();
    payload.extend_from_slice(&nextnonce);
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&verifier);
    payload.extend_from_slice(&username);
    let ciphertext = block_encrypt(&public_key, &payload).unwrap();
    send_data(&ciphertext, stream);
}

fn resume_session(stream: &TcpStream) {
    trace!("Resume session requested. Sending session ID...");
    let mut payload = Vec::new();
    payload.extend_from_slice(&[1u8]);
    //payload.extend_from_slice();
    send_data(&payload, stream);
    trace!("Awaiting sum from server...");
    let rawdata = receive_data(stream);
    let num1 = u32::from_le_bytes(rawdata[..4].try_into().unwrap());
    let num2 = u32::from_le_bytes(rawdata[4..8].try_into().unwrap());
    let sum = num1 & num2;
    trace!("returning XOR result... ");
    send_data(&sum.to_le_bytes(), stream);
}

fn register() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let username = Username::from(request("Username: ", false));
    let password = ClearTextPassword::from(request("Password: ", true));
    let (salt, verifier) = Srp6_4096::default().generate_new_user_secrets(&username, &password);
    (
        username.as_bytes().to_vec(),
        salt.to_vec(),
        verifier.to_vec(),
    )
}

fn request(prompt: &str, password: bool) -> String {
    let stdin = io::stdin();
    if !password {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        let mut username = String::new();
        stdin.lock().read_line(&mut username).unwrap();
        let username = username.trim().to_string();
        io::stdout().flush().unwrap();
        return username;
    }
    let mut password = String::new();
    print!("\x1B[2K\r\x1B[31m{}\x1B[0m", prompt);
    std::io::stdout().flush().unwrap();
    let term = Term::stdout();
    loop {
        match term.read_key().unwrap() {
            console::Key::Char(c) => {
                password.push(c);
            }
            console::Key::Backspace => {
                if password.is_empty() {
                } else {
                    password.pop();
                    if password.is_empty() {
                        print!("\x1B[2K\r\x1B[31m{}\x1B[0m", prompt);
                        std::io::stdout().flush().unwrap();
                    }
                }
                continue;
            }
            console::Key::Enter => {
                break;
            }
            _ => {}
        }
        print!("\x1B[2K\r\x1B[33m{}\x1B[0m", prompt);
        std::io::stdout().flush().unwrap();
    }
    println!("\x1B[2K\r\x1B[32m{}\x1B[0m", prompt);
    let password = password.trim().to_string();
    password
}
