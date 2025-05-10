use aes_gcm_siv::{
    Aes256GcmSiv, AesGcmSiv, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use console::Term;
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, rand_core::RngCore};
use sha3::{Digest, Sha3_256, digest::generic_array::GenericArray};
use srp6::prelude::*;
use std::process::exit;
use std::{
    io::{self, BufRead, Write},
    net::TcpStream,
    vec,
};
use tracing::{Level, debug, error, info, trace};
use utils::{block_encrypt, receive_data, send_data};
const SERVER: &str = "127.0.0.1:15496";
fn main() {
    let log_level = match std::env::args()
        .nth(1)
        .unwrap_or("info".to_string())
        .as_str()
    {
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap_or_else(|_| {
        tracing_subscriber::fmt().init();
    });
    let Ok(stream) = TcpStream::connect(SERVER) else {
        error!("Failed to connect to server");
        return;
    };
    info!("Connected to {}", SERVER);
    //
    new_session(&stream);
    //resume_session(&stream);
}

fn exchange_keys(stream: &TcpStream, identifier: u8) -> (Nonce, RsaPublicKey, Vec<u8>) {
    trace!("Generating client secret... (Diffie-Hellman)");
    let client_secret = EphemeralSecret::random(&mut OsRng);
    let client_pk_bytes = EncodedPoint::from(client_secret.public_key());
    trace!("Initiating new session request with Diffie-Hellman handshake...");
    let mut payload = vec![identifier];
    payload.extend_from_slice(client_pk_bytes.as_bytes());
    trace!("Sending client public key...");
    send_data(&payload, stream);
    print!("Awaiting response from server\x1B[31m.\x1B[32m.\x1B[33m.\x1B[0m");
    io::stdout().flush().unwrap();
    trace!(
        "Awaiting server public key (65b), decryptnonce (12b), encrypted RSA-2048 public key (?b) and descriminator (?b)..."
    );
    let payload = receive_data(stream);
    print!("\x1B[2K\r");
    let server_public =
        PublicKey::from_sec1_bytes(&payload[0..65]).expect("Invalid server public key!");
    let shared_secret = client_secret.diffie_hellman(&server_public);
    trace!("Shared secret derived!");
    trace!("Deriving public key...");
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    let rawkeybytes = &hasher.finalize();
    let key = &rawkeybytes;
    let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(key);
    let cipher = Aes256GcmSiv::new(key);
    let decryptnonce = Nonce::from_slice(&payload[65..77]);
    let cleartext = cipher.decrypt(decryptnonce, &payload[77..]).unwrap();
    let pkstart = u16::from_le_bytes([cleartext[12], cleartext[13]]) as usize;
    let public_key =
        RsaPublicKey::from_public_key_pem(&String::from_utf8_lossy(&cleartext[14..pkstart + 14]))
            .unwrap();
    debug!(
        "Session ID: Client-{}",
        usize::from_le_bytes(cleartext[pkstart + 14..].try_into().unwrap())
    );
    (
        *Nonce::from_slice(&cleartext[0..12]),
        public_key,
        rawkeybytes.to_vec(),
    )
}

fn new_session(stream: &TcpStream) {
    let mut rng = OsRng;
    debug!("New session requested");
    trace!("Requesting username...");
    let username = request("Username: ", false);
    let username = username.as_bytes();
    let (encryptnonce, public_key, rawkeybytes) = exchange_keys(stream, 0u8);
    trace!(
        "Sending decryptnonce (12b) + username (?b) encryped via shared secret through the RSA-2048 public key..."
    );
    let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(&rawkeybytes);
    let cipher = Aes256GcmSiv::new(key);
    let mut decryptnonce = [0; 12];
    rng.try_fill_bytes(&mut decryptnonce).unwrap();
    let mut cleartext = Vec::new();
    cleartext.extend_from_slice(&decryptnonce);
    cleartext.extend_from_slice(username);
    let ciphertext = cipher.encrypt(&encryptnonce, cleartext.as_ref()).unwrap();
    let payload = block_encrypt(&public_key, &ciphertext).unwrap();
    send_data(&payload, stream);
    let response = receive_data(stream);
    if response.len() == 4 {
        error_decode(&response);
    }
    let cleartext = cipher
        .decrypt(Nonce::from_slice(&decryptnonce), &response[..])
        .unwrap();
    let encryptnonce = Nonce::from_slice(&cleartext[..12]);
    let serverip = stream.peer_addr().unwrap().ip().to_string()
        + ":"
        + &stream.peer_addr().unwrap().port().to_string();
    if i64::from_le_bytes(cleartext[12..20].try_into().unwrap()) == 0 {
        let mut plaintext = Vec::new();
        rng.try_fill_bytes(&mut decryptnonce).unwrap();
        plaintext.extend_from_slice(&decryptnonce);
        plaintext.extend_from_slice(&salt_verifier(username));
        let ciphertext = cipher.encrypt(encryptnonce, plaintext.as_ref()).unwrap();
        let payload = block_encrypt(&public_key, &ciphertext).unwrap();
        send_data(&payload, stream);
        let response = receive_data(stream);
        if response.len() == 4 {
            error_decode(&response);
        }
        let cleartext = cipher
            .decrypt(Nonce::from_slice(&decryptnonce), &response[..])
            .unwrap();
        let encryptnonce = &cleartext[..12];
        let magic = &cleartext[12..];
        trace!("Registration successful. Creating a new session to server, and logging in.");
        resume_session(
            &TcpStream::connect(&serverip).unwrap(),
            Some(username),
            magic,
            encryptnonce,
        );
        //println!("magic: {:?}, nextnonce: {:?}", magic, encryptnonce);
    } else {
        login(&TcpStream::connect(&serverip).unwrap(), Some(username));
    };
}

fn resume_session(stream: &TcpStream, usernameraw: Option<&[u8]>, magic: &[u8], nextnonce: &[u8]) {
    let mut rng = OsRng;
    debug!("Resume session requested.");
    let username = match usernameraw {
        Some(username) => username.to_vec(),
        None => {
            trace!("Requesting username...");
            request("Username: ", false).into_bytes()
        }
    };
    let (mut encryptnonce, public_key, rawkeybytes) = exchange_keys(stream, 1u8);
    trace!(
        "Sending decryptnonce (12b) + username (?b) encryped via shared secret through the RSA-2048 public key..."
    );
    let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(&rawkeybytes);
    let cipher = Aes256GcmSiv::new(key);

    let mut decryptnonce = [0; 12];
    let _ = rng.try_fill_bytes(&mut decryptnonce);
    let mut cleartext = Vec::new();
    cleartext.extend_from_slice(&decryptnonce);
    cleartext.extend_from_slice(&username);
    let ciphertext = cipher.encrypt(&encryptnonce, cleartext.as_ref()).unwrap();
    let payload = block_encrypt(&public_key, &ciphertext).unwrap();
    send_data(&payload, stream);
    let mut hasher = Sha3_256::new();
    hasher.update(magic);
    let key = &hasher.finalize();
    let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(key);
    let cipher = Aes256GcmSiv::new(key);
    decryptnonce = nextnonce.try_into().unwrap();
    for i in 0..7 {
        trace!("Awaiting sum from server ({}/7)...", i);
        let response = receive_data(stream);
        if response.len() == 4 {
            error_decode(&response);
        }
        let rawdata = cipher
            .decrypt(Nonce::from_slice(&decryptnonce), response.as_ref())
            .unwrap();
        encryptnonce = *Nonce::from_slice(&rawdata[..12]);
        let num1 = u64::from_le_bytes(rawdata[12..20].try_into().unwrap());
        let num2 = u64::from_le_bytes(rawdata[20..28].try_into().unwrap());
        let sum = num1 ^ num2;
        let _ = rng.try_fill_bytes(&mut decryptnonce);
        let mut data = Vec::new();
        data.extend_from_slice(&decryptnonce);
        data.extend_from_slice(&sum.to_le_bytes());
        let payload = cipher.encrypt(&encryptnonce, data.as_ref()).unwrap();
        trace!("returning XOR result... ");
        send_data(&payload, stream);
    }
    let payload = receive_data(stream);
    if payload.len() == 4 {
        error_decode(&payload);
    }
    trace!("Login successful!");
    println!("We are... in.");
}

fn salt_verifier(username: &[u8]) -> Vec<u8> {
    if !choice(
        "The specified account does not exist. Would you like to create it? [y/n] ",
        "Registering a new account.",
        "Will not register a new account. Aborting program.",
    ) {
        exit(0);
    }
    let password = ClearTextPassword::from(request("Password: ", true));
    let password2 = ClearTextPassword::from(request("Confirm password: ", true));
    if password != password2 {
        error!("Passwords do not match!");
        exit(1);
    }
    let (salt, verifier) = Srp6_4096::default()
        .generate_new_user_secrets(&Username::from_utf8_lossy(username), &password);
    let mut payload = Vec::new();
    payload.extend_from_slice(&salt.to_vec());
    payload.extend_from_slice(&verifier.to_vec());
    payload
}

fn login(stream: &TcpStream, usernameraw: Option<&[u8]>) -> Vec<u8> {
    let password = ClearTextPassword::from(request("Password: ", true));
    let mut rng = OsRng;
    debug!("Login session requested.");
    let username = match usernameraw {
        Some(username) => username.to_vec(),
        None => {
            trace!("Requesting username...");
            request("Username: ", false).into_bytes()
        }
    };
    let (encryptnonce, public_key, rawkeybytes) = exchange_keys(stream, 2u8);
    trace!(
        "Sending decryptnonce (12b) + username (?b) encryped via shared secret through the RSA-2048 public key..."
    );
    let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(&rawkeybytes);
    let cipher = Aes256GcmSiv::new(key);
    let decryptnonce = Nonce::from_slice(&payload[65..77]);
    let cleartext = cipher.decrypt(decryptnonce, &payload[77..]).unwrap();
    let encryptnonce = Nonce::from_slice(&cleartext[0..12]);
    let public_key =
        RsaPublicKey::from_public_key_pem(&String::from_utf8_lossy(&cleartext[12..])).unwrap();
    trace!(
        "Sending decryptnonce (12b) + username (?b) encryped via shared secret through the RSA-2048 public key..."
    );
    let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(&rawkeybytes);
    let cipher = Aes256GcmSiv::new(key);
    let mut decryptnonce = [0; 12];
    rng.try_fill_bytes(&mut decryptnonce).unwrap();
    let mut cleartext = Vec::new();
    cleartext.extend_from_slice(&decryptnonce);
    cleartext.extend_from_slice(&username);
    let ciphertext = cipher.encrypt(&encryptnonce, cleartext.as_ref()).unwrap();
    let payload = block_encrypt(&public_key, &ciphertext).unwrap();
    send_data(&payload, stream);
    trace!("Awaiting handshake from server...");
    Vec::new()
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

fn choice(prompt: &str, yes: &str, no: &str) -> bool {
    let term = Term::stdout();
    loop {
        print!("\x1B[2K\r\x1B[33m{}\x1B[0m", prompt);
        std::io::stdout().flush().unwrap();
        if let console::Key::Char(c) = term.read_key().unwrap() {
            match c {
                'y' => {
                    println!("\x1B[2K\r\x1B[32m{}\x1B[0m", yes);
                    std::io::stdout().flush().unwrap();
                    return true;
                }
                'n' => {
                    println!("\x1B[2K\r\x1B[31m{}\x1B[0m", no);
                    std::io::stdout().flush().unwrap();
                    return false;
                }
                _ => {}
            }
        }
    }
}

fn error_decode(code: &[u8]) {
    let ec = i32::from_le_bytes(code[..4].try_into().unwrap());
    let msg = match ec {
        400 => "Client fault (thats us!). Server refused to elaborate what went wrong.",
        401 => "Server expected a larger payload.",
        402 => "Server expected a smaller payload.",
        500 => "Server fault! There is nothing we can do about it on our end though ¯\\_(ツ)_/¯.",
        501 => "The server actively refused the connection.",
        _ => "Unexpected error code!",
    };
    error!("{}", msg);
    exit(ec);
}
