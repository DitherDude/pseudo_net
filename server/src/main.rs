use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::EncodePublicKey,
    rand_core::{self, RngCore},
};
use sha3::{Digest, Sha3_256, digest::generic_array::GenericArray};
use sqlx::mysql::MySqlPool;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use tracing::{error, info, trace, warn};
use utils::{block_decrypt, receive_data, send_data};

#[async_std::main]
async fn main() {
    tracing_subscriber::fmt().init();
    trace!("Looking for config file...");
    if std::fs::metadata("config").is_err() {
        error!("Config file not found! Please see docs on how to create a config file.");
        std::process::exit(1);
    }
    trace!("Testing MYSQL connection...");
    match MySqlPool::connect(&retreive_config("PATH")).await {
        Ok(pool) => {
            trace!("Checking users table schema...");
            match sqlx::query!(
                r#"
                SELECT 
                COUNT(*) as count
                FROM 
                INFORMATION_SCHEMA.COLUMNS
                WHERE 
                TABLE_NAME = 'users'
                AND (COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_KEY) IN (
                    ('userid', 'varbinary', 64, 'NO', 'PRI'),
                    ('username', 'varbinary', 255, 'NO', 'UNI'),
                    ('salt', 'varbinary', 512, 'NO', ''),
                    ('verifier', 'varbinary', 512, 'NO', ''),
                    ('nonce', 'varbinary', 255, 'YES', ''),
                    ('user_pk', 'varbinary', 2048, 'YES', ''),
                    ('magic', 'varbinary', 255, 'YES', '')
                );
                "#
            )
            .fetch_optional(&pool)
            .await
            {
                Ok(Some(e)) => {
                    if e.count == 7 {
                        trace!("Users table schema is valid.");
                    } else {
                        warn!("Missing users table. Will attempt to create it.");
                        match sqlx::query!(
                            r#"
                            CREATE TABLE users (
                                userid varbinary(64) NOT NULL PRIMARY KEY,
                                username varbinary(255) NOT NULL UNIQUE,
                                salt varbinary(512) NOT NULL,
                                verifier varbinary(512) NOT NULL,
                                nonce varbinary(255),
                                user_pk varbinary(2048),
                                magic varbinary(255)
                            );
                            "#
                        )
                        .execute(&pool)
                        .await
                        {
                            Ok(_) => {
                                trace!("Created users table.");
                            }
                            Err(e) => {
                                error!("Failed to create users table: {}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Failed to check users table schema: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            error!("Failed to connect to database: {}", e);
            std::process::exit(1);
        }
    };
    let listener = TcpListener::bind("127.0.0.1:15496").unwrap();

    info!("Server listening on 127.0.0.1:15496");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                trace!(
                    "New connection from {}:{}",
                    stream.peer_addr().unwrap().ip(),
                    stream.peer_addr().unwrap().port()
                );
                async_std::task::spawn(async {
                    handle_connection(stream).await;
                });
            }
            Err(e) => {
                error!("Failed to establish connection with client: {}", e)
            }
        }
    }
}

async fn handle_connection(stream: TcpStream) {
    let mut rng = OsRng;
    let parsed_data = parse_data(&receive_data(&stream));
    match parsed_data.indentifier {
        0 => {
            trace!("Client new session request. Initiating Diffie-Hellman handshake...");
            let server_secret = EphemeralSecret::random(&mut rng);
            let server_pk_bytes = EncodedPoint::from(server_secret.public_key());
            trace!("Decoding client public key... (sent along with indentifier)");
            let client_public = match PublicKey::from_sec1_bytes(parsed_data.payload.as_ref()) {
                Ok(data) => data,
                Err(e) => {
                    warn!("Failed to decode client public key: {}", e);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
            };
            let shared_secret = server_secret.diffie_hellman(&client_public);
            trace!("Shared secret derived!");
            let (private_key, public_key) = generate_keys(2048);
            trace!("Keypair generated. Sending encrypted public key...");
            let mut hasher = Sha3_256::new();
            hasher.update(shared_secret.raw_secret_bytes());
            let key = &hasher.finalize();
            let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(key);
            let cipher = Aes256GcmSiv::new(key);
            let mut raw_nonce = [0u8; 12];
            rng.try_fill_bytes(&mut raw_nonce).unwrap();
            let nonce = Nonce::from_slice(&raw_nonce);
            let mut cleartext = Vec::new();
            let mut raw_nonce = [0u8; 12];
            rng.try_fill_bytes(&mut raw_nonce).unwrap();
            cleartext.extend_from_slice(&raw_nonce);
            cleartext.extend_from_slice(
                public_key
                    .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                    .unwrap()
                    .as_ref(),
            );
            let ciphertext = cipher.encrypt(nonce, cleartext.as_ref()).unwrap();
            let mut payload = Vec::new();
            payload.extend_from_slice(server_pk_bytes.as_bytes());
            payload.extend_from_slice(nonce);
            payload.extend_from_slice(&ciphertext);
            trace!("Sending server public key (65b), nonce (12b), and encrypted RSA-2048 key...");
            send_data(&payload, &stream);
            trace!("Awaiting nextnonce (12b), salt (512b), verifier (512b), and username (?b)...");
            let payload = receive_data(&stream);
            let response = match block_decrypt(&private_key, &payload) {
                Ok(data) => data,
                Err(e) => {
                    warn!("Failed to decrypt data: {}", e);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
            };
            let nextnonce = &response[0..12];
            let salt = &response[12..524];
            let verifier = &response[524..1036];
            let username = &response[1036..];
            println!("{}", username.len());
            let pool = MySqlPool::connect(&retreive_config("PATH")).await.unwrap();
            trace!("Generating userid...");
            let userid: [u8; 64] = loop {
                let mut userid = [0u8; 64];
                rng.try_fill_bytes(&mut userid).unwrap();
                let result =
                    match sqlx::query!(r#"SELECT userid FROM users WHERE userid = ?"#, &userid[..])
                        .fetch_optional(&pool)
                        .await
                    {
                        Ok(data) => data,
                        Err(e) => {
                            warn!("Failed to query database: {}", e);
                            stream.shutdown(std::net::Shutdown::Both).unwrap();
                            return;
                        }
                    };
                if result.is_none() {
                    break userid;
                }
            };
            trace!("Checking if user exists...");
            if match sqlx::query!(r#"SELECT userid FROM users WHERE userid = ?"#, &userid[..])
                .fetch_optional(&pool)
                .await
            {
                Ok(data) => data,
                Err(e) => {
                    warn!("Failed to query database: {}", e);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
            }
            .is_some()
            {
                warn!("Attempting to register a user that already exists.");
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                return;
            }
            match sqlx::query!(
                r#"
                INSERT INTO users ( userid, username, salt, verifier, nonce )
                VALUES ( ?, ?, ?, ?, ? )
                "#,
                &userid[..],
                username,
                salt,
                verifier,
                nextnonce
            )
            .execute(&pool)
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    warn!("Failed to insert user: {}", e);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
            };
        }
        1 => {
            trace!(
                "Client resume session request with ID {:?}.",
                parsed_data.payload
            );
            let num1 = rand_core::RngCore::next_u32(&mut OsRng);
            let num2 = rand_core::RngCore::next_u32(&mut OsRng);
            let mut payload = Vec::new();
            payload.extend_from_slice(&num1.to_le_bytes());
            payload.extend_from_slice(&num2.to_le_bytes());
            send_data(&payload, &stream);
            if receive_data(&stream) == (num1 ^ num2).to_le_bytes().to_vec() {
                println!("Session resumed!");
            } else {
                warn!("Verification failure. Dropped client.");
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                return;
            }
        }
        _ => {}
    }
    trace!(
        "Connection from {}:{} closed.",
        stream.peer_addr().unwrap().ip(),
        stream.peer_addr().unwrap().port()
    );
}

fn generate_keys(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    trace!("Generating keys...");
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    trace!("Keys generated.");
    (private_key, public_key)
}

struct DataParser {
    indentifier: u8,
    payload: Vec<u8>,
}

fn parse_data(data: &[u8]) -> DataParser {
    DataParser {
        indentifier: data[0],
        payload: data[1..].to_vec(),
    }
}

fn retreive_config(path: &str) -> String {
    if std::fs::metadata("config").is_err() {
        error!("Config file not found!");
        std::process::exit(1);
    }
    let mut file = std::fs::File::open("config").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mut lookup = path.to_string();
    lookup.push(':');
    for line in contents.lines() {
        if line.starts_with(&lookup) {
            return line.replace(&lookup, "").trim().to_string();
        }
    }
    String::new()
}
