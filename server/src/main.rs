// use aes_gcm_siv::{
//     Aes256GcmSiv, Key, Nonce,
//     aead::{Aead, KeyInit, OsRng},
// };
use chacha20poly1305::{
    XChaCha20Poly1305,
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
use srp6::prelude::*;
use std::cmp::Ordering::{Equal, Greater, Less};
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use tracing::{Level, error, info, trace, warn};
use utils::{block_decrypt, receive_data, send_data};
#[async_std::main]
async fn main() {
    let log_level = match std::env::args()
        .nth(1)
        .unwrap_or("info".to_string())
        .as_str()
    {
        "trace" => Level::TRACE,
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
    trace!("Looking for config file...");
    if std::fs::metadata("config").is_err() {
        error!("Config file not found! Please see docs on how to create a config file.");
        exit(1);
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
                AND (
                    (COLUMN_NAME = 'userid' AND DATA_TYPE = 'varbinary' AND CHARACTER_MAXIMUM_LENGTH = 64 AND IS_NULLABLE = 'NO')
                    OR (COLUMN_NAME = 'username' AND DATA_TYPE = 'varbinary' AND CHARACTER_MAXIMUM_LENGTH = 255 AND IS_NULLABLE = 'NO' AND COLUMN_KEY = 'UNI')
                    OR (COLUMN_NAME = 'salt' AND DATA_TYPE = 'varbinary' AND CHARACTER_MAXIMUM_LENGTH = 512 AND IS_NULLABLE = 'NO')
                    OR (COLUMN_NAME = 'verifier' AND DATA_TYPE = 'varbinary' AND CHARACTER_MAXIMUM_LENGTH = 512 AND IS_NULLABLE = 'NO')
                    OR (COLUMN_NAME = 'nonce' AND DATA_TYPE = 'varbinary' AND CHARACTER_MAXIMUM_LENGTH = 255)
                    OR (COLUMN_NAME = 'user_pk' AND DATA_TYPE = 'varbinary' AND CHARACTER_MAXIMUM_LENGTH = 2048)
                    OR (COLUMN_NAME = 'magic' AND DATA_TYPE = 'varbinary' AND CHARACTER_MAXIMUM_LENGTH = 255)
                    OR (COLUMN_NAME = 'danger' AND DATA_TYPE = 'int' AND IS_NULLABLE = 'NO' AND COLUMN_DEFAULT = '0')
                    OR (COLUMN_NAME = 'locked' AND DATA_TYPE = 'tinyint' AND IS_NULLABLE = 'NO' AND COLUMN_DEFAULT = '0')
                );
                "#
            )
            .fetch_optional(&pool)
            .await
            {
                Ok(Some(e)) => {
                    if e.count == 9 {
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
                                magic varbinary(255),
                                danger int unsigned DEFAULT 0 NOT NULL,
                                locked BOOL DEFAULT 0 NOT NULL
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
                                exit(1);
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Failed to check users table schema: {}", e);
                    exit(1);
                }
            }
        }
        Err(e) => {
            error!("Failed to connect to database: {}", e);
            exit(1);
        }
    };
    let port = retreive_config("PORT").parse::<u16>().unwrap_or(15496);
    let listener = TcpListener::bind("127.0.0.1:".to_owned() + &port.to_string()).unwrap();
    info!("Server listening on 127.0.0.1:{}", port);
    let mut connid = 0usize;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                connid += 1;
                trace!(
                    "New connection from {}:{} (ID: {})",
                    stream.peer_addr().unwrap().ip(),
                    stream.peer_addr().unwrap().port(),
                    connid
                );
                async_std::task::spawn(async move {
                    handle_connection(stream, connid).await;
                });
            }
            Err(e) => {
                error!("Failed to establish connection with client: {}", e)
            }
        }
    }
}

async fn handle_connection(stream: TcpStream, id: usize) {
    let mut rng = OsRng;
    let parsed_data = match parse_data(&receive_data(&stream)) {
        Ok(data) => data,
        Err(_) => {
            trace!("Client disappeared... Whoosh!");
            return;
        }
    };
    if parsed_data.indentifier == 0 {
        trace!(
            "Client-{} new session request. Initiating Diffie-Hellman handshake...",
            id
        );
    } else if parsed_data.indentifier == 1 {
        trace!(
            "Client-{} resume session request. Initiating Diffie-Hellman handshake...",
            id
        );
    }
    let server_secret = EphemeralSecret::random(&mut rng);
    let server_pk_bytes = EncodedPoint::from(server_secret.public_key());
    trace!(
        "Decoding client-{} public key... (sent along with indentifier)",
        id
    );
    let client_public = match PublicKey::from_sec1_bytes(parsed_data.payload.as_ref()) {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to decode client-{} public key: {}", id, e);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            return;
        }
    };
    let shared_secret = server_secret.diffie_hellman(&client_public);
    trace!("Shared secret derived from Client-{}!", id);
    let (private_key, public_key) = generate_keys(id);
    trace!(
        "Keypair generated for Client-{}. Encrypting public key...",
        id
    );
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    let key = &hasher.finalize();
    let cipher = XChaCha20Poly1305::new(key);
    let mut encryptnonce: [u8; 24] = [0u8; 24];
    rng.try_fill_bytes(&mut encryptnonce).unwrap();
    //let encryptnonce = Nonce::from_slice(&encryptnonce);
    let mut cleartext = Vec::new();
    let mut decryptnonce = [0u8; 24];
    rng.try_fill_bytes(&mut decryptnonce).unwrap();
    let pubkeybytes = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    let pklen = pubkeybytes.len() as u16;
    cleartext.extend_from_slice(&decryptnonce);
    cleartext.extend_from_slice(&pklen.to_le_bytes());
    cleartext.extend_from_slice(pubkeybytes.as_ref());
    cleartext.extend_from_slice(&id.to_le_bytes());
    let ciphertext = cipher
        .encrypt(&encryptnonce.into(), cleartext.as_ref())
        .unwrap();
    let mut payload = Vec::new();
    payload.extend_from_slice(server_pk_bytes.as_bytes());
    payload.extend_from_slice(&encryptnonce);
    payload.extend_from_slice(&ciphertext);
    trace!(
        "Sending server public key (65b), encryptnonce (24b), encrypted RSA key for Client-{} (?b) and descriminator (?b)...",
        id
    );
    send_data(&payload, &stream);
    trace!(
        "Awaiting encryptnonce (24b) + username (?b) encryped via shared secret through the RSA public key from Client-{}...",
        id
    );
    let payload = receive_data(&stream);
    let ciphertext = match block_decrypt(&private_key, &payload) {
        Ok(data) => data,
        Err(e) => {
            warn!(
                "Client-{} sent invalid bytes. Sending errorcode and dropping connection. {}",
                id, e
            );
            send_data(&400_i32.to_le_bytes(), &stream);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            return;
        }
    };
    let cleartext = match cipher.decrypt(&decryptnonce.into(), &ciphertext[..]) {
        Ok(data) => {
            if data.len() <= 24 {
                warn!(
                    "Data is too short (username must be at least 1b). Sending errorcode and dropping Client-{}.",
                    id
                );
                send_data(&401_i32.to_le_bytes(), &stream);
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                return;
            } else if data.len() > 279 {
                warn!(
                    "Data is too long (username must be less than 255b). Sending errorcode and dropping Client-{}.",
                    id
                );
                send_data(&402_i32.to_le_bytes(), &stream);
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                return;
            } else {
                data
            }
        }
        Err(e) => {
            warn!(
                "Failed to decrypt data from client-{}. Sending errorcode and dropping connection. {}",
                id, e
            );
            send_data(&400_i32.to_le_bytes(), &stream);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            return;
        }
    };
    let pool = MySqlPool::connect(&retreive_config("PATH")).await.unwrap();
    trace!(
        "Checking if Client-{}'s requested user \"{:?}\" exists.",
        id,
        &cleartext[24..]
    );
    let username = &cleartext[24..];
    let userexists = match sqlx::query!(
        r#"SELECT COUNT(*) as count FROM users WHERE username = ?"#,
        &username
    )
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(data)) => data.count,
        Ok(None) => {
            warn!(
                "Unexpected response from database. Sending errorocode and dropping Client-{}.",
                id
            );
            send_data(&500_i32.to_le_bytes(), &stream);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            return;
        }
        Err(e) => {
            error!(
                "Failed to query database. Sending errorocode and dropping Client-{}. {}",
                id, e
            );
            send_data(&500_i32.to_le_bytes(), &stream);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            return;
        }
    };
    if userexists > 2 {
        warn!(
            "Invalid count of occurances for user {:?}! Sending errorocode and dropping Client-{}.",
            &cleartext[24..],
            id
        );
        send_data(&500_i32.to_le_bytes(), &stream);
        stream.shutdown(std::net::Shutdown::Both).unwrap();
        return;
    }
    match parsed_data.indentifier {
        0 => {
            let encryptnonce = &cleartext[..24];
            rng.try_fill_bytes(&mut decryptnonce).unwrap();
            let mut cleartext = Vec::new();
            cleartext.extend_from_slice(&decryptnonce);
            cleartext.extend_from_slice(&userexists.to_le_bytes());
            let payload = cipher
                .encrypt(encryptnonce.into(), cleartext.as_ref())
                .unwrap();
            send_data(&payload, &stream);
            if userexists == 1 {
                //login(&cleartext[24..])
            } else {
                let response = receive_data(&stream);
                let ciphertext = match block_decrypt(&private_key, &response) {
                    Ok(data) => data,
                    Err(e) => {
                        warn!(
                            "Client-{} sent invalid bytes. Sending errorcode and dropping connection. {}",
                            id, e
                        );
                        send_data(&400_i32.to_le_bytes(), &stream);
                        stream.shutdown(std::net::Shutdown::Both).unwrap();
                        return;
                    }
                };
                let payload = match cipher.decrypt(&decryptnonce.into(), &ciphertext[..]) {
                    Ok(data) => data,
                    Err(e) => {
                        warn!(
                            "Failed to decrypt data. Sending errorocode and dropping Client-{}. {}",
                            id, e
                        );
                        send_data(&400_i32.to_le_bytes(), &stream);
                        stream.shutdown(std::net::Shutdown::Both).unwrap();
                        return;
                    }
                };
                match payload.len().cmp(&1048) {
                    Less => {
                        warn!(
                            "Data is too short (expecting 1048b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&401_i32.to_le_bytes(), &stream);
                        stream.shutdown(std::net::Shutdown::Both).unwrap();
                        return;
                    }
                    Greater => {
                        warn!(
                            "Data is too long (expecting 1048b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&402_i32.to_le_bytes(), &stream);
                        stream.shutdown(std::net::Shutdown::Both).unwrap();
                        return;
                    }
                    Equal => {
                        let encryptnonce = &payload[..24];
                        let salt = &payload[24..536];
                        let verifier = &payload[536..1048];
                        rng.try_fill_bytes(&mut decryptnonce).unwrap();
                        let mut plaintext = Vec::new();
                        plaintext.extend_from_slice(&decryptnonce);
                        plaintext.extend_from_slice(
                            &srp6_register(
                                username,
                                &pool,
                                &stream,
                                salt,
                                verifier,
                                &decryptnonce,
                                id,
                            )
                            .await,
                        );
                        let data = cipher
                            .encrypt(encryptnonce.into(), plaintext.as_ref())
                            .unwrap();
                        send_data(&data, &stream);
                    }
                }
            }
        }
        1 => {
            let (magic, mut encryptnonce) = match sqlx::query!(
                r#"SELECT magic, nonce FROM users WHERE username = ?"#,
                &username
            )
            .fetch_optional(&pool)
            .await
            {
                Ok(Some(data)) => (
                    data.magic.unwrap_or_else(|| {
                        let mut fluff = [0; 255];
                        rng.try_fill_bytes(&mut fluff).unwrap();
                        fluff.to_vec()
                    }),
                    data.nonce.unwrap_or_else(|| {
                        let mut fluff = [0u8; 24];
                        rng.try_fill_bytes(&mut fluff).unwrap();
                        fluff.to_vec()
                    }),
                ),
                Ok(None) => {
                    warn!(
                        "Unexpected response from database. Sending errorocode and dropping Client-{}.",
                        id
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
                Err(e) => {
                    error!(
                        "Failed to query database. Sending errorocode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
            };
            let mut hasher = Sha3_256::new();
            hasher.update(magic);
            let key = &hasher.finalize();
            let cipher = XChaCha20Poly1305::new(key);
            let mut failed = false;
            for i in 0..7 {
                trace!("Starting verification round {}/7 for Client-{}", i + 1, id);
                let num1 = rand_core::RngCore::next_u64(&mut OsRng);
                let num2 = rand_core::RngCore::next_u64(&mut OsRng);
                let mut decryptnonce = [0u8; 24];
                rng.try_fill_bytes(&mut decryptnonce).unwrap();
                let mut cleartext = Vec::new();
                cleartext.extend_from_slice(&decryptnonce);
                cleartext.extend_from_slice(&num1.to_le_bytes());
                cleartext.extend_from_slice(&num2.to_le_bytes());
                let data = cipher
                    .encrypt(GenericArray::from_slice(&encryptnonce), cleartext.as_ref())
                    .unwrap();
                send_data(&data, &stream);
                let response = receive_data(&stream);
                let data = match cipher.decrypt(&decryptnonce.into(), &response[..]) {
                    Ok(data) => {
                        if data.len() <= 24 {
                            warn!(
                                "Data is too short (username must be at least 1b). Sending errorcode and dropping Client-{}.",
                                id
                            );
                            send_data(&401_i32.to_le_bytes(), &stream);
                            stream.shutdown(std::net::Shutdown::Both).unwrap();
                            return;
                        } else {
                            data
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to decrypt data. Sending errorocode and dropping Client-{}. {}",
                            id, e
                        );
                        send_data(&400_i32.to_le_bytes(), &stream);
                        stream.shutdown(std::net::Shutdown::Both).unwrap();
                        return;
                    }
                };
                let nextnonce = &data[..24];
                if data[24..].to_vec() != (num1 ^ num2).to_le_bytes().to_vec() {
                    warn!("Client-{} failed verification round {}/7", id, i);
                    failed = true;
                }
                encryptnonce = nextnonce.to_vec();
            }
            if failed {
                warn!(
                    "Verification failure. Sending vague errorcode, and dropping Client-{}.",
                    id
                );
                send_data(&501_i32.to_le_bytes(), &stream);
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                return;
            }
            trace!("Client-{} passed all 7 verification rounds.", id);
            send_data(b"session resumed!", &stream);
        }
        2 => {
            let encryptnonce = &cleartext[..24];
            let srp = Srp6_4096::default();
            let (handshake, proof_verifier) =
                srp.start_handshake(&get_user_details(username, &pool, id).await);
            trace!("Sending serialized handshake to Client-{}...", id);
            let serialized = serde_json::to_vec(&handshake).unwrap();
            rng.try_fill_bytes(&mut decryptnonce).unwrap();
            let mut cleartext = Vec::new();
            cleartext.extend_from_slice(&decryptnonce);
            cleartext.extend_from_slice(&serialized);
            let data = cipher
                .encrypt(encryptnonce.into(), cleartext.as_ref())
                .unwrap();
            //let data = block_decrypt(&private_key, &serialized).unwrap();
            send_data(&data, &stream);
            trace!("Awaiting proof from Client-{}...", id);
            let response = receive_data(&stream);
            let ciphertext = block_decrypt(&private_key, &response).unwrap();
            let data = match cipher.decrypt(&decryptnonce.into(), &ciphertext[..]) {
                Ok(data) => {
                    if data.len() <= 24 {
                        warn!(
                            "Data is too short (proof must be at least 1b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&401_i32.to_le_bytes(), &stream);
                        stream.shutdown(std::net::Shutdown::Both).unwrap();
                        return;
                    } else {
                        data
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to decrypt data. Sending errorocode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&400_i32.to_le_bytes(), &stream);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
            };
            let encryptnonce = &data[..24];
            let proof = data[24..].to_vec();
            let proof: HandshakeProof<512, 512> = match serde_json::from_slice(&proof) {
                Ok(proof) => proof,
                Err(e) => {
                    warn!(
                        "Failed to deserialize proof. Sending vague errorcode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&501_i32.to_le_bytes(), &stream);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
            };
            let (strong_proof, _session_key_server) = match proof_verifier.verify_proof(&proof) {
                Ok(proof) => proof,
                Err(e) => {
                    warn!(
                        "Failed to verify proof. Sending vague errorcode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&501_i32.to_le_bytes(), &stream);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
            };
            trace!("Sending strong proof to Client-{}...", id);
            let serialized = serde_json::to_vec(&strong_proof).unwrap();
            rng.try_fill_bytes(&mut decryptnonce).unwrap();
            let mut cleartext = Vec::new();
            cleartext.extend_from_slice(&decryptnonce);
            cleartext.extend_from_slice(&serialized);
            let data = cipher
                .encrypt(encryptnonce.into(), cleartext.as_ref())
                .unwrap();
            send_data(&data, &stream);
            let mut hasher = Sha3_256::new();
            hasher.update(strong_proof.to_vec());
            let magic = hasher.finalize();
            match sqlx::query!(
                r#"UPDATE users
                SET nonce = ?,
                magic = ?
                WHERE username = ?"#,
                &decryptnonce[..],
                &magic[..],
                &username[..],
            )
            .execute(&pool)
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "Failed to query database. Sending errorcode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
            };
        }
        _ => {}
    }
    trace!(
        "Connection from {}:{} closed. (ID: {})",
        stream.peer_addr().unwrap().ip(),
        stream.peer_addr().unwrap().port(),
        id
    );
    stream.shutdown(std::net::Shutdown::Both).unwrap();
}

fn generate_keys(id: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let bits = retreive_config("BITS").parse::<usize>().unwrap_or(2048);
    trace!("Generating keys for Client-{}...", id);
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    trace!("Keys generated for Client-{}.", id);
    (private_key, public_key)
}

struct DataParser {
    indentifier: u8,
    payload: Vec<u8>,
}

fn parse_data(data: &[u8]) -> Result<DataParser, &'static str> {
    if data.is_empty() {
        return Err("Data is empty");
    }
    if data.len() < 2 {
        return Err("Data length is less than 2");
    }
    Ok(DataParser {
        indentifier: data[0],
        payload: data[1..].to_vec(),
    })
}

fn retreive_config(path: &str) -> String {
    if std::fs::metadata("config").is_err() {
        error!("Config file not found!");
        exit(1);
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

async fn srp6_register(
    username: &[u8],
    pool: &MySqlPool,
    stream: &TcpStream,
    salt: &[u8],
    verifier: &[u8],
    decryptnonce: &[u8],
    id: usize,
) -> Vec<u8> {
    let mut rng = OsRng;
    let mut magic = [0u8; 255];
    rng.try_fill_bytes(&mut magic).unwrap();
    trace!("Generating userid...");
    let userid: [u8; 64] = loop {
        let mut userid = [0u8; 64];
        rng.try_fill_bytes(&mut userid).unwrap();
        let result = match sqlx::query!(r#"SELECT userid FROM users WHERE userid = ?"#, &userid[..])
            .fetch_optional(pool)
            .await
        {
            Ok(data) => data,
            Err(e) => {
                error!(
                    "Failed to query database. Sending errorcode and dropping Client-{}. {}",
                    id, e
                );
                send_data(&500_i32.to_le_bytes(), stream);
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                return Vec::new();
            }
        };
        if result.is_none() {
            break userid;
        }
    };
    trace!("Checking if user exists...");
    if match sqlx::query!(r#"SELECT userid FROM users WHERE username = ?"#, &username)
        .fetch_optional(pool)
        .await
    {
        Ok(data) => data,
        Err(e) => {
            error!(
                "Failed to query database. Sending errorcode and dropping Client-{}. {}",
                id, e
            );
            send_data(&500_i32.to_le_bytes(), stream);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            return Vec::new();
        }
    }
    .is_some()
    {
        warn!(
            "Attempting to register a user that already exists. Sending vague errorcode, and dropping Client-{}.",
            id
        );
        send_data(&400_i32.to_le_bytes(), stream);
        stream.shutdown(std::net::Shutdown::Both).unwrap();
        return Vec::new();
    }
    match sqlx::query!(
        r#"
        INSERT INTO users ( userid, username, salt, verifier, nonce, magic )
        VALUES ( ?, ?, ?, ?, ?, ? )
        "#,
        &userid[..],
        username,
        salt,
        verifier,
        decryptnonce,
        &magic[..]
    )
    .execute(pool)
    .await
    {
        Ok(_) => {}
        Err(e) => {
            warn!(
                "Failed to insert user. Sending errorcode and dropping Client-{}. {}",
                id, e
            );
            send_data(&500_i32.to_le_bytes(), stream);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            return Vec::new();
        }
    };
    magic.to_vec()
}

async fn get_user_details(username: &[u8], pool: &MySqlPool, id: usize) -> UserSecrets {
    match sqlx::query!(
        "SELECT salt, verifier FROM users WHERE username = ?",
        username
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(data)) => UserSecrets {
            username: String::from_utf8_lossy(username).to_string(),
            salt: srp6::prelude::BigNumber::from(&data.salt[..]),
            verifier: srp6::prelude::BigNumber::from(&data.verifier[..]),
        },
        _ => {
            warn!("Invalid logon session sent by Client-{}", id);
            let (mut salt, mut verifier) = ([0u8; 256], [0u8; 256]);
            OsRng.try_fill_bytes(&mut salt).unwrap();
            OsRng.try_fill_bytes(&mut verifier).unwrap();
            UserSecrets {
                username: String::from_utf8_lossy(username).to_string(),
                salt: Salt::from(salt),
                verifier: PasswordVerifier::from(verifier),
            }
        }
    }
}
