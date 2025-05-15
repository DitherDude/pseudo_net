use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, OsRng},
};
use figment::{
    Figment,
    providers::{Format, Yaml},
};
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey, rand_core::RngCore};
use sha3::{Digest, Sha3_256, Sha3_512};
use sqlx::mysql::MySqlPool;
use srp6::prelude::*;
use std::cmp::Ordering::{Equal, Greater, Less};
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use tracing::{Level, debug, error, info, trace, warn};
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
    match MySqlPool::connect(&retreive_config::<String>("path").unwrap_or_else(|| {
        error!("Failed to query config yaml. Please see docs on how to create a config file.");
        exit(1);
    }))
    .await
    {
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
                            )
                            ENGINE=InnoDB
                            DEFAULT CHARSET=utf8mb4
                            COLLATE=utf8mb4_0900_ai_ci; 
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
            trace!("Checking clients table schema...");
            match sqlx::query!(
                r#"
                SELECT
                    COUNT(*) as count
                FROM
                    INFORMATION_SCHEMA.COLUMNS
                WHERE
                    TABLE_NAME = 'clients'
                AND (
                    (COLUMN_NAME = 'client' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 255 AND IS_NULLABLE = 'NO')
                    OR (COLUMN_NAME = 'penalty' AND DATA_TYPE = 'int' AND IS_NULLABLE = 'NO' AND COLUMN_DEFAULT = '0')
                    OR (COLUMN_NAME = 'locked' AND DATA_TYPE = 'tinyint' AND IS_NULLABLE = 'NO' AND COLUMN_DEFAULT = '0')
                );
                "#
            )
            .fetch_optional(&pool)
            .await
            {
                Ok(Some(e)) => {
                    if e.count == 3 {
                        trace!("Clients table schema is valid.");
                    } else {
                        warn!("Missing clients table. Will attempt to create it.");
                        match sqlx::query!(
                            r#"
                            CREATE TABLE PSEUDO_NET.clients (
                                client VARCHAR(255) NOT NULL UNIQUE,
                                penalty INT UNSIGNED DEFAULT 0 NOT NULL,
                                locked BOOL DEFAULT 0 NOT NULL
                            )
                            ENGINE=InnoDB
                            DEFAULT CHARSET=utf8mb4
                            COLLATE=utf8mb4_0900_ai_ci;
                            "#
                        )
                        .execute(&pool)
                        .await
                        {
                            Ok(_) => {
                                trace!("Created clients table.");
                            }
                            Err(e) => {
                                error!("Failed to create clients table: {}", e);
                                exit(1);
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Failed to check clients table schema: {}", e);
                    exit(1);
                }
            }
        }
        Err(e) => {
            error!("Failed to connect to database: {}", e);
            exit(1);
        }
    };
    let port = retreive_config("port").unwrap_or(15496);
    let listener = match TcpListener::bind("127.0.0.1:".to_owned() + &port.to_string()) {
        Ok(listener) => listener,
        Err(e) => {
            error!("Port is busy! {}", e);
            return;
        }
    };
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
    let clientip = stream.peer_addr().unwrap().ip().to_string();
    let pool = MySqlPool::connect(&retreive_config::<String>("path").unwrap())
        .await
        .unwrap();
    match sqlx::query!(
        r#"
        SELECT
        penalty, locked
        FROM clients
        WHERE
        client = ?
        "#,
        clientip
    )
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(data)) => {
            if data.locked == 1
                || data.penalty > retreive_config::<u32>("client.lockout").unwrap_or(1000)
            {
                debug!(
                    "Client-{} is locked out. Sending errorcode and dropping connection.",
                    id
                );
                send_data(&403_i32.to_le_bytes(), &stream);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
        }
        Err(e) => {
            debug!(
                "Internal error! Sending errorcode to Client-{} and dropping connection. {}",
                id, e
            );
            send_data(&500_i32.to_le_bytes(), &stream);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
        _ => {
            trace!("Client-{} record is clear! Proceeding...", id);
        }
    };
    trace!("Keypair generated for Client-{}.", id);
    let (private_key, public_key) = generate_keys(id);
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
        "Decoding Client-{} public key... (sent along with indentifier)",
        id
    );
    let client_public = match PublicKey::from_sec1_bytes(parsed_data.payload.as_ref()) {
        Ok(data) => data,
        Err(e) => {
            debug!("Failed to decode Client-{} public key: {}", id, e);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    };
    let shared_secret = server_secret.diffie_hellman(&client_public);
    trace!(
        "Shared secret derived from Client-{}! Encrypting public key...",
        id
    );
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    let key = &hasher.finalize();
    let cipher = XChaCha20Poly1305::new(key);
    let mut encryptnonce: [u8; 24] = [0u8; 24];
    rng.try_fill_bytes(&mut encryptnonce).unwrap();
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
            debug!(
                "Client-{} sent invalid bytes. Sending errorcode and dropping connection. {}",
                id, e
            );
            send_data(&400_i32.to_le_bytes(), &stream);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    };
    match parsed_data.indentifier {
        0 => {
            let cleartext = match cipher.decrypt(&decryptnonce.into(), &ciphertext[..]) {
                Ok(data) => {
                    if data.len() <= 24 {
                        debug!(
                            "Data is too short (username must be at least 1b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&401_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    } else if data.len() > 279 {
                        debug!(
                            "Data is too long (username must be less than 255b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&402_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    } else {
                        data
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to decrypt data from Client-{}. Sending errorcode and dropping connection. {}",
                        id, e
                    );
                    send_data(&400_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
            };
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
                    debug!(
                        "Unexpected response from database. Sending errorocode and dropping Client-{}.",
                        id
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                Err(e) => {
                    error!(
                        "Failed to query database. Sending errorocode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
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
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
            let encryptnonce = &cleartext[..24];
            rng.try_fill_bytes(&mut decryptnonce).unwrap();
            let mut cleartext = Vec::new();
            cleartext.extend_from_slice(&decryptnonce);
            cleartext.extend_from_slice(&userexists.to_le_bytes());
            let payload = cipher
                .encrypt(encryptnonce.into(), cleartext.as_ref())
                .unwrap();
            send_data(&payload, &stream);
            if userexists != 1 {
                let response = receive_data(&stream);
                let ciphertext = match block_decrypt(&private_key, &response) {
                    Ok(data) => data,
                    Err(e) => {
                        debug!(
                            "Client-{} sent invalid bytes. Sending errorcode and dropping connection. {}",
                            id, e
                        );
                        send_data(&400_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                };
                let payload = match cipher.decrypt(&decryptnonce.into(), &ciphertext[..]) {
                    Ok(data) => data,
                    Err(e) => {
                        debug!(
                            "Failed to decrypt data. Sending errorocode and dropping Client-{}. {}",
                            id, e
                        );
                        send_data(&400_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                };
                match payload.len().cmp(&1048) {
                    Less => {
                        debug!(
                            "Data is too short (expecting 1048b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&401_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                    Greater => {
                        debug!(
                            "Data is too long (expecting 1048b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&402_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                    Equal => {
                        let encryptnonce = &payload[..24];
                        let salt = &payload[24..536];
                        let verifier = &payload[536..1048];
                        rng.try_fill_bytes(&mut decryptnonce).unwrap();
                        let mut plaintext = Vec::new();
                        if srp6_register(username, &pool, &stream, salt, verifier, id).await {
                            let token = get_user_token(username, &pool).await;
                            plaintext.extend_from_slice(&decryptnonce);
                            plaintext.extend_from_slice(&match token {
                            Some(data) => data,
                            None => {
                                debug!(
                                    "Failed to generate token. Sending errorcode and dropping Client-{}.",
                                    id
                                );
                                send_data(&500_i32.to_le_bytes(), &stream);
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                return;
                            }
                        });
                            let data = cipher
                                .encrypt(encryptnonce.into(), plaintext.as_ref())
                                .unwrap();
                            send_data(&data, &stream);
                        } else {
                            warn!(
                                "Somehow we got here. It wasn't our fault, rather that of Client-{}",
                                id
                            );
                            return;
                        }
                    }
                }
            }
        }
        1 => {
            let cleartext = match cipher.decrypt(&decryptnonce.into(), &ciphertext[..]) {
                Ok(data) => {
                    if data.len() <= 280 {
                        debug!(
                            "Data is too short (key should be 256b, and username must be at least 1b). {}. Sending errorcode and dropping Client-{}.",
                            data.len(),
                            id
                        );
                        send_data(&401_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    } else if data.len() > 535 {
                        debug!(
                            "Data is too long (username must be less than 255b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&402_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    } else {
                        data
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to decrypt data from Client-{}. Sending errorcode and dropping connection. {}",
                        id, e
                    );
                    send_data(&400_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
            };
            let mut failed = false;
            let usertoken = &cleartext[24..280];
            let username = &cleartext[280..];
            trace!(
                "Checking if Client-{}'s requested user \"{:?}\" exists.",
                id, &username
            );
            let userexists = match sqlx::query!(
                r#"SELECT COUNT(*) as count FROM users WHERE username = ?"#,
                &username
            )
            .fetch_optional(&pool)
            .await
            {
                Ok(Some(data)) => data.count,
                Ok(None) => {
                    debug!(
                        "Unexpected response from database. Sending errorocode and dropping Client-{}.",
                        id
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                Err(e) => {
                    error!(
                        "Failed to query database. Sending errorocode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
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
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
            let token = match get_user_token(username, &pool).await {
                Some(data) => {
                    trace!("Got token for user {:?}.", username);
                    data
                }
                _ => {
                    debug!(
                        "Incurred error receiveing token for user {:?}. Spoofing Client-{}.",
                        username, id
                    );
                    failed = true;
                    let mut fluff = [0u8; 256];
                    rng.try_fill_bytes(&mut fluff).unwrap();
                    fluff.to_vec()
                }
            };
            if token != usertoken {
                debug!(
                    "Token mismatch for user {:?}. Dropping Client-{}.",
                    username, id
                );
                failed = true;
            }
            if failed {
                debug!(
                    "Verification failure. Sending vague errorcode, and dropping Client-{}.",
                    id
                );
                if user_penalise(
                    username,
                    &pool,
                    retreive_config::<i32>("user.penalty").unwrap_or(50),
                )
                .await
                .is_none()
                {
                    debug!("Failed to penalise user.");
                }
                if client_penalise(
                    &clientip,
                    &pool,
                    retreive_config::<i32>("client.penalty").unwrap_or(50),
                )
                .await
                .is_none()
                {
                    debug!("Failed to penalise client.");
                }
                send_data(&501_i32.to_le_bytes(), &stream);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
            trace!("Client-{} passed verification.", id);
            send_data(b"session resumed!", &stream);
            if user_penalise(
                username,
                &pool,
                retreive_config::<i32>("user.forgive").unwrap_or(-100),
            )
            .await
            .is_none()
            {
                debug!("Failed to forgive user.");
            }
            if client_penalise(
                &clientip,
                &pool,
                retreive_config::<i32>("client.forgive").unwrap_or(-100),
            )
            .await
            .is_none()
            {
                debug!("Failed to forgive client.");
            }
        }
        2 => {
            let cleartext = match cipher.decrypt(&decryptnonce.into(), &ciphertext[..]) {
                Ok(data) => {
                    if data.len() <= 24 {
                        debug!(
                            "Data is too short (username must be at least 1b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&401_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    } else if data.len() > 279 {
                        debug!(
                            "Data is too long (username must be less than 255b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&402_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    } else {
                        data
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to decrypt data from Client-{}. Sending errorcode and dropping connection. {}",
                        id, e
                    );
                    send_data(&400_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
            };
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
                    debug!(
                        "Unexpected response from database. Sending errorocode and dropping Client-{}.",
                        id
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                Err(e) => {
                    error!(
                        "Failed to query database. Sending errorocode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
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
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
            let encryptnonce = &cleartext[..24];
            let srp = Srp6_4096::default();
            let (handshake, proof_verifier) =
                srp.start_handshake(&get_user_secrets(username, &pool, id).await);
            trace!("Sending serialized handshake to Client-{}...", id);
            let serialized = serde_json::to_vec(&handshake).unwrap();
            rng.try_fill_bytes(&mut decryptnonce).unwrap();
            let mut cleartext = Vec::new();
            cleartext.extend_from_slice(&decryptnonce);
            cleartext.extend_from_slice(&serialized);
            let data = cipher
                .encrypt(encryptnonce.into(), cleartext.as_ref())
                .unwrap();
            send_data(&data, &stream);
            trace!("Awaiting proof from Client-{}...", id);
            let response = receive_data(&stream);
            let ciphertext = block_decrypt(&private_key, &response).unwrap();
            let data = match cipher.decrypt(&decryptnonce.into(), &ciphertext[..]) {
                Ok(data) => {
                    if data.len() <= 24 {
                        debug!(
                            "Data is too short (proof must be at least 1b). Sending errorcode and dropping Client-{}.",
                            id
                        );
                        send_data(&401_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    } else {
                        data
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to decrypt data. Sending errorocode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&400_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
            };
            let encryptnonce = &data[..24];
            let proof = data[24..].to_vec();
            let proof: HandshakeProof<512, 512> = match serde_json::from_slice(&proof) {
                Ok(proof) => proof,
                Err(e) => {
                    debug!(
                        "Failed to deserialize proof. Sending vague errorcode and dropping Client-{}. {}",
                        id, e
                    );
                    send_data(&501_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
            };
            let mut verified = true;
            let (_strong_proof, _session_key_server) = match proof_verifier.verify_proof(&proof) {
                Ok(proof) => proof,
                Err(e) => {
                    debug!("Failed to verify proof. Spoofing Client-{}. {}", id, e);
                    verified = false;
                    let mut fluff = [0u8; 32];
                    let mut fluff2 = [0u8; 32];
                    let _ = rng.try_fill_bytes(&mut fluff);
                    let _ = rng.try_fill_bytes(&mut fluff2);
                    if user_penalise(
                        username,
                        &pool,
                        retreive_config::<i32>("user.penalty").unwrap_or(50),
                    )
                    .await
                    .is_none()
                    {
                        debug!("Failed to penalise user.");
                    }
                    if client_penalise(
                        &clientip,
                        &pool,
                        retreive_config::<i32>("client.penalty").unwrap_or(50),
                    )
                    .await
                    .is_none()
                    {
                        debug!("Failed to penalise client.");
                    }
                    (BigNumber::from(fluff), BigNumber::from(fluff2))
                }
            };
            let mut decryptnonce = decryptnonce.to_vec();
            let serialized = if verified {
                trace!("Sending unlockkey to Client-{}...", id);
                decryptnonce =
                    match sqlx::query!("SELECT nonce FROM users WHERE username = ?", username)
                        .fetch_optional(&pool)
                        .await
                    {
                        Ok(data) => match data {
                            Some(data) => data.nonce.unwrap_or_else(|| {
                                debug!("Database error!");
                                let mut fluff = [0u8; 24];
                                rng.try_fill_bytes(&mut fluff).unwrap();
                                fluff.to_vec()
                            }),
                            None => {
                                debug!("Database error!");
                                let mut fluff = [0u8; 24];
                                rng.try_fill_bytes(&mut fluff).unwrap();
                                fluff.to_vec()
                            }
                        },
                        Err(e) => {
                            warn!("Failed to query database. {}", e);
                            let mut fluff = [0u8; 24];
                            rng.try_fill_bytes(&mut fluff).unwrap();
                            fluff.to_vec()
                        }
                    };
                get_user_token(username, &pool).await.unwrap_or_default()
            } else {
                debug!("Generating spoof key for Client-{}...", id);
                let mut fluff = [0u8; 256];
                rng.try_fill_bytes(&mut fluff).unwrap();
                fluff.to_vec()
            };
            let mut cleartext = Vec::new();
            cleartext.extend_from_slice(&decryptnonce);
            cleartext.extend_from_slice(&serialized);
            let data = cipher
                .encrypt(encryptnonce.into(), cleartext.as_ref())
                .unwrap();
            send_data(&data, &stream);
        }
        _ => {}
    }
    trace!(
        "Connection from {}:{} closed. (ID: {})",
        stream.peer_addr().unwrap().ip(),
        stream.peer_addr().unwrap().port(),
        id
    );
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn generate_keys(id: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let bits = retreive_config::<usize>("bits").unwrap_or(2048);
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

async fn srp6_register(
    username: &[u8],
    pool: &MySqlPool,
    stream: &TcpStream,
    salt: &[u8],
    verifier: &[u8],
    id: usize,
) -> bool {
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
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return false;
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
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return false;
        }
    }
    .is_some()
    {
        debug!(
            "Attempting to register a user that already exists. Sending vague errorcode, and dropping Client-{}.",
            id
        );
        send_data(&400_i32.to_le_bytes(), stream);
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return false;
    }
    match sqlx::query!(
        r#"
        INSERT INTO users ( userid, username, salt, verifier, magic )
        VALUES ( ?, ?, ?, ?, ? )
        "#,
        &userid[..],
        username,
        salt,
        verifier,
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
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return false;
        }
    };
    true
}

async fn get_user_secrets(username: &[u8], pool: &MySqlPool, id: usize) -> UserSecrets {
    match sqlx::query!(
        "SELECT salt, verifier, danger, locked FROM users WHERE username = ?",
        username
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(data)) => {
            if data.locked == 1
                || data.danger > retreive_config::<u32>("user.lockout").unwrap_or(1000)
            {
                trace!(
                    "Client-{} requesting to login to user {:?}, who has been locked out",
                    id, username
                );
                let (mut salt, mut verifier) = ([0u8; 256], [0u8; 256]);
                OsRng.try_fill_bytes(&mut salt).unwrap();
                OsRng.try_fill_bytes(&mut verifier).unwrap();
                UserSecrets {
                    username: String::from_utf8_lossy(username).to_string(),
                    salt: Salt::from(salt),
                    verifier: PasswordVerifier::from(verifier),
                }
            } else {
                UserSecrets {
                    username: String::from_utf8_lossy(username).to_string(),
                    salt: srp6::prelude::BigNumber::from(&data.salt[..]),
                    verifier: srp6::prelude::BigNumber::from(&data.verifier[..]),
                }
            }
        }
        _ => {
            debug!("Invalid logon session sent by Client-{}", id);
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

async fn get_user_token(username: &[u8], pool: &MySqlPool) -> Option<Vec<u8>> {
    let (userid, salt, verifier, magic) = match sqlx::query!(
        "SELECT userid, salt, verifier, magic FROM users WHERE username = ?",
        username
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(data)) => (data.userid, data.salt, data.verifier, data.magic),
        _ => return None,
    };
    let mut cleartext = Vec::new();
    cleartext.extend_from_slice(username);
    cleartext.extend_from_slice(&userid);
    cleartext.extend_from_slice(&salt);
    cleartext.extend_from_slice(&verifier);
    cleartext.extend_from_slice(&magic.unwrap_or_default());
    let mut hash = Sha3_512::new();
    hash.update(&cleartext);
    let token = hash.finalize();
    Some(token.to_vec())
}

async fn user_penalise(username: &[u8], pool: &MySqlPool, amount: i32) -> Option<u32> {
    let current = match sqlx::query!("SELECT danger FROM users WHERE username = ?", username)
        .fetch_optional(pool)
        .await
    {
        Ok(data) => match data {
            Some(data) => data.danger,
            None => {
                debug!("Database error!");
                return None;
            }
        },
        Err(e) => {
            warn!("Failed to query database. {}", e);
            return None;
        }
    };
    match amount.cmp(&0) {
        Equal => Some(0),
        Greater => {
            let new = current.saturating_add(amount as u32);
            match sqlx::query!(
                "UPDATE users SET danger = ? WHERE username = ?",
                new,
                username
            )
            .execute(pool)
            .await
            {
                Ok(_) => Some(new),
                Err(e) => {
                    warn!("Failed to query database. {}", e);
                    None
                }
            }
        }
        Less => {
            let new = current.saturating_sub(amount.unsigned_abs());
            match sqlx::query!(
                "UPDATE users SET danger = ? WHERE username = ?",
                new,
                username
            )
            .execute(pool)
            .await
            {
                Ok(_) => Some(new),
                Err(e) => {
                    warn!("Failed to query database. {}", e);
                    None
                }
            }
        }
    }
}

async fn client_penalise(client: &str, pool: &MySqlPool, amount: i32) -> Option<u32> {
    let current = match sqlx::query!("SELECT penalty FROM clients WHERE client = ?", client)
        .fetch_optional(pool)
        .await
    {
        Ok(data) => match data {
            Some(data) => data.penalty,
            None => {
                match sqlx::query!(
                    r#"
                    INSERT INTO clients (client)
                    VALUES (?)
                    "#,
                    client
                )
                .execute(pool)
                .await
                {
                    Ok(_) => 0,
                    Err(e) => {
                        warn!("Failed to insert client! {}", e);
                        return None;
                    }
                }
            }
        },
        Err(e) => {
            warn!("Failed to query database. {}", e);
            return None;
        }
    };
    match amount.cmp(&0) {
        Equal => Some(0),
        Greater => {
            let new = current.saturating_add(amount as u32);
            match sqlx::query!(
                "UPDATE clients SET penalty = ? WHERE client = ?",
                new,
                client
            )
            .execute(pool)
            .await
            {
                Ok(_) => Some(new),
                Err(e) => {
                    warn!("Failed to query database. {}", e);
                    None
                }
            }
        }
        Less => {
            let new = current.saturating_sub(amount.unsigned_abs());
            match sqlx::query!(
                "UPDATE clients SET penalty = ? WHERE client = ?",
                new,
                client
            )
            .execute(pool)
            .await
            {
                Ok(_) => Some(new),
                Err(e) => {
                    warn!("Failed to query database. {}", e);
                    None
                }
            }
        }
    }
}

fn retreive_config<'x, T: serde::de::Deserialize<'x>>(fig: &str) -> Option<T> {
    let figment = Figment::new().merge(Yaml::file("config.yml"));
    match figment.extract_inner(fig) {
        Ok(data) => Some(data),
        Err(e) => {
            debug!("Failed to query config yaml. {}", e);
            None
        }
    }
}
