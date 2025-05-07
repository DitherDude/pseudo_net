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
use std::cmp::Ordering::{Equal, Greater, Less};
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use tracing::{error, info, trace, warn};
use utils::{block_decrypt, receive_data, send_data};
#[async_std::main]
async fn main() {
    tracing_subscriber::fmt().init();
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
    if parsed_data.indentifier == 0 {
        trace!("Client new session request. Initiating Diffie-Hellman handshake...");
    } else if parsed_data.indentifier == 1 {
        trace!("Client resume session request. Initiating Diffie-Hellman handshake...");
    }
    let server_secret = EphemeralSecret::random(&mut rng);
    let server_pk_bytes = EncodedPoint::from(server_secret.public_key());
    trace!("Decoding client public key... (sent along with indentifier)");
    let client_public = match PublicKey::from_sec1_bytes(parsed_data.payload.as_ref()) {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to decode client public key: {}", e);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    };
    let shared_secret = server_secret.diffie_hellman(&client_public);
    trace!("Shared secret derived!");
    let (private_key, public_key) = generate_keys();
    trace!("Keypair generated. Encrypting public key...");
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    let key = &hasher.finalize();
    let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(key);
    let cipher = Aes256GcmSiv::new(key);
    let mut encryptnonce = [0u8; 12];
    rng.try_fill_bytes(&mut encryptnonce).unwrap();
    let encryptnonce = Nonce::from_slice(&encryptnonce);
    let mut cleartext = Vec::new();
    let mut decryptnonce = [0u8; 12];
    rng.try_fill_bytes(&mut decryptnonce).unwrap();
    cleartext.extend_from_slice(&decryptnonce);
    cleartext.extend_from_slice(
        public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .as_ref(),
    );
    let ciphertext = cipher.encrypt(encryptnonce, cleartext.as_ref()).unwrap();
    let mut payload = Vec::new();
    payload.extend_from_slice(server_pk_bytes.as_bytes());
    payload.extend_from_slice(encryptnonce);
    payload.extend_from_slice(&ciphertext);
    trace!("Sending server public key (65b), encryptnonce (12b), and encrypted RSA-2048 key...");
    send_data(&payload, &stream);
    trace!(
        "Awaiting encryptnonce (12b) + username (?b) encryped via shared secret through the RSA-2048 public key..."
    );
    let payload = receive_data(&stream);
    let ciphertext = match block_decrypt(&private_key, &payload) {
        Ok(data) => data,
        Err(e) => {
            warn!(
                "Client sent invalid bytes. Sending errorcode and dropping connection. {}",
                e
            );
            send_data(&400_i32.to_le_bytes(), &stream);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    };
    let cleartext = match cipher.decrypt(Nonce::from_slice(&decryptnonce), &ciphertext[..]) {
        Ok(data) => {
            if data.len() <= 12 {
                warn!(
                    "Client data is too short (username must be at least 1b). Sending errorcode and dropping connection."
                );
                send_data(&401_i32.to_le_bytes(), &stream);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            } else if data.len() > 267 {
                warn!(
                    "Client data is too long (username must be less than 255b). Sending errorcode and dropping connection."
                );
                send_data(&402_i32.to_le_bytes(), &stream);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            } else {
                data
            }
        }
        Err(e) => {
            warn!(
                "Failed to decrypt data. Sending errorcode and dropping connection. {}",
                e
            );
            send_data(&400_i32.to_le_bytes(), &stream);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    };
    let pool = MySqlPool::connect(&retreive_config("PATH")).await.unwrap();
    trace!("Checking if requested user exists.");
    let username = &cleartext[12..];
    let userexists = match sqlx::query!(
        r#"SELECT COUNT(*) as count FROM users WHERE username = ?"#,
        &username
    )
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(data)) => data.count,
        Ok(None) => {
            warn!("Unexpected response from database. Sending errorcode and dropping connection.");
            send_data(&500_i32.to_le_bytes(), &stream);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
        Err(e) => {
            error!(
                "Failed to query database. Sending errorcode and dropping connection. {}",
                e
            );
            send_data(&500_i32.to_le_bytes(), &stream);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    };
    if userexists > 2 {
        warn!(
            "Invalid count of occurances for user {:?}! Sending errorcode and dropping connection.",
            &cleartext[12..]
        );
        send_data(&500_i32.to_le_bytes(), &stream);
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return;
    }
    match parsed_data.indentifier {
        0 => {
            let encryptnonce = Nonce::from_slice(&cleartext[..12]);
            rng.try_fill_bytes(&mut decryptnonce).unwrap();
            let mut cleartext = Vec::new();
            cleartext.extend_from_slice(&decryptnonce);
            cleartext.extend_from_slice(&userexists.to_le_bytes());
            let payload = cipher.encrypt(encryptnonce, cleartext.as_ref()).unwrap();
            send_data(&payload, &stream);
            if userexists == 1 {
                //login(&cleartext[12..])
            } else {
                let response = receive_data(&stream);
                let ciphertext = match block_decrypt(&private_key, &response) {
                    Ok(data) => data,
                    Err(e) => {
                        warn!(
                            "Client sent invalid bytes. Sending errorcode and dropping connection. {}",
                            e
                        );
                        send_data(&400_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                };
                let payload = match cipher
                    .decrypt(Nonce::from_slice(&decryptnonce), &ciphertext[..])
                {
                    Ok(data) => data,
                    Err(e) => {
                        warn!(
                            "Failed to decrypt data. Sending errorcode and dropping connection. {}",
                            e
                        );
                        send_data(&400_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                };
                match payload.len().cmp(&1036) {
                    Less => {
                        warn!(
                            "Client data is too short (expecting 1036b). Sending errorcode and dropping connection. {}",
                            payload.len()
                        );
                        send_data(&401_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                    Greater => {
                        warn!(
                            "Client data is too long (expecting 1036b). Sending errorcode and dropping connection."
                        );
                        send_data(&402_i32.to_le_bytes(), &stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                    Equal => {
                        let encryptnonce = &payload[..12];
                        let salt = &payload[12..524];
                        let verifier = &payload[524..1036];
                        rng.try_fill_bytes(&mut decryptnonce).unwrap();
                        let mut plaintext = Vec::new();
                        plaintext.extend_from_slice(&decryptnonce);
                        plaintext.extend_from_slice(
                            &srp6_register(username, pool, &stream, salt, verifier, &decryptnonce)
                                .await,
                        );
                        let data = cipher
                            .encrypt(Nonce::from_slice(encryptnonce), plaintext.as_ref())
                            .unwrap();
                        send_data(&data, &stream);
                    }
                }
            }
        }
        1 => {
            let (magic, encryptnonce) = match sqlx::query!(
                r#"SELECT magic, nonce FROM users WHERE username = ?"#,
                &username
            )
            .fetch_optional(&pool)
            .await
            {
                Ok(Some(data)) => (
                    data.magic.unwrap_or_else(|| {
                        let mut fluff = [0; 255];
                        let _ = rng.try_fill_bytes(&mut fluff);
                        fluff.to_vec()
                    }),
                    data.nonce.unwrap_or_else(|| {
                        let mut fluff = [0; 12];
                        let _ = rng.try_fill_bytes(&mut fluff);
                        fluff.to_vec()
                    }),
                ),
                Ok(None) => {
                    warn!(
                        "Unexpected response from database. Sending errorcode and dropping connection."
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                Err(e) => {
                    error!(
                        "Failed to query database. Sending errorcode and dropping connection. {}",
                        e
                    );
                    send_data(&500_i32.to_le_bytes(), &stream);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
            };
            let mut hasher = Sha3_256::new();
            hasher.update(magic);
            let key = &hasher.finalize();
            let key: &Key<Aes256GcmSiv> = GenericArray::from_slice(key);
            let cipher = Aes256GcmSiv::new(key);
            let num1 = rand_core::RngCore::next_u32(&mut OsRng);
            let num2 = rand_core::RngCore::next_u32(&mut OsRng);
            let mut cleartext = Vec::new();
            cleartext.extend_from_slice(&num1.to_le_bytes());
            cleartext.extend_from_slice(&num2.to_le_bytes());
            let data = cipher
                .encrypt(Nonce::from_slice(&encryptnonce), cleartext.as_ref())
                .unwrap();
            send_data(&data, &stream);
            if receive_data(&stream) != (num1 ^ num2).to_le_bytes().to_vec() {
                warn!("Verification failure. Sending vague errorcode, and dropping client.");
                send_data(&501_i32.to_le_bytes(), &stream);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
            send_data(b"session resumed!", &stream);
        }
        _ => {}
    }
    trace!(
        "Connection from {}:{} closed.",
        stream.peer_addr().unwrap().ip(),
        stream.peer_addr().unwrap().port()
    );
}

fn generate_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let bits = retreive_config("BITS").parse::<usize>().unwrap_or(2048);
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
    pool: MySqlPool,
    stream: &TcpStream,
    salt: &[u8],
    verifier: &[u8],
    decryptnonce: &[u8],
) -> Vec<u8> {
    let mut rng = OsRng;
    let mut magic = [0u8; 255];
    rng.try_fill_bytes(&mut magic).unwrap();
    trace!("Generating userid...");
    let userid: [u8; 64] = loop {
        let mut userid = [0u8; 64];
        rng.try_fill_bytes(&mut userid).unwrap();
        let result = match sqlx::query!(r#"SELECT userid FROM users WHERE userid = ?"#, &userid[..])
            .fetch_optional(&pool)
            .await
        {
            Ok(data) => data,
            Err(e) => {
                error!(
                    "Failed to query database. Sending errorcode and dropping client. {}",
                    e
                );
                send_data(&500_i32.to_le_bytes(), stream);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Vec::new();
            }
        };
        if result.is_none() {
            break userid;
        }
    };
    trace!("Checking if user exists...");
    if match sqlx::query!(r#"SELECT userid FROM users WHERE username = ?"#, &username)
        .fetch_optional(&pool)
        .await
    {
        Ok(data) => data,
        Err(e) => {
            error!(
                "Failed to query database. Sending errorcode and dropping client. {}",
                e
            );
            send_data(&500_i32.to_le_bytes(), stream);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Vec::new();
        }
    }
    .is_some()
    {
        warn!(
            "Attempting to register a user that already exists. Sending vague errorcode, and dropping client."
        );
        send_data(&400_i32.to_le_bytes(), stream);
        let _ = stream.shutdown(std::net::Shutdown::Both);
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
    .execute(&pool)
    .await
    {
        Ok(_) => {}
        Err(e) => {
            warn!(
                "Failed to insert user. Sending errorcode and dropping client. {}",
                e
            );
            send_data(&500_i32.to_le_bytes(), stream);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Vec::new();
        }
    };
    magic.to_vec()
}
