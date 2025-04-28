use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey};
use std::net::{TcpListener, TcpStream};
use tracing::{error, info, trace};
use utils::{receive_data, send_data};
fn main() {
    tracing_subscriber::fmt().init();
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
                std::thread::spawn(move || {
                    handle_connection(stream);
                });
            }
            Err(e) => {
                error!("Failed to establish connection with client: {}", e)
            }
        }
    }
}

fn handle_connection(stream: TcpStream) {
    let parsed_data = parse_data(&receive_data(&stream));
    match parsed_data.indentifier {
        0 => {
            trace!("Client new session request. Initiating Diffie-Hellman handshake...");
            let server_secret = EphemeralSecret::random(&mut OsRng);
            let server_pk_bytes = EncodedPoint::from(server_secret.public_key());
            trace!("Sending server public key...");
            send_data(server_pk_bytes.as_bytes(), &stream);
            trace!("Decoding client public key... (sent along with indentifier)");
            let client_public = PublicKey::from_sec1_bytes(parsed_data.payload.as_ref())
                .expect("Invalid client public key!");
            let shared_secret = server_secret.diffie_hellman(&client_public);
            trace!("Shared secret derived!");
            //println!("{:?}", shared_secret.raw_secret_bytes());
            let (private_key, public_key) = generate_keys(2048);
            trace!("Keypair generated. Sending public key...");
            send_data(
                public_key
                    .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                    .unwrap()
                    .as_bytes(),
                &stream,
            );
            trace!("Awaiting response...");
            let payload = receive_data(&stream);
            println!(
                "Returned data: {:?}",
                private_key.decrypt(Pkcs1v15Encrypt, &payload).unwrap()
            )
        }
        1 => {
            trace!(
                "Client resume session request with ID {:?}.",
                parsed_data.payload
            );
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
