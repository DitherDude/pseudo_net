use std::net::{TcpListener, TcpStream};
use tracing::{error, info};
use utils::get_data;
fn main() {
    tracing_subscriber::fmt().init();
    let listener = TcpListener::bind("127.0.0.1:15496").unwrap();
    info!("Server listening on 127.0.0.1:15496");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("New client connected.");
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

fn handle_connection(mut stream: TcpStream) {
    let data = get_data(&stream);
    println!("{data:?}");
}