use std::net::TcpStream;
use tracing::error;
use utils::send_data;
fn main() {
    tracing_subscriber::fmt().init();
    let Ok(mut stream) = TcpStream::connect("127.0.0.1:15496") else {
        error!("Failed to connect to server");
        return;
    };
    send_data(b"Hello world!", &stream);
}