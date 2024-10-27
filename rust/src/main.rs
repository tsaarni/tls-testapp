use std::sync::Arc;
use std::io::Write;
use std::io::BufRead;

use rustls::pki_types::pem::{PemObject};

const SERVER_ADDR: &str = "localhost";
const SERVER_PORT: &str = "9876";


fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|x| x.as_str()) {
        Some("server") => run_server().expect("Server error"),
        Some("client") => run_client().expect("Client error"),
        _ => {
            eprintln!("Usage: {} [server|client]", args[0]);
            std::process::exit(1);
        }
    }
}

fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter("server.pem")?
        .map(|cert| cert.unwrap())
        .collect();

    let key = rustls::pki_types::PrivateKeyDer::from_pem_file("server-key.pem")?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            certs,
            key,
        )?;

    let listener = std::net::TcpListener::bind(format!("{}:{}", SERVER_ADDR, SERVER_PORT))?;
    println!("Listening on {}:{}", SERVER_ADDR, SERVER_PORT);

    for sock in listener.incoming() {
        match sock {
            Ok(sock) => {
                let result = handle_client_conn(sock, Arc::new(config.clone()));
                if let Err(e) = result {
                    eprintln!("Error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    return Ok(());
}


fn handle_client_conn(mut sock: std::net::TcpStream, config: Arc<rustls::ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connection from: {}", sock.peer_addr()?);

    let mut conn = rustls::ServerConnection::new(config)?;
    conn.complete_io(&mut sock)?;

    let mut stream = rustls::Stream::new(&mut conn, &mut sock);
    loop {
        let mut reader = std::io::BufReader::new(&mut stream);
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            println!("Connection closed");
            break;
        }
        println!("Received: {}", line.trim());
        println!("Sending: {}", line.trim());
        stream.write_all(line.as_bytes())?;
    }

    return Ok(());
}

fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    let mut root_store = rustls::RootCertStore{
        roots: Vec::new()
    };
    root_store.add(rustls::pki_types::CertificateDer::from_pem_file("server-ca.pem")?)?;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    loop {
        let sock = std::net::TcpStream::connect(format!("{}:{}", SERVER_ADDR, SERVER_PORT));
        if let Err(e) = sock {
            eprintln!("Connection failed: {}", e);
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        }
        let result = handle_server_conn(sock.unwrap(), Arc::new(config.clone()));
        if let Err(e) = result {
            eprintln!("Error: {}", e);
        }
    }
}

fn handle_server_conn(mut sock: std::net::TcpStream, config: Arc<rustls::ClientConfig>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to: {}", sock.peer_addr()?);
    let mut conn = rustls::ClientConnection::new(config, SERVER_ADDR.try_into()?)?;

    let mut stream = rustls::Stream::new(&mut conn, &mut sock);
    loop {
        let message = "Hello, world!\n";

        stream.write_all(message.as_bytes())?;
        println!("Sent: {}", message.trim());

        let mut reader = std::io::BufReader::new(&mut stream);
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            println!("Connection closed");
            break;
        }
        println!("Received: {}", line.trim());
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    return Ok(());
}
