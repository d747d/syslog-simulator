use clap::{Parser, ValueEnum};
use chrono::{DateTime, Utc};
use native_tls::{TlsConnector, Protocol as TlsProtocol};
use rand::{distributions::Alphanumeric, Rng, thread_rng};
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::interval;

#[derive(Parser, Debug)]
#[clap(
    name = "sysloggen",
    author = "Syslog Generator",
    version = "1.0.0",
    about = "Generate and send fake syslog messages for load testing"
)]
struct Args {
    /// Transport protocol to use (udp or tcp)
    #[clap(short, long, value_enum, default_value_t = Protocol::Udp)]
    protocol: Protocol,

    /// Destination address (e.g., 127.0.0.1:514)
    #[clap(short, long, required = true)]
    destination: String,

    /// Number of source hosts to simulate
    #[clap(short, long, default_value_t = 1)]
    hosts: usize,

    /// Size of syslog packets in bytes
    #[clap(short, long, default_value_t = 200)]
    size: usize,

    /// Rate of sending messages (per second)
    #[clap(short, long, default_value_t = 10)]
    rate: u64,

    /// TLS version (for TCP only): 1.0, 1.1, 1.2, 1.3
    #[clap(short = 't', long, value_enum)]
    tls: Option<TlsVersion>,

    /// Syslog facility (0-23, default: 4 - auth)
    #[clap(short = 'f', long, default_value_t = 4)]
    facility: u8,

    /// Syslog severity (0-7, default: 2 - critical)
    #[clap(short = 'v', long, default_value_t = 2)]
    severity: u8,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Protocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TlsVersion {
    V1_0,
    V1_1,
    V1_2,
    V1_3,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Validate arguments
    if matches!(args.protocol, Protocol::Udp) && args.tls.is_some() {
        eprintln!("Error: TLS can only be used with TCP protocol");
        std::process::exit(1);
    }

    if args.facility > 23 {
        eprintln!("Error: Facility must be between 0 and 23");
        std::process::exit(1);
    }

    if args.severity > 7 {
        eprintln!("Error: Severity must be between 0 and 7");
        std::process::exit(1);
    }

    // Create rate limiter
    let mut interval = interval(Duration::from_millis(1000 / args.rate));
    
    // Track statistics
    let start_time = Instant::now();
    let mut count: u64 = 0;

    match args.protocol {
        Protocol::Udp => {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let dest = match args.destination.to_socket_addrs()?.next() {
                Some(addr) => addr,
                None => {
                    eprintln!("Error: Invalid destination address");
                    std::process::exit(1);
                }
            };

            println!("Sending UDP syslog messages to {}", args.destination);
            println!("Press Ctrl+C to stop");
            
            loop {
                interval.tick().await;
                
                let host_id = (count % args.hosts as u64 + 1) as usize;
                let msg = generate_syslog(host_id, args.size, args.facility, args.severity);
                
                socket.send_to(msg.as_bytes(), &dest).await?;
                
                count += 1;
                print_stats(count, start_time);
            }
        },
        Protocol::Tcp => {
            // Handle either TLS or plain TCP connection
            let dest_addr = match args.destination.to_socket_addrs()?.next() {
                Some(addr) => addr,
                None => {
                    eprintln!("Error: Invalid destination address");
                    std::process::exit(1);
                }
            };
            
            if let Some(tls_version) = args.tls {
                // Set up TLS connection
                let tls_proto = match tls_version {
                    TlsVersion::V1_0 => TlsProtocol::Tlsv10,
                    TlsVersion::V1_1 => TlsProtocol::Tlsv11,
                    TlsVersion::V1_2 => TlsProtocol::Tlsv12,
                    TlsVersion::V1_3 => {
                        println!("Warning: TLS 1.3 requested but may not be supported by native-tls");
                        TlsProtocol::Tlsv12 // Use 1.2 as fallback
                    },
                };
                
                // Extract hostname from destination for TLS verification
                let hostname = args.destination.split(':').next().unwrap_or("localhost");
                
                let mut tls_builder = TlsConnector::builder();
                tls_builder.min_protocol_version(Some(tls_proto));
                
                let connector = match tls_builder.build() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error setting up TLS: {}", e);
                        std::process::exit(1);
                    }
                };
                let connector = tokio_native_tls::TlsConnector::from(connector);
                
                let tcp_stream = match TcpStream::connect(dest_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Error connecting to {}: {}", args.destination, e);
                        std::process::exit(1);
                    }
                };
                
                let mut tls_stream = match connector.connect(hostname, tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Error establishing TLS connection: {}", e);
                        std::process::exit(1);
                    }
                };
                
                println!("Sending TLS syslog messages to {}", args.destination);
                println!("Press Ctrl+C to stop");
                
                // Send messages over TLS
                loop {
                    interval.tick().await;
                    
                    let host_id = (count % args.hosts as u64 + 1) as usize;
                    let msg = generate_syslog(host_id, args.size, args.facility, args.severity);
                    let msg_with_delimiter = format!("{}\n", msg);
                    
                    match tls_stream.write_all(msg_with_delimiter.as_bytes()).await {
                        Ok(_) => {},
                        Err(e) => {
                            eprintln!("Error sending message: {}", e);
                            break;
                        }
                    };
                    
                    count += 1;
                    print_stats(count, start_time);
                }
            } else {
                // Plain TCP connection
                let mut stream = match TcpStream::connect(dest_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Error connecting to {}: {}", args.destination, e);
                        std::process::exit(1);
                    }
                };
                
                println!("Sending TCP syslog messages to {}", args.destination);
                println!("Press Ctrl+C to stop");
                
                // Send messages over plain TCP
                loop {
                    interval.tick().await;
                    
                    let host_id = (count % args.hosts as u64 + 1) as usize;
                    let msg = generate_syslog(host_id, args.size, args.facility, args.severity);
                    let msg_with_delimiter = format!("{}\n", msg);
                    
                    match stream.write_all(msg_with_delimiter.as_bytes()).await {
                        Ok(_) => {},
                        Err(e) => {
                            eprintln!("Error sending message: {}", e);
                            break;
                        }
                    };
                    
                    count += 1;
                    print_stats(count, start_time);
                }
            }
        }
    }

    Ok(())
}

// Function to generate a random syslog message following RFC 5424
fn generate_syslog(host_id: usize, packet_size: usize, facility: u8, severity: u8) -> String {
    // RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
    
    // Generate priority (facility * 8 + severity)
    let pri = (facility as u16 * 8 + severity as u16) % 192;
    
    // Generate timestamp in RFC 3339 format
    let now: DateTime<Utc> = Utc::now();
    let timestamp = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    
    // Generate hostname, app name, proc id, and msg id
    let hostname = format!("host-{:05}", host_id);
    let app_name = "sysloggen";
    let proc_id = thread_rng().gen_range(1..10000).to_string();
    let msg_id = format!("ID{:06}", thread_rng().gen_range(1..1000000));
    
    // Calculate the header size to determine how much space is left for the message
    let header = format!("<{}>1 {} {} {} {} {} - ", pri, timestamp, hostname, app_name, proc_id, msg_id);
    let header_len = header.len();
    
    // Generate random content that fits within the packet size
    let content_size = if packet_size > header_len { packet_size - header_len } else { 1 };
    let content: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(content_size)
        .map(char::from)
        .collect();
    
    // Combine all parts to form the complete syslog message
    format!("{}{}", header, content)
}

// Function to print statistics about the messages sent
fn print_stats(count: u64, start_time: Instant) {
    if count % 1000 == 0 {
        let elapsed = start_time.elapsed();
        let seconds = elapsed.as_secs_f64();
        let rate = count as f64 / seconds;
        
        println!(
            "Sent {} messages in {:.2}s (avg rate: {:.2} msgs/sec)",
            count, seconds, rate
        );
    }
}