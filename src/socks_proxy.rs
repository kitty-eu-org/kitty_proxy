#![forbid(unsafe_code)]
// #[macro_use]
// extern crate serde_derive;

use log::{debug, error, info, trace, warn};

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::time::timeout;

use crate::types::{KittyProxyError, ResponseCode};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
#[cfg(windows)]
use tokio::signal::windows::ctrl_c;

/// Version of socks
const SOCKS_VERSION: u8 = 0x05;

const RESERVED: u8 = 0x00;

pub struct SocksReply {
    // From rfc 1928 (S6),
    // the server evaluates the request, and returns a reply formed as follows:
    //
    //    +----+-----+-------+------+----------+----------+
    //    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //    +----+-----+-------+------+----------+----------+
    //    | 1  |  1  | X'00' |  1   | Variable |    2     |
    //    +----+-----+-------+------+----------+----------+
    //
    // Where:
    //
    //      o  VER    protocol version: X'05'
    //      o  REP    Reply field:
    //         o  X'00' succeeded
    //         o  X'01' general SOCKS server failure
    //         o  X'02' connection not allowed by ruleset
    //         o  X'03' Network unreachable
    //         o  X'04' Host unreachable
    //         o  X'05' Connection refused
    //         o  X'06' TTL expired
    //         o  X'07' Command not supported
    //         o  X'08' Address type not supported
    //         o  X'09' to X'FF' unassigned
    //      o  RSV    RESERVED
    //      o  ATYP   address type of following address
    //         o  IP V4 address: X'01'
    //         o  DOMAINNAME: X'03'
    //         o  IP V6 address: X'04'
    //      o  BND.ADDR       server bound address
    //      o  BND.PORT       server bound port in network octet order
    //
    buf: [u8; 10],
}

impl SocksReply {
    pub fn new(status: ResponseCode) -> Self {
        let buf = [
            // VER
            SOCKS_VERSION,
            // REP
            status as u8,
            // RSV
            RESERVED,
            // ATYP
            1,
            // BND.ADDR
            0,
            0,
            0,
            0,
            // BND.PORT
            0,
            0,
        ];
        Self { buf }
    }

    pub async fn send<T>(&self, stream: &mut T) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        stream.write_all(&self.buf[..]).await?;
        Ok(())
    }
}

/// DST.addr variant types
#[derive(PartialEq)]
enum AddrType {
    /// IP V4 address: X'01'
    V4 = 0x01,
    /// DOMAINNAME: X'03'
    Domain = 0x03,
    /// IP V6 address: X'04'
    V6 = 0x04,
}

impl AddrType {
    /// Parse Byte to Command
    fn from(n: usize) -> Option<AddrType> {
        match n {
            1 => Some(AddrType::V4),
            3 => Some(AddrType::Domain),
            4 => Some(AddrType::V6),
            _ => None,
        }
    }

    // /// Return the size of the AddrType
    // fn size(&self) -> u8 {
    //     match self {
    //         AddrType::V4 => 4,
    //         AddrType::Domain => 1,
    //         AddrType::V6 => 16
    //     }
    // }
}

/// SOCK5 CMD Type
#[derive(Debug)]
enum SockCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssosiate = 0x3,
}

impl SockCommand {
    /// Parse Byte to Command
    fn from(n: usize) -> Option<SockCommand> {
        match n {
            1 => Some(SockCommand::Connect),
            2 => Some(SockCommand::Bind),
            3 => Some(SockCommand::UdpAssosiate),
            _ => None,
        }
    }
}

/// Client Authentication Methods
pub enum AuthMethods {
    /// No Authentication
    NoAuth = 0x00,
    // GssApi = 0x01,
    /// Authenticate with a username / password
    UserPass = 0x02,
    /// Cannot authenticate
    NoMethods = 0xFF,
}

pub struct SocksProxy {
    listener: TcpListener,
    // Timeout for connections
    timeout: Option<Duration>,
    shutdown_flag: AtomicBool,
}

impl SocksProxy {
    /// Create a new Merino instance
    pub async fn new(port: u16, ip: &str, timeout: Option<Duration>) -> io::Result<Self> {
        info!("Listening on {}:{}", ip, port);
        Ok(Self {
            listener: TcpListener::bind((ip, port)).await?,
            timeout,
            shutdown_flag: AtomicBool::new(false),
        })
    }

    pub async fn serve(&mut self) {
        info!("Serving Connections...");
        while let Ok((stream, client_addr)) = self.listener.accept().await {
            let timeout = self.timeout.clone();
            tokio::spawn(async move {
                let mut client = SOCKClient::new(stream, timeout);
                match client.init().await {
                    Ok(_) => {}
                    Err(error) => {
                        error!("Error! {:?}, client: {:?}", error, client_addr);

                        if let Err(e) = SocksReply::new(error.into()).send(&mut client.stream).await
                        {
                            warn!("Failed to send error code: {:?}", e);
                        }

                        if let Err(e) = client.shutdown().await {
                            warn!("Failed to shutdown TcpStream: {:?}", e);
                        };
                    }
                };
            });
        }
    }

    async fn quit(&self) {
        #[cfg(unix)]
        {
            let mut term = signal(SignalKind::terminate())
                .expect("Failed to register terminate signal handler");
            let mut interrupt = signal(SignalKind::interrupt())
                .expect("Failed to register interrupt signal handler");

            tokio::select! {
                _ = term.recv() => {
                    println!("Received terminate signal");
                }
                _ = interrupt.recv() => {
                    println!("Received interrupt signal");
                }
            }

            self.shutdown_flag.store(true, Ordering::Relaxed);
        }

        #[cfg(windows)]
        {
            let _ = ctrl_c().await;
            println!("Received Ctrl+C signal");

            self.shutdown_flag.store(true, Ordering::Relaxed);
        }
    }
}

pub struct SOCKClient<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    stream: T,
    socks_version: u8,
    timeout: Option<Duration>,
}

impl<T> SOCKClient<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Create a new SOCKClient
    pub fn new(stream: T, timeout: Option<Duration>) -> Self {
        SOCKClient {
            stream,
            socks_version: 0,
            timeout,
        }
    }

    /// Mutable getter for inner stream
    pub fn stream_mut(&mut self) -> &mut T {
        &mut self.stream
    }
    /// Shutdown a client
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    pub async fn init(&mut self) -> Result<(), KittyProxyError> {
        debug!("New connection");
        let mut header = [0u8; 2];
        // Read a byte from the stream and determine the version being requested
        self.stream.read_exact(&mut header).await?;

        self.socks_version = header[0];

        trace!("Version: {}", self.socks_version,);

        match self.socks_version {
            SOCKS_VERSION => {
                // Authenticate w/ client
                self.handle_client().await?;
            }
            _ => {
                warn!("Init: Unsupported version: SOCKS{}", self.socks_version);
                self.shutdown().await?;
            }
        }

        Ok(())
    }

    /// Handles a client
    pub async fn handle_client(&mut self) -> Result<usize, KittyProxyError> {
        debug!("Starting to relay data");

        let req = SOCKSReq::from_stream(&mut self.stream).await?;

        // Respond
        match req.command {
            // Use the Proxy to connect to the specified addr/port
            SockCommand::Connect => {
                debug!("Handling CONNECT Command");

                let time_out = if let Some(time_out) = self.timeout {
                    time_out
                } else {
                    Duration::from_millis(500)
                };

                let mut target_stream = timeout(time_out, async move {
                    TcpStream::connect(req.target_server).await
                })
                .await
                .map_err(|_| KittyProxyError::Proxy(ResponseCode::ConnectionRefused))??;

                trace!("Connected!");
                target_stream.write_all(&req.readed_buffer).await?;
                trace!("copy bidirectional");
                match tokio::io::copy_bidirectional(&mut self.stream, &mut target_stream).await {
                    // ignore not connected for shutdown error
                    Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                        trace!("already closed");
                        Ok(0)
                    }
                    Err(e) => Err(KittyProxyError::Io(e)),
                    Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
                }
            }
            SockCommand::Bind => Err(KittyProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Bind not supported",
            ))),
            SockCommand::UdpAssosiate => Err(KittyProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UdpAssosiate not supported",
            ))),
        }
    }
}

/// Proxy User Request
#[allow(dead_code)]
struct SOCKSReq {
    pub version: u8,
    pub command: SockCommand,
    pub target_server: String,
    pub readed_buffer: Vec<u8>,
}

impl SOCKSReq {
    /// Parse a SOCKS Req from a TcpStream
    async fn from_stream<T>(stream: &mut T) -> Result<Self, KittyProxyError>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // From rfc 1928 (S4), the SOCKS request is formed as follows:
        //
        //    +----+-----+-------+------+----------+----------+
        //    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        //    +----+-----+-------+------+----------+----------+
        //    | 1  |  1  | X'00' |  1   | Variable |    2     |
        //    +----+-----+-------+------+----------+----------+
        //
        // Where:
        //
        //      o  VER    protocol version: X'05'
        //      o  CMD
        //         o  CONNECT X'01'
        //         o  BIND X'02'
        //         o  UDP ASSOCIATE X'03'
        //      o  RSV    RESERVED
        //      o  ATYP   address type of following address
        //         o  IP V4 address: X'01'
        //         o  DOMAINNAME: X'03'
        //         o  IP V6 address: X'04'
        //      o  DST.ADDR       desired destination address
        //      o  DST.PORT desired destination port in network octet
        //         order
        trace!("Server waiting for connect");
        let mut merged_data: Vec<u8> = Vec::new();

        let mut packet = [0u8; 4];
        // Read a byte from the stream and determine the version being requested
        stream.read_exact(&mut packet).await?;
        trace!("Server received {:?}", packet);
        merged_data.extend_from_slice(&packet);

        if packet[0] != SOCKS_VERSION {
            warn!("from_stream Unsupported version: SOCKS{}", packet[0]);
            stream.shutdown().await?;
        }

        // Get command
        let command = match SockCommand::from(packet[1] as usize) {
            Some(com) => Ok(com),
            None => {
                warn!("Invalid Command");
                stream.shutdown().await?;
                Err(KittyProxyError::Proxy(ResponseCode::CommandNotSupported))
            }
        }?;

        // DST.address

        let addr_type = match AddrType::from(packet[3] as usize) {
            Some(addr) => Ok(addr),
            None => {
                error!("No Addr");
                stream.shutdown().await?;
                Err(KittyProxyError::Proxy(ResponseCode::AddrTypeNotSupported))
            }
        }?;

        trace!("Getting Addr");
        // Get Addr from addr_type and stream
        let addr: Vec<u8> = match addr_type {
            AddrType::Domain => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await?;
                merged_data.extend_from_slice(&dlen);
                let mut domain = vec![0u8; dlen[0] as usize];
                stream.read_exact(&mut domain).await?;
                merged_data.extend_from_slice(&domain);
                domain
            }
            AddrType::V4 => {
                let mut addr: [u8; 4] = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                merged_data.extend_from_slice(&addr);
                addr.to_vec()
            }
            AddrType::V6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                merged_data.extend_from_slice(&addr);
                addr.to_vec()
            }
        };
        let domain_slice: &[u8] = &addr;

        // 使用 from_utf8 函数将切片转换为字符串
        let target_server = std::str::from_utf8(domain_slice)
            .expect("Invalid UTF-8")
            .to_string();

        // Return parsed request
        Ok(SOCKSReq {
            version: packet[0],
            command,
            target_server: target_server,
            readed_buffer: merged_data,
        })
    }
}
