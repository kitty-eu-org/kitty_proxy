use anyhow::{anyhow, Result};
use log::{debug, error, info, trace, warn};
use tokio::sync::watch::Receiver;
use url::Host;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::RwLock;

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::banlancer::{ArcConnectionStatsBanlancer, ConnectionStatsBanlancer};
use crate::traffic_diversion::TrafficStreamRule;
use crate::types::{KittyProxyError, NodeInfo, ResponseCode};
use crate::MatchProxy;

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

pub struct SocksProxy {
    // Timeout for connections
    ip: String,
    port: u16,
    timeout: Option<Duration>,
    balancer: ArcConnectionStatsBanlancer,
    is_serve: bool,
}

impl SocksProxy {
    /// Create a new Merino instance
    pub async fn new(ip: &str, port: u16, timeout: Option<Duration>) -> io::Result<Self> {
        info!("Socks5 proxy listening on {}:{}", ip, port);
        Ok(Self {
            ip: ip.to_string(),
            port,
            timeout,
            balancer: Arc::new(Mutex::new(None)),
            is_serve: false,
        })
    }

    pub async fn serve(
        &mut self,
        match_proxy: Arc<RwLock<MatchProxy>>,
        rx: &mut Receiver<bool>,
        vpn_node_infos: Vec<NodeInfo>,
    ) {
        let listener = TcpListener::bind((self.ip.clone(), self.port))
            .await
            .unwrap();
        self.is_serve = true;
        let timeout = self.timeout.clone();
        let match_proxy_clone = Arc::clone(&match_proxy);
        let mut rx_clone = rx.clone();
        let mut balancer = self.balancer.lock().await;
        *balancer = Some(ConnectionStatsBanlancer::from_vec(&vpn_node_infos));
        drop(balancer);
        let balancer = Arc::clone(&self.balancer);

        tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    loop {
                        let (stream, client_addr) = listener.accept().await.unwrap();
                        let match_proxy_clone = match_proxy_clone.clone();
                        let statistics_map_clone = balancer.clone();
                        let mut client = SOCKClient::new(stream, timeout);
            match client
                .handle_client(match_proxy_clone, statistics_map_clone)
                .await
            {
                Ok(_) => {}
                Err(error) => {
                    debug!("Error {:?}, client: {:?}", error, client_addr);
                    if let Err(e) = SocksReply::new(error.into()).send(&mut client.stream).await
                    {
                        warn!("Failed to send error code: {:?}", e);
                    }

                    if let Err(e) = client.shutdown().await {
                        warn!("Failed to shutdown TcpStream: {:?}", e);
                    };
                }
            };
                    }
                } => {}
                _ =  async {
                        if rx_clone.changed().await.is_ok() {
                            return//该任务退出，别的也会停
                    }
                } => {}
            }
        });
    }
    pub fn is_serving(&self) -> bool {
        self.is_serve
    }
}

pub struct SOCKClient<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    stream: T,
    timeout: Option<Duration>,
}

impl<T> SOCKClient<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Create a new SOCKClient
    pub fn new(stream: T, timeout: Option<Duration>) -> Self {
        SOCKClient { stream, timeout }
    }

    /// Shutdown a client
    pub async fn shutdown(&mut self) -> Result<(), KittyProxyError> {
        self.stream.shutdown().await?;
        Ok(())
    }

    /// Handles a client
    pub async fn handle_client(
        &mut self,
        match_proxy_share: Arc<RwLock<MatchProxy>>,
        arc_banlancer: ArcConnectionStatsBanlancer,
    ) -> Result<usize, KittyProxyError> {
        let req = SOCKSReq::from_stream(&mut self.stream).await?;

        // Respond
        match req.command {
            // Use the Proxy to connect to the specified addr/port
            SockCommand::Connect => {
                let time_out = if let Some(time_out) = self.timeout {
                    time_out
                } else {
                    Duration::from_millis(1000)
                };
                let match_proxy = match_proxy_share.read().await;
                let rule = match_proxy.traffic_stream(&req.host);
                drop(match_proxy);
                info!("Socks5 [TCP] {}:{} {} connect", req.host, req.port, rule);
                let is_direct = match rule {
                    TrafficStreamRule::Reject => {
                        self.shutdown().await?;
                        return Ok(0 as usize);
                    }
                    TrafficStreamRule::Direct => true,
                    TrafficStreamRule::Proxy => false,
                };
                let node_info = if !is_direct {
                    let banlancer = arc_banlancer.lock().await;
                    let banlancer_ref = banlancer.as_ref().unwrap();
                    Some(banlancer_ref.get_least_connected_node().await)
                } else {
                    None
                };
                let target_server = if is_direct {
                    format!("{}:{}", req.host, req.port)
                } else {
                    node_info.unwrap().socket_addr.to_string()
                };
                debug!("req.target_server: {}", target_server);
                let mut target_stream =
                    timeout(
                        time_out,
                        async move { TcpStream::connect(target_server).await },
                    )
                    .await
                    .map_err(|_| {
                        error!("Socks5 error {}:{} connect timeout", req.host, req.port);
                        KittyProxyError::Proxy(ResponseCode::ConnectionRefused)
                    })??;
                if !is_direct {
                    let mut banlancer = arc_banlancer.lock().await;
                    let banlancer_ref = banlancer.as_mut().unwrap();
                    banlancer_ref.incre_count_by_node_info(&node_info.unwrap());
                }
                if !is_direct {
                    target_stream.write_all(&req.readed_buffer).await?;
                    let mut _header = [0u8; 2];
                    target_stream.read_exact(&mut _header).await?;
                } else {
                    SocksReply::new(ResponseCode::Success)
                        .send(&mut self.stream)
                        .await?;
                }

                let return_value =
                    match tokio::io::copy_bidirectional(&mut self.stream, &mut target_stream).await
                    {
                        // ignore not connected for shutdown error
                        Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                            error!("Socks5 error {}:{} {}", req.host, req.port, e);
                            Ok(0)
                        }
                        Err(e) => {
                            error!("Socks5 error {}:{} {}", req.host, req.port, e);
                            Err(KittyProxyError::Io(e))
                        }
                        Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
                    };
                if !is_direct {
                    let mut banlancer = arc_banlancer.lock().await;
                    let banlancer_ref = banlancer.as_mut().unwrap();
                    banlancer_ref.decre_count_by_node_info(&node_info.unwrap());
                }
                return_value
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

pub enum AuthMethod {
    /// No Authentication
    NoAuth = 0x00,
    /// Cannot authenticate
    NoMethod = 0xFF,
}

async fn addr_to_host(addr_type: &AddrType, addr: &[u8]) -> io::Result<Host> {
    match addr_type {
        AddrType::V6 => {
            let new_addr = (0..8)
                .map(|x| {
                    trace!("{} and {}", x * 2, (x * 2) + 1);
                    (u16::from(addr[(x * 2)]) << 8) | u16::from(addr[(x * 2) + 1])
                })
                .collect::<Vec<u16>>();

            Ok(Host::Ipv6(Ipv6Addr::new(
                new_addr[0],
                new_addr[1],
                new_addr[2],
                new_addr[3],
                new_addr[4],
                new_addr[5],
                new_addr[6],
                new_addr[7],
            )))
        }
        AddrType::V4 => Ok(Host::Ipv4(Ipv4Addr::new(
            addr[0], addr[1], addr[2], addr[3],
        ))),
        AddrType::Domain => {
            let domain = std::str::from_utf8(addr).expect("parse domain failed from u8!");
            Ok(Host::Domain(domain.to_string()))
        }
    }
}

/// Proxy User Request
#[allow(dead_code)]
struct SOCKSReq {
    pub version: u8,
    pub command: SockCommand,
    pub host: Host,
    pub port: u16,
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
        let mut readed_buffer: Vec<u8> = Vec::new();
        let mut header = [0u8; 2];
        // Read a byte from the stream and determine the version being requested
        stream.read_exact(&mut header).await?;
        readed_buffer.extend_from_slice(&header);

        let socks_version = header[0];
        let auth_method = header[1] as usize;

        debug!("socks version: {}", socks_version);

        if socks_version != SOCKS_VERSION {
            debug!("Init: Unsupported version: SOCKS{}", socks_version);
            stream.shutdown().await?;
            return Err(anyhow!(format!("Not support version: {}.", socks_version)).into());
        }
        let mut method = vec![0u8; auth_method];
        stream.read_exact(&mut method).await?;
        readed_buffer.extend_from_slice(&method);

        let no_auth = AuthMethod::NoAuth as u8;
        let mut auth_response = [0u8, 2];
        auth_response[0] = SOCKS_VERSION;
        if method.contains(&no_auth) {
            auth_response[1] = no_auth;
            stream.write_all(&auth_response).await?;
        } else {
            auth_response[1] = AuthMethod::NoMethod as u8;
            stream.write_all(&auth_response).await?;
            stream.shutdown().await?;
            return Err(anyhow!("Socks auth failed.").into());
        }

        let mut packet = [0u8; 4];
        // Read a byte from the stream and determine the version being requested
        stream.read_exact(&mut packet).await?;
        readed_buffer.extend_from_slice(&packet);

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

        let addr_type = match AddrType::from(packet[3] as usize) {
            Some(addr) => Ok(addr),
            None => {
                error!("No Addr");
                stream.shutdown().await?;
                Err(KittyProxyError::Proxy(ResponseCode::AddrTypeNotSupported))
            }
        }?;

        // Get Addr from addr_type and stream
        let addr: Vec<u8> = match addr_type {
            AddrType::Domain => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await?;
                readed_buffer.extend_from_slice(&dlen);
                let mut domain = vec![0u8; dlen[0] as usize];
                stream.read_exact(&mut domain).await?;
                readed_buffer.extend_from_slice(&domain);
                domain
            }
            AddrType::V4 => {
                let mut addr: [u8; 4] = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                readed_buffer.extend_from_slice(&addr);
                addr.to_vec()
            }
            AddrType::V6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                readed_buffer.extend_from_slice(&addr);
                addr.to_vec()
            }
        };
        // read DST.port
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        readed_buffer.extend_from_slice(&port);
        let port = (u16::from(port[0]) << 8) | u16::from(port[1]);
        let host = addr_to_host(&addr_type, &addr).await?;

        // Return parsed request
        Ok(SOCKSReq {
            version: packet[0],
            command,
            host,
            port,
            readed_buffer,
        })
    }
}
