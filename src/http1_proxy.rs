#![forbid(unsafe_code)]

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use log::trace;
use log::{debug, error, info, warn};

use anyhow::anyhow;
use anyhow::Result;
use std::{fmt, io};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::time::timeout;
use url::{Host, ParseError, Url};

use crate::traffic_diversion::TrafficStreamRule;
use crate::types::{KittyProxyError, NodeInfo, NodeStatistics, ResponseCode, StatisticsMap};
use crate::MatchProxy;

use hyper::{
    body,
    header::{self, HeaderValue},
    http::uri::{Authority, Scheme},
    HeaderMap,
    Method,
    Request,
    Response,
    StatusCode,
    Uri,
    Version,
};

pub fn host_addr(uri: &Uri) -> Option<Address> {
    match uri.authority() {
        None => None,
        Some(authority) => authority_addr(uri.scheme_str(), authority),
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address (SOCKS4a)
    DomainNameAddress(String, u16),
}


impl fmt::Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{addr}"),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{addr}:{port}"),
        }
    }
}

impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{addr}"),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{addr}:{port}"),
        }
    }
}

impl From<SocketAddrV4> for Address {
    fn from(s: SocketAddrV4) -> Address {
        Address::SocketAddress(s)
    }
}

impl From<(String, u16)> for Address {
    fn from((dn, port): (String, u16)) -> Address {
        Address::DomainNameAddress(dn, port)
    }
}

impl From<(&str, u16)> for Address {
    fn from((dn, port): (&str, u16)) -> Address {
        Address::DomainNameAddress(dn.to_owned(), port)
    }
}

impl From<&Address> for Address {
    fn from(addr: &Address) -> Address {
        addr.clone()
    }
}

impl From<Address> for socks5::Address {
    fn from(addr: Address) -> socks5::Address {
        match addr {
            Address::SocketAddress(a) => socks5::Address::SocketAddress(SocketAddr::V4(a)),
            Address::DomainNameAddress(d, p) => socks5::Address::DomainNameAddress(d, p),
        }
    }
}


fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn make_bad_request() -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty_body())
        .unwrap())
}

fn make_internal_server_error() -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(empty_body())
        .unwrap())
}

fn get_extra_headers(headers: header::GetAll<HeaderValue>) -> Vec<String> {
    let mut extra_headers = Vec::new();
    for connection in headers {
        if let Ok(conn) = connection.to_str() {
            // close is a command instead of a header
            if conn.eq_ignore_ascii_case("close") {
                continue;
            }
            for header in conn.split(',') {
                let header = header.trim();
                extra_headers.push(header.to_owned());
            }
        }
    }
    extra_headers
}

fn clear_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
    // Clear headers indicated by Connection and Proxy-Connection
    let mut extra_headers = get_extra_headers(headers.get_all("Connection"));
    extra_headers.extend(get_extra_headers(headers.get_all("Proxy-Connection")));

    for header in extra_headers {
        while headers.remove(&header).is_some() {}
    }

    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
    const HOP_BY_HOP_HEADERS: [&str; 9] = [
        "Keep-Alive",
        "Transfer-Encoding",
        "TE",
        "Connection",
        "Trailer",
        "Upgrade",
        "Proxy-Authorization",
        "Proxy-Authenticate",
        "Proxy-Connection", // Not standard, but many implementations do send this header
    ];

    for header in &HOP_BY_HOP_HEADERS {
        while headers.remove(*header).is_some() {}
    }
}

fn set_conn_keep_alive(version: Version, headers: &mut HeaderMap<HeaderValue>, keep_alive: bool) {
    match version {
        Version::HTTP_09 | Version::HTTP_10 => {
            // HTTP/1.0 close connection by default
            if keep_alive {
                headers.insert("Connection", HeaderValue::from_static("keep-alive"));
            }
        }
        _ => {
            // HTTP/1.1, HTTP/2, HTTP/3 keep-alive connection by default
            if !keep_alive {
                headers.insert("Connection", HeaderValue::from_static("close"));
            }
        }
    }
}

pub fn authority_addr(scheme_str: Option<&str>, authority: &Authority) -> Option<Address> {
    // RFC7230 indicates that we should ignore userinfo
    // https://tools.ietf.org/html/rfc7230#section-5.3.3

    // Check if URI has port
    let port = match authority.port_u16() {
        Some(port) => port,
        None => {
            match scheme_str {
                None => 80, // Assume it is http
                Some("http") => 80,
                Some("https") => 443,
                _ => return None, // Not supported
            }
        }
    };

    let host_str = authority.host();

    // RFC3986 indicates that IPv6 address should be wrapped in [ and ]
    // https://tools.ietf.org/html/rfc3986#section-3.2.2
    //
    // Example: [::1] without port
    if host_str.starts_with('[') && host_str.ends_with(']') {
        // Must be a IPv6 address
        let addr = &host_str[1..host_str.len() - 1];
        match addr.parse::<Ipv6Addr>() {
            Ok(a) => Some(Address::from(SocketAddr::new(IpAddr::V6(a), port))),
            // Ignore invalid IPv6 address
            Err(..) => None,
        }
    } else {
        // It must be a IPv4 address
        match host_str.parse::<Ipv4Addr>() {
            Ok(a) => Some(Address::from(SocketAddr::new(IpAddr::V4(a), port))),
            // Should be a domain name, or a invalid IP address.
            // Let DNS deal with it.
            Err(..) => Some(Address::DomainNameAddress(host_str.to_owned(), port)),
        }
    }
}

fn get_addr_from_header(req: &mut Request<body::Incoming>) -> Result<Address, ()> {
    // Try to be compatible as a transparent HTTP proxy
    match req.headers().get("Host") {
        Some(hhost) => match hhost.to_str() {
            Ok(shost) => {
                match Authority::from_str(shost) {
                    Ok(authority) => match authority_addr(req.uri().scheme_str(), &authority) {
                        Some(host) => {
                            trace!("HTTP {} URI {} got host from header: {}", req.method(), req.uri(), host);

                            // Reassemble URI
                            let mut parts = req.uri().clone().into_parts();
                            if parts.scheme.is_none() {
                                // Use http as default.
                                parts.scheme = Some(Scheme::HTTP);
                            }
                            parts.authority = Some(authority);

                            // Replaces URI
                            *req.uri_mut() = Uri::from_parts(parts).expect("Reassemble URI failed");

                            debug!("reassembled URI from \"Host\", {}", req.uri());

                            Ok(host)
                        }
                        None => {
                            error!(
                                "HTTP {} URI {} \"Host\" header invalid, value: {}",
                                req.method(),
                                req.uri(),
                                shost
                            );

                            Err(())
                        }
                    },
                    Err(..) => {
                        error!(
                            "HTTP {} URI {} \"Host\" header is not an Authority, value: {:?}",
                            req.method(),
                            req.uri(),
                            hhost
                        );

                        Err(())
                    }
                }
            }
            Err(..) => {
                error!(
                    "HTTP {} URI {} \"Host\" header invalid encoding, value: {:?}",
                    req.method(),
                    req.uri(),
                    hhost
                );

                Err(())
            }
        },
        None => {
            error!(
                "HTTP {} URI doesn't have valid host and missing the \"Host\" header, URI: {}",
                req.method(),
                req.uri()
            );

            Err(())
        }
    }
}

pub struct HttpReply {
    buf: Vec<u8>,
}

impl HttpReply {
    pub fn new(status: ResponseCode) -> Self {
        let mut buffer: Vec<u8> = Vec::new();
        let response = format!(
            "HTTP/1.1 {} Proxy Error\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             \r\n\
             Proxy Error",
            status as usize, 11
        );

        buffer.extend_from_slice(response.as_bytes());
        Self { buf: buffer }
    }

    pub async fn send<T>(&self, stream: &mut T) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        stream.write_all(&self.buf[..]).await?;
        Ok(())
    }
}

pub struct HttpProxy {
    ip: String,
    port: u16,
    timeout: Option<Duration>,
    node_statistics_map: StatisticsMap,
    is_serve: bool,
}

impl HttpProxy {
    pub async fn new(ip: &str, port: u16, timeout: Option<Duration>) -> io::Result<Self> {
        info!("Http proxy listening on {}:{}", ip, port);
        Ok(Self {
            ip: ip.to_string(),
            port,
            timeout,
            node_statistics_map: Arc::new(Mutex::new(None)),
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
        let mut statistics_map = self.node_statistics_map.lock().await;
        *statistics_map = Some(NodeStatistics::from_vec(&vpn_node_infos));
        drop(statistics_map);
        let statistics_map_clone = Arc::clone(&self.node_statistics_map);
        tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    loop {
                        let (stream, client_addr) = listener.accept().await.unwrap();
                        let match_proxy_clone = match_proxy_clone.clone();
                        let statistics_map_clone = statistics_map_clone.clone();
                        let local_addr = stream.local_addr().unwrap();
                        tokio::spawn(async move {
                            let mut client = HttpClient::new(stream, timeout);
                match client
                    .handle_client(match_proxy_clone, statistics_map_clone)
                    .await
                {
                    Ok(_) => {}
                    Err(error) => {
                        debug!("Error {:?}, client: {:?}, local_addr: {}", error, client_addr, local_addr);
                        if let Err(e) = HttpReply::new(error.into()).send(&mut client.stream).await
                        {
                            warn!("Failed to send error code: {:?}, local_addr: {}", e, local_addr);
                        }
                        if let Err(e) = client.shutdown().await {
                            warn!("Failed to shutdown TcpStream: {:?}, local_addr: {}", e, local_addr);
                        };
                    }
                };

                         });
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

    pub async fn serve_connection(
        self,
        mut req: Request<body::Incoming>,
    ) -> hyper::Result<Response<BoxBody<Bytes, hyper::Error>>> {
        // trace!("request {} {:?}", self.peer_addr, req);

        // Parse URI
        //
        // Proxy request URI must contains a host
        let host = match host_addr(req.uri()) {
            None => {
                if req.uri().authority().is_some() {
                    // URI has authority but invalid
                    error!("HTTP {} URI {} doesn't have a valid host", req.method(), req.uri());
                    return make_bad_request();
                } else {
                    trace!("HTTP {} URI {} doesn't have a valid host", req.method(), req.uri());
                }

                match get_addr_from_header(&mut req) {
                    Ok(h) => h,
                    Err(()) => return make_bad_request(),
                }
            }
            Some(h) => h,
        };

        if req.method() == Method::CONNECT {
            // Establish a TCP tunnel
            // https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01

            debug!("HTTP CONNECT {}", host);

            // Connect to Shadowsocks' remote
            //
            // FIXME: What STATUS should I return for connection error?
            let (mut stream, server_opt) = match connect_host(self.context, &host, &self.balancer).await {
                Ok(s) => s,
                Err(err) => {
                    error!("failed to CONNECT host: {}, error: {}", host, err);
                    return make_internal_server_error();
                }
            };

            // debug!(
            //     "CONNECT relay connected {} <-> {} ({})",
            //     self.peer_addr,
            //     host,
            //     if stream.is_bypassed() { "bypassed" } else { "proxied" }
            // );

            let client_addr = self.peer_addr;
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        trace!("CONNECT tunnel upgrade success, {} <-> {}", client_addr, host);

                        let mut upgraded_io = TokioIo::new(upgraded);

                        let _ = match server_opt {
                            Some(server) => {
                                establish_tcp_tunnel(
                                    server.server_config(),
                                    &mut upgraded_io,
                                    &mut stream,
                                    client_addr,
                                    &host,
                                )
                                .await
                            }
                            None => {
                                establish_tcp_tunnel_bypassed(&mut upgraded_io, &mut stream, client_addr, &host).await
                            }
                        };
                    }
                    Err(err) => {
                        error!("failed to upgrade CONNECT request, error: {}", err);
                    }
                }
            });

            return Ok(Response::new(empty_body()));
        }

        // Traditional HTTP Proxy request

        let method = req.method().clone();
        let version = req.version();
        debug!("HTTP {} {} {:?}", method, host, version);

        // Check if client wants us to keep long connection
        let conn_keep_alive = check_keep_alive(version, req.headers(), true);

        // Remove non-forwardable headers
        clear_hop_headers(req.headers_mut());

        // Set keep-alive for connection with remote
        set_conn_keep_alive(version, req.headers_mut(), conn_keep_alive);

        let mut res = match self.http_client.send_request(self.context, req, &self.balancer).await {
            Ok(resp) => resp,
            Err(HttpClientError::Hyper(e)) => return Err(e),
            Err(HttpClientError::Io(err)) => {
                error!("failed to make request to host: {}, error: {}", host, err);
                return make_internal_server_error();
            }
        };

        trace!("received {} <- {} {:?}", self.peer_addr, host, res);

        let res_keep_alive = conn_keep_alive && check_keep_alive(res.version(), res.headers(), false);

        // Clear unforwardable headers
        clear_hop_headers(res.headers_mut());

        if res.version() != version {
            // Reset version to matches req's version
            trace!("response version {:?} => {:?}", res.version(), version);
            *res.version_mut() = version;
        }

        // Set Connection header
        set_conn_keep_alive(res.version(), res.headers_mut(), res_keep_alive);

        trace!("response {} <- {} {:?}", self.peer_addr, host, res);

        debug!("HTTP {} relay {} <-> {} finished", method, self.peer_addr, host);

        Ok(res.map(|b| b.boxed()))
    }
}

pub struct HttpClient {
    stream: TcpStream,
    timeout: Option<Duration>,
}

impl HttpClient {
    pub fn new(stream: TcpStream, timeout: Option<Duration>) -> Self {
        Self { stream, timeout }
    }

    /// Shutdown a client
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    fn get_local_addr(&self) -> SocketAddr {
        self.stream.local_addr().unwrap()
    }

    /// Handles a client
    pub async fn handle_client(
        &mut self,
        match_proxy_share: Arc<RwLock<MatchProxy>>,
        vpn_node_statistics_map: StatisticsMap,
    ) -> Result<usize, KittyProxyError> {
        let req: HttpReq = HttpReq::from_stream(&mut self.stream).await?;

        let time_out = if let Some(time_out) = self.timeout {
            time_out
        } else {
            Duration::from_millis(1000)
        };
        let match_proxy = match_proxy_share.read().await;
        let rule = match_proxy.traffic_stream(&req.host);
        drop(match_proxy);
        info!("HTTP [TCP] {}:{} {} connect local_addr: {}", req.host, req.port, rule, self.get_local_addr());

        let is_direct = match rule {
            TrafficStreamRule::Reject => {
                self.shutdown().await?;
                return Ok(0 as usize);
            }
            TrafficStreamRule::Direct => true,
            TrafficStreamRule::Proxy => false,
        };
        let node_info = if !is_direct {
            let vpn_node_statistics = vpn_node_statistics_map.lock().await;
            let vpn_node_statistics_ref = vpn_node_statistics.as_ref().unwrap();
            Some(vpn_node_statistics_ref.get_least_connected_node().await)
        } else {
            None
        };
        let target_server = if is_direct {
            format!("{}:{}", req.host, req.port)
        } else {
            node_info.unwrap().socket_addr.to_string()
        };
        debug!("target_server: {}", target_server);
        let mut target_stream =
            timeout(
                time_out,
                async move { TcpStream::connect(target_server).await },
            )
            .await
            .map_err(|_| {
                error!("HTTP error {}:{} connect timeout, local_addr: {}", req.host, req.port, self.get_local_addr());
                KittyProxyError::Proxy(ResponseCode::ConnectionRefused)
            })??;
        if !is_direct {
            let mut vpn_node_statistics = vpn_node_statistics_map.lock().await;
            let vpn_node_statistics = vpn_node_statistics.as_mut().unwrap();
            vpn_node_statistics.incre_count_by_node_info(&node_info.unwrap());
        }

        if req.method == "CONNECT" && is_direct {
            self.stream
                .write_all(format!("{} 200 Connection established\r\n\r\n", req.version).as_bytes())
                .await?;
        } else {
            target_stream.write_all(&req.readed_buffer).await?;
        }

        let return_value =
            match tokio::io::copy_bidirectional(&mut self.stream, &mut target_stream).await {
                // ignore not connected for shutdown error
                Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                    error!("HTTP error {}:{} {}, local_addr: {}", req.host, req.port, e , self.get_local_addr());
                    Ok(0)
                }
                Err(e) => {
                    error!("HTTP error {}:{} {}, local_addr: {}", req.host, req.port, e, self.get_local_addr());
                    Err(KittyProxyError::Io(e))
                }
                Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
            };
        if !is_direct {
            let mut vpn_node_statistics = vpn_node_statistics_map.lock().await;
            let vpn_node_statistics = vpn_node_statistics.as_mut().unwrap();
            vpn_node_statistics.decre_count_by_node_info(&node_info.unwrap());
        }
        return_value
    }
}

/// Proxy User Request
#[allow(dead_code)]
struct HttpReq {
    pub method: String,
    pub host: Host,
    pub port: u16,
    pub readed_buffer: Vec<u8>,
    pub version: String,
}

impl HttpReq {
    /// Parse a SOCKS Req from a TcpStream
    async fn from_stream<T>(stream: &mut T) -> Result<Self, KittyProxyError>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut request_headers: Vec<String> = Vec::new();
        let mut reader: BufReader<&mut T> = BufReader::new(stream);

        loop {
            let mut tmp = String::new();
            reader.read_line(&mut tmp).await?;
            request_headers.push(tmp.clone());
            if tmp == "\r\n" {
                break;
            }
        }
        let request_first_line = request_headers.get(0).unwrap().clone();
        let mut parts = request_first_line.split_whitespace();
        let method = parts.next().expect("Invalid request");
        let origin_path = parts.next().expect("Invalid request");
        let version = parts.next().expect("Invalid request");
        debug!("http req path:{origin_path}, method:{method}, version:{version}");

        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            debug!("Init: Unsupported version: {}", version);
            stream.shutdown().await?;
            return Err(anyhow!(format!("Not support version: {}.", version)).into());
        }

        let mut origin_path = origin_path.to_string();
        if method == "CONNECT" {
            origin_path.insert_str(0, "http://")
        };
        let url = Url::parse(&origin_path)?;
        let host = url.host().map(|x| x.to_owned());
        let port = url.port().unwrap_or(80);
        let host = host.ok_or(ParseError::EmptyHost)?;
        Ok(HttpReq {
            method: method.to_string(),
            host,
            port,
            readed_buffer: request_headers.join("").as_bytes().to_vec(),
            version: version.into(),
        })
    }
}
