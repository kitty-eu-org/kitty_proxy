#![forbid(unsafe_code)]

use hyper::body::Bytes;
use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use log::trace;
use log::{debug, error, info, warn};

use anyhow::anyhow;
use anyhow::Result;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::time::timeout;
use url::{Host, ParseError, Url};

use crate::banlancer::{ArcConnectionStatsBanlancer, ConnectionStatsBanlancer};
use crate::traffic_diversion::TrafficStreamRule;
use crate::traits::BanlancerTrait;
use crate::types::{Address, KittyProxyError, NodeInfo, ResponseCode};
use crate::MatchProxy;

use hyper::{
    body,
    header::{self, HeaderValue},
    http::uri::{Authority, Scheme},
    HeaderMap, Method, Request, Response, StatusCode, Uri, Version,
};

use http_body_util::{combinators::BoxBody, BodyExt};

pub fn host_addr(uri: &Uri) -> Option<Address> {
    match uri.authority() {
        None => None,
        Some(authority) => authority_addr(uri.scheme_str(), authority),
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
            Ok(a) => Some(Address::from((IpAddr::V6(a), port))),
            // Ignore invalid IPv6 address
            Err(..) => None,
        }
    } else {
        // It must be a IPv4 address
        match host_str.parse::<Ipv4Addr>() {
            Ok(a) => Some(Address::from((IpAddr::V4(a), port))),
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
                            trace!(
                                "HTTP {} URI {} got host from header: {}",
                                req.method(),
                                req.uri(),
                                host
                            );

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

fn get_keep_alive_val(values: header::GetAll<HeaderValue>) -> Option<bool> {
    let mut conn_keep_alive = None;
    for value in values {
        if let Ok(value) = value.to_str() {
            if value.eq_ignore_ascii_case("close") {
                conn_keep_alive = Some(false);
            } else {
                for part in value.split(',') {
                    let part = part.trim();
                    if part.eq_ignore_ascii_case("keep-alive") {
                        conn_keep_alive = Some(true);
                        break;
                    }
                }
            }
        }
    }
    conn_keep_alive
}

pub fn check_keep_alive(
    version: Version,
    headers: &HeaderMap<HeaderValue>,
    check_proxy: bool,
) -> bool {
    // HTTP/1.1, HTTP/2, HTTP/3 keeps alive by default
    let mut conn_keep_alive = !matches!(version, Version::HTTP_09 | Version::HTTP_10);

    if check_proxy {
        // Modern browsers will send Proxy-Connection instead of Connection
        // for HTTP/1.0 proxies which blindly forward Connection to remote
        //
        // https://tools.ietf.org/html/rfc7230#appendix-A.1.2
        if let Some(b) = get_keep_alive_val(headers.get_all("Proxy-Connection")) {
            conn_keep_alive = b
        }
    }

    // Connection will replace Proxy-Connection
    //
    // But why client sent both Connection and Proxy-Connection? That's not standard!
    if let Some(b) = get_keep_alive_val(headers.get_all("Connection")) {
        conn_keep_alive = b
    }

    conn_keep_alive
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

async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);

    // Proxying data
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    // Print message when done
    println!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}

pub struct HttpProxy {
    ip: String,
    port: u16,
    timeout: Option<Duration>,
    banlancer: ArcConnectionStatsBanlancer,
    is_serve: bool,
}

impl HttpProxy {
    pub async fn new(ip: &str, port: u16, timeout: Option<Duration>) -> io::Result<Self> {
        info!("Http proxy listening on {}:{}", ip, port);
        Ok(Self {
            ip: ip.to_string(),
            port,
            timeout,
            banlancer: Arc::new(Mutex::new(None)),
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
        let match_proxy_clone = Arc::clone(&match_proxy);
        let mut rx_clone = rx.clone();
        let mut banlancer = self.banlancer.lock().await;
        *banlancer = Some(ConnectionStatsBanlancer::from_vec(&vpn_node_infos));
        drop(banlancer);
        let banlancer_clone = Arc::clone(&self.banlancer);
        tokio::task::spawn(async move {
            // loop {
            tokio::select! {
                        _ = async {
                            loop {
                                let (stream, client_addr) = listener.accept().await.unwrap();
                                let match_proxy_clone = match_proxy_clone.clone();
                                let banlancer_clone = banlancer_clone.clone();
                                let local_addr = stream.local_addr().unwrap();
                                let io = TokioIo::new(stream);

                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(io,
                            service_fn(move |req| {
                                let match_proxy_clone = match_proxy_clone.clone();
                                let banlancer_clone = banlancer_clone.clone();
                                serve_connection(req, match_proxy_clone, banlancer_clone)
                            }
                        ))
                        .with_upgrades()
                        .await
                    {
                        println!("Failed to serve connection: {:?}", err);
                    }
                });
                            }
                        } => {}
                        _ =  async {
                                if rx_clone.changed().await.is_ok() {
                                    return//该任务退出，别的也会停
                            }
                        } => {}
                    // }
            }
        });
    }

    pub fn is_serving(&self) -> bool {
        self.is_serve
    }
}

pub async fn serve_connection(
    mut req: Request<body::Incoming>,
    match_proxy_share: Arc<RwLock<MatchProxy>>,
    arc_banlancer: ArcConnectionStatsBanlancer,
) -> hyper::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    // Parse URI
    //
    // Proxy request URI must contains a host
    let host: Address = match host_addr(req.uri()) {
        None => {
            if req.uri().authority().is_some() {
                // URI has authority but invalid
                error!(
                    "HTTP {} URI {} doesn't have a valid host",
                    req.method(),
                    req.uri()
                );
                return make_bad_request();
            } else {
                trace!(
                    "HTTP {} URI {} doesn't have a valid host",
                    req.method(),
                    req.uri()
                );
            }

            match get_addr_from_header(&mut req) {
                Ok(h) => h,
                Err(()) => return make_bad_request(),
            }
        }
        Some(h) => h,
    };
    let match_proxy = match_proxy_share.read().await;

    let rule = match_proxy.traffic_stream(&Host::from(&host));
    drop(match_proxy);
    info!("Socks5 [TCP] {} {} connect", host.to_string(), rule);
    let is_direct = match rule {
        TrafficStreamRule::Reject => {
            return Ok(Response::new(empty_body()));
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

    let target_host = if is_direct {
        host
    } else {
        Address::from(node_info.unwrap())
    };
    if req.method() == Method::CONNECT {
        // Establish a TCP tunnel
        // https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01

        debug!("HTTP CONNECT {}", target_host);

        // Connect to Shadowsocks' remote
        //
        // FIXME: What STATUS should I return for connection error?
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, target_host.to_string()).await {
                        error!("server io error: {}", e);
                    };
                }
                Err(e) => error!("upgrade error: {}", e),
            }
        });

        return Ok(Response::new(empty_body()));
    }
    let stream = TcpStream::connect(target_host.to_string()).await.unwrap();
    let io = TokioIo::new(stream);
    if !is_direct {
        let mut banlancer = arc_banlancer.lock().await;
        let banlancer_ref = banlancer.as_mut().unwrap();
        banlancer_ref.incre_count_by_node_info(&node_info.unwrap());
    }
    let (mut sender, conn) = Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {:?}", err);
        }
    });

    let resp = sender.send_request(req).await?;
    if !is_direct {
        let mut banlancer = arc_banlancer.lock().await;
        let banlancer_ref = banlancer.as_mut().unwrap();
        banlancer_ref.decre_count_by_node_info(&node_info.unwrap());
    }
    Ok(resp.map(|b| b.boxed()))
}
