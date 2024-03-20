use std::borrow::Borrow;
use std::io::ErrorKind;
use std::net::Incoming;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

use anyhow::anyhow;
use anyhow::Result;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::{Body, Bytes};
use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{
    body,
    header::{self, HeaderValue},
    http::uri::{Authority, Scheme},
    HeaderMap, Method, Request, Response, StatusCode, Uri, Version,
};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use log::trace;
use log::{debug, error, info, warn};
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

async fn tunnel(upgraded: Upgraded, target_host: String, is_direct: bool) -> std::io::Result<()> {
    // Connect to remote server
    let mut upgraded = TokioIo::new(upgraded);
    let mut target_stream = TcpStream::connect(&target_host).await.unwrap();
    // let (from_client, from_server) = if !is_direct {
    //     let mut tls_stream = connect_https(target_stream, target_host.as_str()).await;
    //     let (from_client, from_server) =
    //         tokio::io::copy_bidirectional(&mut upgraded, &mut tls_stream).await?;
    //     (from_client, from_server)
    // } else {
    //     let (from_client, from_server) =
    //         tokio::io::copy_bidirectional(&mut upgraded, &mut target_stream).await?;
    //     (from_client, from_server)
    // };
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut target_stream).await?;

    println!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}

async fn send_connect_req(
    target_host: Address,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target_stream = TcpStream::connect(target_host.to_string()).await.unwrap();
    let io: TokioIo<TcpStream> = TokioIo::new(target_stream);
    let (mut sender, conn) = Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await?;
    let req = Request::builder()
        .method("CONNECT")
        .uri(format!("http://{}", target_host.to_string()))
        .body(empty_body())
        .unwrap();

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {:?}", err);
        }
    });

    let resp = sender.send_request(req).await.unwrap();

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
        // tokio::task::spawn(async move {
        // loop {
        tokio::select! {
                    _ = async {
                        loop {
                            let (stream, client_addr) = listener.accept().await.unwrap();
                            let match_proxy_clone = match_proxy_clone.clone();
                            let banlancer_clone = banlancer_clone.clone();
                            let local_addr = stream.local_addr().unwrap();
                            let io = TokioIo::new(stream);

            // tokio::task::spawn(async move {
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
            // });
                        }
                    } => {}
                    _ =  async {
                            if rx_clone.changed().await.is_ok() {
                                return//该任务退出，别的也会停
                        }
                    } => {}
                // }
        }
        // });
    }

    pub fn is_serving(&self) -> bool {
        self.is_serve
    }
}

// pub async fn connect_https(stream: TcpStream, domain: &str) -> TlsStream<TcpStream> {
//     let tls_connector = tokio_native_tls::native_tls::TlsConnector::new().unwrap();
//     let connector = TlsConnector::from(tls_connector);
//     println!("domain: {domain}");
//     let tls_stream = connector.connect("127.0.0.1", stream).await.unwrap();
//     tls_stream
// }

pub async fn serve_connection(
    mut req: Request<body::Incoming>,
    match_proxy_share: Arc<RwLock<MatchProxy>>,
    arc_banlancer: ArcConnectionStatsBanlancer,
) -> hyper::Result<Response<BoxBody<Bytes, hyper::Error>>> {
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
    println!("rule: {:?}", rule);
    drop(match_proxy);
    info!("HTTP [TCP] {} {} connect", host.to_string(), rule);
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
    println!("req: {:?}", req);
    // println!("req.extensions: {:?}", req.());
    if req.method() == Method::CONNECT {
        // Establish a TCP tunnel
        // https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01

        debug!("HTTP CONNECT {}", target_host);
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    println!("target_host: {:?}", target_host);

                    send_connect_req(target_host);
                    if let Err(e) = tunnel(upgraded, target_host, is_direct).await {
                        error!("server io error: {}", e);
                    };
                }
                Err(e) => error!("upgrade error: {}", e),
            }
        });
        println!("upgrade success");
        let response = Response::new(empty_body());
        println!("response: {:?}", response);
        return Ok(response);
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;
    use std::{path::PathBuf, sync::Arc};

    use anyhow::Ok;
    use anyhow::Result;
    use tokio::sync::{watch, RwLock};

    use super::*;

    #[tokio::test]
    async fn it_works() -> Result<()> {
        let mut proxy = HttpProxy::new("127.0.0.1", 10089, None).await?;
        let geoip_file = "/Users/hezhaozhao/myself/kitty/src-tauri/static/kitty_geoip.dat";
        let geosite_file = "/Users/hezhaozhao/myself/kitty/src-tauri/static/kitty_geosite.dat";
        let match_proxy = MatchProxy::from_geo_dat(
            Some(&PathBuf::from_str(geoip_file).unwrap()),
            Some(&PathBuf::from_str(geosite_file).unwrap()),
        )
        .unwrap();
        let arc_match_proxy = Arc::new(RwLock::new(match_proxy));

        let (http_kill_tx, mut http_kill_rx) = watch::channel(false);
        let mut http_vpn_node_infos = Vec::new();
        http_vpn_node_infos.push(NodeInfo::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            20171,
            1,
        ));
        let _ = proxy
            .serve(arc_match_proxy, &mut http_kill_rx, http_vpn_node_infos)
            .await;
        thread::sleep(Duration::from_secs(1000000000));
        Ok(())
    }
}
