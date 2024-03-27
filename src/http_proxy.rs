use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    body,
    http::uri::{Authority, Scheme}, Method, Request, Response, StatusCode, Uri
};
use hyper::body::Bytes;
use hyper::client::conn::http1::Builder;
use hyper::header::USER_AGENT;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use log::{debug, error, info, trace};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::sync::watch::Receiver;
use url::Host;

use crate::banlancer::{ArcConnectionStatsBanlancer, ConnectionStatsBanlancer};
use crate::MatchProxy;
use crate::traffic_diversion::TrafficStreamRule;
use crate::types::{Address, NodeInfo};

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

async fn tunnel(
    upgraded: Upgraded,
    target_host: Address,
    is_direct: bool,
    req: Request<body::Incoming>,
) -> std::io::Result<()> {
    let mut upgraded = TokioIo::new(upgraded);
    let mut target_stream = TcpStream::connect(target_host.to_string()).await.unwrap();
    if !is_direct {
        target_stream
            .write_all(
                format!(
                    "CONNECT {} {:?}\r\nHost: {}\r\nUser-Agent: {}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
                    req.uri().to_string(),
                    req.version(),
                    req.uri().to_string(),
                    req.headers()
                        .get(USER_AGENT)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
                )
                    .as_bytes(),
            )
            .await
            .unwrap();

        // 读取代理服务器响应
        let mut resp_buf = [0; 1024];
        let resp_len = target_stream.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..resp_len]);
        if !resp_str.starts_with("HTTP/1.1 200") {
            eprintln!("Proxy server denied CONNECT request: {}", resp_str);
            return Ok(());
        }
        // 确保代理服务器响应成功
        let (from_client, from_server) =
            tokio::io::copy_bidirectional(&mut upgraded, &mut target_stream).await?;
        println!(
            "client wrote {} bytes and received {} bytes",
            from_client, from_server
        );
    } else {
        let (from_client, from_server) =
            tokio::io::copy_bidirectional(&mut upgraded, &mut target_stream).await?;
        println!(
            "client wrote {} bytes and received {} bytes",
            from_client, from_server
        );
    }
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
        tokio::task::spawn(async move {
        // loop {
        tokio::select! {
                    _ = async {
                        loop {
                            let (stream, _client_addr) = listener.accept().await.unwrap();
                            let match_proxy_clone = match_proxy_clone.clone();
                            let banlancer_clone = banlancer_clone.clone();
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
                }
        // }
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
    if req.method() == Method::CONNECT {
        tokio::task::spawn(async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, target_host, is_direct, req).await {
                        error!("server io error: {}", e);
                    };
                }
                Err(e) => error!("upgrade error: {}", e),
            }
        });
        let response = Response::new(empty_body());
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
    use std::{path::PathBuf, sync::Arc};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::time::Duration;

    use anyhow::Ok;
    use anyhow::Result;
    use tokio::sync::{RwLock, watch};
    use tokio::time;

    use super::*;

    #[tokio::test]
    async fn it_works() -> Result<()> {
        let mut proxy = HttpProxy::new("127.0.0.1", 10089, None).await?;
        // let geoip_file = "/Users/hezhaozhao/myself/kitty/src-tauri/static/kitty_geoip.dat";
        let geoip_file = "/home/hezhaozhao/opensource/kitty/src-tauri/static/kitty_geoip.dat";
        // let geosite_file = "/Users/hezhaozhao/myself/kitty/src-tauri/static/kitty_geosite.dat";
        let geosite_file = "/home/hezhaozhao/opensource/kitty/src-tauri/static/kitty_geosite.dat";
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
            1078,
            1,
        ));
        let _ = proxy
            .serve(arc_match_proxy, &mut http_kill_rx, http_vpn_node_infos)
            .await;
        time::sleep(Duration::from_secs(1000000000)).await;
        Ok(())
    }
}
