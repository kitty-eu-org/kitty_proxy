#![forbid(unsafe_code)]
// #[macro_use]
// extern crate serde_derive;

use log::error;
use std::collections::HashMap;

use snafu::Snafu;
use url::ParseError;

use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::{fmt, io};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Error, Debug)]
pub enum KittyProxyError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Proxy error: {0}")]
    Proxy(#[from] ResponseCode),

    #[error("Proxy error: {0}")]
    ParseError(#[from] ParseError),

    #[error("error: {0}")]
    Error(#[from] anyhow::Error),
}

#[derive(Debug, Snafu)]
/// Possible SOCKS5 Response Codes
pub enum ResponseCode {
    Success = 0x00,
    #[snafu(display("Server Failure"))]
    Failure = 0x01,
    #[snafu(display("Proxy Rule failure"))]
    RuleFailure = 0x02,
    #[snafu(display("network unreachable"))]
    NetworkUnreachable = 0x03,
    #[snafu(display("host unreachable"))]
    HostUnreachable = 0x04,
    #[snafu(display("connection refused"))]
    ConnectionRefused = 0x05,
    #[snafu(display("TTL expired"))]
    TtlExpired = 0x06,
    #[snafu(display("Command not supported"))]
    CommandNotSupported = 0x07,
    #[snafu(display("Addr Type not supported"))]
    AddrTypeNotSupported = 0x08,
    #[snafu(display("HTTP Proxy Error: Bad Gateway (502)"))]
    HttpBadGateway = 0x502,
}

impl From<KittyProxyError> for ResponseCode {
    fn from(e: KittyProxyError) -> Self {
        match e {
            KittyProxyError::Proxy(e) => e,
            KittyProxyError::Io(_) => ResponseCode::Failure,
            KittyProxyError::ParseError(_) => ResponseCode::Failure,
            KittyProxyError::Error(_) => ResponseCode::Failure,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub struct NodeInfo {
    pub socket_addr: SocketAddr,
    pub node_number: i8,
}

impl NodeInfo {
    pub fn new(ip_addr: IpAddr, port: u16, node_number: i8) -> Self {
        Self {
            socket_addr: SocketAddr::new(ip_addr, port),
            node_number,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address (SOCKS4a)
    DomainNameAddress(String, u16),
}

impl From<NodeInfo> for Address {
    fn from(value: NodeInfo) -> Self {
        Address::SocketAddress(value.socket_addr)
    }
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
        Address::SocketAddress(SocketAddr::V4(s))
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

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}

impl From<(IpAddr, u16)> for Address {
    fn from((ip, port): (IpAddr, u16)) -> Address {
        match ip {
            IpAddr::V4(ip) => Address::from(SocketAddr::new(IpAddr::V4(ip), port)),
            IpAddr::V6(ip) => Address::from(SocketAddr::new(IpAddr::V6(ip), port)),
        }
    }
}
