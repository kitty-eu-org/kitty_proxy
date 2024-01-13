#![forbid(unsafe_code)]
// #[macro_use]
// extern crate serde_derive;

use std::collections::HashMap;
use log::error;

use snafu::Snafu;
use url::ParseError;

use std::io;
use std::sync::Arc;
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


#[derive(Default)]
struct NodeStatistics {
    bytes_sent: u64,
    bytes_received: u64,
    connection_count: u64,
}

type StatisticsMap = Arc<Mutex<HashMap<String, NodeStatistics>>>;