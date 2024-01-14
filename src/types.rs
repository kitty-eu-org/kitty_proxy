#![forbid(unsafe_code)]
// #[macro_use]
// extern crate serde_derive;

use std::collections::HashMap;
use std::hash::Hash;
use log::error;

use snafu::Snafu;
use url::ParseError;

use std::io;
use std::net::SocketAddr;
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


pub struct NodeInfo {
    socket_addr: SocketAddr,
    node_number: i8,
}

#[derive(Default)]
pub struct NodeStatistics {
    statistics_map: HashMap<NodeInfo, usize>,
}

impl NodeStatistics {
    pub fn from_vec(node_infos: &Vec<NodeInfo>) -> Self {
        let mut statistics_map: HashMap<NodeInfo, usize> = HashMap::with_capacity(node_infos.len());
        for node_info in &node_infos {
            statistics_map.insert(node_info, 0);
        }
        Self {
            statistics_map
        }
    }

    async fn get_least_connected_node(&self) -> SocketAddr {
        let new_map: HashMap<SocketAddr, f32> = self.statistics_map
            .iter()
            .map(|(&key, value)| (key.socket_addr, value / key.node_number))
            .collect();
        let target = new_map.iter().min_by_key(|&(_, &value)| value).map(|(key, _)| key).unwrap().to_owned();
        target
    }
}


pub type StatisticsMap = Arc<Mutex<Option<NodeStatistics>>>;