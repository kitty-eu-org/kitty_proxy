#![forbid(unsafe_code)]
// #[macro_use]
// extern crate serde_derive;

use log::error;
use std::collections::HashMap;

use snafu::Snafu;
use url::ParseError;

use std::io;
use std::net::{SocketAddr, IpAddr};
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

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub struct NodeInfo {
    pub socket_addr: SocketAddr,
    pub node_number: i8,
}


impl NodeInfo {
    pub fn new(ip_addr: IpAddr, port: u16, node_number: i8) -> Self {
        Self { socket_addr: SocketAddr::new(ip_addr, port), node_number }
        }
}

#[derive(Default)]
pub struct NodeStatistics {
    statistics_map: HashMap<NodeInfo, usize>,
}

impl NodeStatistics {
    pub fn from_vec(node_infos: &Vec<NodeInfo>) -> Self {
        let mut statistics_map: HashMap<NodeInfo, usize> = HashMap::with_capacity(node_infos.len());
        for node_info in node_infos.iter() {
            statistics_map.insert(*node_info, 0);
        }
        Self { statistics_map }
    }

    pub async fn get_least_connected_node(&self) -> NodeInfo {
        let new_map: HashMap<NodeInfo, f32> = self
            .statistics_map
            .iter()
            .map(|(&key, value)| (key, *value as f32 / key.node_number as f32))
            .collect();
        let target = new_map
            .iter()
            .min_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(key, _)| key)
            .unwrap()
            .to_owned();
        target
    }

    pub fn incre_count_by_node_info(&mut self, node_info: &NodeInfo) {
        self.statistics_map
            .entry(node_info.to_owned())
            .and_modify(|v| *v += 1);
    }

    pub fn decre_count_by_node_info(&mut self, node_info: &NodeInfo) {
        self.statistics_map
            .entry(node_info.to_owned())
            .and_modify(|v| *v -= 1);
    }
}

pub type StatisticsMap = Arc<Mutex<Option<NodeStatistics>>>;
