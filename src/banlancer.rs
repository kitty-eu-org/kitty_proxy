use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::traits::BanlancerTrait;
use crate::types::Address;
use crate::NodeInfo;

#[derive(Default)]
pub struct ConnectionStatsBanlancer {
    statistics_map: HashMap<NodeInfo, usize>,
}

impl ConnectionStatsBanlancer {
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

impl BanlancerTrait for ConnectionStatsBanlancer {
    async fn get_best_node(&self) -> Address {
        let node = self.get_least_connected_node().await;
        Address::from(node)
    }
}

pub type ArcConnectionStatsBanlancer = Arc<Mutex<Option<ConnectionStatsBanlancer>>>;
