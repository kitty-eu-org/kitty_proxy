use crate::types::Address;

pub trait BanlancerTrait {
    async fn get_best_node(&self) -> Address;
}

