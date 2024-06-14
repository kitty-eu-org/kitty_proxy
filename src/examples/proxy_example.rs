use kitty_proxy::{HttpProxy, MatchProxy, NodeInfo};
use std::{path::PathBuf, sync::Arc};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tokio::signal;


use anyhow::Ok;
use anyhow::Result;
use tokio::sync::{RwLock, watch};

#[tokio::main]
async fn main() -> Result<()> {

    let mut proxy = HttpProxy::new("127.0.0.1", 10089, None).await?;
        // let geoip_file = "/Users/hezhaozhao/myself/kitty/src-tauri/static/kitty_geoip.dat";
        let geoip_file = "src/geo_files/geoip.dat";
        // let geosite_file = "/Users/hezhaozhao/myself/kitty/src-tauri/static/kitty_geosite.dat";
        let geosite_file = "src/geo_files/geosite.dat";
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
            24689,
            1,
        ));
        // http_vpn_node_infos.push(NodeInfo::new(
        //     IpAddr::V4(Ipv4Addr::new(192,168, 50,104)),
        //     24656,
        //     1,
        // ));
        let _ = proxy
            .serve(arc_match_proxy, &mut http_kill_rx, http_vpn_node_infos)
            .await;
        signal::ctrl_c().await?;

        Ok(())
}