use kitty_proxy::SocksProxy;

use anyhow::Ok;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {

    let socks_proxy = SocksProxy::new("127.0.0.1".into(), 8080);
    socks_proxy.serve().await?;
    Ok(())

}