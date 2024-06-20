use fast_socks5::{
    server::{Config, SimpleUserPassword, Socks5Server, Socks5Socket},
    Result, SocksError,
};
use log::{error, info};

use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task;

use tokio_stream::StreamExt;

pub struct SocksProxy{
    ip: String,
    port: u16
}

impl SocksProxy {
    pub fn new(ip: String, port: u16) -> Self {
        Self {ip, port}
    }

}

fn spawn_and_log_error<F, T>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<Socks5Socket<T, SimpleUserPassword>>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin,
{
    task::spawn(async move {
        match fut.await {
            Ok(mut socket) => {
                if let Some(user) = socket.take_credentials() {
                    info!("user logged in with `{}`", user.username);
                }
            }
            Err(err) => error!("{:#}", &err),
        }
    })
}

impl SocksProxy {

   pub async fn serve(&self) -> anyhow::Result<()> {
        let config = Config::default();
        let listen_addr = format!("{}:{}", self.ip, self.port);
        let listener = <Socks5Server>::bind(&listen_addr).await?;
        let listener = listener.with_config(config);

        let mut incoming = listener.incoming();

    info!("Listen for socks connections @ {}", &listen_addr);

    // Standard TCP loop
    while let Some(socket_res) = incoming.next().await {
        match socket_res {
            Ok(socket) => {
                spawn_and_log_error(socket.upgrade_to_socks5());
            }
            Err(err) => {
                error!("accept error = {:?}", err);
            }
        }
    }

    Ok(())
    }
}
