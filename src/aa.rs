use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 连接到代理服务器
    let mut stream = TcpStream::connect("proxy_server_address:proxy_port").await?;
    
    // 向代理服务器发送CONNECT请求
    stream.write_all(b"CONNECT destination_host:443 HTTP/1.1\r\n\r\n").await?;
    stream.flush().await?;
    
    // 读取代理服务器的响应
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    println!("Proxy response: {}", response);
    
    // 连接到目标服务器
    let mut tls_stream = tokio_tls::TlsConnector::from(native_tls::TlsConnector::new()?).connect("destination_host", stream).await?;
    
    // 在这里可以继续进行与目标服务器的通信
    
    Ok(())
}
