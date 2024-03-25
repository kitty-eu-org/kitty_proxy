// This code was derived from the hudsucker repository:
// https://github.com/omjadas/hudsucker

use http::uri::Authority;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::http::uri::Scheme;
use hyper::{
    header::Entry, service::service_fn, upgrade::Upgraded, Method, Request, Response, Uri,
};
use hyper_util::rt::TokioIo;
use tokio::io::AsyncReadExt;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use tokio_tungstenite::{tungstenite, Connector};

use bytes::{Buf, Bytes};
use std::{
    cmp, io,
    marker::Unpin,
    pin::Pin,
    task::{self, Poll},
};

pub(crate) struct Rewind<T> {
    pre: Option<Bytes>,
    inner: T,
}

impl<T> Rewind<T> {
    #[allow(dead_code)]
    pub(crate) fn new(io: T) -> Self {
        Rewind {
            pre: None,
            inner: io,
        }
    }

    pub(crate) fn new_buffered(io: T, buf: Bytes) -> Self {
        Rewind {
            pre: Some(buf),
            inner: io,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn rewind(&mut self, bs: Bytes) {
        debug_assert!(self.pre.is_none());
        self.pre = Some(bs);
    }

    #[allow(dead_code)]
    pub(crate) fn into_inner(self) -> (T, Bytes) {
        (self.inner, self.pre.unwrap_or_default())
    }
}

impl<T> AsyncRead for Rewind<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut prefix) = self.pre.take() {
            // If there are no remaining bytes, let the bytes get dropped.
            if !prefix.is_empty() {
                let copy_len = cmp::min(prefix.len(), buf.remaining());
                // TODO: There should be a way to do following two lines cleaner...
                buf.put_slice(&prefix[..copy_len]);
                prefix.advance(copy_len);
                // Put back whats left
                if !prefix.is_empty() {
                    self.pre = Some(prefix);
                }

                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for Rewind<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub(crate) async fn proxy(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        process_connect(req)
    } else if hyper_tungstenite::is_upgrade_request(&req) {
        Ok(upgrade_websocket(req))
    } else {
        let res = self.client.request(normalize_request(req)).await?;
        Ok(res)
    }
}

fn process_connect(
    mut req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let fut = async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(mut upgraded) => {
                let mut buffer = [0; 4];

                let bytes_read = match upgraded.read(&mut buffer).await {
                    Ok(bytes_read) => bytes_read,
                    Err(e) => {
                        eprintln!("Failed to read from upgraded connection: {e}");
                        return;
                    }
                };

                let mut upgraded: Rewind<Upgraded> = Rewind::new_buffered(
                    upgraded,
                    bytes::Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                );

                if buffer == *b"GET " {
                    if let Err(e) = serve_stream(upgraded, Scheme::HTTP).await {
                        eprintln!("Websocket connect error: {e}");
                    }
                } else {
                    eprintln!(
                        "Unknown protocol, read '{:02X?}' from upgraded connection",
                        &buffer[..bytes_read]
                    );

                    let authority = req
                        .uri()
                        .authority()
                        .expect("Uri doesn't contain authority")
                        .as_ref();

                    let mut server = match TcpStream::connect(authority).await {
                        Ok(server) => server,
                        Err(e) => {
                            eprintln! {"failed to connect to {authority}: {e}"};
                            return;
                        }
                    };

                    if let Err(e) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await
                    {
                        eprintln!("Failed to tunnel unknown protocol to {}: {}", authority, e);
                    }
                }
            }
            Err(e) => eprintln!("Upgrade error {e}"),
        };
    };

    tokio::spawn(fut);
    Ok(Response::new(empty_body()))
}

fn upgrade_websocket(
    req: Request<hyper::body::Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut req = {
        let (mut parts, _) = req.into_parts();

        parts.uri = {
            let mut parts = parts.uri.into_parts();

            parts.scheme = if parts.scheme.unwrap_or(Scheme::HTTP) == Scheme::HTTP {
                Some("ws".try_into().expect("Failed to convert scheme"))
            } else {
                Some("wss".try_into().expect("Failed to convert scheme"))
            };

            Uri::from_parts(parts).expect("Failed to build URI")
        };

        Request::from_parts(parts, ())
    };

    let (res, websocket) =
        hyper_tungstenite::upgrade(&mut req, None).expect("Request missing headers");

    let fut = async move {
        match websocket.await {
            Ok(ws) => {
                if let Err(e) = handle_websocket(ws, req).await {
                    eprintln!("Failed to handle websocket: {e}");
                }
            }
            Err(e) => {
                eprintln!("Failed to upgrade to websocket: {e}");
            }
        }
    };

    tokio::spawn(fut);
    res
}

async fn handle_websocket(
    _server_socket: hyper_tungstenite::WebSocketStream<Upgraded>,
    _req: Request<()>,
) -> Result<(), tungstenite::Error> {
    Ok(())
}

async fn serve_stream<I>(stream: I, scheme: Scheme) -> Result<(), hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(|mut req| {
        if req.version() == hyper::Version::HTTP_10 || req.version() == hyper::Version::HTTP_11 {
            let (mut parts, body) = req.into_parts();

            let authority = parts
                .headers
                .get(hyper::header::HOST)
                .expect("Host is a required header")
                .as_bytes();
            parts.uri = {
                let mut parts = parts.uri.into_parts();
                parts.scheme = Some(scheme.clone());
                parts.authority =
                    Some(Authority::try_from(authority).expect("Failed to parse authority"));
                Uri::from_parts(parts).expect("Failed to build URI")
            };

            req = Request::from_parts(parts, body);
        };

        proxy(req)
    });

    Http::new()
        .serve_connection(stream, service)
        .with_upgrades()
        .await
}

fn normalize_request<T>(mut req: Request<T>) -> Request<T> {
    req.headers_mut().remove(hyper::header::HOST);

    if let Entry::Occupied(mut cookies) = req.headers_mut().entry(hyper::header::COOKIE) {
        let joined_cookies = bstr::join(b"; ", cookies.iter());
        cookies.insert(joined_cookies.try_into().expect("Failed to join cookies"));
    }

    *req.version_mut() = hyper::Version::HTTP_11;
    req
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use anyhow::Ok;
    use anyhow::Result;
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn it_works() -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

        let listener = TcpListener::bind(addr).await?;
        println!("Listening on http://{}", addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let io = TokioIo::new(stream);

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service_fn(proxy))
                    .with_upgrades()
                    .await
                {
                    println!("Failed to serve connection: {:?}", err);
                }
            });
        }
        Ok(())
    }
}
