use axum::body::Bytes;
use h3::ext::Protocol;
use h3_datagram::{
    datagram_handler::HandleDatagramsExt,
    quic_traits::{DatagramConnectionExt, RecvDatagram},
};
use h3_util::{server::H3Acceptor, server_body::H3IncomingServer};
use http::{Request, Response};
use http_body::Body;
use hyper::rt::Executor;
use serde::Deserialize;
use std::{future::Future, net::SocketAddr};
use tokio::sync::mpsc;

#[cfg(feature = "msquic-async")]
pub mod msquic_async {
    pub use h3_util::msquic_async::*;
}

pub mod bound_udp;
mod masque;

#[derive(Deserialize, Clone, Debug)]
pub struct Claim {
    /// Subject (whom the token refers to)
    pub sub: String,
}

#[derive(Clone, Debug)]
pub struct PublicAddress {
    pub addr: SocketAddr,
}

pub(crate) fn validate_connect_udp<ReqBody>(request: &Request<ReqBody>) -> bool
where
    ReqBody: Body<Data = Bytes> + Send + Unpin + 'static,
{
    let protocol = request.extensions().get::<Protocol>();
    matches!((request.method(), protocol), (&http::Method::CONNECT, Some(p)) if p == &Protocol::CONNECT_UDP)
}

pub(crate) fn decode_var_int(data: &[u8]) -> Option<(u64, &[u8])> {
    // The length of variable-length integers is encoded in the
    // first two bits of the first byte.
    let mut v: u64 = data[0].into();
    let prefix = v >> 6;
    let length = 1 << prefix;

    if data.len() < length {
        return None;
    }
    // Once the length is known, remove these bits and read any
    // remaining bytes.
    v &= 0x3f;
    for v1 in data.iter().take(length).skip(1) {
        v = (v << 8) + Into::<u64>::into(*v1);
    }

    Some((v, &data[length..]))
}

pub(crate) fn encode_var_int(mut v: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let length = if v < 0x40 {
        1
    } else if v < 0x4000 {
        2
    } else if v < 0x400000 {
        4
    } else {
        8
    };
    let prefix = match length {
        1 => 0b00,
        2 => 0b01,
        4 => 0b10,
        8 => 0b11,
        _ => unreachable!(),
    };
    let mut first_byte = (prefix << 6) as u8;
    for _ in (1..length).rev() {
        let byte = (v & 0xff) as u8;
        buf.insert(0, byte);
        v >>= 8;
    }
    first_byte |= (v & 0x3f) as u8;
    buf.insert(0, first_byte);
    buf
}

/// Accept each connection from acceptor, then for each connection
/// accept each request. Spawn a task to handle each request.
async fn serve_inner<AC, F>(
    svc: axum::Router,
    executor: &h3_util::executor::SharedExec,
    mut acceptor: AC,
    signal: F,
) -> Result<(), h3_util::Error>
where
    AC: H3Acceptor,
    AC::CONN: DatagramConnectionExt<bytes::Bytes> + Send,
    <AC::CONN as DatagramConnectionExt<bytes::Bytes>>::SendDatagramHandler: Send,
    <AC::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler: Send,
    <<AC::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler as RecvDatagram>::Buffer: Send,
    AC::RS: Sync,
    F: Future<Output = ()>,
{
    let svc = tower::ServiceBuilder::new().service(svc);

    let mut sig = std::pin::pin!(signal);
    tracing::trace!("loop start");
    loop {
        tracing::trace!("loop");
        // get the next stream to run http on
        let conn = tokio::select! {
            res = acceptor.accept() =>{
                match res{
                Ok(x) => x,
                Err(e) => {
                    tracing::error!("accept error : {e}");
                    return Err(e);
                }
            }
            }
            _ = &mut sig =>{
                tracing::trace!("cancellation triggered");
                return Ok(());
            }
        };

        let Some(conn) = conn else {
            tracing::trace!("acceptor end of conn");
            return Ok(());
        };

        // server each connection in the background
        let svc_cp = svc.clone();
        let executor_clone = executor.clone();
        executor.execute(async move {
            let mut conn = match h3::server::Connection::new(conn).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("server connection failed: {}", e);
                    return;
                }
            };
            let (from_quic_to_udp_tx, from_quic_to_udp_rx) = mpsc::channel(1024);
            let datagram_reader = conn.get_datagram_reader();
            executor_clone.execute(async move {
                crate::masque::from_quic_to_udp::thread(from_quic_to_udp_rx, datagram_reader)
                    .await
                    .unwrap();
            });
            loop {
                let resolver = match conn.accept().await {
                    Ok(req) => match req {
                        Some(r) => r,
                        None => {
                            tracing::trace!("server connection ended:");
                            break;
                        }
                    },
                    Err(e) => {
                        if e.is_h3_no_error() {
                            tracing::trace!("server connection ended with h3 no error:");
                        } else {
                            tracing::warn!("server connection accept failed: {}", e);
                        }
                        break;
                    }
                };
                let (mut req, stream) = match resolver.resolve_request().await {
                    Ok(req) => req,
                    Err(e) => {
                        tracing::warn!("fail resolve request {e:#?}");
                        return;
                    }
                };
                let stream_id = stream.id();
                let datagram_sender = conn.get_datagram_sender(stream_id);
                let svc_cp = svc_cp.clone();
                let executor_clone2 = executor_clone.clone();
                let from_quic_to_udp_tx2 = from_quic_to_udp_tx.clone();
                executor_clone.execute(async move {
                    if req.uri().path() == "/.well-known/masque/udp/%2A/%2A/" {
                        let (from_udp_to_quic_tx, from_udp_to_quic_rx) = mpsc::channel(1024);
                        let state = crate::masque::ProxyState {
                            from_udp_to_quic: crate::masque::from_udp_to_quic::Controller::new(
                                from_udp_to_quic_tx,
                            ),
                            from_quic_to_udp: crate::masque::from_quic_to_udp::Controller::new(
                                stream_id,
                                from_quic_to_udp_tx2,
                            ),
                        };
                        req.extensions_mut().insert(state);
                        executor_clone2.execute(async move {
                            crate::masque::from_udp_to_quic::thread(
                                from_udp_to_quic_rx,
                                datagram_sender,
                            )
                            .await
                            .unwrap();
                        });
                    }
                    if let Err(e) = serve_request::<AC, _, _>(req, stream, svc_cp.clone()).await {
                        tracing::warn!("server request failed: {}", e);
                    }
                });
            }
        });
    }
}

async fn serve_request<AC, SVC, BD>(
    request: Request<()>,
    stream: h3::server::RequestStream<
        <<AC as H3Acceptor>::CONN as h3::quic::OpenStreams<Bytes>>::BidiStream,
        Bytes,
    >,
    mut service: SVC,
) -> Result<(), h3_util::Error>
where
    AC: H3Acceptor,
    SVC: tower::Service<
            Request<H3IncomingServer<AC::RS, Bytes>>,
            Response = Response<BD>,
            Error = std::convert::Infallible,
        >,
    SVC::Future: 'static,
    BD: Body + 'static,
    BD::Error: Into<h3_util::Error>,
    <BD as Body>::Error: Into<h3_util::Error> + std::error::Error + Send + Sync,
    <BD as Body>::Data: Send + Sync,
{
    tracing::trace!("serving request");
    let (parts, _) = request.into_parts();
    let (mut w, r) = stream.split();

    let req = Request::from_parts(parts, H3IncomingServer::new(r));
    tracing::trace!("serving request call service");
    let res = service.call(req).await?;

    let (res_h, res_b) = res.into_parts();

    // write header
    tracing::trace!("serving request write header");
    w.send_response(Response::from_parts(res_h, ())).await?;

    // write body or trailer.
    h3_util::server_body::send_h3_server_body::<BD, AC::BS>(&mut w, res_b).await?;

    tracing::trace!("serving request end");
    Ok(())
}

pub struct H3Router {
    inner: axum::Router,
    executor: h3_util::executor::SharedExec, // expose this for the user.
}

impl H3Router {
    pub fn new(inner: axum::Router) -> Self {
        Self {
            inner,
            executor: h3_util::executor::SharedExec::tokio(),
        }
    }
}

impl From<axum::Router> for H3Router {
    fn from(value: axum::Router) -> Self {
        Self::new(value)
    }
}

impl H3Router {
    /// Runs the service on acceptor until shutdown.
    pub async fn serve_with_shutdown<AC, F>(
        self,
        acceptor: AC,
        signal: F,
    ) -> Result<(), h3_util::Error>
    where
        AC: H3Acceptor,
        AC::CONN: DatagramConnectionExt<bytes::Bytes> + Send,
        <AC::CONN as DatagramConnectionExt<bytes::Bytes>>::SendDatagramHandler: Send,
        <AC::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler: Send,
        <<AC::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler as RecvDatagram>::Buffer: Send,
        AC::RS: Sync,
        F: Future<Output = ()>,
    {
        serve_inner(self.inner, &self.executor, acceptor, signal).await
    }

    /// Runs all services on acceptor
    pub async fn serve<AC>(self, acceptor: AC) -> Result<(), h3_util::Error>
    where
        AC: H3Acceptor,
        AC::CONN: DatagramConnectionExt<bytes::Bytes> + Send,
        <AC::CONN as DatagramConnectionExt<bytes::Bytes>>::SendDatagramHandler: Send,
        <AC::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler: Send,
        <<AC::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler as RecvDatagram>::Buffer: Send,
        AC::RS: Sync,
    {
        self.serve_with_shutdown(acceptor, async {
            // never returns
            futures::future::pending().await
        })
        .await
    }
}
