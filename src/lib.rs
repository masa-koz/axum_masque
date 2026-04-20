use std::{
    collections::HashMap,
    future::{Future, poll_fn},
};

use axum::body::Bytes;
use bytes::{Buf, BufMut, BytesMut};
use h3::{ext::Protocol, quic::StreamId};
use h3_datagram::{
    datagram_handler::{DatagramReader, DatagramSender, HandleDatagramsExt},
    quic_traits::{DatagramConnectionExt, RecvDatagram, SendDatagram},
};
use h3_util::{server::H3Acceptor, server_body::H3IncomingServer};
use http::{Request, Response};
use http_body::Body;
use http_body_util::{BodyExt, channel::Channel};
use hyper::rt::Executor;
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::mpsc, sync::oneshot};
use tower::layer::Layer;

#[cfg(feature = "msquic-async")]
pub mod msquic_async {
    pub use h3_util::msquic_async::*;
}

pub struct BoundUdpProxyLayer;

impl BoundUdpProxyLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for BoundUdpProxyLayer {
    type Service = BoundUdpProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BoundUdpProxyService::new(inner)
    }
}

#[derive(Clone)]
pub struct BoundUdpProxyService<S> {
    inner: S,
    executor: h3_util::executor::SharedExec,
}

impl<S> BoundUdpProxyService<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            executor: h3_util::executor::SharedExec::tokio(),
        }
    }
}

impl<RS, BD, S> tower::Service<Request<H3IncomingServer<RS, Bytes>>> for BoundUdpProxyService<S>
where
    RS: h3::quic::RecvStream + Send + Sync + 'static,
    BD: Body<Data = Bytes> + Send + 'static,
    BD::Error: Into<h3_util::Error> + std::error::Error + Send + Sync,
    S: tower::Service<Request<H3IncomingServer<RS, Bytes>>, Response = Response<BD>>,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<axum::body::Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<H3IncomingServer<RS, Bytes>>) -> Self::Future {
        if req.uri().path() == "/.well-known/masque/udp/%2A/%2A/" {
            let proxy_state = req.extensions_mut().remove::<ProxyState>().unwrap();
            let stream_id = req.extensions_mut().remove::<StreamId>().unwrap();

            let socket = match (
                validate_connect_udp(&req),
                req.headers().get("connect-udp-bind"),
                req.headers().get("capsule-protocol"),
            ) {
                (true, Some(bind), Some(capsule)) if bind == "?1" && capsule == "?1" => {
                    tracing::debug!("BoundUdpProxyService handling bound_udp_proxy");
                    std::net::UdpSocket::bind("0.0.0.0:0").unwrap()
                }
                _ => {
                    tracing::debug!("BoundUdpProxyService invalid request");
                    let res = Response::builder()
                        .status(http::StatusCode::BAD_REQUEST)
                        .body(axum::body::Body::empty())
                        .unwrap();
                    return Box::pin(futures::future::ready(Ok(res)));
                }
            };
            let proxy_public_addr = socket.local_addr().unwrap();
            let (mut tx, res_body) = Channel::<Bytes, Infallible>::new(4);
            self.executor.execute(async move {
                let (_, mut req_body) = req.into_parts();
                socket.set_nonblocking(true).unwrap();
                let socket = Arc::new(UdpSocket::from_std(socket).unwrap());

                let (resp_tx, resp_rx) = oneshot::channel();
                proxy_state.from_udp_to_quic.send(FromUdpToQuicRequest::RegisterSocket(socket.clone(), resp_tx)).await.unwrap();
                match resp_rx.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::error!("Failed to register socket: {e}");
                        return;
                    }
                    Err(_) => {
                        tracing::error!("Failed to register socket");
                        return;
                    }
                }

                let (resp_tx, resp_rx) = oneshot::channel();
                proxy_state.from_quic_to_udp.send(FromQuicToUdpRequest::RegisterSocket(stream_id.clone(), socket, resp_tx)).await.unwrap();
                match resp_rx.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::error!("Failed to register socket: {e}");
                        return;
                    }
                    Err(_) => {
                        tracing::error!("Failed to register socket");
                        return;
                    }
                }

                let mut buf = BytesMut::new();
                while let Some(chunk) = req_body.frame().await {
                    match chunk {
                        Ok(bytes) => {
                            let bytes = bytes.into_data().unwrap();
                            buf.extend_from_slice(&bytes);
                            let Some((capsule_type, payload)) = crate::decode_var_int(buf.chunk()) else {
                                // incomplete capsule
                                continue;
                            };
                            let Some((length, payload)) = crate::decode_var_int(payload) else {
                                // incomplete capsule
                                continue;
                            };
                            if buf.len() < length as usize {
                                // incomplete capsule
                                continue;
                            }
                            match capsule_type {
                                0x11 => {
                                    // COMPRESSION_ASSIGN capsule
                                    let Some((context_id, mut payload)) = crate::decode_var_int(payload)
                                    else {
                                        buf.advance(length as usize);
                                        continue;
                                    };
                                    if payload.len() < 1 {
                                        buf.advance(length as usize);
                                        continue;
                                    }
                                    let ip_version = payload.get_u8();
                                    let addr = match ip_version {
                                        0 => {
                                            tracing::info!(
                                                "received COMPRESSION_ASSIGN capsule with context id {}",
                                                context_id
                                            );
                                            None
                                        }
                                        4 => {
                                            if payload.len() < 6 {
                                                tracing::error!(
                                                    "missing IPv4 address and port in COMPRESSION_ASSIGN capsule: context id {}",
                                                    context_id
                                                );
                                                buf.advance((length) as usize);
                                                continue;
                                            }
                                            let ip_bytes = &payload[..4];
                                            let port_bytes = &payload[4..6];
                                            let ip = std::net::Ipv4Addr::new(
                                                ip_bytes[0],
                                                ip_bytes[1],
                                                ip_bytes[2],
                                                ip_bytes[3],
                                            );
                                            let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
                                            Some(addr)
                                        }
                                        6 => {
                                            if payload.len() < 18 {
                                                tracing::error!(
                                                    "missing IPv6 address and port in COMPRESSION_ASSIGN capsule: context id {}",
                                                    context_id
                                                );
                                                buf.advance((length) as usize);
                                                continue;
                                            }
                                            let ip_bytes = &payload[..16];
                                            let port_bytes = &payload[16..18];
                                            let ip = std::net::Ipv6Addr::from([
                                                ip_bytes[0],
                                                ip_bytes[1],
                                                ip_bytes[2],
                                                ip_bytes[3],
                                                ip_bytes[4],
                                                ip_bytes[5],
                                                ip_bytes[6],
                                                ip_bytes[7],
                                                ip_bytes[8],
                                                ip_bytes[9],
                                                ip_bytes[10],
                                                ip_bytes[11],
                                                ip_bytes[12],
                                                ip_bytes[13],
                                                ip_bytes[14],
                                                ip_bytes[15],
                                            ]);
                                            let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                            let addr = SocketAddr::new(std::net::IpAddr::V6(ip), port);
                                            Some(addr)
                                        }
                                        _ => {
                                            tracing::error!(
                                                "unknown IP version in COMPRESSION_ASSIGN capsule: {}",
                                                ip_version
                                            );
                                            buf.advance((length) as usize);
                                            continue;
                                        }
                                    };
                                    buf.advance((length) as usize);

                                    tracing::info!(
                                        "received COMPRESSION_ASSIGN capsule: context id {}, addr {:?}",
                                        context_id, addr
                                    );

                                    let (resp_tx, resp_rx) = oneshot::channel();
                                    proxy_state.from_udp_to_quic.send(FromUdpToQuicRequest::RegisterContextID(context_id, addr, resp_tx)).await.unwrap();
                                    match resp_rx.await {
                                        Ok(Ok(())) => {}
                                        Ok(Err(e)) => {
                                            tracing::error!("Failed to register context_id: {e}");
                                            return;
                                        }
                                        Err(_) => {
                                            tracing::error!("Failed to register context_id");
                                            return;
                                        }
                                    }

                                    let (resp_tx, resp_rx) = oneshot::channel();
                                    proxy_state.from_quic_to_udp.send(FromQuicToUdpRequest::RegisterContextID(stream_id.clone(), context_id, addr, resp_tx)).await.unwrap();
                                    match resp_rx.await {
                                        Ok(Ok(())) => {}
                                        Ok(Err(e)) => {
                                            tracing::error!("Failed to register context_id: {e}");
                                            return;
                                        }
                                        Err(_) => {
                                            tracing::error!("Failed to register context_id");
                                            return;
                                        }
                                    }

                                    let mut resp_buf = BytesMut::new();
                                    let resp_length = crate::encode_var_int(0x12).len()
                                        + 1
                                        + crate::encode_var_int(context_id).len();
                                    resp_buf.extend_from_slice(
                                        &crate::encode_var_int(0x12), // COMPRESSION_ACK capsule
                                    );
                                    resp_buf.extend_from_slice(&crate::encode_var_int(resp_length as u64));
                                    resp_buf.extend_from_slice(&crate::encode_var_int(context_id));
                                    tx.send(http_body::Frame::data(resp_buf.freeze())).await.unwrap();
                                }
                                _ => {
                                    tracing::error!("unknown capsule type {}", capsule_type);
                                    buf.advance(length as usize);
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("BoundUdpProxyService receive error: {}", e);
                            break;
                        }
                    }
                }

                let (resp_tx, resp_rx) = oneshot::channel();
                proxy_state.from_udp_to_quic.send(FromUdpToQuicRequest::Finish(resp_tx)).await.unwrap();
                match resp_rx.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::error!("Failed to finish: {e}");
                        return;
                    }
                    Err(_) => {
                        tracing::error!("Failed to finish");
                        return;
                    }
                }

                let (resp_tx, resp_rx) = oneshot::channel();
                proxy_state.from_quic_to_udp.send(FromQuicToUdpRequest::Finish(resp_tx)).await.unwrap();
                match resp_rx.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::error!("Failed to finish: {e}");
                        return;
                    }
                    Err(_) => {
                        tracing::error!("Failed to finish");
                        return;
                    }
                }

            });
            let res = Response::builder()
                .status(http::StatusCode::OK)
                .header("connect-udp-bind", "?1")
                .header("capsule-protocol", "?1")
                .header("proxy-public-address", format!("{}", proxy_public_addr))
                .body(axum::body::Body::new(res_body))
                .unwrap();
            return Box::pin(futures::future::ready(Ok(res)));
        }
        let fut = self.inner.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map(axum::body::Body::new))
        })
    }
}

fn validate_connect_udp<RS>(request: &Request<H3IncomingServer<RS, Bytes>>) -> bool
where
    RS: h3::quic::RecvStream + Send + Sync + 'static,
{
    let protocol = request.extensions().get::<Protocol>();
    matches!((request.method(), protocol), (&http::Method::CONNECT, Some(p)) if p == &Protocol::CONNECT_UDP)
}

fn decode_var_int(data: &[u8]) -> Option<(u64, &[u8])> {
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
    v = v & 0x3f;
    for i in 1..length - 1 {
        v = (v << 8) + Into::<u64>::into(data[i]);
    }

    Some((v, &data[length..]))
}

fn encode_var_int(mut v: u64) -> Vec<u8> {
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

enum FromUdpToQuicRequest {
    RegisterSocket(Arc<UdpSocket>, oneshot::Sender<anyhow::Result<()>>),
    RegisterContextID(u64, Option<SocketAddr>, oneshot::Sender<anyhow::Result<()>>),
    Finish(oneshot::Sender<anyhow::Result<()>>),
}

enum FromQuicToUdpRequest {
    RegisterSocket(
        StreamId,
        Arc<UdpSocket>,
        oneshot::Sender<anyhow::Result<()>>,
    ),
    RegisterContextID(
        StreamId,
        u64,
        Option<SocketAddr>,
        oneshot::Sender<anyhow::Result<()>>,
    ),
    Finish(oneshot::Sender<anyhow::Result<()>>),
}

#[derive(Clone)]
struct ProxyState {
    from_udp_to_quic: mpsc::Sender<FromUdpToQuicRequest>,
    from_quic_to_udp: mpsc::Sender<FromQuicToUdpRequest>,
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
    let svc = tower::ServiceBuilder::new()
        //.add_extension(Arc::new(ConnInfo { addr, certificates }))
        .layer(BoundUdpProxyLayer::new())
        .service(svc);

    // TODO: tonic body is wrapped? Is it for error to status conversion?
    // use tower::ServiceExt;
    // let h_svc =
    //     hyper_util::service::TowerToHyperService::new(svc.map_request(|req: http::Request<_>| {
    //         req.map(tonic::body::boxed::<crate::H3IncomingServer<AC::RS, Bytes>>)
    //     }));

    // let h_svc = hyper_util::service::TowerToHyperService::new(svc);

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
                from_quic_to_udp_thread(from_quic_to_udp_rx, datagram_reader)
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
                        tracing::debug!("received request for bound_udp_proxy");
                        let (tx, rx) = mpsc::channel(1024);
                        let state = ProxyState {
                            from_udp_to_quic: tx,
                            from_quic_to_udp: from_quic_to_udp_tx2,
                        };
                        req.extensions_mut().insert(state);
                        req.extensions_mut().insert(stream_id);
                        executor_clone2.execute(async move {
                            from_udp_to_quic_thread(rx, datagram_sender).await.unwrap();
                        });
                    } else {
                        tracing::debug!("received request for {}", req.uri().path());
                    }
                    if let Err(e) = serve_request::<AC, _, _>(req, stream, svc_cp.clone()).await {
                        tracing::warn!("server request failed: {}", e);
                    }
                });
            }
        });
    }
}

async fn from_quic_to_udp_thread<H>(
    mut rx: mpsc::Receiver<FromQuicToUdpRequest>,
    mut datagram_reader: DatagramReader<H>,
) -> anyhow::Result<()>
where
    H: RecvDatagram + 'static + Send,
    <H as RecvDatagram>::Buffer: Send,
{
    let mut socket_info: HashMap<StreamId, Arc<UdpSocket>> = HashMap::new();
    let mut compression_info: HashMap<(StreamId, u64), Option<SocketAddr>> = HashMap::new();
    loop {
        tokio::select! {
            datagram = datagram_reader.read_datagram() => {
                let datagram = match datagram {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!("recv datagram error: {}", e);
                        break;
                    }
                };
                let stream_id = datagram.stream_id();
                let datagram = datagram.into_payload();
                if let Some((context_id, mut payload)) = decode_var_int(datagram.chunk()) {
                    let (socket, addr) = {
                        let Some(socket) = socket_info.get(&stream_id) else {
                            tracing::error!("unknown stream id {}", stream_id);
                            continue;
                        };
                        let addr = match compression_info.get(&(stream_id, context_id)) {
                            Some(Some(addr)) => addr.clone(),
                            Some(None) => {
                                if payload.len() < 1 {
                                    tracing::error!(
                                        "missing IP version byte in datagram with context id {}",
                                        context_id
                                    );
                                    continue;
                                }
                                let ip_version = payload.get_u8();
                                match ip_version {
                                    4 => {
                                        if payload.len() < 6 {
                                            tracing::error!(
                                                "missing IPv4 address and port in datagram with context id {}",
                                                context_id
                                            );
                                            continue;
                                        }
                                        let ip_bytes = &payload[..4];
                                        let port_bytes = &payload[4..6];
                                        let ip = std::net::Ipv4Addr::new(
                                            ip_bytes[0],
                                            ip_bytes[1],
                                            ip_bytes[2],
                                            ip_bytes[3],
                                        );
                                        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                        let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
                                        tracing::info!("context id {} target {}", context_id, addr);
                                        payload.advance(6);
                                        addr
                                    }
                                    6 => {
                                        if payload.len() < 18 {
                                            tracing::error!(
                                                "missing IPv6 address and port in datagram with context id {}",
                                                context_id
                                            );
                                            continue;
                                        }
                                        let ip_bytes = &payload[..16];
                                        let port_bytes = &payload[16..18];
                                        let ip = std::net::Ipv6Addr::from([
                                            ip_bytes[0],
                                            ip_bytes[1],
                                            ip_bytes[2],
                                            ip_bytes[3],
                                            ip_bytes[4],
                                            ip_bytes[5],
                                            ip_bytes[6],
                                            ip_bytes[7],
                                            ip_bytes[8],
                                            ip_bytes[9],
                                            ip_bytes[10],
                                            ip_bytes[11],
                                            ip_bytes[12],
                                            ip_bytes[13],
                                            ip_bytes[14],
                                            ip_bytes[15],
                                        ]);
                                        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                                        let addr = SocketAddr::new(std::net::IpAddr::V6(ip), port);
                                        tracing::info!("context id {} target {}", context_id, addr);
                                        payload.advance(18);
                                        addr
                                    }
                                    _ => {
                                        tracing::error!(
                                            "unknown IP version {} in datagram with context id {}",
                                            ip_version, context_id
                                        );
                                        continue;
                                    }
                                }
                            }
                            None => {
                                tracing::error!("unknown context id {}", context_id);
                                continue;
                            }
                        };
                        (socket.clone(), addr)
                    };
                    if let Err(err) = socket.send_to(payload, addr).await {
                        tracing::error!("failed to send datagram: {:?}", err);
                        continue;
                    }
                } else {
                    tracing::error!("failed to decode var int from datagram");
                    continue;
                }
            }
            req = rx.recv() => {
                match req {
                    Some(FromQuicToUdpRequest::RegisterSocket(stream_id, socket, resp_tx)) => {
                        tracing::debug!("from_quic_to_udp_thread received RegisterSocket request for stream id {}", stream_id);
                        socket_info.insert(stream_id, socket);
                        resp_tx.send(anyhow::Ok(())).unwrap();
                    }
                    Some(FromQuicToUdpRequest::RegisterContextID(stream_id, context_id, addr, resp_tx)) => {
                        tracing::debug!("from_quic_to_udp_thread received RegisterContextID request for stream id {}, context id {}, addr {:?}", stream_id, context_id, addr);
                        compression_info.insert((stream_id, context_id), addr);
                        resp_tx.send(anyhow::Ok(())).unwrap();
                    }
                    Some(FromQuicToUdpRequest::Finish(resp_tx)) => {
                        tracing::info!("from_quic_to_udp_thread received Finish request, exiting");
                        resp_tx.send(anyhow::Ok(())).unwrap();
                        return Ok(());
                    }
                    None => {
                        tracing::debug!("from_quic_to_udp_thread channel closed");
                        return Ok(());
                    }
                }
            }
        }
    }
    anyhow::Ok(())
}

async fn from_udp_to_quic_thread<H>(
    mut rx: mpsc::Receiver<FromUdpToQuicRequest>,
    mut datagram_sender: DatagramSender<H, Bytes>,
) -> anyhow::Result<()>
where
    H: SendDatagram<Bytes> + 'static + Send,
{
    let socket = match rx.recv().await {
        Some(FromUdpToQuicRequest::RegisterSocket(socket, resp_tx)) => {
            tracing::debug!("from_udp_to_quic_thread received RegisterSocket request");
            resp_tx.send(anyhow::Ok(())).unwrap();
            socket
        }
        Some(_) => {
            tracing::debug!("from_udp_to_quic_thread received unknown request");
            return Ok(());
        }
        None => {
            tracing::debug!("from_udp_to_quic_thread channel closed");
            return Ok(());
        }
    };

    let mut uncompressed_context_id = None;
    let mut compression_info = HashMap::new();
    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            req = rx.recv() => {
                match req {
                    Some(FromUdpToQuicRequest::RegisterSocket(_, resp_tx)) => {
                        tracing::debug!("from_udp_to_quic_thread received unexpected RegisterSocket request");
                        resp_tx.send(Err(anyhow::anyhow!("unexpected RegisterSocket request"))).unwrap();
                    }
                    Some(FromUdpToQuicRequest::RegisterContextID(context_id, addr, resp_tx)) => {
                        if let Some(addr) = addr {
                            compression_info.insert(addr, context_id);
                            tracing::info!("registered compressed context id {} for addr {}", context_id, addr);
                        } else {
                            uncompressed_context_id = Some(context_id);
                            tracing::info!("registered uncompressed context id {}", context_id);
                        }
                        resp_tx.send(anyhow::Ok(())).unwrap();
                    }
                    Some(FromUdpToQuicRequest::Finish(resp_tx)) => {
                        tracing::info!("from_udp_to_quic_thread received Finish request, exiting");
                        resp_tx.send(anyhow::Ok(())).unwrap();
                        return Ok(());
                    }
                    None => {
                        tracing::debug!("from_udp_to_quic_thread channel closed");
                        return Ok(());
                    }
                }
            }
            res = socket.recv_from(&mut buf) => {
                let (len, addr) = match res {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::error!("udp receive error: {}", e);
                        break;
                    }
                };
                let (context_id, compressed) = {
                    match compression_info.get(&addr) {
                        Some(id) => (*id, true),
                        None => match uncompressed_context_id {
                            Some(id) => (id, false),
                            None => {
                                tracing::error!("no context id for uncompressed");
                                continue;
                            }
                        },
                    }
                };
                let mut datagram = BytesMut::new();
                datagram.extend_from_slice(&crate::encode_var_int(context_id));
                if !compressed {
                    match addr.ip() {
                        std::net::IpAddr::V4(ipv4) => {
                            datagram.put_u8(4); // IP version
                            datagram.extend_from_slice(&ipv4.octets());
                        }
                        std::net::IpAddr::V6(ipv6) => {
                            datagram.put_u8(6); // IP version
                            datagram.extend_from_slice(&ipv6.octets());
                        }
                    }
                    datagram.extend_from_slice(&addr.port().to_be_bytes());
                }
                datagram.extend_from_slice(&buf[..len]);

                if let Err(e) = datagram_sender.send_datagram(datagram.freeze()) {
                    tracing::error!("send datagram error: {}", e);
                    break;
                }
            }
        }
    }
    anyhow::Ok(())
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
