use axum::body::Bytes;
use bytes::{Buf, BytesMut};
use http::{Request, Response};
use http_body::Body;
use http_body_util::{BodyExt, channel::Channel};
use hyper::rt::Executor;
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tower::Service;
use tower_jwt::RequestClaim;

#[derive(Clone)]
pub struct BoundUdp<S> {
    inner: S,
    executor: h3_util::executor::SharedExec,
}

impl<S> BoundUdp<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            executor: h3_util::executor::SharedExec::tokio(),
        }
    }
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for BoundUdp<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Body<Data = Bytes> + Send + Unpin + 'static,
    ReqBody::Error: std::error::Error + Send + Sync,
    ResBody: Body<Data = Bytes> + Send + 'static,
    ResBody::Error: std::error::Error + Send + Sync,
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

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        tracing::debug!("received request: {} {}", req.method(), req.uri().path());
        if req.uri().path() == "/.well-known/masque/udp/%2A/%2A/" {
            let Some(claim) = req.extensions().get::<RequestClaim<crate::Claim>>().cloned() else {
                tracing::warn!("missing Claim in request extensions");
                let res = Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(axum::body::Body::empty())
                    .unwrap();
                return Box::pin(futures::future::ready(Ok(res)));
            };
            let Some(proxy_state) = req.extensions_mut().remove::<crate::masque::ProxyState>()
            else {
                tracing::warn!("missing ProxyState in request extensions");
                let res = Response::builder()
                    .status(http::StatusCode::SERVICE_UNAVAILABLE)
                    .body(axum::body::Body::empty())
                    .unwrap();
                return Box::pin(futures::future::ready(Ok(res)));
            };
            tracing::info!("handling bound_udp_proxy request for subject {}", claim.claim.sub);

            let public_address = req.extensions().get::<crate::PublicAddress>().cloned().unwrap_or_else(|| {
                let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
                crate::PublicAddress { addr }
            });
            let socket = match (
                crate::validate_connect_udp(&req),
                req.headers().get("connect-udp-bind"),
                req.headers().get("capsule-protocol"),
            ) {
                (true, Some(bind), Some(capsule)) if bind == "?1" && capsule == "?1" => {
                    std::net::UdpSocket::bind(public_address.addr).unwrap()
                }
                _ => {
                    tracing::warn!("invalid request");
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

                match proxy_state.from_udp_to_quic.register_socket(socket.clone()).await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!("Failed to register socket to from_udp_to_quic: {e}");
                        return;
                    }
                }

                match proxy_state.from_quic_to_udp.register_socket(socket.clone()).await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!("Failed to register socket to from_quic_to_udp: {e}");
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
                                    if payload.is_empty() {
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
                                            let ip = std::net::Ipv4Addr::from_octets(<[u8; 4]>::try_from(&payload[..4]).unwrap());
                                            let port = u16::from_be_bytes(<[u8; 2]>::try_from(&payload[4..6]).unwrap());
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
                                            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&payload[..16]).unwrap());
                                            let port = u16::from_be_bytes(<[u8; 2]>::try_from(&payload[16..18]).unwrap());
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

                                    match proxy_state.from_udp_to_quic.register_context_id(context_id, addr).await {
                                        Ok(()) => {}
                                        Err(e) => {
                                            tracing::error!("Failed to register context_id to from_udp_to_quic: {e}");
                                            return;
                                        }
                                    }

                                    match proxy_state.from_quic_to_udp.register_context_id(context_id, addr).await {
                                        Ok(()) => {}
                                        Err(e) => {
                                            tracing::error!("Failed to register context_id to from_quic_to_udp: {e}");
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
                            tracing::warn!("receive error: {}", e);
                            break;
                        }
                    }
                }

                match proxy_state.from_udp_to_quic.finish().await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!("Failed to finish from_udp_to_quic: {e}");
                    }
                }
            });
            tracing::info!(
                "handling bound_udp_proxy, proxy public address is {}",
                proxy_public_addr
            );
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
