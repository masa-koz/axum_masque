use bytes::Buf;
use h3::quic::StreamId;
use h3_datagram::{datagram_handler::DatagramReader, quic_traits::RecvDatagram};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::mpsc, sync::oneshot};

pub(crate) enum Message {
    RegisterSocket(
        StreamId,
        Arc<UdpSocket>,
        oneshot::Sender<anyhow::Result<()>>,
    ),
    RegisterContextId(
        StreamId,
        u64,
        Option<SocketAddr>,
        oneshot::Sender<anyhow::Result<()>>,
    ),
}

#[derive(Clone)]
pub(crate) struct Controller {
    stream_id: StreamId,
    tx: mpsc::Sender<Message>,
}

impl Controller {
    pub(crate) fn new(stream_id: StreamId, tx: mpsc::Sender<Message>) -> Self {
        Self { stream_id, tx }
    }

    pub(crate) async fn register_socket(&self, socket: Arc<UdpSocket>) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::RegisterSocket(
                self.stream_id,
                socket,
                resp_tx,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send RegisterSocket Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive RegisterSocket response"))?
    }

    pub(crate) async fn register_context_id(
        &self,
        context_id: u64,
        addr: Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::RegisterContextId(
                self.stream_id,
                context_id,
                addr,
                resp_tx,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send RegisterContextId Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive RegisterContextId response"))?
    }
}

pub(crate) async fn thread<H>(
    mut rx: mpsc::Receiver<Message>,
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
            msg = rx.recv() => {
                match msg {
                    Some(Message::RegisterSocket(stream_id, socket, resp_tx)) => {
                        tracing::debug!("received RegisterSocket Message for stream id {}", stream_id);
                        socket_info.insert(stream_id, socket);
                        resp_tx.send(anyhow::Ok(())).unwrap();
                    }
                    Some(Message::RegisterContextId(stream_id, context_id, addr, resp_tx)) => {
                        tracing::debug!("received RegisterContextID Message for stream id {}, context id {}, addr {:?}", stream_id, context_id, addr);
                        compression_info.insert((stream_id, context_id), addr);
                        resp_tx.send(anyhow::Ok(())).unwrap();
                    }
                    None => {
                        tracing::debug!("channel closed");
                        return Ok(());
                    }
                }
            }
            datagram = datagram_reader.read_datagram() => {
                let datagram = match datagram {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!("recv datagram error: {}", e);
                        break;
                    }
                };
                let stream_id = datagram.stream_id();
                let datagram = datagram.into_payload();
                if let Some((context_id, mut payload)) = crate::decode_var_int(datagram.chunk()) {
                    let (socket, addr) = {
                        let Some(socket) = socket_info.get(&stream_id) else {
                            tracing::error!("unknown stream id {}", stream_id);
                            continue;
                        };
                        let addr = match compression_info.get(&(stream_id, context_id)) {
                            Some(Some(addr)) => *addr,
                            Some(None) => {
                                if payload.is_empty() {
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
                                        let ip = std::net::Ipv4Addr::from_octets(<[u8; 4]>::try_from(&payload[..4]).unwrap());
                                        let port = u16::from_be_bytes(<[u8; 2]>::try_from(&payload[4..6]).unwrap());
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
                                        let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&payload[..16]).unwrap());
                                        let port = u16::from_be_bytes(<[u8; 2]>::try_from(&payload[16..18]).unwrap());
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
        }
    }
    anyhow::Ok(())
}
