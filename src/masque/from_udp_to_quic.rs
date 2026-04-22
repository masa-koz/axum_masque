use axum::body::Bytes;
use bytes::{BufMut, BytesMut};
use h3_datagram::{datagram_handler::DatagramSender, quic_traits::SendDatagram};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::mpsc, sync::oneshot};

pub(crate) enum Message {
    RegisterSocket(Arc<UdpSocket>, oneshot::Sender<anyhow::Result<()>>),
    RegisterContextId(u64, Option<SocketAddr>, oneshot::Sender<anyhow::Result<()>>),
    Finish(oneshot::Sender<anyhow::Result<()>>),
}

#[derive(Clone)]
pub(crate) struct Controller {
    tx: mpsc::Sender<Message>,
}

impl Controller {
    pub(crate) fn new(tx: mpsc::Sender<Message>) -> Self {
        Self { tx }
    }

    pub(crate) async fn register_socket(&self, socket: Arc<UdpSocket>) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::RegisterSocket(socket, resp_tx))
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
                context_id, addr, resp_tx,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send RegisterContextId Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive RegisterContextId response"))?
    }

    pub(crate) async fn finish(&self) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::Finish(resp_tx))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send Finish Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive Finish response"))?
    }
}

pub(crate) async fn thread<H>(
    mut rx: mpsc::Receiver<Message>,
    mut datagram_sender: DatagramSender<H, Bytes>,
) -> anyhow::Result<()>
where
    H: SendDatagram<Bytes> + 'static + Send,
{
    let socket = match rx.recv().await {
        Some(Message::RegisterSocket(socket, resp_tx)) => {
            tracing::debug!("received RegisterSocket Message");
            resp_tx.send(anyhow::Ok(())).unwrap();
            socket
        }
        Some(_) => {
            tracing::debug!("received unknown Message");
            return Ok(());
        }
        None => {
            tracing::debug!("channel closed");
            return Ok(());
        }
    };

    let mut uncompressed_context_id = None;
    let mut compression_info = HashMap::new();
    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(Message::RegisterSocket(_, resp_tx)) => {
                        tracing::debug!("received unexpected RegisterSocket Message");
                        resp_tx.send(Err(anyhow::anyhow!("unexpected RegisterSocket Message"))).unwrap();
                    }
                    Some(Message::RegisterContextId(context_id, addr, resp_tx)) => {
                        if let Some(addr) = addr {
                            compression_info.insert(addr, context_id);
                            tracing::info!("registered compressed context id {} for addr {}", context_id, addr);
                        } else {
                            uncompressed_context_id = Some(context_id);
                            tracing::info!("registered uncompressed context id {}", context_id);
                        }
                        resp_tx.send(anyhow::Ok(())).unwrap();
                    }
                    Some(Message::Finish(resp_tx)) => {
                        tracing::info!("received Finish Message, exiting");
                        resp_tx.send(anyhow::Ok(())).unwrap();
                        return Ok(());
                    }
                    None => {
                        tracing::debug!("channel closed");
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
                    tracing::warn!("send datagram error: {}", e);
                }
            }
        }
    }
    anyhow::Ok(())
}
