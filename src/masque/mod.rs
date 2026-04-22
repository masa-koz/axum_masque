pub(crate) mod from_udp_to_quic;
pub(crate) mod from_quic_to_udp;

#[derive(Clone)]
pub(crate) struct ProxyState {
    pub(crate) from_udp_to_quic: self::from_udp_to_quic::Controller,
    pub(crate) from_quic_to_udp: self::from_quic_to_udp::Controller,
}