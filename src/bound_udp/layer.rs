use super::service::BoundUdp;
use tower::layer::Layer;

#[derive(Clone, Debug)]
pub struct BoundUdpLayer;

impl BoundUdpLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BoundUdpLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for BoundUdpLayer {
    type Service = BoundUdp<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BoundUdp::new(inner)
    }
}
