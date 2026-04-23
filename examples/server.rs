use argh::FromArgs;
use async_trait::async_trait;
use axum::{
    Router,
    body::Bytes,
    extract::{Request, State},
    http::header,
    middleware,
    response::Response,
};
use axum_masque::H3Router;
use axum_masque::msquic_async::{
    H3MsQuicAsyncAcceptor,
    h3_msquic_async::{msquic, msquic_async},
};
use jwks::Jwks;
use std::{io::Write, net::SocketAddr, sync::Arc, time::Duration};
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;
use tower::{ServiceBuilder, make::MakeService, service_fn};
use tower_http::{
    LatencyUnit, ServiceBuilderExt,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tower_jwt::{DecodingKey, DecodingKeyFn, JwtLayer, RequestClaim, Validation};

mod public_address_store;

fn make_msquic_async_listner(
    addr: Option<SocketAddr>,
) -> anyhow::Result<(Arc<msquic::Registration>, msquic_async::Listener)> {
    let registration = msquic::Registration::new(&msquic::RegistrationConfig::default())?;
    let alpn = [msquic::BufferRef::from("h3")];
    let configuration = msquic::Configuration::open(
        &registration,
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(10000)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled(),
        ),
    )?;

    let cert = include_bytes!("cert.pem");
    let key = include_bytes!("key.pem");

    let mut cert_file = NamedTempFile::new()?;
    cert_file.write_all(cert)?;
    let cert_path = cert_file.into_temp_path();
    let cert_path = cert_path.to_string_lossy().into_owned();

    let mut key_file = NamedTempFile::new()?;
    key_file.write_all(key)?;
    let key_path = key_file.into_temp_path();
    let key_path = key_path.to_string_lossy().into_owned();

    let cred_config = msquic::CredentialConfig::new().set_credential(
        msquic::Credential::CertificateFile(msquic::CertificateFile::new(key_path, cert_path)),
    );

    configuration.load_credential(&cred_config)?;
    let listner = msquic_async::Listener::new(&registration, configuration)?;
    listner.start(&alpn, addr)?;
    Ok((Arc::new(registration), listner))
}

#[derive(Clone)]
struct FetchDecodingKey {
    url: String,
    kid: String,
}

impl FetchDecodingKey {
    pub fn new(url: String, kid: String) -> Self {
        Self { url, kid }
    }
}

#[async_trait]
impl DecodingKeyFn for FetchDecodingKey {
    type Error = FetchDecodingKeyError;

    async fn decoding_key(&self) -> Result<DecodingKey, Self::Error> {
        tracing::debug!("Fetching JWKS from URL: {}", self.url);
        let jwks = Jwks::from_jwks_url(&self.url).await;
        match jwks {
            Ok(mut jwks) => jwks
                .keys
                .remove(&self.kid)
                .ok_or_else(|| FetchDecodingKeyError::KeyNotFound)
                .map(|jwk| jwk.decoding_key),
            Err(err) => {
                tracing::error!("Failed to fetch JWKS: {}", err);
                Err(FetchDecodingKeyError::FetchError(err))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum FetchDecodingKeyError {
    #[error("Failed to fetch JWKS: {0}")]
    FetchError(#[from] jwks::JwksError),
    #[error("Key not found")]
    KeyNotFound,
}

#[derive(Debug, Clone)]
struct AppState {
    public_address_store: public_address_store::Store,
}

#[derive(FromArgs, Clone)]
/// server args
pub struct CmdOptions {
    /// service address
    #[argh(option, default = "String::from(\"127.0.0.1:8443\")")]
    service_addr: String,

    /// public address db path
    #[argh(option, default = "String::from(\"./public_address.db\")")]
    public_address_db: String,
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let cmd_opts: CmdOptions = argh::from_env();

    let token = CancellationToken::new();
    let addr: SocketAddr = cmd_opts.service_addr.parse()?;
    let (_registration, listener) = make_msquic_async_listner(Some(addr))?;
    let listen_addr = listener.local_addr()?;
    tracing::info!("service listening on: {}", listen_addr);
    let acceptor = H3MsQuicAsyncAcceptor::new(listener);

    let public_address_store =
        public_address_store::Store::new(&cmd_opts.public_address_db).await?;
    let state = AppState { public_address_store };

    let sensitive_headers: Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();

    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&["https://seera-networks.jp.auth0.com/"]);
    validation.set_audience(&[
        "https://masque.seera-networks.com/",
        "https://seera-networks.jp.auth0.com/userinfo",
    ]);

    async fn read_public_address(
        State(state): State<AppState>,
        mut req: Request,
        next: middleware::Next,
    ) -> Response {
        if let Some(claim) = req
            .extensions()
            .get::<RequestClaim<axum_masque::Claim>>()
            .cloned()
        {
            tracing::debug!("User claim in middleware: sub={}", claim.claim.sub);
            let addr = state.public_address_store.get(&claim.claim.sub).await.ok().flatten().map(|addr_str| {
                tracing::debug!("Found public address for sub {}: {}", claim.claim.sub, addr_str);
                addr_str.parse::<SocketAddr>().ok()
            }).flatten();
            if let Some(addr) = addr {
                tracing::debug!("Inserting public address into request extensions: {}", addr);
                req.extensions_mut()
                    .insert(axum_masque::PublicAddress { addr });
            }
        }
        let response = next.run(req).await;
        response
    }

    let middleware = ServiceBuilder::new()
        // .sensitive_request_headers(sensitive_headers.clone())
        // .layer(
        //     TraceLayer::new_for_http()
        //         .on_body_chunk(|chunk: &Bytes, latency: Duration, _: &tracing::Span| {
        //             tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk")
        //         })
        //         .make_span_with(DefaultMakeSpan::new().include_headers(true))
        //         .on_response(DefaultOnResponse::new().include_headers(true).latency_unit(LatencyUnit::Micros)),
        // )
        .layer(JwtLayer::<axum_masque::Claim, FetchDecodingKey>::new(
            validation,
            FetchDecodingKey::new(
                "https://seera-networks.jp.auth0.com/.well-known/jwks.json".to_string(),
                "HHTPL7guEDEcUT-9j0rC5".to_string(),
            ),
        ))
        .layer(middleware::from_fn_with_state(state.clone(),read_public_address))
        .layer(axum_masque::bound_udp::BoundUdpLayer::new());

    let router = Router::new()
        .route("/", axum::routing::get(|| async { "Hello, World!" }))
        .layer(middleware);

    let token_cloned = token.clone();
    let handle_svc = tokio::spawn(async move {
        let _ = H3Router::new(router)
            .serve_with_shutdown(acceptor, async move { token_cloned.cancelled().await })
            .await;
    });

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for event");
    token.cancel();
    let _ = handle_svc.await?;

    Ok(())
}
