use crate::Error;
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, body::Incoming};
use hyper_util::rt::TokioIo;
use rcgen::generate_simple_self_signed;
use rquest::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    ServerConfig, pki_types::CertificateDer, pki_types::PrivatePkcs8KeyDer,
};

pub struct TlsSpoofingProxy {
    port: u16,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for TlsSpoofingProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()); // Send shutdown signal
        }
    }
}

impl TlsSpoofingProxy {
    pub async fn start(impersonate_client: Client) -> Result<Self, Error> {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await?;
        let port = listener.local_addr()?.port();

        let client = Arc::new(impersonate_client);

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok((stream, _)) = listener.accept() => {
                        let io = TokioIo::new(stream);
                        let client_clone = Arc::clone(&client);

                        tokio::task::spawn(async move {
                            if let Err(err) = http1::Builder::new()
                                .preserve_header_case(true)
                                .title_case_headers(true)
                                .serve_connection(io, service_fn(move |req| {
                                    Self::handle_request(req, Arc::clone(&client_clone))
                                }))
                                .with_upgrades()
                                .await
                            {
                                eprintln!("Failed to serve connection: {:?}", err);
                            }
                        });
                    }
                    _ = &mut shutdown_rx => {
                        println!("Proxy listener shutting down.");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            port,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    async fn handle_request(
        mut req: Request<Incoming>,
        client: Arc<Client>,
    ) -> Result<Response<rquest::Body>, std::convert::Infallible> {
        if Method::CONNECT == req.method() {
            let target_host = req.uri().host().unwrap_or("").to_string();

            tokio::task::spawn(async move {
                match hyper::upgrade::on(&mut req).await {
                    Ok(upgraded) => {
                        let _ = Self::handle_tunnel(upgraded, target_host, client).await;
                    }
                    Err(e) => eprintln!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(rquest::Body::from("")))
        } else {
            let hyper_uri = req.uri().to_string();
            let method = req.method().clone();

            // Build outbound request
            let mut req_builder = client.request(
                rquest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
                hyper_uri,
            );

            for (key, value) in req.headers() {
                req_builder = req_builder.header(key.as_str(), value.as_bytes());
            }

            // Read incoming body bytes
            let body_bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => bytes::Bytes::new(),
            };
            req_builder = req_builder.body(rquest::Body::from(body_bytes));

            let response = match req_builder.send().await {
                Ok(resp) => resp,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(502)
                        .body(rquest::Body::from(""))
                        .unwrap());
                }
            };

            let mut builder = Response::builder().status(response.status().as_u16());

            for (key, value) in response.headers() {
                builder = builder.header(key.as_str(), value.as_bytes());
            }

            let resp_bytes = response.bytes().await.unwrap_or_default();
            Ok(builder.body(rquest::Body::from(resp_bytes)).unwrap())
        }
    }

    async fn handle_tunnel(
        upgraded: Upgraded,
        target_host: String,
        client: Arc<Client>,
    ) -> Result<(), Error> {
        let subject_alt_names = vec![target_host.clone()];

        // Spawn blocking for CPU-bound cert generation
        let cert =
            tokio::task::spawn_blocking(move || generate_simple_self_signed(subject_alt_names))
                .await
                .map_err(|e| Error::Internal(anyhow::anyhow!("Join error: {}", e)))?
                .map_err(|e| Error::Internal(anyhow::anyhow!("Cert generation error: {}", e)))?;

        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        let single_cert = CertificateDer::from(cert_der);
        let private_key = PrivatePkcs8KeyDer::from(key_der).into();

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![single_cert], private_key)
            .map_err(|e| Error::Internal(anyhow::anyhow!("TLS config error: {}", e)))?;

        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(config));

        let io = TokioIo::new(upgraded);
        let tls_stream = acceptor
            .accept(io)
            .await
            .map_err(|e| Error::Internal(anyhow::anyhow!("TLS Accept error: {}", e)))?;

        let tls_io = TokioIo::new(tls_stream);

        if let Err(err) = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(
                tls_io,
                service_fn(move |inner_req| {
                    let host = target_host.clone();
                    let client_ref = Arc::clone(&client);
                    async move { Self::forward_tls_request(inner_req, host, client_ref).await }
                }),
            )
            .await
        {
            eprintln!("TLS Proxy connection failed: {:?}", err);
        }

        Ok(())
    }

    async fn forward_tls_request(
        req: Request<Incoming>,
        host: String,
        client: Arc<Client>,
    ) -> Result<Response<rquest::Body>, std::convert::Infallible> {
        let uri = format!(
            "https://{}{}",
            host,
            req.uri()
                .path_and_query()
                .map(|x| x.as_str())
                .unwrap_or("/")
        );

        let mut req_builder = client.request(
            rquest::Method::from_bytes(req.method().as_str().as_bytes()).unwrap(),
            uri,
        );

        for (key, value) in req.headers() {
            if key != "host" {
                req_builder = req_builder.header(key.as_str(), value.as_bytes());
            }
        }

        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => bytes::Bytes::new(),
        };
        req_builder = req_builder.body(rquest::Body::from(body_bytes));

        match req_builder.send().await {
            Ok(resp) => {
                let mut hyper_res = Response::builder().status(resp.status().as_u16());
                for (key, value) in resp.headers() {
                    hyper_res = hyper_res.header(key.as_str(), value.as_bytes());
                }
                let resp_bytes = resp.bytes().await.unwrap_or_default();
                Ok(hyper_res.body(rquest::Body::from(resp_bytes)).unwrap())
            }
            Err(_) => Ok(Response::builder()
                .status(502)
                .body(rquest::Body::from(""))
                .unwrap()),
        }
    }
}
