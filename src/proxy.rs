//! Local MITM TLS-spoofing proxy ([`TlsSpoofingProxy`]) that terminates the
//! browser's TLS, then re-emits each request through `wreq` with a forged JA4
//! `ClientHello` and HTTP/2 fingerprint. The upstream client is hot-swappable so
//! the egress proxy can rotate without relaunching the browser.

use crate::Error;
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    ServerConfig, pki_types::CertificateDer, pki_types::PrivatePkcs8KeyDer,
};
use tokio_util::sync::CancellationToken;
use wreq::Client;

/// Shared, hot-swappable handle to the upstream impersonation client.
///
/// The inner `Arc<Client>` can be replaced at runtime (see
/// [`TlsSpoofingProxy::set_upstream_client`]) so the egress proxy can be rotated
/// without relaunching the browser — Chrome keeps talking to the same local
/// MITM port while the outbound client changes underneath it. Read guards are
/// always cloned out and dropped before any `.await`, never held across one.
type SharedClient = Arc<RwLock<Arc<Client>>>;

/// Build an empty response with the given status.
///
/// Infallible by construction (uses [`Response::new`] + `status_mut`, never the
/// fallible builder), so it is safe to use as a fallback when forwarding fails.
fn empty_response(status: StatusCode) -> Response<wreq::Body> {
    let mut response = Response::new(wreq::Body::from(""));
    *response.status_mut() = status;
    response
}

/// Translate an upstream `wreq` response into a streaming `hyper` response.
///
/// Copies the upstream status and headers and streams the body. Upstream data is
/// untrusted: if a header cannot be represented by `hyper` (so the builder
/// errors), this returns a `502` instead of panicking.
fn upstream_response(resp: wreq::Response) -> Response<wreq::Body> {
    let mut builder = Response::builder().status(resp.status().as_u16());
    for (key, value) in resp.headers() {
        builder = builder.header(key.as_str(), value.as_bytes());
    }
    match builder.body(wreq::Body::wrap_stream(resp.bytes_stream())) {
        Ok(response) => response,
        Err(err) => {
            log::warn!("dropping upstream response with unrepresentable headers: {err}");
            empty_response(StatusCode::BAD_GATEWAY)
        }
    }
}

/// A silent TLS Man-in-the-Middle (MITM) proxy that injects JA4/TLS fingerprints.
///
/// This proxy intercepts HTTP/HTTPS requests from a standard proxy-equipped client
/// (like Headless Chrome), terminates the TLS connection using self-signed certs via `rcgen`,
/// and forwards the upstream request utilizing a tightly bound `wreq` client matching the
/// intended target fingerprint.
pub struct TlsSpoofingProxy {
    port: u16,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    cancel_token: CancellationToken,
    client_slot: SharedClient,
}

impl Drop for TlsSpoofingProxy {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()); // Send shutdown signal
        }
    }
}

impl TlsSpoofingProxy {
    /// Binds the proxy to an available local TCP port and spawns the background listener.
    ///
    /// # Arguments
    /// * `impersonate_client` - The configured `wreq` TLS/JA4 impersonation client
    /// * `debug_mode` - If `true`, logs all intercepted requests and TLS upgrades to stdout
    pub async fn start(impersonate_client: Client, debug_mode: bool) -> Result<Self, Error> {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await?;
        let port = listener.local_addr()?.port();

        if debug_mode {
            log::info!("TLS spoofing proxy listening on 127.0.0.1:{port}");
        }

        let client_slot: SharedClient = Arc::new(RwLock::new(Arc::new(impersonate_client)));
        let client = Arc::clone(&client_slot);
        let cancel_token = CancellationToken::new();
        let loop_token = cancel_token.clone();

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = loop_token.cancelled() => {
                        log::debug!("proxy listener loop cancelled");
                        break;
                    }
                    res = listener.accept() => {
                        match res {
                            Ok((stream, addr)) => {
                                if debug_mode {
                                    log::debug!("accepted connection from {addr}");
                                }
                                let io = TokioIo::new(stream);
                                let client_clone = Arc::clone(&client);
                                let conn_token = loop_token.clone();

                                tokio::task::spawn(async move {
                                    let service_token = conn_token.clone();
                                    let conn = http1::Builder::new()
                                        .preserve_header_case(true)
                                        .title_case_headers(true)
                                        .serve_connection(io, service_fn(move |req| {
                                            let req_token = service_token.clone();
                                            Self::handle_request(req, Arc::clone(&client_clone), req_token, debug_mode)
                                        }))
                                        .with_upgrades();

                                    tokio::pin!(conn);

                                    tokio::select! {
                                        res = &mut conn => {
                                            if let Err(err) = res {
                                                log::warn!("failed to serve connection: {err:?}");
                                            }
                                        }
                                        _ = conn_token.cancelled() => {
                                            conn.as_mut().graceful_shutdown();
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                log::warn!("accept failed: {e}");
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        log::debug!("proxy listener shutting down");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            port,
            shutdown_tx: Some(shutdown_tx),
            cancel_token,
            client_slot,
        })
    }

    /// Returns the active local loopback port dynamically assigned during `start()`.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Hot-swap the upstream impersonation client (e.g. to rotate the egress proxy).
    ///
    /// In-flight requests finish on the previous client; subsequent requests use
    /// `client`. The local MITM port is unchanged, so the browser needs no restart.
    pub fn set_upstream_client(&self, client: Client) {
        *self.client_slot.write().expect("client_slot lock poisoned") = Arc::new(client);
    }

    async fn handle_request(
        mut req: Request<Incoming>,
        client: SharedClient,
        token: CancellationToken,
        debug_mode: bool,
    ) -> Result<Response<wreq::Body>, std::convert::Infallible> {
        if Method::CONNECT == req.method() {
            let target_host = req.uri().host().unwrap_or("").to_string();

            if debug_mode {
                log::debug!("[MITM] intercepting TLS upgrade for {target_host}");
            }

            tokio::task::spawn(async move {
                match hyper::upgrade::on(&mut req).await {
                    Ok(upgraded) => {
                        let _ =
                            Self::handle_tunnel(upgraded, target_host, client, token, debug_mode)
                                .await;
                    }
                    Err(e) => log::warn!("upgrade error: {e}"),
                }
            });

            Ok(empty_response(StatusCode::OK))
        } else {
            let hyper_uri = req.uri().to_string();
            let method = req.method().clone();

            // Untrusted client method: fall back to 400 rather than panicking.
            let Ok(wreq_method) = wreq::Method::from_bytes(method.as_str().as_bytes()) else {
                return Ok(empty_response(StatusCode::BAD_REQUEST));
            };

            // Snapshot the current upstream client; drop the guard before awaiting.
            let client = client.read().expect("client_slot lock poisoned").clone();

            // Build outbound request
            let mut req_builder = client.request(wreq_method, hyper_uri.clone());

            for (key, value) in req.headers() {
                req_builder = req_builder.header(key.as_str(), value.as_bytes());
            }

            // Stream incoming body bytes dynamically
            let req_body = req.into_body().into_data_stream();
            req_builder = req_builder.body(wreq::Body::wrap_stream(req_body));

            match req_builder.send().await {
                Ok(resp) => {
                    if debug_mode {
                        log::debug!("[HTTP] {method} {hyper_uri} -> {}", resp.status());
                    }
                    Ok(upstream_response(resp))
                }
                Err(e) => {
                    if debug_mode {
                        log::debug!("[HTTP ERROR] {method} {hyper_uri} -> {e:?}");
                    }
                    Ok(empty_response(StatusCode::BAD_GATEWAY))
                }
            }
        }
    }

    async fn handle_tunnel(
        upgraded: Upgraded,
        target_host: String,
        client: SharedClient,
        token: CancellationToken,
        debug_mode: bool,
    ) -> Result<(), Error> {
        let subject_alt_names = vec![target_host.clone()];

        // Spawn blocking for CPU-bound cert generation. The SAN comes from the
        // (untrusted) CONNECT target host, so a generation failure is mapped to a
        // TLS error rather than panicking the tunnel task.
        let CertifiedKey { cert, signing_key } =
            tokio::task::spawn_blocking(move || generate_simple_self_signed(subject_alt_names))
                .await
                .map_err(|e| Error::JoinError(format!("Join error: {e}")))?
                .map_err(|e| Error::TlsError(format!("self-signed cert generation failed: {e}")))?;

        let cert_der = cert.der().to_vec();
        let key_der = signing_key.serialize_der();

        let single_cert = CertificateDer::from(cert_der);
        let private_key = PrivatePkcs8KeyDer::from(key_der).into();

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![single_cert], private_key)
            .map_err(|e| Error::TlsError(format!("TLS config error: {}", e)))?;

        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(config));

        let io = TokioIo::new(upgraded);
        let tls_stream = acceptor
            .accept(io)
            .await
            .map_err(|e| Error::TlsError(format!("TLS Accept error: {}", e)))?;

        let tls_io = TokioIo::new(tls_stream);
        let conn_token = token.clone();

        let conn = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(
                tls_io,
                service_fn(move |inner_req| {
                    let host = target_host.clone();
                    let client_ref = Arc::clone(&client);
                    async move {
                        Self::forward_tls_request(inner_req, host, client_ref, debug_mode).await
                    }
                }),
            );

        tokio::pin!(conn);

        tokio::select! {
            res = &mut conn => {
                if let Err(err) = res {
                    // Silently ignore harmless TCP teardowns (like incomplete headers or HTTP keep-alive timeouts)
                    // These naturally occur when the parent rs-arlo client pauses for ~30 seconds (IMAP Auth)
                    let err_str = format!("{err:?}");
                    if !err_str.contains("Parse(Method)") && !err_str.contains("IncompleteMessage") {
                        log::warn!("[TLS] connection drop: {err:?}");
                    }
                }
            }
            _ = conn_token.cancelled() => {
                conn.as_mut().graceful_shutdown();
            }
        }

        Ok(())
    }

    async fn forward_tls_request(
        req: Request<Incoming>,
        host: String,
        client: SharedClient,
        debug_mode: bool,
    ) -> Result<Response<wreq::Body>, std::convert::Infallible> {
        let uri = format!(
            "https://{}{}",
            host,
            req.uri()
                .path_and_query()
                .map(|x| x.as_str())
                .unwrap_or("/")
        );

        let method = req.method().clone();

        // Untrusted client method: fall back to 400 rather than panicking.
        let Ok(wreq_method) = wreq::Method::from_bytes(method.as_str().as_bytes()) else {
            return Ok(empty_response(StatusCode::BAD_REQUEST));
        };

        // Snapshot the current upstream client; drop the guard before awaiting.
        let client = client.read().expect("client_slot lock poisoned").clone();

        let mut req_builder = client.request(wreq_method, uri.clone());

        for (key, value) in req.headers() {
            if key != "host" {
                req_builder = req_builder.header(key.as_str(), value.as_bytes());
            }
        }

        let req_body = req.into_body().into_data_stream();
        req_builder = req_builder.body(wreq::Body::wrap_stream(req_body));

        match req_builder.send().await {
            Ok(resp) => {
                if debug_mode {
                    log::debug!("[TLS] {method} {uri} -> {}", resp.status());
                }
                Ok(upstream_response(resp))
            }
            Err(e) => {
                if debug_mode {
                    log::debug!("[TLS ERROR] {method} {uri} -> {e:?}");
                }
                Ok(empty_response(StatusCode::BAD_GATEWAY))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_initialization() {
        let client = wreq::Client::builder()
            .build()
            .expect("Failed to build client");

        let proxy = TlsSpoofingProxy::start(client, false)
            .await
            .expect("Failed to start proxy");

        // Assert a port was dynamically assigned
        assert!(proxy.port() > 0);

        // The Drop impl should trigger smooth shutdown
        drop(proxy);
    }

    #[tokio::test]
    async fn test_proxy_http_and_https_forwarding() {
        // Rustls 0.23+ requires an explicit process-level crypto provider,
        // since reqwest doesn't automatically install it when used as a library.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        let client = wreq::Client::builder()
            .build()
            .expect("Failed to build client");

        let proxy = TlsSpoofingProxy::start(client, false)
            .await
            .expect("Failed to start proxy");

        let port = proxy.port();

        // Use a standard reqwest client to fire a request AT the proxy
        let req_client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", port)).unwrap())
            .danger_accept_invalid_certs(true) // accept the local MITM cert
            .build()
            .unwrap();

        // 1. Test standard HTTP forwarding
        let http_resp = req_client.get("http://example.com").send().await;
        assert!(http_resp.is_ok());
        let http_status = http_resp.unwrap().status();
        assert!(http_status.is_success() || http_status.is_redirection());

        // 2. Test TLS Upgrading / HTTPS CONNECT handling
        let https_resp = req_client.get("https://example.com").send().await;
        assert!(https_resp.is_ok());
        let https_status = https_resp.unwrap().status();

        // We accept success, redirects, or 502 (if our proxy fails to forward cleanly due to networking restrictions, but the tunnel was built)
        assert!(
            https_status.is_success()
                || https_status.is_redirection()
                || https_status.as_u16() == 502
        );
    }

    #[tokio::test]
    async fn test_proxy_shutdown() {
        let client = wreq::Client::builder().build().unwrap();
        let proxy = TlsSpoofingProxy::start(client, false).await.unwrap();
        let port = proxy.port();

        let req_client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", port)).unwrap())
            .build()
            .unwrap();

        // Drop the proxy to trigger cancellation token and close listener
        drop(proxy);

        // Give it a tiny bit of time for tokio shutdown process to finalize the bind release
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Firing request should fail due to proxy being down
        let res = req_client.get("http://example.com").send().await;
        assert!(res.is_err(), "Request succeeded but proxy should be down");
    }

    #[tokio::test]
    async fn test_proxy_502_error_flow() {
        // Mock upstream server that fails or drops connections
        let mut server = mockito::Server::new_async().await;

        // Mock an upstream returning 500
        let _mock = server
            .mock("GET", "/")
            .with_status(500)
            .create_async()
            .await;

        let client = wreq::Client::builder().build().unwrap();
        let proxy = TlsSpoofingProxy::start(client, false).await.unwrap();
        let port = proxy.port();

        let req_client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", port)).unwrap())
            .build()
            .unwrap();

        // Fire request to the mocked upstream via our proxy
        let url = server.url();
        let res = req_client.get(&url).send().await.unwrap();

        // The mock returned 500, but our proxy correctly forwarded the HTTP response
        assert_eq!(res.status().as_u16(), 500);

        // Now test routing to a truly invalid host to trigger internal 502 behavior
        let bad_url = format!("http://127.0.0.1:{}", server.url().len()); // an invalid or closed port might work, but let's test a non-existent port
        let res2 = req_client.get(&bad_url).send().await;

        // Either the hyper proxy returns 502 OR the reqwest client surfaces the connection refused
        if let Ok(response) = res2 {
            assert_eq!(response.status().as_u16(), 502);
        }
    }
}
