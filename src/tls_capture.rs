//! Passive capture of the `ClientHello` at the start of a MITM tunnel.
//!
//! The MITM proxy terminates the browser's TLS, which means the browser's real
//! `ClientHello` passes through this process. Recording it turns the proxy into
//! a fingerprint observatory: point any browser at the proxy and read off the
//! JA4 it actually emits, rather than trusting a hand-maintained table.
//!
//! Capture is opt-in and passive. [`CapturingStream`] tees the first record out
//! of the read path as the TLS acceptor consumes it, so the handshake is never
//! pre-read, delayed, or otherwise perturbed.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ja4::{ClientHello, Ja4, Transport};

/// Bytes in a TLS record header (type, version, length).
const RECORD_HEADER_LEN: usize = 5;

/// Cap on buffered handshake bytes.
///
/// A `ClientHello` is a few kilobytes at most; this bounds memory if a peer
/// declares a large record and then stalls.
const MAX_CAPTURE_BYTES: usize = 16 * 1024;

/// Receives the `ClientHello` observed at the start of each intercepted tunnel.
///
/// Implementations must not block: they are called from the connection's task,
/// on the handshake path.
pub trait ClientHelloObserver: Send + Sync {
    /// Called once per tunnel with the target host and the raw hello bytes.
    ///
    /// `client_hello` is exactly what the peer sent, GREASE and all.
    fn observe(&self, host: &str, client_hello: &[u8]);
}

/// An observer that parses each hello and reports its JA4 via [`log`].
///
/// This is the batteries-included way to discover a browser's real fingerprint:
/// attach it, browse, and read the JA4 out of the logs.
pub struct LogJa4Observer;

impl ClientHelloObserver for LogJa4Observer {
    fn observe(&self, host: &str, client_hello: &[u8]) {
        match ClientHello::parse(client_hello) {
            Ok(hello) => {
                let ja4 = Ja4::from_client_hello(&hello, Transport::Tcp);
                log::info!("observed JA4 for {host}: {ja4}");
            }
            Err(err) => {
                log::debug!("could not fingerprint ClientHello for {host}: {err}");
            }
        }
    }
}

/// An observer that retains the most recent hello, for tests and tooling.
#[derive(Default)]
pub struct RecordingObserver {
    captured: Mutex<Vec<(String, Vec<u8>)>>,
}

impl RecordingObserver {
    /// Creates an empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every `(host, client_hello)` pair observed so far.
    pub fn captured(&self) -> Vec<(String, Vec<u8>)> {
        self.captured.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// Returns the JA4 of the most recently observed hello, if it parsed.
    pub fn latest_ja4(&self) -> Option<Ja4> {
        let captured = self.captured.lock().ok()?;
        let (_, bytes) = captured.last()?;
        let hello = ClientHello::parse(bytes).ok()?;
        Some(Ja4::from_client_hello(&hello, Transport::Tcp))
    }
}

impl ClientHelloObserver for RecordingObserver {
    fn observe(&self, host: &str, client_hello: &[u8]) {
        // A poisoned lock must not take down the tunnel; drop the sample.
        if let Ok(mut captured) = self.captured.lock() {
            captured.push((host.to_string(), client_hello.to_vec()));
        }
    }
}

/// Accumulates the first TLS record seen on a stream.
#[derive(Default)]
struct Capture {
    buf: Vec<u8>,
    done: bool,
}

impl Capture {
    /// Absorbs freshly read bytes, returning the hello once it is complete.
    fn push(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        if self.done {
            return None;
        }
        self.buf.extend_from_slice(bytes);

        if self.buf.len() < RECORD_HEADER_LEN {
            return None;
        }

        let declared = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
        let total = declared.saturating_add(RECORD_HEADER_LEN);

        if self.buf.len() >= total || self.buf.len() >= MAX_CAPTURE_BYTES {
            self.done = true;
            // Hand back exactly the record, not the trailing bytes of whatever
            // the peer pipelined behind it.
            let end = total.min(self.buf.len());
            return Some(self.buf[..end].to_vec());
        }

        None
    }
}

/// Wraps a stream and tees its opening TLS record to an observer.
///
/// Reads are forwarded verbatim; the capture is a side effect, so the wrapped
/// TLS implementation sees an unmodified byte stream.
pub struct CapturingStream<S> {
    inner: S,
    host: String,
    /// `None` disables capture entirely, making this a plain passthrough so the
    /// proxy can wrap unconditionally without paying for unused observation.
    observer: Option<Arc<dyn ClientHelloObserver>>,
    capture: Capture,
}

impl<S> CapturingStream<S> {
    /// Wraps `inner`, reporting the first record for `host` to `observer`.
    ///
    /// A `None` observer makes this a transparent passthrough.
    pub fn new(
        inner: S,
        host: impl Into<String>,
        observer: Option<Arc<dyn ClientHelloObserver>>,
    ) -> Self {
        Self {
            inner,
            host: host.into(),
            observer,
            capture: Capture::default(),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CapturingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `Self: Unpin` whenever `S: Unpin`, so a plain mutable borrow is sound
        // here without any pin projection.
        let this = self.get_mut();

        // Fast path: with no observer there is nothing to record, so skip the
        // bookkeeping entirely rather than buffering bytes nobody reads.
        let Some(observer) = this.observer.as_ref() else {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        };

        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &result {
            let fresh = &buf.filled()[before..];
            if !fresh.is_empty()
                && let Some(hello) = this.capture.push(fresh)
            {
                observer.observe(&this.host, &hello);
            }
        }

        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CapturingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// A minimal record: handshake type, version, length, then `len` bytes.
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x16, 0x03, 0x01];
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[tokio::test]
    async fn captures_a_record_delivered_in_one_read() {
        let bytes = record(&[0xaa; 64]);
        let observer = Arc::new(RecordingObserver::new());
        let mut stream = CapturingStream::new(
            &bytes[..],
            "example.com",
            Some(observer.clone() as Arc<dyn ClientHelloObserver>),
        );

        let mut sink = Vec::new();
        stream.read_to_end(&mut sink).await.expect("read");

        // The stream must forward every byte untouched...
        assert_eq!(sink, bytes);
        // ...and still have observed the record.
        let captured = observer.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].0, "example.com");
        assert_eq!(captured[0].1, bytes);
    }

    #[tokio::test]
    async fn reassembles_a_record_split_across_reads() {
        // A browser's hello routinely spans several reads; capturing only the
        // first chunk would yield a truncated, unparseable fingerprint.
        let bytes = record(&[0xbb; 4000]);
        let (mut client, server) = tokio::io::duplex(64);

        let observer = Arc::new(RecordingObserver::new());
        let mut stream = CapturingStream::new(
            server,
            "split.example",
            Some(observer.clone() as Arc<dyn ClientHelloObserver>),
        );

        let to_send = bytes.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&to_send).await.expect("write");
            client.shutdown().await.expect("shutdown");
        });

        let mut sink = Vec::new();
        stream.read_to_end(&mut sink).await.expect("read");

        assert_eq!(sink, bytes, "forwarded bytes were altered");
        assert_eq!(observer.captured()[0].1, bytes, "record not reassembled");
    }

    #[tokio::test]
    async fn observes_only_the_first_record() {
        // Application data follows the handshake; only the hello is of interest.
        let hello = record(&[0xcc; 32]);
        let mut bytes = hello.clone();
        bytes.extend_from_slice(&record(&[0xdd; 32]));

        let observer = Arc::new(RecordingObserver::new());
        let mut stream = CapturingStream::new(
            &bytes[..],
            "once.example",
            Some(observer.clone() as Arc<dyn ClientHelloObserver>),
        );

        let mut sink = Vec::new();
        stream.read_to_end(&mut sink).await.expect("read");

        let captured = observer.captured();
        assert_eq!(captured.len(), 1, "observer fired more than once");
        assert_eq!(captured[0].1, hello, "capture bled into the next record");
    }

    #[tokio::test]
    async fn a_short_stream_never_fires_the_observer() {
        // Fewer bytes than a record header: nothing to fingerprint.
        let observer = Arc::new(RecordingObserver::new());
        let mut stream = CapturingStream::new(
            &[0x16, 0x03][..],
            "short.example",
            Some(observer.clone() as Arc<dyn ClientHelloObserver>),
        );

        let mut sink = Vec::new();
        stream.read_to_end(&mut sink).await.expect("read");

        assert!(observer.captured().is_empty());
        assert!(observer.latest_ja4().is_none());
    }
}
