//! The CDP wire: NUL-delimited JSON over the browser's pipe, demultiplexed.
//!
//! A single stream carries three interleaved things: replies to our commands,
//! replies to commands issued from other tasks, and unsolicited events. Reading
//! "the next message" after sending a command is therefore wrong — it will
//! sooner or later return someone else's reply, and the mistake is
//! timing-dependent, so it survives testing and fails in production.
//!
//! This module removes the possibility. One task owns the read side and routes
//! every message by shape:
//!
//! - a message with an `id` resolves the [`oneshot`] registered for that id,
//! - anything else is an event, published on a [`broadcast`] channel.
//!
//! Callers only ever await their own reply, so any number of tasks can share
//! one browser without coordinating. The whole path is async: no thread per
//! tab, and no `spawn_blocking` imposed on callers.
//!
//! # Shutdown
//!
//! When the browser exits, the read side reaches end-of-file. The reader task
//! then fails every pending call with the reason, and records it so later calls
//! fail immediately rather than waiting for a reply that cannot arrive.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::pipe;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

use super::launch::LaunchedBrowser;
use crate::Error;

/// CDP frames its JSON messages by terminating each with a NUL byte.
const MESSAGE_DELIMITER: u8 = 0;

/// How long a command waits for its reply before giving up.
///
/// A CDP call can legitimately take seconds (a navigation, a slow evaluation),
/// but never minutes; without a bound a lost reply would hang a caller
/// permanently.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// How many events are buffered for a receiver that is not keeping up.
///
/// A slow consumer loses the oldest events rather than stalling the reader
/// task, which must keep draining the pipe or the browser blocks on its write.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// An unsolicited message from the browser.
#[derive(Debug, Clone)]
pub struct CdpEvent {
    /// The event name, for example `Page.loadEventFired`.
    pub method: String,
    /// The event payload, or `Value::Null` when it carried none.
    pub params: Value,
    /// The session the event belongs to, absent for browser-level events.
    pub session_id: Option<String>,
}

/// State shared between the reader task and the handles that issue commands.
///
/// Held behind its own `Arc` rather than inside the transport, so the reader
/// task can reach it without a reference cycle through its own `JoinHandle`.
#[derive(Debug)]
struct Shared {
    pending: Mutex<Pending>,
    events: broadcast::Sender<CdpEvent>,
}

/// Calls awaiting a reply, and why no further reply can arrive.
#[derive(Debug, Default)]
struct Pending {
    waiting: HashMap<u64, oneshot::Sender<Result<Value, Error>>>,
    /// Set once the stream ends; every later call fails with this reason.
    closed: Option<String>,
}

impl Shared {
    /// Routes one decoded message to its waiting call, or to the event stream.
    fn dispatch(&self, message: Value) {
        if let Some(id) = message.get("id").and_then(Value::as_u64) {
            let Some(reply) = self.take_waiter(id) else {
                // A reply to a call that timed out or whose caller went away.
                log::debug!("CDP reply {id} arrived with nobody waiting for it");
                return;
            };
            let _ = reply.send(parse_reply(&message));
            return;
        }

        let Some(method) = message.get("method").and_then(Value::as_str) else {
            log::debug!("ignoring a CDP message with neither an id nor a method");
            return;
        };

        // `send` fails only when nothing is subscribed, which is normal.
        let _ = self.events.send(CdpEvent {
            method: method.to_string(),
            params: message.get("params").cloned().unwrap_or(Value::Null),
            session_id: message
                .get("sessionId")
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    }

    fn take_waiter(&self, id: u64) -> Option<oneshot::Sender<Result<Value, Error>>> {
        self.lock().waiting.remove(&id)
    }

    /// Marks the connection dead and fails everything still waiting.
    fn close(&self, reason: String) {
        let mut pending = self.lock();
        pending.closed.get_or_insert_with(|| reason.clone());
        for (_, reply) in pending.waiting.drain() {
            let _ = reply.send(Err(Error::BrowserError(reason.clone())));
        }
    }

    /// The pending map is never locked across an await, so a poisoned lock can
    /// only mean a panic inside this module; recovering keeps a panic in one
    /// call from wedging every other one.
    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Turns a CDP reply into the `result` object or an actionable error.
fn parse_reply(message: &Value) -> Result<Value, Error> {
    if let Some(error) = message.get("error") {
        return Err(Error::Cdp {
            code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unspecified protocol error")
                .to_string(),
            data: error
                .get("data")
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    }
    Ok(message.get("result").cloned().unwrap_or(Value::Null))
}

/// Owns the browser, the write side and the reader task.
#[derive(Debug)]
struct Inner {
    /// Serialises writes so two concurrent calls cannot interleave bytes
    /// within a frame.
    writer: tokio::sync::Mutex<pipe::Sender>,
    shared: Arc<Shared>,
    next_id: AtomicU64,
    call_timeout: Duration,
    reader: JoinHandle<()>,
    /// Present when this transport launched the browser, so dropping the
    /// transport also terminates it.
    browser: Mutex<Option<LaunchedBrowser>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // The reader is parked on a pipe that may never close by itself (the
        // browser could outlive us if the caller kept it), so stop it rather
        // than leaking a task.
        self.reader.abort();
    }
}

/// An async CDP connection, shareable by cloning.
///
/// Cloning is cheap and gives another handle onto the same browser; the
/// connection closes when the last handle is dropped.
#[derive(Debug, Clone)]
pub struct CdpTransport {
    inner: Arc<Inner>,
}

impl CdpTransport {
    /// Adopts a launched browser's pipes and starts serving CDP on them.
    ///
    /// Must be called from within a Tokio runtime: it takes over the
    /// descriptors in non-blocking mode and spawns the reader task.
    pub fn connect(mut browser: LaunchedBrowser) -> Result<Self, Error> {
        let (from_browser, to_browser) = browser.take_pipes()?;
        Self::from_pipes(
            from_browser,
            to_browser,
            Some(browser),
            DEFAULT_CALL_TIMEOUT,
        )
    }

    /// The browser's process id, when this transport owns one.
    pub fn browser_id(&self) -> Option<u32> {
        self.inner
            .browser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(LaunchedBrowser::id)
    }

    /// Subscribes to events from this point on.
    ///
    /// Events emitted before the call are not replayed, so a subscription must
    /// be taken before the command that provokes the event.
    pub fn events(&self) -> broadcast::Receiver<CdpEvent> {
        self.inner.shared.events.subscribe()
    }

    /// Calls a browser-level method.
    pub async fn call(&self, method: &str, params: Option<Value>) -> Result<Value, Error> {
        self.call_in_session(None, method, params).await
    }

    /// Calls a method, optionally within an attached target's session.
    ///
    /// `session_id` selects a target in flat mode; `None` addresses the browser
    /// itself.
    pub async fn call_in_session(
        &self,
        session_id: Option<&str>,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, Error> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);

        let mut request = json!({ "id": id, "method": method });
        // CDP rejects a null `params` or `sessionId`, so absent means omitted.
        if let Some(params) = params {
            request["params"] = params;
        }
        if let Some(session_id) = session_id {
            request["sessionId"] = Value::String(session_id.to_string());
        }

        let receiver = self.register(id, method)?;
        self.write_frame(&request, method).await.inspect_err(|_| {
            // Nothing will ever answer this id, so do not leave it pending.
            let _ = self.inner.shared.take_waiter(id);
        })?;

        match tokio::time::timeout(self.inner.call_timeout, receiver).await {
            Ok(Ok(result)) => result,
            // The reader task dropped the sender without answering.
            Ok(Err(_)) => Err(Error::BrowserError(format!(
                "the CDP connection closed while waiting for {method}"
            ))),
            Err(_) => {
                let _ = self.inner.shared.take_waiter(id);
                Err(Error::BrowserError(format!(
                    "{method} timed out after {:?}",
                    self.inner.call_timeout
                )))
            }
        }
    }

    /// Registers a slot for `id`'s reply, unless the connection is already dead.
    fn register(
        &self,
        id: u64,
        method: &str,
    ) -> Result<oneshot::Receiver<Result<Value, Error>>, Error> {
        let (sender, receiver) = oneshot::channel();
        let mut pending = self.inner.shared.lock();
        if let Some(reason) = &pending.closed {
            return Err(Error::BrowserError(format!(
                "cannot call {method}: {reason}"
            )));
        }
        pending.waiting.insert(id, sender);
        Ok(receiver)
    }

    async fn write_frame(&self, request: &Value, method: &str) -> Result<(), Error> {
        let mut frame = serde_json::to_vec(request)
            .map_err(|e| Error::BrowserError(format!("could not encode {method}: {e}")))?;
        frame.push(MESSAGE_DELIMITER);

        let mut writer = self.inner.writer.lock().await;
        writer
            .write_all(&frame)
            .await
            .map_err(|e| Error::BrowserError(format!("could not send {method}: {e}")))?;
        writer
            .flush()
            .await
            .map_err(|e| Error::BrowserError(format!("could not flush {method}: {e}")))
    }

    /// The constructor both [`connect`](Self::connect) and the tests use.
    ///
    /// Taking the raw pipes keeps the transport testable against a scripted
    /// peer, with no browser involved.
    fn from_pipes(
        from_browser: std::io::PipeReader,
        to_browser: std::io::PipeWriter,
        browser: Option<LaunchedBrowser>,
        call_timeout: Duration,
    ) -> Result<Self, Error> {
        use std::os::fd::OwnedFd;

        let reader = pipe::Receiver::from_owned_fd(OwnedFd::from(from_browser))
            .map_err(|e| Error::BrowserError(format!("could not adopt the CDP read pipe: {e}")))?;
        let writer = pipe::Sender::from_owned_fd(OwnedFd::from(to_browser))
            .map_err(|e| Error::BrowserError(format!("could not adopt the CDP write pipe: {e}")))?;

        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let shared = Arc::new(Shared {
            pending: Mutex::new(Pending::default()),
            events,
        });

        let task_shared = Arc::clone(&shared);
        let reader = tokio::spawn(async move { read_loop(reader, task_shared).await });

        Ok(Self {
            inner: Arc::new(Inner {
                writer: tokio::sync::Mutex::new(writer),
                shared,
                // Starts at 1 because a CDP id of 0 is accepted but makes logs
                // ambiguous against an absent field.
                next_id: AtomicU64::new(1),
                call_timeout,
                reader,
                browser: Mutex::new(browser),
            }),
        })
    }
}

/// Reads frames until the browser goes away, dispatching each one.
async fn read_loop(reader: pipe::Receiver, shared: Arc<Shared>) {
    let mut reader = BufReader::new(reader);
    let mut frame = Vec::new();

    let reason = loop {
        frame.clear();
        match reader.read_until(MESSAGE_DELIMITER, &mut frame).await {
            Ok(0) => break "the browser closed the CDP connection".to_string(),
            Ok(_) => {}
            Err(e) => break format!("the CDP connection failed: {e}"),
        }

        // A frame without its terminator means the stream ended mid-message.
        if frame.last() != Some(&MESSAGE_DELIMITER) {
            break "the CDP connection ended mid-message".to_string();
        }
        frame.pop();

        match serde_json::from_slice::<Value>(&frame) {
            Ok(message) => shared.dispatch(message),
            // One unparseable frame is not a reason to tear down a working
            // connection; the pending call it belonged to will time out.
            Err(e) => log::warn!("ignoring an undecodable CDP message: {e}"),
        }
    };

    shared.close(reason);
}

/// A scripted stand-in for a browser, for testing everything above the wire.
///
/// Shared with the session layer, which needs to assert on exactly which CDP
/// methods reach the browser — most importantly the ones that must never be
/// sent at all.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::io::{Read, Write};

    /// The browser end of a CDP pipe, driven by the test.
    ///
    /// Its reads and writes are synchronous, which is why every test using it
    /// runs on a multi-threaded runtime: blocking the test thread on `recv`
    /// must not stop the transport's reader task from making progress.
    pub(crate) struct FakePeer {
        /// What the transport reads.
        to_transport: std::io::PipeWriter,
        /// What the transport writes.
        from_transport: std::io::PipeReader,
        /// Every method the transport has sent, in order.
        seen: Vec<String>,
    }

    impl FakePeer {
        /// Pushes a raw message to the transport.
        pub(crate) fn send(&mut self, message: &str) {
            self.to_transport
                .write_all(format!("{message}\0").as_bytes())
                .expect("write to transport");
            self.to_transport.flush().expect("flush");
        }

        /// Reads one frame the transport sent, recording its method.
        pub(crate) fn recv(&mut self) -> Value {
            let mut frame = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                match self.from_transport.read(&mut byte) {
                    Ok(1) if byte[0] == MESSAGE_DELIMITER => break,
                    Ok(1) => frame.push(byte[0]),
                    Ok(_) | Err(_) => panic!("the transport sent nothing"),
                }
            }
            let request: Value =
                serde_json::from_slice(&frame).expect("decode the transport's frame");
            if let Some(method) = request.get("method").and_then(Value::as_str) {
                self.seen.push(method.to_string());
            }
            request
        }

        /// Answers the next request, asserting it is `method`.
        ///
        /// Returns the request, so a test can inspect the parameters it carried.
        pub(crate) fn answer(&mut self, method: &str, result: Value) -> Value {
            let request = self.recv();
            assert_eq!(
                request["method"], method,
                "expected a {method} call, got {request}"
            );
            let id = request["id"].as_u64().expect("an id");
            self.send(&json!({ "id": id, "result": result }).to_string());
            request
        }

        /// Every method sent so far.
        pub(crate) fn methods(&self) -> &[String] {
            &self.seen
        }
    }

    /// A transport wired to a fake peer instead of a browser.
    pub(crate) fn connected(timeout: Duration) -> (CdpTransport, FakePeer) {
        let (transport_reads, peer_writes) = std::io::pipe().expect("pipe");
        let (peer_reads, transport_writes) = std::io::pipe().expect("pipe");
        let transport = CdpTransport::from_pipes(transport_reads, transport_writes, None, timeout)
            .expect("connect");
        (
            transport,
            FakePeer {
                to_transport: peer_writes,
                from_transport: peer_reads,
                seen: Vec::new(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::testing::connected;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_call_receives_its_own_reply() {
        let (transport, mut peer) = connected(DEFAULT_CALL_TIMEOUT);

        let call = tokio::spawn({
            let transport = transport.clone();
            async move { transport.call("Browser.getVersion", None).await }
        });

        let request = peer.recv();
        assert_eq!(request["method"], "Browser.getVersion");
        // An absent `params` must be omitted, not sent as null.
        assert!(request.get("params").is_none());
        let id = request["id"].as_u64().expect("an id");

        peer.send(&json!({ "id": id, "result": { "product": "Chrome/153" } }).to_string());

        let result = call.await.expect("join").expect("call");
        assert_eq!(result["product"], "Chrome/153");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replies_reach_their_own_caller_when_answered_out_of_order() {
        // The defect this transport exists to prevent: reading "the next
        // message" would hand the second caller the first one's reply.
        let (transport, mut peer) = connected(DEFAULT_CALL_TIMEOUT);

        let first = tokio::spawn({
            let transport = transport.clone();
            async move { transport.call("First", None).await }
        });
        let first_id = peer.recv()["id"].as_u64().expect("an id");

        let second = tokio::spawn({
            let transport = transport.clone();
            async move { transport.call("Second", None).await }
        });
        let second_id = peer.recv()["id"].as_u64().expect("an id");
        assert_ne!(first_id, second_id, "ids must be unique per call");

        // Answer in reverse, with an event in between for good measure.
        peer.send(&json!({ "id": second_id, "result": { "who": "second" } }).to_string());
        peer.send(&json!({ "method": "Page.loadEventFired", "params": {} }).to_string());
        peer.send(&json!({ "id": first_id, "result": { "who": "first" } }).to_string());

        assert_eq!(second.await.expect("join").expect("call")["who"], "second");
        assert_eq!(first.await.expect("join").expect("call")["who"], "first");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_are_published_rather_than_mistaken_for_replies() {
        let (transport, mut peer) = connected(DEFAULT_CALL_TIMEOUT);
        let mut events = transport.events();

        let call = tokio::spawn({
            let transport = transport.clone();
            async move {
                transport
                    .call("Page.navigate", Some(json!({ "url": "about:blank" })))
                    .await
            }
        });

        let request = peer.recv();
        assert_eq!(request["params"]["url"], "about:blank");
        let id = request["id"].as_u64().expect("an id");

        peer.send(
            &json!({
                "method": "Page.frameNavigated",
                "params": { "frame": { "id": "F1" } },
                "sessionId": "S1"
            })
            .to_string(),
        );
        peer.send(&json!({ "id": id, "result": {} }).to_string());

        let event = events.recv().await.expect("an event");
        assert_eq!(event.method, "Page.frameNavigated");
        assert_eq!(event.params["frame"]["id"], "F1");
        assert_eq!(event.session_id.as_deref(), Some("S1"));

        call.await.expect("join").expect("call");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_id_addresses_an_attached_target() {
        let (transport, mut peer) = connected(DEFAULT_CALL_TIMEOUT);

        let call = tokio::spawn({
            let transport = transport.clone();
            async move {
                transport
                    .call_in_session(Some("S1"), "Runtime.evaluate", None)
                    .await
            }
        });

        let request = peer.recv();
        assert_eq!(request["sessionId"], "S1");
        let id = request["id"].as_u64().expect("an id");
        peer.send(&json!({ "id": id, "result": {} }).to_string());
        call.await.expect("join").expect("call");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_protocol_error_is_reported_with_its_code() {
        let (transport, mut peer) = connected(DEFAULT_CALL_TIMEOUT);

        let call = tokio::spawn({
            let transport = transport.clone();
            async move { transport.call("Nope.doesNotExist", None).await }
        });

        let id = peer.recv()["id"].as_u64().expect("an id");
        peer.send(
            &json!({
                "id": id,
                "error": { "code": -32601, "message": "'Nope.doesNotExist' wasn't found" }
            })
            .to_string(),
        );

        match call.await.expect("join") {
            Err(Error::Cdp { code, message, .. }) => {
                assert_eq!(code, -32601);
                assert!(message.contains("wasn't found"));
            }
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_reply_times_out_instead_of_hanging() {
        let (transport, mut peer) = connected(Duration::from_millis(100));

        let call = tokio::spawn({
            let transport = transport.clone();
            async move { transport.call("Never.answered", None).await }
        });
        let _ = peer.recv();

        let err = call.await.expect("join").expect_err("should time out");
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_closed_connection_fails_pending_and_later_calls() {
        let (transport, peer) = connected(DEFAULT_CALL_TIMEOUT);

        let call = tokio::spawn({
            let transport = transport.clone();
            async move { transport.call("In.flight", None).await }
        });
        // Wait until the call is registered, then hang up on it.
        let mut peer = peer;
        let _ = peer.recv();
        drop(peer);

        let err = call.await.expect("join").expect_err("should fail");
        assert!(err.to_string().contains("closed"), "{err}");

        // A later call must fail at once rather than wait out the timeout.
        let err = transport
            .call("Too.late", None)
            .await
            .expect_err("should fail");
        assert!(err.to_string().contains("closed"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_undecodable_message_does_not_break_the_connection() {
        let (transport, mut peer) = connected(DEFAULT_CALL_TIMEOUT);

        peer.send("{ this is not json");

        let call = tokio::spawn({
            let transport = transport.clone();
            async move { transport.call("Still.works", None).await }
        });
        let id = peer.recv()["id"].as_u64().expect("an id");
        peer.send(&json!({ "id": id, "result": { "ok": true } }).to_string());

        assert_eq!(call.await.expect("join").expect("call")["ok"], true);
    }
}
