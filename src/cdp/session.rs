//! Typed CDP calls, with domains enabled only when something needs them.
//!
//! A conventional driver enables whole protocol domains when a tab opens,
//! because it is convenient to have every event available. That convenience is
//! observable. `Runtime.enable` in particular is a well-known detection signal:
//! it makes the browser announce every execution context as it is created, and
//! a page can see the effect of being watched.
//!
//! So this layer inverts the default. Nothing is enabled when a page opens.
//! A domain is enabled at the moment a call genuinely requires it, once per
//! page, and the domains that are never required are never enabled at all:
//!
//! - **`Runtime` is never enabled.** `Runtime.evaluate` works perfectly well
//!   without it, so every read of the page — its content, its URL, whether a
//!   selector exists — goes through evaluation rather than through the DOM
//!   domain's node bookkeeping.
//! - **`DOM` is never enabled.** Finding an element by selector is done in the
//!   page, not by pushing the node tree across the wire.
//! - **`Page` is enabled only when a caller waits for a load event**, because
//!   that event cannot be observed any other way.
//!
//! [`NEVER_ENABLED`] records that list, and a test asserts none of them reach
//! the browser while a page is driven through its whole surface.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::transport::CdpTransport;
use crate::Error;
use crate::identity::{Cookie, SameSite};

/// Domains this layer must never enable, each one observable from the page.
///
/// Kept as data so a test can assert they stay unsent: the discipline is easy
/// to break by adding one convenient `enable` call, and the cost of breaking it
/// is invisible without a test that measures the wire.
#[cfg(test)]
#[rustfmt::skip]
pub(crate) const NEVER_ENABLED: &[&str] = &[
    // Announces every execution context as it is created.
    "Runtime",
    // Mirrors the node tree and tracks it as the page mutates.
    "DOM",
    // Surfaces console and browser log entries.
    "Log",
    // Both change how script is executed, not merely what is reported.
    "Debugger",
    "Profiler",
];

/// How often [`Page::wait_for_selector`] re-checks the page.
///
/// Polling in-page rather than subscribing to DOM mutations keeps the `DOM`
/// domain disabled; the interval is short enough to feel immediate and long
/// enough not to busy-loop the renderer.
const SELECTOR_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A connection to the browser itself, from which pages are opened.
#[derive(Debug, Clone)]
pub struct BrowserHandle {
    cdp: CdpTransport,
}

impl BrowserHandle {
    /// Wraps an established transport.
    pub fn new(cdp: CdpTransport) -> Self {
        Self { cdp }
    }

    /// The underlying transport, for calls this layer does not wrap.
    pub fn transport(&self) -> &CdpTransport {
        &self.cdp
    }

    /// The browser's version information.
    pub async fn version(&self) -> Result<Value, Error> {
        self.cdp.call("Browser.getVersion", None).await
    }

    /// Opens a page at `url` and attaches to it, **without waiting for it**.
    ///
    /// The target begins loading the moment it is created, before this call
    /// can attach — so there is no point at which a load watcher could be
    /// installed, and no way to wait for that first document. Reading the page
    /// straight afterwards can therefore return an empty document.
    ///
    /// Use [`open`](Self::open) when the page's content is wanted; this is for
    /// callers that drive the page themselves.
    ///
    /// Attaches in flat mode, so the page's traffic shares the one connection
    /// and is addressed by session id rather than by a second socket.
    pub async fn new_page(&self, url: &str) -> Result<Page, Error> {
        let created = self
            .cdp
            .call("Target.createTarget", Some(json!({ "url": url })))
            .await?;
        let target_id = string_field(&created, "targetId", "Target.createTarget")?;

        let attached = self
            .cdp
            .call(
                "Target.attachToTarget",
                Some(json!({ "targetId": target_id, "flatten": true })),
            )
            .await?;
        let session_id = string_field(&attached, "sessionId", "Target.attachToTarget")?;

        Ok(Page {
            cdp: self.cdp.clone(),
            target_id,
            session_id,
            enabled: Mutex::new(HashSet::new()),
        })
    }

    /// Every cookie the browser holds, across all hosts.
    ///
    /// Uses `Storage.getCookies`, which is browser-level and — verified against
    /// Chromium 153 — needs no `Network.enable`. That matters: enabling the
    /// Network domain to read cookies would undo the discipline this module
    /// exists for. The browser-level `Network.getAllCookies` older drivers call
    /// does not exist as a browser-level method at all.
    pub async fn cookies(&self) -> Result<Vec<Cookie>, Error> {
        let result = self.cdp.call("Storage.getCookies", None).await?;
        let entries = result
            .get("cookies")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::BrowserError("Storage.getCookies returned no list".into()))?;

        // A cookie we cannot read is skipped rather than failing the transfer:
        // losing one cookie degrades the session, losing all of them ends it.
        Ok(entries.iter().filter_map(cookie_from_cdp).collect())
    }

    /// Installs `cookies` into the browser, replacing nothing else.
    ///
    /// The counterpart of [`cookies`](Self::cookies), for handing a session back
    /// to the browser when it escalates.
    pub async fn set_cookies(&self, cookies: &[Cookie]) -> Result<(), Error> {
        if cookies.is_empty() {
            return Ok(());
        }
        let encoded: Vec<Value> = cookies.iter().map(cookie_to_cdp).collect();
        self.cdp
            .call("Storage.setCookies", Some(json!({ "cookies": encoded })))
            .await?;
        Ok(())
    }

    /// Opens a page and waits for `url` to finish loading.
    ///
    /// Opens a blank target first and navigates it, because that is the only
    /// order in which the load can be observed: a target created directly at
    /// `url` is already loading before anything can subscribe.
    pub async fn open(&self, url: &str, timeout: Duration) -> Result<Page, Error> {
        let page = self.new_page("about:blank").await?;
        page.navigate_and_wait(url, timeout).await?;
        Ok(page)
    }
}

/// An attached page.
///
/// Every call is addressed to this page's session, so several pages can be
/// driven concurrently over the one connection.
#[derive(Debug)]
pub struct Page {
    cdp: CdpTransport,
    target_id: String,
    session_id: String,
    /// Domains already enabled for this page, so each is enabled at most once.
    enabled: Mutex<HashSet<&'static str>>,
}

impl Page {
    /// The page's target id.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// The page's CDP session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Calls `method` in this page's session.
    pub async fn call(&self, method: &str, params: Option<Value>) -> Result<Value, Error> {
        self.cdp
            .call_in_session(Some(&self.session_id), method, params)
            .await
    }

    // -- Reading the page ---------------------------------------------------

    /// Evaluates `expression` and returns its value.
    ///
    /// Deliberately does **not** enable the `Runtime` domain: evaluation does
    /// not require it, and enabling it would announce every execution context
    /// to the page.
    pub async fn evaluate(&self, expression: &str) -> Result<Value, Error> {
        let response = self
            .call(
                "Runtime.evaluate",
                Some(json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true,
                })),
            )
            .await?;

        // A thrown exception is reported in the result, not as a protocol
        // error, so it has to be surfaced explicitly or it passes as success.
        if let Some(details) = response.get("exceptionDetails") {
            let text = details
                .get("exception")
                .and_then(|e| e.get("description"))
                .and_then(Value::as_str)
                .or_else(|| details.get("text").and_then(Value::as_str))
                .unwrap_or("script threw");
            return Err(Error::BrowserError(format!(
                "evaluating in the page failed: {text}"
            )));
        }

        Ok(response
            .get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// The page's serialised DOM.
    pub async fn content(&self) -> Result<String, Error> {
        let value = self
            .evaluate("document.documentElement ? document.documentElement.outerHTML : ''")
            .await?;
        value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::BrowserError("the page returned no content".to_string()))
    }

    /// The page's current URL.
    pub async fn url(&self) -> Result<String, Error> {
        let value = self.evaluate("document.location.href").await?;
        value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::BrowserError("the page returned no URL".to_string()))
    }

    /// Whether `selector` currently matches an element.
    pub async fn has_selector(&self, selector: &str) -> Result<bool, Error> {
        let expression = format!("!!document.querySelector({})", js_string(selector));
        Ok(self.evaluate(&expression).await? == Value::Bool(true))
    }

    /// Waits until `selector` matches, or `timeout` elapses.
    ///
    /// Polls in the page rather than subscribing to mutations, which keeps the
    /// `DOM` domain disabled.
    pub async fn wait_for_selector(&self, selector: &str, timeout: Duration) -> Result<(), Error> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.has_selector(selector).await? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::BrowserError(format!(
                    "{selector} did not appear within {timeout:?}"
                )));
            }
            tokio::time::sleep(SELECTOR_POLL_INTERVAL).await;
        }
    }

    /// The viewport coordinates of `selector`'s centre, if it is present.
    ///
    /// Returns `None` rather than an error when the element is absent, since a
    /// caller usually wants to fall through to another strategy.
    pub async fn element_center(&self, selector: &str) -> Result<Option<(f64, f64)>, Error> {
        // A non-rendered element (display:none, or detached) still has a rect —
        // an all-zero one. Returning its "centre" would hand the caller (0, 0),
        // the viewport's corner, which is a real coordinate pointing at
        // something else entirely. No box means no centre.
        let expression = format!(
            "(() => {{ const el = document.querySelector({}); if (!el) return null; \
             const r = el.getBoundingClientRect(); \
             if (r.width === 0 && r.height === 0) return null; \
             return {{ x: r.left + r.width / 2, y: r.top + r.height / 2 }}; }})()",
            js_string(selector)
        );
        let value = self.evaluate(&expression).await?;
        let (Some(x), Some(y)) = (
            value.get("x").and_then(Value::as_f64),
            value.get("y").and_then(Value::as_f64),
        ) else {
            return Ok(None);
        };
        Ok(Some((x, y)))
    }

    // -- Driving the page ---------------------------------------------------

    /// Navigates to `url`.
    pub async fn navigate(&self, url: &str) -> Result<(), Error> {
        let response = self
            .call("Page.navigate", Some(json!({ "url": url })))
            .await?;
        // Navigation failures are reported in the result, not as an error.
        if let Some(reason) = response.get("errorText").and_then(Value::as_str) {
            return Err(Error::BrowserError(format!(
                "navigating to {url} failed: {reason}"
            )));
        }
        Ok(())
    }

    /// Reloads the page.
    pub async fn reload(&self, ignore_cache: bool) -> Result<(), Error> {
        self.call("Page.reload", Some(json!({ "ignoreCache": ignore_cache })))
            .await?;
        Ok(())
    }

    /// Starts watching for a load, before the action that causes it.
    ///
    /// Subscribing has to happen *first*. A load triggered and completed
    /// between the trigger and the subscription would otherwise be missed
    /// entirely, and the caller would wait out its timeout for an event that
    /// already fired — a race that only shows up under load, which is when it
    /// matters.
    ///
    /// This is also the one place the `Page` domain is enabled, because a load
    /// event cannot be observed without it.
    pub async fn watch_load(&self) -> Result<LoadWatcher, Error> {
        let events = self.cdp.events();
        self.enable_domain("Page").await?;
        Ok(LoadWatcher {
            events,
            session_id: self.session_id.clone(),
        })
    }

    /// Navigates to `url` and waits for the page to load.
    pub async fn navigate_and_wait(&self, url: &str, timeout: Duration) -> Result<(), Error> {
        let watcher = self.watch_load().await?;
        self.navigate(url).await?;
        watcher.wait(timeout).await
    }

    /// Reloads the page and waits for it to load.
    pub async fn reload_and_wait(
        &self,
        ignore_cache: bool,
        timeout: Duration,
    ) -> Result<(), Error> {
        let watcher = self.watch_load().await?;
        self.reload(ignore_cache).await?;
        watcher.wait(timeout).await
    }

    /// Moves the mouse to a point, without clicking.
    pub async fn move_mouse(&self, x: f64, y: f64) -> Result<(), Error> {
        self.call(
            "Input.dispatchMouseEvent",
            Some(json!({ "type": "mouseMoved", "x": x, "y": y })),
        )
        .await?;
        Ok(())
    }

    /// Clicks a point.
    ///
    /// Sends a move before the press, as a real pointer necessarily does: a
    /// press at a location the cursor never travelled to is a tell.
    pub async fn click_point(&self, x: f64, y: f64) -> Result<(), Error> {
        self.move_mouse(x, y).await?;
        for event in ["mousePressed", "mouseReleased"] {
            self.call(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": event,
                    "x": x,
                    "y": y,
                    "button": "left",
                    "buttons": 1,
                    "clickCount": 1,
                })),
            )
            .await?;
        }
        Ok(())
    }

    /// Types one character as a real key press would.
    ///
    /// Uses key events rather than `Input.insertText`: inserting text changes
    /// the field without producing the `keydown`/`keyup` pair a page's own
    /// handlers expect to see.
    pub async fn press_key(&self, character: char) -> Result<(), Error> {
        let text = character.to_string();
        for event in ["keyDown", "keyUp"] {
            self.call(
                "Input.dispatchKeyEvent",
                Some(json!({
                    "type": event,
                    "text": if event == "keyDown" { text.clone() } else { String::new() },
                    "unmodifiedText": if event == "keyDown" { text.clone() } else { String::new() },
                    "key": text,
                })),
            )
            .await?;
        }
        Ok(())
    }

    // -- Identity -----------------------------------------------------------

    /// Runs `source` before any page script, on every document.
    ///
    /// This is how stealth hooks are installed: the script executes ahead of
    /// the page's own code, so a page cannot capture the originals first.
    pub async fn add_init_script(&self, source: &str) -> Result<(), Error> {
        self.call(
            "Page.addScriptToEvaluateOnNewDocument",
            Some(json!({ "source": source })),
        )
        .await?;
        Ok(())
    }

    /// Overrides the User-Agent, and optionally the language and platform.
    ///
    /// `metadata` carries the Client Hints (`Sec-CH-UA`,
    /// `navigator.userAgentData`), which the browser otherwise derives from its
    /// own build. Passing `None` leaves them reporting the real version, which
    /// a page can compare against the User-Agent string — so a caller that
    /// cares about coherence must supply it.
    pub async fn set_user_agent(
        &self,
        user_agent: &str,
        accept_language: Option<&str>,
        platform: Option<&str>,
        metadata: Option<Value>,
    ) -> Result<(), Error> {
        let mut params = json!({ "userAgent": user_agent });
        if let Some(accept_language) = accept_language {
            params["acceptLanguage"] = Value::String(accept_language.to_string());
        }
        if let Some(platform) = platform {
            params["platform"] = Value::String(platform.to_string());
        }
        if let Some(metadata) = metadata {
            params["userAgentMetadata"] = metadata;
        }
        self.call("Emulation.setUserAgentOverride", Some(params))
            .await?;
        Ok(())
    }

    /// Overrides the page's timezone, keeping it coherent with the egress IP.
    pub async fn set_timezone(&self, timezone_id: &str) -> Result<(), Error> {
        self.call(
            "Emulation.setTimezoneOverride",
            Some(json!({ "timezoneId": timezone_id })),
        )
        .await?;
        Ok(())
    }

    /// Overrides the page's locale.
    pub async fn set_locale(&self, locale: &str) -> Result<(), Error> {
        self.call(
            "Emulation.setLocaleOverride",
            Some(json!({ "locale": locale })),
        )
        .await?;
        Ok(())
    }

    /// Makes the viewport **and the screen around it** match the profile.
    ///
    /// The screen matters as much as the viewport. A headless browser reports
    /// `screen` as 800x600 whatever its window size, so a 1920x1080 window sits
    /// on an 800x600 screen — a window larger than its own display, which cannot
    /// happen and takes one line to check:
    ///
    /// ```text
    /// window.outerWidth > screen.width
    /// ```
    ///
    /// `Emulation.setDeviceMetricsOverride` sets both at the browser level, so
    /// there is no JavaScript hook for a page to find. `position` places the
    /// window at the screen origin, because a screen-sized window at a non-zero
    /// offset would extend past the display edge — the same contradiction in a
    /// different coordinate.
    pub async fn set_viewport(&self, width: u32, height: u32) -> Result<(), Error> {
        self.call(
            "Emulation.setDeviceMetricsOverride",
            Some(json!({
                // Zero leaves the window and viewport as the browser has them,
                // so the chrome height it computes for itself is preserved.
                "width": 0,
                "height": 0,
                // The screen is the same size as the window: a maximised window
                // on a display of the profile's declared resolution. Every value
                // here follows from the profile rather than being invented.
                "screenWidth": width,
                "screenHeight": height,
                "positionX": 0,
                "positionY": 0,
                "deviceScaleFactor": 1,
                "mobile": false,
                "screenOrientation": {
                    "type": "landscapePrimary",
                    "angle": 0,
                },
            })),
        )
        .await?;
        Ok(())
    }

    // -- Lifetime -----------------------------------------------------------

    /// Closes the page.
    ///
    /// Explicit rather than automatic on drop, since closing is an async call
    /// and a silent best-effort close would hide failures.
    pub async fn close(self) -> Result<(), Error> {
        self.cdp
            .call(
                "Target.closeTarget",
                Some(json!({ "targetId": self.target_id })),
            )
            .await?;
        Ok(())
    }

    /// Enables `domain` for this page, at most once.
    async fn enable_domain(&self, domain: &'static str) -> Result<(), Error> {
        {
            let mut enabled = self.enabled.lock().unwrap_or_else(|e| e.into_inner());
            if !enabled.insert(domain) {
                return Ok(());
            }
        }

        let result = self.call(&format!("{domain}.enable"), None).await;
        if result.is_err() {
            // Not actually enabled, so do not remember it as such.
            self.enabled
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(domain);
        }
        result.map(|_| ())
    }
}

/// A subscription taken before a navigation, awaited after it.
///
/// Exists so that subscribing and triggering cannot be reordered by accident:
/// a watcher must be obtained first, and only then can it be awaited.
#[derive(Debug)]
pub struct LoadWatcher {
    events: tokio::sync::broadcast::Receiver<super::transport::CdpEvent>,
    session_id: String,
}

impl LoadWatcher {
    /// Waits for this page's load event.
    pub async fn wait(mut self, timeout: Duration) -> Result<(), Error> {
        use tokio::sync::broadcast::error::RecvError;

        let wait = async {
            loop {
                match self.events.recv().await {
                    Ok(event)
                        if event.method == "Page.loadEventFired"
                            && event.session_id.as_deref() == Some(self.session_id.as_str()) =>
                    {
                        return Ok(());
                    }
                    // Another page's load, or an unrelated event.
                    Ok(_) => continue,
                    // Lagging means events were dropped while we were behind,
                    // and ours may have been among them; keep waiting rather
                    // than report a load that may not have happened.
                    Err(RecvError::Lagged(dropped)) => {
                        log::warn!("missed {dropped} CDP events while waiting for a page load");
                        continue;
                    }
                    Err(RecvError::Closed) => {
                        return Err(Error::BrowserError(
                            "the CDP connection closed while waiting for a page load".to_string(),
                        ));
                    }
                }
            }
        };

        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Error::BrowserError(format!("the page did not load within {timeout:?}")))?
    }
}

/// Converts one CDP cookie into the portable form.
///
/// Returns `None` when the entry lacks the fields that define a cookie, rather
/// than inventing defaults that would change its scope.
fn cookie_from_cdp(entry: &Value) -> Option<Cookie> {
    Some(Cookie {
        name: entry.get("name")?.as_str()?.to_string(),
        value: entry.get("value")?.as_str()?.to_string(),
        domain: entry.get("domain")?.as_str()?.to_string(),
        path: entry.get("path")?.as_str()?.to_string(),
        // CDP reports `expires` as a **float**, and uses a negative value for a
        // session cookie — reading it as an integer would turn session cookies
        // into ones expiring in 1970.
        expires: match entry.get("expires").and_then(Value::as_f64) {
            Some(seconds) if seconds > 0.0 => Some(seconds as u64),
            _ => None,
        },
        secure: entry
            .get("secure")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        http_only: entry
            .get("httpOnly")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        same_site: match entry.get("sameSite").and_then(Value::as_str) {
            Some("Strict") => Some(SameSite::Strict),
            Some("Lax") => Some(SameSite::Lax),
            Some("None") => Some(SameSite::None),
            _ => None,
        },
    })
}

/// Converts one portable cookie into CDP's form.
fn cookie_to_cdp(cookie: &Cookie) -> Value {
    let mut encoded = json!({
        "name": cookie.name,
        "value": cookie.value,
        "domain": cookie.domain,
        "path": cookie.path,
        "secure": cookie.secure,
        "httpOnly": cookie.http_only,
    });
    // Omitted rather than sent as null: an absent expiry is what makes a
    // session cookie, and CDP rejects a null.
    if let Some(expires) = cookie.expires {
        encoded["expires"] = json!(expires as f64);
    }
    if let Some(same_site) = cookie.same_site {
        encoded["sameSite"] = json!(match same_site {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        });
    }
    encoded
}

/// Renders `value` as a JavaScript string literal.
///
/// Selectors reach the page inside an expression, so they are encoded as JSON
/// rather than interpolated — a selector containing a quote would otherwise
/// change the meaning of the script around it.
fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

/// Reads a required string field from a CDP result.
fn string_field(value: &Value, field: &str, method: &str) -> Result<String, Error> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::BrowserError(format!("{method} returned no {field}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdp::transport::DEFAULT_CALL_TIMEOUT;
    use crate::cdp::transport::testing::{FakePeer, connected};

    /// Answers the two calls `new_page` makes.
    fn serve_new_page(peer: &mut FakePeer) {
        peer.answer("Target.createTarget", json!({ "targetId": "T1" }));
        peer.answer("Target.attachToTarget", json!({ "sessionId": "S1" }));
    }

    async fn opened() -> (BrowserHandle, Page, FakePeer) {
        let (cdp, mut peer) = connected(DEFAULT_CALL_TIMEOUT);
        let browser = BrowserHandle::new(cdp);
        let page = tokio::spawn({
            let browser = browser.clone();
            async move { browser.new_page("about:blank").await }
        });
        serve_new_page(&mut peer);
        let page = page.await.expect("join").expect("new page");
        (browser, page, peer)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn opening_a_page_attaches_in_flat_mode() {
        let (cdp, mut peer) = connected(DEFAULT_CALL_TIMEOUT);
        let browser = BrowserHandle::new(cdp);

        let page = tokio::spawn(async move { browser.new_page("about:blank").await });
        peer.answer("Target.createTarget", json!({ "targetId": "T1" }));
        let attach = peer.answer("Target.attachToTarget", json!({ "sessionId": "S1" }));

        assert_eq!(
            attach["params"]["flatten"], true,
            "flat mode keeps the page on one connection"
        );
        let page = page.await.expect("join").expect("new page");
        assert_eq!(page.target_id(), "T1");
        assert_eq!(page.session_id(), "S1");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn driving_a_page_never_enables_an_observable_domain() {
        // The point of this layer: exercise the whole surface and assert the
        // browser was never asked to start watching itself.
        let (_browser, page, mut peer) = opened().await;

        let driven = tokio::spawn(async move {
            page.add_init_script("void 0").await.expect("init script");
            page.set_user_agent("UA", Some("en-US"), Some("Win32"), None)
                .await
                .expect("user agent");
            page.set_timezone("Europe/Paris").await.expect("timezone");
            page.set_locale("fr").await.expect("locale");
            page.navigate("https://example.test/")
                .await
                .expect("navigate");
            let _ = page.content().await.expect("content");
            let _ = page.url().await.expect("url");
            let _ = page.has_selector("#gone").await.expect("selector");
            page.click_point(10.0, 20.0).await.expect("click");
            page.press_key('a').await.expect("key");
        });

        for expected in [
            "Page.addScriptToEvaluateOnNewDocument",
            "Emulation.setUserAgentOverride",
            "Emulation.setTimezoneOverride",
            "Emulation.setLocaleOverride",
            "Page.navigate",
        ] {
            peer.answer(expected, json!({}));
        }
        // content, url, has_selector
        peer.answer(
            "Runtime.evaluate",
            json!({ "result": { "value": "<html></html>" } }),
        );
        peer.answer(
            "Runtime.evaluate",
            json!({ "result": { "value": "https://example.test/" } }),
        );
        peer.answer("Runtime.evaluate", json!({ "result": { "value": false } }));
        // click: move, press, release — then two key events
        for _ in 0..3 {
            peer.answer("Input.dispatchMouseEvent", json!({}));
        }
        for _ in 0..2 {
            peer.answer("Input.dispatchKeyEvent", json!({}));
        }
        driven.await.expect("join");

        for domain in NEVER_ENABLED {
            let forbidden = format!("{domain}.enable");
            assert!(
                !peer.methods().contains(&forbidden),
                "{forbidden} reached the browser; it is observable from the page"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_domain_is_enabled_once_and_only_when_needed() {
        let (_browser, page, mut peer) = opened().await;

        let navigated = tokio::spawn(async move {
            page.navigate_and_wait("https://a.test/", Duration::from_secs(5))
                .await
                .expect("first load");
            page.navigate_and_wait("https://b.test/", Duration::from_secs(5))
                .await
                .expect("second load");
        });

        // The first navigation has to enable the domain.
        peer.answer("Page.enable", json!({}));
        peer.answer("Page.navigate", json!({}));
        peer.send(
            &json!({ "method": "Page.loadEventFired", "sessionId": "S1", "params": {} })
                .to_string(),
        );

        // The second must not re-enable. Seeing its navigate also proves the
        // watcher is already subscribed, so the event cannot fall into a gap.
        peer.answer("Page.navigate", json!({}));
        peer.send(
            &json!({ "method": "Page.loadEventFired", "sessionId": "S1", "params": {} })
                .to_string(),
        );
        navigated.await.expect("join");

        let enables = peer
            .methods()
            .iter()
            .filter(|m| *m == "Page.enable")
            .count();
        assert_eq!(enables, 1, "Page.enable should be sent exactly once");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_load_that_fires_before_the_wait_is_not_missed() {
        // The race the watcher exists to prevent: subscribing happens before
        // the navigation, so a load that completes immediately still counts.
        let (_browser, page, mut peer) = opened().await;

        let navigated = tokio::spawn(async move {
            page.navigate_and_wait("https://fast.test/", Duration::from_secs(5))
                .await
        });

        peer.answer("Page.enable", json!({}));
        let request = peer.recv();
        assert_eq!(request["method"], "Page.navigate");
        // The load lands before the reply to the navigation itself.
        peer.send(
            &json!({ "method": "Page.loadEventFired", "sessionId": "S1", "params": {} })
                .to_string(),
        );
        let id = request["id"].as_u64().expect("an id");
        peer.send(&json!({ "id": id, "result": {} }).to_string());

        navigated
            .await
            .expect("join")
            .expect("the early load counted");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_load_event_for_another_page_is_ignored() {
        let (_browser, page, mut peer) = opened().await;

        let waited = tokio::spawn(async move {
            let watcher = page.watch_load().await.expect("watch");
            watcher.wait(Duration::from_secs(5)).await
        });

        peer.answer("Page.enable", json!({}));
        // Another page's load, and a browser-level event: neither is ours.
        peer.send(
            &json!({ "method": "Page.loadEventFired", "sessionId": "OTHER", "params": {} })
                .to_string(),
        );
        peer.send(&json!({ "method": "Page.loadEventFired", "params": {} }).to_string());
        peer.send(
            &json!({ "method": "Page.loadEventFired", "sessionId": "S1", "params": {} })
                .to_string(),
        );

        waited.await.expect("join").expect("our own load");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_thrown_exception_is_an_error_rather_than_a_null_value() {
        let (_browser, page, mut peer) = opened().await;

        let evaluated = tokio::spawn(async move { page.evaluate("boom()").await });
        peer.answer(
            "Runtime.evaluate",
            json!({
                "result": { "type": "object" },
                "exceptionDetails": {
                    "text": "Uncaught",
                    "exception": { "description": "ReferenceError: boom is not defined" }
                }
            }),
        );

        let err = evaluated.await.expect("join").expect_err("should fail");
        assert!(err.to_string().contains("boom is not defined"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_navigation_is_reported() {
        let (_browser, page, mut peer) = opened().await;

        let navigated =
            tokio::spawn(async move { page.navigate("https://nowhere.invalid/").await });
        peer.answer(
            "Page.navigate",
            json!({ "errorText": "net::ERR_NAME_NOT_RESOLVED" }),
        );

        let err = navigated.await.expect("join").expect_err("should fail");
        assert!(err.to_string().contains("ERR_NAME_NOT_RESOLVED"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_selector_reaches_the_page_as_a_literal_not_as_code() {
        let (_browser, page, mut peer) = opened().await;

        // A selector carrying a quote must not be able to change the script.
        let selector = r#"input[name="q"]"#;
        let checked = tokio::spawn({
            let selector = selector.to_string();
            async move { page.has_selector(&selector).await }
        });
        let request = peer.answer("Runtime.evaluate", json!({ "result": { "value": true } }));

        let expression = request["params"]["expression"]
            .as_str()
            .expect("expression");
        assert_eq!(
            expression, r#"!!document.querySelector("input[name=\"q\"]")"#,
            "the selector was interpolated rather than encoded"
        );
        assert!(checked.await.expect("join").expect("check"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_click_moves_before_it_presses() {
        let (_browser, page, mut peer) = opened().await;

        let clicked = tokio::spawn(async move { page.click_point(12.0, 34.0).await });
        let moved = peer.answer("Input.dispatchMouseEvent", json!({}));
        let pressed = peer.answer("Input.dispatchMouseEvent", json!({}));
        let released = peer.answer("Input.dispatchMouseEvent", json!({}));
        clicked.await.expect("join").expect("click");

        // A press at a point the cursor never travelled to is a tell.
        assert_eq!(moved["params"]["type"], "mouseMoved");
        assert_eq!(pressed["params"]["type"], "mousePressed");
        assert_eq!(released["params"]["type"], "mouseReleased");
        assert_eq!(moved["params"]["x"], 12.0);
        assert_eq!(released["params"]["clickCount"], 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn typing_produces_key_events_rather_than_inserted_text() {
        let (_browser, page, mut peer) = opened().await;

        let typed = tokio::spawn(async move { page.press_key('x').await });
        let down = peer.answer("Input.dispatchKeyEvent", json!({}));
        let up = peer.answer("Input.dispatchKeyEvent", json!({}));
        typed.await.expect("join").expect("key");

        assert_eq!(down["params"]["type"], "keyDown");
        assert_eq!(down["params"]["text"], "x");
        assert_eq!(up["params"]["type"], "keyUp");
        // Input.insertText would change the field without a keydown pair.
        assert!(!peer.methods().iter().any(|m| m == "Input.insertText"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_absent_element_has_no_centre() {
        let (_browser, page, mut peer) = opened().await;

        let centre = tokio::spawn(async move { page.element_center("#gone").await });
        peer.answer("Runtime.evaluate", json!({ "result": { "value": null } }));
        assert_eq!(centre.await.expect("join").expect("centre"), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_page_call_carries_its_own_session() {
        let (_browser, page, mut peer) = opened().await;

        let called = tokio::spawn(async move { page.reload(true).await });
        let request = peer.answer("Page.reload", json!({}));
        called.await.expect("join").expect("reload");

        assert_eq!(
            request["sessionId"], "S1",
            "a page call must address its own target"
        );
        assert_eq!(request["params"]["ignoreCache"], true);
    }
}
