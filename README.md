<p align="center">
  <img src="https://raw.githubusercontent.com/YpNo/stealthscraper-rs/main/docs/banner.svg" alt="stealthscraper-rs — stealthy Rust web scraping with JA4 TLS impersonation" width="100%">
</p>

# stealthscraper-rs

[![Rust CI](https://github.com/YpNo/stealthscraper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/YpNo/stealthscraper-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/stealthscraper-rs.svg)](https://crates.io/crates/stealthscraper-rs)
[![GitHub release](https://img.shields.io/github/v/release/YpNo/stealthscraper-rs?sort=semver)](https://github.com/YpNo/stealthscraper-rs/releases/latest)
[![docs.rs](https://docs.rs/stealthscraper-rs/badge.svg)](https://docs.rs/stealthscraper-rs)
[![codecov](https://codecov.io/gh/YpNo/stealthscraper-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/YpNo/stealthscraper-rs)
[![MSRV](https://img.shields.io/badge/MSRV-1.95.0-blue.svg)](https://github.com/YpNo/stealthscraper-rs)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`stealthscraper-rs` is a blazing-fast, stealthy Rust library designed to simulate highly realistic human browser behavior and completely bypass advanced bot-protection systems like Cloudflare, Akamai, and Datadome.

By combining the low-level automation power of CDP (Chrome DevTools Protocol) with state-of-the-art JA4 / TLS `ClientHello` network impersonation, `stealthscraper-rs` guarantees that your scraping agents remain undetectable.

---

## 🚀 Features

- **Measured fingerprints, not transcribed ones**: every TLS, HTTP/2 and header value the crate emits is captured from a real browser and verified by round-trip — emulate the capture, measure what we then emit, require the two to match. No third-party fingerprint table, and nothing derived from documentation.
- **JA4 TLS Emulation**: An embedded Man-in-the-Middle (MITM) proxy intercepts browser traffic and reconstructs it with the target's TLS `ClientHello` and HTTP/2 signature using `wreq` — SETTINGS *and their wire order*, connection window, `HEADERS` priority, pseudo-header order, and the header set and order.
- **Dual-mode sessions**: solve the first challenge in a real browser, then carry the whole identity — cookies, client hints, locale and the *same* egress IP — onto a plain HTTP transport and shut Chrome down. Steady-state scraping runs with **no browser process**, and re-escalates automatically when a challenge reappears.
- **First-party async CDP client**: Chrome is driven over `--remote-debugging-pipe`, so there is no TCP debug port for a page to scan, `--enable-automation` is never passed, and `Runtime`/`DOM`/`Log`/`Debugger`/`Profiler` are never enabled. The whole API is `async` — no `spawn_blocking`.
- **Intelligent CDP Stealth**: Overrides land on `Navigator.prototype`, patched accessors report `[native code]`, and Canvas/Audio noise is seeded per identity so it is stable within a session. What the browser already reports correctly is deliberately left alone — hooking it is itself a signal.
- **Challenge Detection & Mitigation**: Classifies bot-protection pages (Turnstile, managed JS, legacy IUAM, access-denied, rate-limit) and runs a configurable retry/back-off policy via `solve_challenge` — clicking interactive Turnstile widgets when needed.
- **Proxy Pool & Rotation**: Register a pool of upstream proxies; on a hard block the egress IP is rotated by hot-swapping the MITM client — **no browser relaunch**. Round-robin or random strategies.
- **Geo/Locale Consistency**: Tag proxies with their exit country and the browser's `Accept-Language`, `navigator.languages`, and timezone are derived to match — eliminating the IP/locale mismatch that anti-bot systems flag.
- **Profile Rotation**: Relaunch under a fresh `BrowserProfile` (new UA/fingerprint) while preserving the MITM port and egress IP, for when the identity itself is burned.
- **Session State (optional)**: Per-domain outcome/cooldown tracking behind a `StateStore` port — in-memory by default, durable via the pure-Rust `redb` backend under the `persistence` feature.
- **Observability**: A `ScraperEvent` / `EventSink` stream (no-op by default, or routed to the `log` crate).
- **Human Evasion**: Bézier-curve mouse paths, keystroke jitter, idle micro-drift, and scroll-then-settle before a click.
- **Streaming & Async**: The MITM engine supports `wreq::Body::wrap_stream` for zero-overhead streaming of large `POST`/`PUT` payloads.
- **Safe & Strongly Typed**: `#![forbid(unsafe_code)]` (zero first-party `unsafe`) with explicit `thiserror` variants — no opaque `anyhow` in the public API.
- **One TLS stack, permissive licence**: BoringSSL only (no rustls/ring/aws-lc alongside it), and MIT + Apache-2.0 throughout — no GPL in any feature combination.

## 🏗️ How it Works

Bot-protections identify headless browsers using two primary vectors:
1. **JavaScript Probing**: Inspecting the DOM (like `navigator.webdriver` or distinct WebGL signatures).
2. **Network Fingerprinting (JA3/JA4)**: Inspecting the raw TLS connection. Headless Chrome's network signature is explicitly different from a standard Chrome browser.

**The `stealthscraper-rs` solution:**
1. A realistic `BrowserProfile` (e.g. Windows, Chrome 153, 16 GB RAM, NVIDIA WebGL) is defined — or randomised.
2. A headless Chrome is launched over a pipe, and a document-start script masks the DOM to match that profile.
3. Chrome routes its traffic through the internal `TlsSpoofingProxy`.
4. The proxy terminates Chrome's TLS locally and re-dispatches through `wreq`, shaped to the JA4 and HTTP/2 signature of the profile's browser — selected from the profile's **own parsed User-Agent**, so the signature and the advertised browser cannot disagree.
5. Once the challenge is cleared, the session can drop the browser entirely and continue over HTTP carrying the same identity and the same egress IP.

## 📦 Installation

Add this to your `Cargo.toml`. The headless-browser API (`CloudScraper`) lives behind the
`browser` feature, so enable it for the examples below:

```toml
[dependencies]
stealthscraper-rs = { version = "1.0", features = ["browser"] }
```

### Feature flags

| Feature | Default | Enables |
|---------|---------|---------|
| `browser` | no | Headless-Chrome automation: `CloudScraper`, `solve_challenge`, profile rotation, human-behavior helpers. |
| `persistence` | no | The `redb`-backed `RedbStateStore`, for sharing one state file between processes or for large host sets. |

With no features the crate builds the pure, dependency-light core (challenge detection,
proxy pool, geo/locale, the state model, events) plus `JsonStateStore`, which gives durable
per-domain state with no extra dependency.

### Build requirements

The TLS impersonation backend (`wreq` → `btls-sys`) compiles vendored BoringSSL, so the
build machine needs more than a Rust toolchain:

| Needed | Why |
|---|---|
| `cmake`, a C++ compiler | building BoringSSL |
| **`libclang`** (`libclang-dev`) | `bindgen` generates the FFI bindings; without it the build fails deep inside BoringSSL with an error that does not name clang |
| `perl` | BoringSSL's assembly generation |
| **`git`** | the build script shells out to `git init` to apply its patches, and fails with a bare `NotFound` without it |

On Debian/Ubuntu:

```bash
sudo apt-get install -y clang libclang-dev cmake build-essential pkg-config perl git
```

`libclang` and `git` are the two that are easy to miss, because neither failure mentions the
missing tool.

## 💻 Usage

### No browser at all (default build)

Many "protected" endpoints gate on the TLS/HTTP-2 fingerprint alone and serve no JavaScript
challenge. Against one of those a browser is pure overhead: the measured emulation and a
`wreq` client are the whole answer, with no `browser` feature and no Chrome in the graph.

```rust
use stealthscraper_rs::{BrowserProfile, impersonation_client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Carries the measured TLS + HTTP/2 emulation, and the User-Agent,
    // Sec-CH-UA* and Accept-Language of the same profile.
    let client = impersonation_client(&BrowserProfile::random()).build()?;

    let body = client
        .get("https://target-website.com")
        .send()
        .await?
        .text()
        .await?;
    println!("{} bytes", body.len());
    Ok(())
}
```

A `wreq::ClientBuilder` is returned rather than a finished client, so you can still add a
proxy, a cookie jar or a redirect policy. `wreq` is re-exported as `stealthscraper_rs::wreq`
for exactly that, so you cannot end up on a different `wreq` major from the one the
emulation was measured against.

If the target *does* serve a JavaScript challenge, use the dual-mode session below instead.

### Dual-mode session (recommended)

Start in a real browser, clear the challenge, then keep scraping over plain HTTP with the
same identity and the same egress IP — with no browser process running.

```rust
use stealthscraper_rs::{BrowserProfile, StealthSession};

#[tokio::main]
async fn main() -> Result<(), stealthscraper_rs::Error> {
    let mut session = StealthSession::builder()
        .profile(BrowserProfile::random())
        .build();

    // Launches a browser only if the response needs one, and shuts it down
    // again once the page comes back clean.
    let response = session.fetch("https://target-protected-website.com").await?;
    println!("{} ({} bytes)", response.status, response.body.len());

    // Later requests reuse the cleared cookies over HTTP alone.
    let next = session.fetch("https://target-protected-website.com/page/2").await?;
    println!("mode: {:?}", session.mode());
    println!("{}", next.status);

    Ok(())
}
```

### Driving the browser directly

```rust
use stealthscraper_rs::{BrowserProfile, CloudScraper};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), stealthscraper_rs::Error> {
    // Choose a specific profile, or let the library randomise it.
    let profile = BrowserProfile::random();

    // The builder starts the JA4 proxy and matches it to the profile.
    let scraper = CloudScraper::builder().profile(profile).build().await?;

    // The page starts blank, so the stealth script is installed before any
    // document can capture the originals.
    let page = scraper.new_stealth_page().await?;

    page.navigate_and_wait(
        "https://target-protected-website.com",
        Duration::from_secs(30),
    )
    .await?;

    // Detect any bot-protection challenge and wait it out / solve it.
    let signal = scraper.solve_challenge(&page).await?;
    println!("Page cleared (challenge: {:?})", signal.kind);

    Ok(())
}
```

### Advanced Configuration

The `CloudScraperBuilder` provides extensive toggles for manipulating traffic flow and debug states:

```rust
let scraper = CloudScraper::builder()
    // Explicitly toggle the visual browser window on (headless = false)
    .headless(false)
    // Turn on verbose MITM diagnostics (emitted via the `log` crate)
    .with_debug(true)
    // Chain the stealth TLS packets via a residential SOCKS/HTTP upstream proxy
    .upstream_proxy("http://username:password@my-proxy:8080".to_string())
    .build()
    .await?;
```

### Opting out of the Proxy

If you only need CDP stealth and want to save network overhead, you can entirely disable the local TLS edge proxy:

```rust
let scraper = CloudScraper::builder()
    .disable_proxy()
    .build()
    .await?;
```

### Proxy rotation, geo-consistency & resilience

Register geo-tagged proxies and the locale (Accept-Language, `navigator.languages`,
timezone) is matched to each egress country. A hard block rotates the egress IP
automatically; outcomes and cooldowns are tracked per domain.

```rust
use stealthscraper_rs::{CloudScraper, CountryCode, RotationStrategy, InMemoryStateStore, LogEventSink};
use std::sync::Arc;

let scraper = CloudScraper::builder()
    // Geo-tagged residential proxies — locale is derived per exit country.
    .with_geo_proxies([
        ("http://user:pass@de.proxy:8080".to_string(), CountryCode::new("DE").unwrap()),
        ("http://user:pass@fr.proxy:8080".to_string(), CountryCode::new("FR").unwrap()),
    ])
    .proxy_strategy(RotationStrategy::RoundRobin)
    .with_max_challenge_attempts(3)
    // Remember per-domain outcomes & rate-limit cooldowns (in-memory here).
    .with_state_store(Arc::new(InMemoryStateStore::new()))
    // Stream scrape events (challenge detected, proxy rotated, …) to the `log` crate.
    .with_event_sink(Arc::new(LogEventSink))
    .build()
    .await?;
```

For durable state across restarts, enable the `persistence` feature and use
`stealthscraper_rs::state::RedbStateStore::open("state.redb")?`.

When the browser *identity* itself is burned (not just the IP), rotate to a fresh
fingerprint — this relaunches Chrome but keeps the MITM port and egress proxy:

```rust
let scraper = scraper.rotate_profile().await?; // consumes self, returns a fresh scraper
```

## 🔬 Capturing a fingerprint

Adding a browser to the emulation table is a measurement, not a transcription. Each tool
prints values ready to paste into `src/emulation.rs` or `src/client_hints.rs`:

```bash
cargo run --example capture_fingerprint          # TLS ClientHello → JA4
cargo run --example capture_h2                   # HTTP/2 SETTINGS, window, pseudo order
cargo run --example capture_h2 -- --h1           # header names and order, as plaintext
cargo run --example capture_hints --features browser   # User-Agent Client Hints
cargo run --example emulation_roundtrip          # prove an entry reproduces its browser
```

Point a browser at the listener each prints — including one on another machine, which is how
the Safari and Windows entries were captured — and read the values off. `capture_hints` also
prints a console snippet for a machine with no Rust toolchain.

The round-trip check is what makes an entry trustworthy: a single mis-transcribed cipher
changes the JA4 hash, so a matching fingerprint cannot be luck.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Format and Lint your code (`cargo fmt` and `cargo clippy`)
4. Run the test suite (`cargo test`)
5. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
6. Push to the Branch (`git push origin feature/AmazingFeature`)
7. Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## ⚠️ Disclaimer

This library is intended for educational purposes, legitimate web scraping, and automated software testing. Authors accept no responsibility for the misuse of this tool. Please consult the Terms of Service of the targeted websites before engaging in scraping operations.
