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

- **JA4 TLS Emulation**: An embedded Man-in-the-Middle (MITM) proxy automatically intercepts headless Chrome traffic and reconstructs it with perfect HTTP/2 and TLS signatures (`ClientHello`, exact ciphers, and extensions) using `wreq`.
- **Intelligent CDP Stealth**: Automatically overrides `navigator.webdriver`, masks WebGL vendors, mocks `window.chrome`, spoofs Permissions/Plugins APIs, and injects micro-noise into Canvas and AudioContext rendering to defeat browser fingerprinting.
- **Challenge Detection & Mitigation**: Classifies bot-protection pages (Turnstile, managed JS, legacy IUAM, access-denied, rate-limit) and runs a configurable retry/back-off policy via `solve_challenge` — clicking interactive Turnstile widgets when needed.
- **Proxy Pool & Rotation**: Register a pool of upstream proxies; on a hard block the egress IP is rotated by hot-swapping the MITM client — **no browser relaunch**. Round-robin or random strategies.
- **Geo/Locale Consistency**: Tag proxies with their exit country and the browser's `Accept-Language`, `navigator.languages`, and timezone are derived to match — eliminating the IP/locale mismatch that anti-bot systems flag.
- **Profile Rotation**: Relaunch under a fresh `BrowserProfile` (new UA/fingerprint) while preserving the MITM port and egress IP, for when the identity itself is burned.
- **Session State (optional)**: Per-domain outcome/cooldown tracking behind a `StateStore` port — in-memory by default, durable via the pure-Rust `redb` backend under the `persistence` feature.
- **Observability**: A `ScraperEvent` / `EventSink` stream (no-op by default, or routed to the `log` crate).
- **Human Evasion**: API methods to simulate Bezier-curve mouse movements and human-like typing delays based on psychological keystroke timing.
- **Streaming & Async**: The MITM engine supports `wreq::Body::wrap_stream` for zero-overhead streaming of large `POST`/`PUT` payloads.
- **Safe & Strongly Typed**: `#![forbid(unsafe_code)]` (zero first-party `unsafe`) with explicit `thiserror` variants — no opaque `anyhow` in the public API.

## 🏗️ How it Works

Bot-protections identify headless browsers using two primary vectors:
1. **JavaScript Probing**: Inspecting the DOM (like `navigator.webdriver` or distinct WebGL signatures).
2. **Network Fingerprinting (JA3/JA4)**: Inspecting the raw TLS connection. Headless Chrome's network signature is explicitly different from a standard Chrome browser.

**The `stealthscraper-rs` solution:**
1. A realistic `BrowserProfile` (e.g., Windows 10, Chrome 120, 16GB RAM, NVIDIA WebGL) is explicitly defined.
2. A headless Chrome instance is launched, and Javascript interceptors mask the internal DOM to perfectly match this profile.
3. Chrome routes its traffic through our internal multi-threaded `TlsSpoofingProxy`.
4. The proxy terminates Chrome's TLS connection locally, reads the HTTP data, and forwards it to the target website using a specialized Rust HTTP/2 Client (`wreq`). This client perfectly shapes the outbound TLS layer to mimic the exact JA4 network signature of the configured `BrowserProfile`, tricking the edge proxy (like Cloudflare) into accepting the connection as a genuine human browser.

## 📦 Installation

Add this to your `Cargo.toml`. The headless-browser API (`CloudScraper`) lives behind the
`browser` feature, so enable it for the examples below:

```toml
[dependencies]
stealthscraper-rs = { version = "0.3", features = ["browser"] }
```

### Feature flags

| Feature | Default | Enables |
|---------|---------|---------|
| `browser` | no | Headless-Chrome automation: `CloudScraper`, `solve_challenge`, profile rotation, human-behavior helpers. |
| `persistence` | no | The durable `redb`-backed `RedbStateStore`. |

With no features the crate builds the pure, dependency-light core (challenge detection,
proxy pool, geo/locale, the state model, and events) for embedding into your own pipeline.

*Note: the TLS impersonation backend (`wreq` → `boring-sys`) requires `cmake` and a C++
compiler on the build machine.*

## 💻 Usage

```rust
use stealthscraper_rs::{CloudScraper, BrowserProfile};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), stealthscraper_rs::Error> {
    
    // Choose a specific profile, or let the library randomize it
    let profile = BrowserProfile::random();

    // The builder automatically initializes the JA4 proxy to match the profile!
    let scraper = CloudScraper::builder()
        .profile(profile)
        .build()
        .await?;

    let tab = scraper.new_stealth_tab()?;

    // The headless browser traffic is transparently MITM intercepted
    // and rebuilt as perfect HTTP/2 TLS mimicking the exact BrowserProfile.
    tab.navigate_to("https://target-protected-website.com")?;
    tab.wait_until_navigated()?;

    // Detect any bot-protection challenge and wait it out / solve it.
    let signal = scraper.solve_challenge(&tab)?;
    println!("Page cleared (challenge: {:?})", signal.kind);

    Ok(())
}
```

> `solve_challenge` is synchronous and blocking (CDP + back-off sleeps). On an async
> runtime, call it from `tokio::task::spawn_blocking` and run on a multi-threaded runtime.

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
let scraper = scraper.rotate_profile()?; // consumes self, returns a fresh scraper
```

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
