# Technical Context: stealthscraper-rs

## 🎯 Purpose
`stealthscraper-rs` is a Rust-based stealth scraping library. Its primary goal is to bypass "anti-bot" services (Cloudflare, Akamai, Datadome) that use both JavaScript-based environment probing and network-layer TLS fingerprinting.

## 🏗️ Core Architecture
The library operates as a **Hybrid MITM Automation Framework**:

1.  **Automation Layer**: Uses `headless_chrome` (via CDP) to execute real browser logic, allowing it to solve complex JS challenges and execute site-specific scripts.
2.  **Stealth Engine**: Injects CDP commands to override internal browser variables (e.g., `navigator.webdriver`, WebGL vendors, Canvas fingerprinting) to prevent "Environment Probing" detection.
3.  **Network Layer (The Proxy)**: Headless Chrome is configured to route all traffic through an internal `TlsSpoofingProxy`.
4.  **Impersonation Client (`wreq`)**: The proxy terminates Chrome's TLS connection, extracts the HTTP data, and re-dispatches it using `wreq`. `wreq` is a specialized HTTP client that can spoof TLS `ClientHello` packets and HTTP/2 settings to match a specific `BrowserProfile` (JA4 signatures). The proxy's upstream client is hot-swappable, so the egress proxy can rotate without relaunching the browser.
5.  **Challenge Layer**: A pure `challenge` module classifies bot-protection responses (`detect`), and a `MitigationPolicy` decides the next `Action` (wait/back-off, rotate proxy, fail). `CloudScraper::solve_challenge` drives the loop and reuses the `solver` for interactive Turnstile.
6.  **Resilience & Observability**: a rotatable upstream-proxy pool (`proxy_pool`) with egress hot-swap; proxy-led geo/locale consistency (`geo`) applied via CDP; geo-aware browser-profile rotation; per-domain session state (`state`, optional `redb` persistence); and a `ScraperEvent` / `EventSink` stream (`events`).

## 🛠️ Key Technologies
- **Asynchronous Runtime**: `tokio`.
- **HTTP Stack**: `hyper` and `hyper-util` for the MITM server; `wreq` (a `reqwest`-family fork) for the outgoing impersonation client.
- **TLS Backends**: Links against `boring-sys2` or `aws-lc-sys` (via `rcgen` and `wreq`) to allow low-level control over the TLS handshake.
- **Browser Control**: `headless_chrome`.
- **Certificate Logic**: `rcgen` for dynamic generation of MITM certificates.
- **Persistence**: `redb` (pure-Rust embedded KV store), behind the optional `persistence` feature.
- **Serialization**: `serde` / `serde_json` for `BrowserProfile` and `DomainState`.
- **Diagnostics**: the `log` crate (no `eprintln!`); the `LogEventSink` bridges `ScraperEvent`s into `log`.
- **Error Handling**: Explicitly typed errors using `thiserror`.

## 🛡️ Stealth Vector Details
- **JA4/TLS Impersonation**: Standard Rust clients (like `reqwest` or `rustls`) have distinct TLS fingerprints. `wreq` allows this project to mimic the exact cipher suites, extensions, and elliptic curves of a real Chrome on Windows or Safari on macOS.
- **HTTP/2 Fingerprinting**: Mimics frame sizes, initial window increments, and header priority logic.
- **CDP Hardening**: Blocks the `Runtime.enable` detection vector and mocks hardware concurrency, memory, and device pixel ratios to match the `BrowserProfile`.
- **Geo/Locale Coherence (proxy-led)**: The egress proxy's country drives `Accept-Language`, `navigator.languages`, and the IANA timezone (applied via CDP overrides), so the IP and the browser's locale never contradict each other.

## ⚙️ Build Requirements
Due to the underlying C-based cryptographic backends (`boring-sys2` or `aws-lc-sys`):
- `cmake` is required.
- A C++ compiler (clang/gcc/msvc) is required.
- The project targets the `2024` edition of Rust, MSRV **1.95**.

## 🧪 Logic Flow for AI Agents
When debugging or extending:
- `CloudScraperBuilder` initializes the `tokio` runtime components, the proxy pool, and the MITM proxy; `CloudScraper` is the orchestration root (`browser` feature).
- `TlsSpoofingProxy` (`proxy.rs`) is where request interception and re-signing live; its upstream `wreq` client is hot-swappable for rotation.
- `BrowserProfile` is the source of truth for JS injection values and the network signature; `geo::Locale` adds the proxy-led locale layer.
- `CloudScraper::solve_challenge` runs the detect → decide → wait/rotate loop (`challenge` + `proxy_pool`); `rotate_profile` relaunches Chrome under a fresh profile while preserving the MITM port and egress.
- Human-behavior helpers (`CloudScraper::human_type_str` / `human_move_mouse`, `behavior.rs`) wrap `headless_chrome` operations with Bézier curves and keystroke jitter.
- Pure domain modules (`challenge`, `proxy_pool`, `geo`, `state` model, `events`) carry no I/O and are unit-tested without a browser.

## ⚠️ Important Constraints
- **Feature Flags**: Headless-browser functionality (`scraper`, `solver`, `behavior`) is gated behind `browser`; the `redb`-backed state store is gated behind `persistence`. The pure domain modules build with no features.
- **Safety**: First-party code is `#![forbid(unsafe_code)]`; all `unsafe`/FFI is confined to dependencies.
- **Proxy Overhead**: Traffic is decrypted and re-encrypted locally. This provides high stealth at the cost of some CPU overhead compared to raw HTTP clients.
- **Upstream Proxies**: The library chains to residential proxies at the `wreq` layer (not the browser layer) so the TLS fingerprint stays controlled by the library. Proxies may be tagged with a country to drive locale; rotation swaps the egress without relaunching the browser.
- **Credentials**: `user:password@` proxy URLs are redacted before reaching logs, events, or persisted state.
- **`solve_challenge` blocks**: it is synchronous (CDP + `std::thread::sleep` back-off) — call it from `tokio::task::spawn_blocking` and run the proxy on a multi-threaded runtime.