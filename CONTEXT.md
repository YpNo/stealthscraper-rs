# Technical Context: rs-cloudscraper

## 🎯 Purpose
`rs-cloudscraper` is a Rust-based stealth scraping library. Its primary goal is to bypass "anti-bot" services (Cloudflare, Akamai, Datadome) that use both JavaScript-based environment probing and network-layer TLS fingerprinting.

## 🏗️ Core Architecture
The library operates as a **Hybrid MITM Automation Framework**:

1.  **Automation Layer**: Uses `headless_chrome` (via CDP) to execute real browser logic, allowing it to solve complex JS challenges and execute site-specific scripts.
2.  **Stealth Engine**: Injects CDP commands to override internal browser variables (e.g., `navigator.webdriver`, WebGL vendors, Canvas fingerprinting) to prevent "Environment Probing" detection.
3.  **Network Layer (The Proxy)**: Headless Chrome is configured to route all traffic through an internal `TlsSpoofingProxy`.
4.  **Impersonation Client (`wreq`)**: The proxy terminates Chrome's TLS connection, extracts the HTTP data, and re-dispatches it using `wreq`. `wreq` is a specialized HTTP client that can spoof TLS `ClientHello` packets and HTTP/2 settings to match a specific `BrowserProfile` (JA4 signatures).

## 🛠️ Key Technologies
- **Asynchronous Runtime**: `tokio`.
- **HTTP Stack**: `hyper` and `hyper-util` for the MITM server; `wreq` (a `reqwest` fork) for the outgoing impersonation client.
- **TLS Backends**: Links against `boring-sys2` or `aws-lc-sys` (via `rcgen` and `wreq`) to allow low-level control over the TLS handshake.
- **Browser Control**: `headless_chrome`.
- **Certificate Logic**: `rcgen` for dynamic generation of MITM certificates.
- **Error Handling**: Explicitly typed errors using `thiserror`.

## 🛡️ Stealth Vector Details
- **JA4/TLS Impersonation**: Standard Rust clients (like `reqwest` or `rustls`) have distinct TLS fingerprints. `wreq` allows this project to mimic the exact cipher suites, extensions, and elliptic curves of a real Chrome on Windows or Safari on macOS.
- **HTTP/2 Fingerprinting**: Mimics frame sizes, initial window increments, and header priority logic.
- **CDP Hardening**: Blocks the `Runtime.enable` detection vector and mocks hardware concurrency, memory, and device pixel ratios to match the `BrowserProfile`.

## ⚙️ Build Requirements
Due to the underlying C-based cryptographic backends (`boring-sys2` or `aws-lc-sys`):
- `cmake` is required.
- A C++ compiler (clang/gcc/msvc) is required.
- The project is currently targeting the `2024` edition of Rust.

## 🧪 Logic Flow for AI Agents
When debugging or extending:
- `CloudScraperBuilder` handles the initialization of the `tokio` runtime components and the MITM proxy.
- `TlsSpoofingProxy` is where the request interception and re-signing logic resides.
- `BrowserProfile` is the source of truth for both JS injection values and network signature configuration.
- Methods on `StealthTab` wrap `headless_chrome` operations with additional human-behavior simulation (Bezier curves, keystroke jitter).

## ⚠️ Important Constraints
- **Feature Flags**: Browser functionality is gated behind the `browser` feature.
- **Proxy Overhead**: Traffic is decrypted and re-encrypted locally. This provides high stealth at the cost of some CPU overhead compared to raw HTTP clients.
- **Upstream Proxies**: The library supports chaining to residential proxies at the `wreq` layer, not the browser layer, to ensure the TLS fingerprint remains controlled by the library.