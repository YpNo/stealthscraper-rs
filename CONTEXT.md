# Technical Context: stealthscraper-rs

## 🎯 Purpose
`stealthscraper-rs` is a Rust-based stealth scraping library. Its primary goal is to bypass "anti-bot" services (Cloudflare, Akamai, Datadome) that use both JavaScript-based environment probing and network-layer TLS fingerprinting.

## 🏗️ Core Architecture
The library operates as a **Hybrid MITM Automation Framework** with two transports sharing one identity:

1.  **Automation Layer** (`cdp`): a first-party async CDP client. Chrome is launched over `--remote-debugging-pipe` — no TCP debug port for a page to scan — and without `--enable-automation`. `CdpTransport` demultiplexes replies by `id` and events by `method`; `BrowserHandle`/`Page` expose the ~25 methods actually used. `Runtime`, `DOM`, `Log`, `Debugger` and `Profiler` are **never** enabled, which is asserted by test.
2.  **Stealth Engine** (`stealth`): injects one document-start script that overrides `Navigator.prototype` (not the instance), reports `[native code]` from patched accessors via a `WeakMap` registry behind `Function.prototype.toString`, and seeds Canvas/Audio noise from a hash of the profile so it is stable within a session and applied once per buffer. It deliberately leaves alone everything the browser already reports correctly — `navigator.plugins`, `pdfViewerEnabled`, `connection` — because hooking those was itself the signal.
3.  **Network Layer** (`proxy`): Chrome routes all traffic through the internal `TlsSpoofingProxy`, which terminates TLS with BoringSSL using a per-process ephemeral CA (`ca`).
4.  **Impersonation Client** (`wreq` + `emulation`): the proxy re-dispatches requests through `wreq`, shaped by a first-party emulation table. The upstream client is hot-swappable, so the egress proxy rotates without relaunching the browser.
5.  **Challenge Layer** (`challenge`): `detect` classifies bot-protection responses and `MitigationPolicy` decides the next `Action`. Detection requires interstitial markers — a bare Turnstile widget or a `cf-ray` header is not a challenge, and vendor-only evidence returns `ChallengeKind::None` with the evidence attached.
6.  **Dual-mode sessions** (`session`, `identity`, `http_scraper`): `StealthSession` solves the first challenge in a real browser, exports the whole identity (profile, RFC 6265-scoped cookies, client hints, locale, and the *same* egress proxy), continues on a plain HTTP transport, and shuts the browser down. It re-escalates on a fresh challenge or a near-expiry clearance cookie.
7.  **Resilience & Observability**: rotatable upstream-proxy pool (`proxy_pool`); proxy-led geo/locale consistency (`geo`); profile rotation; per-domain session state (`state`); a `ScraperEvent` / `EventSink` stream (`events`).

## 📐 The measurement principle
Every fingerprint value this crate emits is **captured from a real browser**, never transcribed from a third-party table or derived from documentation. This is not a style preference — it is the lesson of the values that were not:

- Five client-hint values were reasoned to from documentation. All five were wrong, and not by a little.
- The GPL emulation table that was removed was measured to be **no better** than values read straight off the browser.

Each entry is verified by round-trip: emulate the captured values, capture what *we* then emit, and require the two fingerprints to match. A transcription error changes the hash, so agreement cannot be coincidence.

The apparatus lives in `ja4` (ClientHello parsing + JA4), `tls_capture` (passive capture through the proxy), and four examples:

| Tool | Captures |
|---|---|
| `capture_fingerprint` | TLS `ClientHello` → cipher/curve/extension lists, JA4 |
| `capture_h2` | HTTP/2 SETTINGS in wire order, `WINDOW_UPDATE`, `HEADERS` priority, pseudo-header order; `--h1` reads header names as plaintext, which HPACK otherwise hides |
| `capture_hints` | User-Agent Client Hints, incl. a console snippet for machines with no Rust toolchain |
| `emulation_roundtrip` | Proves an entry reproduces the browser it claims to be |

## 🛠️ Key Technologies
- **Asynchronous Runtime**: `tokio`.
- **HTTP Stack**: `hyper` / `hyper-util` for the MITM server; `wreq` for the outgoing impersonation client.
- **TLS Backend**: **BoringSSL only** (`btls` / `tokio-btls`, shared with `wreq` 6 by pinning the same minor version). rustls structurally cannot forge a `ClientHello` — it exposes no control over extension order, GREASE, curve order or ALPS — so BoringSSL is permanent for egress, and using it for the MITM leg too means one cryptographic implementation to track instead of three.
- **Browser Control**: a first-party CDP client (`cdp`); no `headless_chrome`.
- **Certificate Logic**: `ca` mints leaves from one ephemeral in-memory CA, cached per host.
- **Persistence**: `JsonStateStore` in the default build (no dependency); `redb` behind `persistence` for cross-process safety or large host sets.
- **Serialization**: `serde` / `serde_json`.
- **Diagnostics**: the `log` crate (no `eprintln!`); `LogEventSink` bridges `ScraperEvent`s into `log`.
- **Error Handling**: explicitly typed errors using `thiserror`.
- **License posture**: MIT + Apache-2.0 throughout. No GPL in any feature combination.

## 🛡️ Stealth Vector Details
- **JA4/TLS Impersonation**: the emulation is selected from the profile's own parsed User-Agent, so the signature and the advertised browser cannot contradict each other. Safari 27 is reproduced exactly; Chrome matches except for extension `0xca34` and three ML-DSA signature schemes, which the vendored BoringSSL cannot emit.
- **HTTP/2 Fingerprinting**: SETTINGS identifiers *and their wire order*, connection window, `HEADERS` priority block and pseudo-header order, measured per browser. Chrome and Safari share none of it: Safari sends `MaxConcurrentStreams` and `NoRfc7540Priorities` where Chrome sends `HeaderTableSize` and `MaxHeaderListSize`, sends no priority block, and transposes `:scheme` and `:authority`.
- **Headers**: the measured set *and order*, including what each browser does **not** send — Safari has no `sec-fetch-user` and no `upgrade-insecure-requests`, and an absence contradicts a User-Agent as loudly as a wrong value. The emulation never sets `User-Agent`, `Sec-CH-UA*` or `Accept-Language`; those belong to the profile and the proxy-led locale.
- **CDP Hardening**: no `--enable-automation`, no TCP debug port, and no observable domain ever enabled — so `navigator.webdriver` is false natively and the JS override is belt-and-braces.
- **Geo/Locale Coherence (proxy-led)**: the egress proxy's country drives `Accept-Language`, `navigator.languages` and the IANA timezone.
- **Screen coherence**: `screen.*` is overridden to match the window, which otherwise reported 800×600 under a 1920×1080 window.

## ⚙️ Build Requirements
`wreq` → `btls-sys` builds vendored BoringSSL:
- `cmake`, a C++ compiler (clang/gcc/msvc), **`libclang`** (`bindgen` generates the FFI bindings), `perl`, and **`git`** (the build script shells out to `git init` to apply its patches).
- `libclang` and `git` are the two that are easy to miss: neither failure names the missing tool — the build dies deep inside BoringSSL, or with a bare `NotFound`.
- Debian/Ubuntu: `clang libclang-dev cmake build-essential pkg-config perl git`.
- Edition **2024**, MSRV **1.95**.

## 🧪 Logic Flow for AI Agents
When debugging or extending:
- `CloudScraperBuilder` → `CloudScraper` is the browser-mode orchestration root; `StealthSessionBuilder` → `StealthSession` is the dual-mode one and is what most callers want.
- `TlsSpoofingProxy` (`proxy.rs`) holds interception and re-signing; its upstream `wreq` client is hot-swappable for rotation.
- `BrowserProfile` is the source of truth for both the JS injection values and the network signature; `emulation::for_kind` maps its parsed `BrowserKind` to a measured entry, and always returns one — there is no fallback path that would leave a bare client's fingerprint on the wire.
- `CloudScraper::solve_challenge` runs the detect → decide → wait/rotate loop.
- Human-behaviour helpers (`behavior.rs`) drive `Input.dispatch*` with `tokio` timers: Bézier mouse paths, keystroke jitter, idle micro-drift, and scroll-then-settle before a click.
- Pure domain modules (`challenge`, `proxy_pool`, `geo`, `state` model, `events`, `profile`) carry no I/O and are unit-tested without a browser.

## ⚠️ Important Constraints
- **Feature Flags**: headless-browser functionality is gated behind `browser`; the `redb` state store behind `persistence`. The pure domain modules build with no features.
- **Safety**: first-party code is `#![forbid(unsafe_code)]`. The one `dup2` the pipe launch needs lives in the audited `command-fds`; all other FFI is in `btls`/`wreq`.
- **Fully async**: there is no blocking CDP call and no `spawn_blocking` in the public API.
- **Proxy Overhead**: traffic is decrypted and re-encrypted locally — high stealth at some CPU cost.
- **Upstream Proxies**: chained at the `wreq` layer, not the browser layer, so the TLS fingerprint stays under the library's control.
- **Credentials**: `user:password@` proxy URLs are redacted in the constructor of `EgressRef`, before reaching logs, events or persisted state.
- **The MITM CA is ephemeral by design**: generated in memory per process and never written to disk, because a persisted CA key — especially one installed into a trust store — is a standing man-in-the-middle capability against the host for as long as the file exists. The browser is pinned to it with `--ignore-certificate-errors-spki-list`, which exempts exactly one key rather than disabling certificate checking.
- **`wreq` is a release candidate** (`6.0.0-rc.31`), and it is re-exported, so it is public API.
  Accepted because the whole `wreq 5.x` line is yanked: a lockfile keeps an existing build alive,
  but a new consumer cannot resolve the manifest and `cargo update` cannot run at all. The pin
  moves when `6.0` goes stable; the 13 wire-level fingerprint assertions make that mechanical.
- **Known gap**: Edge is not modelled; an Edge User-Agent carries a `Chrome/` token and parses as Chrome.
