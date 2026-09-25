# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Breaking. The headless-browser API is now fully async, `headless_chrome` is gone, and the
only GPL dependency is gone with it. Every fingerprint value the crate emits is now measured
from a real browser rather than transcribed or inferred.

### Added

- **Own async CDP client** (`cdp` module): `LaunchConfig`/`launch`, a `CdpTransport` that
  demultiplexes replies by `id` and events by `method`, and a typed `BrowserHandle`/`Page`
  surface of ~25 methods. Chrome is launched over `--remote-debugging-pipe` (no scannable
  TCP debug port) and **without** `--enable-automation`. `Runtime`, `DOM`, `Log`, `Debugger`
  and `Profiler` are never enabled — asserted by test, where the previous claim to that
  effect was false.
- **Dual-mode sessions** (`StealthSession`, `identity`, `http_scraper`): solve the first
  challenge in a real browser, then carry the whole identity — profile, cookies (RFC 6265
  scoped), client hints, locale and the *same* egress proxy — onto a plain HTTP transport and
  shut the browser down. It re-escalates automatically on a fresh challenge or a
  near-expiry clearance cookie. Steady-state scraping runs with no Chrome process.
- **Measured emulation table** (`emulation` module): complete Chrome and Safari emulations —
  TLS, HTTP/2 SETTINGS in wire order, connection window, `HEADERS` priority, pseudo-header
  order, and the header set and order — every value captured from the browser it claims to
  be.
- **JA4 measurement apparatus** (`ja4`, `tls_capture`): a `ClientHello` parser and JA4
  computation, plus passive capture through the MITM proxy, so any browser's real
  fingerprint can be read off rather than guessed.
- **Capture tooling**: `examples/capture_fingerprint` (TLS), `examples/capture_h2` (HTTP/2
  frames, and header names as plaintext with `--h1`), `examples/capture_hints` (User-Agent
  Client Hints, including a console snippet for machines with no Rust toolchain), and
  `examples/emulation_roundtrip` (proves an entry reproduces its browser).
- **`JsonStateStore`**: a durable `StateStore` in the **default** build, needing no
  dependency. Writes go to a sibling temp file, are flushed, then `rename`d over the target,
  so a crash leaves either the previous complete file or the new one.
- **BoringSSL certificate authority** (`ca` module): one ephemeral in-memory CA per process,
  leaves minted on demand and cached per host, replacing a fresh self-signed certificate per
  `CONNECT`. The browser is pinned to it with `--ignore-certificate-errors-spki-list` rather
  than having certificate checking disabled wholesale.
- Automated stealth audit (`tests/stealth_audit.rs`, 14 live checks) and wire-level
  regression tests for TLS (`ja4_egress`), HTTP/2 (`h2_egress`) and headers
  (`http_leg_headers`).

### Changed

- **Breaking:** `CloudScraper`'s browser API is async and tab-free. `new_stealth_tab()` →
  `new_stealth_page().await`, and `solve_challenge`, `detect_challenge`, `rotate_profile`
  and every `human_*` helper are now `async`. `spawn_blocking` is no longer needed or
  wanted.
- **Breaking:** `wreq-util` (GPL-3.0) removed. Measured through the same harness, its newest
  Chrome entry put byte-identical TLS *and* HTTP/2 on the wire to values captured directly
  from the browser, so the GPL table bought nothing; the Safari entry it replaced was worse.
  The crate is now MIT + Apache-2.0 throughout.
- **Breaking:** `BrowserProfile::random()` claims Chrome 153 — the version actually
  captured, and the version of the binary that renders the page. It previously claimed
  Chrome 124–126 while launching a much newer browser, which feature detection alone
  exposes.
- MITM TLS termination and certificate minting moved from rustls + rcgen onto BoringSSL,
  which `wreq` already links. `rustls`, `tokio-rustls`, `rcgen`, `ring`, `aws-lc`,
  `rustls-webpki`, `yasna` and `pem` are gone from the dependency graph: **three
  cryptographic backends became one.**
- `wreq` now builds with `gzip`/`deflate`/`brotli`/`zstd`, so the `Accept-Encoding` the crate
  advertises is one it can actually decode.

### Fixed

- **The HTTP leg advertised a different browser from the profile.** The emulation supplied
  its own `User-Agent` and `Sec-CH-UA`, which silently overrode the profile's, so a session
  that demoted from browser to HTTP changed identity mid-flight — the exact failure a shared
  identity exists to prevent.
- **Every Cloudflare-served page was reported as a challenge.** A bare `cf-turnstile` widget
  or a `cf-ray` header was enough. Detection now requires interstitial markers, and
  vendor-only evidence returns `ChallengeKind::None` *with* the evidence attached.
- **A clean page was never demoted without a clearance cookie**, pinning the browser open
  and defeating the memory saving that dual-mode sessions exist for.
- **The window reported an 800×600 screen while being 1920×1080.** `screen.*` is now
  overridden coherently with the window.
- **Two stealth hooks were themselves the signal.** `navigator.plugins` and
  `pdfViewerEnabled` were being synthesised over values the browser already reported
  correctly; they are left alone, and a test asserts the injected script does not mention
  them. Canvas and audio noise is now seeded per identity and applied once per buffer, where
  re-perturbing on every read was itself detectable.
- **`wait_for_load` subscribed after issuing the navigation** — a real race, not a flaky
  test. Split into `watch_load` / `navigate_and_wait` / `reload_and_wait`.
- **`element_center` returned `Some((0, 0))` for a hidden element**, so a human click could
  be aimed at something invisible. Zero-area boxes now return `None`.
- **Client-hint values that were reasoned to rather than observed.** All five were wrong:
  Windows `platformVersion` (`15.0.0` → `19.0.0`), macOS (`14.6.1` → `27.0.0`), the GREASE
  brand (`"Not-A.Brand";v="99"` → `"Not_A Brand";v="8"`), the brand order, and the
  `fullVersionList` build (`153.0.0.0` → `153.0.8010.53`, since no real Chrome reports a
  zeroed build). `full_version_list` also restated the brand list instead of deriving it, so
  the two could disagree — something a page can check directly.
- JA4 selection no longer depends on a `Chrome/120` string match that never fired, which had
  every request emitting a Chrome 120 fingerprint under a Chrome 124–126 User-Agent.

### Removed

- `headless_chrome` and its dependency tree (`auto_generate_cdp`, `tungstenite`, `which`,
  `winreg`, `walkdir`, `ureq`, `derive_builder`, `tempfile`), `wreq-util`, `rustls`,
  `tokio-rustls`, `rcgen`, `ring`, `aws-lc`, `regex`, `bytes`, `cookie_store` (direct),
  `tokio-socks` (direct) and `rand_distr`. The `browser` graph went from ~199 crates to 154,
  the default build from ~160 to 151.

### Known limitations

- Edge is not modelled. An Edge User-Agent carries a `Chrome/` token and so parses as Chrome,
  which would report the `Google Chrome` brand under an `Edg/` User-Agent. Edge also carries
  a different version per brand in `fullVersionList`, which the current hint struct cannot
  express.
- Chrome's TLS fingerprint is reproduced except for extension `0xca34` and three ML-DSA
  signature schemes, which the vendored BoringSSL cannot emit. This is a property of the TLS
  stack, not of the data: the GPL table that was removed hit exactly the same ceiling.


## [0.4.0] - 2026-06-28

### Added

- **Challenge detection and mitigation** (`challenge` module): a pure, dependency-free
  `detect()` that classifies a response/page into a `ChallengeSignal` (`Turnstile`,
  `JsChallenge`, `IuamV1`, `AccessDenied`, `RateLimited`, `Unknown`, `None`), and a
  `MitigationPolicy` that selects a retry `Action` with exponential back-off. Surfaced on
  `CloudScraper` via `detect_challenge()` and `solve_challenge()` (the latter reuses
  `GenericSolver` for interactive Turnstile), plus a `with_max_challenge_attempts()` builder
  option.
- **Upstream proxy pool with rotation** (`proxy_pool` module): `ProxyPool` and
  `RotationStrategy` (`RoundRobin`, `Random`) with per-endpoint health tracking. The MITM
  proxy's upstream client is hot-swappable (`TlsSpoofingProxy::set_upstream_client`), so
  rotation changes the egress IP without relaunching Chrome. A hard block (`AccessDenied`)
  now rotates to the next healthy proxy (`Action::RotateProxy`), failing only once the pool
  is exhausted. Builder gains `with_proxies()` and `proxy_strategy()`.
- **Geo/locale consistency** (`geo` module): `CountryCode`, a coherent `Locale`
  (`Accept-Language` + `navigator.languages` + IANA timezone) with a curated
  `Locale::for_country()` table, and a `GeoResolver` port. Proxies can be tagged with their
  exit country (`with_geo_proxies()`, `with_geo_resolver()`); the browser locale is derived
  **proxy-led** and applied per tab via CDP (`setUserAgentOverride`, `setTimezoneOverride`,
  `setLocaleOverride`), preventing the IP/locale mismatches that anti-bot systems flag.
- **Geo-aware profile rotation**: `CloudScraper::rotate_profile()` /
  `rotate_profile_with()` relaunch Chrome under a new `BrowserProfile` while preserving the
  MITM port and egress IP. They consume `self` and return a fresh scraper, so rotation is
  caller-driven (it cannot run inside the tab-scoped `solve_challenge`). Emits
  `ScraperEvent::ProfileRotated`.
- **Per-domain session state** (`state` module): a serializable `DomainState` (last
  outcome/proxy, success/failure tallies, rate-limit cooldown) behind a `StateStore` port.
  `InMemoryStateStore` is the default; the durable `RedbStateStore` is gated behind the new
  `persistence` feature (pure-Rust `redb`, no C toolchain). `CloudScraper` records outcomes
  automatically and exposes `domain_state()`, `record_outcome()`, and `cooldown_remaining()`.
- **Observability events** (`events` module): a `ScraperEvent` enum and an `EventSink`
  port, with `NoopEventSink` (the zero-overhead default) and `LogEventSink`. Configurable
  via `with_event_sink()`.
- Crate metadata for crates.io publishing: `rust-version` (MSRV 1.95), an `include`
  allowlist for the published package, and `docs.rs` all-features configuration.

### Changed

- **Breaking:** the crate has been renamed from `rs-cloudscraper` to `stealthscraper-rs`
  (repository `ypno/stealthscraper-rs`). Update your `Cargo.toml` dependency name and any
  `use rs_cloudscraper::…` imports to `use stealthscraper_rs::…`.
- Migrated the TLS/JA4 impersonation client from the fully-yanked `rquest` / `rquest-util`
  to their maintained successors `wreq` 5.3.0 / `wreq-util` 2.2.6. The public API is
  unchanged.
- `wreq-util` (GPL-3.0) is now optional and gated behind the `browser` feature, and
  `deny.toml` scopes the GPL allowance to it via a per-crate exception — so the default
  build stays permissive (MIT + Apache-2.0) and the license gate still flags any GPL crate
  that enters the default dependency tree.
- **Breaking:** `CloudScraperBuilder::upstream_proxy()` now *appends* to the rotation pool
  instead of replacing the previous value. Call it once per proxy, or use `with_proxies()` /
  `with_geo_proxies()`.
- `Outcome::Challenged` (a challenge that ultimately cleared) now counts as a success in
  `DomainState`; `cooldown_until` is set only by `Outcome::RateLimited` and cleared by every
  other outcome.
- Proxy diagnostics now use the `log` crate instead of `eprintln!`; the unused `chrono`
  dependency was removed.

### Fixed

- `navigator.languages` is now derived from the active locale (or the profile's
  `Accept-Language`) instead of a hardcoded `["en-US","en"]`, and is never emitted as an
  empty array.
- Challenge detection no longer classifies generic "rate limited" / "too many requests"
  text on non-Cloudflare pages as `RateLimited` (an HTTP 429 status remains unconditional),
  avoiding spurious cooldowns on innocent hosts.
- `record_outcome` is now an atomic read-modify-write (`StateStore::update`), preventing
  lost updates when a scraper is shared across threads.
- On proxy-pool exhaustion, `solve_challenge` emits `SolveFailed` and records the outcome
  before returning, instead of short-circuiting with an unrecorded error.

### Security

- Proxy credentials are redacted: a `user:password@` upstream URL is stripped of its
  userinfo before reaching logs/events (`ProxyRotated`) or the persisted
  `DomainState.last_proxy`. The credentialed URL is used only for the connection itself.
- The MITM proxy handlers no longer panic on untrusted data: malformed upstream headers, an
  invalid request method, or a certificate-generation failure now yield a `4xx`/`5xx` (or a
  mapped error) instead of aborting the connection task.
- Added `#![forbid(unsafe_code)]` — the crate contains zero first-party `unsafe`, now
  enforced at compile time.
- `DomainState` and `BrowserProfile` deserialization uses `#[serde(deny_unknown_fields)]`.
- Refreshed the dependency tree (`cargo update`), pulling in `quinn-proto` 0.11.15 to resolve
  **RUSTSEC-2026-0185** (remote memory exhaustion in QUIC stream reassembly, reached only via
  the `reqwest` dev-dependency). The remaining `cargo audit` findings are non-blocking
  warnings: `lru` 0.13.0 (RUSTSEC-2026-0002, unsound `IterMut`) is pinned transitively by
  `wreq` 5.3.0 and clears once `wreq` 6.x leaves release-candidate status.

## [0.3.0] - 2026-05-23

### Added

- Configuration support for the scraper builder.

### Fixed

- Headless Chrome idle timeout that killed the browser during long-lived sessions.

## [0.2.0] - 2025

See the [v0.2.0 release notes](https://github.com/ypno/stealthscraper-rs/releases/tag/v0.2.0).

## [0.1.0] - 2025

Initial release. See the [v0.1.0 release notes](https://github.com/ypno/stealthscraper-rs/releases/tag/v0.1.0).

[Unreleased]: https://github.com/ypno/stealthscraper-rs/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ypno/stealthscraper-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ypno/stealthscraper-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ypno/stealthscraper-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ypno/stealthscraper-rs/releases/tag/v0.1.0
