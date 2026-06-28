# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
