# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Migrated the TLS/JA4 impersonation client from `rquest`/`rquest-util` to their
  maintained successors `wreq` 5.3.0 / `wreq-util` 2.2.6. All `rquest` versions
  were yanked from crates.io, which made the crate uninstallable for downstream
  consumers. The public API is unchanged.
- `wreq-util` (GPL-3.0) is now an optional dependency gated behind the `browser`
  feature, so the default build stays fully permissive (MIT + Apache-2.0).

### Added

- Per-domain session state (`state` module): a serializable `DomainState`
  (last outcome, last proxy, success/failure tallies, rate-limit cooldown) plus a
  `StateStore` port. `InMemoryStateStore` ships by default; the durable
  `RedbStateStore` is gated behind the new `persistence` feature (pure-Rust
  `redb`, no C toolchain). `CloudScraper` gains `with_state_store()` and
  records outcomes automatically in `solve_challenge` (per host, via the tab
  URL), exposing `domain_state()`, `record_outcome()`, and `cooldown_remaining()`.
- Upstream proxy pool with rotation (`proxy_pool` module): `ProxyPool` +
  `RotationStrategy` (`RoundRobin`, `Random`) with per-endpoint health tracking.
  Builder gains `with_proxies()` and `proxy_strategy()` (and `upstream_proxy()`
  now feeds the pool). The MITM proxy's upstream client is hot-swappable
  (`TlsSpoofingProxy::set_upstream_client`), so rotation changes the egress IP
  without relaunching Chrome — it keeps talking to the same local MITM port.
- Hard blocks now trigger proxy rotation: `Action::RotateProxy` plus
  `MitigationPolicy::with_proxy_rotation`; `AccessDenied` rotates to the next
  healthy proxy (reloading the page) instead of failing immediately, falling back
  to failure only once the pool is exhausted.
- Bot-protection challenge detection and mitigation (`challenge` module): a pure,
  dependency-free `detect()` that classifies a response/page into a
  `ChallengeSignal` (`Turnstile`, `JsChallenge`, `IuamV1`, `AccessDenied`,
  `RateLimited`, `Unknown`, `None`), and a `MitigationPolicy` that decides the
  retry `Action` with exponential back-off. Wired into `CloudScraper` via
  `detect_challenge()` / `solve_challenge()` (the latter reuses `GenericSolver`
  for interactive Turnstile) and a `with_max_challenge_attempts()` builder toggle.
- Crate metadata for crates.io publishing: `rust-version` (MSRV 1.95), `include`
  allowlist for the published package, and `docs.rs` `all-features` build config.
- `CHANGELOG.md` following the Keep a Changelog format.

## [0.3.0] - 2026-05-23

### Added

- Configuration support for the scraper builder.

### Fixed

- Headless Chrome timeout when a long-lived session is required.

## [0.2.0] - 2025

See the [v0.2.0 release](https://github.com/ypno/rs-cloudscraper/releases/tag/v0.2.0).

## [0.1.0] - 2025

Initial release. See the [v0.1.0 release](https://github.com/ypno/rs-cloudscraper/releases/tag/v0.1.0).

[Unreleased]: https://github.com/ypno/rs-cloudscraper/compare/v0.2.0...HEAD
[0.3.0]: https://github.com/ypno/rs-cloudscraper/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ypno/rs-cloudscraper/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ypno/rs-cloudscraper/releases/tag/v0.1.0
