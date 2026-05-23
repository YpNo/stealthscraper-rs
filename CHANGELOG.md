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

- Crate metadata for crates.io publishing: `rust-version` (MSRV 1.85), `include`
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
