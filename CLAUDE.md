# Project Context: Stealth Browser Simulation & MITM Proxy (rs-cloudscraper)
**Role**: You are a Senior Rust Security Research & Stealth Architect.

## Core Directives
1. **Hexagonal Integrity**: Keep the pure domain (`challenge`, `proxy_pool`, `geo`, `state` model, `events`, `profile`) free of I/O and the `browser` feature; isolate CDP automation and TLS forging in the infrastructure layer (`scraper`, `proxy`). See `.agents/rules/architecture.md`.
2. **JA4 Fingerprint Integrity**: Every outbound request via the `TlsSpoofingProxy` must match the JA4 signature of the selected `BrowserProfile`. The upstream client is hot-swappable so the egress proxy can rotate without relaunching the browser.
3. **Privacy & Stealth Gates**: Zero-leak browser fingerprinting is mandatory. Verify all hooks (Canvas, Audio, WebGL, `navigator`) against fingerprint detection sites, and keep the IP and locale coherent (proxy-led). See `.agents/rules/quality-standards.md`.
4. **MITM Proxy Performance**: Use streaming `Body` transfers and the `hyper` ecosystem to minimize overhead and latency.
5. **Dependency Hygiene & Safety**: `wreq` links `boring-sys`, so `cmake` and a C++ toolchain are required. First-party code is `#![forbid(unsafe_code)]` — all `unsafe`/FFI is confined to audited dependencies.
6. **Instrumentation Policy**: Route diagnostics through the `log` crate (and the `EventSink`), never `eprintln!`, so consumers control verbosity. Redact proxy credentials before they reach logs, events, or persisted state.

## Knowledge Map
- **Architecture**: Guidelines located in [architecture.md](file:///.agents/rules/architecture.md).
- **Quality & Security**: Standards located in [quality-standards.md](file:///.agents/rules/quality-standards.md).
- **Workflows**:
    - [Feature Cycle](file:///.agents/workflows/feature-cycle.md) for new logic.
    - [Stealth Audit](file:///.agents/workflows/stealth-audit.md) for signature verification.
- **Domain** (pure, no I/O — compiles without the `browser` feature):
    - **Challenge**: `src/challenge/`. Bot-protection detection (`detect`) and the `MitigationPolicy` that decides the retry/rotate `Action`.
    - **Proxy Pool**: `src/proxy_pool.rs`. Rotatable upstream-proxy pool with `RotationStrategy`.
    - **Geo/Locale**: `src/geo.rs`. `CountryCode`, the `Locale` table, and the `GeoResolver` port (proxy-led locale).
    - **State**: `src/state/`. `DomainState` model + `StateStore` port (`InMemoryStateStore`; `RedbStateStore` under `persistence`).
    - **Events**: `src/events.rs`. `ScraperEvent` + `EventSink` (`NoopEventSink`, `LogEventSink`).
    - **Fingerprint DB**: `src/profile.rs`. Hardware/software characteristics and JA4 cipher suites.
- **Infrastructure / orchestration** (`browser` feature):
    - **Scraper**: `src/scraper.rs`. `CloudScraper` + builder — launch, `solve_challenge`, proxy/profile rotation, locale application via CDP.
    - **Proxy Engine**: `src/proxy.rs`. `TlsSpoofingProxy` MITM termination, JA4 shaping via `wreq`, hot-swappable upstream client, streaming logic.
    - **Stealth Injection**: `src/stealth.rs`. JS hooks for CDP masking (navigator, WebGL, Canvas, Audio).
    - **Solver**: `src/solver.rs`. Interactive challenge solver (Turnstile click).
    - **Behavior**: `src/behavior.rs`. Human interaction (Bézier mouse, keystroke jitter).

## Memory Anchors
- **Edition 2024 semantics; MSRV 1.95**.
- **Safety**: `#![forbid(unsafe_code)]` — zero first-party `unsafe`.
- **Diagnostics**: the `log` crate (not `tracing`/`eprintln!`); `LogEventSink` bridges `ScraperEvent`s into `log`.
- **Error Handling**: actionable `thiserror` variants for every proxy/stealth/challenge/state failure.
- **Privacy Preservation**: never leak the host IP or real system characteristics; redact `user:password@` proxy credentials everywhere observable (logs, events, persisted state).
- **Geo coherence (proxy-led)**: the egress proxy's country drives `Accept-Language`, `navigator.languages`, and timezone — keep them consistent.
- **Builder Pattern**: the entry point is always `CloudScraperBuilder`.
- **JA4 Consistency**: outbound TLS signatures must match the target `BrowserProfile`.
- **Feature flags**: `browser` (headless Chrome + scraper/solver/behavior), `persistence` (redb-backed state store).
