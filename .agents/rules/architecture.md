# Hexagonal Architecture & Core Principles
**Role**: Senior Rust Architect

## Architectural Guidelines

- **Domain Layer (Pure)**: 
    - Must be free of I/O and external transport dependencies.
    - Contains: Device state machines, Browser Profile definitions, SSE event enums.
    
- **Application Layer (Use Cases)**: 
    - Orchestrates logic using Ports (Traits).
    - Contains: MFA challenge-response flows, Stealth navigation sequences, Re-attachment logic.
    
- **Infrastructure Layer (Adapters)**: 
    - Implementation of Output Ports using specialized crates.
    - **`rs-arlo`**: `imap-tokio` for OTP fetching, `reqwest` for the Arlo fallback client.
    - **`stealthscraper-rs`**: `wreq` for JA4 forging, a first-party async CDP client (`cdp`) for browser automation, `hyper` for the MITM proxy, `btls` for TLS termination.

- **Error Handling**: 
    - Use `thiserror` for all library/domain errors.
    - Use `anyhow` strictly in binaries and integration tests.

## Specialized Expertise (Agent Skills)

When working in this codebase, the following specialized skills are activated:
- **`rust-core`**: Governs hexagonal boilerplate, crate management, and instrumentation.
- **`protocol-specialist`**: Governs Arlo-specific API emulation and SSE actor management.
- **`stealth-researcher`**: Governs JA4 auditing, CDP stealth hooks, and noise injection consistency.
- **`mitm-engineer`**: Governs Hyper/H2 frame manipulation and TLS termination logic.

## Coding Style & Safety

- **Instrumentation**: Use the `log` crate, never `tracing` or `eprintln!` — `tracing` is not a dependency of this crate. `ScraperEvent`/`EventSink` carries structured events; `LogEventSink` bridges them into `log`.
- **Explicit Returns**: Prefer `impl Trait` for opaque return types.
- **Defensive Coding**: Avoid `unwrap()`. Use `.expect()` with a safety disclaimer.
- **Unsafe Boundary**: First-party code is `#![forbid(unsafe_code)]`, so there are no first-party `unsafe` blocks to document. All FFI lives in audited dependencies (`btls`/`btls-sys`, `wreq`, and `command-fds` for the one `dup2` the pipe launch needs).
