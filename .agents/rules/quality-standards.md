# Quality Standards & Security Gates
**Role**: Senior Rust Security & Quality Engineer

## Quality Gates

- **Zero-Warning Policy**: All code must pass `cargo clippy` and `cargo fmt`.
- **Documentation Integrity**: Public APIs must have comprehensive docstrings; sync via `cargo-rdme`.
- **Testing Thresholds**: Mandatory unit tests for Domain logic; integration tests for Infrastructure.

## Security Gates

- **Dependency Auditing**: `cargo audit` must be run frequently.
- **Secret Management**: **Zero-Secret Policy**. Use `config.toml` or Env vars only.
- **Memory Safety**: `unsafe` is forbidden unless documented with `// SAFETY:` and strictly audited.

## Specialized Skill Enforcement

Quality and security are governed by specialized Agent Skills:
- **`rust-core`**: Handles crate security and architectural safety benchmarks.
- **`stealth-researcher`**: Mandates privacy leak verification and JA4 consistency checks.
- **`protocol-specialist`**: (rs-arlo) Mandates protocol fidelity checks for all undocumented header manipulations.

## Stealth & Privacy Gates (Special Focus)

- **Privacy Leak Prevention**: Verify against public fingerprinting test sites.
- **JA4 Consistency**: Outbound TLS signatures must match the target `BrowserProfile`.
