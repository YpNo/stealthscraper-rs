---
name: rust-core
description: Specialized skill for managing the Rust ecosystem, audits, and hexagonal boilerplate.
---
# Rust Core Skill

## Dependency Management
When adding a dependency:
1. Run `cargo search <crate>` to find the latest version.
2. Check for known vulnerabilities using `cargo audit`.
3. Verify if the crate supports `no_std` if building for the domain layer (to maintain purity).
4. Prefer standard library over crates where the implementation is trivial.

## Hexagonal Boilerplate
- **Trait Definition**: Always define Ports as traits in the Domain/Application layer.
- **Dependency Injection**: Use `Box<dyn Trait>` or generics to inject Infrastructure adapters into Application services.

## Instrumentation
- Prefer `tracing::instrument` for all async functions.
- Include relevant fields in spans (e.g., `device_id`, `profile_name`).

## Testing Strategy
- **Unit Tests**: Place in the same file using `mod tests` with `#[cfg(test)]`.
- **Mocking**: Use `mockall` or manual trait implementations for mocking infrastructure in unit tests.
