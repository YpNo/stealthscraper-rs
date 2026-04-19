# Workflow: Feature Implementation Cycle
Description: A strict end-to-end process for building features with a Senior Architect's oversight.

## Steps

1. **Design Phase**: 
    - Analyze the request against the [Hexagonal Architecture](file:///rules/architecture.md).
    - Identify Domain entities and determine the necessary Ports (Traits).
    
2. **Scaffolding**: 
    - **Domain**: Create/Update pure data models and state machines.
    - **Application**: Define use cases as service logic.
    - **Infrastructure**: Implement I/O adapters (Transport, Storage).
    
3. **Security Check**: 
    - Run `cargo audit` to detect vulnerable crates.
    - Verify that no hardcoded secrets or sensitive telemetry are exposed.
    
4. **Validation**:
    - **Unit Tests**: Run `cargo test` to verify domain logic in isolation.
    - **Integration Tests**: Run `cargo test --test '*' ` to verify adapter interactions.
    
5. **Quality Check**: 
    - Run `cargo clippy --all-targets --all-features -- -D warnings` for zero-lint policy.
    - Run `cargo fmt` for stylistic consistency.
    
6. **Documentation**:
    - Update public API documentation comments (`///`).
    - Run `cargo-rdme` to sync the `README.md` if the public surface changed.
    
7. **Final Report**: 
    - Provide a concise summary of changes.
    - Confirm all security and quality gates passed successfully.
