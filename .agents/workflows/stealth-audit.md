# Workflow: Stealth & Signature Audit
Description: Specialized workflow for verifying browser fingerprint integrity and JA4 handshake consistency.

## Steps

1. **Fingerprint Selection**:
    - Select a `BrowserProfile` from `src/profile/`.
    - Document the target JA4 signature and hardware characteristics.

2. **Handshake Verification**:
    - Run the `TlsSpoofingProxy` and capture the `ClientHello`.
    - Use a tool like `ja4` (if available) or manual inspection to verify extensions (ALPN, SNI, KeyShare) match the profile.

3. **CDP Hook Integrity**:
    - Inject JS hooks from `src/stealth/`.
    - Run the stealth test suite against bot-detection sites (CreepJS, SannySoft).
    - Verify that `navigator.webdriver` is false and WebGL/Canvas fingerprints are consistent with the profile.

4. **Side-Effect Audit**:
    - Check for detectable side-effects of JS injection (e.g., `toString` modifications).
    - Use `Proxy` objects correctly to avoid detection.

5. **Regression Test**:
    - Ensure that performance optimizations (streaming `Body`) haven't leaked any system characteristics.

6. **Final Report**:
    - Confirm the JA4 consistency and stealth integrity.
    - Document any discovered leaks or signature mismatches.
