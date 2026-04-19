# Workflow: Stealth Patch Cycle
Description: Sensitive workflow for diagnosing and fixing fingerprint leaks in the stealth proxy.

## Steps

1. **Diagnosis Phase**:
    - Identify the leak source (e.g., `navigator.webdriver`, WebGL, Canvas).
    - Use the `stealth-researcher` skill to verify the detection site result (CreepJS/SannySoft).
    
2. **JA4 Audit**:
    - Check if the TLS signature has drifted from the selected `BrowserProfile`.
    - Run `cargo run --example diag_tls` to inspect the raw `ClientHello`.
    
3. **Injection Patching**:
    - Modify the stealth scripts in `src/stealth/` to improve DOM masking.
    - Ensure zero-overhead by keeping JS hooks concise and efficient.
    
4. **Regression Testing**:
    - Run the full suite of "Stealth Verifiers".
    - **Crucial**: Ensure patching one leak didn't inadvertently introduce another (e.g., a detection for the patch script itself).
    
5. **Performance Benchmarking**:
    - Verify that the MITM proxy latency hasn't significantly increased.
    - Check streaming throughput for large POST payloads.
    
6. **Final Report**:
    - Detailed diff of the fingerprint before and after the patch.
    - Confirmation that the bypass is restored against target bot-protections.
