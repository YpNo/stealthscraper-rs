---
name: stealth-researcher
description: High-sensitivity skill for fingerprinting evasion and network stealth.
---
# Stealth Researcher Skill

## JA4 / TLS Auditing
- When modifying the `TlsSpoofingProxy` or `BrowserProfile`:
  1. Verify the outbound JA4 signature matches the profile's expected fingerprint.
  2. Audit `ClientHello` extensions (ALPN, SNI, KeyShare) for consistency.

## CDP Stealth Injection
- When adding JavaScript hooks:
  1. Ensure the hook is injected *before* the page starts loading.
  2. Verify that the hook does not introduce detectable side-effects (e.g., `toString` modifications).
  3. Check against CreepJS and SannySoft periodically.

## Behavior Simulation
- Use Bezier curves for mouse movements to avoid linear-path detection.
- Implement variable keystroke delays based on human psychological patterns.
