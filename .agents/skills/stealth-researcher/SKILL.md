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

## Daemon browser lifetime

`headless_chrome::LaunchOptions::idle_browser_timeout` defaults to a short interval (crate default ~30 s; `rs-cloudscraper` historically set 120 s). In a long-lived daemon where the browser is needed only *sporadically* (auth refresh, Cloudflare challenge, session revalidation), the event loop times out and the `Browser` is torn down mid-session, breaking the TLS-spoofing proxy for every subsequent request.

- Set an effectively-daemon-lifetime timeout — e.g. `Duration::from_secs(60 * 60 * 24 * 365 * 10)` (10 y, well within `Instant` range so the internal `recv_timeout` cannot overflow).
- Never `Duration::MAX` — some `recv_timeout` impls do `Instant::now() + timeout` and panic on overflow.
- Document *why* with a named constant (e.g. `BROWSER_IDLE_TIMEOUT`) — not a magic literal. Explain the daemon use case in the doc-comment so future readers don't reset it to a "reasonable" 60 s.
