# Implementation Plan: Lean Dependencies, Dual-Mode Sessions & Stealth Hardening

**Status:** proposed · **Author:** Senior Rust Architect review · **Date:** 2026-09-23
**Crate:** `stealthscraper-rs` v0.4.0 → v0.5.0 (breaking)

This plan responds to four goals: (1) usage performance & RAM, (2) security, (3) reduce blast
radius by shedding crates / replacing them with dedicated code where it pays off, and (4) a
browser⇄HTTP session model that carries the full fingerprint across a mode switch. It also folds
in new anti-bot techniques worth adopting.

Decisions locked with the maintainer are marked **[DECIDED]**.

---

## 0. Findings that drive the plan

Evidence gathered from the current tree (`src/`, `Cargo.lock`, and the pinned dep sources).

### 0.1 Dependency blast radius
- **160 crates with *no* features**, 198 with `browser`, 199 with `browser,persistence`.
- Three C/asm crypto backends link **even in the default build**: BoringSSL (`wreq→boring2`),
  ring (`rustls`/`tokio-rustls`, used only for the MITM server leg), aws-lc (`rcgen`, cert minting).
- **Two rustls crypto providers are linked simultaneously.** The manifest asks for
  `tokio-rustls = { features = ["ring"] }` and `rcgen = { features = ["aws_lc_rs"] }`, but neither
  sets `default-features = false`. Measured, the real culprit is **`tokio-rustls`**, not `rcgen`:
  its default feature set includes `aws_lc_rs`, which turns on `rustls/aws_lc_rs`; the explicit
  `features = ["ring"]` merely adds ring *on top*. `rcgen`'s own default is already
  `["crypto","pem","ring"]`, so its `aws_lc_rs` is purely additive.
  **Verified:** dropping `tokio-rustls` default features removes `aws-lc-rs` + `aws-lc-sys` from
  the normal-dependency graph entirely (199 → 197 crates, and one whole vendored cmake C build).
  Changing `rcgen` alone changes nothing. See P0 for the exact edit and its one caveat.
- Duplicate trees carried: `cookie_store` 0.21 **and** 0.22, `rand` 0.9 **and** 0.10,
  `thiserror` 1 **and** 2, `getrandom` 0.2/0.3/0.4, `socket2` 0.5/0.6.
- The rustls/rcgen cluster is cleanly severable: `ring`, `aws-lc-rs`, `aws-lc-sys`, `rustls`,
  `rustls-webpki`, `rustls-pki-types`, `yasna`, `pem` are reachable **only** via `rcgen` and
  `tokio-rustls`, and nothing else in the crate depends on them (verified by reverse-dep tree).

### 0.2 Declared-but-unused / thin dependencies (verified by grep over `src`)
| Crate | Direct uses | Verdict |
|---|---|---|
| `cookie_store` | **0** | **Remove** — never referenced; `wreq` has its own cookie jar. |
| `regex` | **0** | **Remove** — detection uses plain `contains`; pulls `regex-automata`+`aho-corasick`. |
| `tokio-socks` | **0** | **Remove** as a *direct* dep — only `wreq` needs it transitively. |
| `rustls-pki-types` | **0** direct | Only needed while we keep rustls for the MITM leg (see §3). |
| `bytes` | 0 real | **Remove** — no `Bytes` used in first-party code. |
| `http-body-util` | 1 (`BodyExt`) | Keep (needed for streaming). |
| `hyper-util` | 1 | Keep. |
| `rand_distr` | 1 (`Normal`) | **Replace** with a 6-line Box–Muller; drops the dep. |

### 0.3 Correctness / stealth defects found while reading
1. **JA4 ↔ UA mismatch (HIGH).** `build_impersonation_client` (`scraper.rs:42`) matches on
   `"Chrome/120"`, but every UA in `BrowserProfile::random()` is Chrome **124–126**. So the
   `else` branch always fires → every request emits the **Chrome120** fingerprint while the UA
   says 124–126. This is exactly the JA4 inconsistency CLAUDE.md forbids.
2. **`wreq-util` is GPL-3.0** and caps at Chrome 137. It's the only GPL in the tree and it taints
   the `browser` build's license posture. Its whole job is that one `.emulation()` call.
3. **`--enable-automation` is always on.** `headless_chrome`'s `DEFAULT_ARGS` inject
   `--enable-automation` (sets `navigator.webdriver=true` at the C++ level, exposes the
   automation info-bar) and the code never disables default args. The stealth JS papers over
   `webdriver` *after* the fact, but the launch flag is itself a tell.
4. **Debug port is scannable.** `headless_chrome` launches with `--remote-debugging-port=<tcp>`
   on loopback. A page that fetches `http://localhost:<port>/json` (or the range) can detect the
   CDP endpoint. `--remote-debugging-pipe` removes the port entirely.
5. **Runtime.enable detection vector is NOT actually blocked.** CONTEXT.md claims "Blocks the
   `Runtime.enable` detection vector," but `headless_chrome` calls `Runtime::Enable` (tab
   `mod.rs:1403`) and `Page.enable`/`Page.SetLifecycleEventsEnabled` on **every** tab creation.
   Creepjs/Cloudflare detect the `Runtime.enable` CDP leak. The claim is currently false.
6. **Stealth JS is detectable by shape.** Getters defined with arrow functions whose
   `.toString()` doesn't read `native code`; `navigator.plugins → [1,2,3]` (real is
   `PluginArray` of `Plugin`); `Function.prototype.toString` not patched, so every proxied
   `getParameter`/`toDataURL` is unmaskable via `.toString()`. Canvas/Audio noise is applied on
   **every** read (real hardware is deterministic within a session) — itself a signal.
7. **Blocking CDP on the async runtime.** `solve_challenge` and all `human_*` helpers use
   `std::thread::sleep` and block on CDP I/O; the whole `headless_chrome` API is sync (one OS
   thread per tab). Correct usage requires `spawn_blocking`, which the API forces on callers.

### 0.4 What `wreq` already gives us (so we don't hand-roll it)
`wreq` v5 publicly exposes `EmulationProvider`, `EmulationProviderFactory`, `Http1Config`,
`Http2Config`, `TlsConfig`, and re-exports the boring2 primitives (`SslCurve`, `ExtensionType`,
`CertCompressionAlgorithm`, `CertStore`, `CertStoreBuilder`, `Identity`, `TlsInfo`) — all under
**Apache-2.0**. This is the seam that lets us build our own emulation table without `wreq-util`.

---

## 1. Guiding principles for "crate vs. hand-rolled"

Keep a crate when it owns **hard, security-sensitive, or high-churn** complexity: `wreq`
(BoringSSL TLS + HTTP/2 emulation), `hyper` (HTTP/1 server state machine), `tokio`, `serde`,
`boring` (crypto). Replace a crate when it is **thin, misfit, or a liability**: a Gaussian
sampler, an unused regex engine, a sync/thread-per-tab CDP client whose defaults fight our
stealth goals, a GPL fingerprint table we can't tune. We do **not** hand-roll TLS or crypto.

---

## 2. Emulation table — drop `wreq-util`, own the fingerprint **[DECIDED: own table]**

**Why:** fixes the JA4↔UA mismatch (§0.3.1), removes the only GPL dep, lifts the Chrome-137 cap,
and makes the fingerprint a first-class, versioned artifact tied to the browser we actually launch.

**Design.** New pure module `src/profile/emulation.rs`:
- `struct ChromeEmulation { version: u16 }` implementing `wreq::EmulationProviderFactory`, built
  from data: cipher list, `SslCurve` order, extension order + GREASE, ALPS/ALPN, cert-compression
  (brotli), and an `Http2Config` (HEADER_TABLE_SIZE, ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS,
  INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE, WINDOW_UPDATE increment, header pseudo-order, priority).
- One small `const` data block per supported Chrome major (start: 124, 131, 133, latest-stable),
  plus a Safari block. Values sourced from published Chrome JA4/Akamai fingerprints; a unit test
  asserts the emitted JA4 string per version so regressions are caught in CI.
- `BrowserProfile` gains a parsed `browser: BrowserKind { Chrome(u16), Safari(semver) }` derived
  from the UA (single source of truth), so the client build **cannot** disagree with the UA again.
- `build_impersonation_client` selects the emulation from `profile.browser`, not string `contains`.

### 2.1 Data provenance — the constraint that re-scoped this phase

The table cannot be populated by copying `wreq-util` (GPL-3.0; removing it is
the point) nor written from memory: a single cipher out of order changes the JA4
hash entirely, yielding a fingerprint matching **no real browser** — strictly
worse than today, where the data is at least internally correct.

So P1 was split. **P1a (done)** builds the measurement apparatus: a JA4
implementation validated against independently published values, plus proxy
capture so any browser's real fingerprint can be observed directly. **P1b**
populates the table from those captures, one verified entry per version.

To add a version: point the browser at the proxy with `LogJa4Observer`
attached, browse, and read the JA4 from the logs. This is strictly better than
a transcribed table — it is reproducible, legally clean, and not capped at
whatever version an upstream crate happens to support.

**Removes:** `wreq-util` (and its GPL). **Adds:** ~1 data file, no new deps.
**Ongoing cost:** ~1 small data block per Chrome release we choose to track (self-service, no
upstream dependency). H2 SETTINGS/WINDOW_UPDATE parity (a quality gate in CLAUDE.md) becomes a
tested invariant instead of an opaque enum.

---

## 3. Crypto backends — BoringSSL vs rustls+ring **[DECIDED: role-based split]**

### 3.1 The choice is per-role, not global

**For the egress/impersonation leg there is no choice: it must be BoringSSL.** rustls
*structurally cannot* forge a JA3/JA4 fingerprint — it exposes a constrained `cipher_suites` list
and nothing else: no extension ordering, no GREASE control, no arbitrary curve order, no cert
compression, no ALPS. This is a deliberate design stance (rustls aims to be one correct,
opinionated TLS), not a missing feature. Every impersonation tool in existence
(curl-impersonate, wreq/rquest, tls-client) uses BoringSSL or patched NSS for this reason.

So BoringSSL is **permanent** in `stealthscraper-rs`. The only open question is what else we link
alongside it.

### 3.2 Correction: boring and rustls do **not** conflict

An earlier assumption was that mixing them caused link-level friction. Verified: `boring-sys2`
vendors its own BoringSSL (`deps/` + `patches/`, static, namespaced build config) and `aws-lc-sys`
vendors likewise. This is **not** the historical `boring-sys` vs `openssl-sys` symbol collision.
The cost of running both is **weight, two cmake C builds, and two CVE feeds — not correctness.**
That lowers the risk of the boring-only move below from High to Medium.

### 3.3 Target architecture: one stack per crate, two in the binary

| Role | Backend | Rationale |
|---|---|---|
| stealthscraper **egress** | **BoringSSL** | Only option; impersonation impossible otherwise. |
| stealthscraper **MITM/cert** | **BoringSSL** | boring is *already* linked here — adding rustls is pure additive weight. |
| `arlo-rs` / `imap-rs` | **rustls + ring** | Keep as-is (see §3.4). |

Two stacks in the final binary is the **correct** outcome, not a compromise: the binary links two
because it genuinely does two different jobs. What we eliminate is the redundant *third* (aws-lc)
and the unnecessary *second-within-one-crate* (rustls inside stealthscraper).

### 3.4 Why NOT migrate `arlo-rs` / `imap-rs` to BoringSSL

Considered (it is the only coherent route to a single stack, since rustls-everywhere is
impossible) and **rejected**:

1. **The security argument favours rustls, in precisely the high-risk layer.** TLS CVEs cluster in
   the protocol/parsing/state-machine layer (Heartbleed, CCS injection, state confusion), not in
   the primitives. rustls's state machine is safe Rust; BoringSSL's is C. Both use asm primitives
   (ring and aws-lc are asm too) — so the rustls advantage is real but narrower than "Rust = safe".
2. **Threat-model asymmetry.** stealthscraper's boring talks to deliberately hostile endpoints —
   but it has no alternative. `arlo-rs`/`imap-rs` talk to Arlo's API and an IMAP server with no
   impersonation requirement; moving them to boring takes on C-parser risk for zero benefit.
3. **Coupling.** Using boring directly elsewhere pins those crates to whatever `boring2` version
   `wreq` demands, coupling IMAP/Arlo TLS to a fast-moving scraping fork's release cadence.
4. **Ecosystem + optionality.** reqwest / tokio-tungstenite / hyper have first-class rustls
   support; boring means `hyper-boring` or custom connectors — more bespoke code, the opposite of
   the blast-radius goal. Keeping them on rustls also lets them build standalone with **no
   cmake/C++ toolchain**; only the scraping crate pays that tax.

### 3.5 Execution

**P0 — drop aws-lc (measured: −2 crates + one vendored cmake C build).** The edit is on
**`tokio-rustls`**, not `rcgen` (see §0.1):

```toml
tokio-rustls = { version = "0.26.4", default-features = false, features = ["ring", "logging", "tls12"] }
rcgen        = "0.14.8"   # default = ["crypto","pem","ring"]; the aws_lc_rs feature was additive
```

**Status: ✅ IMPLEMENTED AND VERIFIED** (in the `rust-build` distrobox, see §11):
- `cargo check` green on **all three** feature combos: default, `persistence`, `browser,persistence`.
- `cargo clippy --all-targets -- -D warnings` clean (zero-warning gate holds).
- `cargo test --features persistence`: **65 passed, 0 failed**, including
  `proxy::tests::test_proxy_http_and_https_forwarding` — a real TLS handshake through the MITM
  proxy, so the ring provider is functionally validated on the MITM leg, not merely compiled.
- aws-lc **gone** from the normal-dependency graph (0 occurrences). Crate count
  199 → **197** (`browser,persistence`) and 160 → **158** (default).

A previously suspected risk — that `rustls`'s `std` feature is not implied by `ring`/`logging`/
`tls12` and that `tokio-rustls` exposes no `std` passthrough — **did not materialise**; feature
unification across the graph supplies it in every combination tested. No explicit `rustls` direct
dependency is needed. (If a future dependency change ever breaks this, the fix is
`rustls = { version = "0.23", default-features = false, features = ["std","ring","logging","tls12"] }`.)

*Not covered:* the `browser`-gated tests need a real Chrome binary and were not run here.

*Note:* the dev-dependency `reqwest` still pulls `rustls` + aws-lc for the test build (dev-deps are
excluded from the shipped graph, so consumers are unaffected). Switching that dev-dep to a ring
provider is optional tidy-up.

**P3 (spike, Medium risk).** Move MITM TLS termination and cert minting off rustls+rcgen onto
`wreq`'s re-exported boring (`boring::ssl::SslAcceptor`, `boring::x509` for an on-the-fly leaf
signed by a persistent CA). The cut is clean — per §0.1, `rustls`, `tokio-rustls`, `rcgen`,
`rustls-pki-types`, `rustls-webpki`, `ring`, `yasna`, `pem` are reachable only through those two
direct deps. Validate by building the **consumer** binary (`arlo-camera-streamer-rs`), which
legitimately keeps rustls for the Arlo/IMAP side.

If the spike stalls, P0 has already banked the aws-lc win and the status quo (boring for egress +
ring for the local leg) is an acceptable resting state.

**Either way — persistent CA.** Replace the current **per-CONNECT `generate_simple_self_signed`**
(`proxy.rs:601`): today every HTTPS tunnel mints a fresh cert on a `spawn_blocking`, a real
per-request CPU + latency cost. One cached CA + per-host cached leaves is both faster and more
browser-like. This is independent of which backend wins.

---

## 4. CDP client — replace `headless_chrome` with a minimal async client **[DECIDED: own async CDP]**

**Why:** kills defects §0.3.3/.4/.5/.7 at the source, removes ~38 crates
(`auto_generate_cdp`, `tungstenite`+`tokio-tungstenite` dupes, `which`, `winreg`, `walkdir`,
`ureq`, `derive_builder`, `tempfile`, a second `rand`, `regex`, …), and gives us total control of
which CDP domains are enabled (no forced `Runtime.enable`).

**Scope (`src/cdp/`, browser feature, ~800–1200 LOC):**
- `launch.rs` — spawn Chrome ourselves with a curated arg set: **omit** `--enable-automation`,
  add `--disable-blink-features=AutomationControlled`, `--remote-debugging-pipe` (**no TCP port**),
  ephemeral `--user-data-dir`, `--no-first-run`, locale/UA/window flags from the profile.
- `transport.rs` — CDP over the pipe (fd 3/4) framed JSON, or a WebSocket fallback; one tokio task
  demuxes responses (by `id`) and events (by `method`) over `oneshot`/`broadcast`. **Fully async**;
  no thread-per-tab, no `spawn_blocking` forced on callers.
- `session.rs` — typed wrappers for only the ~20 methods we use: `Target.createTarget`/
  `attachToTarget` with `flatten:true`, `Page.addScriptToEvaluateOnNewDocument`,
  `Page.navigate`/`lifecycleEvent`, `Runtime.evaluate` (only when *we* choose),
  `Emulation.setUserAgentOverride`/`setTimezoneOverride`/`setLocaleOverride`/
  `setDeviceMetricsOverride`, `Network.setCookies`/`getAllCookies`, `Input.dispatchMouseEvent`/
  `dispatchKeyEvent`. We **never** blanket-enable `Runtime`/`Log`.
- Human input (`behavior.rs`) moves onto `Input.dispatchMouseEvent` with proper `async` sleeps
  (`tokio::time::sleep`), not `std::thread::sleep`.

This is the largest single-module effort; it's also what unblocks §5 and §6. Non-goal: full CDP
coverage — we hand-type only what we use and add methods as needed.

---

## 5. Dual-mode session: **start Browser → demote to HTTP, auto escalate/demote** **[DECIDED]**

**Model:** the fingerprint identity is extracted into a portable, serializable value and both
transports (Chrome via §4, HTTP via `wreq`) render from it, so a switch is lossless.

```
StealthIdentity {
    profile: BrowserProfile,            // UA, platform, HW, WebGL, viewport
    emulation: BrowserKind,             // JA4/H2 source (§2)
    locale: Option<Locale>,             // proxy-led (existing)
    cookies: Vec<Cookie>,               // domain/path/expiry/secure/httponly/samesite
    client_hints: ClientHints,          // Sec-CH-UA{,-platform,-mobile,-arch,...}
    egress: Option<String>,             // sticky upstream proxy (same exit IP!)
    cf_clearance_expiry: Option<u64>,   // drives re-escalation
}
```

**Flow (matches "challenge is usually up front"):**
1. **Start in Browser mode.** Launch Chrome, solve the initial challenge (existing
   `solve_challenge`), and — critically — keep the **same egress proxy** so the IP that earned
   `cf_clearance` is the IP that reuses it.
2. **Demote to HTTP.** Export `StealthIdentity` (cookies via `Network.getAllCookies`, client
   hints from the profile), build a `wreq` client from the **same emulation + same egress +
   same cookie jar**, then **shut Chrome down** to reclaim its RAM (the whole point).
3. **Auto-escalate** when the HTTP session sees a fresh challenge (reuse `challenge::detect` on
   the HTTP body/status) **or** `cf_clearance` is near expiry: relaunch Chrome with the *same*
   identity + cookies, solve, re-demote. A `SessionMode` policy (mirroring `MitigationPolicy`)
   owns the escalate/demote thresholds; every transition emits a `ScraperEvent`.

**New surface:** `StealthSession` façade over `enum Transport { Browser(CloudScraper),
Http(HttpScraper) }`, plus `HttpScraper` (a thin `wreq` wrapper that runs `detect` on responses).
`fetch(url)` auto-manages the mode; `escalate()`/`demote()` exposed for manual control.

**Payoff:** steady-state scraping runs with **zero Chrome process** (Chrome is ~150–300 MB+
resident; the HTTP path is a few MB), while first-hit challenge solving keeps full browser
fidelity. This is the single biggest usage-performance/RAM win.

---

## 6. Stealth hardening (new techniques + fixing §0.3.6)

Adopt current-generation evasion; each is independently testable against Creepjs/BrowserScan/
Cloudflare bot-score:
- **Native-shape hooks.** Patch `Function.prototype.toString` so all proxied getters report
  `native code`; define spoofed props via `Object.defineProperty` with realistic descriptors;
  make `navigator.plugins`/`mimeTypes` real `PluginArray`/`Plugin` objects (the PDF viewer set),
  not `[1,2,3]`.
- **Deterministic, per-identity fingerprint noise.** Seed Canvas/Audio/WebGL noise from a hash of
  `StealthIdentity` so it's *stable within a session* (real hardware is) but varies per identity —
  instead of re-perturbing on every read (a signal today).
- **Client Hints coherence.** Set `Sec-CH-UA`, `-platform`, `-mobile`, `-arch`, `-bitness`,
  `-full-version-list` to agree with UA + platform, on **both** transports. Missing/incoherent
  UA-CH is a strong modern signal and is currently unhandled.
- **WebGL/UNMASKED via `Emulation.setDeviceMetricsOverride`** + matching `deviceScaleRatio`, and
  screen/`window` dimension coherence with the profile viewport.
- **navigator.webdriver at the source:** with our own launcher we drop `--enable-automation`, so
  `webdriver` is false natively — the JS override becomes belt-and-suspenders, not the primary fix.
- **TLS session resumption / ALPS** parity via the §2 table.
- **Behavioral:** mouse paths already Bézier; add idle micro-movements and scroll before click,
  and randomized `Input` timing driven by `tokio` timers.

New: `stealth-audit` becomes an automated `e2e` test asserting a battery of Creepjs/BrowserScan
signals (webdriver, plugins shape, `toString` native-ness, CH coherence, JA4==UA-major).

---

## 7. Sequencing (each phase compiles, tests green, independently shippable)

| Phase | Deliverable | Risk | Blast-radius delta |
|---|---|---|---|
| **P0** | Remove unused deps: `cookie_store`, `regex`, `bytes`, direct `tokio-socks`; inline `rand_distr`. **`tokio-rustls` `default-features = false` (§3.5), dropping aws-lc + its cmake build.** Fix JA4↔UA bug as an interim (select emulation by real UA major). | Low | −5 direct, −~12 transitive, **−aws-lc C build** |
| **P1a** | ✅ `ja4` module (ClientHello parser + fingerprint), proxy `ClientHello` observation, egress self-test pinned to published Chrome/Safari JA4. | Med | +1 crate (`sha2`) |
| **P1b** | §2 own emulation table, populated from P1a captures; drop `wreq-util`. **Blocked**: needs verified data per browser version (see §2.1). | Med | −1 GPL dep, +1 data file |
| **P2** | §4 own async CDP (`src/cdp/`), delete `headless_chrome`; port scraper/solver/behavior. | **High** | −~38 crates; kills §0.3.3–.5,.7 |
| **P3** | §3.5 crypto spike → boring-only for the MITM/cert leg; persistent CA. | Med | −~8 further crates |
| **P4** | §5 `StealthSession` browser⇄HTTP + `HttpScraper`. | Med | +0 deps (reuses wreq) |
| **P5** | §6 stealth hardening + automated audit e2e. | Med | +0 deps |

TDD throughout (pure modules unit-tested with no browser, per hexagonal rules). P2 is the pivot:
it's the most work and the enabler for P4/P5 — worth its own spike branch first.

## 8. Expected outcome
- **Default build:** ~160 → ~120 crates; **browser build:** ~198 → ~150; **one** GPL removed;
  crypto backends in this crate 3 → 1, removing the aws-lc cmake build (aws-lc goes at P0, rustls
  at P3). Workspace-wide the final binary keeps 2 by design — boring for impersonation, rustls+ring
  for the Arlo/IMAP clients (§3.3).
- **RAM:** steady-state scraping with no Chrome process after the first challenge.
- **Correctness:** JA4 provably matches the UA; `Runtime.enable`/automation tells actually gone;
  no scannable debug port.
- **Safety posture unchanged:** still `#![forbid(unsafe_code)]` first-party; all FFI stays in
  `boring`/`wreq`.

## 9. Resolved
- **Crypto backend choice (§3).** Role-based split: BoringSSL for stealthscraper (mandatory for
  impersonation), rustls+ring retained for `arlo-rs`/`imap-rs`. aws-lc dropped at P0. No
  workspace-wide migration.

## 10. Open questions for the maintainer
1. **MSRV/Chrome cadence:** which Chrome majors must the emulation table track at launch (I propose
   124, 131, 133, latest-stable + Safari 17)?
2. **P2 buy-vs-build checkpoint:** OK to spike the async CDP client on a branch and compare against
   a `chromiumoxide` fallback before committing to delete `headless_chrome`?
3. **Chrome discovery:** keep auto-discovery (adds `which`-like logic) or require an explicit
   `chrome_path` / `CHROME_BIN` env (simpler, one less concern)?
4. **`persistence`:** keep `redb`, or is per-domain state small enough for an append-only JSON
   file (drops `redb` + a chunk of tree)?

---

## 11. Build environment

Rust is not on the default PATH on this host; `cmake`, `libclang`, and `git` are absent too, and
`wreq → boring-sys2` needs all of them to build vendored BoringSSL.

**Dependency-graph work only** (`cargo tree`, `cargo fetch`) — mise is enough:

```bash
mise exec rust@1.98.1 -- cargo tree -e normal --features browser,persistence
```

**Compiling / testing / clippy** — use the `rust-build` distrobox (Debian trixie, matching the
host). It shares `$HOME`, so the rustup toolchain at `~/.cargo/bin` works inside unchanged:

```bash
distrobox enter --name rust-build -- sh -c \
  'cd /home/ypno/workspace/arlo-camera-streamer/stealthscraper-rs && $HOME/.cargo/bin/cargo check --features browser,persistence'
```

Container provisioning (already done; recorded for reproducibility):

```bash
distrobox create --name rust-build --image docker.io/library/debian:trixie --yes
distrobox enter --name rust-build -- sudo apt-get install -y \
  clang libclang-dev cmake build-essential pkg-config perl git
```

`git` is required but easy to miss: `boring-sys2`'s build script shells out to `git init` to apply
its BoringSSL patches, and fails with a bare `NotFound` if it is absent.
