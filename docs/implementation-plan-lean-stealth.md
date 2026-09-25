# Implementation Plan: Lean Dependencies, Dual-Mode Sessions & Stealth Hardening

**Status:** P0–P5 implemented on `chore/p0-lean-dependencies`, P1b included — the GPL dependency
is gone.
**Author:** Senior Rust Architect review · **Date:** 2026-09-23, revised 2026-09-25
**Crate:** `stealthscraper-rs` v0.4.0 → v0.5.0 (breaking)

> **Reading this document.** Sections 0–6 are the original analysis and design, kept as the
> rationale record, with the §0.3 defects marked **[FIXED]** / **[OPEN]** where they were
> resolved and design sections marked **[DONE]**. Section 7 carries the sequencing table with
> the shipped status, and **§7.1 is the as-built record** — what each phase actually delivered, where it deviated from this plan,
> and the defects that only measurement exposed. §8 replaces the projected crate counts with
> measured ones. Start at §7.1 if you want the current state rather than the reasoning.

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
1. **JA4 ↔ UA mismatch (HIGH).** **[FIXED — P0, `0ef7a03`.]**
   `build_impersonation_client` (`scraper.rs:42`) matches on
   `"Chrome/120"`, but every UA in `BrowserProfile::random()` is Chrome **124–126**. So the
   `else` branch always fires → every request emits the **Chrome120** fingerprint while the UA
   says 124–126. This is exactly the JA4 inconsistency CLAUDE.md forbids.
2. **`wreq-util` is GPL-3.0** and caps at Chrome 137. **[FIXED — P1b; see §7.4.]** Removed
   entirely; no GPL remains in the graph. It caused two defects on the way out: its emulation set
   its *own* `User-Agent` and `Sec-CH-UA`, which silently overrode the profile's on the HTTP leg
   (`6f9c203`), and its supposed advantage did not exist — measured, its newest Chrome entry put
   byte-identical TLS **and** HTTP/2 on the wire to what our own measured values put there. It's the only GPL in the tree and it taints
   the `browser` build's license posture. Its whole job is that one `.emulation()` call.
3. **`--enable-automation` is always on.** **[FIXED — P2, `5786f47`.]** `headless_chrome`'s `DEFAULT_ARGS` inject
   `--enable-automation` (sets `navigator.webdriver=true` at the C++ level, exposes the
   automation info-bar) and the code never disables default args. The stealth JS papers over
   `webdriver` *after* the fact, but the launch flag is itself a tell.
4. **Debug port is scannable.** **[FIXED — P2, `5786f47`: `--remote-debugging-pipe` only.]** `headless_chrome` launches with `--remote-debugging-port=<tcp>`
   on loopback. A page that fetches `http://localhost:<port>/json` (or the range) can detect the
   CDP endpoint. `--remote-debugging-pipe` removes the port entirely.
5. **Runtime.enable detection vector is NOT actually blocked.** **[FIXED — P2, `1fd2578`:
   `NEVER_ENABLED = ["Runtime", "DOM", "Log", "Debugger", "Profiler"]`, asserted by test.]** CONTEXT.md claims "Blocks the
   `Runtime.enable` detection vector," but `headless_chrome` calls `Runtime::Enable` (tab
   `mod.rs:1403`) and `Page.enable`/`Page.SetLifecycleEventsEnabled` on **every** tab creation.
   Creepjs/Cloudflare detect the `Runtime.enable` CDP leak. The claim is currently false.
6. **Stealth JS is detectable by shape.** **[FIXED — P5, `4bbf8b9`; see §7.1 P5 for the
   deviation on `navigator.plugins`.]** Getters defined with arrow functions whose
   `.toString()` doesn't read `native code`; `navigator.plugins → [1,2,3]` (real is
   `PluginArray` of `Plugin`); `Function.prototype.toString` not patched, so every proxied
   `getParameter`/`toDataURL` is unmaskable via `.toString()`. Canvas/Audio noise is applied on
   **every** read (real hardware is deterministic within a session) — itself a signal.
7. **Blocking CDP on the async runtime.** **[FIXED — P2, `f9ed0e0`: the whole surface is async,
   `tokio::time::sleep` throughout, no `spawn_blocking` in the public API.]** `solve_challenge` and all `human_*` helpers use
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

**As shipped (P1b).** `src/emulation.rs` holds complete emulations — TLS *and* HTTP/2 *and* the
header set and order — for two families, every value measured rather than transcribed.
`wreq-util` is removed and there is no GPL anywhere in the graph. See §7.4 for the measurements
that justified the swap and for what remains unmeasured.

**Removes:** `wreq-util` (and its GPL). **Adds:** no new dependency for the emulation itself; four
`wreq` decompression features (+3 crates) so the `Accept-Encoding` we advertise is one we can
actually decode — see §7.4.
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

**P3 (spike, Medium risk). [DONE — `061bbc5`, `a29179e`, `601593d`.]** Move MITM TLS termination and cert minting off rustls+rcgen onto
`wreq`'s re-exported boring (`boring::ssl::SslAcceptor`, `boring::x509` for an on-the-fly leaf
signed by a persistent CA). The cut is clean — per §0.1, `rustls`, `tokio-rustls`, `rcgen`,
`rustls-pki-types`, `rustls-webpki`, `ring`, `yasna`, `pem` are reachable only through those two
direct deps. Validate by building the **consumer** binary (`arlo-camera-streamer-rs`), which
legitimately keeps rustls for the Arlo/IMAP side.

If the spike stalls, P0 has already banked the aws-lc win and the status quo (boring for egress +
ring for the local leg) is an acceptable resting state.

**Either way — persistent CA.** **[DONE, with a deliberate deviation: the CA is *ephemeral per
process*, not persistent on disk — see §7.1 P3.]** Replace the current
**per-CONNECT `generate_simple_self_signed`**
(`proxy.rs:601`): today every HTTPS tunnel mints a fresh cert on a `spawn_blocking`, a real
per-request CPU + latency cost. One cached CA + per-host cached leaves is both faster and more
browser-like. This is independent of which backend wins.

---

## 4. CDP client — replace `headless_chrome` with a minimal async client **[DECIDED: own async CDP]**

**Why:** kills defects §0.3.3/.4/.5/.7 at the source, removes ~38 crates
(`auto_generate_cdp`, `tungstenite`+`tokio-tungstenite` dupes, `which`, `winreg`, `walkdir`,
`ureq`, `derive_builder`, `tempfile`, a second `rand`, `regex`, …), and gives us total control of
which CDP domains are enabled (no forced `Runtime.enable`).

**[DONE — P2: `5786f47`, `ce299d9`, `b60271a`, `1fd2578`, `f9ed0e0`.]** Ported **in place**
(breaking), not behind a compatibility shim: `headless_chrome` is gone from the graph. The
*browser* is unchanged — we still launch the same Chrome/Chromium binary; only the client crate
was replaced.

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

**[DONE — P4: `c52dc35`, `0858666`, `ac494ac`.]** Shipped as `src/identity.rs`,
`src/http_scraper.rs`, `src/session.rs`; see §7.1 P4 for the two defects this phase exposed.

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

**[DONE — P5: `4bbf8b9`, `04c8dfc`, `a49b691`, `ba921bb`; see §7.1 P5 for deviations.]**

New: `stealth-audit` becomes an automated `e2e` test asserting a battery of Creepjs/BrowserScan
signals (webdriver, plugins shape, `toString` native-ness, CH coherence, JA4==UA-major).
**Shipped as `tests/stealth_audit.rs`: 14 checks, run against a live browser.**

---

## 7. Sequencing (each phase compiles, tests green, independently shippable)

| Phase | Deliverable | Risk | Blast-radius delta | Status |
|---|---|---|---|---|
| **P0** | Remove unused deps: `cookie_store`, `regex`, `bytes`, direct `tokio-socks`; inline `rand_distr`. **`tokio-rustls` `default-features = false` (§3.5), dropping aws-lc + its cmake build.** Fix JA4↔UA bug as an interim (select emulation by real UA major). | Low | −5 direct, −~12 transitive, **−aws-lc C build** | ✅ `a34ff5f`, `0ef7a03`, `fa72803` |
| **P1a** | `ja4` module (ClientHello parser + fingerprint), proxy `ClientHello` observation, egress self-test pinned to published Chrome/Safari JA4. | Med | +1 crate (`sha2`) | ✅ `134f08c`, `5bef5ea`, + capture examples |
| **P1b** | §2 own emulation table, populated from P1a captures; drop `wreq-util`. | Med | −1 GPL dep, +1 data file | ✅ `b0c8ccb` + the P1b port — `wreq-util` gone, Chrome and Safari measured; Safari's HTTP/2 still needs one capture (§7.4) |
| **P2** | §4 own async CDP (`src/cdp/`), delete `headless_chrome`; port scraper/solver/behavior. | **High** | −~38 crates; kills §0.3.3–.5,.7 | ✅ `5786f47` → `f9ed0e0` (in-place breaking port) |
| **P3** | §3.5 crypto spike → boring-only for the MITM/cert leg; persistent CA. | Med | −~8 further crates | ✅ `061bbc5`, `a29179e`, `601593d` (CA is ephemeral by design) |
| **P4** | §5 `StealthSession` browser⇄HTTP + `HttpScraper`. | Med | +0 deps (reuses wreq) | ✅ `c52dc35`, `0858666`, `ac494ac` |
| **P5** | §6 stealth hardening + automated audit e2e. | Med | +0 deps | ✅ `4bbf8b9`, `04c8dfc`, `a49b691`, `ba921bb` |

TDD throughout (pure modules unit-tested with no browser, per hexagonal rules). P2 is the pivot:
it's the most work and the enabler for P4/P5 — worth its own spike branch first.

**Suite as it stands:** 288 lib tests + 49 integration tests across 12 binaries, full run **29 s**
on a warm build, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean.

---

## 7.1 As built — per phase

Each entry records what shipped, where it departs from the plan above, and what only turned up by
measuring. The deviations are the useful part: three of them are defects the tests did not catch.

### P0 — lean dependencies
As planned. `cookie_store`, `regex`, `bytes`, `rand_distr` and the direct `tokio-socks` are gone;
the Gaussian sampler is an inlined Box–Muller. `cookie_store` **still appears in the graph**
transitively via `wreq`'s own jar — that is expected and was never the target. aws-lc is out of the
normal-dependency graph. The JA4↔UA fix selects the emulation from the parsed UA major
(`CHROME_EMULATIONS` / `SAFARI_EMULATIONS` tables in `scraper.rs`), so the two cannot disagree.

### P1a/P1b — fingerprint measurement
`src/ja4/` parses a ClientHello and computes JA4; `src/tls_capture.rs` + the proxy observer expose
any browser's real fingerprint. The apparatus is validated against independently published values,
and the capture examples (`f49a22b`…`c897229`) reproduce a target from captured bytes.

P1b first shipped as a **TLS-only overlay** over `wreq-util`'s base emulation (`b0c8ccb`), because
nothing then measured HTTP/2. `examples/capture_h2` closed that gap, and the full table — TLS,
HTTP/2, headers and header order — then replaced `wreq-util` outright. See **§7.4**.

### P2 — own async CDP client
`src/cdp/` = `launch.rs` (pipe launch, curated args, no `--enable-automation`, no TCP port),
`transport.rs` (demultiplexer: replies by `id`, events by `method`, 30 s call timeout, close fails
all pending with a recorded reason), `session.rs` (`BrowserHandle` + `Page`, ~25 typed methods).

Measured findings that changed the design:
- **`wait_for_load` subscribed after issuing the navigation** — a real race, not a flaky test.
  Fixed by splitting `watch_load()` from the navigation, giving `navigate_and_wait()` /
  `reload_and_wait()`.
- **`new_page(url)` cannot observe its own first load**, since the target does not exist when the
  subscription would have to start. Documented, and `BrowserHandle::open` added for the
  create-then-navigate shape.
- **`element_center` returned `Some((0,0))`** for `display:none` elements; now returns `None` for
  any zero-area box, so a human click cannot be aimed at a hidden target.
- Transport tests deadlocked under `#[tokio::test]`'s current-thread runtime (blocking peer reads
  starved the spawned work) → they run `multi_thread, worker_threads = 2`.

### P3 — BoringSSL MITM leg and the CA
`src/ca.rs` mints leaves from one CA (`basicConstraints pathlen:0`, one shared leaf key, CN
truncated to `ub-common-name` = 64, `iPAddress` vs `dNSName` SANs chosen by parse, ALPN pinned to
`http/1.1`), with a bounded 256-entry FIFO cache of `SslAcceptor`s per host. `rustls`, `rcgen`,
`ring`, `webpki`, `yasna` and `pem` are gone from the normal graph; the intercepted leg terminates
with `tokio_boring2::accept`.

**Deviation (decided with the maintainer): the CA is ephemeral per process, not persistent on
disk.** Persisting a MITM CA key is a standing local-compromise risk for a scraping library, and
the trust problem is solved instead by **`--ignore-certificate-errors-spki-list`** with the
base64 SHA-256 of *this* CA's SPKI (`601593d`). That pins the launched browser to exactly one
interception key for one process lifetime, rather than disabling certificate checking wholesale.
Note the earlier claim that the blanket `--ignore-certificate-errors` flag is *observable from
JS* was asserted without evidence and is withdrawn; the reason to prefer the SPKI pin is scope,
not detectability.

### P4 — dual-mode session
`identity.rs` (`StealthIdentity`, `Cookie` + RFC 6265 scoping, `SessionPolicy`, `Transition`,
`EgressRef` which redacts `user:password@` in its constructor), `http_scraper.rs`, `session.rs`
(`StealthSession` deciding mode before *and* after each fetch; `restore()` refuses an identity
carrying a different egress).

Two defects measurement exposed after the phase was called done:
- **The HTTP leg sent the wrong identity** (`6f9c203`). The commit message claimed both transports
  render the same fingerprint; they did not — `wreq-util`'s emulation supplies its own
  `User-Agent`/`Sec-CH-UA`, which quietly won over the profile's. `HttpScraper` now sets
  `User-Agent`, `Sec-CH-UA`, `-Mobile`, `-Platform`, `Accept-Language` and `Cookie` explicitly.
  `tests/http_leg_headers.rs` (5 checks) pins this.
- **The policy pinned the browser open** (`ba57bc3`): a clean page with no clearance cookie was
  never demoted, defeating the RAM goal that motivates §5. `require_clearance_for_http` defaults
  to `false`; `clearance_margin` is 120 s.

### P5 — stealth hardening
`stealth.rs` rewritten: overrides land on `Navigator.prototype` (not the instance), `defineNative`
emits `function get X() { [native code] }`, a `WeakMap` registry backs the patched
`Function.prototype.toString`, all injected values go through `js_literal()` (JSON-encoded, so
nothing is string-spliced into the page), and Canvas/Audio noise is seeded from SHA-256 of the
profile and applied **once per buffer** via a `WeakSet`. `client_hints.rs` renders `Sec-CH-UA*` and
`navigator.userAgentData` coherently on both transports. `behavior.rs` gained idle micro-drift,
notch-quantised scrolling with jitter, and scroll-then-settle before a click.

**Deviations from §6, all deliberate:**
- **`navigator.plugins`/`mimeTypes`/`pdfViewerEnabled`/`connection` are left untouched.** §6 said
  to synthesise a real `PluginArray`; measurement showed the launched browser *already* reports the
  correct five PDF plugins, `pdfViewerEnabled: true` and a real `NetworkInformation`. Two of the
  planned hooks were therefore themselves the signal. A unit test asserts the injected script does
  **not** mention `'plugins'` or `'pdfViewerEnabled'`, so the hooks cannot creep back in.
- **Screen coherence** (`a49b691`) uses `Emulation.setDeviceMetricsOverride` with
  `width: 0, height: 0` so only `screen.*` is overridden and the window is left alone — without it
  a 1920×1080 window reported an 800×600 screen.
- **`navigator.userAgentData` is secure-context-only**; the audit accounts for that rather than
  asserting it everywhere.
- **`Sec-CH-UA` brand list** uses the observed real form and order
  (`Chromium`, `Google Chrome`, `Not-A.Brand` v99) rather than an invented GREASE string.
- **`platformVersion` for Windows/macOS is not measured** — the constant is marked as such in
  `PLATFORM_VERSIONS`. See §7.2.

### Challenge detection (found during P5, `2729df8`)
`detect` reported *every* Cloudflare-served page as a challenge: a bare `cf-turnstile` widget or a
`cf-ray` header was enough. It now requires interstitial markers (`just a moment`, `cf_chl_opt`,
`/cdn-cgi/challenge-platform/h/{b,g}/orchestrate`, the challenge form/stage ids); a Turnstile
widget only counts inside an interstitial or with `cf-mitigated`. Vendor-only evidence returns
`ChallengeKind::None` **with** the evidence attached. Three existing tests encoded the old
behaviour as an expectation and were corrected deliberately.

---

## 7.2 Still open

1. **~~`wreq-util` (GPL-3.0) is still the base emulation.~~** — removed; see §7.4. The BoringSSL
   limitation is real but turned out to be irrelevant to the decision, because the GPL table hit
   exactly the same ceiling.
2. **Safari's HTTP/2 is unmeasured** — its TLS is measured and exact, but capturing SETTINGS needs
   the browser, which the build host does not have. `wreq`'s default applies, which is not
   Safari-shaped. Run `cargo run --example capture_h2` on a host the Mac can reach, visit the URL
   it prints, and fill in the values the way `chrome()` does. Latent rather than active:
   `BrowserProfile::random` only generates Chrome.
3. **Branded Chrome's `Sec-CH-UA` is unmeasured.** The local build is unbranded Chromium
   (`"Chromium";v="153", "Not_A Brand";v="8"`); the three-entry branded form in
   `client_hints.rs` came from `wreq-util` and now has no witness in the tree. Capture it from a
   real branded Chrome with `capture_h2 --h1`.
4. **Windows/macOS `platformVersion` is unmeasured.** Capture with
   `navigator.userAgentData.getHighEntropyValues(['platformVersion'])` in a real Chrome on each
   platform and replace the placeholder constants.
5. **The branch has never been pushed.** It is local-only on
   `chore/p0-lean-dependencies`, and there is no PR.
6. **~~§10 Q4 (`redb` vs append-only JSON)~~** — resolved, see §7.3.

---

## 7.3 Resolved: `redb` vs a JSON file (§10 Q4)

**The question's premise was wrong.** The plan assumed dropping `redb` would "drop `redb` + a chunk
of tree". Measured, `redb v4.1.0` is a **leaf crate with zero dependencies** — build, normal or
otherwise — so the whole `persistence` feature is worth exactly **one** crate (148 → 149). As a
blast-radius argument this was never worth acting on, and the removal framing is closed.

**The argument that did survive** is audit surface, not crate count: `redb` is 21,358 LOC with 37
`unsafe` sites, to store seven scalars per host. And the real gap was elsewhere — the *default*
build had no durable store at all, only `InMemoryStateStore`, purely because the only durable
implementation happened to need a crate.

**Resolution: both stores, neither removed.**

- **`JsonStateStore`** (`src/state/json_store.rs`, **default build, no new dependency**) — the
  in-memory map is authoritative, and each mutation serializes it to a sibling temporary, `sync_all`s
  it, and `rename`s it over the target. `rename` is atomic, so a crash leaves either the previous
  complete file or the new one, never a partial record; the directory entry is not flushed, so a
  power loss may lose the *last* write but cannot corrupt the file. `update()` holds one lock across
  read-closure-write, satisfying the port's atomicity contract. The file is a pretty-printed JSON
  array sorted by host, so it is hand-inspectable and stable across writes. A missing or empty file
  reads as empty; a file that exists but does not parse is an **error**, so corrupt state is
  reported rather than silently discarded.
- **`RedbStateStore`** (`persistence`) — **still the recommendation** for either case the JSON store
  cannot cover. (a) **A second process may open the same file.** Neither store supports concurrent
  writers, but `redb` takes an *exclusive, non-blocking* lock and fails the second opener
  immediately with `DatabaseAlreadyOpen`, while the JSON store has no lock and is silently
  last-writer-wins. The win is a loud failure, not concurrent access. (b) **A large host set** —
  `redb` writes only the pages it touches; the JSON store rewrites the whole file per mutation
  (`O(hosts)`).

Note the plan's "append-only" framing was also unnecessary: append-only exists to avoid rewriting,
which then needs compaction. At a few KB, a full rewrite plus `rename` is both cheaper and simpler,
and gets crash atomicity for free. 9 unit tests cover the adapter.

---

## 7.4 Resolved: dropping `wreq-util` and its GPL (P1b)

The plan treated this as blocked on a Chrome TLS entry the vendored BoringSSL could emit. That
framing conflated two separate things — **removing the GPL dependency** and **having a perfect
Chrome fingerprint** — and the measurements below separate them.

### What was measured

A new `examples/emulation_baseline` scored each candidate against the real browser, and
`examples/capture_h2` (new — the HTTP/2 counterpart of `capture_fingerprint`) read the opening
frames of an h2 connection, with `--h1` to read header names and order as plaintext.

**TLS, against Chromium 153's real `t13d1517h2_8daaf6152771_cb7bf5808d99`:**

| Candidate | JA4 emitted | Segments matching |
|---|---|---|
| our hand-built entry | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 1/3 |
| `wreq-util` Chrome137 (its newest) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 1/3 |
| `wreq-util` Chrome124 | `t13d1516h2_8daaf6152771_02713d6af862` | 1/3 |
| bare `wreq`, no emulation | `t13d2812h2_257f3020b3a2_ef7df7f74e48` | 0/3 |

The first two rows are **byte-identical**. The ceiling is the TLS stack — extension `0xca34` and
the ML-DSA sigalgs `0x0904/5/6`, neither of which the vendored BoringSSL has (its
signature-algorithm name table is closed, and `sigalgs_list` takes names, not code points). The
GPL data bought nothing. On Safari the comparison goes the other way: our measured entry scores
**3/3** where `wreq-util`'s newest Safari scores 2/3.

**HTTP/2, from the browser directly** (two connections, identical both times):

```
SETTINGS, in wire order:  HeaderTableSize 65536 · EnablePush 0
                          InitialWindowSize 6291456 · MaxHeaderListSize 262144
                          (MaxConcurrentStreams and MaxFrameSize are not sent at all)
WINDOW_UPDATE stream 0:   +15663105  → connection window 15728640
HEADERS flags 0x25:       priority depends on 0, weight 256, exclusive
pseudo order:             :method, :authority, :scheme, :path
```

`wreq-util` Chrome137 reproduced every one of those values exactly; bare `wreq` sent one setting,
a 5242880 window and `:method, :scheme, :authority, :path`. So the emulation genuinely matters —
but the values are now *measured from Chrome*, not borrowed.

### Conclusion and what shipped

Dropping `wreq-util` costs nothing measurable on either half and improves Safari's TLS. The knobs
were all available from **`wreq` itself, under Apache-2.0** (`TlsConfig`, `Http2Config`,
`settings_order`, `headers_pseudo_order`, `headers_priority`, `default_headers`, `headers_order`).

`src/emulation.rs` is now complete emulations rather than TLS overlays:
`chrome()` (TLS + HTTP/2 + headers, all measured), `safari_27()` (TLS measured), and `for_kind()`
which always returns an entry — there is no `None` path that could silently leave a bare client's
fingerprint on the wire. `tests/ja4_egress.rs` (10 tests) asserts each entry's JA4 on real wire
bytes, that a bare client differs, and that `for_kind` routes every family to a measured entry.

**One entry per family, not per version.** Only one version of each family has been captured, and
a per-version table would imply measurements that do not exist. So `BrowserProfile::random` now
claims **Chrome 153** — `emulation::CHROME_MAJOR` — in every User-Agent it generates. That keeps
the JA4↔UA invariant true by construction, and fixes a second problem the old list had: it claimed
Chrome 124–126 while the binary rendering the page was Chromium 153, which feature detection alone
would expose, and which in late 2026 is a stale-version signal on its own.

### The defect this exposed

Adding Chrome's measured `Accept-Encoding: gzip, deflate, br, zstd` broke two end-to-end tests:
107875 bytes came back with no `<html>` in them. `wreq` was built with no decompression features,
so advertising encodings it cannot decode handed the caller a compressed body. The fix is the
`gzip`/`deflate`/`brotli`/`zstd` features (+3 crates: `async-compression`, `compression-codecs`,
`compression-core` — no C toolchain), because the alternative, advertising only what we can decode,
is itself a signal: current Chrome sends all four. `tests/http_leg_headers.rs` now pins the exact
`Accept-Encoding`, the navigation `Accept` and `Sec-Fetch-*` values, and the **header order** on
the wire.

---

## 8. Outcome — projected vs measured

Measured on the branch with `cargo tree -e normal` (unique `name vX.Y.Z`, so duplicate versions of
one crate count separately):

| Graph | Before | Projected | **Measured now** |
|---|---|---|---|
| default | ~160 | ~120 | **151** |
| `persistence` | ~161 | — | **152** |
| `browser,persistence` | ~199 | ~150 | **154** |

Dropping `wreq-util` took the browser graph 155 → 151; the three compression crates the measured
`Accept-Encoding` requires (§7.4) bring every graph back up by 3, which is why the default build
is 151 rather than 148.

Gone from the normal graph: `aws-lc-rs`/`aws-lc-sys`, `rustls`, `rustls-webpki`, `rustls-pki-types`,
`rcgen`, `ring`, `yasna`, `pem`, `headless_chrome` and its tree (`auto_generate_cdp`,
`tungstenite`/`tokio-tungstenite`, `which`, `winreg`, `walkdir`, `ureq`, `derive_builder`,
`tempfile`), `regex`, `bytes`, direct `tokio-socks`, `rand_distr`, **`wreq-util`**. Added: `sha2`,
`boring2`, `tokio-boring2`, `command-fds`, `async-compression` + 2 codec crates.
**Crypto backends in this crate: 3 → 1** (one vendored BoringSSL, shared with `wreq` by pinning
the same minor).

The default build did not reach ~120 because the projection counted duplicate-version trees as
single crates and did not foresee the decompression requirement. `tokio-rustls` remains, as a
**dev**-dependency only, so consumers are unaffected.

- **GPL removed: yes.** `wreq-util` is gone from every graph (§7.4); the crate is MIT +
  Apache-2.0 throughout.
- **RAM:** achieved — `StealthSession` runs steady state with no Chrome process, escalating only on
  a detected challenge or near-expiry clearance.
- **Correctness:** JA4 is selected from the parsed UA major, so it cannot contradict the UA;
  `--enable-automation` and the TCP debug port are gone; `Runtime`/`DOM`/`Log`/`Debugger`/`Profiler`
  are never enabled, asserted by test.
- **Safety posture unchanged:** `#![forbid(unsafe_code)]` holds — the one `dup2` the pipe launch
  needs lives in `command-fds`, and all other FFI in `boring2`/`wreq`.

## 9. Resolved
- **Crypto backend choice (§3).** Role-based split: BoringSSL for stealthscraper (mandatory for
  impersonation), rustls+ring retained for `arlo-rs`/`imap-rs`. aws-lc dropped at P0. No
  workspace-wide migration.

## 10. Questions — answered by the work

1. **~~Chrome cadence for the emulation table~~** — answered by the constraint that every value is
   measured: **one entry per family**, for the version actually captured, and
   `BrowserProfile::random` claims that version. Tracking more Chrome majors means capturing them,
   which `examples/capture_fingerprint` + `capture_h2` now make a two-command job.
2. **~~P2 buy-vs-build~~** — built, in place and breaking. No `chromiumoxide` comparison was run;
   `headless_chrome`'s forced `Runtime.enable`, TCP debug port and thread-per-tab sync API were
   each disqualifying on their own, and the surface we need is ~25 methods.
3. **~~Chrome discovery~~** — explicit path / env, per the simpler option; `LaunchConfig` takes the
   binary and `for_profile()` derives the rest.
4. **~~`persistence`: keep `redb`, or an append-only JSON file?~~** — **both.** `redb` stays and
   remains the recommendation for its cases (a second process opening the file; a large host
   set); a dependency-free `JsonStateStore` was added so the *default* build has a durable store
   at all. See §7.3.

---

## 11. Build environment

Rust is not on the default PATH on this host; `cmake`, `libclang`, and `git` are absent too, and
`wreq → boring-sys2` needs all of them to build vendored BoringSSL.

**Dependency-graph work only** (`cargo tree`, `cargo fetch`) — mise is enough:

```bash
mise exec rust@1.98.1 -- cargo tree -e normal --features browser,persistence
```

**Compiling / testing / clippy** — use the `rust-build` distrobox (Debian trixie, matching the
host). **mise is not available inside the container**; it shares `$HOME`, so the rustup toolchain
at `~/.cargo/bin` is what works inside — put it on `PATH` explicitly:

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

The `browser`-gated tests launch a real Chromium and are expected to be run: the full suite (279
lib + 49 integration tests, 12 binaries) completes in **29 s** on a warm build, so there is no
reason to skip or throttle them. Each browser shows up as ~10 OS processes, so `pgrep -c chromium`
is not a count of running browsers.

`git` is required but easy to miss: `boring-sys2`'s build script shells out to `git init` to apply
its BoringSSL patches, and fails with a bare `NotFound` if it is absent.
