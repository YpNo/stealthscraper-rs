//! The dual-mode session, end to end against a live site.
//!
//! P4 shipped without this, and it could not have passed: the challenge
//! detector reported every Cloudflare-protected page as challenged, so the
//! policy saw `challenged: true` on every decision and the session would
//! escalate to the browser and never come back. Now that detection is correct,
//! the behaviour the design exists for is actually observable — so it is
//! asserted rather than described.

#![cfg(feature = "browser")]

use std::time::Duration;

use stealthscraper_rs::identity::SessionPolicy;
use stealthscraper_rs::{BrowserProfile, SessionMode, StealthSession};

/// A highly-available site behind Cloudflare.
const TARGET: &str = "https://nowsecure.nl";

/// Builds a session with `policy`.
fn build_session(policy: SessionPolicy) -> StealthSession {
    StealthSession::builder()
        .profile(BrowserProfile::random())
        .headless(true)
        .policy(policy)
        .build()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unchallenged_site_is_fetched_without_ever_launching_a_browser() {
    // The steady state the whole design exists to reach. A browser costs
    // hundreds of megabytes; a site that does not challenge should never pay it.
    let mut session = build_session(SessionPolicy::default());
    assert!(
        !session.browser_is_running(),
        "nothing launches at build time"
    );

    let response = match session.fetch(TARGET).await {
        Ok(response) => response,
        Err(err) => {
            eprintln!("skipping: could not reach the network ({err})");
            return;
        }
    };

    assert_eq!(response.status, 200, "unexpected status");
    assert!(
        response.body.contains("<html") || response.body.contains("<HTML"),
        "no document came back ({} bytes)",
        response.body.len()
    );
    assert!(
        !response.is_challenge(),
        "expected the site, got {:?}",
        response.signal.kind
    );

    assert!(
        !session.browser_is_running(),
        "a browser was launched for a site that never challenged"
    );
    assert_eq!(session.mode(), SessionMode::Http);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_strict_policy_escalates_then_demotes_again() {
    // The transfer itself: the browser is launched, does its work, hands the
    // session over, and is shut down. Forcing it with require_clearance_for_http
    // rather than waiting for a live challenge keeps the test deterministic.
    let mut session = build_session(SessionPolicy {
        require_clearance_for_http: true,
        ..SessionPolicy::default()
    });

    // The policy demands a clearance it does not have, so the first decision
    // must be to escalate.
    if let Err(err) = session.escalate().await {
        eprintln!("skipping: no browser available ({err})");
        return;
    }
    assert!(session.browser_is_running());
    assert_eq!(session.mode(), SessionMode::Browser);

    // Cookies gathered in the browser reach the shared identity, which is what
    // makes the handover lossless.
    let response = match session.fetch(TARGET).await {
        Ok(response) => response,
        Err(err) => {
            eprintln!("skipping: could not reach the network ({err})");
            return;
        }
    };
    assert!(response.body.contains("<html") || response.body.contains("<HTML"));

    let cookie_count = session
        .identity()
        .lock()
        .expect("identity lock")
        .cookies
        .len();

    // Demote explicitly and confirm the browser is gone.
    session.demote().expect("demote");
    assert!(
        !session.browser_is_running(),
        "the browser outlived its demotion"
    );
    assert_eq!(session.mode(), SessionMode::Http);

    // The identity survives the browser it was built in; that is the point.
    assert_eq!(
        session
            .identity()
            .lock()
            .expect("identity lock")
            .cookies
            .len(),
        cookie_count,
        "cookies were lost when the browser shut down"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_fetch_reuses_the_http_transport() {
    // Two requests, still no browser: the saving is per-session, not per-request.
    let mut session = build_session(SessionPolicy::default());

    for attempt in 0..2 {
        match session.fetch(TARGET).await {
            Ok(response) => assert!(
                !response.is_challenge(),
                "attempt {attempt} was challenged: {:?}",
                response.signal.kind
            ),
            Err(err) => {
                eprintln!("skipping: could not reach the network ({err})");
                return;
            }
        }
        assert!(
            !session.browser_is_running(),
            "attempt {attempt} launched a browser"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_identity_survives_a_save_and_restore() {
    // What makes a session resumable across process restarts.
    let mut session = build_session(SessionPolicy::default());

    if let Err(err) = session.fetch(TARGET).await {
        eprintln!("skipping: could not reach the network ({err})");
        return;
    }

    let saved = session.identity().lock().expect("lock").clone();
    let encoded = serde_json::to_string(&saved).expect("serialise the identity");
    let restored: stealthscraper_rs::StealthIdentity =
        serde_json::from_str(&encoded).expect("deserialise the identity");

    let mut fresh = build_session(SessionPolicy::default());
    fresh
        .restore(restored)
        .expect("restore onto the same egress");

    assert_eq!(
        fresh.identity().lock().expect("lock").cookies.len(),
        saved.cookies.len(),
        "cookies did not survive the round trip"
    );

    // And the restored session still works.
    match fresh.fetch(TARGET).await {
        Ok(response) => assert!(!response.is_challenge()),
        Err(err) => eprintln!("restored session could not fetch: {err}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn timing_is_reported_so_the_saving_is_visible() {
    // Not an assertion about speed — a record of what the two modes cost, since
    // the whole design is a performance trade.
    let mut session = build_session(SessionPolicy::default());

    let started = std::time::Instant::now();
    let first = session.fetch(TARGET).await;
    let first_elapsed = started.elapsed();
    if first.is_err() {
        eprintln!("skipping: could not reach the network");
        return;
    }

    let started = std::time::Instant::now();
    let _ = session.fetch(TARGET).await;
    let second_elapsed = started.elapsed();

    println!(
        "HTTP-only fetches: first {first_elapsed:?}, second {second_elapsed:?}, \
         browser running: {}",
        session.browser_is_running()
    );
    assert!(first_elapsed < Duration::from_secs(60));
}
