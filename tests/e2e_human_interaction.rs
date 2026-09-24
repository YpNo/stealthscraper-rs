//! End-to-end check that simulated input arrives in a real browser with
//! human-like timing, measured by the page itself rather than by us.

use std::time::Duration;

use stealthscraper_rs::{BrowserProfile, CloudScraper};

/// How long to wait for the fixture page to load.
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Characters typed by the test.
const PHRASE: &str = "hello";

/// Floor for the whole typing burst: five keys at the 20 ms minimum each.
const MIN_TYPING_SPAN_MS: u64 = 80;

#[tokio::test]
async fn typing_and_pointer_motion_arrive_with_human_timing() {
    let scraper = CloudScraper::builder()
        .profile(BrowserProfile::random())
        .headless(true)
        .disable_proxy()
        .build()
        .await
        .expect("Failed to build stealth scraper");

    let page = scraper
        .new_stealth_page()
        .await
        .expect("Failed to open a page");

    // The page timestamps every event it receives, so the assertions below are
    // about what the browser actually observed, not about what we sent.
    let fixture = "<html><body style='margin:0'>\
         <input id='field' style='position:absolute;left:20px;top:20px;width:200px;height:30px'>\
         <script>\
         window.keyTimings=[];window.mouseTimings=[];\
         document.getElementById('field').addEventListener('keydown',()=>\
           window.keyTimings.push(Date.now()));\
         document.addEventListener('mousemove',()=>window.mouseTimings.push(Date.now()));\
         </script></body></html>";

    page.navigate_and_wait(&format!("data:text/html,{fixture}"), LOAD_TIMEOUT)
        .await
        .expect("Failed to navigate");

    // 1. Move the pointer to the field along a Bézier path.
    let (x, y) = page
        .element_center("#field")
        .await
        .expect("element centre")
        .expect("the field is present");
    CloudScraper::human_move_mouse(&page, x, y)
        .await
        .expect("Failed to move the mouse");

    let moves = page
        .evaluate("window.mouseTimings.length")
        .await
        .expect("read mouse timings")
        .as_u64()
        .unwrap_or(0);
    assert!(
        moves > 10,
        "a Bézier path should emit many intermediate moves, saw {moves}"
    );

    // 2. Click the field and type into it.
    page.click_point(x, y).await.expect("Failed to click");
    CloudScraper::human_type_str(&page, PHRASE)
        .await
        .expect("Failed to type");

    let timings: Vec<u64> = serde_json::from_str(
        page.evaluate("JSON.stringify(window.keyTimings)")
            .await
            .expect("read key timings")
            .as_str()
            .expect("key timings as JSON"),
    )
    .expect("decode key timings");

    assert_eq!(
        timings.len(),
        PHRASE.chars().count(),
        "every keystroke should register exactly once"
    );

    // Keystrokes spaced by a sampled delay, not emitted as fast as the loop runs.
    let span = timings
        .last()
        .zip(timings.first())
        .map(|(last, first)| last - first)
        .expect("at least two keystrokes");
    assert!(
        span >= MIN_TYPING_SPAN_MS,
        "typing spanned only {span}ms; the inter-key jitter was not applied"
    );

    // The characters landed in the field, not merely as events.
    assert_eq!(
        page.evaluate("document.getElementById('field').value")
            .await
            .expect("read the field"),
        serde_json::Value::String(PHRASE.to_string()),
    );
}
