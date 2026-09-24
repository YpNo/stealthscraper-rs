//! Drives a real browser through the session layer.
//!
//! The unit tests prove the session layer's behaviour against a scripted peer.
//! These prove the assumptions that peer cannot check: that the browser really
//! does accept every one of these calls, and — the point of the whole module —
//! that reading a page works without ever enabling an observable domain.

#![cfg(feature = "browser")]

use std::time::Duration;

use stealthscraper_rs::cdp::{BrowserHandle, CdpTransport, LaunchConfig, launch};
use stealthscraper_rs::profile::BrowserProfile;

/// Connects to a browser, or returns `None` when none is installed.
fn browser() -> Option<BrowserHandle> {
    let profile = BrowserProfile::random();
    match launch(&LaunchConfig::for_profile(&profile)) {
        Ok(browser) => Some(BrowserHandle::new(
            CdpTransport::connect(browser).expect("connect the transport"),
        )),
        Err(err) => {
            eprintln!("skipping: no browser available ({err})");
            None
        }
    }
}

/// A page whose content is known, without needing a network or a server.
fn data_url(body: &str) -> String {
    // Percent-encoding only what a data URL cannot carry literally.
    let encoded = body
        .replace('%', "%25")
        .replace('#', "%23")
        .replace('&', "%26")
        .replace('?', "%3F");
    format!("data:text/html,{encoded}")
}

#[tokio::test]
async fn a_page_can_be_read_without_enabling_the_runtime_domain() {
    let Some(browser) = browser() else { return };

    let page = browser
        .open(
            &data_url(
                "<html><body><h1 id=title>Hello</h1><input name=q>\
                 <div id=hidden style='display:none'>x</div></body></html>",
            ),
            TIMEOUT,
        )
        .await
        .expect("open a page");

    // Runtime.evaluate is used throughout and Runtime.enable is never sent;
    // if evaluation required enabling the domain, these would fail.
    let content = page.content().await.expect("content");
    assert!(
        content.contains("Hello"),
        "the page's DOM did not come back: {content}"
    );

    let url = page.url().await.expect("url");
    assert!(url.starts_with("data:text/html,"), "unexpected URL: {url}");

    assert!(page.has_selector("#title").await.expect("selector"));
    assert!(!page.has_selector("#absent").await.expect("selector"));

    let centre = page
        .element_center("#title")
        .await
        .expect("centre")
        .expect("the heading is present");
    assert!(
        centre.0 > 0.0 && centre.1 > 0.0,
        "the heading has no position: {centre:?}"
    );
    assert_eq!(
        page.element_center("#absent").await.expect("centre"),
        None,
        "an absent element should have no centre"
    );
    // A hidden element does have a rect — an all-zero one. Reporting its
    // "centre" would give (0, 0): a real coordinate pointing somewhere else.
    assert_eq!(
        page.element_center("#hidden").await.expect("centre"),
        None,
        "a non-rendered element should have no centre"
    );

    page.close().await.expect("close the page");
}

#[tokio::test]
async fn a_navigation_and_its_load_event_are_not_raced() {
    let Some(browser) = browser() else { return };

    let page = browser.new_page("about:blank").await.expect("open a page");

    // A data URL loads about as fast as a load can complete, which is exactly
    // the case that would be missed by subscribing after navigating.
    page.navigate_and_wait(&data_url("<html><body>loaded</body></html>"), TIMEOUT)
        .await
        .expect("navigate and wait");

    let content = page.content().await.expect("content");
    assert!(content.contains("loaded"), "{content}");

    page.reload_and_wait(true, TIMEOUT).await.expect("reload");

    page.close().await.expect("close the page");
}

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn an_init_script_runs_before_the_page_and_input_reaches_it() {
    let Some(browser) = browser() else { return };

    let page = browser.new_page("about:blank").await.expect("open a page");

    // An init script must be installed before the document it applies to.
    page.add_init_script("window.__installed_first = true;")
        .await
        .expect("init script");
    page.navigate_and_wait(
        &data_url("<html><body><input id=field></body></html>"),
        TIMEOUT,
    )
    .await
    .expect("navigate");

    assert_eq!(
        page.evaluate("window.__installed_first === true")
            .await
            .expect("evaluate"),
        serde_json::Value::Bool(true),
        "the init script did not run ahead of the document"
    );

    // Typing must reach the focused field as real key events.
    page.evaluate("document.getElementById('field').focus()")
        .await
        .expect("focus");
    for character in "hi".chars() {
        page.press_key(character).await.expect("key");
    }
    assert_eq!(
        page.evaluate("document.getElementById('field').value")
            .await
            .expect("evaluate"),
        serde_json::Value::String("hi".to_string()),
        "key events did not reach the field"
    );

    page.close().await.expect("close the page");
}

#[tokio::test]
async fn a_click_reaches_the_element_it_lands_on() {
    let Some(browser) = browser() else { return };

    let page = browser
        .open(
            &data_url(
                "<html><body style='margin:0'>\
             <button id=b style='position:absolute;left:40px;top:60px;width:120px;height:40px'>\
             go</button>\
             <script>window.__clicked=false;\
             document.getElementById('b').addEventListener('click',()=>window.__clicked=true);\
             </script></body></html>",
            ),
            TIMEOUT,
        )
        .await
        .expect("open a page");

    page.wait_for_selector("#b", TIMEOUT)
        .await
        .expect("the button appeared");

    let (x, y) = page
        .element_center("#b")
        .await
        .expect("centre")
        .expect("the button is present");
    page.click_point(x, y).await.expect("click");

    assert_eq!(
        page.evaluate("window.__clicked").await.expect("evaluate"),
        serde_json::Value::Bool(true),
        "the click did not land on the button"
    );

    page.close().await.expect("close the page");
}

#[tokio::test]
async fn identity_overrides_are_accepted_by_the_browser() {
    let Some(browser) = browser() else { return };

    let profile = BrowserProfile::random();
    let page = browser.new_page("about:blank").await.expect("open a page");

    page.set_user_agent(
        &profile.user_agent,
        Some(&profile.accept_language),
        Some(&profile.platform),
        None,
    )
    .await
    .expect("user agent");
    page.set_timezone("Europe/Paris").await.expect("timezone");
    page.set_locale("fr-FR").await.expect("locale");
    page.set_viewport(profile.viewport_width, profile.viewport_height)
        .await
        .expect("viewport");

    page.navigate_and_wait(&data_url("<html><body>x</body></html>"), TIMEOUT)
        .await
        .expect("navigate");

    assert_eq!(
        page.evaluate("navigator.userAgent")
            .await
            .expect("evaluate"),
        serde_json::Value::String(profile.user_agent.clone()),
        "the page did not adopt the profile's User-Agent"
    );
    assert_eq!(
        page.evaluate("Intl.DateTimeFormat().resolvedOptions().timeZone")
            .await
            .expect("evaluate"),
        serde_json::Value::String("Europe/Paris".to_string()),
        "the timezone override did not take effect"
    );

    page.close().await.expect("close the page");
}

#[tokio::test]
async fn several_pages_are_driven_concurrently_over_one_connection() {
    let Some(browser) = browser() else { return };

    // Each page is addressed by its own session id. Reading all three at once
    // is what would expose a mix-up: with the reads in flight together, a
    // reply routed by arrival order rather than by id lands on the wrong page.
    let mut pages = Vec::new();
    for index in 0..3 {
        pages.push(
            browser
                .open(
                    &data_url(&format!("<html><body>page {index}</body></html>")),
                    TIMEOUT,
                )
                .await
                .expect("open a page"),
        );
    }

    let (first, second, third) =
        tokio::join!(pages[0].content(), pages[1].content(), pages[2].content(),);

    for (index, content) in [first, second, third].into_iter().enumerate() {
        let content = content.expect("content");
        assert!(
            content.contains(&format!("page {index}")),
            "page {index} received another page's content: {content}"
        );
    }

    for page in pages {
        page.close().await.expect("close the page");
    }
}
