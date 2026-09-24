//! Verifies the launcher against a real browser: CDP works over the pipe, and
//! the automation tells this crate exists to avoid are genuinely absent.

#![cfg(feature = "browser")]

use std::io::{Read, Write};

use stealthscraper_rs::cdp::LaunchConfig;
use stealthscraper_rs::cdp::launch::{LaunchedBrowser, launch};

/// Reads one NUL-terminated CDP message, or `None` at end of stream.
fn read_message(browser: &mut LaunchedBrowser) -> Option<String> {
    let mut message = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match browser.from_browser.read(&mut byte) {
            Ok(1) if byte[0] == 0 => return Some(String::from_utf8_lossy(&message).into_owned()),
            Ok(1) => message.push(byte[0]),
            Ok(_) | Err(_) => return None,
        }
    }
}

/// Sends a CDP command and returns the reply carrying the matching `id`.
///
/// The browser interleaves events with command replies on the same stream, so
/// reading the next message is not enough — it has to be demultiplexed by id.
/// (The real transport does this properly; this is the minimum a test needs.)
fn call(browser: &mut LaunchedBrowser, id: u32, message: &str) -> String {
    browser
        .to_browser
        .write_all(format!("{message}\0").as_bytes())
        .expect("write CDP request");
    browser.to_browser.flush().expect("flush");

    let needle = format!("\"id\":{id},");
    let alt = format!("\"id\":{id}}}");
    for _ in 0..200 {
        match read_message(browser) {
            Some(msg) if msg.contains(&needle) || msg.contains(&alt) => return msg,
            // An event or another command's reply; keep looking.
            Some(_) => continue,
            None => break,
        }
    }
    panic!("no CDP reply with id {id} arrived");
}

#[tokio::test]
async fn speaks_cdp_over_the_pipe_with_no_debug_port() {
    let mut browser = match launch(&LaunchConfig::default()) {
        Ok(browser) => browser,
        // Without a browser installed there is nothing to verify; skip rather
        // than fail, so the suite still runs on machines without one.
        Err(err) => {
            eprintln!("skipping: no browser available ({err})");
            return;
        }
    };

    let reply = call(&mut browser, 1, r#"{"id":1,"method":"Browser.getVersion"}"#);

    assert!(
        reply.contains("\"protocolVersion\""),
        "CDP did not answer over the pipe: {reply}"
    );
    assert!(
        reply.contains("\"id\":1"),
        "reply did not correlate to the request: {reply}"
    );
}

#[tokio::test]
async fn the_browser_reports_no_automation_marker() {
    let mut browser = match launch(&LaunchConfig::default()) {
        Ok(browser) => browser,
        Err(err) => {
            eprintln!("skipping: no browser available ({err})");
            return;
        }
    };

    // Open a page and ask it directly. `Runtime.evaluate` is used explicitly
    // here; the point is that nothing enabled the Runtime domain implicitly.
    let created = call(
        &mut browser,
        1,
        r#"{"id":1,"method":"Target.createTarget","params":{"url":"about:blank"}}"#,
    );
    assert!(
        created.contains("targetId"),
        "could not open a target: {created}"
    );

    let target_id = created
        .split("\"targetId\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("targetId in reply")
        .to_string();

    let attached = call(
        &mut browser,
        2,
        &format!(
            r#"{{"id":2,"method":"Target.attachToTarget","params":{{"targetId":"{target_id}","flatten":true}}}}"#
        ),
    );
    let session_id = attached
        .split("\"sessionId\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("sessionId in reply")
        .to_string();

    let evaluated = call(
        &mut browser,
        3,
        &format!(
            r#"{{"id":3,"sessionId":"{session_id}","method":"Runtime.evaluate","params":{{"expression":"String(navigator.webdriver)","returnByValue":true}}}}"#
        ),
    );

    // Without --enable-automation the flag is false at the C++ level, before
    // any JavaScript patching.
    assert!(
        evaluated.contains("\"value\":\"false\"") || evaluated.contains("\"value\":\"undefined\""),
        "navigator.webdriver is not false; the launch flags leaked automation: {evaluated}"
    );
}
