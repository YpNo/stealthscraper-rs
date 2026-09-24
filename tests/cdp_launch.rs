//! Verifies the launcher against a real browser: CDP works over the pipe, and
//! the automation tells this crate exists to avoid are genuinely absent.

#![cfg(feature = "browser")]

use std::io::{Read, Write};

use stealthscraper_rs::cdp::{LaunchConfig, launch};

/// The raw CDP endpoints: what the browser writes, and what it reads.
struct Pipes {
    from_browser: std::io::PipeReader,
    to_browser: std::io::PipeWriter,
}

/// Reads one NUL-terminated CDP message, or `None` at end of stream.
fn read_message(browser: &mut Pipes) -> Option<String> {
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
fn call(browser: &mut Pipes, id: u32, message: &str) -> String {
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
    // Deliberately raw: this test exercises the launcher's pipes, so it does
    // not go through the transport that normally owns them.
    let (from_browser, to_browser) = browser.take_pipes().expect("CDP pipes");
    let mut pipes = Pipes {
        from_browser,
        to_browser,
    };

    let reply = call(&mut pipes, 1, r#"{"id":1,"method":"Browser.getVersion"}"#);

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
    let (from_browser, to_browser) = browser.take_pipes().expect("CDP pipes");
    let mut pipes = Pipes {
        from_browser,
        to_browser,
    };

    // Open a page and ask it directly. `Runtime.evaluate` is used explicitly
    // here; the point is that nothing enabled the Runtime domain implicitly.
    let created = call(
        &mut pipes,
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
        &mut pipes,
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
        &mut pipes,
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

/// Drives a real browser through the transport, which is what the rest of the
/// crate will use. The raw-pipe tests above prove the launcher; this proves the
/// demultiplexer against genuine CDP traffic, where events and replies really
/// do interleave.
#[tokio::test]
async fn the_transport_demultiplexes_real_cdp_traffic() {
    use serde_json::json;
    use stealthscraper_rs::cdp::CdpTransport;

    let browser = match launch(&LaunchConfig::default()) {
        Ok(browser) => browser,
        Err(err) => {
            eprintln!("skipping: no browser available ({err})");
            return;
        }
    };
    let cdp = CdpTransport::connect(browser).expect("connect the transport");

    let version = cdp
        .call("Browser.getVersion", None)
        .await
        .expect("Browser.getVersion");
    assert!(
        version["protocolVersion"].is_string(),
        "CDP did not answer over the pipe: {version}"
    );

    // Two calls in flight at once: the transport must route each reply to its
    // own caller. Sequentially reading "the next message" cannot do this.
    let (first, second) = tokio::join!(
        cdp.call("Browser.getVersion", None),
        cdp.call("SystemInfo.getInfo", None),
    );
    assert!(
        first.expect("first concurrent call")["product"].is_string(),
        "the first concurrent call got the wrong reply"
    );
    // SystemInfo may be unsupported on some builds; either answer is fine, so
    // long as it is *this* call's answer and not the other one's.
    match second {
        Ok(info) => assert!(info.get("product").is_none()),
        Err(err) => assert!(
            matches!(err, stealthscraper_rs::Error::Cdp { .. }),
            "expected this call's own error, got {err}"
        ),
    }

    // Attach to a page and read the automation marker back through the
    // transport, enabling no domain beyond the one this call needs.
    let created = cdp
        .call("Target.createTarget", Some(json!({ "url": "about:blank" })))
        .await
        .expect("Target.createTarget");
    let target_id = created["targetId"].as_str().expect("a targetId");

    let attached = cdp
        .call(
            "Target.attachToTarget",
            Some(json!({ "targetId": target_id, "flatten": true })),
        )
        .await
        .expect("Target.attachToTarget");
    let session_id = attached["sessionId"]
        .as_str()
        .expect("a sessionId")
        .to_string();

    let evaluated = cdp
        .call_in_session(
            Some(&session_id),
            "Runtime.evaluate",
            Some(json!({
                "expression": "String(navigator.webdriver)",
                "returnByValue": true
            })),
        )
        .await
        .expect("Runtime.evaluate");
    let webdriver = evaluated["result"]["value"].as_str().unwrap_or_default();
    assert!(
        webdriver == "false" || webdriver == "undefined",
        "navigator.webdriver is not false; the launch flags leaked automation: {evaluated}"
    );

    // An unknown method must surface as this call's own protocol error rather
    // than corrupting the stream for everyone else.
    let err = cdp
        .call("Nope.doesNotExist", None)
        .await
        .expect_err("an unknown method should fail");
    assert!(
        matches!(err, stealthscraper_rs::Error::Cdp { .. }),
        "expected a protocol error, got {err}"
    );
    // The connection is still usable afterwards.
    cdp.call("Browser.getVersion", None)
        .await
        .expect("the connection survived a protocol error");
}
