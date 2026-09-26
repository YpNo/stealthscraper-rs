//! Captures a real browser's User-Agent Client Hints, including the
//! high-entropy ones a page has to ask for.
//!
//! This is the instrument for the values `client_hints.rs` currently marks as
//! **not measured**: `platformVersion` on Windows and macOS, and the brand list
//! a *branded* Chrome emits (the build on this host is unbranded Chromium, which
//! reports a different greased entry).
//!
//! # Running it on this machine
//!
//! ```text
//! cargo run --example capture_hints
//! ```
//!
//! It launches the local browser with [`LaunchConfig::default`] — an **honest**
//! browser, with no User-Agent flag and none of this crate's stealth overrides —
//! serves it a page on `127.0.0.1` so the hints are exposed at all, and prints
//! what the browser reports.
//!
//! # Running it on a machine without a Rust toolchain
//!
//! Client hints are exposed only in a secure context, and a plain `http://` URL
//! on a LAN address is not one, so a remote browser cannot simply visit this
//! listener. Use the snippet this example prints instead: open any `https://`
//! page in the browser being measured, open the developer console, and paste it.
//! It reports the same values this example reads over CDP.
//!
//! # Why the launch must be honest
//!
//! Every override this crate applies — the `--user-agent` flag,
//! `Emulation.setUserAgentOverride`, the injected stealth script — changes
//! exactly the values being captured. Measuring through them would read our own
//! spoof back and call it evidence.

use std::time::Duration;

use stealthscraper_rs::cdp::{BrowserHandle, CdpTransport, LaunchConfig, launch};

/// Long enough for a cold browser start on a loaded machine.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The high-entropy hints worth capturing. `platformVersion` is the one the
/// crate currently guesses; the rest are captured at the same time because they
/// cost nothing extra and pin down the whole [`ClientHints`] struct.
///
/// [`ClientHints`]: stealthscraper_rs::ClientHints
const HIGH_ENTROPY: &[&str] = &[
    "platform",
    "platformVersion",
    "architecture",
    "bitness",
    "model",
    "uaFullVersion",
    "fullVersionList",
    "wow64",
];

/// The page the browser is pointed at. Anything on `127.0.0.1` counts as a
/// secure context, so no certificate is needed.
const PAGE: &str = "<html><head><title>hints</title></head><body>ok</body></html>";

/// Builds the expression evaluated in the page, and printed for manual use.
fn snippet() -> String {
    let hints = HIGH_ENTROPY
        .iter()
        .map(|h| format!("'{h}'"))
        .collect::<Vec<_>>()
        .join(", ");
    // An async IIFE rather than top-level `await`: `Runtime.evaluate` resolves
    // the promise it is handed (`awaitPromise`), but the expression itself is
    // not a module, so `await` at the top level is a syntax error.
    format!(
        "(async () => JSON.stringify({{ \
           userAgent: navigator.userAgent, \
           brands: navigator.userAgentData ? navigator.userAgentData.brands : null, \
           mobile: navigator.userAgentData ? navigator.userAgentData.mobile : null, \
           platform: navigator.userAgentData ? navigator.userAgentData.platform : null, \
           high: await (navigator.userAgentData \
             ? navigator.userAgentData.getHighEntropyValues([{hints}]) \
             : Promise.resolve(null)) \
         }}, null, 2))()"
    )
}

/// Serves one HTTP response on loopback and returns the URL to visit.
fn serve_once() -> std::io::Result<String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://127.0.0.1:{}/", listener.local_addr()?.port());

    std::thread::spawn(move || {
        use std::io::{Read, Write};
        // The browser may open more than one connection; answer them all so a
        // speculative socket does not leave the page waiting.
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut scratch = [0u8; 2048];
            let _ = stream.read(&mut scratch);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{PAGE}",
                PAGE.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    Ok(url)
}

/// Prints the captured values, and the table rows they belong in.
fn report(raw: &str) {
    println!("{raw}\n");

    let parsed: serde_json::Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(e) => {
            println!("could not parse the result as JSON: {e}");
            return;
        }
    };

    let high = &parsed["high"];
    if high.is_null() {
        println!(
            "navigator.userAgentData is absent — the page was not a secure \
             context, or the browser is not Chromium-based (Safari and Firefox \
             do not implement it)."
        );
        return;
    }

    let platform = high["platform"].as_str().unwrap_or("?");
    let version = high["platformVersion"].as_str().unwrap_or("?");
    println!("{}", "-".repeat(60));
    println!("for PLATFORM_VERSIONS in src/client_hints.rs:");
    println!("    ({platform:?}, {version:?}),");

    println!("\nfor ARCHITECTURE / BITNESS:");
    println!(
        "    architecture = {:?}, bitness = {:?}",
        high["architecture"].as_str().unwrap_or("?"),
        high["bitness"].as_str().unwrap_or("?")
    );

    println!("\nbrand list, in the order the browser reports it:");
    match parsed["brands"].as_array() {
        Some(brands) => {
            for brand in brands {
                println!(
                    "    {:?} v{:?}",
                    brand["brand"].as_str().unwrap_or("?"),
                    brand["version"].as_str().unwrap_or("?")
                );
            }
            let branded = brands
                .iter()
                .any(|b| b["brand"].as_str() == Some("Google Chrome"));
            println!(
                "\n  this is {} build — {}",
                if branded {
                    "a BRANDED Chrome"
                } else {
                    "an UNBRANDED Chromium"
                },
                if branded {
                    "usable for GREASE_BRAND"
                } else {
                    "NOT usable for GREASE_BRAND; a branded Chrome is needed"
                }
            );
        }
        None => println!("    (none reported)"),
    }
    println!("{}", "-".repeat(60));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let expression = snippet();

    println!("To measure a browser on another machine, open any https:// page");
    println!("there, open the developer console, paste this, and send back what");
    println!("it prints:\n");
    println!("{expression}\n");
    println!("{}", "=".repeat(60));
    println!("measuring the browser on this machine");
    println!("{}\n", "=".repeat(60));

    let url = serve_once()?;

    // An honest launch: no profile, so no User-Agent flag and no overrides.
    let browser = match launch(&LaunchConfig::default()) {
        Ok(browser) => browser,
        Err(e) => {
            println!("no local browser to measure ({e})");
            println!("the snippet above still works on any machine.");
            return Ok(());
        }
    };
    let handle = BrowserHandle::new(CdpTransport::connect(browser)?);

    let version = handle.version().await?;
    println!("browser: {version}\n");

    let page = handle.open(&url, TIMEOUT).await?;
    let result = page.evaluate(&expression).await?;
    match result.as_str() {
        Some(raw) => report(raw),
        None => println!("unexpected result shape: {result}"),
    }
    page.close().await?;

    Ok(())
}
