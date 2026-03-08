# rs-cloudscraper

[![Rust CI](https://github.com/YpNo/rs-cloudscraper/actions/workflows/ci.yml/badge.svg)](https://github.com/YpNo/rs-cloudscraper/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rs-cloudscraper.svg)](https://crates.io/crates/rs-cloudscraper)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`rs-cloudscraper` is a blazing-fast, stealthy Rust library designed to simulate highly realistic human browser behavior and completely bypass advanced bot-protection systems like Cloudflare, Akamai, and Datadome.

By combining the low-level automation power of CDP (Chrome DevTools Protocol) with state-of-the-art JA4 / TLS `ClientHello` network impersonation, `rs-cloudscraper` guarantees that your scraping agents remain undetectable.

---

## 🚀 Features

- **JA4 TLS Emulation**: An embedded Man-in-the-Middle (MITM) proxy automatically intercepts headless Chrome traffic and reconstructs it with perfect HTTP/2 and TLS signatures (`ClientHello`, exact ciphers, and extensions) using `rquest`.
- **Intelligent CDP Stealth**: Automatically overrides `navigator.webdriver`, masks WebGL vendors, mocks `window.chrome`, spoofs Permissions/Plugins APIs, and injects micro-noise into Canvas and AudioContext rendering to defeat browser fingerprinting.
- **Human Evasion**: API methods to simulate Bezier-curve mouse movements and human-like typing delays based on psychological keystroke timing.
- **Flexible Builder Pattern**: Easily opt-in or out of the TLS proxy for speed vs. maximum stealth.
- **Strong Types & Errors**: Built with `thiserror` for comprehensive, matchable error states.

## 🏗️ How it Works

Bot-protections identify headless browsers using two primary vectors:
1. **JavaScript Probing**: Inspecting the DOM (like `navigator.webdriver` or distinct WebGL signatures).
2. **Network Fingerprinting (JA3/JA4)**: Inspecting the raw TLS connection. Headless Chrome's network signature is explicitly different from a standard Chrome browser.

**The `rs-cloudscraper` solution:**
1. A realistic `BrowserProfile` (e.g., Windows 10, Chrome 120, 16GB RAM, NVIDIA WebGL) is explicitly defined.
2. A headless Chrome instance is launched, and Javascript interceptors mask the internal DOM to perfectly match this profile.
3. Chrome routes its traffic through our internal multi-threaded `TlsSpoofingProxy`.
4. The proxy terminates Chrome's TLS connection locally, reads the HTTP data, and forwards it to the target website using a specialized Rust HTTP/2 Client (`rquest`). This client perfectly shapes the outbound TLS layer to mimic the exact JA4 cipher suite of the configured `BrowserProfile`, tricking the edge proxy (like Cloudflare) into accepting the connection as a genuine human browser.

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rs-cloudscraper = "0.1.0"
```

*Note: Since the underlying TLS impersonation utilizes `boring-sys`, you will need `cmake` installed on your build machine.*

## 💻 Usage

```rust
use rs_cloudscraper::{CloudScraper, BrowserProfile};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), rs_cloudscraper::Error> {
    
    // Choose a specific profile, or let the library randomize it
    let profile = BrowserProfile::random();

    // The builder automatically initializes the JA4 proxy to match the profile!
    let scraper = CloudScraper::builder()
        .profile(profile)
        .build()
        .await?;

    let tab = scraper.new_stealth_tab()?;

    // The headless browser traffic is transparently MITM intercepted
    // and rebuilt as perfect HTTP/2 TLS mimicking the exact BrowserProfile.
    tab.navigate_to("https://target-protected-website.com")?;
    tab.wait_until_navigated()?;
    
    println!("Successfully bypassed bot protection!");

    Ok(())
}
```

### Opting out of the Proxy

If you only need CDP stealth and want to save network overhead, you can disable the local TLS proxy:

```rust
let scraper = CloudScraper::builder()
    .disable_proxy()
    .build()
    .await?;
```

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Format and Lint your code (`cargo fmt` and `cargo clippy`)
4. Run the test suite (`cargo test`)
5. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
6. Push to the Branch (`git push origin feature/AmazingFeature`)
7. Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## ⚠️ Disclaimer

This library is intended for educational purposes, legitimate web scraping, and automated software testing. Authors accept no responsibility for the misuse of this tool. Please consult the Terms of Service of the targeted websites before engaging in scraping operations.
