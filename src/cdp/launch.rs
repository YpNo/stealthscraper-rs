//! Launching Chrome for CDP control, without the automation tells.
//!
//! The command line a browser is started with decides several things a page can
//! observe. This module owns that command line so the observable ones can be
//! chosen deliberately rather than inherited from a driver's defaults.
//!
//! Three differences from a conventional driver launch matter:
//!
//! - **`--enable-automation` is never passed.** It sets `navigator.webdriver`
//!   at the C++ level and surfaces the automation infobar. Masking it from
//!   JavaScript afterwards is strictly worse than not setting it.
//! - **`--remote-debugging-pipe` replaces `--remote-debugging-port`.** A TCP
//!   debug port on loopback can be found by a page that probes local ports; a
//!   pipe on inherited file descriptors cannot be reached from the network at
//!   all.
//! - **`--headless=new` rather than the legacy headless mode**, whose separate
//!   code path differed from headed Chrome in externally visible ways.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::Error;

/// File descriptor Chrome reads CDP messages from.
pub(crate) const PIPE_READ_FD: i32 = 3;

/// File descriptor Chrome writes CDP messages to.
pub(crate) const PIPE_WRITE_FD: i32 = 4;

/// Executable names to look for when no explicit path is configured.
const CHROME_EXECUTABLES: &[&str] = &[
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "chrome",
];

/// Flags a conventional driver adds that this launcher deliberately omits.
///
/// Kept as data so a test can assert none of them reappear: each one is either
/// directly observable from a page or moves the browser away from a stock
/// configuration.
#[cfg(test)]
const DELIBERATELY_OMITTED: &[&str] = &[
    // Sets navigator.webdriver and shows the automation infobar.
    "--enable-automation",
    // Opens a TCP port a page can probe; superseded by the pipe.
    "--remote-debugging-port",
    // A stock browser has extensions and default apps enabled.
    "--disable-extensions",
    "--disable-default-apps",
    // Used by drivers to suppress the "Chrome is being controlled" state.
    "--disable-infobars",
];

/// How to launch the browser.
#[derive(Debug, Clone)]
pub struct LaunchConfig {
    /// Explicit browser binary. Discovered from `PATH` when `None`.
    pub chrome_path: Option<PathBuf>,
    /// Run without a visible window.
    pub headless: bool,
    /// `User-Agent` to launch with, which must agree with the active profile.
    pub user_agent: Option<String>,
    /// `Accept-Language` to launch with.
    pub accept_language: Option<String>,
    /// Window size in pixels.
    pub window_size: Option<(u32, u32)>,
    /// Proxy for the browser to use, usually the local MITM listener.
    pub proxy_server: Option<String>,
    /// Accept invalid certificates, required when routing through the MITM proxy.
    pub accept_insecure_certs: bool,
    /// Disable the OS sandbox.
    ///
    /// Required inside most containers, where the sandbox cannot initialise.
    /// This weakens the isolation between renderer and host, so it is left to
    /// the caller rather than being forced on.
    pub no_sandbox: bool,
    /// Extra flags appended verbatim, for cases this config does not cover.
    pub extra_args: Vec<String>,
}

impl Default for LaunchConfig {
    fn default() -> Self {
        Self {
            chrome_path: None,
            headless: true,
            user_agent: None,
            accept_language: None,
            window_size: None,
            proxy_server: None,
            accept_insecure_certs: false,
            // Matches the historical behaviour of this crate, which is deployed
            // in containers where the sandbox is unavailable.
            no_sandbox: true,
            extra_args: Vec::new(),
        }
    }
}

/// Locates a browser binary, preferring `config`'s explicit path.
pub fn find_chrome(config: &LaunchConfig) -> Result<PathBuf, Error> {
    if let Some(path) = &config.chrome_path {
        return if path.exists() {
            Ok(path.clone())
        } else {
            Err(Error::ConfigError(format!(
                "configured chrome_path does not exist: {}",
                path.display()
            )))
        };
    }

    if let Some(path) = std::env::var_os("CHROME_BIN").map(PathBuf::from)
        && path.exists()
    {
        return Ok(path);
    }

    let search_path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&search_path) {
        for name in CHROME_EXECUTABLES {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(Error::ConfigError(format!(
        "no browser found on PATH (looked for {}); set CHROME_BIN or chrome_path",
        CHROME_EXECUTABLES.join(", ")
    )))
}

/// Builds the browser's command line.
///
/// Pure, so the resulting flags can be asserted without launching anything.
pub fn build_args(config: &LaunchConfig, user_data_dir: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();

    // CDP over inherited descriptors, so no port is exposed.
    args.push("--remote-debugging-pipe".into());

    // Each launch gets a private profile directory, so nothing persists
    // between identities unless the caller arranges it.
    let mut user_data = OsString::from("--user-data-dir=");
    user_data.push(user_data_dir.as_os_str());
    args.push(user_data);

    if config.headless {
        // The modern headless mode shares the headed code path.
        args.push("--headless=new".into());
    }

    // Blink-level flag that removes the automation-controlled marker.
    args.push("--disable-blink-features=AutomationControlled".into());

    // First-run UI and default-browser prompts would block an automated start.
    args.push("--no-first-run".into());
    args.push("--no-default-browser-check".into());

    if config.no_sandbox {
        args.push("--no-sandbox".into());
    }

    // Shared memory in containers is typically too small for Chrome's default.
    args.push("--disable-dev-shm-usage".into());

    if let Some(user_agent) = &config.user_agent {
        args.push(format!("--user-agent={user_agent}").into());
    }
    if let Some(language) = &config.accept_language {
        args.push(format!("--accept-lang={language}").into());
    }
    if let Some((width, height)) = config.window_size {
        args.push(format!("--window-size={width},{height}").into());
    }
    if let Some(proxy) = &config.proxy_server {
        args.push(format!("--proxy-server={proxy}").into());
        // Keep loopback traffic off the proxy so the CDP transport and any
        // local test server stay reachable.
        args.push("--proxy-bypass-list=<-loopback>".into());
    }
    if config.accept_insecure_certs {
        args.push("--ignore-certificate-errors".into());
    }

    args.extend(config.extra_args.iter().map(OsString::from));

    args
}

/// A private profile directory removed when the launch ends.
#[derive(Debug)]
pub struct ProfileDir {
    path: PathBuf,
}

impl ProfileDir {
    /// Creates a fresh profile directory under the system temp directory.
    pub fn new() -> Result<Self, Error> {
        use rand::RngExt;

        // A random suffix keeps concurrent launches from colliding without
        // pulling in a temp-file crate.
        let suffix: u64 = rand::rng().random();
        let path = std::env::temp_dir().join(format!("stealthscraper-{suffix:016x}"));
        std::fs::create_dir_all(&path).map_err(|e| {
            Error::ConfigError(format!(
                "could not create profile directory {}: {e}",
                path.display()
            ))
        })?;
        Ok(Self { path })
    }

    /// The directory's path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ProfileDir {
    fn drop(&mut self) {
        // Best effort: a leftover temp directory is not worth failing over.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A launched browser and the CDP pipe endpoints that talk to it.
///
/// Dropping this kills the browser and removes its profile directory.
#[derive(Debug)]
pub struct LaunchedBrowser {
    child: std::process::Child,
    /// Writes CDP messages to the browser.
    pub to_browser: std::io::PipeWriter,
    /// Reads CDP messages from the browser.
    pub from_browser: std::io::PipeReader,
    /// Kept alive so the profile outlives the process that uses it.
    _profile: ProfileDir,
}

impl LaunchedBrowser {
    /// The browser process id, for diagnostics.
    pub fn id(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for LaunchedBrowser {
    fn drop(&mut self) {
        // The browser has no other owner, so terminate rather than orphan it.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Launches a browser with CDP bound to inherited file descriptors.
///
/// Chrome reads its CDP input from descriptor 3 and writes its output to
/// descriptor 4, so two pipes are created and their far ends mapped onto those
/// numbers in the child. No network port is involved at any point.
///
/// The descriptor remapping is performed by `command-fds`, which keeps the
/// required `dup2` inside an audited dependency rather than adding `unsafe`
/// here.
pub fn launch(config: &LaunchConfig) -> Result<LaunchedBrowser, Error> {
    use command_fds::{CommandFdExt, FdMapping};
    use std::os::fd::OwnedFd;

    let binary = find_chrome(config)?;
    let profile = ProfileDir::new()?;

    // Parent writes here, the browser reads it as descriptor 3.
    let (browser_input, to_browser) = std::io::pipe()
        .map_err(|e| Error::BrowserError(format!("could not create CDP input pipe: {e}")))?;
    // The browser writes to descriptor 4, the parent reads it here.
    let (from_browser, browser_output) = std::io::pipe()
        .map_err(|e| Error::BrowserError(format!("could not create CDP output pipe: {e}")))?;

    let mut command = std::process::Command::new(&binary);
    command
        .args(build_args(config, profile.path()))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // Ownership of the child's ends moves into the mapping, so they are closed
    // in the parent once the child has them. Holding a copy here would stop the
    // parent from ever seeing end-of-file.
    command
        .fd_mappings(vec![
            FdMapping {
                parent_fd: OwnedFd::from(browser_input),
                child_fd: PIPE_READ_FD,
            },
            FdMapping {
                parent_fd: OwnedFd::from(browser_output),
                child_fd: PIPE_WRITE_FD,
            },
        ])
        .map_err(|e| Error::BrowserError(format!("could not map CDP descriptors: {e}")))?;

    let child = command
        .spawn()
        .map_err(|e| Error::BrowserError(format!("could not launch {}: {e}", binary.display())))?;

    Ok(LaunchedBrowser {
        child,
        to_browser,
        from_browser,
        _profile: profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_for(config: &LaunchConfig) -> Vec<String> {
        build_args(config, Path::new("/tmp/profile"))
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn never_emits_the_automation_tells() {
        // The point of owning the command line: these must not appear under
        // any configuration.
        let configs = [
            LaunchConfig::default(),
            LaunchConfig {
                headless: false,
                no_sandbox: false,
                accept_insecure_certs: true,
                proxy_server: Some("http://127.0.0.1:8080".into()),
                user_agent: Some("UA".into()),
                ..LaunchConfig::default()
            },
        ];

        for config in &configs {
            let args = args_for(config);
            for omitted in DELIBERATELY_OMITTED {
                assert!(
                    !args.iter().any(|a| a.starts_with(omitted)),
                    "{omitted} must never be passed, found in {args:?}"
                );
            }
        }
    }

    #[test]
    fn uses_a_pipe_rather_than_a_debug_port() {
        let args = args_for(&LaunchConfig::default());
        assert!(args.iter().any(|a| a == "--remote-debugging-pipe"));
        assert!(
            !args
                .iter()
                .any(|a| a.starts_with("--remote-debugging-port")),
            "a TCP debug port is reachable from a page and must not be opened"
        );
    }

    #[test]
    fn uses_the_modern_headless_mode_only_when_headless() {
        let headless = args_for(&LaunchConfig::default());
        assert!(headless.iter().any(|a| a == "--headless=new"));
        // The legacy mode differed observably from headed Chrome.
        assert!(!headless.iter().any(|a| a == "--headless"));

        let headed = args_for(&LaunchConfig {
            headless: false,
            ..LaunchConfig::default()
        });
        assert!(!headed.iter().any(|a| a.starts_with("--headless")));
    }

    #[test]
    fn disables_the_blink_automation_marker() {
        let args = args_for(&LaunchConfig::default());
        assert!(
            args.iter()
                .any(|a| a == "--disable-blink-features=AutomationControlled")
        );
    }

    #[test]
    fn profile_directory_is_private_per_launch() {
        let args = args_for(&LaunchConfig::default());
        assert!(args.iter().any(|a| a == "--user-data-dir=/tmp/profile"));
    }

    #[test]
    fn identity_flags_are_passed_through() {
        let args = args_for(&LaunchConfig {
            user_agent: Some("Mozilla/5.0 Test".into()),
            accept_language: Some("fr-FR,fr;q=0.9".into()),
            window_size: Some((1280, 800)),
            ..LaunchConfig::default()
        });
        assert!(args.iter().any(|a| a == "--user-agent=Mozilla/5.0 Test"));
        assert!(args.iter().any(|a| a == "--accept-lang=fr-FR,fr;q=0.9"));
        assert!(args.iter().any(|a| a == "--window-size=1280,800"));
    }

    #[test]
    fn proxy_bypasses_loopback_so_cdp_and_local_servers_stay_reachable() {
        let args = args_for(&LaunchConfig {
            proxy_server: Some("http://127.0.0.1:9000".into()),
            ..LaunchConfig::default()
        });
        assert!(
            args.iter()
                .any(|a| a == "--proxy-server=http://127.0.0.1:9000")
        );
        assert!(args.iter().any(|a| a == "--proxy-bypass-list=<-loopback>"));
    }

    #[test]
    fn insecure_certs_are_accepted_only_when_requested() {
        assert!(
            !args_for(&LaunchConfig::default())
                .iter()
                .any(|a| a == "--ignore-certificate-errors")
        );
        assert!(
            args_for(&LaunchConfig {
                accept_insecure_certs: true,
                ..LaunchConfig::default()
            })
            .iter()
            .any(|a| a == "--ignore-certificate-errors")
        );
    }

    #[test]
    fn sandbox_stays_on_when_the_caller_asks_for_it() {
        let sandboxed = args_for(&LaunchConfig {
            no_sandbox: false,
            ..LaunchConfig::default()
        });
        assert!(!sandboxed.iter().any(|a| a == "--no-sandbox"));
    }

    #[test]
    fn profile_directory_is_created_and_removed() {
        let path = {
            let dir = ProfileDir::new().expect("create profile dir");
            let path = dir.path().to_path_buf();
            assert!(path.is_dir());
            path
        };
        assert!(!path.exists(), "profile directory outlived its handle");
    }

    #[test]
    fn missing_configured_chrome_path_is_reported() {
        let result = find_chrome(&LaunchConfig {
            chrome_path: Some(PathBuf::from("/nonexistent/chrome")),
            ..LaunchConfig::default()
        });
        assert!(matches!(result, Err(Error::ConfigError(_))));
    }
}
