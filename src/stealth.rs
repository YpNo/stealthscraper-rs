use crate::profile::BrowserProfile;

/// Generates the stealth JavaScript required to mask headless browser attributes.
///
/// This function produces an IIFE (Immediately Invoked Function Expression) that overrides
/// `navigator` properties, masks WebGL vendor/renderer APIs, mocks `window.chrome`,
/// and spoofs the Permissions and Plugins APIs according to the given `BrowserProfile`.
pub fn generate_stealth_js(profile: &BrowserProfile) -> String {
    format!(
        r#"
(function() {{
    // 1. Overwrite navigator properties
    const overrideProperty = (obj, prop, value) => {{
        Object.defineProperty(obj, prop, {{
            get: () => value,
            enumerable: true,
            configurable: true
        }});
    }};

    overrideProperty(navigator, 'webdriver', false);
    overrideProperty(navigator, 'hardwareConcurrency', {concurrency});
    overrideProperty(navigator, 'deviceMemory', {memory});
    overrideProperty(navigator, 'platform', "{platform}");
    overrideProperty(navigator, 'userAgent', "{userAgent}");
    overrideProperty(navigator, 'languages', ["en-US", "en"]);

    // 2. Spoof WebGL
    const getParameterProxyHandler = {{
        apply: function(target, ctx, args) {{
            const param = args[0];
            // UNMASKED_VENDOR_WEBGL
            if (param === 37445) {{
                return "{webglVendor}";
            }}
            // UNMASKED_RENDERER_WEBGL
            if (param === 37446) {{
                return "{webglRenderer}";
            }}
            return Reflect.apply(target, ctx, args);
        }}
    }};
    
    const extensions = ['WEBGL_debug_renderer_info'];
    const getExtensionProxyHandler = {{
        apply: function(target, ctx, args) {{
            if (extensions.includes(args[0])) {{
                return {{}};
            }}
            return Reflect.apply(target, ctx, args);
        }}
    }};

    if (window.WebGLRenderingContext) {{
        WebGLRenderingContext.prototype.getParameter = new Proxy(
            WebGLRenderingContext.prototype.getParameter,
            getParameterProxyHandler
        );
        WebGLRenderingContext.prototype.getExtension = new Proxy(
            WebGLRenderingContext.prototype.getExtension,
            getExtensionProxyHandler
        );
    }}
    if (window.WebGL2RenderingContext) {{
        WebGL2RenderingContext.prototype.getParameter = new Proxy(
            WebGL2RenderingContext.prototype.getParameter,
            getParameterProxyHandler
        );
        WebGL2RenderingContext.prototype.getExtension = new Proxy(
            WebGL2RenderingContext.prototype.getExtension,
            getExtensionProxyHandler
        );
    }}

    // 3. Mock window.chrome
    if (!window.chrome) {{
        window.chrome = {{
            app: {{
                isInstalled: false,
                InstallState: {{
                    DISABLED: 'disabled',
                    INSTALLED: 'installed',
                    NOT_INSTALLED: 'not_installed'
                }},
                RunningState: {{
                    CANNOT_RUN: 'cannot_run',
                    READY_TO_RUN: 'ready_to_run',
                    RUNNING: 'running'
                }}
            }},
            runtime: {{
                OnInstalledReason: {{
                    CHROME_UPDATE: 'chrome_update',
                    INSTALL: 'install',
                    SHARED_MODULE_UPDATE: 'shared_module_update',
                    UPDATE: 'update'
                }},
                OnRestartRequiredReason: {{
                    APP_UPDATE: 'app_update',
                    OS_UPDATE: 'os_update',
                    PERIODIC: 'periodic'
                }},
                PlatformArch: {{
                    ARM: 'arm',
                    ARM64: 'arm64',
                    MIPS: 'mips',
                    MIPS64: 'mips64',
                    X86_32: 'x86-32',
                    X86_64: 'x86-64'
                }},
                PlatformNaclArch: {{
                    ARM: 'arm',
                    MIPS: 'mips',
                    MIPS64: 'mips64',
                    X86_32: 'x86-32',
                    X86_64: 'x86-64'
                }},
                PlatformOs: {{
                    ANDROID: 'android',
                    CROS: 'cros',
                    LINUX: 'linux',
                    MAC: 'mac',
                    OPENBSD: 'openbsd',
                    WIN: 'win'
                }},
                RequestUpdateCheckStatus: {{
                    NO_UPDATE: 'no_update',
                    THROTTLED: 'throttled',
                    UPDATE_AVAILABLE: 'update_available'
                }}
            }}
        }};
    }}

    // 4. Spoof Permissions API to avoid showing "prompt" when headless
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = parameters => (
        parameters.name === 'notifications' ?
            Promise.resolve({{ state: Notification.permission }}) :
            originalQuery(parameters)
    );

    // 5. Spoof Plugins
    Object.defineProperty(navigator, 'plugins', {{
        get: () => [1, 2, 3],
        enumerable: true,
        configurable: true
    }});

    // 6. Canvas Fingerprint Noise
    const addCanvasNoise = (canvas) => {{
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        const width = canvas.width || 0;
        const height = canvas.height || 0;
        if (width === 0 || height === 0) return;
        
        let imgData;
        try {{ imgData = ctx.getImageData(0, 0, width, height); }} catch (e) {{ return; }}
        if (imgData && imgData.data && imgData.data.length >= 4) {{
            // Add tiny, pseudo-random but consistent-per-session noise based on dimensions
            imgData.data[0] = (imgData.data[0] + (width % 5)) % 255;
            ctx.putImageData(imgData, 0, 0);
        }}
    }};

    const originalToDataUrl = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {{
        addCanvasNoise(this);
        return originalToDataUrl.apply(this, args);
    }};

    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(...args) {{
        const imgData = originalGetImageData.apply(this, args);
        if (imgData && imgData.data && imgData.data.length >= 4) {{
            imgData.data[0] = (imgData.data[0] + 1) % 255;
        }}
        return imgData;
    }};

    // 7. WebRTC Leak Prevention
    if (window.RTCPeerConnection) {{
        const originalRtc = window.RTCPeerConnection;
        window.RTCPeerConnection = function(...args) {{
            const pc = new originalRtc(...args);
            // Replace createDataChannel to mitigate leak patterns via data channels
            pc.createDataChannel = () => ({{
                close: () => {{}}, send: () => {{}}, 
                addEventListener: () => {{}}, removeEventListener: () => {{}}
            }});
            return pc;
        }};
        window.RTCPeerConnection.prototype = originalRtc.prototype;
    }}

    // 8. AudioContext Fingerprint Noise
    if (window.AudioBuffer) {{
        const originalGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function(channel) {{
            const results = originalGetChannelData.call(this, channel);
            if (results && results.length > 0) {{
                // Shift the first sample by a microscopic amount
                results[0] = results[0] + 0.0000001;
            }}
            return results;
        }};
    }}
}})();
        "#,
        concurrency = profile.hardware_concurrency,
        memory = profile.device_memory,
        platform = profile.platform,
        userAgent = profile.user_agent,
        webglVendor = profile.webgl_vendor,
        webglRenderer = profile.webgl_renderer
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::BrowserProfile;

    #[test]
    fn test_generate_stealth_js() {
        let profile = BrowserProfile {
            user_agent: "TestUserAgent".to_string(),
            platform: "TestPlatform".to_string(),
            hardware_concurrency: 8,
            device_memory: 16,
            webgl_vendor: "TestVendor".to_string(),
            webgl_renderer: "TestRenderer".to_string(),
            viewport_width: 1920,
            viewport_height: 1080,
            accept_language: "en-US".to_string(),
        };

        let script = generate_stealth_js(&profile);

        // Ensure key spoofing values are injected into the script
        assert!(script.contains("TestUserAgent"));
        assert!(script.contains("TestPlatform"));
        assert!(script.contains("16")); // Memory
        assert!(script.contains("TestVendor"));
        assert!(script.contains("TestRenderer"));
        assert!(script.contains("overrideProperty(navigator, 'webdriver', false)"));
        assert!(script.contains("window.chrome"));
    }
}
