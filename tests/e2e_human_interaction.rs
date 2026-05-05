use rs_cloudscraper::{BrowserProfile, CloudScraper};

#[tokio::test]
async fn test_e2e_human_interaction_timing() {
    let profile = BrowserProfile::random();

    let scraper = CloudScraper::builder()
        .profile(profile)
        .headless(true)
        .disable_proxy()
        .build()
        .await
        .expect("Failed to build stealth scraper");

    let tab = scraper.new_stealth_tab().expect("Failed to open tab");

    // We can load a local HTML blob that logs Javascript Date.now() values to track typing jitter dynamically in DOM
    let html_content = r#"
        <html>
        <body>
            <input id="test-input" type="text" />
            <script>
                window.keyTimings = [];
                document.getElementById('test-input').addEventListener('keydown', (e) => {
                    window.keyTimings.push(Date.now());
                });
                
                window.mouseTimings = [];
                document.addEventListener('mousemove', (e) => {
                    window.mouseTimings.push(Date.now());
                });
            </script>
        </body>
        </html>
    "#;

    let file_path = std::env::temp_dir().join("test_human.html");
    std::fs::write(&file_path, html_content).expect("Failed to write mock HTML");
    let file_url = format!("file://{}", file_path.display());

    tab.navigate_to(&file_url).expect("Failed to navigate");
    tab.wait_until_navigated()
        .expect("Failed wait for navigation");

    // 1. Move the mouse to the input using Bezier curves
    let input_element = tab.wait_for_element("#test-input").unwrap();
    let box_model = input_element.get_box_model().unwrap();
    let x = box_model.content.most_left();
    let y = box_model.content.most_top();

    CloudScraper::human_move_mouse(&tab, x, y).expect("Failed to move mouse");

    // Verify DOM captured the bezier trajectory events
    let mouse_events = tab.evaluate("window.mouseTimings.length", false).unwrap();
    let mouse_count = mouse_events.value.unwrap_or_default().as_u64().unwrap_or(0);
    assert!(
        mouse_count > 10,
        "Not enough mouse events captured, path generation failed to emit realistic steps"
    );

    // 2. Click the input and type using human jitter
    tab.click_point(headless_chrome::browser::tab::point::Point { x, y })
        .unwrap();

    let phrase = "hello"; // 5 keys
    CloudScraper::human_type_str(&tab, phrase).expect("Failed to type string");

    // Verify typing interaction jitter via DOM tracking!
    let key_events_js = tab
        .evaluate("JSON.stringify(window.keyTimings)", false)
        .unwrap();
    let key_events_str = key_events_js
        .value
        .unwrap_or_default()
        .as_str()
        .unwrap()
        .to_string();
    let timings: Vec<u64> = serde_json::from_str(&key_events_str).unwrap();

    assert_eq!(
        timings.len(),
        5,
        "Should have exactly 5 key events registered"
    );

    // Ensure the timespan between the first keystroke and the last is greater than minimum inhuman bounds
    // (5 keys * min 20ms delay each = at least 80ms total delta)
    let total_delta = timings.last().unwrap() - timings.first().unwrap();
    assert!(
        total_delta >= 80,
        "Typing speed unrealistic, jitter wasn't applied"
    );

    println!("Validated global E2E human interaction tracing inside headless Chromium.");
}
