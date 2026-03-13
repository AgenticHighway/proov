pub mod base;
pub mod browser_footprints;
pub mod containers;
pub mod content_analysis;
pub mod cursor_rules;
pub mod mcp_configs;
pub mod prompt_configs;

use base::Detector;

pub fn get_all_detectors(mode: &str) -> Vec<Box<dyn Detector>> {
    let mut d: Vec<Box<dyn Detector>> = vec![
        Box::new(cursor_rules::CursorRulesDetector),
        Box::new(containers::ContainerDetector),
        Box::new(prompt_configs::PromptConfigDetector),
        Box::new(mcp_configs::MCPConfigDetector),
    ];
    if mode == "host" || mode == "filesystem" {
        d.push(Box::new(browser_footprints::BrowserFootprintDetector));
    }
    d
}
