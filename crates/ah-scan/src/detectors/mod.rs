pub mod base;
pub mod browser_footprints;
pub mod containers;
pub mod custom_rules;
pub mod mcp_configs;

use base::Detector;

pub fn get_all_detectors(mode: &str) -> Vec<Box<dyn Detector>> {
    let mut d: Vec<Box<dyn Detector>> = vec![
        Box::new(custom_rules::CustomRulesDetector::load()),
        Box::new(containers::ContainerDetector),
        Box::new(mcp_configs::MCPConfigDetector),
    ];
    if matches!(mode, "host" | "filesystem" | "home" | "root") {
        d.push(Box::new(browser_footprints::BrowserFootprintDetector));
    }
    d
}
