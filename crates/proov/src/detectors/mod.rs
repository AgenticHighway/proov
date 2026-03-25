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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workdir_mode_has_three_detectors() {
        let detectors = get_all_detectors("workdir");
        assert_eq!(detectors.len(), 3);
    }

    #[test]
    fn host_mode_includes_browser_detector() {
        let detectors = get_all_detectors("host");
        assert_eq!(detectors.len(), 4);
        assert!(detectors.iter().any(|d| d.name() == "browser_footprints"));
    }

    #[test]
    fn root_mode_includes_browser_detector() {
        let detectors = get_all_detectors("root");
        assert_eq!(detectors.len(), 4);
    }

    #[test]
    fn file_mode_excludes_browser_detector() {
        let detectors = get_all_detectors("file");
        assert!(!detectors.iter().any(|d| d.name() == "browser_footprints"));
    }

    #[test]
    fn all_detectors_have_names() {
        let detectors = get_all_detectors("host");
        for d in &detectors {
            assert!(!d.name().is_empty());
        }
    }
}
