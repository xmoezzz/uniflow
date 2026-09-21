use serde_yaml::Value;
use std::collections::BTreeSet;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

/// `Podfile.lock`'s `PODS:` sequence mixes plain scalars (`Alamofire
/// (5.4.3)`) with single-key mappings for pods that themselves list
/// subspecs (`SDWebImage (5.11.1): [...]`) — both forms carry the same
/// `Name (version)` string, just in a different YAML position, so both are
/// read the same way and the nested subspec list (already covered by its
/// own top-level `PODS` entry) is ignored.
pub struct CocoaPodsParser;

impl ManifestParser for CocoaPodsParser {
    fn ecosystem(&self) -> &'static str {
        "cocoapods"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["Podfile.lock"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(root) = serde_yaml::from_str::<Value>(&text) else {
            return Ok(Vec::new());
        };
        let Some(pods) = root.get("PODS").and_then(Value::as_sequence) else {
            return Ok(Vec::new());
        };

        let mut seen = BTreeSet::new();
        let mut deps = Vec::new();
        for item in pods {
            let entry = match item {
                Value::String(name) => Some(name.as_str()),
                Value::Mapping(map) => map.keys().next().and_then(Value::as_str),
                _ => None,
            };
            let Some((name, version)) = entry.and_then(parse_pod_entry) else { continue };
            if !seen.insert((name.clone(), version.clone())) {
                continue;
            }
            deps.push(Dependency {
                ecosystem: "cocoapods".to_string(),
                name,
                version,
                manifest_path: manifest_path.clone(),
                direct: false,
            });
        }
        Ok(deps)
    }
}

/// Parses `"Name (version)"` or `"Name/Subspec (version)"` into
/// `(pod_name, version)`, treating a subspec as belonging to its parent pod.
fn parse_pod_entry(entry: &str) -> Option<(String, String)> {
    let open = entry.find('(')?;
    let close = entry.rfind(')')?;
    if close <= open {
        return None;
    }
    let name = entry[..open].trim().split('/').next().unwrap_or_default().trim();
    let version = entry[open + 1..close].trim().trim_start_matches("= ").trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_a_pod_and_its_subspec_into_one_dependency() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Podfile.lock");
        std::fs::write(
            &path,
            "PODS:\n  - Alamofire (5.4.3)\n  - SDWebImage (5.11.1):\n    - SDWebImage/Core (= 5.11.1)\n  - SDWebImage/Core (5.11.1)\n\nDEPENDENCIES:\n  - Alamofire\n  - SDWebImage\n",
        )
        .expect("write fixture");

        let deps = CocoaPodsParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2, "{deps:?}");
        assert!(deps.iter().any(|dep| dep.name == "Alamofire" && dep.version == "5.4.3"));
        assert_eq!(deps.iter().filter(|dep| dep.name == "SDWebImage").count(), 1, "subspec must not double-count");
    }
}
