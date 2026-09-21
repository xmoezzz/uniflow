use serde_json::Value;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

/// Swift Package Manager's `Package.resolved` changed shape between format
/// version 1 (`object.pins[].package` / `.state.version`) and version 2
/// (`pins[].identity` / `.state.version`); both are handled here.
pub struct SwiftPmParser;

impl ManifestParser for SwiftPmParser {
    fn ecosystem(&self) -> &'static str {
        "swiftpm"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["Package.resolved"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(root) = serde_json::from_str::<Value>(&text) else {
            return Ok(Vec::new());
        };

        let format_version = root.get("version").and_then(Value::as_i64).unwrap_or(2);
        let pins = if format_version == 1 {
            root.pointer("/object/pins")
        } else {
            root.get("pins")
        };
        let Some(pins) = pins.and_then(Value::as_array) else {
            return Ok(Vec::new());
        };

        let name_key = if format_version == 1 { "package" } else { "identity" };
        Ok(pins
            .iter()
            .filter_map(|pin| {
                let name = pin.get(name_key).and_then(Value::as_str)?;
                let version = pin.pointer("/state/version").and_then(Value::as_str)?;
                Some(Dependency {
                    ecosystem: "swiftpm".to_string(),
                    name: name.to_string(),
                    version: version.to_string(),
                    manifest_path: manifest_path.clone(),
                    direct: false,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_format_package_resolved() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Package.resolved");
        std::fs::write(
            &path,
            r#"{ "pins": [ { "identity": "swift-nio", "state": { "version": "2.29.0" } } ], "version": 2 }"#,
        )
        .expect("write fixture");

        let deps = SwiftPmParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "swift-nio");
        assert_eq!(deps[0].version, "2.29.0");
    }

    #[test]
    fn parses_v1_format_package_resolved() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Package.resolved");
        std::fs::write(
            &path,
            r#"{ "object": { "pins": [ { "package": "swift-nio", "state": { "version": "2.29.0" } } ] }, "version": 1 }"#,
        )
        .expect("write fixture");

        let deps = SwiftPmParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "swift-nio");
    }
}
