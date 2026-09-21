use serde_json::Value;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

/// Haxe has no widely-used resolved lockfile the way npm/Cargo do; the
/// closest analog is `haxelib.json`'s own `dependencies` map (name ->
/// version, where an empty string conventionally means "any version").
pub struct HaxelibParser;

impl ManifestParser for HaxelibParser {
    fn ecosystem(&self) -> &'static str {
        "haxelib"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["haxelib.json"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(root) = serde_json::from_str::<Value>(&text) else {
            return Ok(Vec::new());
        };
        let Some(dependencies) = root.get("dependencies").and_then(Value::as_object) else {
            return Ok(Vec::new());
        };
        Ok(dependencies
            .iter()
            .map(|(name, version)| Dependency {
                ecosystem: "haxelib".to_string(),
                name: name.clone(),
                version: version.as_str().unwrap_or_default().to_string(),
                manifest_path: manifest_path.clone(),
                direct: true,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dependencies_including_an_any_version_entry() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("haxelib.json");
        std::fs::write(&path, r#"{ "name": "demo", "dependencies": { "hxcpp": "4.2.1", "utest": "" } }"#).expect("write fixture");

        let deps = HaxelibParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2);
        let hxcpp = deps.iter().find(|dep| dep.name == "hxcpp").expect("present");
        assert_eq!(hxcpp.version, "4.2.1");
        let utest = deps.iter().find(|dep| dep.name == "utest").expect("present");
        assert_eq!(utest.version, "");
    }
}
