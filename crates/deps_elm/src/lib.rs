use serde_json::Value;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

/// `elm.json` doubles as both manifest and (for `"type": "application"`)
/// lockfile: an application pins exact versions under
/// `dependencies.direct`/`dependencies.indirect`, while a package instead
/// declares version *ranges* under a flat `dependencies` map — this records
/// the range string as-is in that case, same as other ecosystems do for an
/// unresolved manifest-level constraint.
pub struct ElmParser;

impl ManifestParser for ElmParser {
    fn ecosystem(&self) -> &'static str {
        "elm"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["elm.json"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(root) = serde_json::from_str::<Value>(&text) else {
            return Ok(Vec::new());
        };

        let mut deps = Vec::new();
        let Some(dependencies) = root.get("dependencies").and_then(Value::as_object) else {
            return Ok(deps);
        };

        if dependencies.contains_key("direct") || dependencies.contains_key("indirect") {
            // "application"-type elm.json: exact versions split by directness.
            for (key, direct) in [("direct", true), ("indirect", false)] {
                if let Some(map) = dependencies.get(key).and_then(Value::as_object) {
                    collect_flat(map, &manifest_path, direct, &mut deps);
                }
            }
        } else {
            // "package"-type elm.json: a flat map of name -> version range.
            collect_flat(dependencies, &manifest_path, true, &mut deps);
        }
        Ok(deps)
    }
}

fn collect_flat(map: &serde_json::Map<String, Value>, manifest_path: &str, direct: bool, out: &mut Vec<Dependency>) {
    for (name, version) in map {
        let Some(version) = version.as_str() else { continue };
        out.push(Dependency {
            ecosystem: "elm".to_string(),
            name: name.clone(),
            version: version.to_string(),
            manifest_path: manifest_path.to_string(),
            direct,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_application_type_direct_and_indirect_dependencies() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("elm.json");
        std::fs::write(
            &path,
            r#"{ "type": "application", "dependencies": { "direct": { "elm/core": "1.0.5" }, "indirect": { "elm/json": "1.1.3" } } }"#,
        )
        .expect("write fixture");

        let deps = ElmParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2);
        let core = deps.iter().find(|dep| dep.name == "elm/core").expect("present");
        assert!(core.direct);
        let json = deps.iter().find(|dep| dep.name == "elm/json").expect("present");
        assert!(!json.direct);
    }

    #[test]
    fn parses_package_type_flat_version_range_map() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("elm.json");
        std::fs::write(&path, r#"{ "type": "package", "dependencies": { "elm/core": "1.0.0 <= v < 2.0.0" } }"#).expect("write fixture");

        let deps = ElmParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "1.0.0 <= v < 2.0.0");
    }
}
