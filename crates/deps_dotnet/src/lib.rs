use serde::Deserialize;
use serde_json::Value;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct NuGetParser;

impl ManifestParser for NuGetParser {
    fn ecosystem(&self) -> &'static str {
        "nuget"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["packages.lock.json"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(lock) = serde_json::from_str::<PackagesLock>(&text) else {
            return Ok(Vec::new());
        };

        let mut deps = Vec::new();
        for framework in lock.dependencies.values() {
            let Some(packages) = framework.as_object() else { continue };
            for (name, meta) in packages {
                let Some(resolved) = meta.get("resolved").and_then(Value::as_str) else { continue };
                let direct = meta.get("type").and_then(Value::as_str) == Some("Direct");
                deps.push(Dependency {
                    ecosystem: "nuget".to_string(),
                    name: name.clone(),
                    version: resolved.to_string(),
                    manifest_path: manifest_path.clone(),
                    direct,
                });
            }
        }
        Ok(deps)
    }
}

#[derive(Deserialize)]
struct PackagesLock {
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_direct_resolved_version_from_packages_lock_json() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("packages.lock.json");
        std::fs::write(
            &path,
            r#"{ "version": 1, "dependencies": { "net6.0": { "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1" } } } }"#,
        )
        .expect("write fixture");

        let deps = NuGetParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Newtonsoft.Json");
        assert_eq!(deps[0].version, "13.0.1");
        assert!(deps[0].direct);
    }
}
