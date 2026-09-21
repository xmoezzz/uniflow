use serde_json::{Map, Value};
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct NpmParser;

impl ManifestParser for NpmParser {
    fn ecosystem(&self) -> &'static str {
        "npm"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["package-lock.json", "package.json"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let file_name = manifest_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let text = std::fs::read_to_string(manifest_path)?;
        let json: Value = serde_json::from_str(&text)?;
        let manifest_path = manifest_path.display().to_string();

        if file_name == "package-lock.json" {
            return Ok(parse_lockfile(&json, &manifest_path));
        }
        Ok(parse_manifest(&json, &manifest_path))
    }
}

fn parse_lockfile(json: &Value, manifest_path: &str) -> Vec<Dependency> {
    if let Some(packages) = json.get("packages").and_then(Value::as_object) {
        return packages
            .iter()
            .filter(|(path, _)| !path.is_empty())
            .filter_map(|(path, meta)| {
                let name = path.rsplit("node_modules/").next().unwrap_or(path);
                let version = meta.get("version").and_then(Value::as_str)?;
                Some(Dependency {
                    ecosystem: "npm".to_string(),
                    name: name.to_string(),
                    version: version.to_string(),
                    manifest_path: manifest_path.to_string(),
                    direct: false,
                })
            })
            .collect();
    }

    let mut deps = Vec::new();
    if let Some(dependencies) = json.get("dependencies").and_then(Value::as_object) {
        collect_v1_dependencies(dependencies, manifest_path, &mut deps);
    }
    deps
}

fn collect_v1_dependencies(map: &Map<String, Value>, manifest_path: &str, out: &mut Vec<Dependency>) {
    for (name, meta) in map {
        if let Some(version) = meta.get("version").and_then(Value::as_str) {
            out.push(Dependency {
                ecosystem: "npm".to_string(),
                name: name.clone(),
                version: version.to_string(),
                manifest_path: manifest_path.to_string(),
                direct: false,
            });
        }
        if let Some(nested) = meta.get("dependencies").and_then(Value::as_object) {
            collect_v1_dependencies(nested, manifest_path, out);
        }
    }
}

fn parse_manifest(json: &Value, manifest_path: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(map) = json.get(field).and_then(Value::as_object) else {
            continue;
        };
        for (name, version) in map {
            deps.push(Dependency {
                ecosystem: "npm".to_string(),
                name: name.clone(),
                version: version.as_str().unwrap_or_default().to_string(),
                manifest_path: manifest_path.to_string(),
                direct: true,
            });
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write fixture");
        path
    }

    #[test]
    fn parses_direct_dependencies_from_package_json() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write(
            dir.path(),
            "package.json",
            r#"{ "dependencies": { "lodash": "4.17.15" }, "devDependencies": { "jest": "^29.0.0" } }"#,
        );
        let deps = NpmParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().all(|dep| dep.direct));
        let lodash = deps.iter().find(|dep| dep.name == "lodash").expect("lodash present");
        assert_eq!(lodash.version, "4.17.15");
    }

    #[test]
    fn parses_resolved_versions_from_package_lock_v2() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write(
            dir.path(),
            "package-lock.json",
            r#"{ "packages": { "": {}, "node_modules/minimist": { "version": "1.2.5" } } }"#,
        );
        let deps = NpmParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "minimist");
        assert_eq!(deps[0].version, "1.2.5");
        assert!(!deps[0].direct);
    }
}
