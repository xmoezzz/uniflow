use serde_json::{Map, Value};
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct NpmParser;

impl ManifestParser for NpmParser {
    fn ecosystem(&self) -> &'static str {
        "npm"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["package-lock.json", "package.json", "yarn.lock", "pnpm-lock.yaml"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let file_name = manifest_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();

        match file_name {
            "yarn.lock" => return Ok(parse_yarn_lock(&text, &manifest_path)),
            "pnpm-lock.yaml" => return Ok(parse_pnpm_lock(&text, &manifest_path)),
            _ => {}
        }

        let json: Value = serde_json::from_str(&text)?;
        if file_name == "package-lock.json" {
            return Ok(parse_lockfile(&json, &manifest_path));
        }
        Ok(parse_manifest(&json, &manifest_path))
    }
}

/// Classic (v1) yarn.lock format: no JSON/YAML, just a hand-rolled
/// block format — one or more comma-separated `"name@range"` header
/// specifiers per block (ending in `:`), followed by indented `key value`
/// lines, the only one we need being `version "x.y.z"`. Does NOT handle
/// Yarn Berry (v2+) lockfiles, which switched to real YAML with a
/// `__metadata:` header — those fall through here with zero dependencies
/// found rather than misparsing, since this format's headers wouldn't match.
fn parse_yarn_lock(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut pending_name: Option<String> = None;
    for raw_line in text.lines() {
        if raw_line.starts_with('#') || raw_line.trim().is_empty() {
            continue;
        }
        if !raw_line.starts_with([' ', '\t']) {
            // A new block header, e.g. `"@babel/core@^7.0.0", "@babel/core@^7.12.0":`
            let Some(first_spec) = raw_line.trim_end_matches(':').split(',').next() else { continue };
            let spec = first_spec.trim().trim_matches('"');
            // Scoped packages (`@scope/name@range`) have a leading '@' that
            // isn't the version separator — skip it when hunting for the
            // real name/range boundary.
            let search_from = if spec.starts_with('@') { 1 } else { 0 };
            pending_name = spec[search_from..]
                .find('@')
                .map(|at| spec[..search_from + at].to_string())
                .or_else(|| Some(spec.to_string()));
            continue;
        }
        let trimmed = raw_line.trim();
        if let Some(name) = &pending_name {
            if let Some(rest) = trimmed.strip_prefix("version ") {
                let version = rest.trim().trim_matches('"');
                deps.push(Dependency {
                    ecosystem: "npm".to_string(),
                    name: name.clone(),
                    version: version.to_string(),
                    manifest_path: manifest_path.to_string(),
                    direct: false,
                });
                pending_name = None;
            }
        }
    }
    deps
}

/// pnpm-lock.yaml: real YAML. Package keys under `packages:` look like
/// `/lodash@4.17.21:` (pnpm <9) or `lodash@4.17.21:` (pnpm 9+), and scoped
/// names embed their own '@' (`@babel/core@7.12.3`) — `rsplit_once('@')`
/// correctly separates name/version in both cases since the version is
/// always the last `@`-delimited segment. A trailing `(peer@1.0.0)`
/// suffix (peer-dependency resolution suffix) is stripped first.
fn parse_pnpm_lock(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let Ok(doc) = serde_yaml::from_str::<Value>(text) else { return Vec::new() };
    let Some(packages) = doc.get("packages").and_then(Value::as_object) else { return Vec::new() };
    packages
        .keys()
        .filter_map(|key| {
            let key = key.trim_start_matches('/');
            let key = key.split('(').next().unwrap_or(key);
            let (name, version) = key.rsplit_once('@')?;
            if name.is_empty() || version.is_empty() {
                return None;
            }
            Some(Dependency {
                ecosystem: "npm".to_string(),
                name: name.to_string(),
                version: version.to_string(),
                manifest_path: manifest_path.to_string(),
                direct: false,
            })
        })
        .collect()
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

    #[test]
    fn parses_resolved_versions_from_yarn_lock_including_scoped_packages() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write(
            dir.path(),
            "yarn.lock",
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
             # yarn lockfile v1\n\
             \n\
             minimist@^1.2.0:\n  version \"1.2.5\"\n  resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.5.tgz\"\n\
             \n\
             \"@babel/core@^7.0.0\", \"@babel/core@^7.12.0\":\n  version \"7.12.3\"\n  resolved \"https://registry.yarnpkg.com/@babel/core/-/core-7.12.3.tgz\"\n",
        );
        let deps = NpmParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2);
        let minimist = deps.iter().find(|dep| dep.name == "minimist").expect("minimist present");
        assert_eq!(minimist.version, "1.2.5");
        assert!(!minimist.direct);
        let babel = deps.iter().find(|dep| dep.name == "@babel/core").expect("scoped package name preserved");
        assert_eq!(babel.version, "7.12.3");
    }

    #[test]
    fn parses_resolved_versions_from_pnpm_lock_yaml() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = write(
            dir.path(),
            "pnpm-lock.yaml",
            "lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n  /@babel/core@7.12.3:\n    resolution: {integrity: sha512-def}\n  /minimist@1.2.5(peer@1.0.0):\n    resolution: {integrity: sha512-ghi}\n",
        );
        let deps = NpmParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 3);
        let lodash = deps.iter().find(|dep| dep.name == "lodash").expect("lodash present");
        assert_eq!(lodash.version, "4.17.21");
        let babel = deps.iter().find(|dep| dep.name == "@babel/core").expect("scoped package name preserved");
        assert_eq!(babel.version, "7.12.3");
        let minimist = deps.iter().find(|dep| dep.name == "minimist").expect("peer suffix stripped");
        assert_eq!(minimist.version, "1.2.5");
    }
}
