use std::path::Path;
use toml::Value;
use uniflow_sca_core::{Dependency, ManifestParser};

/// Fortran's `fpm.toml` has no separate resolved-lockfile convention the way
/// npm/Cargo do — dependencies are declared directly here, either as a
/// version requirement string or a table pinning a git `tag`/`branch`/`rev`.
/// This records whichever pin is present (falling back to the raw
/// requirement string) rather than resolving anything itself.
pub struct FpmParser;

impl ManifestParser for FpmParser {
    fn ecosystem(&self) -> &'static str {
        "fpm"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["fpm.toml"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(root) = text.parse::<Value>() else {
            return Ok(Vec::new());
        };

        let mut deps = Vec::new();
        for table_name in ["dependencies", "dev-dependencies"] {
            let Some(table) = root.get(table_name).and_then(Value::as_table) else { continue };
            for (name, spec) in table {
                deps.push(Dependency {
                    ecosystem: "fpm".to_string(),
                    name: name.clone(),
                    version: version_of(spec),
                    manifest_path: manifest_path.clone(),
                    direct: true,
                });
            }
        }
        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_version_string_and_a_git_tag_pin_from_fpm_toml() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("fpm.toml");
        std::fs::write(
            &path,
            "name = \"demo\"\n[dependencies]\nstdlib = \"*\"\nfoo = { git = \"https://github.com/foo/bar\", tag = \"v1.0.0\" }\n",
        )
        .expect("write fixture");

        let deps = FpmParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2, "{deps:?}");
        let stdlib = deps.iter().find(|dep| dep.name == "stdlib").expect("present");
        assert_eq!(stdlib.version, "*");
        let foo = deps.iter().find(|dep| dep.name == "foo").expect("present");
        assert_eq!(foo.version, "v1.0.0");
    }
}

fn version_of(spec: &Value) -> String {
    if let Some(version) = spec.as_str() {
        return version.to_string();
    }
    for key in ["tag", "rev", "branch"] {
        if let Some(value) = spec.get(key).and_then(Value::as_str) {
            return value.to_string();
        }
    }
    spec.get("git").and_then(Value::as_str).unwrap_or_default().to_string()
}
