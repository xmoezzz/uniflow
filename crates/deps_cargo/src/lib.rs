use serde::Deserialize;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

#[derive(Deserialize)]
struct CargoLock {
    #[serde(default, rename = "package")]
    packages: Vec<CargoLockPackage>,
}

#[derive(Deserialize)]
struct CargoLockPackage {
    name: String,
    version: String,
}

pub struct CargoParser;

impl ManifestParser for CargoParser {
    fn ecosystem(&self) -> &'static str {
        "cargo"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["Cargo.lock"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let lock: CargoLock = toml::from_str(&text)?;
        let manifest_path = manifest_path.display().to_string();
        Ok(lock
            .packages
            .into_iter()
            .map(|package| Dependency {
                ecosystem: "cargo".to_string(),
                name: package.name,
                version: package.version,
                manifest_path: manifest_path.clone(),
                direct: false,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolved_packages_from_cargo_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Cargo.lock");
        std::fs::write(
            &path,
            r#"
[[package]]
name = "time"
version = "0.2.23"

[[package]]
name = "serde"
version = "1.0.219"
"#,
        )
        .expect("write fixture");

        let deps = CargoParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().all(|dep| !dep.direct && dep.ecosystem == "cargo"));
        let time = deps.iter().find(|dep| dep.name == "time").expect("time present");
        assert_eq!(time.version, "0.2.23");
    }
}
