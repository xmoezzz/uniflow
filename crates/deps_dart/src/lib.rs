use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct PubParser;

impl ManifestParser for PubParser {
    fn ecosystem(&self) -> &'static str {
        "pub"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["pubspec.lock"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(lock) = serde_yaml::from_str::<PubspecLock>(&text) else {
            return Ok(Vec::new());
        };
        Ok(lock
            .packages
            .into_iter()
            .map(|(name, package)| Dependency {
                ecosystem: "pub".to_string(),
                name,
                version: package.version,
                manifest_path: manifest_path.clone(),
                direct: package.dependency.starts_with("direct"),
            })
            .collect())
    }
}

#[derive(Deserialize)]
struct PubspecLock {
    #[serde(default)]
    packages: BTreeMap<String, PubPackage>,
}

#[derive(Deserialize)]
struct PubPackage {
    #[serde(default)]
    dependency: String,
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_direct_from_transitive_packages_in_pubspec_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("pubspec.lock");
        std::fs::write(
            &path,
            "packages:\n  http:\n    dependency: \"direct main\"\n    version: \"0.13.4\"\n  path:\n    dependency: transitive\n    version: \"1.8.1\"\n",
        )
        .expect("write fixture");

        let deps = PubParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2);
        let http = deps.iter().find(|dep| dep.name == "http").expect("present");
        assert!(http.direct);
        assert_eq!(http.version, "0.13.4");
        let path_dep = deps.iter().find(|dep| dep.name == "path").expect("present");
        assert!(!path_dep.direct);
    }
}
