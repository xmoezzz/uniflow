use serde::Deserialize;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct ComposerParser;

impl ManifestParser for ComposerParser {
    fn ecosystem(&self) -> &'static str {
        "packagist"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["composer.lock"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(lock) = serde_json::from_str::<ComposerLock>(&text) else {
            return Ok(Vec::new());
        };
        Ok(lock
            .packages
            .into_iter()
            .chain(lock.packages_dev)
            .map(|package| Dependency {
                ecosystem: "packagist".to_string(),
                name: package.name,
                version: package.version.trim_start_matches('v').to_string(),
                manifest_path: manifest_path.clone(),
                direct: false,
            })
            .collect())
    }
}

#[derive(Deserialize)]
struct ComposerLock {
    #[serde(default)]
    packages: Vec<ComposerPackage>,
    #[serde(default, rename = "packages-dev")]
    packages_dev: Vec<ComposerPackage>,
}

#[derive(Deserialize)]
struct ComposerPackage {
    name: String,
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_main_and_dev_packages_from_composer_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("composer.lock");
        std::fs::write(
            &path,
            r#"{ "packages": [ { "name": "monolog/monolog", "version": "v2.3.0" } ], "packages-dev": [ { "name": "phpunit/phpunit", "version": "9.5.0" } ] }"#,
        )
        .expect("write fixture");

        let deps = ComposerParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2);
        let monolog = deps.iter().find(|dep| dep.name == "monolog/monolog").expect("present");
        assert_eq!(monolog.version, "2.3.0", "leading v should be stripped");
        assert!(deps.iter().all(|dep| dep.ecosystem == "packagist"));
    }
}
