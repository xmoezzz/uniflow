use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

/// R's `renv` package (the modern, standard dependency-locking tool for R
/// projects) writes `renv.lock` as plain JSON.
pub struct RenvParser;

impl ManifestParser for RenvParser {
    fn ecosystem(&self) -> &'static str {
        "cran"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["renv.lock"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(lock) = serde_json::from_str::<RenvLock>(&text) else {
            return Ok(Vec::new());
        };
        Ok(lock
            .packages
            .into_values()
            .map(|package| Dependency {
                ecosystem: "cran".to_string(),
                name: package.package,
                version: package.version,
                manifest_path: manifest_path.clone(),
                direct: false,
            })
            .collect())
    }
}

#[derive(Deserialize)]
struct RenvLock {
    #[serde(default, rename = "Packages")]
    packages: BTreeMap<String, RenvPackage>,
}

#[derive(Deserialize)]
struct RenvPackage {
    #[serde(rename = "Package")]
    package: String,
    #[serde(rename = "Version")]
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_packages_from_renv_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("renv.lock");
        std::fs::write(
            &path,
            r#"{ "R": { "Version": "4.2.0" }, "Packages": { "dplyr": { "Package": "dplyr", "Version": "1.0.9" } } }"#,
        )
        .expect("write fixture");

        let deps = RenvParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "dplyr");
        assert_eq!(deps[0].version, "1.0.9");
        assert_eq!(deps[0].ecosystem, "cran");
    }
}
