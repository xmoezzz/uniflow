use serde::Deserialize;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct PythonParser;

impl ManifestParser for PythonParser {
    fn ecosystem(&self) -> &'static str {
        "pypi"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["requirements.txt", "poetry.lock"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let file_name = manifest_path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        if file_name == "poetry.lock" {
            return Ok(parse_poetry_lock(&text, &manifest_path));
        }
        Ok(parse_requirements_txt(&text, &manifest_path))
    }
}

const VERSION_OPERATORS: &[&str] = &["===", "==", "~=", ">=", "<=", "!=", ">", "<"];

fn parse_requirements_txt(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        let (name, version) = match VERSION_OPERATORS.iter().find_map(|op| line.split_once(op)) {
            Some((name, version)) => (name.trim(), version.trim()),
            None => (line, ""),
        };
        let name = name.split(['[', ';']).next().unwrap_or(name).trim();
        if name.is_empty() {
            continue;
        }
        deps.push(Dependency {
            ecosystem: "pypi".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: manifest_path.to_string(),
            direct: true,
        });
    }
    deps
}

#[derive(Deserialize)]
struct PoetryLock {
    #[serde(default, rename = "package")]
    packages: Vec<PoetryPackage>,
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
}

fn parse_poetry_lock(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let Ok(lock) = toml::from_str::<PoetryLock>(text) else {
        return Vec::new();
    };
    lock.packages
        .into_iter()
        .map(|package| Dependency {
            ecosystem: "pypi".to_string(),
            name: package.name,
            version: package.version,
            manifest_path: manifest_path.to_string(),
            direct: false,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requirements_txt_skipping_comments_and_includes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("requirements.txt");
        std::fs::write(&path, "requests==2.25.0\nflask>=2.0.0\n# a comment\n-r other.txt\n\n").expect("write fixture");

        let deps = PythonParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2);
        let requests = deps.iter().find(|dep| dep.name == "requests").expect("requests present");
        assert_eq!(requests.version, "2.25.0");
        let flask = deps.iter().find(|dep| dep.name == "flask").expect("flask present");
        assert_eq!(flask.version, "2.0.0");
        assert!(deps.iter().all(|dep| dep.direct && dep.ecosystem == "pypi"));
    }

    #[test]
    fn parses_resolved_versions_from_poetry_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("poetry.lock");
        std::fs::write(
            &path,
            "[[package]]\nname = \"requests\"\nversion = \"2.25.0\"\n",
        )
        .expect("write fixture");

        let deps = PythonParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert!(!deps[0].direct);
    }
}
