use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct BundlerParser;

impl ManifestParser for BundlerParser {
    fn ecosystem(&self) -> &'static str {
        "rubygems"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["Gemfile.lock"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        Ok(parse_gemfile_lock(&text, &manifest_path))
    }
}

/// Only lines inside a `specs:` block are exactly 4-space indented
/// `name (version)`; a spec's own sub-dependencies (6-space indented) and
/// the top-level `DEPENDENCIES` block (2-space indented) both fail this
/// exact-width check, so no explicit section-tracking state machine is
/// needed to tell them apart.
fn parse_gemfile_lock(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    for line in text.lines() {
        let leading_spaces = line.len() - line.trim_start_matches(' ').len();
        if leading_spaces != 4 {
            continue;
        }
        let trimmed = line.trim();
        let Some(open) = trimmed.find('(') else { continue };
        let Some(close) = trimmed.rfind(')') else { continue };
        if close <= open {
            continue;
        }
        let name = trimmed[..open].trim();
        let version = trimmed[open + 1..close].trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        deps.push(Dependency {
            ecosystem: "rubygems".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: manifest_path.to_string(),
            direct: false,
        });
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_only_top_level_specs_not_nested_sub_dependencies() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Gemfile.lock");
        std::fs::write(
            &path,
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    concurrent-ruby (1.1.9)\n    rack (2.2.3)\n      foo (~> 1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n",
        )
        .expect("write fixture");

        let deps = BundlerParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2, "{deps:?}");
        assert!(deps.iter().any(|dep| dep.name == "concurrent-ruby" && dep.version == "1.1.9"));
        assert!(deps.iter().any(|dep| dep.name == "rack" && dep.version == "2.2.3"));
        assert!(deps.iter().all(|dep| dep.name != "foo"), "nested sub-dependency line must be excluded");
    }
}
