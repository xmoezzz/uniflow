use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

/// `Berksfile.lock` (Berkshelf, Chef's Bundler-inspired dependency locker)
/// resolves cookbooks under a `GRAPH` section as 2-space-indented
/// `name (version)` lines, with each cookbook's own (unresolved) constraints
/// nested more deeply below it — the same shape as `Gemfile.lock`'s `specs:`
/// block, just with different indentation and an explicit section name to
/// key off of instead of a fixed indent being unambiguous on its own (a
/// `DEPENDENCIES` section above `GRAPH` also uses 2-space indent, so this
/// only starts capturing once the `GRAPH` header line has been seen).
///
/// Confidence note: Chef/Berkshelf has a much smaller footprint than the
/// other ecosystems ported alongside it, and this format is reconstructed
/// from general knowledge of the tool rather than a verified real
/// `Berksfile.lock` sample — treat this parser as best-effort.
pub struct BerkshelfParser;

impl ManifestParser for BerkshelfParser {
    fn ecosystem(&self) -> &'static str {
        "chef"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["Berksfile.lock"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();

        let mut deps = Vec::new();
        let mut in_graph = false;
        for line in text.lines() {
            if !line.starts_with(' ') && !line.trim().is_empty() {
                in_graph = line.trim() == "GRAPH";
                continue;
            }
            if !in_graph {
                continue;
            }
            let leading_spaces = line.len() - line.trim_start_matches(' ').len();
            if leading_spaces != 2 {
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
                ecosystem: "chef".to_string(),
                name: name.to_string(),
                version: version.to_string(),
                manifest_path: manifest_path.clone(),
                direct: false,
            });
        }
        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_graph_entries_but_not_the_dependencies_section() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("Berksfile.lock");
        std::fs::write(
            &path,
            "DEPENDENCIES\n  mysql (~> 8.0)\n\nGRAPH\n  mysql (8.0.1)\n    build-essential (>= 0.0.0)\n  build-essential (8.2.1)\n",
        )
        .expect("write fixture");

        let deps = BerkshelfParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2, "{deps:?}");
        assert!(deps.iter().any(|dep| dep.name == "mysql" && dep.version == "8.0.1"));
        assert!(deps.iter().any(|dep| dep.name == "build-essential" && dep.version == "8.2.1"));
    }
}
