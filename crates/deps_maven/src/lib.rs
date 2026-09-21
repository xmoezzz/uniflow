use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct MavenParser;

impl ManifestParser for MavenParser {
    fn ecosystem(&self) -> &'static str {
        "maven"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["pom.xml"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(document) = roxmltree::Document::parse(&text) else {
            return Ok(Vec::new());
        };

        let mut deps = Vec::new();
        for node in document.descendants().filter(|node| node.has_tag_name("dependency")) {
            let child_text = |tag: &str| {
                node.children()
                    .find(|child| child.has_tag_name(tag))
                    .and_then(|child| child.text())
                    .unwrap_or_default()
                    .trim()
            };
            let group_id = child_text("groupId");
            let artifact_id = child_text("artifactId");
            let version = child_text("version");
            if group_id.is_empty() || artifact_id.is_empty() {
                continue;
            }
            deps.push(Dependency {
                ecosystem: "maven".to_string(),
                name: format!("{group_id}:{artifact_id}"),
                version: version.to_string(),
                manifest_path: manifest_path.clone(),
                direct: true,
            });
        }
        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_group_artifact_version_from_pom_xml() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("pom.xml");
        std::fs::write(
            &path,
            r#"<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.9</version></dependency></dependencies></project>"#,
        )
        .expect("write fixture");

        let deps = MavenParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "org.apache.commons:commons-lang3");
        assert_eq!(deps[0].version, "3.9");
        assert!(deps[0].direct);
    }
}
