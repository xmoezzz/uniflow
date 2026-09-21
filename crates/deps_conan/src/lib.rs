use serde_json::Value;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

/// Conan's lockfile shape changed between v1 (`graph_lock.nodes[*].ref`) and
/// v2 (a flat `requires` array) — both are read leniently via
/// `serde_json::Value` rather than a single fixed schema, since either can
/// show up depending on the Conan version that produced the file.
pub struct ConanParser;

impl ManifestParser for ConanParser {
    fn ecosystem(&self) -> &'static str {
        "conan"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["conan.lock"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Ok(root) = serde_json::from_str::<Value>(&text) else {
            return Ok(Vec::new());
        };

        let mut refs: Vec<String> = Vec::new();
        if let Some(nodes) = root.pointer("/graph_lock/nodes").and_then(Value::as_object) {
            for node in nodes.values() {
                if let Some(reference) = node.get("ref").and_then(Value::as_str) {
                    refs.push(reference.to_string());
                }
            }
        }
        for key in ["requires", "build_requires", "python_requires"] {
            if let Some(list) = root.get(key).and_then(Value::as_array) {
                refs.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
            }
        }

        Ok(refs
            .iter()
            .filter_map(|reference| parse_conan_ref(reference))
            .map(|(name, version)| Dependency {
                ecosystem: "conan".to_string(),
                name,
                version,
                manifest_path: manifest_path.clone(),
                direct: false,
            })
            .collect())
    }
}

/// A Conan reference looks like `name/version[@user/channel][#revision]`,
/// with v2 lockfiles sometimes appending `%timestamp` after the revision.
fn parse_conan_ref(reference: &str) -> Option<(String, String)> {
    let without_timestamp = reference.split('%').next().unwrap_or(reference);
    let without_revision = without_timestamp.split('#').next().unwrap_or(without_timestamp);
    let without_channel = without_revision.split('@').next().unwrap_or(without_revision);
    let (name, version) = without_channel.split_once('/')?;
    Some((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v1_graph_lock_nodes_and_strips_channel_and_revision() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("conan.lock");
        std::fs::write(
            &path,
            r#"{ "graph_lock": { "nodes": { "0": { "ref": "libpng/1.6.37" }, "1": { "ref": "zlib/1.2.11@user/stable#abc123" } } } }"#,
        )
        .expect("write fixture");

        let deps = ConanParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2, "{deps:?}");
        assert!(deps.iter().any(|dep| dep.name == "libpng" && dep.version == "1.6.37"));
        assert!(deps.iter().any(|dep| dep.name == "zlib" && dep.version == "1.2.11"));
    }

    #[test]
    fn parses_v2_flat_requires_array() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("conan.lock");
        std::fs::write(&path, r#"{ "version": "0.5", "requires": ["openssl/3.1.0#hash"] }"#).expect("write fixture");

        let deps = ConanParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "openssl");
        assert_eq!(deps[0].version, "3.1.0");
    }
}
