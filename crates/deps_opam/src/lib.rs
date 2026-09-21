use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

/// opam files (`<package>.opam`, or `<package>.opam.locked` once `opam lock`
/// has pinned exact versions) are named after the package itself rather
/// than a fixed convention, so this matches by suffix instead of exact
/// filename (see `ManifestParser::matches_file_name`). The format is
/// opam-file-format, a small custom syntax — not TOML/YAML/JSON — so
/// `depends: [ "name" {constraint} ... ]` is parsed with a short
/// hand-rolled scanner rather than pulling in a full opam-file-format
/// parser for one field.
pub struct OpamParser;

impl ManifestParser for OpamParser {
    fn ecosystem(&self) -> &'static str {
        "opam"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &[]
    }

    fn matches_file_name(&self, file_name: &str) -> bool {
        file_name.ends_with(".opam") || file_name.ends_with(".opam.locked")
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let Some(block) = extract_depends_block(&text) else {
            return Ok(Vec::new());
        };
        Ok(parse_depends_entries(block)
            .into_iter()
            .map(|(name, version)| Dependency {
                ecosystem: "opam".to_string(),
                name,
                version: version.unwrap_or_default(),
                manifest_path: manifest_path.clone(),
                direct: true,
            })
            .collect())
    }
}

/// Finds the `[ ... ]` list following a top-level `depends:` field,
/// respecting nested brackets (opam constraint expressions can themselves
/// contain `[...]` for version-range disjunctions).
fn extract_depends_block(text: &str) -> Option<&str> {
    let after_key = text.find("depends:")? + "depends:".len();
    let rest = &text[after_key..];
    let open = rest.find('[')?;
    let bytes = rest.as_bytes();
    let mut depth = 0i32;
    let mut end = None;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    Some(&rest[open + 1..end?])
}

fn parse_depends_entries(block: &str) -> Vec<(String, Option<String>)> {
    let chars: Vec<char> = block.chars().collect();
    let mut results = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '"' {
            i += 1;
            continue;
        }
        let name_start = i + 1;
        let Some(name_end_offset) = chars[name_start..].iter().position(|c| *c == '"') else {
            break;
        };
        let name_end = name_start + name_end_offset;
        let name: String = chars[name_start..name_end].iter().collect();
        i = name_end + 1;

        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }

        let mut version = None;
        if i < chars.len() && chars[i] == '{' {
            let constraint_start = i + 1;
            let mut depth = 1;
            let mut j = constraint_start;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                if depth > 0 {
                    j += 1;
                }
            }
            let constraint: String = chars[constraint_start..j].iter().collect();
            version = last_quoted(&constraint);
            i = j + 1;
        }
        results.push((name, version));
    }
    results
}

fn last_quoted(text: &str) -> Option<String> {
    let last_close = text.rfind('"')?;
    let last_open = text[..last_close].rfind('"')?;
    Some(text[last_open + 1..last_close].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_files_by_opam_and_opam_locked_suffix_not_exact_name() {
        let parser = OpamParser;
        assert!(parser.matches_file_name("mypkg.opam"));
        assert!(parser.matches_file_name("mypkg.opam.locked"));
        assert!(!parser.matches_file_name("mypkg.json"));
    }

    #[test]
    fn extracts_pinned_versions_from_a_locked_depends_block() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("mypkg.opam.locked");
        std::fs::write(
            &path,
            "opam-version: \"2.0\"\nname: \"mypkg\"\ndepends: [\n  \"ocaml\" {>= \"4.08.0\"}\n  \"dune\" {= \"2.9.1\"}\n]\n",
        )
        .expect("write fixture");

        let deps = OpamParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2, "{deps:?}");
        let ocaml = deps.iter().find(|dep| dep.name == "ocaml").expect("present");
        assert_eq!(ocaml.version, "4.08.0");
        let dune = deps.iter().find(|dep| dep.name == "dune").expect("present");
        assert_eq!(dune.version, "2.9.1");
    }
}
