use std::collections::BTreeSet;
use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct GoParser;

impl ManifestParser for GoParser {
    fn ecosystem(&self) -> &'static str {
        "go"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["go.mod", "go.sum"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let file_name = manifest_path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        Ok(if file_name == "go.sum" {
            parse_go_sum(&text, &manifest_path)
        } else {
            parse_go_mod(&text, &manifest_path)
        })
    }
}

fn parse_go_sum(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let mut seen = BTreeSet::new();
    let mut deps = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(raw_version)) = (fields.next(), fields.next()) else {
            continue;
        };
        let version = raw_version.trim_end_matches("/go.mod");
        if !seen.insert((name.to_string(), version.to_string())) {
            continue;
        }
        deps.push(Dependency {
            ecosystem: "go".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: manifest_path.to_string(),
            direct: false,
        });
    }
    deps
}

fn parse_go_mod(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_require_block = false;
    for raw_line in text.lines() {
        // `// indirect` is how go.mod marks a requirement that no package in
        // this module imports directly (Go ≥1.17 lists the full selected
        // set, so these are the transitive ones) — captured before the
        // comment is stripped.
        let indirect = raw_line.split_once("//").is_some_and(|(_, comment)| comment.trim_start().starts_with("indirect"));
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("require (") {
            in_require_block = true;
            let _ = rest;
            continue;
        }
        if in_require_block {
            if line == ")" {
                in_require_block = false;
                continue;
            }
            if let Some(dep) = parse_require_entry(line, manifest_path, indirect) {
                deps.push(dep);
            }
        } else if let Some(rest) = line.strip_prefix("require ") {
            if let Some(dep) = parse_require_entry(rest.trim(), manifest_path, indirect) {
                deps.push(dep);
            }
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_require_block_and_standalone_require_from_go_mod() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("go.mod");
        std::fs::write(
            &path,
            "module example.com/demo\n\ngo 1.21\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n\tgolang.org/x/net v0.10.0 // indirect\n)\n\nrequire github.com/single/one v1.0.0\n",
        )
        .expect("write fixture");

        let deps = GoParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().all(|dep| dep.ecosystem == "go"));
        assert_eq!(deps.iter().filter(|dep| dep.direct).count(), 2, "the `// indirect` requirement is transitive");
        let errors = deps.iter().find(|dep| dep.name == "github.com/pkg/errors").expect("present");
        assert_eq!(errors.version, "v0.9.1");
    }

    #[test]
    fn dedupes_and_strips_go_mod_suffix_from_go_sum() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("go.sum");
        std::fs::write(
            &path,
            "github.com/pkg/errors v0.9.1 h1:abc=\ngithub.com/pkg/errors v0.9.1/go.mod h1:def=\n",
        )
        .expect("write fixture");

        let deps = GoParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "v0.9.1");
        assert!(!deps[0].direct);
    }

    #[test]
    fn marks_indirect_requirements_as_not_direct() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("go.mod");
        std::fs::write(
            &path,
            "module example.com/app\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.7.0 // indirect\n)\n",
        )
        .expect("write fixture");
        let deps = GoParser.parse(&path).expect("parse");
        assert!(deps.iter().find(|d| d.name == "github.com/gin-gonic/gin").unwrap().direct);
        assert!(!deps.iter().find(|d| d.name == "golang.org/x/net").unwrap().direct);
    }
}

fn parse_require_entry(entry: &str, manifest_path: &str, indirect: bool) -> Option<Dependency> {
    let mut fields = entry.split_whitespace();
    let name = fields.next()?;
    let version = fields.next()?;
    Some(Dependency {
        ecosystem: "go".to_string(),
        name: name.to_string(),
        version: version.to_string(),
        manifest_path: manifest_path.to_string(),
        direct: !indirect,
    })
}
