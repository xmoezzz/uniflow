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

/// What `go.mod` says, before resolution: requirements (with their
/// `// indirect` marks), `replace` and `exclude` directives, and the `go`
/// language version — which decides whether the file is complete.
#[derive(Default)]
struct GoMod {
    go_version: Option<(u32, u32)>,
    requires: Vec<(String, String, bool)>,
    /// old path (and optional old version) -> new path + version; `None`
    /// target version means a local directory replacement (`=> ../fork`).
    replaces: Vec<(String, Option<String>, String, Option<String>)>,
    excludes: BTreeSet<(String, String)>,
}

fn parse_go_mod_file(text: &str) -> GoMod {
    let mut out = GoMod::default();
    let mut block: Option<&str> = None;
    for raw_line in text.lines() {
        // `// indirect` is how go.mod marks a requirement that no package in
        // this module imports directly — captured before the comment is
        // stripped.
        let indirect = raw_line.split_once("//").is_some_and(|(_, comment)| comment.trim_start().starts_with("indirect"));
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(b) = block {
            if line == ")" {
                block = None;
            } else {
                directive(&mut out, b, line, indirect);
            }
            continue;
        }
        let (keyword, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let rest = rest.trim();
        match keyword {
            "go" => {
                let mut parts = rest.split('.');
                if let (Some(major), Some(minor)) = (parts.next().and_then(|p| p.parse().ok()), parts.next().and_then(|p| p.parse().ok())) {
                    out.go_version = Some((major, minor));
                }
            }
            "require" | "replace" | "exclude" if rest == "(" => block = Some(keyword),
            "require" | "replace" | "exclude" => directive(&mut out, keyword, rest, indirect),
            _ => {}
        }
    }
    out
}

fn directive(out: &mut GoMod, keyword: &str, entry: &str, indirect: bool) {
    let fields: Vec<&str> = entry.split_whitespace().collect();
    match keyword {
        "require" if fields.len() >= 2 => out.requires.push((fields[0].to_string(), fields[1].to_string(), indirect)),
        "exclude" if fields.len() >= 2 => {
            out.excludes.insert((fields[0].to_string(), fields[1].to_string()));
        }
        "replace" => {
            // `old [v] => new [v]`
            let Some(arrow) = fields.iter().position(|f| *f == "=>") else { return };
            let (old, new) = (&fields[..arrow], &fields[arrow + 1..]);
            let (Some(old_path), Some(new_path)) = (old.first(), new.first()) else { return };
            out.replaces.push((old_path.to_string(), old.get(1).map(|v| v.to_string()), new_path.to_string(), new.get(1).map(|v| v.to_string())));
        }
        _ => {}
    }
}

impl GoMod {
    /// Go ≥ 1.17 records the full (pruned) module graph in go.mod itself;
    /// older modules list only what they require directly.
    fn is_complete(&self) -> bool {
        self.go_version.is_some_and(|v| v >= (1, 17))
    }

    /// Applies `replace` to one resolved (path, version): the build uses
    /// the replacement's path and version, and a local-directory
    /// replacement has no version to check at all (`None`).
    fn resolve(&self, path: &str, version: &str) -> Option<(String, String)> {
        let rule = self
            .replaces
            .iter()
            .find(|(old, old_v, _, _)| old == path && old_v.as_deref() == Some(version))
            .or_else(|| self.replaces.iter().find(|(old, old_v, _, _)| old == path && old_v.is_none()));
        match rule {
            Some((_, _, new_path, Some(new_v))) => Some((new_path.clone(), new_v.clone())),
            Some((_, _, _, None)) => None,
            None => Some((path.to_string(), version.to_string())),
        }
    }
}

fn parse_go_mod(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let go_mod = parse_go_mod_file(text);
    let mut deps: Vec<Dependency> = go_mod
        .requires
        .iter()
        .filter_map(|(path, version, indirect)| {
            let (name, version) = go_mod.resolve(path, version)?;
            Some(Dependency { ecosystem: "go".into(), name, version, manifest_path: manifest_path.to_string(), direct: !indirect })
        })
        .collect();
    if !go_mod.is_complete() {
        deps.extend(supplement_from_go_sum(&go_mod, manifest_path));
    }
    deps
}

/// A pre-1.17 go.mod lists only direct requirements; the rest of the build
/// list exists only as MVS over dependencies' own go.mod files, which an
/// offline scan cannot fetch. go.sum is the best local evidence: it holds
/// every module version resolution consulted, so — as Trivy does — each
/// module go.mod doesn't mention contributes its *highest* go.sum version
/// (what MVS would select among those listed), honoring `exclude` and
/// `replace`. This can over-report a version the build no longer selects;
/// missing the whole transitive graph is the worse error.
fn supplement_from_go_sum(go_mod: &GoMod, go_mod_path: &str) -> Vec<Dependency> {
    let sum_path = Path::new(go_mod_path).with_file_name("go.sum");
    let Ok(text) = std::fs::read_to_string(&sum_path) else { return Vec::new() };
    let required: BTreeSet<&str> = go_mod.requires.iter().map(|(p, _, _)| p.as_str()).collect();
    let mut best: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(path), Some(raw)) = (fields.next(), fields.next()) else { continue };
        let version = raw.trim_end_matches("/go.mod");
        if required.contains(path) || go_mod.excludes.contains(&(path.to_string(), version.to_string())) {
            continue;
        }
        let entry = best.entry(path.to_string()).or_insert_with(|| version.to_string());
        if semver_cmp(version, entry) == std::cmp::Ordering::Greater {
            *entry = version.to_string();
        }
    }
    // Attributed to go.mod: the orchestrator discards dependencies parsed
    // from go.sum itself whenever a go.mod sits next to it.
    best.into_iter()
        .filter_map(|(path, version)| {
            let (name, version) = go_mod.resolve(&path, &version)?;
            Some(Dependency { ecosystem: "go".into(), name, version, manifest_path: go_mod_path.to_string(), direct: false })
        })
        .collect()
}

/// Go module version order (semver 2.0 with the `v` prefix; pseudo-versions
/// are pre-releases, `+incompatible` is build metadata and ignored).
fn semver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn split(v: &str) -> (Vec<u64>, Option<&str>) {
        let v = v.trim_start_matches('v');
        let v = v.split('+').next().unwrap_or(v);
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v, None),
        };
        (core.split('.').map(|p| p.parse().unwrap_or(0)).collect(), pre)
    }
    let ((ca, pa), (cb, pb)) = (split(a), split(b));
    ca.cmp(&cb).then_with(|| match (pa, pb) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(x), Some(y)) => {
            for (p, q) in x.split('.').zip(y.split('.')) {
                let ord = match (p.parse::<u64>(), q.parse::<u64>()) {
                    (Ok(m), Ok(n)) => m.cmp(&n),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                    (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                    _ => p.cmp(q),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            x.split('.').count().cmp(&y.split('.').count())
        }
    })
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
    fn pre_1_17_modules_are_supplemented_from_go_sum_with_the_highest_version() {
        // gin v1.6.0's shape: `go 1.13`, only direct requirements in go.mod,
        // the transitive golang.org/x/sys only in go.sum (two versions).
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            dir.path().join("go.mod"),
            "module github.com/gin-gonic/gin\n\ngo 1.13\n\nrequire (\n\tgithub.com/json-iterator/go v1.1.9\n)\n\nexclude golang.org/x/text v0.3.2\nreplace gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.8\nreplace example.com/local => ../local\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("go.sum"),
            "github.com/json-iterator/go v1.1.9 h1:a=\n\
             golang.org/x/sys v0.0.0-20190222072716-a9d3bda3a223/go.mod h1:b=\n\
             golang.org/x/sys v0.0.0-20200116001909-b77594299b42 h1:c=\n\
             golang.org/x/text v0.3.2 h1:d=\n\
             golang.org/x/text v0.3.0 h1:e=\n\
             gopkg.in/yaml.v2 v2.2.2 h1:f=\n\
             example.com/local v1.0.0 h1:g=\n",
        )
        .unwrap();
        let deps = GoParser.parse(&dir.path().join("go.mod")).unwrap();
        let get = |name: &str| deps.iter().find(|d| d.name == name).map(|d| (d.version.as_str(), d.direct));
        assert_eq!(get("github.com/json-iterator/go"), Some(("v1.1.9", true)));
        assert_eq!(get("golang.org/x/sys"), Some(("v0.0.0-20200116001909-b77594299b42", false)), "highest pseudo-version wins");
        assert_eq!(get("golang.org/x/text"), Some(("v0.3.0", false)), "the excluded version is skipped");
        assert_eq!(get("gopkg.in/yaml.v2"), Some(("v2.2.8", false)), "replace pins the version");
        assert_eq!(get("example.com/local"), None, "a local-directory replacement has no version to check");
    }

    #[test]
    fn go_1_17_modules_are_complete_and_ignore_go_sum() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("go.mod"), "module m\n\ngo 1.21\n\nrequire golang.org/x/net v0.17.0 // indirect\n").unwrap();
        std::fs::write(dir.path().join("go.sum"), "golang.org/x/crypto v0.14.0 h1:x=\n").unwrap();
        let deps = GoParser.parse(&dir.path().join("go.mod")).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(!deps[0].direct);
    }

    #[test]
    fn go_semver_orders_pseudo_versions_as_prereleases() {
        use std::cmp::Ordering::*;
        assert_eq!(semver_cmp("v0.0.0-20200116001909-b77594299b42", "v0.0.0-20220412211240-33da011f77ad"), Less);
        assert_eq!(semver_cmp("v0.0.0-20220412211240-33da011f77ad", "v0.1.0"), Less);
        assert_eq!(semver_cmp("v1.2.3", "v1.2.3-pre"), Greater);
        assert_eq!(semver_cmp("v2.0.0+incompatible", "v2.0.0"), Equal);
        assert_eq!(semver_cmp("v1.10.0", "v1.9.9"), Greater);
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
