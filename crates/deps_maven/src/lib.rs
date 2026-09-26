//! Maven dependencies from `pom.xml`, with the version resolution Maven
//! itself would do before touching the network:
//! - `${property}` interpolation from `<properties>` and the `project.*` /
//!   `parent.*` coordinates, inherited through the **local** parent chain
//!   (`<relativePath>`, default `../pom.xml` — the multi-module layout of
//!   WebGoat and most enterprise repos, where versions live in the root);
//! - versionless dependencies filled from `<dependencyManagement>`, again
//!   inherited from parents;
//! - BOM imports (`<scope>import</scope>` in dependencyManagement) when the
//!   BOM's pom is available offline: as a module of the same repository,
//!   or in the local repository (`~/.m2/repository`, or `$MAVEN_REPO_LOCAL`).
//!
//! What stays unresolved — `LATEST`/`RELEASE`, version ranges, a property
//! defined only in a remote parent — is passed through unchanged, so the
//! matcher reports it as an unpinned version ("could not be checked")
//! rather than the package silently disappearing.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
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
        let Some(pom) = Pom::load(manifest_path) else { return Ok(Vec::new()) };
        let effective = Effective::build(manifest_path);
        let display = manifest_path.display().to_string();
        Ok(pom
            .dependencies
            .iter()
            .map(|dep| {
                let key = format!("{}:{}", effective.interpolate(&dep.group_id), effective.interpolate(&dep.artifact_id));
                let version = match &dep.version {
                    Some(v) => effective.interpolate(v),
                    None => effective.managed.get(&key).map(|v| effective.interpolate(v)).unwrap_or_default(),
                };
                Dependency { ecosystem: "maven".into(), name: key, version, manifest_path: display.clone(), direct: true }
            })
            .collect())
    }
}

#[derive(Clone, Debug, Default)]
struct Coord {
    group_id: String,
    artifact_id: String,
    version: Option<String>,
    scope: Option<String>,
    kind: Option<String>,
}

#[derive(Debug, Default)]
struct Pom {
    group_id: Option<String>,
    artifact_id: String,
    version: Option<String>,
    parent: Option<(Coord, String)>,
    properties: BTreeMap<String, String>,
    managed: Vec<Coord>,
    dependencies: Vec<Coord>,
}

fn child_text<'a>(node: roxmltree::Node<'a, 'a>, tag: &str) -> Option<&'a str> {
    node.children().find(|c| c.has_tag_name(tag)).and_then(|c| c.text()).map(str::trim).filter(|t| !t.is_empty())
}

fn coord(node: roxmltree::Node) -> Coord {
    Coord {
        group_id: child_text(node, "groupId").unwrap_or_default().to_string(),
        artifact_id: child_text(node, "artifactId").unwrap_or_default().to_string(),
        version: child_text(node, "version").map(str::to_string),
        scope: child_text(node, "scope").map(str::to_string),
        kind: child_text(node, "type").map(str::to_string),
    }
}

impl Pom {
    fn load(path: &Path) -> Option<Pom> {
        let text = std::fs::read_to_string(path).ok()?;
        let doc = roxmltree::Document::parse(&text).ok()?;
        let project = doc.root_element();
        let mut pom = Pom {
            group_id: child_text(project, "groupId").map(str::to_string),
            artifact_id: child_text(project, "artifactId").unwrap_or_default().to_string(),
            version: child_text(project, "version").map(str::to_string),
            ..Default::default()
        };
        for child in project.children().filter(|c| c.is_element()) {
            match child.tag_name().name() {
                "parent" => pom.parent = Some((coord(child), child_text(child, "relativePath").unwrap_or("../pom.xml").to_string())),
                "properties" => {
                    for prop in child.children().filter(|c| c.is_element()) {
                        pom.properties.insert(prop.tag_name().name().to_string(), prop.text().unwrap_or_default().trim().to_string());
                    }
                }
                "dependencyManagement" => {
                    let deps = child.children().find(|c| c.has_tag_name("dependencies"));
                    pom.managed = deps.map(|d| d.children().filter(|c| c.has_tag_name("dependency")).map(coord).collect()).unwrap_or_default();
                }
                // Only the project's own <dependencies>, not plugin ones.
                "dependencies" => {
                    pom.dependencies = child.children().filter(|c| c.has_tag_name("dependency")).map(coord).filter(|c| !c.group_id.is_empty() && !c.artifact_id.is_empty()).collect();
                }
                _ => {}
            }
        }
        Some(pom)
    }
}

/// The merged view of a pom and its local ancestors: properties and
/// managed versions, nearest definition winning.
struct Effective {
    properties: BTreeMap<String, String>,
    managed: BTreeMap<String, String>,
}

impl Effective {
    fn build(path: &Path) -> Effective {
        // Nearest first: the pom itself, then each parent found locally —
        // at `<relativePath>` (if it really is that parent) or in the local
        // repository. A parent only on a remote repository ends the chain.
        let mut chain: Vec<(PathBuf, Pom)> = Vec::new();
        let mut next = Pom::load(path).map(|pom| (path.to_path_buf(), pom));
        while let Some((here, pom)) = next.take() {
            if chain.len() < 16 {
                if let Some((parent, relative)) = pom.parent.clone() {
                    let candidate = here.parent().map(|d| d.join(&relative)).map(|p| if p.is_dir() { p.join("pom.xml") } else { p });
                    next = candidate
                        .filter(|p| p.is_file())
                        .and_then(|p| Pom::load(&p).map(|found| (p, found)))
                        .filter(|(_, found)| found.artifact_id == parent.artifact_id)
                        .or_else(|| local_repo_pom(&parent).and_then(|p| Pom::load(&p).map(|found| (p, found))));
                }
            }
            chain.push((here, pom));
        }
        if chain.is_empty() {
            return Effective { properties: BTreeMap::new(), managed: BTreeMap::new() };
        }

        let mut properties = BTreeMap::new();
        // Farthest first so nearer definitions overwrite.
        for (_, p) in chain.iter().rev() {
            properties.extend(p.properties.clone());
        }
        let root = &chain[0].1;
        let parent_coord = root.parent.as_ref().map(|(c, _)| c.clone()).unwrap_or_default();
        let group = root.group_id.clone().or_else(|| (!parent_coord.group_id.is_empty()).then(|| parent_coord.group_id.clone())).unwrap_or_default();
        let version = root.version.clone().or_else(|| parent_coord.version.clone()).unwrap_or_default();
        for (key, value) in [
            ("project.groupId", group.clone()),
            ("pom.groupId", group),
            ("project.artifactId", root.artifact_id.clone()),
            ("project.version", version.clone()),
            ("pom.version", version),
            ("project.parent.groupId", parent_coord.group_id.clone()),
            ("project.parent.version", parent_coord.version.clone().unwrap_or_default()),
            ("parent.version", parent_coord.version.clone().unwrap_or_default()),
        ] {
            properties.entry(key.to_string()).or_insert(value);
        }

        let mut effective = Effective { properties, managed: BTreeMap::new() };
        let repo_root = chain.last().map(|(p, _)| p.parent().unwrap_or(Path::new(".")).to_path_buf()).unwrap_or_default();
        for (_, p) in chain.iter().rev() {
            for managed in &p.managed {
                effective.add_managed(managed, &repo_root, 0);
            }
        }
        effective
    }

    fn add_managed(&mut self, managed: &Coord, repo_root: &Path, depth: usize) {
        let group = self.interpolate(&managed.group_id);
        let artifact = self.interpolate(&managed.artifact_id);
        let version = managed.version.as_deref().map(|v| self.interpolate(v)).unwrap_or_default();
        if managed.scope.as_deref() == Some("import") && managed.kind.as_deref() == Some("pom") {
            // A BOM: pull in its managed versions if its pom is available
            // offline. Its own properties apply only to its own entries.
            if depth >= 8 {
                return;
            }
            let bom = Coord { group_id: group, artifact_id: artifact, version: Some(version), ..Default::default() };
            let Some(path) = find_module_pom(repo_root, &bom).or_else(|| local_repo_pom(&bom)) else { return };
            let Some(bom_pom) = Pom::load(&path) else { return };
            let mut inner = Effective::build(&path);
            for entry in &bom_pom.managed {
                inner.add_managed(entry, repo_root, depth + 1);
            }
            for (k, v) in inner.managed {
                self.managed.entry(k).or_insert(v);
            }
            return;
        }
        self.managed.insert(format!("{group}:{artifact}"), version);
    }

    /// Expands `${name}` (repeatedly, for properties defined via other
    /// properties); unknown names stay as they are.
    fn interpolate(&self, value: &str) -> String {
        let mut out = value.trim().to_string();
        for _ in 0..8 {
            let Some(start) = out.find("${") else { break };
            let Some(len) = out[start..].find('}') else { break };
            let name = &out[start + 2..start + len];
            let Some(replacement) = self.properties.get(name).filter(|v| !v.contains(&format!("${{{name}}}"))) else { break };
            let replacement = replacement.clone();
            out.replace_range(start..start + len + 1, &replacement);
        }
        out
    }
}

/// A module of the same checkout with these coordinates (a repo's own BOM).
fn find_module_pom(repo_root: &Path, target: &Coord) -> Option<PathBuf> {
    let mut stack = vec![(repo_root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let pom = dir.join("pom.xml");
        if let Some(p) = Pom::load(&pom) {
            let group = p.group_id.clone().or_else(|| p.parent.as_ref().map(|(c, _)| c.group_id.clone()));
            if p.artifact_id == target.artifact_id && group.as_deref() == Some(target.group_id.as_str()) {
                return Some(pom);
            }
        }
        if depth < 4 {
            for entry in std::fs::read_dir(&dir).ok()?.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if path.is_dir() && !name.starts_with('.') && name != "target" && name != "node_modules" {
                    stack.push((path, depth + 1));
                }
            }
        }
    }
    None
}

/// `<repo>/<group path>/<artifact>/<version>/<artifact>-<version>.pom`.
fn local_repo_pom(target: &Coord) -> Option<PathBuf> {
    let version = target.version.as_deref().filter(|v| !v.is_empty() && !v.contains("${"))?;
    let repo = std::env::var_os("MAVEN_REPO_LOCAL")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".m2").join("repository")))?;
    let path = repo
        .join(target.group_id.replace('.', "/"))
        .join(&target.artifact_id)
        .join(version)
        .join(format!("{}-{version}.pom", target.artifact_id));
    path.is_file().then_some(path)
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

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn properties_and_dependency_management_resolve_through_the_local_parent_chain() {
        // WebGoat's shape: the root defines `guava.version` and manages
        // commons-lang3; a module uses both.
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("pom.xml"),
            r#"<project><groupId>org.owasp.webgoat</groupId><artifactId>webgoat-parent</artifactId><version>8.0.0.M14</version>
<properties><guava.version>18.0</guava.version><lang.version>3.4</lang.version></properties>
<dependencyManagement><dependencies>
  <dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>${lang.version}</version></dependency>
  <dependency><groupId>org.owasp.webgoat</groupId><artifactId>webgoat-bom</artifactId><version>${project.version}</version><type>pom</type><scope>import</scope></dependency>
</dependencies></dependencyManagement></project>"#,
        );
        write(
            &dir.path().join("bom/pom.xml"),
            r#"<project><parent><groupId>org.owasp.webgoat</groupId><artifactId>webgoat-parent</artifactId><version>8.0.0.M14</version></parent><artifactId>webgoat-bom</artifactId>
<properties><jackson.version>2.9.8</jackson.version></properties>
<dependencyManagement><dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency></dependencies></dependencyManagement></project>"#,
        );
        let module = dir.path().join("webgoat-container/pom.xml");
        write(
            &module,
            r#"<project><parent><groupId>org.owasp.webgoat</groupId><artifactId>webgoat-parent</artifactId><version>8.0.0.M14</version></parent>
<artifactId>webgoat-container</artifactId>
<dependencies>
  <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>${guava.version}</version></dependency>
  <dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId></dependency>
  <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
  <dependency><groupId>${project.groupId}</groupId><artifactId>webgoat-lessons</artifactId><version>${project.version}</version></dependency>
  <dependency><groupId>commons-io</groupId><artifactId>commons-io</artifactId><version>LATEST</version></dependency>
  <dependency><groupId>x</groupId><artifactId>y</artifactId><version>${remote.only}</version></dependency>
</dependencies></project>"#,
        );
        let deps = MavenParser.parse(&module).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).map(|d| d.version.clone());
        assert_eq!(get("com.google.guava:guava").as_deref(), Some("18.0"), "property from the parent");
        assert_eq!(get("org.apache.commons:commons-lang3").as_deref(), Some("3.4"), "managed version from the parent");
        assert_eq!(get("com.fasterxml.jackson.core:jackson-databind").as_deref(), Some("2.9.8"), "managed version from a local BOM import");
        assert_eq!(get("org.owasp.webgoat:webgoat-lessons").as_deref(), Some("8.0.0.M14"), "project coordinates inherited from the parent");
        assert_eq!(get("commons-io:commons-io").as_deref(), Some("LATEST"), "left for the matcher to report as unpinned");
        assert_eq!(get("x:y").as_deref(), Some("${remote.only}"));
    }
}
