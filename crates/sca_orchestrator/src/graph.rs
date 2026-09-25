//! Dependency-graph extraction from lockfiles — the manifest parsers
//! (`deps_*`) only emit flat `(name, version)` lists, so every lockfile
//! entry used to be reported `direct: false` and no finding could say *how*
//! a vulnerable package got into the build. This reads the edges the
//! lockfile already records and answers two questions per package:
//! is it declared directly, and what's the shortest root → … → package
//! chain (`dependency_path`, what Dependabot/Snyk show as "introduced
//! through").
//!
//! Deliberately name-level, not (name, version)-level: a lockfile can hold
//! two versions of one package, but the chain to *either* is the useful
//! answer for "which of my direct deps pulls this in", and name-level edges
//! keep every format's parser small. Unsupported/unreadable lockfiles just
//! yield no graph — paths are an enrichment, never a reason to fail a scan.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;
use uniflow_vuln_db::normalize_package_name;

/// One lockfile's graph. Node keys are *normalized* package names (see
/// `uniflow_vuln_db::normalize_package_name`), so they line up with
/// `Dependency.name` regardless of spelling.
#[derive(Debug, Default, Clone)]
pub struct LockGraph {
    pub ecosystem: String,
    /// Label for the chain's first element (the project itself).
    pub root_label: String,
    pub direct: BTreeSet<String>,
    pub edges: BTreeMap<String, BTreeSet<String>>,
    /// Display name + version for a normalized key, for rendering paths.
    pub display: HashMap<String, String>,
}

impl LockGraph {
    fn new(ecosystem: &str, root_label: String) -> Self {
        Self { ecosystem: ecosystem.to_string(), root_label, ..Default::default() }
    }

    fn key(&self, name: &str) -> String {
        normalize_package_name(&self.ecosystem, name)
    }

    fn add_direct(&mut self, name: &str) {
        let key = self.key(name);
        self.direct.insert(key);
    }

    fn add_edge(&mut self, from: &str, to: &str) {
        let (from, to) = (self.key(from), self.key(to));
        if from != to {
            self.edges.entry(from).or_default().insert(to);
        }
    }

    fn set_display(&mut self, name: &str, version: &str) {
        let key = self.key(name);
        self.display.entry(key).or_insert_with(|| if version.is_empty() { name.to_string() } else { format!("{name}@{version}") });
    }

    /// Shortest root → … → `name` chain, BFS over name-level edges from
    /// the direct set (sorted, so the result is deterministic). A direct
    /// dependency's path is `[root, itself]`; `None` if unreachable from
    /// any direct dependency in this graph (stale lockfile, a format we
    /// don't read edges for).
    pub fn path_to(&self, name: &str) -> Option<Vec<String>> {
        let target = self.key(name);
        let mut previous: HashMap<&str, Option<&str>> = HashMap::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        for root in &self.direct {
            previous.insert(root.as_str(), None);
            queue.push_back(root.as_str());
        }
        while let Some(node) = queue.pop_front() {
            if node == target {
                let mut chain = vec![node];
                let mut cursor = node;
                while let Some(Some(prev)) = previous.get(cursor) {
                    chain.push(prev);
                    cursor = prev;
                }
                chain.reverse();
                let mut out = vec![self.root_label.clone()];
                out.extend(chain.into_iter().map(|key| self.display.get(key).cloned().unwrap_or_else(|| key.to_string())));
                return Some(out);
            }
            if let Some(next) = self.edges.get(node) {
                for child in next {
                    if !previous.contains_key(child.as_str()) {
                        previous.insert(child.as_str(), Some(node));
                        queue.push_back(child.as_str());
                    }
                }
            }
        }
        None
    }
}

fn dir_label(path: &Path) -> String {
    path.parent()
        .and_then(|dir| dir.file_name())
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| "(project)".to_string())
}

/// Parses `path` as a lockfile graph if it's a format this module reads.
pub fn read_lock_graph(path: &Path) -> Option<LockGraph> {
    let file_name = path.file_name()?.to_str()?;
    let text = std::fs::read_to_string(path).ok()?;
    let label = dir_label(path);
    match file_name {
        "package-lock.json" | "npm-shrinkwrap.json" => npm_package_lock(&text, label),
        "pnpm-lock.yaml" => pnpm_lock(&text, label),
        "yarn.lock" => yarn_lock(&text, label),
        "Cargo.lock" => cargo_lock(&text, label),
        "poetry.lock" => python_lock(&text, label, "poetry"),
        "uv.lock" => python_lock(&text, label, "uv"),
        _ => None,
    }
}

fn npm_package_lock(text: &str, label: String) -> Option<LockGraph> {
    let json: Value = serde_json::from_str(text).ok()?;
    let label = json.get("name").and_then(Value::as_str).map(str::to_string).unwrap_or(label);
    let mut graph = LockGraph::new("npm", label);
    const DEP_FIELDS: [&str; 4] = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
    if let Some(packages) = json.get("packages").and_then(Value::as_object) {
        // lockfileVersion 2/3: `packages[""]` is the root project; every
        // other key is an install path whose last `node_modules/` segment
        // is the package name (nested paths = duplicated versions).
        for (install_path, meta) in packages {
            let is_root = install_path.is_empty();
            let name = install_path.rsplit("node_modules/").next().unwrap_or(install_path).to_string();
            if !is_root {
                graph.set_display(&name, meta.get("version").and_then(Value::as_str).unwrap_or_default());
            }
            for field in DEP_FIELDS {
                let Some(deps) = meta.get(field).and_then(Value::as_object) else { continue };
                for child in deps.keys() {
                    if is_root {
                        graph.add_direct(child);
                    } else {
                        graph.add_edge(&name, child);
                    }
                }
            }
        }
        return Some(graph);
    }
    // lockfileVersion 1: a nested `dependencies` tree with `requires`
    // edges. It doesn't mark which top-level entries are direct (hoisting
    // puts transitive deps there too) — the sibling package.json supplies
    // that (see the orchestrator's direct-marking pass).
    fn walk(graph: &mut LockGraph, deps: &serde_json::Map<String, Value>) {
        for (name, meta) in deps {
            graph.set_display(name, meta.get("version").and_then(Value::as_str).unwrap_or_default());
            if let Some(requires) = meta.get("requires").and_then(Value::as_object) {
                for child in requires.keys() {
                    graph.add_edge(name, child);
                }
            }
            if let Some(nested) = meta.get("dependencies").and_then(Value::as_object) {
                walk(graph, nested);
            }
        }
    }
    walk(&mut graph, json.get("dependencies")?.as_object()?);
    Some(graph)
}

fn pnpm_lock(text: &str, label: String) -> Option<LockGraph> {
    let doc: Value = serde_yaml::from_str(text).ok()?;
    let mut graph = LockGraph::new("npm", label);
    // pnpm ≥6 lists the workspace root(s) under `importers`; older
    // single-project lockfiles put `dependencies` at the top level.
    let mut roots: Vec<&Value> = Vec::new();
    if let Some(importers) = doc.get("importers").and_then(Value::as_object) {
        roots.extend(importers.values());
    } else {
        roots.push(&doc);
    }
    for root in roots {
        for field in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(deps) = root.get(field).and_then(Value::as_object) {
                for name in deps.keys() {
                    graph.add_direct(name);
                }
            }
        }
    }
    // Edges live under `snapshots` (v9) or `packages` (<9); keys are
    // `name@version` or `/name@version`, optionally with a `(peer...)` suffix.
    for section in ["snapshots", "packages"] {
        let Some(entries) = doc.get(section).and_then(Value::as_object) else { continue };
        for (key, meta) in entries {
            let key = key.trim_start_matches('/');
            let key = key.split('(').next().unwrap_or(key);
            let Some((name, version)) = key.rsplit_once('@').filter(|(name, _)| !name.is_empty()) else { continue };
            graph.set_display(name, version);
            for field in ["dependencies", "optionalDependencies"] {
                if let Some(deps) = meta.get(field).and_then(Value::as_object) {
                    for child in deps.keys() {
                        graph.add_edge(name, child);
                    }
                }
            }
        }
    }
    Some(graph)
}

/// Yarn v1's block format: a header line of `name@range` specs, then an
/// indented `dependencies:` sub-block of `child "range"` lines. Direct
/// deps come from the sibling package.json, as with npm lockfile v1.
fn yarn_lock(text: &str, label: String) -> Option<LockGraph> {
    let mut graph = LockGraph::new("npm", label);
    let mut current: Option<String> = None;
    let mut in_deps = false;
    for raw in text.lines() {
        if raw.starts_with('#') || raw.trim().is_empty() {
            continue;
        }
        if !raw.starts_with([' ', '\t']) {
            let spec = raw.trim_end_matches(':').split(',').next().unwrap_or_default().trim().trim_matches('"');
            let from = usize::from(spec.starts_with('@'));
            current = spec[from..].find('@').map(|at| spec[..from + at].to_string());
            in_deps = false;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        let Some(name) = current.clone() else { continue };
        if indent <= 2 {
            in_deps = line == "dependencies:" || line == "optionalDependencies:";
            if let Some(version) = line.strip_prefix("version ") {
                graph.set_display(&name, version.trim().trim_matches('"'));
            }
        } else if in_deps {
            if let Some(child) = line.split_whitespace().next() {
                graph.add_edge(&name, child.trim_matches('"'));
            }
        }
    }
    Some(graph)
}

fn cargo_lock(text: &str, label: String) -> Option<LockGraph> {
    #[derive(serde::Deserialize)]
    struct Lock {
        #[serde(default, rename = "package")]
        packages: Vec<Package>,
    }
    #[derive(serde::Deserialize)]
    struct Package {
        name: String,
        version: String,
        source: Option<String>,
        #[serde(default)]
        dependencies: Vec<String>,
    }
    let lock: Lock = toml::from_str(text).ok()?;
    // Workspace members are the packages with no `source` (they're built
    // from this checkout); their dependencies are the direct ones.
    let members: BTreeSet<&str> = lock.packages.iter().filter(|p| p.source.is_none()).map(|p| p.name.as_str()).collect();
    let label = if members.len() == 1 { members.iter().next().map(|m| m.to_string()).unwrap_or(label) } else { label };
    let mut graph = LockGraph::new("cargo", label);
    for package in &lock.packages {
        if !members.contains(package.name.as_str()) {
            graph.set_display(&package.name, &package.version);
        }
        for dep in &package.dependencies {
            // `"name"`, `"name version"`, or `"name version (source)"`.
            let child = dep.split_whitespace().next().unwrap_or(dep);
            if members.contains(child) {
                continue;
            }
            if members.contains(package.name.as_str()) {
                graph.add_direct(child);
            } else {
                graph.add_edge(&package.name, child);
            }
        }
    }
    Some(graph)
}

/// poetry.lock and uv.lock are both TOML `[[package]]` arrays but spell
/// edges differently: poetry uses a `[package.dependencies]` table keyed by
/// name, uv a `dependencies = [{ name = ... }]` array. Poetry's lockfile
/// has no root entry, so its direct set comes from the sibling
/// pyproject.toml via the orchestrator; uv marks the project itself with a
/// `source = { editable = "." }` / `{ virtual = "." }` entry.
fn python_lock(text: &str, label: String, flavor: &str) -> Option<LockGraph> {
    let doc: toml::Value = toml::from_str(text).ok()?;
    let packages = doc.get("package")?.as_array()?;
    let mut graph = LockGraph::new("pypi", label);
    for package in packages {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else { continue };
        let version = package.get("version").and_then(toml::Value::as_str).unwrap_or_default();
        let is_root = flavor == "uv"
            && package
                .get("source")
                .and_then(toml::Value::as_table)
                .is_some_and(|source| source.contains_key("editable") || source.contains_key("virtual"));
        if !is_root {
            graph.set_display(name, version);
        } else {
            graph.root_label = name.to_string();
        }
        let mut children: Vec<String> = Vec::new();
        match flavor {
            "poetry" => {
                if let Some(table) = package.get("dependencies").and_then(toml::Value::as_table) {
                    children.extend(table.keys().cloned());
                }
            }
            _ => {
                let mut push_array = |value: Option<&toml::Value>| {
                    for dep in value.and_then(toml::Value::as_array).into_iter().flatten() {
                        if let Some(child) = dep.get("name").and_then(toml::Value::as_str) {
                            children.push(child.to_string());
                        }
                    }
                };
                push_array(package.get("dependencies"));
                for group_key in ["optional-dependencies", "dev-dependencies"] {
                    if let Some(groups) = package.get(group_key).and_then(toml::Value::as_table) {
                        for group in groups.values() {
                            push_array(Some(group));
                        }
                    }
                }
            }
        }
        for child in children {
            if is_root {
                graph.add_direct(&child);
            } else {
                graph.add_edge(name, &child);
            }
        }
    }
    Some(graph)
}

/// Direct dependency names a *manifest* declares, for lockfile formats
/// whose graph has no root entry (npm lockfile v1, yarn v1, poetry): the
/// sibling package.json / pyproject.toml. Returns `(ecosystem, names)`.
pub fn declared_direct_names(path: &Path) -> Option<(&'static str, Vec<String>)> {
    let file_name = path.file_name()?.to_str()?;
    let text = std::fs::read_to_string(path).ok()?;
    match file_name {
        "package.json" => {
            let json: Value = serde_json::from_str(&text).ok()?;
            let mut names = Vec::new();
            for field in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
                if let Some(deps) = json.get(field).and_then(Value::as_object) {
                    names.extend(deps.keys().cloned());
                }
            }
            Some(("npm", names))
        }
        "pyproject.toml" => {
            let doc: toml::Value = toml::from_str(&text).ok()?;
            let mut names = Vec::new();
            // PEP 621 `[project] dependencies = ["requests>=2", ...]`.
            let pep621 = doc.get("project").and_then(|p| p.get("dependencies")).and_then(toml::Value::as_array);
            for spec in pep621.into_iter().flatten().filter_map(toml::Value::as_str) {
                let name: String = spec.chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')).collect();
                if !name.is_empty() {
                    names.push(name);
                }
            }
            // Poetry `[tool.poetry.dependencies]` (+ legacy dev table and
            // group tables); `python` is the interpreter constraint, not a package.
            let poetry = doc.get("tool").and_then(|t| t.get("poetry"));
            let mut tables: Vec<&toml::Value> = Vec::new();
            if let Some(poetry) = poetry {
                tables.extend(poetry.get("dependencies"));
                tables.extend(poetry.get("dev-dependencies"));
                if let Some(groups) = poetry.get("group").and_then(toml::Value::as_table) {
                    tables.extend(groups.values().filter_map(|g| g.get("dependencies")));
                }
            }
            for table in tables.into_iter().filter_map(toml::Value::as_table) {
                names.extend(table.keys().filter(|k| k.as_str() != "python").cloned());
            }
            Some(("pypi", names))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn npm_v3_lockfile_marks_direct_and_finds_introduction_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "package-lock.json",
            r#"{"name":"shop","lockfileVersion":3,"packages":{
                "":{"dependencies":{"express":"^4.17.0"}},
                "node_modules/express":{"version":"4.17.1","dependencies":{"qs":"6.7.0","body-parser":"1.19.0"}},
                "node_modules/body-parser":{"version":"1.19.0","dependencies":{"qs":"6.7.0"}},
                "node_modules/qs":{"version":"6.7.0"}}}"#,
        );
        let graph = read_lock_graph(&path).unwrap();
        assert!(graph.direct.contains("express"));
        assert!(!graph.direct.contains("qs"));
        assert_eq!(graph.path_to("qs").unwrap(), vec!["shop", "express@4.17.1", "qs@6.7.0"]);
        assert_eq!(graph.path_to("express").unwrap(), vec!["shop", "express@4.17.1"]);
        assert!(graph.path_to("left-pad").is_none());
    }

    #[test]
    fn cargo_lock_uses_workspace_members_as_roots() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "Cargo.lock",
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["hyper", "serde"]

[[package]]
name = "hyper"
version = "0.14.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["h2 0.3.0"]

[[package]]
name = "h2"
version = "0.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        );
        let graph = read_lock_graph(&path).unwrap();
        assert_eq!(graph.path_to("h2").unwrap(), vec!["app", "hyper@0.14.0", "h2@0.3.0"]);
        assert!(graph.direct.contains("serde"));
    }

    #[test]
    fn uv_lock_root_and_pep503_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "uv.lock",
            r#"
version = 1

[[package]]
name = "svc"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "Flask" }]

[[package]]
name = "flask"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "jinja2" }]

[[package]]
name = "jinja2"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
"#,
        );
        let graph = read_lock_graph(&path).unwrap();
        assert_eq!(graph.path_to("Jinja2").unwrap(), vec!["svc", "flask@2.0.0", "jinja2@3.0.0"]);
    }

    #[test]
    fn yarn_v1_edges_from_dependency_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "yarn.lock",
            "# yarn lockfile v1\n\nexpress@^4.0.0:\n  version \"4.17.1\"\n  dependencies:\n    qs \"6.7.0\"\n\nqs@6.7.0:\n  version \"6.7.0\"\n",
        );
        let mut graph = read_lock_graph(&path).unwrap();
        graph.add_direct("express");
        assert_eq!(graph.path_to("qs").unwrap().last().unwrap(), "qs@6.7.0");
    }

    #[test]
    fn pyproject_declares_direct_names_for_both_pep621_and_poetry() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "pyproject.toml",
            "[project]\ndependencies = [\"requests>=2\", \"PyYAML==5.3\"]\n[tool.poetry.dependencies]\npython = \"^3.10\"\nflask = \"^2\"\n",
        );
        let (eco, names) = declared_direct_names(&path).unwrap();
        assert_eq!(eco, "pypi");
        assert_eq!(names, vec!["requests", "PyYAML", "flask"]);
    }
}
