use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dependency {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub manifest_path: String,
    pub direct: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub vulnerable_range: String,
    pub recommended_version: Option<String>,
    pub manifest_path: String,
    pub cve_ids: Vec<String>,
    pub cwe: Vec<String>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MalwareFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub path: String,
    pub line: usize,
    pub snippet: String,
    pub message: String,
}

pub trait ManifestParser {
    fn ecosystem(&self) -> &'static str;
    /// Exact filenames this parser handles (the common case: `package.json`,
    /// `go.mod`, ...). Ecosystems whose manifest is named after the package
    /// itself rather than a fixed convention (OCaml opam's `<name>.opam`)
    /// instead override [`Self::matches_file_name`].
    fn manifest_file_names(&self) -> &'static [&'static str];
    /// Whether this parser should run against a file named `file_name`.
    /// Defaults to an exact match against [`Self::manifest_file_names`].
    fn matches_file_name(&self, file_name: &str) -> bool {
        self.manifest_file_names().contains(&file_name)
    }
    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>>;
}
