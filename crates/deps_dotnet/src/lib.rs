//! NuGet dependencies, from whichever of these a project has:
//! - `packages.lock.json` — resolved versions (a lockfile: preferred by the
//!   orchestrator over the project files next to it);
//! - `*.csproj` / `*.fsproj` / `*.vbproj` `<PackageReference>`s, with the
//!   version from the element itself, its `VersionOverride`, or — central
//!   package management — the nearest ancestor `Directory.Packages.props`
//!   (`<PackageVersion>`), plus that file's `<GlobalPackageReference>`s;
//! - legacy `packages.config`.
//!
//! `$(Property)` references are expanded from the project's own
//! `<PropertyGroup>`s and every `Directory.Build.props` /
//! `Directory.Packages.props` above it — how eShopOnWeb-style repos write
//! `Version="$(AspNetVersion)"`. A floating or range version is reduced to
//! the version NuGet would actually pick without a lockfile: its lower
//! bound (`[1.2.3, )` → `1.2.3`); anything still unresolved (`*`, an
//! unknown property) is passed through so the matcher reports it as an
//! unpinned version instead of silently dropping the package.
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use uniflow_sca_core::{Dependency, ManifestParser};

pub struct NuGetParser;

const PROJECT_EXTENSIONS: &[&str] = &["csproj", "fsproj", "vbproj"];

impl ManifestParser for NuGetParser {
    fn ecosystem(&self) -> &'static str {
        "nuget"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["packages.lock.json", "packages.config"]
    }

    fn matches_file_name(&self, file_name: &str) -> bool {
        self.manifest_file_names().contains(&file_name)
            || Path::new(file_name).extension().and_then(|e| e.to_str()).is_some_and(|e| PROJECT_EXTENSIONS.contains(&e))
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let file_name = manifest_path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let display = manifest_path.display().to_string();
        Ok(match file_name {
            "packages.lock.json" => parse_lock(&text, &display),
            "packages.config" => parse_packages_config(&text, &display),
            _ => parse_project(manifest_path, &text, &display),
        })
    }
}

#[derive(Deserialize)]
struct PackagesLock {
    #[serde(default)]
    dependencies: BTreeMap<String, Value>,
}

fn parse_lock(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let Ok(lock) = serde_json::from_str::<PackagesLock>(text) else { return Vec::new() };
    let mut deps = Vec::new();
    for framework in lock.dependencies.values() {
        let Some(packages) = framework.as_object() else { continue };
        for (name, meta) in packages {
            // `Project` entries are sibling projects of the same solution.
            if meta.get("type").and_then(Value::as_str) == Some("Project") {
                continue;
            }
            let Some(resolved) = meta.get("resolved").and_then(Value::as_str) else { continue };
            deps.push(nuget_dep(name, resolved, manifest_path, meta.get("type").and_then(Value::as_str) == Some("Direct")));
        }
    }
    deps
}

fn parse_packages_config(text: &str, manifest_path: &str) -> Vec<Dependency> {
    let Ok(doc) = roxmltree::Document::parse(text) else { return Vec::new() };
    doc.descendants()
        .filter(|n| n.has_tag_name("package"))
        .filter_map(|n| Some(nuget_dep(n.attribute("id")?, n.attribute("version")?, manifest_path, true)))
        .collect()
}

fn nuget_dep(name: &str, version: &str, manifest_path: &str, direct: bool) -> Dependency {
    Dependency { ecosystem: "nuget".into(), name: name.to_string(), version: version.to_string(), manifest_path: manifest_path.to_string(), direct }
}

/// Everything MSBuild would have imported implicitly above `project`:
/// the nearest `Directory.Packages.props` and every `Directory.Build.props`
/// up to the filesystem root, nearest last (so the nearest wins).
struct Imports {
    properties: BTreeMap<String, String>,
    central: BTreeMap<String, String>,
    global_refs: Vec<(String, String)>,
    central_enabled: bool,
}

fn load_imports(project: &Path) -> Imports {
    let mut chain: Vec<PathBuf> = Vec::new();
    let mut dir = project.parent();
    let mut found_packages_props = false;
    while let Some(d) = dir {
        let build = d.join("Directory.Build.props");
        if build.is_file() {
            chain.push(build);
        }
        let packages = d.join("Directory.Packages.props");
        if !found_packages_props && packages.is_file() {
            // Only the nearest one applies (it may import a parent itself).
            chain.push(packages);
            found_packages_props = true;
        }
        dir = d.parent();
    }
    chain.reverse();
    let mut imports = Imports { properties: BTreeMap::new(), central: BTreeMap::new(), global_refs: Vec::new(), central_enabled: false };
    for file in chain {
        let Ok(text) = std::fs::read_to_string(&file) else { continue };
        let Ok(doc) = roxmltree::Document::parse(&text) else { continue };
        collect_properties(&doc, &mut imports.properties);
        for node in doc.descendants() {
            let (Some(include), Some(version)) = (node.attribute("Include"), node.attribute("Version")) else { continue };
            if node.has_tag_name("PackageVersion") {
                imports.central.insert(include.to_ascii_lowercase(), version.to_string());
            } else if node.has_tag_name("GlobalPackageReference") {
                imports.global_refs.push((include.to_string(), version.to_string()));
            }
        }
    }
    imports.central_enabled = imports.properties.get("managepackageversionscentrally").is_some_and(|v| v.eq_ignore_ascii_case("true"))
        || !imports.central.is_empty();
    imports
}

fn collect_properties(doc: &roxmltree::Document, into: &mut BTreeMap<String, String>) {
    for group in doc.descendants().filter(|n| n.has_tag_name("PropertyGroup")) {
        for prop in group.children().filter(|n| n.is_element()) {
            // MSBuild property names are case-insensitive.
            into.insert(prop.tag_name().name().to_ascii_lowercase(), prop.text().unwrap_or_default().trim().to_string());
        }
    }
}

/// Expands `$(Name)` references; unknown names are left as-is (and then
/// reported as an unresolved version by the matcher).
fn expand(value: &str, properties: &BTreeMap<String, String>) -> String {
    let mut out = value.to_string();
    for _ in 0..8 {
        let Some(start) = out.find("$(") else { break };
        let Some(len) = out[start..].find(')') else { break };
        let name = out[start + 2..start + len].to_ascii_lowercase();
        let Some(replacement) = properties.get(&name) else { break };
        out.replace_range(start..start + len + 1, replacement);
    }
    out
}

/// NuGet resolves a range to the lowest version it allows: `[1.2.3, )`,
/// `[1.2.3,2.0)` and `(,2.0]`-less forms all start at their lower bound.
/// An exclusive lower bound or open start can't be pinned — left as-is.
fn lowest_applicable(version: &str) -> String {
    let v = version.trim();
    if let Some(rest) = v.strip_prefix('[') {
        let lower = rest.split([',', ']']).next().unwrap_or_default().trim();
        if !lower.is_empty() {
            return lower.to_string();
        }
    }
    v.to_string()
}

fn parse_project(path: &Path, text: &str, manifest_path: &str) -> Vec<Dependency> {
    let Ok(doc) = roxmltree::Document::parse(text) else { return Vec::new() };
    let mut imports = load_imports(path);
    collect_properties(&doc, &mut imports.properties);
    let mut deps = Vec::new();
    for node in doc.descendants().filter(|n| n.has_tag_name("PackageReference")) {
        // `Update=` modifies an item from an import; only `Include=` adds one.
        let Some(name) = node.attribute("Include") else { continue };
        let child = |tag: &str| node.children().find(|c| c.has_tag_name(tag)).and_then(|c| c.text()).map(str::trim);
        let version = node
            .attribute("VersionOverride")
            .or_else(|| child("VersionOverride"))
            .or_else(|| node.attribute("Version"))
            .or_else(|| child("Version"))
            .map(str::to_string)
            .or_else(|| imports.central.get(&name.to_ascii_lowercase()).cloned())
            .unwrap_or_default();
        deps.push(nuget_dep(name, &lowest_applicable(&expand(&version, &imports.properties)), manifest_path, true));
    }
    if imports.central_enabled {
        for (name, version) in &imports.global_refs {
            deps.push(nuget_dep(name, &lowest_applicable(&expand(version, &imports.properties)), manifest_path, true));
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_direct_resolved_version_from_packages_lock_json() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("packages.lock.json");
        std::fs::write(
            &path,
            r#"{ "version": 1, "dependencies": { "net6.0": { "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1" }, "Web": { "type": "Project" } } } }"#,
        )
        .expect("write fixture");

        let deps = NuGetParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 1, "sibling projects are not packages");
        assert_eq!(deps[0].name, "Newtonsoft.Json");
        assert_eq!(deps[0].version, "13.0.1");
        assert!(deps[0].direct);
    }

    #[test]
    fn central_package_management_resolves_versions_and_properties() {
        // eShopOnWeb's layout: versions (some via `$(AspNetVersion)`) live
        // only in the root Directory.Packages.props.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Directory.Packages.props"),
            r#"<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally><AspNetVersion>8.0.2</AspNetVersion></PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Azure.Identity" Version="1.10.4" />
    <PackageVersion Include="Microsoft.AspNetCore.Identity.EntityFrameworkCore" Version="$(AspNetVersion)" />
    <PackageVersion Include="System.Text.Json" Version="8.0.3" />
    <GlobalPackageReference Include="Nerdbank.GitVersioning" Version="[3.6.133, )" />
  </ItemGroup>
</Project>"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src/Web")).unwrap();
        let project = dir.path().join("src/Web/Web.csproj");
        std::fs::write(
            &project,
            r#"<Project Sdk="Microsoft.NET.Sdk.Web">
  <ItemGroup>
    <PackageReference Include="Azure.Identity" />
    <PackageReference Include="microsoft.aspnetcore.identity.entityframeworkcore" />
    <PackageReference Include="System.Text.Json" VersionOverride="8.0.0" />
    <PackageReference Update="Azure.Identity" PrivateAssets="all" />
  </ItemGroup>
</Project>"#,
        )
        .unwrap();
        assert!(NuGetParser.matches_file_name("Web.csproj"));
        let deps = NuGetParser.parse(&project).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).map(|d| d.version.clone());
        assert_eq!(get("Azure.Identity").as_deref(), Some("1.10.4"));
        assert_eq!(get("microsoft.aspnetcore.identity.entityframeworkcore").as_deref(), Some("8.0.2"), "property expanded, lookup case-insensitive");
        assert_eq!(get("System.Text.Json").as_deref(), Some("8.0.0"), "VersionOverride wins");
        assert_eq!(get("Nerdbank.GitVersioning").as_deref(), Some("3.6.133"), "global reference, range lower bound");
        assert_eq!(deps.len(), 4, "`Update=` adds nothing");
    }

    #[test]
    fn classic_project_versions_and_packages_config() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("App.fsproj");
        std::fs::write(
            &project,
            r#"<Project><PropertyGroup><JsonVer>12.0.1</JsonVer></PropertyGroup><ItemGroup>
<PackageReference Include="Newtonsoft.Json" Version="$(JsonVer)" />
<PackageReference Include="Serilog"><Version>2.10.0</Version></PackageReference>
<PackageReference Include="Floating" Version="*" /></ItemGroup></Project>"#,
        )
        .unwrap();
        let deps = NuGetParser.parse(&project).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).map(|d| d.version.clone());
        assert_eq!(get("Newtonsoft.Json").as_deref(), Some("12.0.1"));
        assert_eq!(get("Serilog").as_deref(), Some("2.10.0"));
        assert_eq!(get("Floating").as_deref(), Some("*"), "left unresolved for the matcher to report");

        let config = dir.path().join("packages.config");
        std::fs::write(&config, r#"<packages><package id="jQuery" version="1.7.1" targetFramework="net45" /></packages>"#).unwrap();
        let deps = NuGetParser.parse(&config).unwrap();
        assert_eq!((deps[0].name.as_str(), deps[0].version.as_str()), ("jQuery", "1.7.1"));
    }
}
