//! Docker Compose adapter: parses `docker-compose.yml`/`docker-compose.yaml`/
//! `compose.yml`/`compose.yaml`, recovering services, `depends_on`,
//! environment (inline and `env_file`), ports/`expose`, and networks.
//!
//! Recovered relationships:
//! - `DockerService --STARTUP_DEPENDS_ON--> DockerService` (from `depends_on`;
//!   this is a startup-ordering edge, never a data-flow edge).
//! - `DockerService --DEFINES_CONFIG--> EnvironmentVariable` (from a static
//!   `environment:`/`env_file:` entry; only literal, non-interpolated values
//!   are recorded as a concrete `value` attr).
//! - `DockerService --EXPOSES--> Port` (from `ports:`/`expose:`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::graph::{BoundarySummary, Confidence, Evidence, NodeKind, SystemGraph, SystemNode};

/// File names recognized as Docker Compose project files.
pub const COMPOSE_FILE_NAMES: &[&str] =
    &["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"];

pub fn is_compose_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| COMPOSE_FILE_NAMES.contains(&name))
}

/// Finds every Docker Compose file under `roots`.
pub fn find_compose_files(roots: &[PathBuf]) -> Vec<PathBuf> {
    crate::discovery::find_files(roots, is_compose_file)
}

fn service_id(service: &str) -> String {
    format!("docker-compose:service:{service}")
}

fn env_id(service: &str, key: &str) -> String {
    format!("docker-compose:env:{service}:{key}")
}

fn port_id(service: &str, port: &str) -> String {
    format!("docker-compose:port:{service}:{port}")
}

/// Parses every compose file in `compose_files` and folds the recovered
/// services/dependencies/config/ports into `graph`. Each path's own
/// directory is used to resolve a relative `env_file:` entry.
pub fn discover_into(graph: &mut SystemGraph, compose_files: &[PathBuf]) -> Result<()> {
    for path in compose_files {
        if let Err(error) = discover_one_file(graph, path) {
            // A malformed/unexpected file under a *discovered* (not
            // user-specified) compose path must not abort every other
            // recovered fact — log and move on.
            eprintln!("uniflow: skipping compose file {}: {error:#}", path.display());
        }
    }
    Ok(())
}

fn discover_one_file(graph: &mut SystemGraph, path: &Path) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read compose file {}", path.display()))?;
    let document: serde_yaml::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("failed to parse compose file {}", path.display()))?;
    discover_document(graph, &document, path)
}

fn discover_document(graph: &mut SystemGraph, document: &serde_yaml::Value, path: &Path) -> Result<()> {
    let location = path.display().to_string();
    let base_dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let Some(services) = document.get("services").and_then(|value| value.as_mapping()) else {
        return Ok(());
    };

    for (name_value, definition) in services {
        let Some(name) = name_value.as_str() else { continue };
        let id = service_id(name);
        let mut node = SystemNode::new(NodeKind::DockerService, id.clone(), name);
        if let Some(image) = definition.get("image").and_then(|v| v.as_str()) {
            node = node.with_attr("image", image);
        }
        if let Some(build) = definition.get("build") {
            let build_desc = build.as_str().map(str::to_string).unwrap_or_else(|| "custom".to_string());
            node = node.with_attr("build", build_desc);
        }
        if let Some(command) = command_string(definition.get("command")) {
            node = node.with_attr("command", command);
        }
        graph.upsert_node(node);

        record_ports(graph, name, definition.get("ports"), &location)?;
        record_ports(graph, name, definition.get("expose"), &location)?;
        record_environment(graph, name, definition.get("environment"), &location)?;
        record_env_files(graph, name, definition.get("env_file"), &base_dir)?;
        record_depends_on(graph, name, definition.get("depends_on"), &location)?;
    }
    Ok(())
}

fn command_string(command: Option<&serde_yaml::Value>) -> Option<String> {
    let command = command?;
    if let Some(text) = command.as_str() {
        return Some(text.to_string());
    }
    let sequence = command.as_sequence()?;
    let parts: Vec<&str> = sequence.iter().filter_map(|item| item.as_str()).collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn record_ports(
    graph: &mut SystemGraph,
    service: &str,
    ports: Option<&serde_yaml::Value>,
    location: &str,
) -> Result<()> {
    let Some(ports) = ports.and_then(|value| value.as_sequence()) else {
        return Ok(());
    };
    let service_node_id = service_id(service);
    for port in ports {
        let port_spec = match port {
            serde_yaml::Value::String(text) => text.clone(),
            serde_yaml::Value::Number(number) => number.to_string(),
            _ => continue,
        };
        let id = port_id(service, &port_spec);
        graph.upsert_node(SystemNode::new(NodeKind::Port, id.clone(), &port_spec));
        graph.apply_boundary(
            BoundarySummary::new(
                crate::graph::EdgeKind::Exposes,
                service_node_id.clone(),
                id,
                Confidence::Exact,
            )
            .with_evidence(Evidence::at(format!("compose ports/expose entry {port_spec:?}"), location)),
        )?;
    }
    Ok(())
}

/// `environment:` accepts either a `KEY=VALUE` list or a `KEY: VALUE` map;
/// both forms are normalized to the same `(key, Option<value>)` pairs
/// (`value` is `None` when the list form omits `=value`, meaning "inherit
/// from the host shell" — nothing statically recoverable).
fn normalize_environment(value: &serde_yaml::Value) -> Vec<(String, Option<String>)> {
    if let Some(mapping) = value.as_mapping() {
        return mapping
            .iter()
            .filter_map(|(key, value)| {
                let key = key.as_str()?.to_string();
                let value = match value {
                    serde_yaml::Value::Null => None,
                    serde_yaml::Value::String(text) => Some(text.clone()),
                    serde_yaml::Value::Number(number) => Some(number.to_string()),
                    serde_yaml::Value::Bool(flag) => Some(flag.to_string()),
                    _ => None,
                };
                Some((key, value))
            })
            .collect();
    }
    let Some(sequence) = value.as_sequence() else {
        return Vec::new();
    };
    sequence
        .iter()
        .filter_map(|entry| entry.as_str())
        .map(|entry| match entry.split_once('=') {
            Some((key, value)) => (key.to_string(), Some(value.to_string())),
            None => (entry.to_string(), None),
        })
        .collect()
}

/// A value is only recorded as a concrete literal when it contains no shell
/// interpolation (`${...}`/`$NAME`) — those depend on the host environment
/// at `docker compose up` time and are not statically recoverable here.
fn is_static_literal(value: &str) -> bool {
    !value.contains('$')
}

fn record_environment(
    graph: &mut SystemGraph,
    service: &str,
    environment: Option<&serde_yaml::Value>,
    location: &str,
) -> Result<()> {
    let Some(environment) = environment else { return Ok(()) };
    let service_node_id = service_id(service);
    for (key, value) in normalize_environment(environment) {
        add_config_value(graph, &service_node_id, service, &key, value.as_deref(), location, "compose environment")?;
    }
    Ok(())
}

fn record_env_files(
    graph: &mut SystemGraph,
    service: &str,
    env_file: Option<&serde_yaml::Value>,
    base_dir: &Path,
) -> Result<()> {
    let Some(env_file) = env_file else { return Ok(()) };
    let paths: Vec<String> = match env_file {
        serde_yaml::Value::String(text) => vec![text.clone()],
        serde_yaml::Value::Sequence(sequence) => {
            sequence.iter().filter_map(|item| item.as_str().map(str::to_string)).collect()
        }
        _ => Vec::new(),
    };
    let service_node_id = service_id(service);
    for relative in paths {
        let full_path = base_dir.join(&relative);
        let Ok(text) = std::fs::read_to_string(&full_path) else {
            // Not statically available (missing, or path depends on something
            // dynamic) — nothing to recover, not an error for the whole run.
            continue;
        };
        let file_location = full_path.display().to_string();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else { continue };
            add_config_value(
                graph,
                &service_node_id,
                service,
                key.trim(),
                Some(value.trim()),
                &file_location,
                &format!("env_file {relative}"),
            )?;
        }
    }
    Ok(())
}

fn add_config_value(
    graph: &mut SystemGraph,
    service_node_id: &str,
    service: &str,
    key: &str,
    value: Option<&str>,
    location: &str,
    evidence_kind: &str,
) -> Result<()> {
    let id = env_id(service, key);
    let mut node = SystemNode::new(NodeKind::EnvironmentVariable, id.clone(), key);
    let mut description = format!("{evidence_kind} {key}");
    if let Some(value) = value.filter(|value| is_static_literal(value)) {
        node = node.with_attr("value", value);
        description = format!("{evidence_kind} {key}={value}");
    }
    graph.upsert_node(node);
    graph.apply_boundary(
        BoundarySummary::new(crate::graph::EdgeKind::DefinesConfig, service_node_id, id, Confidence::Exact)
            .with_evidence(Evidence::at(description, location)),
    )
}

fn record_depends_on(
    graph: &mut SystemGraph,
    service: &str,
    depends_on: Option<&serde_yaml::Value>,
    location: &str,
) -> Result<()> {
    let Some(depends_on) = depends_on else { return Ok(()) };
    let names: Vec<String> = if let Some(sequence) = depends_on.as_sequence() {
        sequence.iter().filter_map(|item| item.as_str().map(str::to_string)).collect()
    } else if let Some(mapping) = depends_on.as_mapping() {
        mapping.keys().filter_map(|key| key.as_str().map(str::to_string)).collect()
    } else {
        Vec::new()
    };
    let service_node_id = service_id(service);
    for dependency in names {
        let dependency_id = service_id(&dependency);
        // The dependency might be declared later in the same file (or in
        // another compose file entirely, e.g. an override file) — insert a
        // placeholder so the edge is always valid; a later `upsert_node`
        // call for the real service definition merges into this same node.
        if !graph.contains(&dependency_id) {
            graph.upsert_node(SystemNode::new(NodeKind::DockerService, dependency_id.clone(), &dependency));
        }
        graph.apply_boundary(
            BoundarySummary::new(
                crate::graph::EdgeKind::StartupDependsOn,
                service_node_id.clone(),
                dependency_id,
                Confidence::Exact,
            )
            .with_evidence(Evidence::at(format!("compose depends_on: {dependency}"), location)),
        )?;
    }
    Ok(())
}

/// Every `EnvironmentVariable` node recovered anywhere, keyed by name, with
/// its statically-known literal `value` when one was recorded — the shape
/// `config`'s cross-language `getenv` resolution needs, decoupled from
/// Compose's own node-id scheme.
pub fn environment_values(graph: &SystemGraph) -> BTreeMap<String, Vec<(String, Option<String>)>> {
    let mut out: BTreeMap<String, Vec<(String, Option<String>)>> = BTreeMap::new();
    for node in graph.nodes() {
        if node.kind != NodeKind::EnvironmentVariable {
            continue;
        }
        out.entry(node.name.clone())
            .or_default()
            .push((node.id.clone(), node.attrs.get("value").cloned()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("write fixture");
        (dir, path)
    }

    #[test]
    fn recovers_services_depends_on_and_environment() {
        let (_dir, path) = write_temp(
            "docker-compose.yml",
            r#"
services:
  api:
    image: api:latest
    depends_on:
      - db
    environment:
      - USER_SERVICE_URL=http://user:8080
      - DEBUG=1
    ports:
      - "8080:8080"
  db:
    image: postgres:15
"#,
        );

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[path]).expect("discover compose");

        assert!(graph.contains("docker-compose:service:api"));
        assert!(graph.contains("docker-compose:service:db"));

        let depends_on_edges: Vec<_> = graph
            .edges()
            .filter(|(_, _, edge)| edge.kind == crate::graph::EdgeKind::StartupDependsOn)
            .collect();
        assert_eq!(depends_on_edges.len(), 1);
        assert_eq!(depends_on_edges[0].0.id, "docker-compose:service:api");
        assert_eq!(depends_on_edges[0].1.id, "docker-compose:service:db");
        assert!(!depends_on_edges[0].2.kind.carries_data_flow());

        let env_values = environment_values(&graph);
        let url_entries = env_values.get("USER_SERVICE_URL").expect("USER_SERVICE_URL recorded");
        assert_eq!(url_entries.len(), 1);
        assert_eq!(url_entries[0].1.as_deref(), Some("http://user:8080"));
    }

    #[test]
    fn shell_interpolated_environment_values_are_not_treated_as_literals() {
        let (_dir, path) = write_temp(
            "docker-compose.yml",
            r#"
services:
  api:
    environment:
      - SERVICE_URL=${SERVICE_URL}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[path]).expect("discover compose");
        let env_values = environment_values(&graph);
        assert_eq!(env_values.get("SERVICE_URL").unwrap()[0].1, None);
    }
}
