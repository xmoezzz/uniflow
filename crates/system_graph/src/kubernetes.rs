//! Kubernetes adapter: parses ordinary (possibly `---`-separated
//! multi-document) YAML manifests, recovering `Deployment`/`StatefulSet`/
//! `DaemonSet`/`Job`/`CronJob` workloads, `Service`, `Ingress`, and
//! `ConfigMap`/`Secret` references.
//!
//! Recovered relationships:
//! - `Ingress --ROUTES_TO--> KubernetesService` (from `spec.rules[].http.paths[].backend`).
//! - `KubernetesService --SELECTS--> Workload` (label-selector match against
//!   the workload's own pod-template labels — never a data-flow edge).
//! - `Workload --READS_CONFIG--> ConfigMap` (from `envFrom`/`valueFrom.configMapKeyRef`).
//! - `Workload --DEFINES_CONFIG--> EnvironmentVariable` (literal `env:` values,
//!   or a `configMapKeyRef`/`secretKeyRef`-sourced value resolved through a
//!   ConfigMap defined in the same input set, including concrete `envFrom`
//!   ConfigMap keys and their optional prefix — Secret *values* are
//!   deliberately never read, only the reference structure).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_yaml::Value;

use crate::graph::{BoundarySummary, Confidence, EdgeKind, Evidence, NodeKind, SystemGraph, SystemNode};

const WORKLOAD_KINDS: &[&str] = &["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"];

fn looks_like_manifest(path: &Path) -> bool {
    let is_yaml = path.extension().and_then(|extension| extension.to_str()).is_some_and(|extension| extension == "yaml" || extension == "yml");
    is_yaml && !crate::docker_compose::is_compose_file(path)
}

/// Finds every `.yaml`/`.yml` file under `roots` that isn't a Docker
/// Compose file — a document with no recognized `kind:` (i.e. anything
/// that isn't actually a Kubernetes manifest) is simply skipped by
/// [`discover_into`], so this only needs to narrow by extension.
pub fn find_manifest_files(roots: &[PathBuf]) -> Vec<PathBuf> {
    crate::discovery::find_files(roots, looks_like_manifest)
}

fn ns(value: &Value) -> String {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get("namespace"))
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string()
}

fn name_of(value: &Value) -> Option<String> {
    value.get("metadata")?.get("name")?.as_str().map(str::to_string)
}

fn workload_id(kind: &str, namespace: &str, name: &str) -> String {
    format!("k8s:{kind}:{namespace}/{name}")
}

fn service_id(namespace: &str, name: &str) -> String {
    format!("k8s:Service:{namespace}/{name}")
}

fn ingress_id(namespace: &str, name: &str) -> String {
    format!("k8s:Ingress:{namespace}/{name}")
}

fn configmap_id(namespace: &str, name: &str) -> String {
    format!("k8s:ConfigMap:{namespace}/{name}")
}

fn secret_id(namespace: &str, name: &str) -> String {
    format!("k8s:Secret:{namespace}/{name}")
}

fn env_id(namespace: &str, workload: &str, container: &str, key: &str) -> String {
    format!("k8s:env:{namespace}/{workload}:{container}:{key}")
}

/// Parses every manifest in `manifest_files` (each may contain multiple
/// `---`-separated YAML documents) and folds the recovered resources into
/// `graph`.
pub fn discover_into(graph: &mut SystemGraph, manifest_files: &[PathBuf]) -> Result<()> {
    // Two passes: first every resource is registered as a node (so
    // label-selector/ConfigMap-key lookups below can see resources declared
    // later in the same file, or in a different file entirely), then
    // relationships are recovered.
    let mut documents = Vec::new();
    for path in manifest_files {
        if let Err(error) = collect_documents(path, &mut documents) {
            // A malformed/unexpected file under a *discovered* (not
            // user-specified) manifest path must not abort every other
            // recovered fact — log and move on.
            eprintln!("uniflow: skipping Kubernetes manifest {}: {error:#}", path.display());
        }
    }

    for (document, _path) in &documents {
        register_node(graph, document);
    }
    for (document, path) in &documents {
        if let Err(error) = recover_relationships(graph, document, path) {
            eprintln!("uniflow: failed to process a document in {}: {error:#}", path.display());
        }
    }
    Ok(())
}

fn collect_documents(path: &Path, out: &mut Vec<(Value, PathBuf)>) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read Kubernetes manifest {}", path.display()))?;
    let yaml = normalize_helm_template(&text);
    for document in serde_yaml::Deserializer::from_str(&yaml) {
        let value = Value::deserialize(document)
            .with_context(|| format!("failed to parse a YAML document in {}", path.display()))?;
        if value.is_null() {
            continue;
        }
        out.push((value, path.to_path_buf()));
    }
    Ok(())
}

/// Produces a conservative YAML view of a Helm template without evaluating it.
///
/// Deployment discovery needs stable resource names/selectors, not rendered
/// values. Helm control lines are not YAML, so drop them and replace inline
/// expressions with deterministic scalar markers. Identical value references
/// receive identical markers, preserving relationships such as a Service's
/// selector and its Deployment label. For an `if`/`else`, the first branch is
/// selected as a stable representative; evaluating every branch in one YAML
/// document would create duplicate mapping keys and lose the entire manifest.
fn normalize_helm_template(text: &str) -> String {
    if !text.contains("{{") {
        return text.to_string();
    }
    let mut output = Vec::new();
    let mut branches = Vec::<bool>::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(action) = helm_control_action(trimmed) {
            let active = branches.last().copied().unwrap_or(true);
            if is_helm_branch_start(action) {
                branches.push(active);
            } else if action.starts_with("else") {
                if let Some(current) = branches.last_mut() {
                    // Keep the first branch. A single representative preserves
                    // valid YAML while we cannot know chart values statically.
                    *current = false;
                }
            } else if action == "end" {
                branches.pop();
            }
            continue;
        }
        if branches.last().copied().unwrap_or(true) {
            output.push(replace_helm_actions(line));
        }
    }
    output.join("\n")
}

fn helm_control_action(line: &str) -> Option<&str> {
    let action = line.strip_prefix("{{")?.strip_suffix("}}")?;
    Some(action.trim().trim_matches('-').trim())
}

fn is_helm_branch_start(action: &str) -> bool {
    action == "if"
        || action.starts_with("if ")
        || action == "with"
        || action.starts_with("with ")
        || action == "range"
        || action.starts_with("range ")
        || action == "define"
        || action.starts_with("define ")
        || action == "block"
        || action.starts_with("block ")
}

fn replace_helm_actions(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut remaining = line;
    while let Some(start) = remaining.find("{{") {
        output.push_str(&remaining[..start]);
        let after_open = &remaining[start + 2..];
        let Some(end) = after_open.find("}}") else {
            // Leave an unterminated action intact so the YAML parser reports
            // the original malformed manifest instead of silently changing it.
            output.push_str(&remaining[start..]);
            return output;
        };
        output.push_str(&helm_action_marker(&after_open[..end]));
        remaining = &after_open[end + 2..];
    }
    output.push_str(remaining);
    output
}

fn helm_action_marker(action: &str) -> String {
    let action = action.trim().trim_matches('-').trim();
    let reference = action
        .split(|character: char| {
            character.is_whitespace() || matches!(character, '|' | '(' | ')' | ',')
        })
        .find(|token| {
            token.starts_with(".Values.")
                || token.starts_with(".Release.")
                || token.starts_with(".Chart.")
        });
    let Some(reference) = reference else {
        return "uniflow-helm-expression".to_string();
    };
    let slug = reference
        .trim_start_matches('.')
        .chars()
        .map(|character| match character {
            '.' => '-',
            character if character.is_ascii_alphanumeric() || character == '_' || character == '-' => {
                character.to_ascii_lowercase()
            }
            _ => '-',
        })
        .collect::<String>();
    format!("uniflow-helm-{slug}")
}

fn kind_of(document: &Value) -> Option<&str> {
    document.get("kind")?.as_str()
}

fn register_node(graph: &mut SystemGraph, document: &Value) {
    let Some(kind) = kind_of(document) else { return };
    let Some(name) = name_of(document) else { return };
    let namespace = ns(document);

    if WORKLOAD_KINDS.contains(&kind) {
        let mut node = SystemNode::new(NodeKind::KubernetesWorkload, workload_id(kind, &namespace, &name), &name)
            .with_attr("kind", kind)
            .with_attr("namespace", &namespace);
        if let Some(labels) = pod_template(document, kind).and_then(|template| template.get("metadata")?.get("labels")?.as_mapping()) {
            for (key, value) in labels {
                if let (Some(key), Some(value)) = (key.as_str(), value.as_str()) {
                    node = node.with_attr(format!("label:{key}"), value);
                }
            }
        }
        graph.upsert_node(node);
    } else if kind == "Service" {
        graph.upsert_node(
            SystemNode::new(NodeKind::KubernetesService, service_id(&namespace, &name), &name)
                .with_attr("namespace", &namespace),
        );
    } else if kind == "Ingress" {
        graph.upsert_node(
            SystemNode::new(NodeKind::Ingress, ingress_id(&namespace, &name), &name)
                .with_attr("namespace", &namespace),
        );
    } else if kind == "ConfigMap" {
        let mut node = SystemNode::new(NodeKind::ConfigMap, configmap_id(&namespace, &name), &name)
            .with_attr("namespace", &namespace);
        if let Some(data) = document.get("data").and_then(Value::as_mapping) {
            for (key, value) in data {
                if let (Some(key), Some(value)) = (key.as_str(), value.as_str()) {
                    node = node.with_attr(format!("data:{key}"), value);
                }
            }
        }
        graph.upsert_node(node);
    } else if kind == "Secret" {
        graph.upsert_node(
            SystemNode::new(NodeKind::Secret, secret_id(&namespace, &name), &name)
                .with_attr("namespace", &namespace),
        );
    }
}

fn recover_relationships(graph: &mut SystemGraph, document: &Value, path: &Path) -> Result<()> {
    let Some(kind) = kind_of(document) else { return Ok(()) };
    let Some(name) = name_of(document) else { return Ok(()) };
    let namespace = ns(document);
    let location = path.display().to_string();

    if WORKLOAD_KINDS.contains(&kind) {
        recover_workload(graph, document, kind, &namespace, &name, &location)?;
    } else if kind == "Service" {
        recover_service(graph, document, &namespace, &name)?;
    } else if kind == "Ingress" {
        recover_ingress(graph, document, &namespace, &name, &location)?;
    }
    Ok(())
}

/// The pod template a workload's containers live under differs only by kind:
/// `spec.template` for Deployment/StatefulSet/DaemonSet/Job, and
/// `spec.jobTemplate.spec.template` for CronJob.
fn pod_template<'a>(document: &'a Value, kind: &str) -> Option<&'a Value> {
    if kind == "CronJob" {
        document.get("spec")?.get("jobTemplate")?.get("spec")?.get("template")
    } else {
        document.get("spec")?.get("template")
    }
}

fn recover_workload(
    graph: &mut SystemGraph,
    document: &Value,
    kind: &str,
    namespace: &str,
    name: &str,
    location: &str,
) -> Result<()> {
    let workload_node_id = workload_id(kind, namespace, name);
    let Some(template) = pod_template(document, kind) else { return Ok(()) };
    let Some(containers) = template.get("spec").and_then(|spec| spec.get("containers")).and_then(Value::as_sequence)
    else {
        return Ok(());
    };

    for container in containers {
        let container_name = container.get("name").and_then(Value::as_str).unwrap_or("default");
        recover_container_env(graph, &workload_node_id, namespace, name, container_name, container, location)?;
        recover_container_env_from(
            graph,
            &workload_node_id,
            namespace,
            name,
            container_name,
            container,
            location,
        )?;
    }
    Ok(())
}

fn recover_container_env(
    graph: &mut SystemGraph,
    workload_node_id: &str,
    namespace: &str,
    workload_name: &str,
    container_name: &str,
    container: &Value,
    location: &str,
) -> Result<()> {
    let Some(env) = container.get("env").and_then(Value::as_sequence) else { return Ok(()) };
    for entry in env {
        let Some(key) = entry.get("name").and_then(Value::as_str) else { continue };
        let env_node_id = env_id(namespace, workload_name, container_name, key);

        if let Some(literal) = entry.get("value").and_then(Value::as_str) {
            graph.upsert_node(SystemNode::new(NodeKind::EnvironmentVariable, env_node_id.clone(), key).with_attr("value", literal));
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::DefinesConfig, workload_node_id, env_node_id, Confidence::Exact)
                    .with_evidence(Evidence::at(format!("container env {key}={literal}"), location)),
            )?;
            continue;
        }

        let Some(value_from) = entry.get("valueFrom") else { continue };
        if let Some(config_map_key_ref) = value_from.get("configMapKeyRef") {
            let Some(map_name) = config_map_key_ref.get("name").and_then(Value::as_str) else { continue };
            let Some(map_key) = config_map_key_ref.get("key").and_then(Value::as_str) else { continue };
            let configmap_node_id = configmap_id(namespace, map_name);
            if !graph.contains(&configmap_node_id) {
                graph.upsert_node(SystemNode::new(NodeKind::ConfigMap, configmap_node_id.clone(), map_name));
            }
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::ReadsConfig, workload_node_id, configmap_node_id.clone(), Confidence::Exact)
                    .with_evidence(Evidence::at(format!("env {key} <- configMapKeyRef {map_name}.{map_key}"), location)),
            )?;
            let resolved_value = graph
                .node(&configmap_node_id)
                .and_then(|node| node.attrs.get(&format!("data:{map_key}")))
                .cloned();
            let mut env_node = SystemNode::new(NodeKind::EnvironmentVariable, env_node_id.clone(), key);
            if let Some(value) = &resolved_value {
                env_node = env_node.with_attr("value", value.as_str());
            }
            graph.upsert_node(env_node);
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::DefinesConfig, workload_node_id, env_node_id, Confidence::Inferred)
                    .with_evidence(Evidence::at(format!("resolved via ConfigMap {map_name}.{map_key}"), location)),
            )?;
        } else if let Some(secret_key_ref) = value_from.get("secretKeyRef") {
            // Reference structure only — Secret *contents* are never read.
            let Some(secret_name) = secret_key_ref.get("name").and_then(Value::as_str) else { continue };
            let secret_node_id = secret_id(namespace, secret_name);
            if !graph.contains(&secret_node_id) {
                graph.upsert_node(SystemNode::new(NodeKind::Secret, secret_node_id.clone(), secret_name));
            }
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::ReadsConfig, workload_node_id, secret_node_id, Confidence::Exact)
                    .with_evidence(Evidence::at(format!("env {key} <- secretKeyRef {secret_name}"), location)),
            )?;
        }
    }
    Ok(())
}

fn recover_container_env_from(
    graph: &mut SystemGraph,
    workload_node_id: &str,
    namespace: &str,
    workload_name: &str,
    container_name: &str,
    container: &Value,
    location: &str,
) -> Result<()> {
    let Some(env_from) = container.get("envFrom").and_then(Value::as_sequence) else { return Ok(()) };
    for source in env_from {
        if let Some(name) = source.get("configMapRef").and_then(|r| r.get("name")).and_then(Value::as_str) {
            let configmap_node_id = configmap_id(namespace, name);
            if !graph.contains(&configmap_node_id) {
                graph.upsert_node(SystemNode::new(NodeKind::ConfigMap, configmap_node_id.clone(), name));
            }
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::ReadsConfig, workload_node_id, configmap_node_id.clone(), Confidence::Exact)
                    .with_evidence(Evidence::at(format!("envFrom.configMapRef {name}"), location)),
            )?;

            // `envFrom` injects every literal key in a ConfigMap as an
            // environment variable.  Expand only keys declared in the same
            // analysis input; inventing keys for an external ConfigMap would
            // make a later `getenv` lookup look proven when it is not.
            let prefix = source.get("prefix").and_then(Value::as_str).unwrap_or("");
            let entries: Vec<(String, String)> = graph
                .node(&configmap_node_id)
                .into_iter()
                .flat_map(|node| node.attrs.iter())
                .filter_map(|(key, value)| key.strip_prefix("data:").map(|key| (key.to_string(), value.clone())))
                .collect();
            for (map_key, value) in entries {
                let env_key = format!("{prefix}{map_key}");
                let env_node_id = env_id(namespace, workload_name, container_name, &env_key);
                graph.upsert_node(
                    SystemNode::new(NodeKind::EnvironmentVariable, env_node_id.clone(), &env_key)
                        .with_attr("value", &value),
                );
                graph.apply_boundary(
                    BoundarySummary::new(EdgeKind::DefinesConfig, workload_node_id, env_node_id, Confidence::Inferred)
                        .with_evidence(Evidence::at(
                            format!("envFrom.configMapRef {name} injects {env_key} from {map_key}"),
                            location,
                        )),
                )?;
            }
        }
    }
    Ok(())
}

fn recover_service(graph: &mut SystemGraph, document: &Value, namespace: &str, name: &str) -> Result<()> {
    let service_node_id = service_id(namespace, name);
    let Some(selector) = document.get("spec").and_then(|spec| spec.get("selector")).and_then(Value::as_mapping)
    else {
        return Ok(());
    };
    let selector: HashMap<String, String> = selector
        .iter()
        .filter_map(|(key, value)| Some((key.as_str()?.to_string(), value.as_str()?.to_string())))
        .collect();
    if selector.is_empty() {
        return Ok(());
    }

    // Find every already-registered workload in the same namespace whose pod
    // template labels are a superset of the Service's selector.
    let candidates: Vec<(String, HashMap<String, String>)> = graph
        .nodes()
        .filter(|node| node.kind == NodeKind::KubernetesWorkload && node.attrs.get("namespace").map(String::as_str) == Some(namespace))
        .map(|node| (node.id.clone(), node.attrs.clone()))
        .collect();

    for (workload_id, attrs) in candidates {
        let matches = selector.iter().all(|(key, value)| attrs.get(&format!("label:{key}")).map(String::as_str) == Some(value.as_str()));
        if matches {
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::Selects, service_node_id.clone(), workload_id, Confidence::Exact)
                    .with_evidence(Evidence::new(format!("Service selector {selector:?} matches workload labels"))),
            )?;
        }
    }
    Ok(())
}

fn recover_ingress(graph: &mut SystemGraph, document: &Value, namespace: &str, name: &str, location: &str) -> Result<()> {
    let ingress_node_id = ingress_id(namespace, name);
    let Some(rules) = document.get("spec").and_then(|spec| spec.get("rules")).and_then(Value::as_sequence) else {
        return Ok(());
    };
    for rule in rules {
        let Some(paths) = rule.get("http").and_then(|http| http.get("paths")).and_then(Value::as_sequence) else {
            continue;
        };
        for path_rule in paths {
            let Some(service_name) = path_rule
                .get("backend")
                .and_then(|backend| backend.get("service"))
                .and_then(|service| service.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let service_node_id = service_id(namespace, service_name);
            if !graph.contains(&service_node_id) {
                graph.upsert_node(SystemNode::new(NodeKind::KubernetesService, service_node_id.clone(), service_name));
            }
            let path_text = path_rule.get("path").and_then(Value::as_str).unwrap_or("/");
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::RoutesTo, ingress_node_id.clone(), service_node_id, Confidence::Exact)
                    .with_evidence(Evidence::at(format!("ingress rule path {path_text}"), location)),
            )?;
        }
    }
    Ok(())
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
    fn recovers_ingress_service_and_workload_topology_without_data_flow() {
        let (_dir, path) = write_temp(
            "manifests.yaml",
            r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
  namespace: default
  labels:
    app: worker
spec:
  template:
    metadata:
      labels:
        app: worker
    spec:
      containers:
        - name: worker
          env:
            - name: LOG_LEVEL
              value: "debug"
---
apiVersion: v1
kind: Service
metadata:
  name: worker
  namespace: default
spec:
  selector:
    app: worker
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: main
  namespace: default
spec:
  rules:
    - http:
        paths:
          - path: /worker
            backend:
              service:
                name: worker
"#,
        );

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[path]).expect("discover kubernetes manifests");

        assert!(graph.contains("k8s:Deployment:default/worker"));
        assert!(graph.contains("k8s:Service:default/worker"));
        assert!(graph.contains("k8s:Ingress:default/main"));

        let routes_to: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::RoutesTo).collect();
        assert_eq!(routes_to.len(), 1, "{routes_to:?}");
        assert_eq!(routes_to[0].0.id, "k8s:Ingress:default/main");
        assert_eq!(routes_to[0].1.id, "k8s:Service:default/worker");

        // No edge kind here may ever carry data flow — this is pure topology.
        for (_, _, edge) in graph.edges() {
            assert!(!edge.kind.carries_data_flow(), "{edge:?} must not be a data-flow edge");
        }
    }

    #[test]
    fn resolves_env_through_configmap_key_ref() {
        let (_dir, path) = write_temp(
            "manifests.yaml",
            r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  SERVICE_URL: http://worker:9000
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: api
          env:
            - name: SERVICE_URL
              valueFrom:
                configMapKeyRef:
                  name: app-config
                  key: SERVICE_URL
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[path]).expect("discover kubernetes manifests");
        let reads_config: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::ReadsConfig).collect();
        assert_eq!(reads_config.len(), 1, "{reads_config:?}");
        assert_eq!(reads_config[0].1.id, "k8s:ConfigMap:default/app-config");
    }

    #[test]
    fn expands_configmap_env_from_keys_with_the_declared_prefix() {
        let (_dir, path) = write_temp(
            "env-from.yaml",
            r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: messaging
data:
  TOPIC: orders
  UNUSED: ignored
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: producer
spec:
  template:
    spec:
      containers:
        - name: app
          envFrom:
            - prefix: APP_
              configMapRef:
                name: messaging
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[path]).expect("discover kubernetes manifests");

        let topic = graph
            .nodes()
            .find(|node| node.kind == NodeKind::EnvironmentVariable && node.name == "APP_TOPIC")
            .expect("envFrom must materialize a concrete environment variable");
        assert_eq!(topic.attrs.get("value").map(String::as_str), Some("orders"));
        assert!(graph.edges().any(|(from, to, edge)| {
            from.id == "k8s:Deployment:default/producer"
                && to.id == topic.id
                && edge.kind == EdgeKind::DefinesConfig
        }));
    }

    #[test]
    fn recovers_workload_service_relationships_from_a_helm_template() {
        let (_dir, path) = write_temp(
            "worker.yaml",
            r#"
{{- if .Values.worker.create }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.worker.name }}
spec:
  selector:
    matchLabels:
      app: {{ .Values.worker.name }}
  template:
    metadata:
      labels:
        app: {{ .Values.worker.name }}
    spec:
      containers:
        - name: worker
          image: {{ .Values.images.repository }}/{{ .Values.worker.name }}:{{ .Values.images.tag }}
      {{- if .Values.serviceAccounts.create }}
      serviceAccountName: {{ .Values.worker.name }}
      {{- else }}
      serviceAccountName: default
      {{- end }}
{{- end }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.worker.name }}
spec:
  selector:
    app: {{ .Values.worker.name }}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[path]).expect("discover Helm manifest");

        let name = "uniflow-helm-values-worker-name";
        assert!(graph.contains(&workload_id("Deployment", "default", name)));
        assert!(graph.contains(&service_id("default", name)));
        assert!(graph.edges().any(|(from, to, edge)| {
            from.id == service_id("default", name)
                && to.id == workload_id("Deployment", "default", name)
                && edge.kind == EdgeKind::Selects
        }));
    }
}
