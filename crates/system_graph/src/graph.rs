//! The unified system-wide graph: nodes and typed edges recovered by
//! semantic-boundary adapters (Docker Compose, Kubernetes, config
//! resolution, HTTP stitching, lifecycle/framework entrypoints, FFI, ...).
//!
//! This is a deliberately separate graph from each language's own
//! `uniflow_value_flow::FlowGraph` — that graph is fundamentally
//! single-language (`uniflow_ir::merge_programs` refuses to combine two
//! `Language`s), while a Docker service, a Kubernetes Ingress, or an HTTP
//! route has no natural home there at all. Nodes here that DO correspond to
//! a piece of code (`Function`/`Method`/...) carry a [`CodeRef`] back to that
//! language's own qualified-name convention, so a [`SystemEdge`] that
//! connects two such nodes can be *bridged* into a synthetic per-language
//! taint rule (see `crate::bridge`) — the same "probe/summary, then inject a
//! synthetic rule" pattern already used for the JNI/FFI bridge — rather than
//! attempting to merge graphs.

use std::collections::HashMap;

use anyhow::{bail, Result};
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

/// What kind of thing a [`SystemNode`] represents. Deliberately broad: not
/// every adapter populates every variant in this first implementation, but
/// the vocabulary is fixed here so adapters agree on terms instead of
/// inventing ad hoc string tags per adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    // Code-level: a node of one of these kinds is a *reference* to something
    // a language frontend already represents (see `CodeRef`), not a
    // replacement for it.
    Function,
    Method,
    CallSite,
    Parameter,
    ReturnValue,
    Variable,
    AbstractObject,
    MemoryRegion,

    // Runtime/framework
    Application,
    LifecycleEvent,
    Entrypoint,
    HttpRoute,
    RpcMethod,
    MessageHandler,
    ScheduledTask,

    // Component
    Process,
    Service,
    Container,
    Workload,

    // Communication/resource
    HttpEndpoint,
    RpcChannel,
    MessageTopic,
    MessageQueue,
    Database,
    DatabaseTable,

    // Configuration/deployment
    EnvironmentVariable,
    ConfigValue,
    Hostname,
    Port,
    DockerService,
    KubernetesService,
    KubernetesDeployment,
    KubernetesWorkload,
    Ingress,
    ConfigMap,
    Secret,
}

/// Typed semantic relationships. Kept intentionally specific — see this
/// crate's top-level docs and [`EdgeKind::carries_data_flow`] for why a
/// deployment/topology edge (e.g. `STARTUP_DEPENDS_ON`) must never be
/// conflated with an edge that actually carries a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeKind {
    // Program
    Call,
    DataFlow,
    ControlFlow,
    PointsTo,

    // Language interoperability
    InteropCall,
    InteropArg,
    InteropReturn,
    InteropMemory,
    InteropCallback,

    // Framework/lifecycle
    RegistersHandler,
    Triggers,
    Handles,
    Startup,
    Shutdown,

    // Service communication
    HttpCall,
    RpcCall,
    RoutesTo,
    Publishes,
    Subscribes,
    DeliversTo,

    // Configuration
    ReadsConfig,
    DefinesConfig,
    ResolvesTo,

    // Deployment
    Deploys,
    Selects,
    Exposes,
    StartupDependsOn,

    // Storage
    ReadsResource,
    WritesResource,
}

impl EdgeKind {
    /// `true` for edges that represent (or carry) value/taint flow — the
    /// ones [`crate::bridge`] is allowed to turn into a synthetic taint
    /// rule. Pure topology/deployment/registration edges are excluded on
    /// purpose: a `docker-compose depends_on` (`STARTUP_DEPENDS_ON`) or a
    /// `Service -> Deployment` selector (`SELECTS`) is never a data-flow
    /// edge, no matter how tempting it is to conflate "connected" with
    /// "flows data".
    pub fn carries_data_flow(self) -> bool {
        matches!(
            self,
            EdgeKind::DataFlow
                | EdgeKind::InteropArg
                | EdgeKind::InteropReturn
                | EdgeKind::InteropMemory
                | EdgeKind::HttpCall
                | EdgeKind::RpcCall
                | EdgeKind::Publishes
                | EdgeKind::DeliversTo
                | EdgeKind::ResolvesTo
                | EdgeKind::ReadsResource
                | EdgeKind::WritesResource
        )
    }
}

/// How much to trust a recovered edge. Ordered low-to-high so
/// `Confidence::Exact > Confidence::Inferred > Confidence::Conservative`
/// reads naturally with derived [`Ord`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Ambiguous: this is one of several candidate targets, listed rather
    /// than arbitrarily chosen (e.g. a dynamically-constructed URL, or a
    /// config value that could resolve to more than one service).
    Conservative,
    /// Recovered through indirection that is itself sound but not a literal
    /// match (e.g. an environment variable resolved through a Compose/
    /// Kubernetes definition rather than a hardcoded literal).
    Inferred,
    /// Directly evidenced with no indirection (e.g. a literal URL matching
    /// an exact, statically-declared route).
    Exact,
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Conservative
    }
}

/// A human-readable reason to believe a recovered edge is real, plus (when
/// available) a source location — every non-local edge should carry at
/// least one of these so a user can answer "why does UniFlow think these
/// are connected?".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl Evidence {
    pub fn new(description: impl Into<String>) -> Self {
        Self { description: description.into(), location: None }
    }

    pub fn at(description: impl Into<String>, location: impl Into<String>) -> Self {
        Self { description: description.into(), location: Some(location.into()) }
    }
}

/// Which language/callable a code-level [`SystemNode`] corresponds to.
/// `qualified_name` follows the exact same dotted convention each language
/// frontend already uses for `Callee::Static`/rule `ApiMatcher::exact` (e.g.
/// `App.source`, `com.example.Foo.bar`), so it can be dropped directly into
/// a synthetic rule's matcher with no translation step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRef {
    pub language: uniflow_hir::Language,
    pub qualified_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemNode {
    pub kind: NodeKind,
    /// Stable, globally-unique, human-readable identity, e.g.
    /// `docker-compose:service:api`, `k8s:Deployment:default/worker`,
    /// `java:App.nativeSink`. Each adapter picks its own namespacing
    /// convention; the graph only requires uniqueness.
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attrs: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_ref: Option<CodeRef>,
}

impl SystemNode {
    pub fn new(kind: NodeKind, id: impl Into<String>, name: impl Into<String>) -> Self {
        Self { kind, id: id.into(), name: name.into(), attrs: HashMap::new(), code_ref: None }
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    pub fn with_code_ref(mut self, code_ref: CodeRef) -> Self {
        self.code_ref = Some(code_ref);
        self
    }
}

/// Addresses one specific value inside one specific function, in one
/// language/component — the identity a [`BoundaryFlowEdge`] connects.
///
/// `function` is this codebase's *existing* stable cross-referencing
/// identity for a callable (the exact same dotted-qualified-name convention
/// `Callee::Static`/`ApiMatcher::exact`/`FunctionMatcher::exact` already use
/// everywhere) — not a new convention invented here, and not "a function
/// name alone": a call-site-anchored ref also carries `call_site`, a real
/// per-instruction id (`uniflow_ir::InstId`'s numeric value), so two
/// identical-looking calls to the same callee from the same function are
/// still distinguishable. `port` reuses [`uniflow_rules::Port`] — the same
/// port vocabulary the taint engine's own rules already address values
/// with — rather than inventing a parallel identity scheme.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowNodeRef {
    pub language: uniflow_hir::Language,
    pub function: String,
    /// Present when this ref anchors to one call site's own ports
    /// (`Port::Arg`/`Port::Return` of *that call*); absent when it anchors
    /// to `function`'s own formal parameters/return instead (the shape
    /// `uniflow_rules::FunctionSourceRule`/`FunctionSinkRule` already
    /// address — see `crate::bridge`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_site: Option<u32>,
    pub port: uniflow_rules::Port,
}

impl FlowNodeRef {
    pub fn function_port(language: uniflow_hir::Language, function: impl Into<String>, port: uniflow_rules::Port) -> Self {
        Self { language, function: function.into(), call_site: None, port }
    }

    pub fn call_site_port(
        language: uniflow_hir::Language,
        function: impl Into<String>,
        call_site: u32,
        port: uniflow_rules::Port,
    ) -> Self {
        Self { language, function: function.into(), call_site: Some(call_site), port }
    }
}

/// What kind of correspondence a [`BoundaryFlowEdge`] represents — kept
/// distinct from the *mechanism* (HTTP, FFI, message, RPC, ...) that
/// recovered it, since the same shapes recur across every mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueMappingKind {
    /// A plain value handed across with no positional/role meaning of its
    /// own (e.g. an opaque message payload).
    ValueToValue,
    /// A caller's actual argument to a callee's formal parameter (FFI, an
    /// HTTP query/path/body field bound to a handler parameter, ...).
    ArgumentToParameter,
    /// A callee's return value back to the caller's own result.
    ReturnToResult,
    /// One named field of a producer's structure to a same-named field a
    /// consumer reads (message/RPC payload fields).
    FieldToField,
}

/// One precise, addressable correspondence between a value on one side of a
/// recovered semantic boundary and a value on the other side — the
/// mechanism-agnostic unit [`crate::bridge`] composes into synthetic
/// per-language rules and, ultimately, one continuous cross-component
/// finding. This is an *analysis input*, not descriptive metadata: unlike
/// declaring every parameter of a callee tainted, a `BoundaryFlowEdge`
/// preserves *which* value maps to *which* value, so unrelated
/// parameters/fields are never conflated (see the negative tests in
/// `crates/cli/tests/system_graph_analysis.rs`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundaryFlowEdge {
    pub kind: ValueMappingKind,
    pub from: FlowNodeRef,
    pub to: FlowNodeRef,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Reserved for a future adapter to describe a non-identity transform
    /// applied to the value crossing the boundary (JSON encoding, a
    /// protobuf field projection, ...). Not populated by any v1 adapter —
    /// every mapping today is a direct, untransformed value correspondence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<String>,
}

impl BoundaryFlowEdge {
    pub fn new(kind: ValueMappingKind, from: FlowNodeRef, to: FlowNodeRef, confidence: Confidence) -> Self {
        Self { kind, from, to, confidence, evidence: Vec::new(), transform: None }
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemEdge {
    pub kind: EdgeKind,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Populated when this edge carries one or more specific value mappings
    /// across the boundary (e.g. HTTP query field -> handler parameter).
    /// Absent for pure topology/registration edges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value_mappings: Vec<BoundaryFlowEdge>,
}

impl SystemEdge {
    pub fn new(kind: EdgeKind, confidence: Confidence) -> Self {
        Self { kind, confidence, evidence: Vec::new(), value_mappings: Vec::new() }
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn with_value_mapping(mut self, mapping: BoundaryFlowEdge) -> Self {
        self.value_mappings.push(mapping);
        self
    }
}

/// A normalized, mechanism-agnostic recovered fact: "producer is connected
/// to consumer this way, for these reasons, with this confidence, possibly
/// carrying these specific value mappings." Every adapter (Docker Compose,
/// Kubernetes, config resolution, HTTP stitching, FFI, ...) produces these
/// instead of mutating the graph directly, so the graph-construction and
/// rule-bridging logic in [`crate::bridge`] stays uniform across mechanisms.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BoundarySummary {
    pub kind: Option<EdgeKind>,
    pub producer: String,
    pub consumer: String,
    #[serde(default)]
    pub value_mappings: Vec<BoundaryFlowEdge>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub confidence: Confidence,
}

impl BoundarySummary {
    pub fn new(kind: EdgeKind, producer: impl Into<String>, consumer: impl Into<String>, confidence: Confidence) -> Self {
        Self {
            kind: Some(kind),
            producer: producer.into(),
            consumer: consumer.into(),
            value_mappings: Vec::new(),
            evidence: Vec::new(),
            confidence,
        }
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn with_value_mapping(mut self, mapping: BoundaryFlowEdge) -> Self {
        self.value_mappings.push(mapping);
        self
    }
}

/// The unified system-wide graph. A thin, serializable wrapper around a
/// `petgraph` directed multigraph, keyed by each node's own stable `id`.
#[derive(Default)]
pub struct SystemGraph {
    graph: DiGraph<SystemNode, SystemEdge>,
    index_by_id: HashMap<String, NodeIndex>,
}

impl SystemGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `node`, or — if a node with the same `id` already exists —
    /// merges `node`'s attrs/code_ref into it. Adapters commonly discover
    /// the same node (e.g. a Docker service mentioned in both its own
    /// definition and another service's `depends_on`) more than once.
    pub fn upsert_node(&mut self, node: SystemNode) -> NodeIndex {
        if let Some(&index) = self.index_by_id.get(&node.id) {
            let existing = &mut self.graph[index];
            existing.attrs.extend(node.attrs);
            if existing.code_ref.is_none() {
                existing.code_ref = node.code_ref;
            }
            return index;
        }
        let id = node.id.clone();
        let index = self.graph.add_node(node);
        self.index_by_id.insert(id, index);
        index
    }

    pub fn node(&self, id: &str) -> Option<&SystemNode> {
        self.index_by_id.get(id).map(|&index| &self.graph[index])
    }

    pub fn contains(&self, id: &str) -> bool {
        self.index_by_id.contains_key(id)
    }

    pub fn add_edge(&mut self, from_id: &str, to_id: &str, edge: SystemEdge) -> Result<()> {
        let Some(&from) = self.index_by_id.get(from_id) else {
            bail!("system graph edge references unknown node id {from_id:?}");
        };
        let Some(&to) = self.index_by_id.get(to_id) else {
            bail!("system graph edge references unknown node id {to_id:?}");
        };
        self.graph.add_edge(from, to, edge);
        Ok(())
    }

    /// Applies a normalized [`BoundarySummary`]: inserts (or reuses) the
    /// edge it describes. Both `producer`/`consumer` must already exist
    /// (adapters insert nodes via [`SystemGraph::upsert_node`] before
    /// producing a summary that references them).
    pub fn apply_boundary(&mut self, summary: BoundarySummary) -> Result<()> {
        let Some(kind) = summary.kind else {
            bail!("boundary summary for {:?} -> {:?} has no edge kind", summary.producer, summary.consumer);
        };
        let mut edge = SystemEdge::new(kind, summary.confidence);
        edge.evidence = summary.evidence;
        edge.value_mappings = summary.value_mappings;
        self.add_edge(&summary.producer, &summary.consumer, edge)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &SystemNode> {
        self.graph.node_weights()
    }

    pub fn edges(&self) -> impl Iterator<Item = (&SystemNode, &SystemNode, &SystemEdge)> {
        self.graph.edge_indices().map(move |edge_index| {
            let (from, to) = self.graph.edge_endpoints(edge_index).expect("edge index is valid");
            (&self.graph[from], &self.graph[to], &self.graph[edge_index])
        })
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// A JSON shape suitable for `--system-graph-out`: `{"nodes": [...],
    /// "edges": [{"from", "to", "kind", "confidence", "evidence",
    /// "value_mappings"}]}`.
    pub fn to_json(&self) -> serde_json::Value {
        let nodes: Vec<_> = self.nodes().map(|node| serde_json::to_value(node).unwrap()).collect();
        let edges: Vec<_> = self
            .edges()
            .map(|(from, to, edge)| {
                serde_json::json!({
                    "from": from.id,
                    "to": to.id,
                    "kind": edge.kind,
                    "confidence": edge.confidence,
                    "evidence": edge.evidence,
                    "value_mappings": edge.value_mappings,
                })
            })
            .collect();
        serde_json::json!({ "nodes": nodes, "edges": edges })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_merges_attrs_instead_of_duplicating_nodes() {
        let mut graph = SystemGraph::new();
        graph.upsert_node(SystemNode::new(NodeKind::DockerService, "svc:api", "api").with_attr("image", "api:latest"));
        graph.upsert_node(SystemNode::new(NodeKind::DockerService, "svc:api", "api").with_attr("port", "8080"));
        assert_eq!(graph.node_count(), 1);
        let node = graph.node("svc:api").unwrap();
        assert_eq!(node.attrs.get("image").map(String::as_str), Some("api:latest"));
        assert_eq!(node.attrs.get("port").map(String::as_str), Some("8080"));
    }

    #[test]
    fn add_edge_rejects_unknown_endpoints() {
        let mut graph = SystemGraph::new();
        graph.upsert_node(SystemNode::new(NodeKind::DockerService, "svc:api", "api"));
        let error = graph
            .add_edge("svc:api", "svc:missing", SystemEdge::new(EdgeKind::StartupDependsOn, Confidence::Exact))
            .unwrap_err();
        assert!(error.to_string().contains("svc:missing"));
    }

    #[test]
    fn topology_edges_never_carry_data_flow() {
        assert!(!EdgeKind::StartupDependsOn.carries_data_flow());
        assert!(!EdgeKind::Selects.carries_data_flow());
        assert!(!EdgeKind::Deploys.carries_data_flow());
        assert!(!EdgeKind::Exposes.carries_data_flow());
        assert!(EdgeKind::HttpCall.carries_data_flow());
        assert!(EdgeKind::DataFlow.carries_data_flow());
    }
}
