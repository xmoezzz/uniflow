//! System-wide semantic boundary recovery for UniFlow.
//!
//! UniFlow's existing engine (`uniflow_ir`/`uniflow_value_flow`/`uniflow_taint`)
//! reasons about data flow *within* one language's `Program`/`FlowGraph`.
//! Modern systems have semantic edges that never appear in any single
//! language's CFG/CG/DFG at all: a JavaScript call into a native addon, an
//! HTTP client call whose literal target resolves — through a Docker Compose
//! environment variable — to another service's route handler, a Kubernetes
//! Ingress routing to a Service that selects a Deployment, a message
//! published to a topic another process consumes. This crate recovers those
//! edges ("Semantic Boundary Recovery") into one unified [`graph::SystemGraph`]
//! and, where a recovered edge actually carries a value across the boundary,
//! bridges it into a synthetic per-language taint rule so UniFlow's existing
//! propagation engine follows the flow across the boundary — without ever
//! conflating deployment/topology edges (e.g. `depends_on`) with data flow.
//!
//! # Architecture
//!
//! ```text
//! Language/Code Analysis (existing HIR/IR per group)
//!          |
//!          v
//! Boundary Discovery  <-- adapters: docker_compose, kubernetes, config,
//!          |               http, lifecycle (each independent, see below)
//!          v
//! Mechanism-Specific Resolver (per adapter: normalizes its own facts)
//!          |
//!          v
//! Normalized Boundary Facts (BoundarySummary, see `graph`)
//!          |
//!          v
//! Unified System Graph (`SystemGraph`)
//!          |
//!          v
//! bridge: synthetic per-language RuleSet entries
//!          |
//!          v
//! Existing UniFlow data-flow analysis (unchanged)
//! ```
//!
//! Adapters are independent modules that each produce [`graph::BoundarySummary`]
//! values; none of them talk to each other or to the propagation engine
//! directly, so a future adapter (Terraform, Helm, gRPC, Kafka, an
//! additional FFI mechanism, ...) only needs to implement the same
//! producer/consumer/evidence/confidence contract — see each module's own
//! doc comment for its specific scope.
//!
//! # Modules
//!
//! - [`graph`]: the node/edge taxonomy, [`graph::SystemGraph`], and
//!   [`graph::BoundarySummary`] — the central, mechanism-agnostic model.
//! - [`docker_compose`]: parses `docker-compose.yml`/`compose.yml` (and the
//!   corresponding `.yaml`), recovering services, `depends_on`, environment,
//!   ports, and networks.
//! - [`kubernetes`]: parses (possibly multi-document) Kubernetes manifests,
//!   recovering Deployment/StatefulSet/DaemonSet/Job/CronJob workloads,
//!   Services, Ingresses, and ConfigMap/Secret references.
//! - [`config`]: connects `getenv`-style reads found in each language's own
//!   IR to environment values recovered by the deployment adapters above.
//! - [`http`]: recognizes simple, statically-evident outbound HTTP calls and
//!   inbound route registrations, and stitches a caller's call to a
//!   matching service's route using the resolved deployment topology.
//! - [`message`]: recognizes statically-evident Kafka/RabbitMQ/AMQP-style
//!   publication and consumer registration, and stitches a producer payload
//!   to the receiving handler's payload parameter by literal topic.
//! - [`lifecycle`]: represents framework/runtime-triggered entrypoints
//!   (handlers, startup/shutdown hooks, scheduled jobs) that have no
//!   ordinary source-level caller.
//! - [`bridge`]: turns a data-flow-carrying [`graph::SystemEdge`] whose
//!   endpoints both have a [`graph::CodeRef`] into a synthetic per-language
//!   `uniflow_rules::RuleSet` addition — the same "probe/summary, inject a
//!   synthetic rule" pattern used for `uniflow-jni-bridge`.

pub mod bridge;
pub mod compose;
pub mod config;
pub mod csharp_ffi;
pub mod database;
pub mod discovery;
pub mod docker_compose;
pub mod go_ffi;
pub mod graph;
pub mod grpc;
pub mod http;
mod ir_utils;
pub mod js_ffi;
pub mod kubernetes;
pub mod lifecycle;
pub mod message;
pub mod php_ffi;
pub mod python_ffi;
pub mod rust_ffi;
pub mod ruby_ffi;

pub use graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, Evidence, FlowNodeRef, NodeKind,
    SystemEdge, SystemGraph, SystemNode, ValueMappingKind,
};
pub use ir_utils::FunctionIndex;
