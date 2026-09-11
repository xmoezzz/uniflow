use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use uniflow_hir::{Language, SourceOriginKind, Span};
use uniflow_ir::{
    BlockId, CallInst, Callee, Function, FunctionId, InstId, InstKind, Instruction, LifetimeEvent,
    Program, Terminator, ValueId,
};
use uniflow_rules::{
    expand_port, language_matches, ApiMatcherIndex, CallInfo, FlowSpec, Port, RuleSet,
};

include!("types.rs");
include!("aliasing.rs");
include!("lifetime.rs");
include!("nullness.rs");
include!("integer_range.rs");
include!("case_break.rs");
include!("build.rs");
include!("query.rs");
include!("heap.rs");
include!("solver.rs");
include!("calls.rs");
include!("tests.rs");
