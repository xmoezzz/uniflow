use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
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

/// Interior-mutable query cache. It mirrors the `RefCell` borrow API the
/// engine was written against but is `Sync`, so a finished `FlowGraph` can
/// serve read-only demand queries from several threads (taint slicing runs
/// them in parallel). A poisoned lock only means another query panicked
/// mid-insert into a memo table; the table is still a valid cache.
#[derive(Default)]
pub struct QueryCell<T>(std::sync::RwLock<T>);

impl<T> QueryCell<T> {
    pub fn new(value: T) -> Self {
        Self(std::sync::RwLock::new(value))
    }

    pub fn borrow(&self) -> std::sync::RwLockReadGuard<'_, T> {
        self.0.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn borrow_mut(&self) -> std::sync::RwLockWriteGuard<'_, T> {
        self.0.write().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl<T: Clone> Clone for QueryCell<T> {
    fn clone(&self) -> Self {
        Self::new(self.borrow().clone())
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for QueryCell<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.borrow().fmt(f)
    }
}

include!("types.rs");
include!("aliasing.rs");
include!("lifetime.rs");
include!("nullness.rs");
include!("integer_range.rs");
include!("case_break.rs");
include!("build.rs");
include!("query.rs");
include!("heap.rs");
include!("java_collections.rs");
include!("solver.rs");
include!("calls.rs");
include!("tests.rs");
