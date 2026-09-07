use anyhow::Result;
use std::sync::OnceLock;
use uniflow_hir::Language;
use uniflow_rules::{
    language_matches, ApiMatcher, FlowSpec, Port, PropagatorRule, RuleSet, SanitizerRule, SinkRule,
    SourceRule, SummaryRule,
};

include!("api.rs");
include!("mit.rs");
include!("legacy.rs");
include!("java.rs");
include!("python.rs");
include!("c_like.rs");
include!("portable.rs");
include!("tests.rs");
