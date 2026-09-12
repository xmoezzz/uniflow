use anyhow::Result;
use regex::Regex;
use rayon::prelude::*;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use uniflow_hir::{
    BinaryOp, Block, CallTarget, CatchClause, Class, Expr, ExprId, Field, Item, LValue,
    LambdaCapture, Language, Param, ParamKind, Program, Span, Stmt, SymbolId, SymbolKind, UnaryOp,
};
use uniflow_parser_core::{
    default_span, ensure_known_symbol, is_int_literal, is_string_literal, module_name_from_path,
    new_call, new_call_with_arg_names, new_dynamic_call_with_arg_names, new_field_read, new_int,
    new_string, new_var_ref, parse_call_parts, span_from_line_range, split_last_top_level_dot,
    split_once_top_level, split_top_level_commas, ModuleBuilder, SourceParser,
};
include!("project_index.rs");

// Python projects frequently contain generated, deeply nested type and
// decorator expressions. Project-index and module-parser workers must match
// the CLI analysis thread's stack budget; worker threads otherwise silently
// fall back to the platform default and can abort the entire scan.
const PYTHON_ANALYSIS_STACK_SIZE: usize = 1 << 30;

include!("entry.rs");
include!("syntax.rs");
include!("type_inference.rs");
include!("type_declarations.rs");
include!("summaries.rs");
include!("declarations.rs");
include!("control_flow.rs");
include!("environment_effects.rs");
include!("call_effects.rs");
include!("containers.rs");
include!("expressions.rs");
include!("tests.rs");
