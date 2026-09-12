use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;
use uniflow_hir::{
    BinaryOp, Block, CallExpr, CallTarget, Class, Expr, Field, Item, LValue, LambdaCapture,
    Language, Param, ParamKind, Program, Stmt, SymbolId, SymbolKind, UnaryOp,
};
use uniflow_parser_core::{
    default_span, ensure_known_symbol, find_matching_brace, find_substring_span, is_int_literal,
    is_probable_type_name, is_string_literal, matching_delimiter, module_name_from_path, new_call,
    new_field_read, new_int, new_string, new_var_ref, parse_call_parts, span_from_offsets,
    split_last_top_level_dot, split_once_top_level, split_top_level_commas, strip_c_like_comments,
    ModuleBuilder, SourceParser,
};
include!("project_index.rs");
include!("resolver.rs");
include!("declarations.rs");
include!("statements.rs");
include!("expressions.rs");
include!("expression_shapes.rs");
include!("tests.rs");
