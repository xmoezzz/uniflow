use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use uniflow_hir::{
    BinaryOp, Block, CatchClause, Class, Expr, Field, Item, LValue, Language, Param, ParamKind,
    Stmt, SymbolId, SymbolKind, UnaryOp,
};
use uniflow_parser_core::{
    default_span, ensure_known_symbol, find_matching_brace, is_int_literal, is_string_literal,
    matching_delimiter, module_name_from_path, new_call, new_dynamic_call, new_field_read, new_int,
    new_string, new_var_ref, parse_call_parts, split_last_top_level_dot, split_once_top_level,
    split_top_level_commas, split_top_level_statements_c_like, strip_c_like_comments,
    ModuleBuilder, SourceParser,
};

include!("preprocessor.rs");
include!("entry.rs");
include!("environment.rs");
include!("expressions.rs");
include!("tests.rs");
