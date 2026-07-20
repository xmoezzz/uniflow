use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use uniflow_hir::{
    Block, CallTarget, Class, Expr, Field, Item, LValue, Language, Param, ParamKind, Program, Stmt,
    SymbolId, SymbolKind,
};
use uniflow_parser_core::{
    default_span, ensure_known_symbol, find_matching_brace, find_substring_span, is_int_literal,
    is_probable_type_name, is_string_literal, module_name_from_path, new_call, new_field_read,
    new_int, new_string, new_var_ref, parse_call_parts, span_from_offsets,
    split_last_top_level_dot, split_once_top_level, split_top_level_commas,
    split_top_level_statements_c_like_with_offsets, strip_c_like_comments, ModuleBuilder,
    SourceParser,
};
include!("project_index.rs");
include!("resolver.rs");
include!("declarations.rs");
include!("statements.rs");
include!("expressions.rs");
include!("tests.rs");
