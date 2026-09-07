use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use std::collections::HashMap;
use uniflow_hir::{
    BinaryOp, Block, BlockId, CallExpr, CallTarget, CatchClause, CollectionKind, CppValueSemantics,
    Expr, ExprId, FileId, FunctionId, Import, Item, Language, LiteralKind, Module, ModuleId,
    Program, SourceFile, Span, StmtId, Symbol, SymbolId, SymbolKind, Type, TypeId, TypeKind,
};
include!("parser.rs");
include!("text.rs");
include!("builder.rs");
include!("expressions.rs");
include!("lexer.rs");
include!("cursor.rs");
include!("stmt_parser.rs");
include!("for_parser.rs");
include!("expr_parser.rs");
include!("descriptor.rs");
#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod lexer_tests;
