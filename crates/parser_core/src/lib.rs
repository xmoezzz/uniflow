use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use regex::Regex;
use std::collections::HashMap;
use uniflow_hir::{
    BinaryOp, Block, BlockId, CallExpr, CallTarget, CatchClause, Expr, ExprId, FileId, Function,
    FunctionId, Import, Item, Language, LiteralKind, Module, ModuleId, Param, Program, SourceFile,
    Span, StmtId, Symbol, SymbolId, SymbolKind, Type, TypeId, TypeKind,
};

pub trait SourceParser {
    fn language(&self) -> Language;
    fn parse_file(&self, path: &str, source: &str) -> Result<Program>;
}

pub fn default_span() -> Span {
    Span::default()
}

pub fn line_col_for_offset(source: &str, offset: usize) -> (u32, u32) {
    let capped = offset.min(source.len());
    let mut line = 1u32;
    let mut col = 1u32;
    for ch in source[..capped].chars() {
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

pub fn span_from_offsets(file: FileId, source: &str, start: usize, end: usize) -> Span {
    let start = start.min(source.len());
    let end = end.min(source.len()).max(start);
    let (start_line, start_col) = line_col_for_offset(source, start);
    let (end_line, end_col) = line_col_for_offset(source, end);
    Span {
        file: file.0,
        start_byte: start as u32,
        end_byte: end as u32,
        start_line,
        start_col,
        end_line,
        end_col,
    }
}

pub fn span_from_line_range(file: FileId, start_line: u32, end_line: u32) -> Span {
    Span {
        file: file.0,
        start_byte: 0,
        end_byte: 0,
        start_line,
        start_col: 1,
        end_line,
        end_col: 1,
    }
}

pub fn find_substring_span(file: FileId, source: &str, needle: &str, search_from: usize) -> Span {
    if needle.trim().is_empty() {
        return default_span();
    }
    if let Some(rel) = source[search_from.min(source.len())..].find(needle) {
        let start = search_from.min(source.len()) + rel;
        let end = start + needle.len();
        return span_from_offsets(file, source, start, end);
    }
    if let Some(start) = source.find(needle) {
        let end = start + needle.len();
        return span_from_offsets(file, source, start, end);
    }
    default_span()
}

pub fn module_name_from_path(path: &str) -> String {
    let last = path.rsplit('/').next().unwrap_or(path);
    let without_ext = last.split('.').next().unwrap_or(last);
    if without_ext.is_empty() {
        "main".to_string()
    } else {
        without_ext.to_string()
    }
}

pub fn strip_c_like_comments(source: &str) -> String {
    let line_re = Regex::new(r"//.*").expect("valid regex");
    let block_re = Regex::new(r"(?s)/\*.*?\*/").expect("valid regex");
    let without_blocks = block_re.replace_all(source, "");
    line_re.replace_all(&without_blocks, "").into_owned()
}

pub fn split_top_level_commas(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;

    for ch in input.chars() {
        if in_string {
            cur.push(ch);
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
                cur.push(ch);
            }
            '(' => {
                paren += 1;
                cur.push(ch);
            }
            ')' => {
                paren = paren.saturating_sub(1);
                cur.push(ch);
            }
            '[' => {
                bracket += 1;
                cur.push(ch);
            }
            ']' => {
                bracket = bracket.saturating_sub(1);
                cur.push(ch);
            }
            '{' => {
                brace += 1;
                cur.push(ch);
            }
            '}' => {
                brace = brace.saturating_sub(1);
                cur.push(ch);
            }
            ',' if paren == 0 && bracket == 0 && brace == 0 => {
                let piece = cur.trim();
                if !piece.is_empty() {
                    out.push(piece.to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }

    let tail = cur.trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

pub fn split_top_level_statements_c_like(body: &str) -> Vec<String> {
    split_top_level_statements_c_like_with_offsets(body)
        .into_iter()
        .map(|(_, _, stmt)| stmt)
        .collect()
}

pub fn split_top_level_statements_c_like_with_offsets(body: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut paren = 0usize;
    let mut brace = 0usize;
    let mut bracket = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;
    let mut stmt_start = 0usize;

    for (idx, ch) in body.char_indices() {
        if in_string {
            cur.push(ch);
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
                cur.push(ch);
            }
            '(' => {
                paren += 1;
                cur.push(ch);
            }
            ')' => {
                paren = paren.saturating_sub(1);
                cur.push(ch);
            }
            '[' => {
                bracket += 1;
                cur.push(ch);
            }
            ']' => {
                bracket = bracket.saturating_sub(1);
                cur.push(ch);
            }
            '{' => {
                brace += 1;
                cur.push(ch);
            }
            '}' => {
                brace = brace.saturating_sub(1);
                cur.push(ch);
            }
            ';' if paren == 0 && brace == 0 && bracket == 0 => {
                let piece = cur.trim();
                if !piece.is_empty() {
                    let trim_prefix = cur.find(piece).unwrap_or(0);
                    let start = stmt_start + trim_prefix;
                    let end = start + piece.len();
                    out.push((start, end, piece.to_string()));
                }
                cur.clear();
                stmt_start = idx + ch.len_utf8();
            }
            _ => cur.push(ch),
        }
    }

    let piece = cur.trim();
    if !piece.is_empty() {
        let trim_prefix = cur.find(piece).unwrap_or(0);
        let start = stmt_start + trim_prefix;
        let end = start + piece.len();
        out.push((start, end, piece.to_string()));
    }
    out
}

pub fn find_matching_brace(source: &str, open_idx: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open_idx).copied() != Some(b'{') {
        return None;
    }

    let mut depth = 0usize;
    let mut in_string = false;
    let mut quote = b'\0';
    let mut escape = false;

    for (idx, b) in bytes.iter().copied().enumerate().skip(open_idx) {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if b == b'\\' {
                escape = true;
                continue;
            }
            if b == quote {
                in_string = false;
            }
            continue;
        }

        if b == b'"' || b == b'\'' {
            in_string = true;
            quote = b;
            continue;
        }

        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
    }

    None
}

pub fn split_once_top_level(input: &str, target: char) -> Option<(String, String)> {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;

    for (idx, ch) in input.char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
            }
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            _ if ch == target && paren == 0 && bracket == 0 && brace == 0 => {
                let left = input[..idx].trim().to_string();
                let right = input[idx + ch.len_utf8()..].trim().to_string();
                return Some((left, right));
            }
            _ => {}
        }
    }

    None
}

pub fn split_last_top_level_dot(input: &str) -> Option<(String, String)> {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;
    let mut last = None;

    for (idx, ch) in input.char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
            }
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            '.' if paren == 0 && bracket == 0 && brace == 0 => last = Some(idx),
            _ => {}
        }
    }

    last.map(|idx| {
        (
            input[..idx].trim().to_string(),
            input[idx + 1..].trim().to_string(),
        )
    })
}

pub fn is_string_literal(text: &str) -> bool {
    let trimmed = text.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
}

pub fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    if is_string_literal(trimmed) && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn is_int_literal(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit())
}

pub fn is_identifier_like(text: &str) -> bool {
    let trimmed = text.trim();
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

pub fn is_probable_type_name(text: &str) -> bool {
    let first = text.trim().chars().next();
    matches!(first, Some(ch) if ch.is_ascii_uppercase())
}

pub struct ModuleBuilder {
    language: Language,
    file: SourceFile,
    module: Module,
    symbols: Vec<Symbol>,
    types: Vec<Type>,
    next_function_id: u32,
    next_block_id: u32,
    next_stmt_id: u32,
    next_expr_id: u32,
    next_symbol_id: u32,
    next_type_id: u32,
}

impl ModuleBuilder {
    pub fn new(language: Language, path: &str, module_name: &str) -> Self {
        let file = SourceFile {
            id: FileId(0),
            path: path.to_string(),
        };
        let module = Module {
            id: ModuleId(0),
            file: file.id,
            name: module_name.to_string(),
            imports: Vec::new(),
            items: Vec::new(),
            span: default_span(),
        };
        Self {
            language,
            file,
            module,
            symbols: Vec::new(),
            types: Vec::new(),
            next_function_id: 0,
            next_block_id: 0,
            next_stmt_id: 0,
            next_expr_id: 0,
            next_symbol_id: 0,
            next_type_id: 0,
        }
    }

    pub fn add_import(&mut self, path: &str, alias: Option<String>) {
        self.module.imports.push(Import {
            path: path.to_string(),
            alias,
            span: default_span(),
        });
    }

    pub fn file_id(&self) -> FileId {
        self.file.id
    }

    pub fn alloc_function_id(&mut self) -> FunctionId {
        let id = FunctionId(self.next_function_id);
        self.next_function_id += 1;
        id
    }

    pub fn alloc_block_id(&mut self) -> BlockId {
        let id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        id
    }

    pub fn alloc_stmt_id(&mut self) -> StmtId {
        let id = StmtId(self.next_stmt_id);
        self.next_stmt_id += 1;
        id
    }

    pub fn alloc_expr_id(&mut self) -> ExprId {
        let id = ExprId(self.next_expr_id);
        self.next_expr_id += 1;
        id
    }

    pub fn add_symbol(&mut self, name: &str, kind: SymbolKind) -> SymbolId {
        let id = SymbolId(self.next_symbol_id);
        self.next_symbol_id += 1;
        self.symbols.push(Symbol {
            id,
            name: name.to_string(),
            kind,
            declared_in: Some(self.module.id),
            span: default_span(),
            attributes: IndexMap::new(),
        });
        id
    }

    pub fn ensure_type(&mut self, name: &str) -> TypeId {
        if let Some(existing) = self.types.iter().find(|t| t.name == name) {
            return existing.id;
        }
        let id = TypeId(self.next_type_id);
        self.next_type_id += 1;
        self.types.push(Type {
            id,
            name: name.to_string(),
            kind: classify_type_kind(name),
        });
        id
    }

    pub fn empty_block(&mut self) -> Block {
        Block {
            id: self.alloc_block_id(),
            stmts: Vec::new(),
            span: default_span(),
        }
    }

    pub fn push_item(&mut self, item: Item) {
        self.module.items.push(item);
    }

    pub fn find_type_name(&self, id: TypeId) -> Option<&str> {
        self.types
            .iter()
            .find(|ty| ty.id == id)
            .map(|ty| ty.name.as_str())
    }

    pub fn finish(self) -> Program {
        Program {
            language: self.language,
            files: vec![self.file],
            modules: vec![self.module],
            symbols: self.symbols,
            types: self.types,
        }
    }
}

fn classify_type_kind(name: &str) -> TypeKind {
    match name {
        "void" | "bool" | "boolean" | "int" | "i32" | "i64" | "String" | "str" | "float"
        | "double" | "char" => TypeKind::Primitive,
        _ => TypeKind::Named,
    }
}

pub fn parse_call_parts(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    let open = trimmed.find('(')?;
    if !trimmed.ends_with(')') {
        return None;
    }
    let callee = trimmed[..open].trim().to_string();
    let args = trimmed[open + 1..trimmed.len() - 1].trim().to_string();
    Some((callee, args))
}

pub fn new_var_ref(builder: &mut ModuleBuilder, symbol: SymbolId) -> Expr {
    Expr::VarRef {
        id: builder.alloc_expr_id(),
        symbol,
        span: default_span(),
    }
}

pub fn new_string(builder: &mut ModuleBuilder, value: &str) -> Expr {
    Expr::Literal {
        id: builder.alloc_expr_id(),
        kind: LiteralKind::String(value.to_string()),
        span: default_span(),
    }
}

pub fn new_int(builder: &mut ModuleBuilder, value: i64) -> Expr {
    Expr::Literal {
        id: builder.alloc_expr_id(),
        kind: LiteralKind::Int(value),
        span: default_span(),
    }
}

pub fn new_call(
    builder: &mut ModuleBuilder,
    target_name: &str,
    receiver: Option<Expr>,
    args: Vec<Expr>,
) -> Expr {
    new_call_with_arg_names(builder, target_name, receiver, args, Vec::new())
}

pub fn new_call_with_arg_names(
    builder: &mut ModuleBuilder,
    target_name: &str,
    receiver: Option<Expr>,
    args: Vec<Expr>,
    arg_names: Vec<Option<String>>,
) -> Expr {
    Expr::Call(CallExpr {
        id: builder.alloc_expr_id(),
        target: CallTarget::Named(target_name.to_string()),
        receiver: receiver.map(Box::new),
        args,
        arg_names,
        span: default_span(),
    })
}

pub fn new_dynamic_call(
    builder: &mut ModuleBuilder,
    callee: Expr,
    receiver: Option<Expr>,
    args: Vec<Expr>,
) -> Expr {
    new_dynamic_call_with_arg_names(builder, callee, receiver, args, Vec::new())
}

pub fn new_dynamic_call_with_arg_names(
    builder: &mut ModuleBuilder,
    callee: Expr,
    receiver: Option<Expr>,
    args: Vec<Expr>,
    arg_names: Vec<Option<String>>,
) -> Expr {
    Expr::Call(CallExpr {
        id: builder.alloc_expr_id(),
        target: CallTarget::Dynamic(Box::new(callee)),
        receiver: receiver.map(Box::new),
        args,
        arg_names,
        span: default_span(),
    })
}

pub fn new_field_read(builder: &mut ModuleBuilder, base: Expr, field: &str) -> Expr {
    Expr::FieldRead {
        id: builder.alloc_expr_id(),
        base: Box::new(base),
        field: field.to_string(),
        span: default_span(),
    }
}

pub fn new_binary(builder: &mut ModuleBuilder, lhs: Expr, rhs: Expr, op: BinaryOp) -> Expr {
    Expr::Binary {
        id: builder.alloc_expr_id(),
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        span: default_span(),
    }
}

pub fn ensure_known_symbol(
    builder: &mut ModuleBuilder,
    env: &mut HashMap<String, SymbolId>,
    name: &str,
    kind: SymbolKind,
) -> SymbolId {
    if let Some(existing) = env.get(name).copied() {
        existing
    } else {
        let id = builder.add_symbol(name, kind);
        env.insert(name.to_string(), id);
        id
    }
}

pub fn empty_try_catch(builder: &mut ModuleBuilder) -> CatchClause {
    CatchClause {
        symbol: None,
        ty: None,
        body: builder.empty_block(),
        span: default_span(),
    }
}

pub fn unsupported<T>(msg: &str) -> Result<T> {
    Err(anyhow!(msg.to_string()))
}
