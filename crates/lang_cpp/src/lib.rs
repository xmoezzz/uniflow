mod semantics;
use anyhow::Result;
use regex::Regex;
use uniflow_hir::{CallTarget, Expr, Item, LValue, Language, Stmt};
use uniflow_lang_c::parse_c_like_file;
use uniflow_parser_core::SourceParser;

#[derive(Default)]
pub struct CppParser;

impl SourceParser for CppParser {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn parse_file(&self, path: &str, source: &str) -> Result<uniflow_hir::Program> {
        let class_metadata = collect_cpp_class_metadata(source);
        let semantic_index = semantics::collect(source);
        let normalized = normalize_cpp_for_hir(source);
        let mut program = parse_c_like_file(Language::Cpp, path, &normalized)?;
        if let Some(file) = program.files.first() {
            program
                .source_maps
                .push(build_cpp_source_map(file.id, source, &normalized));
        }
        restore_cpp_class_semantics(&mut program, &class_metadata);
        restore_cpp_lambda_semantics(&mut program);
        attach_cpp_semantics(&mut program, &semantic_index);
        Ok(program)
    }
}

/// The surface normalizer represents a capturing C++ lambda with a bind
/// intrinsic plus a synthetic function. Recover which leading synthetic
/// parameters are captures so the shared lowering/value-flow engine can bind
/// closure fields to formal capture parameters just like native HIR lambdas.
fn restore_cpp_lambda_semantics(program: &mut uniflow_hir::Program) {
    let symbol_names = program
        .symbols
        .iter()
        .map(|symbol| (symbol.id, symbol.name.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let mut capture_counts = std::collections::HashMap::<String, usize>::new();
    for module in &program.modules {
        for item in &module.items {
            match item {
                Item::Function(function) => collect_cpp_lambda_binds_block(
                    &function.body,
                    &symbol_names,
                    &mut capture_counts,
                ),
                Item::Class(class) => {
                    for method in &class.methods {
                        collect_cpp_lambda_binds_block(
                            &method.body,
                            &symbol_names,
                            &mut capture_counts,
                        );
                    }
                }
                Item::GlobalVar(global) => {
                    if let Some(init) = &global.init {
                        collect_cpp_lambda_binds_expr(init, &symbol_names, &mut capture_counts);
                    }
                }
            }
        }
    }
    for module in &mut program.modules {
        for item in &mut module.items {
            let Item::Function(function) = item else {
                continue;
            };
            let Some(count) = capture_counts.get(&function.name).copied() else {
                continue;
            };
            let count = count.min(function.params.len());
            let explicit = function.params.split_off(count);
            function.captures = std::mem::take(&mut function.params);
            function.params = explicit;
        }
    }
}

fn collect_cpp_lambda_binds_block(
    block: &uniflow_hir::Block,
    symbol_names: &std::collections::HashMap<uniflow_hir::SymbolId, String>,
    out: &mut std::collections::HashMap<String, usize>,
) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Let { init, .. } => {
                if let Some(expr) = init {
                    collect_cpp_lambda_binds_expr(expr, symbol_names, out);
                }
            }
            Stmt::Assign { lhs, rhs, .. } => {
                collect_cpp_lambda_binds_lvalue(lhs, symbol_names, out);
                collect_cpp_lambda_binds_expr(rhs, symbol_names, out);
            }
            Stmt::Expr { expr, .. } => collect_cpp_lambda_binds_expr(expr, symbol_names, out),
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                collect_cpp_lambda_binds_expr(cond, symbol_names, out);
                collect_cpp_lambda_binds_block(then_block, symbol_names, out);
                if let Some(block) = else_block {
                    collect_cpp_lambda_binds_block(block, symbol_names, out);
                }
            }
            Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
                collect_cpp_lambda_binds_expr(cond, symbol_names, out);
                collect_cpp_lambda_binds_block(body, symbol_names, out);
            }
            Stmt::ForEach { iterable, body, .. } => {
                collect_cpp_lambda_binds_expr(iterable, symbol_names, out);
                collect_cpp_lambda_binds_block(body, symbol_names, out);
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
                ..
            } => {
                collect_cpp_lambda_binds_block(init, symbol_names, out);
                if let Some(cond) = cond {
                    collect_cpp_lambda_binds_expr(cond, symbol_names, out);
                }
                collect_cpp_lambda_binds_block(update, symbol_names, out);
                collect_cpp_lambda_binds_block(body, symbol_names, out);
            }
            Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
                if let Some(expr) = value {
                    collect_cpp_lambda_binds_expr(expr, symbol_names, out);
                }
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                collect_cpp_lambda_binds_block(try_block, symbol_names, out);
                for catch in catches {
                    collect_cpp_lambda_binds_block(&catch.body, symbol_names, out);
                }
                if let Some(block) = finally_block {
                    collect_cpp_lambda_binds_block(block, symbol_names, out);
                }
            }
            Stmt::Switch {
                scrutinee,
                clauses,
                default,
                ..
            } => {
                collect_cpp_lambda_binds_expr(scrutinee, symbol_names, out);
                for clause in clauses {
                    for value in &clause.values {
                        collect_cpp_lambda_binds_expr(value, symbol_names, out);
                    }
                    collect_cpp_lambda_binds_block(&clause.body, symbol_names, out);
                }
                if let Some(block) = default {
                    collect_cpp_lambda_binds_block(block, symbol_names, out);
                }
            }
            Stmt::Break { .. } | Stmt::Continue { .. } => {}
        }
    }
}

fn collect_cpp_lambda_binds_lvalue(
    lvalue: &LValue,
    symbol_names: &std::collections::HashMap<uniflow_hir::SymbolId, String>,
    out: &mut std::collections::HashMap<String, usize>,
) {
    match lvalue {
        LValue::Var(_) => {}
        LValue::Field { base, .. } => collect_cpp_lambda_binds_expr(base, symbol_names, out),
        LValue::Index { base, index } => {
            collect_cpp_lambda_binds_expr(base, symbol_names, out);
            collect_cpp_lambda_binds_expr(index, symbol_names, out);
        }
    }
}

fn collect_cpp_lambda_binds_expr(
    expr: &Expr,
    symbol_names: &std::collections::HashMap<uniflow_hir::SymbolId, String>,
    out: &mut std::collections::HashMap<String, usize>,
) {
    match expr {
        Expr::Call(call) => {
            if matches!(&call.target, CallTarget::Named(name) if name == "__uniflow_cpp_lambda_bind")
            {
                if let Some(Expr::VarRef { symbol, .. }) = call.args.first() {
                    if let Some(name) = symbol_names.get(symbol) {
                        out.insert(name.clone(), call.args.len().saturating_sub(1));
                    }
                }
            }
            if let CallTarget::Dynamic(callee) = &call.target {
                collect_cpp_lambda_binds_expr(callee, symbol_names, out);
            }
            if let Some(receiver) = &call.receiver {
                collect_cpp_lambda_binds_expr(receiver, symbol_names, out);
            }
            for arg in &call.args {
                collect_cpp_lambda_binds_expr(arg, symbol_names, out);
            }
        }
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => {
            collect_cpp_lambda_binds_expr(expr, symbol_names, out)
        }
        Expr::Binary { lhs, rhs, .. } => {
            collect_cpp_lambda_binds_expr(lhs, symbol_names, out);
            collect_cpp_lambda_binds_expr(rhs, symbol_names, out);
        }
        Expr::FieldRead { base, .. } => collect_cpp_lambda_binds_expr(base, symbol_names, out),
        Expr::IndexRead { base, index, .. } => {
            collect_cpp_lambda_binds_expr(base, symbol_names, out);
            collect_cpp_lambda_binds_expr(index, symbol_names, out);
        }
        Expr::Lambda { body, .. } => collect_cpp_lambda_binds_block(body, symbol_names, out),
        Expr::New { args, .. } => {
            for arg in args {
                collect_cpp_lambda_binds_expr(arg, symbol_names, out);
            }
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            collect_cpp_lambda_binds_expr(cond, symbol_names, out);
            collect_cpp_lambda_binds_expr(then_expr, symbol_names, out);
            collect_cpp_lambda_binds_expr(else_expr, symbol_names, out);
        }
        Expr::Assign { lhs, rhs, .. } => {
            collect_cpp_lambda_binds_lvalue(lhs, symbol_names, out);
            collect_cpp_lambda_binds_expr(rhs, symbol_names, out);
        }
        Expr::Interp { parts, .. }
        | Expr::Collection {
            elements: parts, ..
        } => {
            for part in parts {
                collect_cpp_lambda_binds_expr(part, symbol_names, out);
            }
        }
        Expr::Range { low, high, .. } => {
            collect_cpp_lambda_binds_expr(low, symbol_names, out);
            collect_cpp_lambda_binds_expr(high, symbol_names, out);
        }
        Expr::VarRef { .. } | Expr::Literal { .. } | Expr::Opaque { .. } | Expr::Unknown { .. } => {
        }
    }
}

fn build_cpp_source_map(
    file: uniflow_hir::FileId,
    original: &str,
    normalized: &str,
) -> uniflow_hir::SourceMap {
    use uniflow_hir::{SourceMap, SourceMapSegment};

    fn line_ranges(text: &str) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        let mut start = 0u32;
        for line in text.split_inclusive('\n') {
            let end = start.saturating_add(line.len() as u32);
            out.push((start, end));
            start = end;
        }
        if !text.is_empty()
            && !text.ends_with('\n')
            && out.last().map(|(_, end)| *end) != Some(text.len() as u32)
        {
            out.push((start, text.len() as u32));
        }
        out
    }

    fn common_prefix(left: &[u8], right: &[u8]) -> usize {
        left.iter().zip(right).take_while(|(a, b)| a == b).count()
    }

    fn common_suffix(left: &[u8], right: &[u8], prefix: usize) -> usize {
        let max = left.len().min(right.len()).saturating_sub(prefix);
        (0..max)
            .take_while(|offset| left[left.len() - 1 - offset] == right[right.len() - 1 - offset])
            .count()
    }

    let original_lines = line_ranges(original);
    let normalized_lines = line_ranges(normalized);
    let original_bytes = original.as_bytes();
    let normalized_bytes = normalized.as_bytes();
    let mut segments = Vec::new();

    for (index, &(normalized_start, normalized_end)) in normalized_lines.iter().enumerate() {
        let (original_start, original_end) = original_lines
            .get(index)
            .copied()
            .unwrap_or((original.len() as u32, original.len() as u32));
        let n = &normalized_bytes[normalized_start as usize..normalized_end as usize];
        let o = &original_bytes[original_start as usize..original_end as usize];
        let prefix = common_prefix(n, o) as u32;
        let suffix = common_suffix(n, o, prefix as usize) as u32;

        if prefix > 0 {
            segments.push(SourceMapSegment {
                normalized_start,
                normalized_end: normalized_start + prefix,
                original_start,
                original_end: original_start + prefix,
            });
        }

        let normalized_middle_start = normalized_start + prefix;
        let normalized_middle_end = normalized_end.saturating_sub(suffix);
        let original_middle_start = original_start + prefix;
        let original_middle_end = original_end.saturating_sub(suffix);
        if normalized_middle_end > normalized_middle_start {
            segments.push(SourceMapSegment {
                normalized_start: normalized_middle_start,
                normalized_end: normalized_middle_end,
                original_start: original_middle_start,
                original_end: original_middle_end,
            });
        }

        if suffix > 0 {
            segments.push(SourceMapSegment {
                normalized_start: normalized_end - suffix,
                normalized_end,
                original_start: original_end - suffix,
                original_end,
            });
        }
    }

    let mut original_line_starts = original_lines
        .iter()
        .map(|(start, _)| *start)
        .collect::<Vec<_>>();
    if original_line_starts.is_empty() {
        original_line_starts.push(0);
    }

    SourceMap {
        file,
        original_len: original.len() as u32,
        normalized_len: normalized.len() as u32,
        original_line_starts,
        segments,
    }
}

#[derive(Clone, Debug, Default)]
struct CppClassMetadata {
    bases: Vec<String>,
}

fn collect_cpp_class_metadata(source: &str) -> std::collections::HashMap<String, CppClassMetadata> {
    let re =
        Regex::new(r"(?m)\b(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([^\{]+))?\s*\{")
            .expect("valid regex");
    re.captures_iter(source)
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str().to_string();
            let bases = caps
                .get(2)
                .map(|m| {
                    m.as_str()
                        .split(',')
                        .map(|base| {
                            base.split_whitespace()
                                .filter(|part| {
                                    !matches!(*part, "public" | "protected" | "private" | "virtual")
                                })
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .filter(|base| !base.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Some((name, CppClassMetadata { bases }))
        })
        .collect()
}

fn restore_cpp_class_semantics(
    program: &mut uniflow_hir::Program,
    metadata: &std::collections::HashMap<String, CppClassMetadata>,
) {
    use uniflow_hir::{
        CppOwnershipKind, CppReferenceKind, CppValueSemantics, Param, ParamKind, Symbol, SymbolId,
        SymbolKind, Type, TypeId, TypeKind,
    };

    let class_names = program
        .modules
        .iter()
        .flat_map(|module| module.items.iter())
        .filter_map(|item| match item {
            Item::Class(class) => Some(class.name.clone()),
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();
    let mut next_symbol = program
        .symbols
        .iter()
        .map(|symbol| symbol.id.0)
        .max()
        .map_or(0, |id| id + 1);
    let mut next_type = program
        .types
        .iter()
        .map(|ty| ty.id.0)
        .max()
        .map_or(0, |id| id + 1);
    let mut class_types = program
        .types
        .iter()
        .map(|ty| (ty.name.clone(), ty.id))
        .collect::<std::collections::HashMap<_, _>>();
    for class in &class_names {
        class_types.entry(class.clone()).or_insert_with(|| {
            let id = TypeId(next_type);
            next_type += 1;
            program.types.push(Type {
                id,
                name: class.clone(),
                kind: TypeKind::Named,
                cpp: CppValueSemantics::default(),
            });
            id
        });
    }

    for module in &mut program.modules {
        let mut retained = Vec::new();
        let mut methods = std::collections::HashMap::<String, Vec<uniflow_hir::Function>>::new();
        for item in std::mem::take(&mut module.items) {
            match item {
                Item::Function(mut function) => {
                    let owner = function
                        .name
                        .rsplit_once("::")
                        .map(|(owner, _)| owner.rsplit("::").next().unwrap_or(owner).to_string());
                    if let Some(owner) = owner.filter(|owner| class_names.contains(owner)) {
                        function.is_method = true;
                        if function.receiver.is_none() {
                            let symbol = SymbolId(next_symbol);
                            next_symbol += 1;
                            let cpp = CppValueSemantics {
                                reference_kind: CppReferenceKind::LValue,
                                ownership: CppOwnershipKind::Borrowed,
                                pointee_type: Some(owner.clone()),
                            };
                            program.symbols.push(Symbol {
                                id: symbol,
                                name: format!("{}::this", function.name),
                                kind: SymbolKind::Param,
                                declared_in: Some(module.id),
                                span: function.span,
                                attributes: Default::default(),
                                array_extents: Vec::new(),
                                cpp: Some(uniflow_hir::CppSymbolSemantics {
                                    method: None,
                                    value: cpp.clone(),
                                }),
                            });
                            function.receiver = Some(Param {
                                name: "this".to_string(),
                                symbol,
                                ty: class_types.get(&owner).copied(),
                                kind: ParamKind::Positional,
                                has_default: false,
                                keyword_only: false,
                                cpp,
                                span: function.span,
                            });
                        }
                        methods.entry(owner).or_default().push(function);
                    } else {
                        retained.push(Item::Function(function));
                    }
                }
                other => retained.push(other),
            }
        }

        for item in &mut retained {
            let Item::Class(class) = item else { continue };
            if let Some(meta) = metadata.get(&class.name) {
                class.bases = meta.bases.clone();
            }
            if let Some(discovered) = methods.remove(&class.name) {
                for method in discovered {
                    if let Some(existing) = class
                        .methods
                        .iter_mut()
                        .find(|existing| existing.name == method.name)
                    {
                        *existing = method;
                    } else {
                        class.methods.push(method);
                    }
                }
            }
        }
        // A malformed class declaration should not make recovered method bodies disappear.
        for (_, orphaned) in methods {
            retained.extend(orphaned.into_iter().map(Item::Function));
        }
        module.items = retained;
    }
}

fn attach_cpp_semantics(program: &mut uniflow_hir::Program, index: &semantics::SemanticIndex) {
    use std::collections::HashMap;
    use uniflow_hir::{
        Block, CppMethodSemantics, CppSymbolSemantics, CppValueSemantics, Stmt, SymbolId,
        SymbolKind,
    };

    fn method_for_name(index: &semantics::SemanticIndex, name: &str) -> Option<CppMethodSemantics> {
        let normalized = name.replace('.', "::");
        index.methods.get(&normalized).cloned().or_else(|| {
            let mut matches = index
                .methods
                .iter()
                .filter(|(candidate, _)| normalized.ends_with(candidate.as_str()))
                .map(|(_, value)| value.clone());
            let first = matches.next()?;
            matches.next().is_none().then_some(first)
        })
    }

    fn scoped_values_for_function<'a>(
        index: &'a semantics::SemanticIndex,
        function_name: &str,
        owner: Option<&str>,
        arity: usize,
    ) -> Option<&'a HashMap<String, CppValueSemantics>> {
        let normalized = function_name.replace('.', "::");
        let simple = normalized.rsplit("::").next().unwrap_or(&normalized);
        let qualified = owner.map(|owner| format!("{owner}::{simple}"));
        for key in [
            Some(normalized.as_str()),
            qualified.as_deref(),
            Some(simple),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(values) = index.scoped_values.get(&(key.to_string(), arity)) {
                return Some(values);
            }
        }
        let mut candidates = index
            .scoped_values
            .iter()
            .filter(|((name, candidate_arity), _)| {
                *candidate_arity == arity
                    && (name == simple
                        || name.ends_with(&format!("::{simple}"))
                        || normalized.ends_with(name))
            })
            .map(|(_, values)| values);
        let first = candidates.next()?;
        candidates.next().is_none().then_some(first)
    }

    fn collect_block_symbols(block: &Block, out: &mut Vec<SymbolId>) {
        for stmt in &block.stmts {
            match stmt {
                Stmt::For {
                    init, update, body, ..
                } => {
                    collect_block_symbols(init, out);
                    collect_block_symbols(update, out);
                    collect_block_symbols(body, out);
                }
                Stmt::Let { symbol, .. } => out.push(*symbol),
                Stmt::If {
                    then_block,
                    else_block,
                    ..
                } => {
                    collect_block_symbols(then_block, out);
                    if let Some(block) = else_block {
                        collect_block_symbols(block, out);
                    }
                }
                Stmt::While { body, .. }
                | Stmt::ForEach { body, .. }
                | Stmt::DoWhile { body, .. } => {
                    if let Stmt::ForEach { item_symbol, .. } = stmt {
                        out.push(*item_symbol);
                    }
                    collect_block_symbols(body, out);
                }
                Stmt::Switch {
                    clauses, default, ..
                } => {
                    for clause in clauses {
                        collect_block_symbols(&clause.body, out);
                    }
                    if let Some(block) = default {
                        collect_block_symbols(block, out);
                    }
                }
                Stmt::Try {
                    try_block,
                    catches,
                    finally_block,
                    ..
                } => {
                    collect_block_symbols(try_block, out);
                    for catch in catches {
                        if let Some(symbol) = catch.symbol {
                            out.push(symbol);
                        }
                        collect_block_symbols(&catch.body, out);
                    }
                    if let Some(block) = finally_block {
                        collect_block_symbols(block, out);
                    }
                }
                Stmt::Assign { .. }
                | Stmt::Expr { .. }
                | Stmt::Return { .. }
                | Stmt::Throw { .. }
                | Stmt::Break { .. }
                | Stmt::Continue { .. } => {}
            }
        }
    }

    fn collect_function_bindings(
        function: &uniflow_hir::Function,
        owner: Option<&str>,
        index: &semantics::SemanticIndex,
        symbol_names: &HashMap<SymbolId, String>,
        out: &mut HashMap<SymbolId, CppValueSemantics>,
    ) {
        let Some(scoped) =
            scoped_values_for_function(index, &function.name, owner, function.params.len())
        else {
            return;
        };
        let mut symbols = function
            .params
            .iter()
            .chain(function.captures.iter())
            .map(|param| param.symbol)
            .collect::<Vec<_>>();
        if let Some(receiver) = &function.receiver {
            symbols.push(receiver.symbol);
        }
        collect_block_symbols(&function.body, &mut symbols);
        for symbol in symbols {
            let Some(name) = symbol_names.get(&symbol) else {
                continue;
            };
            if let Some(value) = scoped.get(name) {
                out.insert(symbol, value.clone());
            }
        }
    }

    fn write_legacy_attributes(symbol: &mut uniflow_hir::Symbol, typed: &CppSymbolSemantics) {
        if let Some(meta) = &typed.method {
            symbol
                .attributes
                .insert("cpp.owner".into(), meta.owner.clone());
            symbol
                .attributes
                .insert("cpp.virtual".into(), meta.is_virtual.to_string());
            symbol
                .attributes
                .insert("cpp.pure_virtual".into(), meta.is_pure_virtual.to_string());
            symbol
                .attributes
                .insert("cpp.override".into(), meta.is_override.to_string());
            symbol
                .attributes
                .insert("cpp.final".into(), meta.is_final.to_string());
            symbol
                .attributes
                .insert("cpp.const".into(), meta.is_const.to_string());
            symbol
                .attributes
                .insert("cpp.noexcept".into(), meta.is_noexcept.to_string());
            if let Some(kind) = meta.special_member {
                let legacy = match kind {
                    uniflow_hir::CppSpecialMemberKind::Constructor => "constructor",
                    uniflow_hir::CppSpecialMemberKind::Destructor => "destructor",
                    uniflow_hir::CppSpecialMemberKind::CopyConstructor => "copy_constructor",
                    uniflow_hir::CppSpecialMemberKind::MoveConstructor => "move_constructor",
                    uniflow_hir::CppSpecialMemberKind::CopyAssignment => "copy_assignment",
                    uniflow_hir::CppSpecialMemberKind::MoveAssignment => "move_assignment",
                    uniflow_hir::CppSpecialMemberKind::Assignment => "assignment",
                };
                symbol
                    .attributes
                    .insert("cpp.special_member".into(), legacy.into());
            }
        }
        if typed.value.ownership != uniflow_hir::CppOwnershipKind::None {
            symbol.attributes.insert(
                "cpp.ownership".into(),
                format!("{:?}", typed.value.ownership).to_ascii_lowercase(),
            );
        }
        if typed.value.reference_kind != uniflow_hir::CppReferenceKind::None {
            symbol.attributes.insert(
                "cpp.reference".into(),
                match typed.value.reference_kind {
                    uniflow_hir::CppReferenceKind::LValue => "lvalue",
                    uniflow_hir::CppReferenceKind::RValue => "rvalue",
                    uniflow_hir::CppReferenceKind::None => "none",
                }
                .into(),
            );
        }
        if let Some(pointee) = &typed.value.pointee_type {
            symbol
                .attributes
                .insert("cpp.pointee_type".into(), pointee.clone());
        }
    }

    let symbol_names = program
        .symbols
        .iter()
        .map(|symbol| (symbol.id, symbol.name.clone()))
        .collect::<HashMap<_, _>>();
    let mut scoped_by_symbol = HashMap::<SymbolId, CppValueSemantics>::new();
    for module in &program.modules {
        for item in &module.items {
            match item {
                Item::Function(function) => collect_function_bindings(
                    function,
                    None,
                    index,
                    &symbol_names,
                    &mut scoped_by_symbol,
                ),
                Item::Class(class) => {
                    for method in &class.methods {
                        collect_function_bindings(
                            method,
                            Some(&class.name),
                            index,
                            &symbol_names,
                            &mut scoped_by_symbol,
                        );
                    }
                }
                Item::GlobalVar(_) => {}
            }
        }
    }

    let mut typed_by_symbol = HashMap::<SymbolId, CppSymbolSemantics>::new();
    for symbol in &mut program.symbols {
        let method = method_for_name(index, &symbol.name);
        let value = scoped_by_symbol
            .get(&symbol.id)
            .cloned()
            .or_else(|| {
                matches!(&symbol.kind, SymbolKind::Global | SymbolKind::Field)
                    .then(|| index.values.get(&symbol.name).cloned())
                    .flatten()
            })
            .unwrap_or_default();
        if method.is_none() && value == CppValueSemantics::default() {
            continue;
        }
        let typed = CppSymbolSemantics { method, value };
        write_legacy_attributes(symbol, &typed);
        symbol.cpp = Some(typed.clone());
        typed_by_symbol.insert(symbol.id, typed);
    }

    fn attach_function(
        function: &mut uniflow_hir::Function,
        typed: &HashMap<SymbolId, CppSymbolSemantics>,
        initializers: &HashMap<String, Vec<uniflow_hir::CppConstructorInitializer>>,
    ) {
        if let Some(symbol) = function.symbol.and_then(|id| typed.get(&id)) {
            function.cpp = symbol.method.clone();
        }
        let normalized = function.name.replace('.', "::");
        if let Some(found) = initializers.get(&normalized).or_else(|| {
            initializers
                .iter()
                .find(|(name, _)| normalized.ends_with(name.as_str()))
                .map(|(_, value)| value)
        }) {
            function.cpp_initializers = found.clone();
        }
        for param in &mut function.params {
            if let Some(symbol) = typed.get(&param.symbol) {
                param.cpp = symbol.value.clone();
            }
        }
        for capture in &mut function.captures {
            if let Some(symbol) = typed.get(&capture.symbol) {
                capture.cpp = symbol.value.clone();
            }
        }
        if let Some(receiver) = &mut function.receiver {
            if let Some(symbol) = typed.get(&receiver.symbol) {
                receiver.cpp = symbol.value.clone();
            }
        }
    }

    for module in &mut program.modules {
        for item in &mut module.items {
            match item {
                Item::Function(function) => {
                    attach_function(function, &typed_by_symbol, &index.initializers)
                }
                Item::Class(class) => {
                    for method in &mut class.methods {
                        attach_function(method, &typed_by_symbol, &index.initializers);
                    }
                }
                Item::GlobalVar(_) => {}
            }
        }
    }
    inject_cpp_raii_cleanup(program, &typed_by_symbol);
}

fn inject_cpp_raii_cleanup(
    program: &mut uniflow_hir::Program,
    typed: &std::collections::HashMap<uniflow_hir::SymbolId, uniflow_hir::CppSymbolSemantics>,
) {
    use uniflow_hir::{CallExpr, CallTarget, Expr, ExprId, Stmt, StmtId, SymbolId};

    fn collect_expr_ids(expr: &Expr, max_expr: &mut u32, max_stmt: &mut u32) {
        match expr {
            Expr::VarRef { id, .. }
            | Expr::Literal { id, .. }
            | Expr::Opaque { id, .. }
            | Expr::Unknown { id, .. } => *max_expr = (*max_expr).max(id.0),
            Expr::Unary { id, expr, .. } | Expr::Cast { id, expr, .. } => {
                *max_expr = (*max_expr).max(id.0);
                collect_expr_ids(expr, max_expr, max_stmt);
            }
            Expr::Binary { id, lhs, rhs, .. } => {
                *max_expr = (*max_expr).max(id.0);
                collect_expr_ids(lhs, max_expr, max_stmt);
                collect_expr_ids(rhs, max_expr, max_stmt);
            }
            Expr::Conditional {
                id,
                cond,
                then_expr,
                else_expr,
                ..
            } => {
                *max_expr = (*max_expr).max(id.0);
                collect_expr_ids(cond, max_expr, max_stmt);
                collect_expr_ids(then_expr, max_expr, max_stmt);
                collect_expr_ids(else_expr, max_expr, max_stmt);
            }
            Expr::Assign { id, lhs, rhs, .. } => {
                *max_expr = (*max_expr).max(id.0);
                match lhs {
                    uniflow_hir::LValue::Var(_) => {}
                    uniflow_hir::LValue::Field { base, .. } => {
                        collect_expr_ids(base, max_expr, max_stmt);
                    }
                    uniflow_hir::LValue::Index { base, index } => {
                        collect_expr_ids(base, max_expr, max_stmt);
                        collect_expr_ids(index, max_expr, max_stmt);
                    }
                }
                collect_expr_ids(rhs, max_expr, max_stmt);
            }
            Expr::Interp { id, parts, .. }
            | Expr::Collection {
                id,
                elements: parts,
                ..
            } => {
                *max_expr = (*max_expr).max(id.0);
                for part in parts {
                    collect_expr_ids(part, max_expr, max_stmt);
                }
            }
            Expr::Range { id, low, high, .. } => {
                *max_expr = (*max_expr).max(id.0);
                collect_expr_ids(low, max_expr, max_stmt);
                collect_expr_ids(high, max_expr, max_stmt);
            }
            Expr::FieldRead { id, base, .. } => {
                *max_expr = (*max_expr).max(id.0);
                collect_expr_ids(base, max_expr, max_stmt);
            }
            Expr::IndexRead {
                id, base, index, ..
            } => {
                *max_expr = (*max_expr).max(id.0);
                collect_expr_ids(base, max_expr, max_stmt);
                collect_expr_ids(index, max_expr, max_stmt);
            }
            Expr::Call(call) => {
                *max_expr = (*max_expr).max(call.id.0);
                if let Some(receiver) = &call.receiver {
                    collect_expr_ids(receiver, max_expr, max_stmt);
                }
                for arg in &call.args {
                    collect_expr_ids(arg, max_expr, max_stmt);
                }
            }
            Expr::Lambda { id, body, .. } => {
                *max_expr = (*max_expr).max(id.0);
                collect_block_ids(body, max_expr, max_stmt);
            }
            Expr::New { id, args, .. } => {
                *max_expr = (*max_expr).max(id.0);
                for arg in args {
                    collect_expr_ids(arg, max_expr, max_stmt);
                }
            }
        }
    }

    fn collect_block_ids(block: &uniflow_hir::Block, max_expr: &mut u32, max_stmt: &mut u32) {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Let { id, init, .. } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    if let Some(expr) = init {
                        collect_expr_ids(expr, max_expr, max_stmt);
                    }
                }
                Stmt::Assign { id, lhs, rhs, .. } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    match lhs {
                        uniflow_hir::LValue::Var(_) => {}
                        uniflow_hir::LValue::Field { base, .. } => {
                            collect_expr_ids(base, max_expr, max_stmt)
                        }
                        uniflow_hir::LValue::Index { base, index } => {
                            collect_expr_ids(base, max_expr, max_stmt);
                            collect_expr_ids(index, max_expr, max_stmt);
                        }
                    }
                    collect_expr_ids(rhs, max_expr, max_stmt);
                }
                Stmt::Expr { id, expr, .. } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    collect_expr_ids(expr, max_expr, max_stmt);
                }
                Stmt::If {
                    id,
                    cond,
                    then_block,
                    else_block,
                    ..
                } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    collect_expr_ids(cond, max_expr, max_stmt);
                    collect_block_ids(then_block, max_expr, max_stmt);
                    if let Some(block) = else_block {
                        collect_block_ids(block, max_expr, max_stmt);
                    }
                }
                Stmt::While { id, cond, body, .. } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    collect_expr_ids(cond, max_expr, max_stmt);
                    collect_block_ids(body, max_expr, max_stmt);
                }
                Stmt::For {
                    id,
                    init,
                    cond,
                    update,
                    body,
                    ..
                } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    collect_block_ids(init, max_expr, max_stmt);
                    if let Some(cond) = cond {
                        collect_expr_ids(cond, max_expr, max_stmt);
                    }
                    collect_block_ids(update, max_expr, max_stmt);
                    collect_block_ids(body, max_expr, max_stmt);
                }
                Stmt::ForEach {
                    id, iterable, body, ..
                } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    collect_expr_ids(iterable, max_expr, max_stmt);
                    collect_block_ids(body, max_expr, max_stmt);
                }
                Stmt::Return { id, value, .. } | Stmt::Throw { id, value, .. } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    if let Some(expr) = value {
                        collect_expr_ids(expr, max_expr, max_stmt);
                    }
                }
                Stmt::Try {
                    id,
                    try_block,
                    catches,
                    finally_block,
                    ..
                } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    collect_block_ids(try_block, max_expr, max_stmt);
                    for catch in catches {
                        collect_block_ids(&catch.body, max_expr, max_stmt);
                    }
                    if let Some(block) = finally_block {
                        collect_block_ids(block, max_expr, max_stmt);
                    }
                }
                Stmt::Break { id, .. } | Stmt::Continue { id, .. } => {
                    *max_stmt = (*max_stmt).max(id.0);
                }
                Stmt::DoWhile { id, body, cond, .. } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    collect_expr_ids(cond, max_expr, max_stmt);
                    collect_block_ids(body, max_expr, max_stmt);
                }
                Stmt::Switch {
                    id,
                    scrutinee,
                    clauses,
                    default,
                    ..
                } => {
                    *max_stmt = (*max_stmt).max(id.0);
                    collect_expr_ids(scrutinee, max_expr, max_stmt);
                    for clause in clauses {
                        for value in &clause.values {
                            collect_expr_ids(value, max_expr, max_stmt);
                        }
                        collect_block_ids(&clause.body, max_expr, max_stmt);
                    }
                    if let Some(block) = default {
                        collect_block_ids(block, max_expr, max_stmt);
                    }
                }
            }
        }
    }

    fn returned_symbol(expr: Option<&Expr>) -> Option<SymbolId> {
        match expr? {
            Expr::VarRef { symbol, .. } => Some(*symbol),
            Expr::Call(call) if matches!(&call.target, CallTarget::Named(name) if name == "__uniflow_cpp_move" || name == "__uniflow_cpp_forward") => {
                call.args.first().and_then(|arg| match arg {
                    Expr::VarRef { symbol, .. } => Some(*symbol),
                    _ => None,
                })
            }
            _ => None,
        }
    }

    fn cleanup_stmt(
        symbol: SymbolId,
        span: uniflow_hir::Span,
        next_expr: &mut u32,
        next_stmt: &mut u32,
    ) -> Stmt {
        let arg_id = ExprId(*next_expr);
        *next_expr += 1;
        let call_id = ExprId(*next_expr);
        *next_expr += 1;
        let stmt_id = StmtId(*next_stmt);
        *next_stmt += 1;
        Stmt::Expr {
            id: stmt_id,
            expr: Expr::Call(CallExpr {
                id: call_id,
                target: CallTarget::Named("__uniflow_cpp_destroy".to_string()),
                receiver: None,
                qualifier_is_explicit: false,
                args: vec![Expr::VarRef {
                    id: arg_id,
                    symbol,
                    span,
                }],
                arg_names: vec![None],
                span,
            }),
            span,
        }
    }

    fn is_owner(
        symbol: SymbolId,
        typed: &std::collections::HashMap<SymbolId, uniflow_hir::CppSymbolSemantics>,
    ) -> bool {
        typed.get(&symbol).is_some_and(|cpp| {
            matches!(
                cpp.value.ownership,
                uniflow_hir::CppOwnershipKind::Unique
                    | uniflow_hir::CppOwnershipKind::Shared
                    | uniflow_hir::CppOwnershipKind::Weak
            )
        })
    }

    fn transform_block(
        block: &mut uniflow_hir::Block,
        inherited: &[SymbolId],
        // Prefix of `inherited + local owners` that survives a handled throw. A try body sets
        // this boundary to the owners active before entering the try; its catch clauses do not
        // catch exceptions thrown by their own bodies and therefore retain the outer boundary.
        throw_cleanup_floor: usize,
        typed: &std::collections::HashMap<SymbolId, uniflow_hir::CppSymbolSemantics>,
        next_expr: &mut u32,
        next_stmt: &mut u32,
    ) {
        let original = std::mem::take(&mut block.stmts);
        let mut rewritten = Vec::new();
        let mut local_owners = Vec::<SymbolId>::new();
        for mut stmt in original {
            match &mut stmt {
                Stmt::If {
                    then_block,
                    else_block,
                    ..
                } => {
                    let mut active = inherited.to_vec();
                    active.extend(local_owners.iter().copied());
                    transform_block(
                        then_block,
                        &active,
                        throw_cleanup_floor,
                        typed,
                        next_expr,
                        next_stmt,
                    );
                    if let Some(else_block) = else_block {
                        transform_block(
                            else_block,
                            &active,
                            throw_cleanup_floor,
                            typed,
                            next_expr,
                            next_stmt,
                        );
                    }
                }
                Stmt::While { body, .. } | Stmt::ForEach { body, .. } => {
                    let mut active = inherited.to_vec();
                    active.extend(local_owners.iter().copied());
                    transform_block(
                        body,
                        &active,
                        throw_cleanup_floor,
                        typed,
                        next_expr,
                        next_stmt,
                    );
                }
                Stmt::Try {
                    try_block,
                    catches,
                    finally_block,
                    ..
                } => {
                    let mut active = inherited.to_vec();
                    active.extend(local_owners.iter().copied());
                    // A throw from the try body transfers to this statement's handlers and
                    // destroys only owners introduced after entering the try. Owners already
                    // active before the try remain alive in the selected catch.
                    transform_block(
                        try_block,
                        &active,
                        active.len(),
                        typed,
                        next_expr,
                        next_stmt,
                    );
                    for catch in catches {
                        // Exceptions raised by a handler are not caught by sibling handlers; they
                        // propagate to the enclosing try boundary.
                        transform_block(
                            &mut catch.body,
                            &active,
                            throw_cleanup_floor,
                            typed,
                            next_expr,
                            next_stmt,
                        );
                    }
                    if let Some(finally_block) = finally_block {
                        transform_block(
                            finally_block,
                            &active,
                            throw_cleanup_floor,
                            typed,
                            next_expr,
                            next_stmt,
                        );
                    }
                }
                _ => {}
            }

            if matches!(&stmt, Stmt::Return { .. } | Stmt::Throw { .. }) {
                let escaped = match &stmt {
                    Stmt::Return { value, .. } => returned_symbol(value.as_ref()),
                    _ => None,
                };
                let mut active = inherited.to_vec();
                active.extend(local_owners.iter().copied());
                let cleanup_start = if matches!(&stmt, Stmt::Throw { .. }) {
                    throw_cleanup_floor.min(active.len())
                } else {
                    0
                };
                for symbol in active[cleanup_start..]
                    .iter()
                    .rev()
                    .copied()
                    .filter(|symbol| Some(*symbol) != escaped)
                {
                    rewritten.push(cleanup_stmt(symbol, block.span, next_expr, next_stmt));
                }
                rewritten.push(stmt);
                // No lexical-scope cleanup is appended after an unconditional terminator: the
                // active owners were emitted immediately before it.  Keeping trailing statements
                // would both model unreachable code and inject a second destruction sequence.
                block.stmts = rewritten;
                return;
            }

            if let Stmt::Let { symbol, .. } = &stmt {
                if is_owner(*symbol, typed) {
                    local_owners.push(*symbol);
                }
            }
            rewritten.push(stmt);
        }
        for symbol in local_owners.into_iter().rev() {
            rewritten.push(cleanup_stmt(symbol, block.span, next_expr, next_stmt));
        }
        block.stmts = rewritten;
    }

    let mut max_expr = 0u32;
    let mut max_stmt = 0u32;
    for module in &program.modules {
        for item in &module.items {
            match item {
                Item::Function(function) => {
                    collect_block_ids(&function.body, &mut max_expr, &mut max_stmt)
                }
                Item::Class(class) => {
                    for method in &class.methods {
                        collect_block_ids(&method.body, &mut max_expr, &mut max_stmt);
                    }
                }
                Item::GlobalVar(global) => {
                    if let Some(expr) = &global.init {
                        collect_expr_ids(expr, &mut max_expr, &mut max_stmt);
                    }
                }
            }
        }
    }
    let mut next_expr = max_expr.saturating_add(1);
    let mut next_stmt = max_stmt.saturating_add(1);
    for module in &mut program.modules {
        for item in &mut module.items {
            match item {
                Item::Function(function) => transform_block(
                    &mut function.body,
                    &[],
                    0,
                    typed,
                    &mut next_expr,
                    &mut next_stmt,
                ),
                Item::Class(class) => {
                    for method in &mut class.methods {
                        transform_block(
                            &mut method.body,
                            &[],
                            0,
                            typed,
                            &mut next_expr,
                            &mut next_stmt,
                        );
                    }
                }
                Item::GlobalVar(_) => {}
            }
        }
    }
}

fn lower_constructor_initializer_lists(source: &str) -> String {
    // Constructor initializers are collected into typed HIR metadata and lowered explicitly.
    // The fallback C grammar only needs the initializer list removed from the surface syntax.
    let re = Regex::new(r"(?m)(\)\s*(?:noexcept\s*)?):\s*([^\{;]+)(\{)").expect("valid regex");
    re.replace_all(source, |caps: &regex::Captures<'_>| {
        let prefix = caps.get(1).map_or(")", |m| m.as_str());
        format!("{prefix} {{")
    })
    .into_owned()
}

fn lower_cpp_lambdas(source: &str) -> String {
    #[derive(Clone, Debug)]
    struct LambdaSurface {
        start: usize,
        end: usize,
        variable: String,
        captures: String,
        params: String,
        return_type: String,
        body: String,
    }

    fn skip_space(source: &str, mut index: usize) -> usize {
        while source
            .as_bytes()
            .get(index)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            index += 1;
        }
        index
    }

    fn identifier(source: &str, mut index: usize) -> Option<(&str, usize)> {
        let start = index;
        let first = *source.as_bytes().get(index)?;
        if !(first == b'_' || first.is_ascii_alphabetic()) {
            return None;
        }
        index += 1;
        while source
            .as_bytes()
            .get(index)
            .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
        {
            index += 1;
        }
        Some((&source[start..index], index))
    }

    fn matching(source: &str, open: usize, left: u8, right: u8) -> Option<usize> {
        let bytes = source.as_bytes();
        if bytes.get(open).copied()? != left {
            return None;
        }
        let mut depth = 0usize;
        let mut index = open;
        let mut quote = None;
        let mut escaped = false;
        let mut line_comment = false;
        let mut block_comment = false;
        while index < bytes.len() {
            let byte = bytes[index];
            if line_comment {
                if byte == b'\n' {
                    line_comment = false;
                }
                index += 1;
                continue;
            }
            if block_comment {
                if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    block_comment = false;
                    index += 2;
                } else {
                    index += 1;
                }
                continue;
            }
            if escaped {
                escaped = false;
                index += 1;
                continue;
            }
            if let Some(active) = quote {
                if byte == b'\\' {
                    escaped = true;
                } else if byte == active {
                    quote = None;
                }
                index += 1;
                continue;
            }
            if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
                line_comment = true;
                index += 2;
                continue;
            }
            if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
                block_comment = true;
                index += 2;
                continue;
            }
            if byte == b'\'' || byte == b'"' {
                quote = Some(byte);
                index += 1;
                continue;
            }
            if byte == left {
                depth += 1;
            } else if byte == right {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            index += 1;
        }
        None
    }

    fn parse_at(source: &str, start: usize) -> Option<LambdaSurface> {
        if source.get(start..start + 4)? != "auto" {
            return None;
        }
        if start > 0 && source.as_bytes()[start - 1].is_ascii_alphanumeric() {
            return None;
        }
        let mut index = skip_space(source, start + 4);
        let (variable, next) = identifier(source, index)?;
        index = skip_space(source, next);
        if source.as_bytes().get(index) != Some(&b'=') {
            return None;
        }
        index = skip_space(source, index + 1);
        if source.as_bytes().get(index) != Some(&b'[') {
            return None;
        }
        let capture_end = matching(source, index, b'[', b']')?;
        let captures = source[index + 1..capture_end].to_string();
        index = skip_space(source, capture_end + 1);
        if source.as_bytes().get(index) != Some(&b'(') {
            return None;
        }
        let params_end = matching(source, index, b'(', b')')?;
        let params = source[index + 1..params_end].to_string();
        index = skip_space(source, params_end + 1);
        for keyword in ["mutable", "constexpr", "consteval", "noexcept"] {
            if source[index..].starts_with(keyword) {
                index = skip_space(source, index + keyword.len());
                if keyword == "noexcept" && source.as_bytes().get(index) == Some(&b'(') {
                    index = skip_space(source, matching(source, index, b'(', b')')? + 1);
                }
            }
        }
        let mut return_type = "void".to_string();
        if source[index..].starts_with("->") {
            index = skip_space(source, index + 2);
            let type_start = index;
            while source
                .as_bytes()
                .get(index)
                .is_some_and(|byte| *byte != b'{')
            {
                index += 1;
            }
            return_type = source[type_start..index].trim().to_string();
        }
        index = skip_space(source, index);
        if source.as_bytes().get(index) != Some(&b'{') {
            return None;
        }
        let body_end = matching(source, index, b'{', b'}')?;
        let body = source[index + 1..body_end].to_string();
        if return_type == "void" && body.contains("return ") {
            return_type = "void *".to_string();
        }
        let mut end = skip_space(source, body_end + 1);
        if source.as_bytes().get(end) == Some(&b';') {
            end += 1;
        }
        Some(LambdaSurface {
            start,
            end,
            variable: variable.to_string(),
            captures,
            params,
            return_type,
            body,
        })
    }

    fn parameter_names(params: &str) -> std::collections::HashSet<String> {
        split_cpp_list(params)
            .into_iter()
            .filter_map(|param| param.split_whitespace().last())
            .map(|name| {
                name.trim_matches(|ch: char| ch == '*' || ch == '&')
                    .to_string()
            })
            .collect()
    }

    fn referenced_identifiers(
        body: &str,
        excluded: &std::collections::HashSet<String>,
    ) -> Vec<String> {
        let re = Regex::new(r"\b[A-Za-z_][A-Za-z0-9_]*\b").expect("valid identifier regex");
        let keywords = [
            "if", "else", "for", "while", "return", "new", "delete", "true", "false", "nullptr",
            "this", "auto", "const", "static", "sizeof", "throw", "try", "catch",
        ]
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
        let mut out = Vec::new();
        for found in re.find_iter(body) {
            let name = found.as_str();
            if keywords.contains(name) || excluded.contains(name) {
                continue;
            }
            if !out.iter().any(|existing| existing == name) {
                out.push(name.to_string());
            }
        }
        out
    }

    fn split_cpp_list(input: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut start = 0usize;
        let mut depth = 0usize;
        for (index, ch) in input.char_indices() {
            match ch {
                '(' | '[' | '{' | '<' => depth += 1,
                ')' | ']' | '}' | '>' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    out.push(input[start..index].trim());
                    start = index + 1;
                }
                _ => {}
            }
        }
        out.push(input[start..].trim());
        out
    }

    fn capture_bindings(lambda: &LambdaSurface) -> Vec<(String, bool, String)> {
        let mut out = Vec::new();
        let mut default = None;
        for capture in split_cpp_list(&lambda.captures) {
            let capture = capture.trim();
            if capture.is_empty() {
                continue;
            }
            if capture == "=" {
                default = Some(false);
                continue;
            }
            if capture == "&" {
                default = Some(true);
                continue;
            }
            if capture == "this" || capture == "*this" {
                out.push(("this".to_string(), capture == "this", "this".to_string()));
                continue;
            }
            let by_ref = capture.starts_with('&');
            let capture = capture.trim_start_matches('&').trim();
            let (name, expression) = capture
                .split_once('=')
                .map(|(name, expression)| (name.trim(), expression.trim()))
                .unwrap_or((capture, capture));
            if !name.is_empty() {
                out.push((name.to_string(), by_ref, expression.to_string()));
            }
        }
        if let Some(by_ref) = default {
            let excluded = parameter_names(&lambda.params);
            for name in referenced_identifiers(&lambda.body, &excluded) {
                if !out.iter().any(|(existing, _, _)| existing == &name) {
                    out.push((name.clone(), by_ref, name));
                }
            }
        }
        out
    }

    let mut lambdas = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("auto") {
        let start = cursor + relative;
        if let Some(lambda) = parse_at(source, start) {
            cursor = lambda.end;
            lambdas.push(lambda);
        } else {
            cursor = start + 4;
        }
    }
    if lambdas.is_empty() {
        return source.to_string();
    }

    let mut replaced = String::with_capacity(source.len());
    let mut synthetic = Vec::new();
    let mut cursor = 0usize;
    for lambda in lambdas {
        replaced.push_str(&source[cursor..lambda.start]);
        let function = format!("__uniflow_lambda_{}", lambda.variable);
        let captures = capture_bindings(&lambda);
        let capture_params = captures
            .iter()
            .map(|(name, _, _)| format!("void *{name}"))
            .collect::<Vec<_>>();
        let all_params = capture_params
            .iter()
            .cloned()
            .chain((!lambda.params.trim().is_empty()).then(|| lambda.params.trim().to_string()))
            .collect::<Vec<_>>()
            .join(", ");
        synthetic.push(format!(
            "\n{} {}({}) {{ {} }}\n",
            lambda.return_type, function, all_params, lambda.body
        ));
        if captures.is_empty() {
            replaced.push_str(&format!("auto {} = {};", lambda.variable, function));
        } else {
            let bindings = captures
                .iter()
                .map(|(_, by_ref, expression)| {
                    if *by_ref {
                        format!("__uniflow_cpp_capture_ref({expression})")
                    } else {
                        format!("__uniflow_cpp_capture_value({expression})")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            replaced.push_str(&format!(
                "auto {} = __uniflow_cpp_lambda_bind({}, {});",
                lambda.variable, function, bindings
            ));
        }
        cursor = lambda.end;
    }
    replaced.push_str(&source[cursor..]);
    replaced.push_str(&synthetic.join(""));
    replaced
}

fn lower_observed_template_calls(source: &str) -> String {
    // Bounded template handling: erase arguments only at concrete call sites observed in this
    // translation unit. The function body remains shared and unresolved dependent calls retain
    // the normal unknown-effect summary.
    let concrete_call = Regex::new(
        r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*<\s*([A-Za-z_][A-Za-z0-9_:<>, *&0-9]*)\s*>\s*\(",
    )
    .expect("valid concrete template call regex");
    concrete_call
        .replace_all(source, |caps: &regex::Captures<'_>| {
            let name = caps.get(1).map_or("template_call", |m| m.as_str());
            let args = caps.get(2).map_or("unknown", |m| m.as_str());
            let identity = args
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
                .collect::<String>()
                .trim_matches('_')
                .to_string();
            format!(
                "{name}__uniflow_tpl_{}(",
                if identity.is_empty() {
                    "unknown"
                } else {
                    &identity
                }
            )
        })
        .into_owned()
}

/// Normalize common C++ surface constructs into the conservative C-family HIR grammar.
/// The normalization is source-only and intentionally preserves line count. It does not attempt
/// template instantiation or ABI layout; unsupported constructs remain visible to the parser
/// instead of being silently discarded.

fn lower_inline_cpp_methods(source: &str) -> String {
    fn matching_brace(source: &str, open: usize) -> Option<usize> {
        let bytes = source.as_bytes();
        if bytes.get(open) != Some(&b'{') {
            return None;
        }
        let mut depth = 0usize;
        let mut quote = None;
        let mut escaped = false;
        let mut line_comment = false;
        let mut block_comment = false;
        let mut index = open;
        while index < bytes.len() {
            let byte = bytes[index];
            if line_comment {
                if byte == b'\n' {
                    line_comment = false;
                }
                index += 1;
                continue;
            }
            if block_comment {
                if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    block_comment = false;
                    index += 2;
                } else {
                    index += 1;
                }
                continue;
            }
            if escaped {
                escaped = false;
                index += 1;
                continue;
            }
            if let Some(active) = quote {
                if byte == b'\\' {
                    escaped = true;
                } else if byte == active {
                    quote = None;
                }
                index += 1;
                continue;
            }
            if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
                line_comment = true;
                index += 2;
                continue;
            }
            if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
                block_comment = true;
                index += 2;
                continue;
            }
            if matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
            } else if byte == b'{' {
                depth += 1;
            } else if byte == b'}' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            index += 1;
        }
        None
    }

    fn method_name_span(header: &str) -> Option<(usize, usize)> {
        if header.contains("(*") {
            return None;
        }
        if let Some(operator) = header.rfind("operator") {
            let first_open = operator + header[operator..].find('(')?;
            let param_open = if header[operator..first_open].trim() == "operator" {
                let close = header[first_open + 1..].find(')')? + first_open + 1;
                close + 1 + header[close + 1..].find('(')?
            } else {
                first_open
            };
            let end = header[..param_open].trim_end().len();
            return Some((operator, end));
        }
        let open = header.find('(')?;
        let prefix = header[..open].trim_end();
        let end = prefix.len();
        let bytes = prefix.as_bytes();
        let mut start = end;
        while start > 0 {
            let byte = bytes[start - 1];
            if byte == b'_' || byte == b'~' || byte.is_ascii_alphanumeric() {
                start -= 1;
            } else {
                break;
            }
        }
        if start == end {
            return None;
        }
        let name = &prefix[start..end];
        if matches!(name, "if" | "for" | "while" | "switch" | "catch") {
            return None;
        }
        Some((start, end))
    }

    fn split_access_prefix(header: &str) -> (&str, &str) {
        let mut split = 0usize;
        for marker in ["public:", "protected:", "private:"] {
            if let Some(index) = header.rfind(marker) {
                split = split.max(index + marker.len());
            }
        }
        header.split_at(split)
    }

    fn external_method_header(owner: &str, header: &str) -> Option<String> {
        let (_, method) = split_access_prefix(header);
        let mut method = method.trim().to_string();
        let (start, end) = method_name_span(&method)?;
        if method[start..end].trim_start().starts_with("operator") {
            // The fallback C grammar cannot represent operator identifiers.  Keep the declaration
            // and semantic metadata, while binary/call expressions retain conservative flow.
            return None;
        }
        method.insert_str(start, &format!("{owner}::"));
        let virtual_re = Regex::new(r"\bvirtual\s+").expect("valid virtual regex");
        let override_re = Regex::new(r"\s+override\b").expect("valid override regex");
        let final_re = Regex::new(r"\s+final\b").expect("valid final regex");
        method = virtual_re.replace(&method, "").into_owned();
        method = override_re.replace_all(&method, "").into_owned();
        method = final_re.replace_all(&method, "").into_owned();
        Some(method)
    }

    let class_re =
        Regex::new(r"\b(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^\{]+)?\s*\{")
            .expect("valid class regex");
    let mut replacements = Vec::<(usize, usize, String)>::new();
    let mut definitions = Vec::<String>::new();
    let mut search = 0usize;
    while search < source.len() {
        let Some(caps) = class_re.captures(&source[search..]) else {
            break;
        };
        let whole = caps.get(0).expect("class match");
        let owner = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let open = search + whole.end() - 1;
        let Some(close) = matching_brace(source, open) else {
            break;
        };
        let mut cursor = open + 1;
        let mut declaration_start = cursor;
        let mut paren = 0usize;
        let mut bracket = 0usize;
        let mut angle = 0usize;
        let mut quote = None;
        let mut escaped = false;
        while cursor < close {
            let byte = source.as_bytes()[cursor];
            if escaped {
                escaped = false;
                cursor += 1;
                continue;
            }
            if let Some(active) = quote {
                if byte == b'\\' {
                    escaped = true;
                } else if byte == active {
                    quote = None;
                }
                cursor += 1;
                continue;
            }
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'(' => paren += 1,
                b')' => paren = paren.saturating_sub(1),
                b'[' => bracket += 1,
                b']' => bracket = bracket.saturating_sub(1),
                b'<' => angle += 1,
                b'>' => angle = angle.saturating_sub(1),
                b';' if paren == 0 && bracket == 0 && angle == 0 => {
                    declaration_start = cursor + 1;
                }
                b'{' if paren == 0 && bracket == 0 && angle == 0 => {
                    let header = &source[declaration_start..cursor];
                    let Some(body_end) = matching_brace(source, cursor) else {
                        break;
                    };
                    if method_name_span(split_access_prefix(header).1).is_some() {
                        let (access, method) = split_access_prefix(header);
                        let trailing_newlines = source[cursor..=body_end]
                            .bytes()
                            .filter(|byte| *byte == b'\n')
                            .count();
                        let declaration = format!(
                            "{access}{};{}",
                            method.trim_end(),
                            "\n".repeat(trailing_newlines)
                        );
                        if let Some(external) = external_method_header(owner, header) {
                            definitions
                                .push(format!("\n{external} {}\n", &source[cursor..=body_end]));
                        }
                        replacements.push((declaration_start, body_end + 1, declaration));
                    }
                    cursor = body_end;
                    declaration_start = cursor + 1;
                }
                _ => {}
            }
            cursor += 1;
        }
        search = close + 1;
    }
    if replacements.is_empty() {
        return source.to_string();
    }
    let mut out = source.to_string();
    replacements.sort_by_key(|(start, _, _)| *start);
    for (start, end, replacement) in replacements.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    for definition in definitions {
        out.push_str(&definition);
    }
    out
}

pub fn normalize_cpp_for_hir(source: &str) -> String {
    let lambda_lowered = lower_cpp_lambdas(source);
    let qualified = lower_inline_cpp_methods(&lambda_lowered);
    let mut out = lower_observed_template_calls(&qualified);
    out = lower_constructor_initializer_lists(&out);

    // The C-family frontend already models structs as HIR classes. Treat class declarations the
    // same way while preserving line count; exact byte spans are not currently emitted by it.
    let class_re =
        Regex::new(r"\b(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^\{]+)?\s*\{")
            .expect("valid regex");
    out = class_re.replace_all(&out, "struct $1 {").into_owned();

    // Access labels are not statements and otherwise confuse the statement splitter.
    let access_re =
        Regex::new(r"(?m)^(\s*)(public|protected|private)\s*:\s*$").expect("valid regex");
    out = access_re.replace_all(&out, "$1").into_owned();

    // Convert constructor/destructor definitions into function-shaped declarations understood by
    // the shared expression parser. Qualified names are retained for method resolution.
    let ctor_re =
        Regex::new(r"(?m)^(\s*)((?:[A-Za-z_][A-Za-z0-9_]*::)+)([A-Za-z_][A-Za-z0-9_]*)\s*\(")
            .expect("valid regex");
    out = ctor_re
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            let indent = caps.get(1).map_or("", |m| m.as_str());
            let prefix = caps.get(2).map_or("", |m| m.as_str());
            let name = caps.get(3).map_or("", |m| m.as_str());
            format!("{indent}void {prefix}{name}(")
        })
        .into_owned();

    let dtor_re =
        Regex::new(r"(?m)^(\s*)((?:[A-Za-z_][A-Za-z0-9_]*::)*)~([A-Za-z_][A-Za-z0-9_]*)\s*\(")
            .expect("valid regex");
    out = dtor_re
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            let indent = caps.get(1).map_or("", |m| m.as_str());
            let prefix = caps.get(2).map_or("", |m| m.as_str());
            let name = caps.get(3).map_or("", |m| m.as_str());
            format!("{indent}void {prefix}destructor_{name}(")
        })
        .into_owned();

    // Keep template bodies analyzable, but remove the declaration prefix that the conservative
    // signature recognizer cannot consume. Replacing with whitespace preserves line numbering.
    let template_re =
        Regex::new(r"(?m)^\s*template\s*<[^\n>]*(?:>[^\n>]*)*>\s*$").expect("valid regex");
    out = template_re
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            caps.get(0)
                .map(|m| {
                    m.as_str()
                        .chars()
                        .map(|ch| if ch == '\n' { '\n' } else { ' ' })
                        .collect::<String>()
                })
                .unwrap_or_default()
        })
        .into_owned();

    // Preserve alias information in a form understood by the C-family type collector.
    let using_alias_re = Regex::new(r"(?m)^(\s*)using\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);")
        .expect("valid regex");
    out = using_alias_re
        .replace_all(&out, "${1}typedef ${3} ${2};")
        .into_owned();

    // Model the standard owning pointer wrappers as pointer-shaped storage. Ownership/lifetime
    // remains visible in the original source, while the shared C frontend can now recover field
    // and pointee flows.
    let smart_ptr_re =
        Regex::new(r"(?:std::)?(?:unique_ptr|shared_ptr|weak_ptr)\s*<\s*([^<>]+)\s*>")
            .expect("valid regex");
    out = smart_ptr_re.replace_all(&out, "$1 *").into_owned();

    // Lower the common allocation spellings to the C allocation form. This preserves a distinct
    // HIR allocation site and lets the common heap/value-flow engine reason about the pointee.
    let make_ptr_re = Regex::new(
        r"(?:std::)?make_(?:unique|shared)\s*<\s*([A-Za-z_][A-Za-z0-9_:]*)\s*>\s*\([^;\n]*\)",
    )
    .expect("valid regex");
    out = make_ptr_re
        .replace_all(&out, "malloc(sizeof($1))")
        .into_owned();
    let new_re =
        Regex::new(r"\bnew\s+([A-Za-z_][A-Za-z0-9_:]*)\s*(?:\([^;\n]*\))?").expect("valid regex");
    out = new_re.replace_all(&out, "malloc(sizeof($1))").into_owned();

    // Source-level delete is kept distinct from compiler-injected RAII destruction.  The former
    // is a raw deallocation event (and participates in the legacy dangling-pointer checker),
    // while `__uniflow_cpp_destroy` is also used for automatic owner cleanup.
    let delete_re = Regex::new(r"\bdelete(?:\s*\[\s*\])?\s+([^;]+);").expect("valid regex");
    out = delete_re
        .replace_all(&out, "__uniflow_cpp_delete($1);")
        .into_owned();

    let rref_re = Regex::new(r"&&").expect("valid regex");
    out = rref_re.replace_all(&out, "*").into_owned();
    let lref_re =
        Regex::new(r"(?P<ty>[A-Za-z_][A-Za-z0-9_:<>]*)\s*&\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
            .expect("valid regex");
    out = lref_re.replace_all(&out, "$ty *$name").into_owned();

    let move_re = Regex::new(r"(?:std::)?move\s*\(([^()]*)\)").expect("valid regex");
    out = move_re
        .replace_all(&out, "__uniflow_cpp_move($1)")
        .into_owned();
    let forward_re =
        Regex::new(r"(?:std::)?forward\s*(?:<[^>]+>)?\s*\(([^()]*)\)").expect("valid regex");
    out = forward_re
        .replace_all(&out, "__uniflow_cpp_forward($1)")
        .into_owned();
    for (kind, marker) in [
        ("static_cast", "__uniflow_cpp_cast_static"),
        ("dynamic_cast", "__uniflow_cpp_cast_dynamic"),
        ("reinterpret_cast", "__uniflow_cpp_cast_reinterpret"),
        ("const_cast", "__uniflow_cpp_cast_const"),
    ] {
        let cast_re = Regex::new(&format!(r#"{kind}\s*<\s*([^>]+?)\s*>\s*\(([^()]*)\)"#))
            .expect("valid regex");
        out = cast_re
            .replace_all(&out, format!(r#"{marker}("$1", $2)"#))
            .into_owned();
    }

    // Member access through the implicit receiver is equivalent to a normal field access in the
    // current HIR. Removing the spelling avoids creating a synthetic local named `this`.
    out = out.replace("this->", "");

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_hir::Item;

    #[test]
    fn normalizes_classes_access_labels_and_qualified_constructors() {
        let source = r#"
class Widget {
public:
    int value;
};

Widget::Widget(int input) {
    value = input;
}

void Widget::run() {
    system(getenv("CMD"));
}
"#;
        let program = CppParser
            .parse_file("widget.cpp", source)
            .expect("parse C++");
        assert_eq!(program.language, Language::Cpp);
        let widget = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name == "Widget" => Some(class),
                _ => None,
            })
            .expect("Widget class");
        assert!(widget
            .methods
            .iter()
            .any(|method| method.name == "Widget::Widget"));
        assert!(widget
            .methods
            .iter()
            .any(|method| method.name == "Widget::run"));
    }

    #[test]
    fn normalizes_aliases_smart_pointers_and_allocations() {
        let source = r#"
using Command = const char *;
struct Request { Command cmd; };
void run() {
    std::unique_ptr<Request> req = std::make_unique<Request>();
    req->cmd = getenv("CMD");
    system(req->cmd);
}
"#;
        let normalized = normalize_cpp_for_hir(source);
        assert!(normalized.contains("typedef const char * Command"));
        assert!(normalized.contains("Request * req"));
        assert!(normalized.contains("malloc(sizeof(Request))"));
        let program = CppParser
            .parse_file("smart.cpp", source)
            .expect("parse C++");
        let rendered = format!("{program:#?}");
        assert!(rendered.contains("Request"));
        assert!(rendered.contains("getenv"));
        assert!(rendered.contains("system"));
    }

    #[test]
    fn normalizes_new_delete_and_this_member_access() {
        let source = r#"
class Holder {
public:
    char *cmd;
};
void Holder::set(char *value) {
    this->cmd = value;
}
void run() {
    Holder *holder = new Holder();
    delete holder;
}
"#;
        let normalized = normalize_cpp_for_hir(source);
        assert!(!normalized.contains(": cmd(value)"));
        assert!(normalized.contains("malloc(sizeof(Holder))"));
        assert!(normalized.contains("__uniflow_cpp_destroy(holder)"));
    }
}

#[cfg(test)]
mod semantic_tests {
    use super::*;
    use uniflow_hir::Item;

    #[test]
    fn restores_inheritance_and_attaches_qualified_methods() {
        let source = r#"
class Base { public: int value; };
class Derived : public virtual Base {
public:
    void run();
};
void Derived::run() { system(getenv("CMD")); }
"#;
        let program = CppParser
            .parse_file("inherit.cpp", source)
            .expect("parse C++");
        let derived = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name == "Derived" => Some(class),
                _ => None,
            })
            .expect("Derived class");
        assert_eq!(derived.bases, vec!["Base"]);
        assert!(derived
            .methods
            .iter()
            .any(|method| method.name == "Derived::run" && method.is_method));
    }
}

#[cfg(test)]
mod advanced_surface_tests {
    use super::*;
    use uniflow_hir::Item;

    #[test]
    fn lowers_constructor_initializers_moves_casts_and_references() {
        let source = r#"
struct Holder { char *cmd; };
Holder::Holder(char *value) : cmd(value) { }
void use_ref(Holder &holder) {
    char *x = static_cast<char *>(std::move(holder.cmd));
    system(x);
}
"#;
        let normalized = normalize_cpp_for_hir(source);
        assert!(!normalized.contains(": cmd(value)"));
        assert!(!normalized.contains("std::move"));
        assert!(!normalized.contains("static_cast<"));
        assert!(normalized.contains("__uniflow_cpp_move"));
        assert!(normalized.contains("__uniflow_cpp_cast_static"));
        assert!(!normalized.contains(": cmd(value)"));
        assert!(normalized.contains("Holder *holder"));
        let program = CppParser
            .parse_file("advanced.cpp", source)
            .expect("parse C++");
        let rendered = format!("{program:#?}");
        assert!(rendered.contains("system"));
        assert!(program.modules[0].items.iter().any(|item| match item {
            Item::Class(class) => class.methods.iter().any(|method| {
                method.name == "Holder::Holder"
                    && method.cpp_initializers.iter().any(|initializer| {
                        initializer.target == "cmd" && initializer.arguments == vec!["value"]
                    })
            }),
            _ => false,
        }));
    }

    #[test]
    fn lowers_non_capturing_lambda_to_callable_function() {
        let source = r#"
void run() {
    auto callback = [](char *cmd) -> void { system(cmd); };
    callback(getenv("CMD"));
}
"#;
        let normalized = normalize_cpp_for_hir(source);
        assert!(normalized.contains("__uniflow_lambda_callback"));
        let program = CppParser
            .parse_file("lambda.cpp", source)
            .expect("parse C++");
        let names = program.modules[0]
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Function(function) => Some(function.name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(names
            .iter()
            .any(|name| *name == "__uniflow_lambda_callback"));
        assert!(format!("{program:#?}").contains("system"));
    }

    #[test]
    fn restores_capturing_lambda_formals_from_bind_intrinsic() {
        let source = r#"
void run(char *prefix) {
    auto callback = [prefix](char *suffix) { return prefix; };
    callback(suffix());
}
"#;
        let program = CppParser
            .parse_file("capture.cpp", source)
            .expect("parse capturing C++ lambda");
        let lambda = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "__uniflow_lambda_callback" => {
                    Some(function)
                }
                _ => None,
            })
            .expect("synthetic lambda function");
        assert_eq!(lambda.params.len(), 1);
        assert_eq!(lambda.params[0].name, "suffix");
        assert_eq!(lambda.captures.len(), 1);
        assert_eq!(lambda.captures[0].name, "prefix");
    }

    #[test]
    fn records_cpp_virtual_and_ownership_semantics_on_symbols() {
        let source = r#"
class Base { public: virtual void run() = 0; };
class Child : public Base { public: void run() override; };
void Child::run() noexcept { }
std::unique_ptr<Child> child;
"#;
        let program = CppParser.parse_file("sample.cpp", source).expect("parse");
        assert!(program.symbols.iter().any(|symbol| symbol
            .attributes
            .get("cpp.override")
            .map(String::as_str)
            == Some("true")
            || symbol.attributes.get("cpp.noexcept").map(String::as_str) == Some("true")));
        assert!(program.symbols.iter().any(|symbol| symbol
            .attributes
            .get("cpp.ownership")
            .map(String::as_str)
            == Some("unique")));
        assert!(program
            .symbols
            .iter()
            .any(|symbol| symbol.cpp_method_semantics().is_some()));
        assert!(program
            .symbols
            .iter()
            .any(|symbol| symbol.cpp_ownership() == Some(uniflow_hir::CppOwnershipKind::Unique)));
    }

    #[test]
    fn parses_cpp_if_and_while_as_structured_hir() {
        let source = r#"
void run(int condition, int *value) {
    if (condition) { delete value; }
    while (condition) { consume(value); }
    consume(value);
}
"#;
        let program = CppParser
            .parse_file("control.cpp", source)
            .expect("parse C++ control flow");
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("run");
        assert!(function
            .body
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, uniflow_hir::Stmt::If { .. })));
        assert!(function
            .body
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, uniflow_hir::Stmt::While { .. })));
        assert!(function.body.stmts.len() >= 3);
    }

    #[test]
    fn inline_methods_are_qualified_and_keep_virtual_contracts() {
        let source = r#"
class Base {
public:
    virtual void run() = 0;
};
class Child : public Base {
public:
    void run() override final noexcept { }
};
"#;
        let normalized = normalize_cpp_for_hir(source);
        assert!(normalized.contains("Child::run"));
        let program = CppParser
            .parse_file("inline.cpp", source)
            .expect("parse inline methods");
        let child = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name == "Child" => Some(class),
                _ => None,
            })
            .expect("Child class");
        let run = child
            .methods
            .iter()
            .find(|method| method.name.ends_with("Child::run"))
            .expect("inline Child::run");
        let cpp = run.cpp.as_ref().expect("typed C++ method semantics");
        assert!(cpp.is_virtual && cpp.is_override && cpp.is_final && cpp.is_noexcept);
        assert!(program.symbols.iter().any(|symbol| {
            symbol
                .cpp_method_semantics()
                .is_some_and(|method| method.owner == "Base" && method.is_pure_virtual)
        }));
    }

    #[test]
    fn value_ownership_is_scoped_by_function_symbol_identity() {
        let source = r#"
struct Item { int value; };
void owning() {
    std::unique_ptr<Item> value = std::make_unique<Item>();
    consume(value);
}
void borrowed() {
    Item *value = nullptr;
    consume(value);
}
"#;
        let program = CppParser
            .parse_file("scoped.cpp", source)
            .expect("parse scoped ownership");
        let ownership = program
            .symbols
            .iter()
            .filter(|symbol| symbol.name == "value")
            .filter_map(|symbol| symbol.cpp_ownership())
            .collect::<std::collections::HashSet<_>>();
        assert!(ownership.contains(&uniflow_hir::CppOwnershipKind::Unique));
        assert!(ownership.contains(&uniflow_hir::CppOwnershipKind::Raw));
    }

    #[test]
    fn raii_cleanup_is_injected_at_lexical_scope_exit() {
        let source = r#"
struct Item { int value; };
void run() {
    std::unique_ptr<Item> owner = std::make_unique<Item>();
    consume(owner);
}
"#;
        let program = CppParser
            .parse_file("raii.cpp", source)
            .expect("parse RAII");
        let run = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("run");
        assert!(run.body.stmts.iter().any(|stmt| match stmt {
            uniflow_hir::Stmt::Expr {
                expr: uniflow_hir::Expr::Call(call),
                ..
            } => matches!(&call.target, uniflow_hir::CallTarget::Named(name) if name == "__uniflow_cpp_destroy"),
            _ => false,
        }));
    }

    #[test]
    fn raii_cleanup_before_return_is_not_duplicated() {
        let source = r#"
struct Item { int value; };
void run() {
    std::unique_ptr<Item> owner = std::make_unique<Item>();
    return;
}
"#;
        let program = CppParser
            .parse_file("raii_return.cpp", source)
            .expect("parse RAII return");
        let run = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("run");
        let destroy_count = run
            .body
            .stmts
            .iter()
            .filter(|stmt| match stmt {
                uniflow_hir::Stmt::Expr {
                    expr: uniflow_hir::Expr::Call(call),
                    ..
                } => matches!(
                    &call.target,
                    uniflow_hir::CallTarget::Named(name)
                        if name == "__uniflow_cpp_destroy"
                ),
                _ => false,
            })
            .count();
        assert_eq!(
            destroy_count, 1,
            "return cleanup must be emitted exactly once"
        );
        assert!(matches!(
            run.body.stmts.last(),
            Some(uniflow_hir::Stmt::Return { .. })
        ));
    }

    #[test]
    fn caught_throw_cleans_only_try_local_owners() {
        let source = r#"
struct Item { int value; };
void run() {
    std::unique_ptr<Item> outer = std::make_unique<Item>();
    try {
        std::unique_ptr<Item> inner = std::make_unique<Item>();
        throw 1;
    } catch (int error) {
        consume(outer);
    }
}
"#;
        let program = CppParser
            .parse_file("raii_caught_throw.cpp", source)
            .expect("parse caught throw cleanup");
        let run = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("run");
        let symbols = program
            .symbols
            .iter()
            .map(|symbol| (symbol.id, symbol.name.as_str()))
            .collect::<std::collections::HashMap<_, _>>();
        let try_block = run
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                uniflow_hir::Stmt::Try { try_block, .. } => Some(try_block),
                _ => None,
            })
            .expect("try block");
        let destroyed = try_block
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                uniflow_hir::Stmt::Expr {
                    expr: uniflow_hir::Expr::Call(call),
                    ..
                } if matches!(
                    &call.target,
                    uniflow_hir::CallTarget::Named(name)
                        if name == "__uniflow_cpp_destroy"
                ) =>
                {
                    call.args.first()
                }
                _ => None,
            })
            .filter_map(|expr| match expr {
                uniflow_hir::Expr::VarRef { symbol, .. } => symbols.get(symbol).copied(),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(destroyed, vec!["inner"]);
    }

    #[test]
    fn try_catch_and_throw_are_structured_hir() {
        let source = r#"
void run(int fail) {
    try {
        if (fail) { throw fail; }
    } catch (int error) {
        consume(error);
    }
}
"#;
        let program = CppParser
            .parse_file("exceptions.cpp", source)
            .expect("parse try/catch");
        let run = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("run");
        assert!(run.body.stmts.iter().any(|stmt| match stmt {
            uniflow_hir::Stmt::Try { catches, .. } => catches.len() == 1,
            _ => false,
        }));
    }
}
