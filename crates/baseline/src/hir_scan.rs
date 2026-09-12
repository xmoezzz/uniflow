use crate::{
    deduplicate_findings, rule_message, rule_path_matches, strip_comments_preserve_layout,
    BaselineFinding, BaselinePack, BaselineRule, BaselineScanOptions,
};
use regex::Regex;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};
use std::path::Path;
use uniflow_hir::{
    BinaryOp, Block, CallExpr, CallTarget, Expr, Function, Item, LValue, Language, LiteralKind,
    Program, Span, Stmt, SymbolId, UnaryOp,
};

impl BaselinePack {
    /// Scan parsed HIR using structured call/argument constraints, then apply
    /// source regexes only for rules without structured matchers.
    pub fn scan_hir(
        &self,
        program: &Program,
        source_by_path: &HashMap<String, String>,
    ) -> Vec<BaselineFinding> {
        self.scan_hir_with_options(program, source_by_path, &BaselineScanOptions::default())
    }

    pub fn scan_hir_with_options(
        &self,
        program: &Program,
        source_by_path: &HashMap<String, String>,
        options: &BaselineScanOptions,
    ) -> Vec<BaselineFinding> {
        let mut known_class_types = HashSet::new();
        let mut serializable_types = HashSet::new();
        let mut classes_with_equals = HashSet::new();
        if program.language == Language::Java {
            for source in source_by_path.values() {
                let syntax = uniflow_parser_core::java_syntax::JavaSyntax::parse(source);
                for declaration in syntax.declarations.iter().filter(|declaration| {
                    declaration.kind
                        == uniflow_parser_core::java_syntax::JavaDeclarationKind::Class
                }) {
                    known_class_types.insert(declaration.name.clone());
                    if declaration
                        .interfaces
                        .iter()
                        .any(|base| base.rsplit('.').next() == Some("Serializable"))
                    {
                        serializable_types.insert(declaration.name.clone());
                    }
                    let declaration_id = syntax
                        .declarations
                        .iter()
                        .position(|candidate| std::ptr::eq(candidate, declaration));
                    if declaration_id.is_some_and(|owner| {
                        syntax.declarations.iter().any(|member| {
                            member.owner == Some(owner)
                                && member.kind
                                    == uniflow_parser_core::java_syntax::JavaDeclarationKind::Method
                                && member.name == "equals"
                        })
                    }) {
                        classes_with_equals.insert(declaration.name.clone());
                    }
                }
            }
        }
        let (generic_call_rules, exact_call_rules) = build_call_rule_index(self, &program.language);
        let mut scanner = HirScanner {
            pack: self,
            language: &program.language,
            file_paths: program
                .files
                .iter()
                .map(|file| (file.id.0, file.path.clone()))
                .collect(),
            source_by_path,
            automatic_symbols: collect_automatic_symbols(program),
            parameter_symbols: program
                .symbols
                .iter()
                .filter(|symbol| matches!(symbol.kind, uniflow_hir::SymbolKind::Param))
                .map(|symbol| symbol.id)
                .collect(),
            types: HirTypes::new(program),
            symbol_names: program
                .symbols
                .iter()
                .map(|symbol| (symbol.id, symbol.name.clone()))
                .collect(),
            loop_depth: 0,
            finally_depth: 0,
            current_function_name: None,
            current_return_type: None,
            current_param_types: Vec::new(),
            sql_wildcard_symbols: HashMap::new(),
            sql_wildcard_fields: HashSet::new(),
            if_condition_depth: 0,
            has_following_statement: false,
            symbol_loop_depth: HashMap::new(),
            declaration_member_roots: HashMap::new(),
            checked_symbols: HashSet::new(),
            true_properties: HashSet::new(),
            present_optionals: HashSet::new(),
            catch_depth: 0,
            catch_symbols: HashSet::new(),
            string_constants: HashMap::new(),
            known_class_types,
            serializable_types,
            classes_with_equals,
            receiver_calls: HashSet::new(),
            generic_call_rules,
            exact_call_rules,
            callee_regexes: RefCell::new(HashMap::new()),
            findings: Vec::new(),
        };
        for module in &program.modules {
            for item in &module.items {
                scanner.visit_item(item);
            }
        }
        if program.language == Language::Java {
            for rule in &self.rules {
                let Some(check) = rule.matcher.java_project else {
                    continue;
                };
                if !rule.languages.is_empty() && !rule.languages.contains(&Language::Java) {
                    continue;
                }
                for (path, offset) in check.offsets(source_by_path) {
                    if !rule_path_matches(rule, &path) {
                        continue;
                    }
                    if let Some(source) = source_by_path.get(&path) {
                        scanner.findings.push(crate::finding_at_offset(
                            rule,
                            Path::new(&path),
                            source,
                            offset,
                        ));
                    }
                }
            }
        }
        let mut source_regexes = HashMap::new();
        for (path, source) in source_by_path {
            scanner.findings.extend(self.scan_source_rules_with_regex_cache(
                &program.language,
                Path::new(path),
                source,
                true,
                options,
                &mut source_regexes,
            ));
        }
        deduplicate_findings(scanner.findings)
    }
}

#[derive(Clone, Copy)]
enum ValueUse {
    Used,
    Discarded,
    AssignedTo(SymbolId),
}

struct HirScanner<'a> {
    pack: &'a BaselinePack,
    language: &'a Language,
    file_paths: HashMap<u32, String>,
    source_by_path: &'a HashMap<String, String>,
    automatic_symbols: HashSet<SymbolId>,
    parameter_symbols: HashSet<SymbolId>,
    types: HirTypes,
    symbol_names: HashMap<SymbolId, String>,
    loop_depth: usize,
    finally_depth: usize,
    current_function_name: Option<String>,
    current_return_type: Option<String>,
    current_param_types: Vec<String>,
    sql_wildcard_symbols: HashMap<SymbolId, bool>,
    sql_wildcard_fields: HashSet<String>,
    if_condition_depth: usize,
    has_following_statement: bool,
    symbol_loop_depth: HashMap<SymbolId, usize>,
    declaration_member_roots: HashMap<SymbolId, Vec<(String, bool)>>,
    checked_symbols: HashSet<SymbolId>,
    true_properties: HashSet<(SymbolId, String)>,
    present_optionals: HashSet<SymbolId>,
    catch_depth: usize,
    catch_symbols: HashSet<SymbolId>,
    string_constants: HashMap<SymbolId, String>,
    known_class_types: HashSet<String>,
    serializable_types: HashSet<String>,
    classes_with_equals: HashSet<String>,
    receiver_calls: HashSet<(SymbolId, String)>,
    /// HIR call rules whose callee cannot be represented by one literal name.
    /// These are deliberately kept as a fallback so regex semantics remain
    /// unchanged while common exact-name rules avoid a full pack traversal.
    generic_call_rules: Vec<usize>,
    /// Exact identifier callees to their HIR rule positions in `pack.rules`.
    exact_call_rules: HashMap<String, Vec<usize>>,
    /// Regex compilation dominates a large scan when it happens once per call.
    /// This cache is local to one scanner, so it is bounded by the bundled rule
    /// set and needs neither global synchronization nor process-lifetime memory.
    callee_regexes: RefCell<HashMap<String, Option<Regex>>>,
    findings: Vec<BaselineFinding>,
}

fn build_call_rule_index(
    pack: &BaselinePack,
    language: &Language,
) -> (Vec<usize>, HashMap<String, Vec<usize>>) {
    let mut generic = Vec::new();
    let mut exact = HashMap::<String, Vec<usize>>::new();
    for (index, rule) in pack.rules.iter().enumerate() {
        if !rule.matcher.requires_hir()
            || (!rule.languages.is_empty() && !rule.languages.contains(language))
        {
            continue;
        }
        let patterns = if rule.matcher.call_alternatives.is_empty() {
            vec![effective_callee_pattern(rule)]
        } else {
            rule.matcher
                .call_alternatives
                .iter()
                .map(|matcher| {
                    if matcher.callee.is_empty() {
                        rule.pattern.as_str()
                    } else {
                        matcher.callee.as_str()
                    }
                })
                .collect()
        };
        if patterns.iter().all(|pattern| pattern.is_empty()) {
            continue;
        }
        let exact_names = patterns
            .iter()
            .map(|pattern| exact_identifier_callee(pattern))
            .collect::<Option<Vec<_>>>();
        let Some(exact_names) = exact_names else {
            generic.push(index);
            continue;
        };
        for name in exact_names {
            let entries = exact.entry(name.to_string()).or_default();
            if !entries.contains(&index) {
                entries.push(index);
            }
        }
    }
    (generic, exact)
}

fn effective_callee_pattern(rule: &BaselineRule) -> &str {
    if rule.matcher.callee.is_empty() {
        rule.pattern.as_str()
    } else {
        rule.matcher.callee.as_str()
    }
}

/// Only index patterns whose regex spelling proves they match exactly one HIR
/// identifier. Every other regex stays in the generic candidate list, which
/// makes this a semantics-preserving optimization.
fn exact_identifier_callee(pattern: &str) -> Option<&str> {
    let name = pattern.strip_prefix('^')?.strip_suffix('$')?;
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then_some(name)
}

impl HirScanner<'_> {
    fn visit_item(&mut self, item: &Item) {
        match item {
            Item::Function(function) => self.visit_function(function),
            Item::Class(class) => {
                let previous_sql_symbols = self.sql_wildcard_symbols.clone();
                let previous_sql_fields = self.sql_wildcard_fields.clone();
                for field in &class.fields {
                    let is_string = field
                        .ty
                        .and_then(|ty| self.types.names.get(&ty))
                        .is_some_and(|ty| ty.rsplit('.').next() == Some("String"));
                    if let Some(symbol) = field.symbol {
                        if let Some(source) = self.span_source(field.span) {
                            self.declaration_member_roots
                                .insert(symbol, source_initializer_member_roots(source));
                        }
                        let risky = is_string
                            && self
                                .span_source(field.span)
                                .is_some_and(has_sql_wildcard_text);
                        self.sql_wildcard_symbols.insert(symbol, risky);
                        if risky {
                            self.sql_wildcard_fields.insert(field.name.clone());
                        }
                    }
                }
                for method in &class.methods {
                    self.visit_function(method);
                }
                self.sql_wildcard_symbols = previous_sql_symbols;
                self.sql_wildcard_fields = previous_sql_fields;
            }
            Item::GlobalVar(global) => {
                if let Some(init) = &global.init {
                    self.visit_expr(init, ValueUse::Used);
                }
            }
        }
    }

    fn visit_function(&mut self, function: &Function) {
        let previous_checked = std::mem::take(&mut self.checked_symbols);
        let previous_properties = std::mem::take(&mut self.true_properties);
        let previous_present_optionals = std::mem::take(&mut self.present_optionals);
        let previous_catch = std::mem::replace(&mut self.catch_depth, 0);
        collect_true_properties(&function.body, &mut self.true_properties);
        let previous_name = self.current_function_name.replace(function.name.clone());
        let previous_return = self.current_return_type.take();
        self.current_return_type = function
            .return_type
            .and_then(|ty| self.types.names.get(&ty).cloned());
        let previous_param_types = std::mem::replace(
            &mut self.current_param_types,
            function
                .params
                .iter()
                .filter_map(|param| param.ty.and_then(|ty| self.types.names.get(&ty).cloned()))
                .collect(),
        );
        let previous_sql_symbols = self.sql_wildcard_symbols.clone();
        let previous_loop_symbols = self.symbol_loop_depth.clone();
        let previous_string_constants = std::mem::take(&mut self.string_constants);
        let previous_receiver_calls = std::mem::take(&mut self.receiver_calls);
        for param in &function.params {
            let is_string = param
                .ty
                .and_then(|ty| self.types.names.get(&ty))
                .is_some_and(|ty| ty.rsplit('.').next() == Some("String"));
            self.sql_wildcard_symbols.insert(param.symbol, is_string);
            self.symbol_loop_depth.insert(param.symbol, 0);
        }
        if let Some(receiver) = &function.receiver {
            self.types.bind(receiver.symbol, receiver.ty);
        }
        self.match_missing_contract_null_check(function);
        self.match_unreleased_resources(function);
        self.match_null_safety(function);
        self.match_external_process_buffers(function);
        self.match_conflicting_expression_side_effects(function);
        self.visit_block(&function.body);
        self.current_function_name = previous_name;
        self.current_return_type = previous_return;
        self.current_param_types = previous_param_types;
        self.sql_wildcard_symbols = previous_sql_symbols;
        self.symbol_loop_depth = previous_loop_symbols;
        self.string_constants = previous_string_constants;
        self.receiver_calls = previous_receiver_calls;
        self.checked_symbols = previous_checked;
        self.true_properties = previous_properties;
        self.present_optionals = previous_present_optionals;
        self.catch_depth = previous_catch;
    }

    fn visit_block(&mut self, block: &Block) {
        let previous_checked = self.checked_symbols.clone();
        for pair in block.stmts.windows(2) {
            let first_assignment = match &pair[0] {
                Stmt::Let {
                    symbol,
                    init: Some(_),
                    span,
                    ..
                }
                | Stmt::Assign {
                    lhs: LValue::Var(symbol),
                    span,
                    ..
                } => Some((*symbol, *span)),
                _ => None,
            };
            if let (
                Some((symbol, span)),
                Stmt::Assign {
                    lhs: LValue::Var(next),
                    rhs,
                    ..
                },
            ) = (first_assignment, &pair[1])
            {
                if symbol == *next && !expr_references_symbol(rhs, symbol) {
                    let rules = self
                        .pack
                        .rules
                        .iter()
                        .filter(|rule| {
                            rule.matcher.redundant_reassignment
                                && (rule.languages.is_empty()
                                    || rule.languages.contains(self.language))
                                && self.rule_matches_span_path(rule, span)
                        })
                        .collect::<Vec<_>>();
                    for rule in rules {
                        self.push_finding(rule, "redundant assignment", span);
                    }
                }
            }
            let Stmt::Return {
                value: Some(Expr::VarRef { symbol, .. }),
                span,
                ..
            } = &pair[1]
            else {
                continue;
            };
            let assigned_null = match &pair[0] {
                Stmt::Let {
                    symbol: assigned,
                    init: Some(value),
                    ..
                }
                | Stmt::Assign {
                    lhs: LValue::Var(assigned),
                    rhs: value,
                    ..
                } => assigned == symbol && is_null_literal(value),
                _ => false,
            };
            if assigned_null {
                let rules = self
                    .pack
                    .rules
                    .iter()
                    .filter(|rule| {
                        rule.matcher.return_preceded_by_null_assignment
                            && (rule.languages.is_empty() || rule.languages.contains(self.language))
                            && self.rule_matches_span_path(rule, *span)
                    })
                    .collect::<Vec<_>>();
                for rule in rules {
                    self.push_finding(rule, "return after null assignment", *span);
                }
            }
        }
        for (index, stmt) in block.stmts.iter().enumerate() {
            let previous_following = self.has_following_statement;
            self.has_following_statement |= index + 1 < block.stmts.len();
            self.visit_stmt(stmt);
            if let Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } = stmt
            {
                collect_checked_symbols(cond, &mut self.checked_symbols);
                visit_block_expressions(then_block, &mut |expr| {
                    collect_checked_symbols(expr, &mut self.checked_symbols)
                });
                if let Some(block) = else_block {
                    visit_block_expressions(block, &mut |expr| {
                        collect_checked_symbols(expr, &mut self.checked_symbols)
                    });
                }
            }
            self.has_following_statement = previous_following;
        }
        self.checked_symbols = previous_checked;
    }

    fn match_missing_contract_null_check(&mut self, function: &Function) {
        let method_name = function.name.rsplit('.').next().unwrap_or(&function.name);
        let expected_arity = match method_name {
            "equals" | "compareTo" => 1,
            "compare" => 2,
            _ => return,
        };
        if function.params.len() != expected_arity {
            return;
        }
        let parameters = function
            .params
            .iter()
            .map(|parameter| parameter.symbol)
            .collect::<HashSet<_>>();
        let mut checked = HashSet::new();
        visit_block_expressions(&function.body, &mut |expr| {
            let Expr::Binary { op, lhs, rhs, .. } = expr else {
                return;
            };
            if !matches!(op, BinaryOp::Eq | BinaryOp::Ne) {
                return;
            }
            match (&**lhs, &**rhs) {
                (Expr::VarRef { symbol, .. }, value)
                    if parameters.contains(symbol) && is_null_literal(value) =>
                {
                    checked.insert(*symbol);
                }
                (value, Expr::VarRef { symbol, .. })
                    if parameters.contains(symbol) && is_null_literal(value) =>
                {
                    checked.insert(*symbol);
                }
                _ => {}
            }
        });
        if checked.len() == parameters.len() {
            return;
        }
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                rule.matcher.missing_contract_null_check
                    && (rule.languages.is_empty() || rule.languages.contains(self.language))
                    && self.rule_matches_span_path(rule, function.span)
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, "missing null contract check", function.span);
        }
    }

    fn match_external_process_buffers(&mut self, function: &Function) {
        if !self
            .pack
            .rules
            .iter()
            .any(|rule| rule.matcher.external_process_wait_without_io_drain)
        {
            return;
        }

        let mut processes = self
            .types
            .symbols
            .iter()
            .filter_map(|(symbol, ty)| {
                (ty.rsplit('.').next() == Some("Process"))
                    .then_some((*symbol, ProcessIoStatus::default()))
            })
            .collect::<HashMap<_, _>>();
        let mut builders = self
            .types
            .symbols
            .iter()
            .filter_map(|(symbol, ty)| {
                (ty.rsplit('.').next() == Some("ProcessBuilder"))
                    .then_some((*symbol, ProcessBuilderIo::default()))
            })
            .collect::<HashMap<_, _>>();
        let mut streams = HashMap::new();
        let mut events = Vec::new();
        visit_block_statements(&function.body, &mut |statement| match statement {
            Stmt::Let {
                symbol,
                init: Some(rhs),
                span,
                ..
            } => events.push(ProcessRawEvent::Assign {
                symbol: *symbol,
                rhs: rhs.clone(),
                offset: span.start_byte,
            }),
            Stmt::Assign {
                lhs: LValue::Var(symbol),
                rhs,
                span,
                ..
            } => events.push(ProcessRawEvent::Assign {
                symbol: *symbol,
                rhs: rhs.clone(),
                offset: span.start_byte,
            }),
            _ => {}
        });
        visit_block_expressions(&function.body, &mut |expression| {
            visit_expression_nodes(expression, &mut |node| {
                if let Expr::Call(call) = node {
                    events.push(ProcessRawEvent::Call(call.clone()));
                }
            })
        });
        events.sort_by_key(|event| event.sort_key());

        for event in events {
            match event {
                ProcessRawEvent::Assign { symbol, rhs, .. } => {
                    if let Some(status) = process_creation_status(&rhs, &builders) {
                        processes.insert(symbol, status);
                    }
                    if let Some(stream) = process_stream_source(&rhs, &processes, &streams) {
                        streams.insert(symbol, stream);
                    }
                }
                ProcessRawEvent::Call(call) => {
                    let name = call_target_name(&call)
                        .and_then(|name| name.rsplit('.').next())
                        .unwrap_or_default();
                    let receiver = call.receiver.as_deref().and_then(referenced_symbol);
                    if let Some(builder) = receiver.and_then(|symbol| builders.get_mut(&symbol)) {
                        match name {
                            "redirectErrorStream"
                                if call.args.first().is_some_and(|argument| {
                                    matches!(
                                        argument,
                                        Expr::Literal {
                                            kind: LiteralKind::Bool(true),
                                            ..
                                        }
                                    )
                                }) =>
                            {
                                builder.merge_error = true;
                            }
                            "redirectOutput" => builder.output_redirected = true,
                            "redirectError" => builder.error_redirected = true,
                            "inheritIO" => {
                                builder.output_redirected = true;
                                builder.error_redirected = true;
                            }
                            _ => {}
                        }
                    }

                    if matches!(
                        name,
                        "read" | "readAllBytes" | "transferTo" | "lines" | "copyTo"
                    ) {
                        if let Some((process, stream)) = call
                            .receiver
                            .as_deref()
                            .and_then(|receiver| {
                                process_stream_source(receiver, &processes, &streams)
                            })
                        {
                            if let Some(status) = processes.get_mut(&process) {
                                match stream {
                                    ProcessStream::Output => status.output_drained = true,
                                    ProcessStream::Error => status.error_drained = true,
                                }
                            }
                        }
                    }

                    if name == "waitFor" {
                        let Some(process) = receiver else {
                            continue;
                        };
                        let Some(status) = processes.get(&process) else {
                            continue;
                        };
                        let output_safe = status.output_redirected || status.output_drained;
                        let error_safe = status.error_redirected
                            || status.error_drained
                            || status.merge_error && output_safe;
                        if output_safe && error_safe {
                            continue;
                        }
                        let rules = self
                            .pack
                            .rules
                            .iter()
                            .filter(|rule| {
                                rule.matcher.external_process_wait_without_io_drain
                                    && (rule.languages.is_empty()
                                        || rule.languages.contains(self.language))
                                    && self.rule_matches_span_path(rule, call.span)
                            })
                            .collect::<Vec<_>>();
                        for rule in rules {
                            self.push_finding(rule, "process buffers not drained", call.span);
                        }
                    }
                }
            }
        }
    }

    fn match_conflicting_expression_side_effects(&mut self, function: &Function) {
        if !self
            .pack
            .rules
            .iter()
            .any(|rule| rule.matcher.conflicting_side_effects_in_expression)
        {
            return;
        }
        let mut matches = Vec::new();
        visit_block_expressions(&function.body, &mut |expression| {
            let mut written = HashSet::new();
            if expression_has_access_after_write(expression, &mut written) {
                matches.push(argument_span(expression));
            }
        });
        for span in matches {
            let rules = self
                .pack
                .rules
                .iter()
                .filter(|rule| {
                    rule.matcher.conflicting_side_effects_in_expression
                        && (rule.languages.is_empty() || rule.languages.contains(self.language))
                        && self.rule_matches_span_path(rule, span)
                })
                .collect::<Vec<_>>();
            for rule in rules {
                self.push_finding(rule, "access after write in expression", span);
            }
        }
    }

    fn match_unreleased_resources(&mut self, function: &Function) {
        let mut events = ResourceEvents::default();
        collect_resource_block(&function.body, 0, 0, &mut events);
        let rules = self
            .pack
            .rules
            .iter()
            .filter_map(|rule| {
                if rule.matcher.unreleased_resource_type_pattern.is_empty()
                    || (!rule.languages.is_empty() && !rule.languages.contains(self.language))
                {
                    return None;
                }
                Regex::new(&rule.matcher.unreleased_resource_type_pattern)
                    .ok()
                    .map(|regex| (rule, regex))
            })
            .collect::<Vec<_>>();
        for (rule, type_regex) in rules {
            for (symbol, span) in &events.acquisitions {
                if !events.closed.contains(symbol)
                    && self
                        .types
                        .symbols
                        .get(symbol)
                        .is_some_and(|ty| type_regex.is_match(ty))
                    && self.rule_matches_span_path(rule, *span)
                {
                    self.push_finding(rule, "unreleased resource", *span);
                }
            }
            for (symbol, span) in &events.close_in_try {
                if self
                    .types
                    .symbols
                    .get(symbol)
                    .is_some_and(|ty| type_regex.is_match(ty))
                    && self.rule_matches_span_path(rule, *span)
                {
                    self.push_finding(rule, "resource close outside finally", *span);
                }
            }
        }
        let use_after_release_rules = self
            .pack
            .rules
            .iter()
            .filter_map(|rule| {
                if rule
                    .matcher
                    .resource_use_after_release_type_pattern
                    .is_empty()
                    || (!rule.languages.is_empty() && !rule.languages.contains(self.language))
                {
                    return None;
                }
                Regex::new(&rule.matcher.resource_use_after_release_type_pattern)
                    .ok()
                    .map(|regex| (rule, regex))
            })
            .collect::<Vec<_>>();
        for (rule, type_regex) in use_after_release_rules {
            let mut released = HashSet::new();
            for event in &events.lifecycle {
                let (symbol, span) = match event {
                    ResourceLifecycleEvent::Acquire(symbol) => {
                        released.remove(symbol);
                        continue;
                    }
                    ResourceLifecycleEvent::Release(symbol) => {
                        released.insert(*symbol);
                        continue;
                    }
                    ResourceLifecycleEvent::Use(symbol, span) => (*symbol, *span),
                };
                if released.contains(&symbol)
                    && self
                        .types
                        .symbols
                        .get(&symbol)
                        .is_some_and(|ty| type_regex.is_match(ty))
                    && self.rule_matches_span_path(rule, span)
                {
                    self.push_finding(rule, "resource used after release", span);
                }
            }
        }
        let lock_rules = self.pack.rules.clone();
        for rule in &lock_rules {
            if !rule.languages.is_empty() && !rule.languages.contains(self.language) {
                continue;
            }
            let acquired = Regex::new(&rule.matcher.lock_acquired_twice_type_pattern).ok();
            let released = Regex::new(&rule.matcher.lock_released_twice_type_pattern).ok();
            let unreleased = Regex::new(&rule.matcher.unreleased_lock_type_pattern).ok();
            if acquired.is_none()
                && released.is_none()
                && unreleased.is_none()
                && !rule.matcher.sleep_while_lock_held
            {
                continue;
            }
            let mut depths = HashMap::<SymbolId, (usize, Span)>::new();
            for event in &events.lock_lifecycle {
                let (symbol, span, is_acquire) = match event {
                    LockLifecycleEvent::Sleep(span) => {
                        if rule.matcher.sleep_while_lock_held
                            && depths.values().any(|(depth, _)| *depth > 0)
                            && self.rule_matches_span_path(rule, *span)
                        {
                            self.push_finding(rule, "sleep while holding lock", *span);
                        }
                        continue;
                    }
                    LockLifecycleEvent::Acquire(symbol, span) => (*symbol, *span, true),
                    LockLifecycleEvent::Release(symbol, span) => (*symbol, *span, false),
                };
                let Some(ty) = self.types.symbols.get(&symbol) else {
                    continue;
                };
                let entry = depths.entry(symbol).or_insert((0, span));
                if is_acquire {
                    if entry.0 > 0
                        && acquired.as_ref().is_some_and(|regex| regex.is_match(ty))
                        && self.rule_matches_span_path(rule, span)
                    {
                        self.push_finding(rule, "lock acquired repeatedly", span);
                    }
                    if entry.0 == 0 {
                        entry.1 = span;
                    }
                    entry.0 += 1;
                } else if entry.0 == 0 {
                    if released.as_ref().is_some_and(|regex| regex.is_match(ty))
                        && self.rule_matches_span_path(rule, span)
                    {
                        self.push_finding(rule, "lock released repeatedly", span);
                    }
                } else {
                    entry.0 -= 1;
                }
            }
            if let Some(regex) = unreleased {
                for (symbol, (depth, span)) in &depths {
                    if *depth > 0
                        && self
                            .types
                            .symbols
                            .get(symbol)
                            .is_some_and(|ty| regex.is_match(ty))
                        && self.rule_matches_span_path(rule, *span)
                    {
                        self.push_finding(rule, "unreleased synchronization lock", *span);
                    }
                }
            }
        }
        for rule in &self.pack.rules {
            if (!rule.matcher.temporary_file_not_deleted
                && !rule.matcher.temp_file_directory_conversion)
                || (!rule.languages.is_empty() && !rule.languages.contains(self.language))
            {
                continue;
            }
            let mut created = HashMap::<SymbolId, Span>::new();
            let mut deleted = HashSet::<SymbolId>::new();
            for event in &events.temp_files {
                match event {
                    TempFileEvent::Create(symbol, span) => {
                        created.insert(*symbol, *span);
                        deleted.remove(symbol);
                    }
                    TempFileEvent::Delete(symbol) => {
                        deleted.insert(*symbol);
                    }
                    TempFileEvent::Mkdir(symbol, span) => {
                        if rule.matcher.temp_file_directory_conversion
                            && created.contains_key(symbol)
                            && deleted.contains(symbol)
                            && self.rule_matches_span_path(rule, *span)
                        {
                            self.push_finding(rule, "temporary file converted to directory", *span);
                        }
                    }
                }
            }
            if rule.matcher.temporary_file_not_deleted {
                for (symbol, span) in created {
                    if !deleted.contains(&symbol) && self.rule_matches_span_path(rule, span) {
                        self.push_finding(rule, "temporary file not deleted", span);
                    }
                }
            }
        }
    }

    fn match_null_safety(&mut self, function: &Function) {
        let mut events = Vec::new();
        analyze_null_block(&function.body, &mut HashMap::new(), &mut events);
        for (kind, span) in events {
            let rules = self
                .pack
                .rules
                .iter()
                .filter(|rule| {
                    (rule.languages.is_empty() || rule.languages.contains(self.language))
                        && self.rule_matches_span_path(rule, span)
                        && match kind {
                            NullSafetyEvent::DefiniteDereference => {
                                rule.matcher.definite_null_dereference
                            }
                            NullSafetyEvent::NullableDereference => {
                                rule.matcher.nullable_return_dereference
                            }
                            NullSafetyEvent::RedundantCheck => rule.matcher.redundant_null_check,
                        }
                })
                .collect::<Vec<_>>();
            for rule in rules {
                let message = match kind {
                    NullSafetyEvent::DefiniteDereference => "definite null dereference",
                    NullSafetyEvent::NullableDereference => "unchecked nullable API result",
                    NullSafetyEvent::RedundantCheck => "redundant null check",
                };
                self.push_finding(rule, message, span);
            }
        }
    }

    fn match_string_loop_assignment(&mut self, symbol: SymbolId, rhs: &Expr, span: Span) {
        if self.loop_depth == 0
            || self
                .symbol_loop_depth
                .get(&symbol)
                .is_none_or(|depth| *depth >= self.loop_depth)
            || self
                .types
                .symbols
                .get(&symbol)
                .is_none_or(|ty| ty.rsplit('.').next() != Some("String"))
            || !matches!(
                rhs,
                Expr::Binary {
                    op: BinaryOp::Add,
                    ..
                }
            )
            || !expr_references_symbol(rhs, symbol)
            || self
                .span_source(span)
                .is_none_or(|source| !has_plain_assignment(source))
        {
            return;
        }
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                rule.matcher.string_self_concatenation_in_loop
                    && (rule.languages.is_empty() || rule.languages.contains(self.language))
                    && self.rule_matches_span_path(rule, span)
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, "String concatenation in loop", span);
        }
    }

    fn match_string_field_loop_assignment(
        &mut self,
        base: &Expr,
        field: &str,
        rhs: &Expr,
        span: Span,
    ) {
        let field_is_string = self
            .types
            .resolve(base)
            .and_then(|owner| self.types.fields.get(&(owner.to_owned(), field.to_owned())))
            .is_some_and(|ty| ty.rsplit('.').next() == Some("String"));
        if self.loop_depth == 0
            || !field_is_string
            || !matches!(
                rhs,
                Expr::Binary {
                    op: BinaryOp::Add,
                    ..
                }
            )
            || !expr_references_field(rhs, &expression_fingerprint(base), field)
            || self
                .span_source(span)
                .is_none_or(|source| !has_plain_assignment(source))
        {
            return;
        }
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                rule.matcher.string_self_concatenation_in_loop
                    && (rule.languages.is_empty() || rule.languages.contains(self.language))
                    && self.rule_matches_span_path(rule, span)
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, "String concatenation in loop", span);
        }
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let {
                symbol,
                ty,
                init,
                span,
                ..
            } => {
                self.types.bind(*symbol, *ty);
                self.symbol_loop_depth.insert(*symbol, self.loop_depth);
                self.sql_wildcard_symbols
                    .insert(*symbol, init.as_ref().is_some_and(expr_has_sql_wildcard));
                if let Some(expr) = init {
                    self.match_assignment(&LValue::Var(*symbol), expr, *span);
                    self.declaration_member_roots
                        .insert(*symbol, initializer_member_roots(expr, &self.symbol_names));
                    self.visit_expr(expr, ValueUse::AssignedTo(*symbol));
                    self.update_string_constant(*symbol, expr);
                }
            }
            Stmt::Assign { lhs, rhs, span, .. } => {
                self.match_assignment(lhs, rhs, *span);
                match lhs {
                    LValue::Var(symbol) => self.match_string_loop_assignment(*symbol, rhs, *span),
                    LValue::Field { base, field } => {
                        self.match_string_field_loop_assignment(base, field, rhs, *span)
                    }
                    _ => {}
                }
                self.visit_lvalue(lhs);
                let usage = match lhs {
                    LValue::Var(symbol) => {
                        self.sql_wildcard_symbols
                            .insert(*symbol, expr_has_sql_wildcard(rhs));
                        ValueUse::AssignedTo(*symbol)
                    }
                    _ => ValueUse::Used,
                };
                self.visit_expr(rhs, usage);
                if let LValue::Var(symbol) = lhs {
                    self.update_string_constant(*symbol, rhs);
                }
            }
            Stmt::Expr { expr, .. } => self.visit_expr(expr, ValueUse::Discarded),
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                self.if_condition_depth += 1;
                self.visit_expr(cond, ValueUse::Used);
                self.if_condition_depth -= 1;
                let checked = self.checked_symbols.clone();
                let guarded_optional = optional_present_symbol(cond);
                collect_checked_symbols(cond, &mut self.checked_symbols);
                if let Some(symbol) = guarded_optional {
                    self.present_optionals.insert(symbol);
                }
                self.visit_block(then_block);
                if let Some(symbol) = guarded_optional {
                    self.present_optionals.remove(&symbol);
                }
                if let Some(block) = else_block {
                    self.visit_block(block);
                }
                self.checked_symbols = checked;
            }
            Stmt::While {
                cond, body, span, ..
            } => {
                self.loop_depth += 1;
                self.match_loop_condition(cond, *span);
                self.visit_expr(cond, ValueUse::Used);
                self.visit_block(body);
                self.loop_depth -= 1;
            }
            Stmt::DoWhile {
                cond, body, span, ..
            } => {
                self.loop_depth += 1;
                self.match_loop_condition(cond, *span);
                // The body runs before the test, so visit it first.
                self.visit_block(body);
                self.visit_expr(cond, ValueUse::Used);
                self.loop_depth -= 1;
            }
            Stmt::Switch {
                scrutinee,
                clauses,
                default,
                ..
            } => {
                self.visit_expr(scrutinee, ValueUse::Used);
                for clause in clauses {
                    for value in &clause.values {
                        self.visit_expr(value, ValueUse::Used);
                    }
                    self.visit_block(&clause.body);
                }
                if let Some(block) = default {
                    self.visit_block(block);
                }
            }
            Stmt::Break { .. } | Stmt::Continue { .. } => {}
            Stmt::ForEach {
                item_symbol,
                iterable,
                body,
                span,
                ..
            } => {
                self.loop_depth += 1;
                if block_assigns_symbol(body, *item_symbol) {
                    let rules = self
                        .pack
                        .rules
                        .iter()
                        .filter(|rule| {
                            rule.matcher.foreach_item_reassigned
                                && (rule.languages.is_empty()
                                    || rule.languages.contains(self.language))
                                && self.rule_matches_span_path(rule, *span)
                        })
                        .collect::<Vec<_>>();
                    for rule in rules {
                        self.push_finding(rule, "enhanced-for item reassigned", *span);
                    }
                }
                self.visit_expr(iterable, ValueUse::Used);
                self.visit_block(body);
                self.loop_depth -= 1;
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
                span,
                ..
            } => {
                self.loop_depth += 1;
                self.visit_block(init);
                if let Some(cond) = cond {
                    self.match_loop_condition(cond, *span);
                    self.visit_expr(cond, ValueUse::Used);
                }
                self.visit_block(body);
                self.visit_block(update);
                self.loop_depth -= 1;
            }
            Stmt::Return { value, span, .. } => {
                if self.finally_depth != 0 {
                    self.match_finally_transfer(true, *span);
                }
                if value.as_ref().is_some_and(is_null_literal) {
                    self.match_null_return(*span);
                }
                if let Some(expr) = value {
                    self.visit_expr(expr, ValueUse::Used);
                }
            }
            Stmt::Throw { value, span, .. } => {
                if self.finally_depth != 0 {
                    self.match_finally_transfer(false, *span);
                }
                if let Some(expr) = value {
                    self.visit_expr(expr, ValueUse::Used);
                }
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                self.visit_block(try_block);
                for catch in catches {
                    if catch.body.stmts.is_empty() {
                        let rules = self
                            .pack
                            .rules
                            .iter()
                            .filter(|rule| {
                                rule.matcher.empty_catch
                                    && (rule.languages.is_empty()
                                        || rule.languages.contains(self.language))
                                    && self.rule_matches_span_path(rule, catch.span)
                            })
                            .collect::<Vec<_>>();
                        for rule in rules {
                            self.push_finding(rule, "empty catch clause", catch.span);
                        }
                    }
                    if let Some(ty) = catch
                        .ty
                        .and_then(|id| self.types.names.get(&id))
                        .cloned()
                    {
                        let rules = self
                            .pack
                            .rules
                            .iter()
                            .filter(|rule| {
                                let pattern = &rule.matcher.catch_type_pattern;
                                !pattern.is_empty()
                                    && (rule.languages.is_empty()
                                        || rule.languages.contains(self.language))
                                    && self.rule_matches_span_path(rule, catch.span)
                                    && Regex::new(pattern).is_ok_and(|regex| regex.is_match(&ty))
                                    && (!rule.matcher.catch_must_rethrow
                                        || catch.symbol.is_none_or(|symbol| {
                                            !block_throws_symbol(&catch.body, symbol)
                                        }))
                                    && (!rule.matcher.catch_must_handle
                                        || catch.body.stmts.is_empty())
                            })
                            .collect::<Vec<_>>();
                        for rule in rules {
                            self.push_finding(rule, "catch clause", catch.span);
                        }
                        if matches!(
                            ty.rsplit('.').next(),
                            Some("SecurityException" | "AccessControlException")
                        ) {
                            let mut unsafe_calls = Vec::new();
                            visit_block_expressions(&catch.body, &mut |expression| {
                                visit_expression_nodes(expression, &mut |node| {
                                    let Expr::Call(call) = node else {
                                        return;
                                    };
                                    let name = call_target_name(call)
                                        .and_then(|name| name.rsplit('.').next())
                                        .unwrap_or_default();
                                    let receiver_path = call
                                        .receiver
                                        .as_deref()
                                        .and_then(|receiver| {
                                            expression_path(receiver, &self.symbol_names)
                                        })
                                        .unwrap_or_default();
                                    let prints_caught_exception = catch.symbol.is_some_and(|symbol| {
                                        call.args.iter().any(|argument| {
                                            expr_references_symbol(argument, symbol)
                                        })
                                    });
                                    let direct_stack_trace = name == "printStackTrace"
                                        && catch.symbol.is_some_and(|symbol| {
                                            call.receiver
                                                .as_deref()
                                                .and_then(referenced_symbol)
                                                == Some(symbol)
                                        });
                                    let unsafe_console = matches!(
                                        name,
                                        "print" | "println" | "printf" | "format"
                                    ) && prints_caught_exception
                                        && (receiver_path.ends_with("System.err")
                                            || receiver_path.ends_with("System.out")
                                            || call.receiver.as_deref().is_some_and(|receiver| {
                                                self.types.resolve(receiver).is_some_and(|ty| {
                                                    ty.rsplit('.').next() == Some("Console")
                                                })
                                            }));
                                    if direct_stack_trace || unsafe_console {
                                        unsafe_calls.push(call.span);
                                    }
                                })
                            });
                            for span in unsafe_calls {
                                let rules = self
                                    .pack
                                    .rules
                                    .iter()
                                    .filter(|rule| {
                                        rule.matcher.unsafe_security_exception_logging
                                            && (rule.languages.is_empty()
                                                || rule.languages.contains(self.language))
                                            && self.rule_matches_span_path(rule, span)
                                    })
                                    .collect::<Vec<_>>();
                                for rule in rules {
                                    self.push_finding(
                                        rule,
                                        "unsafe security exception logging",
                                        span,
                                    );
                                }
                            }
                        }
                    }
                    if let Some(symbol) = catch.symbol {
                        self.types.bind(symbol, catch.ty);
                        self.catch_symbols.insert(symbol);
                    }
                    self.catch_depth += 1;
                    self.visit_block(&catch.body);
                    self.catch_depth -= 1;
                }
                if let Some(block) = finally_block {
                    self.finally_depth += 1;
                    self.visit_block(block);
                    self.finally_depth -= 1;
                }
            }
        }
    }

    fn visit_lvalue(&mut self, value: &LValue) {
        match value {
            LValue::Var(_) => {}
            LValue::Field { base, .. } => self.visit_expr(base, ValueUse::Used),
            LValue::Index { base, index } => {
                self.visit_expr(base, ValueUse::Used);
                self.visit_expr(index, ValueUse::Used);
            }
        }
    }

    fn visit_expr(&mut self, expr: &Expr, usage: ValueUse) {
        match expr {
            Expr::VarRef { .. } | Expr::Literal { .. } | Expr::Unknown { .. } => {}
            Expr::Unary { expr, .. } => self.visit_expr(expr, usage),
            Expr::Cast { ty, expr, span, .. } => {
                self.match_numeric_cast(*ty, expr, *span);
                self.visit_expr(expr, usage);
            }
            Expr::Binary {
                op, lhs, rhs, span, ..
            } => {
                self.match_binary(*op, lhs, rhs, *span);
                if matches!(op, BinaryOp::Div | BinaryOp::Mod)
                    && integer_literal_value(rhs) == Some(0)
                {
                    let rules = self
                        .pack
                        .rules
                        .iter()
                        .filter(|rule| {
                            rule.matcher.division_by_literal_zero
                                && (rule.languages.is_empty()
                                    || rule.languages.contains(self.language))
                                && self.rule_matches_span_path(rule, *span)
                        })
                        .collect::<Vec<_>>();
                    for rule in rules {
                        self.push_finding(rule, "division by zero", *span);
                    }
                }
                if matches!(op, BinaryOp::And | BinaryOp::Or)
                    && (is_assignment_operand(lhs) || is_assignment_operand(rhs))
                {
                    let rules = self
                        .pack
                        .rules
                        .iter()
                        .filter(|rule| {
                            rule.matcher.assignment_operand_in_logical
                                && (rule.languages.is_empty()
                                    || rule.languages.iter().any(|item| item == self.language))
                                && self.rule_matches_span_path(rule, *span)
                        })
                        .collect::<Vec<_>>();
                    for rule in rules {
                        self.push_finding(rule, "logical expression", *span);
                    }
                }
                self.visit_expr(lhs, ValueUse::Used);
                self.visit_expr(rhs, ValueUse::Used);
            }
            Expr::FieldRead {
                base, field, span, ..
            } => {
                self.match_field_read(base, field, *span);
                self.visit_expr(base, ValueUse::Used);
            }
            Expr::IndexRead {
                base, index, span, ..
            } => {
                if integer_literal_value(index).is_some_and(|value| value < 0) {
                    let rules = self
                        .pack
                        .rules
                        .iter()
                        .filter(|rule| {
                            rule.matcher.negative_literal_array_index
                                && (rule.languages.is_empty()
                                    || rule.languages.contains(self.language))
                                && self.rule_matches_span_path(rule, *span)
                        })
                        .collect::<Vec<_>>();
                    for rule in rules {
                        self.push_finding(rule, "negative array index", *span);
                    }
                }
                self.visit_expr(base, ValueUse::Used);
                self.visit_expr(index, ValueUse::Used);
            }
            Expr::Call(call) => {
                if let CallTarget::Named(callee) = &call.target {
                    self.match_call(callee, call, usage);
                }
                if let Some(receiver) = &call.receiver {
                    self.visit_expr(receiver, ValueUse::Used);
                }
                for arg in &call.args {
                    self.visit_expr(arg, ValueUse::Used);
                }
                if let CallTarget::Dynamic(target) = &call.target {
                    self.visit_expr(target, ValueUse::Used);
                }
            }
            Expr::Lambda { params, body, .. } => {
                for param in params {
                    self.types.bind(param.symbol, param.ty);
                }
                let outer_finally_depth = self.finally_depth;
                let outer_loop_depth = self.loop_depth;
                let outer_checked = std::mem::take(&mut self.checked_symbols);
                let outer_properties = std::mem::take(&mut self.true_properties);
                let outer_present_optionals = std::mem::take(&mut self.present_optionals);
                let outer_catch = std::mem::replace(&mut self.catch_depth, 0);
                let outer_receiver_calls = std::mem::take(&mut self.receiver_calls);
                collect_true_properties(body, &mut self.true_properties);
                self.finally_depth = 0;
                self.loop_depth = 0;
                self.visit_block(body);
                self.finally_depth = outer_finally_depth;
                self.loop_depth = outer_loop_depth;
                self.checked_symbols = outer_checked;
                self.true_properties = outer_properties;
                self.present_optionals = outer_present_optionals;
                self.catch_depth = outer_catch;
                self.receiver_calls = outer_receiver_calls;
            }
            Expr::New {
                type_name,
                args,
                span,
                ..
            } => {
                self.match_constructor(type_name, args, usage, *span);
                for arg in args {
                    self.visit_expr(arg, ValueUse::Used);
                }
            }
            Expr::Conditional {
                cond,
                then_expr,
                else_expr,
                ..
            } => {
                self.visit_expr(cond, ValueUse::Used);
                self.visit_expr(then_expr, usage);
                self.visit_expr(else_expr, usage);
            }
            Expr::Assign { lhs, rhs, span, .. } => {
                self.match_assignment(lhs, rhs, *span);
                self.visit_lvalue(lhs);
                let target = match lhs {
                    LValue::Var(symbol) => ValueUse::AssignedTo(*symbol),
                    _ => ValueUse::Used,
                };
                self.visit_expr(rhs, target);
            }
            Expr::Interp { parts, .. }
            | Expr::Collection {
                elements: parts, ..
            } => {
                for part in parts {
                    self.visit_expr(part, ValueUse::Used);
                }
            }
            Expr::Range { low, high, .. } => {
                self.visit_expr(low, ValueUse::Used);
                self.visit_expr(high, ValueUse::Used);
            }
            Expr::Opaque { .. } => {}
        }
    }

    fn match_call(&mut self, callee: &str, call: &CallExpr, usage: ValueUse) {
        let generic_len = self.generic_call_rules.len();
        let exact_len = self
            .exact_call_rules
            .get(callee)
            .map_or(0, Vec::len);
        for position in 0..generic_len + exact_len {
            let index = if position < generic_len {
                self.generic_call_rules[position]
            } else {
                self.exact_call_rules
                    .get(callee)
                    .expect("exact candidate length was measured from this callee")[position - generic_len]
            };
            let rule = &self.pack.rules[index];
            if !rule.matcher.call_alternatives.is_empty() {
                let matches = rule.matcher.call_alternatives.iter().any(|matcher| {
                    let mut alternative = rule.clone();
                    alternative.matcher = matcher.clone();
                    self.call_matches_context(&alternative, callee, call, usage)
                });
                if matches {
                    self.push_finding(rule, callee, call.span);
                }
                continue;
            }
            if self.call_matches_context(rule, callee, call, usage) {
                self.push_finding(rule, callee, call.span);
            }
        }
        if let Some(receiver) = call.receiver.as_deref().and_then(referenced_symbol) {
            self.receiver_calls.insert((
                receiver,
                callee.rsplit('.').next().unwrap_or(callee).to_string(),
            ));
        }
    }

    fn callee_pattern_matches(&self, pattern: &str, callee: &str) -> bool {
        let mut cache = self.callee_regexes.borrow_mut();
        if let Some(regex) = cache.get(pattern) {
            return regex.as_ref().is_some_and(|regex| regex.is_match(callee));
        }
        let regex = Regex::new(pattern).ok();
        let matches = regex.as_ref().is_some_and(|regex| regex.is_match(callee));
        cache.insert(pattern.to_string(), regex);
        matches
    }

    fn match_numeric_cast(
        &mut self,
        target: Option<uniflow_hir::TypeId>,
        value: &Expr,
        span: Span,
    ) {
        let Some(target) = target.and_then(|id| self.types.names.get(&id)) else {
            return;
        };
        let Some(source) = self.types.resolve(value) else {
            return;
        };
        let target = target.rsplit('.').next().unwrap_or(target);
        let source = source.rsplit('.').next().unwrap_or(source);
        let narrowing = numeric_width(source)
            .zip(numeric_width(target))
            .is_some_and(
                |((source_kind, source_width), (target_kind, target_width))| {
                    source_kind > target_kind
                        || source_kind == target_kind && source_width > target_width
                },
            );
        let precision_loss = matches!(
            (source, target),
            ("int" | "Integer", "float" | "Float")
                | ("long" | "Long", "float" | "Float" | "double" | "Double")
        );
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                (rule.languages.is_empty() || rule.languages.contains(self.language))
                    && self.rule_matches_span_path(rule, span)
                    && (rule.matcher.numeric_narrowing_cast && narrowing
                        || rule.matcher.integer_to_float_precision_loss && precision_loss)
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, "precision-losing numeric conversion", span);
        }
    }

    fn call_matches_context(
        &self,
        rule: &BaselineRule,
        callee: &str,
        call: &CallExpr,
        usage: ValueUse,
    ) -> bool {
        let pattern = if rule.matcher.callee.is_empty() {
            rule.pattern.as_str()
        } else {
            rule.matcher.callee.as_str()
        };
        if pattern.is_empty() || !self.callee_pattern_matches(pattern, callee) {
            return false;
        }
        if rule.matcher.inside_catch && self.catch_depth == 0 {
            return false;
        }
        if !rule.matcher.missing_prior_receiver_call.is_empty() {
            let Some(receiver) = call.receiver.as_deref().and_then(referenced_symbol) else {
                return false;
            };
            if self.receiver_calls.contains(&(
                receiver,
                rule.matcher.missing_prior_receiver_call.clone(),
            )) {
                return false;
            }
        }
        if !rule.matcher.requires_hir() {
            return false;
        }
        if !rule.languages.is_empty() && !rule.languages.iter().any(|item| item == self.language) {
            return false;
        }
        if !self.rule_matches_span_path(rule, call.span) {
            return false;
        }
        if rule.matcher.outside_loop && self.loop_depth != 0 {
            return false;
        }
        if rule.matcher.inside_loop && self.loop_depth == 0 {
            return false;
        }
        if !enclosing_parameter_matches(rule, &self.current_param_types) {
            return false;
        }
        if !self.argument_references_match(rule, &call.args) {
            return false;
        }
        if rule.matcher.parameter_args.iter().any(|index| {
            !matches!(
                call.args.get(*index),
                Some(Expr::VarRef { symbol, .. }) if self.parameter_symbols.contains(symbol)
            )
        }) {
            return false;
        }
        if !rule
            .matcher
            .string_constant_arg_patterns
            .iter()
            .all(|(index, pattern)| {
                call.args.get(*index).is_some_and(|arg| {
                    let value = match arg {
                        Expr::Literal {
                            kind: LiteralKind::String(value),
                            ..
                        } => Some(value.as_str()),
                        Expr::VarRef { symbol, .. } => {
                            self.string_constants.get(symbol).map(String::as_str)
                        }
                        _ => None,
                    };
                    value.is_some_and(|value| {
                        Regex::new(pattern).is_ok_and(|regex| regex.is_match(value))
                    })
                })
            })
        {
            return false;
        }
        if rule.matcher.inside_if_condition && self.if_condition_depth == 0 {
            return false;
        }
        if rule.matcher.optional_get_without_is_present
            && call
                .receiver
                .as_deref()
                .and_then(referenced_symbol)
                .is_some_and(|symbol| self.present_optionals.contains(&symbol))
        {
            return false;
        }
        if rule.matcher.serialize_non_serializable_argument {
            let receiver_matches = call
                .receiver
                .as_deref()
                .and_then(|receiver| self.types.resolve(receiver))
                .is_some_and(|ty| ty.rsplit('.').next() == Some("ObjectOutputStream"));
            let argument_matches = call.args.first().and_then(|argument| self.types.resolve(argument)).is_some_and(|ty| {
                let simple = ty.rsplit('.').next().unwrap_or(ty);
                self.known_class_types.iter().any(|known| known.rsplit('.').next() == Some(simple))
                    && !self.serializable_types.iter().any(|known| known.rsplit('.').next() == Some(simple))
            });
            if !receiver_matches || !argument_matches {
                return false;
            }
        }
        if let Some(index) = rule.matcher.non_serializable_arg {
            let argument_matches = call
                .args
                .get(index)
                .and_then(|argument| self.types.resolve(argument))
                .is_some_and(|ty| {
                    let simple = ty.rsplit('.').next().unwrap_or(ty);
                    self.known_class_types
                        .iter()
                        .any(|known| known.rsplit('.').next() == Some(simple))
                        && !self
                            .serializable_types
                            .iter()
                            .any(|known| known.rsplit('.').next() == Some(simple))
                });
            if !argument_matches {
                return false;
            }
        }
        if rule.matcher.receiver_class_missing_equals {
            let receiver_matches = call
                .receiver
                .as_deref()
                .and_then(|receiver| self.types.resolve(receiver))
                .is_some_and(|ty| {
                    let simple = ty.rsplit('.').next().unwrap_or(ty);
                    self.known_class_types
                        .iter()
                        .any(|known| known.rsplit('.').next() == Some(simple))
                        && !self
                            .classes_with_equals
                            .iter()
                            .any(|known| known.rsplit('.').next() == Some(simple))
                });
            if !receiver_matches {
                return false;
            }
        }
        if rule.matcher.call_not_last_statement && !self.has_following_statement {
            return false;
        }
        if rule.matcher.sql_wildcard_query_argument
            && !call.args.iter().any(|arg| {
                expr_contains_marked_symbol(
                    arg,
                    &self.sql_wildcard_symbols,
                    &self.sql_wildcard_fields,
                )
            })
        {
            return false;
        }
        rule_matches_call(
            rule,
            call,
            usage,
            &self.automatic_symbols,
            &self.types,
            &self.symbol_names,
        )
    }

    fn match_field_read(&mut self, base: &Expr, field: &str, span: Span) {
        let base_path = expression_path(base, &self.symbol_names);
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                !rule.matcher.field_name_pattern.is_empty()
                    && (rule.languages.is_empty() || rule.languages.contains(self.language))
                    && self.rule_matches_span_path(rule, span)
                    && Regex::new(&rule.matcher.field_name_pattern)
                        .is_ok_and(|regex| regex.is_match(field))
                    && (rule.matcher.field_receiver_type_pattern.is_empty()
                        || self.types.resolve(base).is_some_and(|ty| {
                            Regex::new(&rule.matcher.field_receiver_type_pattern)
                                .is_ok_and(|regex| regex.is_match(ty))
                        }))
                    && (rule.matcher.field_receiver_path_pattern.is_empty()
                        || base_path.as_deref().is_some_and(|path| {
                            Regex::new(&rule.matcher.field_receiver_path_pattern)
                                .is_ok_and(|regex| regex.is_match(path))
                        }))
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, field, span);
        }
    }

    fn match_assignment(&mut self, lhs: &LValue, rhs: &Expr, span: Span) {
        let path = match lhs {
            LValue::Var(symbol) => self.symbol_names.get(symbol).cloned(),
            LValue::Field { base, field } => self
                .assignment_base_path(base)
                .map(|base| format!("{base}.{field}")),
            LValue::Index { .. } => None,
        };
        let Some(path) = path else {
            return;
        };
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                !rule.matcher.assignment_target_path_pattern.is_empty()
                    && (rule.languages.is_empty() || rule.languages.contains(self.language))
                    && self.rule_matches_span_path(rule, span)
                    && (!rule.matcher.assignment_requires_field
                        || matches!(lhs, LValue::Field { .. }))
                    && Regex::new(&rule.matcher.assignment_target_path_pattern)
                        .is_ok_and(|regex| regex.is_match(&path))
                    && rule.matcher.assignment_bool_value.is_none_or(|expected| {
                        matches!(rhs, Expr::Literal { kind: LiteralKind::Bool(value), .. } if *value == expected)
                    })
                    && (!rule.matcher.assignment_value_non_string_literal
                        || !matches!(rhs, Expr::Literal { kind: LiteralKind::String(_), .. }))
                    && (rule.matcher.assignment_value_not_string_pattern.is_empty()
                        || !matches!(rhs,
                            Expr::Literal { kind: LiteralKind::String(value), .. }
                                if Regex::new(&rule.matcher.assignment_value_not_string_pattern)
                                    .is_ok_and(|regex| regex.is_match(value))))
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, &path, span);
        }
    }

    fn assignment_base_path(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::VarRef { symbol, .. } => self.symbol_names.get(symbol).cloned(),
            Expr::FieldRead { base, field, .. } => self
                .assignment_base_path(base)
                .map(|base| format!("{base}.{field}")),
            Expr::Cast { expr, .. } => self.assignment_base_path(expr),
            Expr::Unknown { span, .. } | Expr::Opaque { span, .. } => {
                let text = self.span_source(*span)?.trim();
                Regex::new(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|::)[A-Za-z_$][A-Za-z0-9_$]*)*$")
                    .ok()?
                    .is_match(text)
                    .then(|| text.replace("::", "."))
            }
            _ => None,
        }
    }

    fn update_string_constant(&mut self, symbol: SymbolId, value: &Expr) {
        if let Expr::Literal {
            kind: LiteralKind::String(value),
            ..
        } = value
        {
            self.string_constants.insert(symbol, value.clone());
        } else {
            self.string_constants.remove(&symbol);
        }
    }

    fn argument_references_match(&self, rule: &BaselineRule, args: &[Expr]) -> bool {
        rule.matcher
            .argument_references
            .iter()
            .all(|(index, constraint)| {
                args.get(*index)
                    .is_some_and(|arg| self.argument_reference_matches(constraint, arg))
            })
            && rule
                .matcher
                .any_argument_reference
                .as_ref()
                .is_none_or(|constraint| {
                    args.iter()
                        .any(|arg| self.argument_reference_matches(constraint, arg))
                })
            && rule
                .matcher
                .argument_token_patterns
                .iter()
                .all(|(index, pattern)| {
                    use uniflow_parser_core::{Lexer, LexerSpec, TokKind};
                    args.get(*index)
                        .and_then(|arg| self.span_source(argument_span(arg)))
                        .is_some_and(|source| {
                            let tokens = Lexer::new(source, &LexerSpec::default()).tokenize();
                            let spelling = tokens
                                .iter()
                                .filter(|token| token.kind != TokKind::Eof)
                                .map(|token| token.text.as_str())
                                .collect::<String>();
                            Regex::new(pattern).is_ok_and(|regex| regex.is_match(&spelling))
                        })
                })
    }

    fn argument_reference_matches(
        &self,
        constraint: &crate::ArgumentReferenceConstraint,
        arg: &Expr,
    ) -> bool {
        if constraint.direct_identifier && !matches!(arg, Expr::VarRef { .. }) {
            return false;
        }
        let Ok(pattern) = Regex::new(&constraint.type_pattern) else {
            return false;
        };
        let mut matched = false;
        visit_expression_nodes(arg, &mut |expr| {
            let Expr::VarRef { symbol, .. } = expr else {
                return;
            };
            if !self
                .types
                .symbols
                .get(symbol)
                .is_some_and(|ty| pattern.is_match(ty))
            {
                return;
            }
            if constraint.parameter_or_catch_only
                && !self.parameter_symbols.contains(symbol)
                && !self.catch_symbols.contains(symbol)
            {
                return;
            }
            if constraint.exclude_if_checked && self.checked_symbols.contains(symbol) {
                return;
            }
            if !constraint.exclude_when_field_true.is_empty()
                && self
                    .true_properties
                    .contains(&(*symbol, constraint.exclude_when_field_true.clone()))
            {
                return;
            }
            matched |= constraint.parameter_or_initializer_roots.is_empty()
                || self.parameter_symbols.contains(symbol)
                || self
                    .declaration_member_roots
                    .get(symbol)
                    .is_some_and(|roots| {
                        roots.iter().any(|(root, indexed)| {
                            (!indexed || constraint.allow_index_initializer)
                                && constraint.parameter_or_initializer_roots.contains(root)
                        })
                    });
        });
        matched
    }

    fn match_loop_condition(&mut self, condition: &Expr, span: Span) {
        fn matches_type(
            expr: &Expr,
            pattern: &Regex,
            types: &HirTypes,
            excluded: &HashSet<SymbolId>,
        ) -> bool {
            match expr {
                Expr::Binary { op, lhs, rhs, .. } => {
                    (matches!(
                        op,
                        BinaryOp::Eq
                            | BinaryOp::Ne
                            | BinaryOp::Lt
                            | BinaryOp::Le
                            | BinaryOp::Gt
                            | BinaryOp::Ge
                    ) && [lhs.as_ref(), rhs.as_ref()].iter().any(|operand| {
                        let eligible = match operand {
                            Expr::VarRef { symbol, .. } => !excluded.contains(symbol),
                            Expr::FieldRead { .. } => true,
                            _ => false,
                        };
                        eligible
                            && types
                                .resolve(operand)
                                .is_some_and(|ty| pattern.is_match(ty))
                    })) || matches_type(lhs, pattern, types, excluded)
                        || matches_type(rhs, pattern, types, excluded)
                }
                Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => {
                    matches_type(expr, pattern, types, excluded)
                }
                _ => false,
            }
        }
        let empty = HashSet::new();
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                !rule.matcher.loop_condition_type_pattern.is_empty()
                    && (rule.languages.is_empty() || rule.languages.contains(self.language))
                    && self.rule_matches_span_path(rule, span)
                    && Regex::new(&rule.matcher.loop_condition_type_pattern).is_ok_and(|regex| {
                        matches_type(
                            condition,
                            &regex,
                            &self.types,
                            if rule.matcher.loop_condition_exclude_parameters {
                                &self.parameter_symbols
                            } else {
                                &empty
                            },
                        )
                    })
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, "loop condition", span);
        }
    }

    fn match_binary(&mut self, op: BinaryOp, lhs: &Expr, rhs: &Expr, span: Span) {
        if !matches!(op, BinaryOp::Eq | BinaryOp::Ne) {
            return;
        }
        let left = expression_path(lhs, &self.symbol_names);
        let right = expression_path(rhs, &self.symbol_names);
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                let path_pattern = &rule.matcher.equality_operand_path_pattern;
                let type_pattern = &rule.matcher.equality_operand_type_pattern;
                (!path_pattern.is_empty()
                    || !type_pattern.is_empty()
                    || rule.matcher.nested_equality
                    || rule.matcher.equality_constant_result.is_some())
                    && (!rule.matcher.nested_equality
                        || [lhs, rhs].iter().any(|expr| {
                            matches!(
                                expr,
                                Expr::Binary {
                                    op: BinaryOp::Eq | BinaryOp::Ne,
                                    ..
                                }
                            )
                        }))
                    && (rule.languages.is_empty()
                        || rule.languages.iter().any(|item| item == self.language))
                    && self.rule_matches_span_path(rule, span)
                    && (!rule.matcher.equality_exclude_null
                        || (!is_null_literal(lhs) && !is_null_literal(rhs)))
                    && (!rule.matcher.equality_require_null
                        || is_null_literal(lhs)
                        || is_null_literal(rhs))
                    && rule.matcher.equality_constant_result.is_none_or(|wanted| {
                        equality_result(op, lhs, rhs).is_some_and(|actual| actual == wanted)
                    })
                    && (!rule.matcher.equality_require_identifier_operands
                        || matches!(lhs, Expr::VarRef { .. }) && matches!(rhs, Expr::VarRef { .. }))
                    && (path_pattern.is_empty()
                        || Regex::new(path_pattern).is_ok_and(|regex| {
                            left.as_deref().is_some_and(|value| regex.is_match(value))
                                || right.as_deref().is_some_and(|value| regex.is_match(value))
                        }))
                    && (type_pattern.is_empty()
                        || Regex::new(type_pattern).is_ok_and(|regex| {
                            [lhs, rhs].iter().any(|operand| {
                                self.types
                                    .resolve(operand)
                                    .is_some_and(|ty| regex.is_match(ty))
                            })
                        }))
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, "equality expression", span);
        }
    }

    fn match_finally_transfer(&mut self, is_return: bool, span: Span) {
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                (if is_return {
                    rule.matcher.return_in_finally
                } else {
                    rule.matcher.throw_in_finally
                }) && (rule.languages.is_empty()
                    || rule.languages.iter().any(|item| item == self.language))
                    && self.rule_matches_span_path(rule, span)
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, if is_return { "return" } else { "throw" }, span);
        }
    }

    fn match_null_return(&mut self, span: Span) {
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                let name_pattern = &rule.matcher.null_return_method_name_pattern;
                let type_pattern = &rule.matcher.null_return_type_pattern;
                if name_pattern.is_empty() && type_pattern.is_empty() {
                    return false;
                }
                let name_matches = !name_pattern.is_empty()
                    && self.current_function_name.as_deref().is_some_and(|name| {
                        Regex::new(name_pattern).is_ok_and(|regex| regex.is_match(name))
                    });
                let type_matches = !type_pattern.is_empty()
                    && self.current_return_type.as_deref().is_some_and(|ty| {
                        Regex::new(type_pattern).is_ok_and(|regex| regex.is_match(ty))
                    });
                let context_matches = if rule.matcher.null_return_match_any {
                    name_matches || type_matches
                } else {
                    (name_pattern.is_empty() || name_matches)
                        && (type_pattern.is_empty() || type_matches)
                };
                context_matches
                    && (rule.languages.is_empty()
                        || rule.languages.iter().any(|item| item == self.language))
                    && self.rule_matches_span_path(rule, span)
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, "return null", span);
        }
    }

    fn match_constructor(&mut self, type_name: &str, args: &[Expr], usage: ValueUse, span: Span) {
        let rules = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                !rule.matcher.constructor_type.is_empty()
                    && (rule.languages.is_empty()
                        || rule.languages.iter().any(|item| item == self.language))
                    && self.rule_matches_span_path(rule, span)
                    && (!rule.matcher.outside_loop || self.loop_depth == 0)
                    && (!rule.matcher.inside_loop || self.loop_depth != 0)
                    && enclosing_parameter_matches(rule, &self.current_param_types)
                    && self.argument_references_match(rule, args)
                    && rule_matches_constructor(
                        rule,
                        type_name,
                        args,
                        usage,
                        &self.automatic_symbols,
                        &self.parameter_symbols,
                        &self.types,
                        &self.symbol_names,
                    )
            })
            .collect::<Vec<_>>();
        for rule in rules {
            self.push_finding(rule, type_name, span);
        }
    }

    fn rule_matches_span_path(&self, rule: &BaselineRule, span: Span) -> bool {
        if !rule.matcher.forbidden_project_pattern.is_empty()
            && Regex::new(&rule.matcher.forbidden_project_pattern).is_ok_and(|regex| {
                self.source_by_path.values().any(|source| regex.is_match(source))
            })
        {
            return false;
        }
        let Some(path) = self.file_paths.get(&span.file) else {
            return rule.matcher.required_file_pattern.is_empty();
        };
        if !rule_path_matches(rule, path) {
            return false;
        }
        if rule.matcher.required_file_pattern.is_empty() {
            return true;
        }
        self.source_by_path.get(path).is_some_and(|source| {
            let source = strip_comments_preserve_layout(self.language, source);
            Regex::new(&rule.matcher.required_file_pattern)
                .is_ok_and(|regex| regex.is_match(&source))
        })
    }

    fn span_source(&self, span: Span) -> Option<&str> {
        let path = self.file_paths.get(&span.file)?;
        let source = self.source_by_path.get(path)?;
        source.get(span.start_byte as usize..span.end_byte as usize)
    }

    fn push_finding(&mut self, rule: &BaselineRule, callee: &str, span: Span) {
        let path = self
            .file_paths
            .get(&span.file)
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        let snippet = self
            .source_by_path
            .get(&path)
            .and_then(|source| {
                source
                    .lines()
                    .nth(span.start_line.saturating_sub(1) as usize)
            })
            .unwrap_or(callee)
            .trim()
            .to_string();
        self.findings.push(BaselineFinding {
            rule_id: rule.id.clone(),
            title: rule.title.clone(),
            severity: rule.severity.clone(),
            confidence: rule.confidence.clone(),
            path,
            line: span.start_line.max(1) as usize,
            column: span.start_col.max(1) as usize,
            snippet,
            message: rule_message(rule),
            cwe: rule.cwe.clone(),
            standards: rule.standards.clone(),
            translations: rule.translations.clone(),
        });
    }
}

fn rule_matches_call(
    rule: &BaselineRule,
    call: &CallExpr,
    usage: ValueUse,
    automatic_symbols: &HashSet<SymbolId>,
    types: &HirTypes,
    names: &HashMap<SymbolId, String>,
) -> bool {
    if rule.matcher.requires_receiver && call.receiver.is_none() {
        return false;
    }
    if rule.matcher.forbids_receiver && call.receiver.is_some() {
        return false;
    }
    if rule.matcher.requires_explicit_qualifier && !call.qualifier_is_explicit {
        return false;
    }
    let mut receiver_cursor = call.receiver.as_deref();
    for field in &rule.matcher.receiver_field_chain {
        let Some(Expr::FieldRead {
            base,
            field: actual,
            ..
        }) = receiver_cursor
        else {
            return false;
        };
        if field != actual {
            return false;
        }
        receiver_cursor = Some(base);
    }
    for pattern in &rule.matcher.receiver_callee_chain {
        let Some(Expr::Call(receiver_call)) = receiver_cursor else {
            return false;
        };
        let CallTarget::Named(receiver_callee) = &receiver_call.target else {
            return false;
        };
        if Regex::new(pattern).map_or(true, |regex| !regex.is_match(receiver_callee)) {
            return false;
        }
        receiver_cursor = receiver_call.receiver.as_deref();
    }
    if !rule.matcher.receiver_chain_root_type_pattern.is_empty() {
        let Some(root_type) = receiver_cursor.and_then(|expr| types.resolve(expr)) else {
            return false;
        };
        if Regex::new(&rule.matcher.receiver_chain_root_type_pattern)
            .map_or(true, |regex| !regex.is_match(root_type))
        {
            return false;
        }
    }
    if !rule.matcher.receiver_chain_root_path_pattern.is_empty() {
        let Some(path) = receiver_cursor.and_then(|expr| expression_path(expr, names)) else {
            return false;
        };
        if Regex::new(&rule.matcher.receiver_chain_root_path_pattern)
            .map_or(true, |regex| !regex.is_match(&path))
        {
            return false;
        }
    }
    if !rule.matcher.receiver_type_pattern.is_empty() {
        let Some(receiver_type) = call
            .receiver
            .as_deref()
            .and_then(|expr| types.resolve(expr))
        else {
            return false;
        };
        if Regex::new(&rule.matcher.receiver_type_pattern)
            .map_or(true, |regex| !regex.is_match(receiver_type))
        {
            return false;
        }
    }
    if !rule.matcher.receiver_path_pattern.is_empty() {
        let Some(receiver_path) = call
            .receiver
            .as_deref()
            .and_then(|receiver| expression_path(receiver, names))
        else {
            return false;
        };
        if Regex::new(&rule.matcher.receiver_path_pattern)
            .map_or(true, |regex| !regex.is_match(&receiver_path))
        {
            return false;
        }
    }
    if !rule_matches_arguments(rule, &call.args, usage, automatic_symbols, types, names) {
        return false;
    }
    for (name, expected) in &rule.matcher.named_bool_args {
        let Some(index) = named_argument_index(call, name) else {
            return false;
        };
        if !call.args.get(index).is_some_and(|arg| {
            matches!(
                arg,
                Expr::Literal {
                    kind: LiteralKind::Bool(value),
                    ..
                } if value == expected
            )
        }) {
            return false;
        }
    }
    for (name, pattern) in &rule.matcher.named_string_arg_patterns {
        let Some(index) = named_argument_index(call, name) else {
            return false;
        };
        let Some(value) = call.args.get(index).and_then(string_literal_value) else {
            return false;
        };
        if Regex::new(pattern).map_or(true, |regex| !regex.is_match(value)) {
            return false;
        }
    }
    true
}

fn rule_matches_constructor(
    rule: &BaselineRule,
    type_name: &str,
    args: &[Expr],
    usage: ValueUse,
    automatic_symbols: &HashSet<SymbolId>,
    parameter_symbols: &HashSet<SymbolId>,
    types: &HirTypes,
    names: &HashMap<SymbolId, String>,
) -> bool {
    if Regex::new(&rule.matcher.constructor_type).map_or(true, |regex| !regex.is_match(type_name)) {
        return false;
    }
    // HIR New has neither an instance receiver nor named argument metadata.
    // Such constraints must not be silently ignored on construction.
    if rule.matcher.requires_receiver
        || rule.matcher.forbids_receiver
        || rule.matcher.requires_explicit_qualifier
        || !rule.matcher.receiver_type_pattern.is_empty()
        || !rule.matcher.receiver_path_pattern.is_empty()
        || !rule.matcher.receiver_callee_chain.is_empty()
        || !rule.matcher.receiver_field_chain.is_empty()
        || !rule.matcher.receiver_chain_root_path_pattern.is_empty()
        || !rule.matcher.receiver_chain_root_type_pattern.is_empty()
        || !rule.matcher.named_bool_args.is_empty()
        || !rule.matcher.named_string_arg_patterns.is_empty()
        || !rule.matcher.string_constant_arg_patterns.is_empty()
    {
        return false;
    }
    if rule.matcher.parameter_args.iter().any(|index| {
        !matches!(args.get(*index), Some(Expr::VarRef { symbol, .. }) if parameter_symbols.contains(symbol))
    }) {
        return false;
    }
    rule_matches_arguments(rule, args, usage, automatic_symbols, types, names)
}

fn rule_matches_arguments(
    rule: &BaselineRule,
    args: &[Expr],
    usage: ValueUse,
    automatic_symbols: &HashSet<SymbolId>,
    types: &HirTypes,
    names: &HashMap<SymbolId, String>,
) -> bool {
    let argc = args.len();
    if rule.matcher.min_args.is_some_and(|min| argc < min)
        || rule.matcher.max_args.is_some_and(|max| argc > max)
    {
        return false;
    }
    if rule.matcher.ignored_return && !matches!(usage, ValueUse::Discarded) {
        return false;
    }
    if !rule.matcher.assigned_target_type_pattern.is_empty() {
        let ValueUse::AssignedTo(symbol) = usage else {
            return false;
        };
        let Some(target_type) = types.symbols.get(&symbol) else {
            return false;
        };
        if Regex::new(&rule.matcher.assigned_target_type_pattern)
            .map_or(true, |regex| !regex.is_match(target_type))
        {
            return false;
        }
    }
    if rule.matcher.self_assignment {
        let ValueUse::AssignedTo(lhs) = usage else {
            return false;
        };
        let Some(Expr::VarRef { symbol: rhs, .. }) = args.first() else {
            return false;
        };
        if lhs != *rhs {
            return false;
        }
    }
    if rule.matcher.automatic_var_args.iter().any(|&idx| {
        args.get(idx)
            .and_then(referenced_symbol)
            .is_none_or(|symbol| !automatic_symbols.contains(&symbol))
    }) {
        return false;
    }
    if rule
        .matcher
        .literal_args
        .iter()
        .any(|&idx| !args.get(idx).is_some_and(is_literal))
    {
        return false;
    }
    if rule.matcher.float_args.iter().any(|&index| {
        !matches!(
            args.get(index),
            Some(Expr::Literal {
                kind: LiteralKind::Float(_),
                ..
            })
        )
    }) {
        return false;
    }
    if rule
        .matcher
        .non_literal_args
        .iter()
        .any(|&idx| args.get(idx).is_none_or(is_literal))
    {
        return false;
    }
    if rule.matcher.non_string_literal_args.iter().any(|&idx| {
        args.get(idx).is_none_or(|arg| {
            matches!(
                arg,
                Expr::Literal {
                    kind: LiteralKind::String(_),
                    ..
                }
            )
        })
    }) {
        return false;
    }
    if rule.matcher.forbids_string_literal_args
        && args.iter().any(|arg| {
            matches!(
                arg,
                Expr::Literal {
                    kind: LiteralKind::String(_),
                    ..
                }
            )
        })
    {
        return false;
    }
    if rule.matcher.null_args.iter().any(|&idx| {
        !args.get(idx).is_some_and(|arg| {
            matches!(
                arg,
                Expr::Literal {
                    kind: LiteralKind::Null,
                    ..
                }
            )
        })
    }) {
        return false;
    }
    if rule.matcher.null_or_empty_string_args.iter().any(|&idx| {
        !args.get(idx).is_some_and(|arg| match arg {
            Expr::Literal {
                kind: LiteralKind::Null,
                ..
            } => true,
            Expr::Literal {
                kind: LiteralKind::String(value),
                ..
            } => value.is_empty(),
            _ => false,
        })
    }) {
        return false;
    }
    if rule.matcher.false_or_zero_args.iter().any(|&idx| {
        !args.get(idx).is_some_and(|arg| {
            matches!(
                arg,
                Expr::Literal {
                    kind: LiteralKind::Bool(false),
                    ..
                } | Expr::Literal {
                    kind: LiteralKind::Int(0),
                    ..
                }
            )
        })
    }) {
        return false;
    }
    for (index, pattern) in &rule.matcher.string_arg_patterns {
        let Some(value) = args.get(*index).and_then(string_literal_value) else {
            return false;
        };
        if Regex::new(pattern).map_or(true, |regex| !regex.is_match(value)) {
            return false;
        }
    }
    if !rule.matcher.last_string_arg_pattern.is_empty() {
        let Some(value) = args.last().and_then(string_literal_value) else {
            return false;
        };
        if Regex::new(&rule.matcher.last_string_arg_pattern)
            .map_or(true, |regex| !regex.is_match(value))
        {
            return false;
        }
    }
    for (index, pattern) in &rule.matcher.descendant_string_arg_patterns {
        if !args
            .get(*index)
            .is_some_and(|value| expression_has_string_matching(value, pattern))
        {
            return false;
        }
    }
    for (index, pattern) in &rule.matcher.string_arg_not_patterns {
        let Some(value) = args.get(*index).and_then(string_literal_value) else {
            return false;
        };
        if Regex::new(pattern).map_or(true, |regex| regex.is_match(value)) {
            return false;
        }
    }
    for (index, expected) in &rule.matcher.int_arg_values {
        if args.get(*index).and_then(integer_literal_value) != Some(*expected) {
            return false;
        }
    }
    for (index, minimum) in &rule.matcher.int_arg_min_values {
        if args
            .get(*index)
            .and_then(integer_literal_value)
            .is_none_or(|value| value < *minimum)
        {
            return false;
        }
    }
    for (index, maximum) in &rule.matcher.int_arg_max_values {
        if args
            .get(*index)
            .and_then(integer_literal_value)
            .is_none_or(|value| value > *maximum)
        {
            return false;
        }
    }
    for (index, expected) in &rule.matcher.bool_arg_values {
        if !args.get(*index).is_some_and(|arg| {
            matches!(
                arg,
                Expr::Literal {
                    kind: LiteralKind::Bool(value),
                    ..
                } if value == expected
            )
        }) {
            return false;
        }
    }
    if let Some(expected) = rule.matcher.last_bool_arg_value {
        if !args.last().is_some_and(|arg| {
            matches!(
                arg,
                Expr::Literal {
                    kind: LiteralKind::Bool(value),
                    ..
                } if *value == expected
            )
        }) {
            return false;
        }
    }
    if rule
        .matcher
        .arg_path_patterns
        .iter()
        .any(|(index, pattern)| {
            args.get(*index)
                .and_then(|arg| expression_path(arg, names))
                .is_none_or(|path| Regex::new(pattern).map_or(true, |regex| !regex.is_match(&path)))
        })
    {
        return false;
    }
    if rule.matcher.equal_arg_pairs.iter().any(|pair| {
        let Some(left) = args.get(pair[0]) else {
            return true;
        };
        let Some(right) = args.get(pair[1]) else {
            return true;
        };
        expression_fingerprint(left) != expression_fingerprint(right)
    }) {
        return false;
    }
    argument_types_match(&rule.matcher.arg_type_patterns, args, types)
}

fn enclosing_parameter_matches(rule: &BaselineRule, types: &[String]) -> bool {
    rule.matcher.enclosing_param_type_pattern.is_empty()
        || Regex::new(&rule.matcher.enclosing_param_type_pattern)
            .is_ok_and(|regex| types.iter().any(|ty| regex.is_match(ty)))
}

fn argument_types_match(
    patterns: &std::collections::BTreeMap<usize, String>,
    args: &[Expr],
    types: &HirTypes,
) -> bool {
    patterns.iter().all(|(index, pattern)| {
        args.get(*index)
            .and_then(|expr| types.resolve(expr))
            .is_some_and(|ty| Regex::new(pattern).is_ok_and(|regex| regex.is_match(ty)))
    })
}

fn argument_span(expr: &Expr) -> Span {
    match expr {
        Expr::VarRef { span, .. }
        | Expr::Literal { span, .. }
        | Expr::Unary { span, .. }
        | Expr::Binary { span, .. }
        | Expr::FieldRead { span, .. }
        | Expr::IndexRead { span, .. }
        | Expr::Lambda { span, .. }
        | Expr::New { span, .. }
        | Expr::Cast { span, .. }
        | Expr::Conditional { span, .. }
        | Expr::Assign { span, .. }
        | Expr::Interp { span, .. }
        | Expr::Collection { span, .. }
        | Expr::Range { span, .. }
        | Expr::Opaque { span, .. }
        | Expr::Unknown { span, .. } => *span,
        Expr::Call(call) => call.span,
    }
}

fn visit_block_statements(block: &Block, visit: &mut impl FnMut(&Stmt)) {
    for stmt in &block.stmts {
        visit(stmt);
        match stmt {
            Stmt::If {
                then_block,
                else_block,
                ..
            } => {
                visit_block_statements(then_block, visit);
                if let Some(block) = else_block {
                    visit_block_statements(block, visit);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::ForEach { body, .. } => {
                visit_block_statements(body, visit)
            }
            Stmt::For {
                init, update, body, ..
            } => {
                visit_block_statements(init, visit);
                visit_block_statements(body, visit);
                visit_block_statements(update, visit);
            }
            Stmt::Switch {
                clauses, default, ..
            } => {
                for clause in clauses {
                    visit_block_statements(&clause.body, visit);
                }
                if let Some(block) = default {
                    visit_block_statements(block, visit);
                }
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                visit_block_statements(try_block, visit);
                for catch in catches {
                    visit_block_statements(&catch.body, visit);
                }
                if let Some(block) = finally_block {
                    visit_block_statements(block, visit);
                }
            }
            _ => {}
        }
    }
}

fn visit_block_expressions(block: &Block, visit: &mut impl FnMut(&Expr)) {
    visit_block_statements(block, &mut |stmt| match stmt {
        Stmt::Let { init, .. } => {
            if let Some(expr) = init {
                visit(expr);
            }
        }
        Stmt::Expr { expr, .. } => visit(expr),
        Stmt::Assign { lhs, rhs, .. } => {
            match lhs {
                LValue::Field { base, .. } => visit(base),
                LValue::Index { base, index } => {
                    visit(base);
                    visit(index);
                }
                _ => {}
            }
            visit(rhs);
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            visit(cond)
        }
        Stmt::For { cond, .. } => {
            if let Some(cond) = cond {
                visit(cond);
            }
        }
        Stmt::ForEach { iterable, .. } => visit(iterable),
        Stmt::Switch { scrutinee, .. } => visit(scrutinee),
        Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
            if let Some(expr) = value {
                visit(expr);
            }
        }
        _ => {}
    });
}

fn collect_checked_symbols(expr: &Expr, symbols: &mut HashSet<SymbolId>) {
    visit_expression_nodes(expr, &mut |node| {
        if let Expr::VarRef { symbol, .. } = node {
            symbols.insert(*symbol);
        }
    });
}

fn collect_true_properties(block: &Block, properties: &mut HashSet<(SymbolId, String)>) {
    let mut record = |lhs: &LValue, rhs: &Expr| {
        if let LValue::Field { base, field } = lhs {
            if let (
                Some(symbol),
                Expr::Literal {
                    kind: LiteralKind::Bool(true),
                    ..
                },
            ) = (referenced_symbol(base), rhs)
            {
                properties.insert((symbol, field.clone()));
            }
        }
    };
    visit_block_statements(block, &mut |stmt| {
        if let Stmt::Assign { lhs, rhs, .. } = stmt {
            record(lhs, rhs);
        }
    });
    visit_block_expressions(block, &mut |expr| {
        visit_expression_nodes(expr, &mut |node| {
            if let Expr::Assign { lhs, rhs, .. } = node {
                record(lhs, rhs);
            }
        })
    });
}

fn optional_present_symbol(expr: &Expr) -> Option<SymbolId> {
    let Expr::Call(call) = expr else {
        return None;
    };
    let CallTarget::Named(name) = &call.target else {
        return None;
    };
    (name.rsplit('.').next() == Some("isPresent"))
        .then(|| call.receiver.as_deref().and_then(referenced_symbol))
        .flatten()
}

fn visit_expression_nodes(expr: &Expr, visit: &mut impl FnMut(&Expr)) {
    visit(expr);
    match expr {
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } | Expr::FieldRead { base: expr, .. } => {
            visit_expression_nodes(expr, visit)
        }
        Expr::Binary { lhs, rhs, .. }
        | Expr::IndexRead {
            base: lhs,
            index: rhs,
            ..
        }
        | Expr::Range {
            low: lhs,
            high: rhs,
            ..
        } => {
            visit_expression_nodes(lhs, visit);
            visit_expression_nodes(rhs, visit);
        }
        Expr::Call(call) => {
            if let Some(receiver) = &call.receiver {
                visit_expression_nodes(receiver, visit);
            }
            for arg in &call.args {
                visit_expression_nodes(arg, visit);
            }
            if let CallTarget::Dynamic(target) = &call.target {
                visit_expression_nodes(target, visit);
            }
        }
        Expr::New { args, .. }
        | Expr::Collection { elements: args, .. }
        | Expr::Interp { parts: args, .. } => {
            for arg in args {
                visit_expression_nodes(arg, visit);
            }
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            visit_expression_nodes(cond, visit);
            visit_expression_nodes(then_expr, visit);
            visit_expression_nodes(else_expr, visit);
        }
        Expr::Assign { lhs, rhs, .. } => {
            match lhs {
                LValue::Field { base, .. } => visit_expression_nodes(base, visit),
                LValue::Index { base, index } => {
                    visit_expression_nodes(base, visit);
                    visit_expression_nodes(index, visit);
                }
                LValue::Var(_) => {}
            }
            visit_expression_nodes(rhs, visit);
        }
        // Nested executable bodies are scanned in their own visitor context.
        Expr::Lambda { .. }
        | Expr::VarRef { .. }
        | Expr::Literal { .. }
        | Expr::Unknown { .. }
        | Expr::Opaque { .. } => {}
    }
}

fn initializer_member_roots(expr: &Expr, names: &HashMap<SymbolId, String>) -> Vec<(String, bool)> {
    let mut roots = Vec::new();
    visit_expression_nodes(expr, &mut |node| match node {
        Expr::FieldRead { base, .. } => {
            if let Some(path) = expression_path(base, names) {
                roots.push((path, false));
            }
        }
        Expr::IndexRead { base, .. } => {
            if let Some(path) = expression_path(base, names) {
                roots.push((path, true));
            }
        }
        Expr::Call(call) => {
            if let Some(path) = call
                .receiver
                .as_deref()
                .and_then(|base| expression_path(base, names))
            {
                roots.push((path, false));
            }
        }
        _ => {}
    });
    roots.sort();
    roots.dedup();
    roots
}

// Field initializers are not yet represented in Field HIR. Read their retained
// declaration span through the lexer; never match text inside comments/literals.
fn source_initializer_member_roots(source: &str) -> Vec<(String, bool)> {
    use uniflow_parser_core::{Lexer, LexerSpec, TokKind};
    let tokens = Lexer::new(source, &LexerSpec::default()).tokenize();
    let Some(assign) = tokens.iter().position(|token| token.text == "=") else {
        return Vec::new();
    };
    let mut roots = Vec::new();
    for at in assign + 1..tokens.len().saturating_sub(1) {
        if tokens[at].kind != TokKind::Ident || tokens[at - 1].text == "." {
            continue;
        }
        match tokens[at + 1].text.as_str() {
            "." => roots.push((tokens[at].text.clone(), false)),
            "[" => roots.push((tokens[at].text.clone(), true)),
            _ => {}
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

fn referenced_symbol(expr: &Expr) -> Option<SymbolId> {
    match expr {
        Expr::VarRef { symbol, .. } => Some(*symbol),
        Expr::Cast { expr, .. } => referenced_symbol(expr),
        _ => None,
    }
}

fn expr_references_symbol(expr: &Expr, wanted: SymbolId) -> bool {
    match expr {
        Expr::VarRef { symbol, .. } => *symbol == wanted,
        Expr::Literal { .. } | Expr::Unknown { .. } | Expr::Opaque { .. } => false,
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => expr_references_symbol(expr, wanted),
        Expr::Binary { lhs, rhs, .. } => {
            expr_references_symbol(lhs, wanted) || expr_references_symbol(rhs, wanted)
        }
        Expr::FieldRead { base, .. } => expr_references_symbol(base, wanted),
        Expr::IndexRead { base, index, .. } => {
            expr_references_symbol(base, wanted) || expr_references_symbol(index, wanted)
        }
        Expr::Call(call) => {
            call.receiver
                .as_deref()
                .is_some_and(|value| expr_references_symbol(value, wanted))
                || call
                    .args
                    .iter()
                    .any(|value| expr_references_symbol(value, wanted))
                || matches!(&call.target, CallTarget::Dynamic(value) if expr_references_symbol(value, wanted))
        }
        Expr::Lambda { captures, body, .. } => {
            captures
                .iter()
                .any(|capture| capture.source_symbol == wanted)
                || block_references_symbol(body, wanted)
        }
        Expr::New { args, .. }
        | Expr::Interp { parts: args, .. }
        | Expr::Collection { elements: args, .. } => args
            .iter()
            .any(|value| expr_references_symbol(value, wanted)),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => [cond.as_ref(), then_expr.as_ref(), else_expr.as_ref()]
            .iter()
            .any(|value| expr_references_symbol(value, wanted)),
        Expr::Assign { lhs, rhs, .. } => {
            lvalue_references_symbol(lhs, wanted) || expr_references_symbol(rhs, wanted)
        }
        Expr::Range { low, high, .. } => {
            expr_references_symbol(low, wanted) || expr_references_symbol(high, wanted)
        }
    }
}

fn expr_references_field(expr: &Expr, base_key: &str, wanted: &str) -> bool {
    match expr {
        Expr::FieldRead { base, field, .. } => {
            (field == wanted && expression_fingerprint(base) == base_key)
                || expr_references_field(base, base_key, wanted)
        }
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => {
            expr_references_field(expr, base_key, wanted)
        }
        Expr::Binary { lhs, rhs, .. }
        | Expr::IndexRead {
            base: lhs,
            index: rhs,
            ..
        }
        | Expr::Range {
            low: lhs,
            high: rhs,
            ..
        } => {
            expr_references_field(lhs, base_key, wanted)
                || expr_references_field(rhs, base_key, wanted)
        }
        Expr::Call(call) => {
            call.receiver
                .as_deref()
                .is_some_and(|value| expr_references_field(value, base_key, wanted))
                || call
                    .args
                    .iter()
                    .any(|value| expr_references_field(value, base_key, wanted))
        }
        Expr::New { args, .. }
        | Expr::Interp { parts: args, .. }
        | Expr::Collection { elements: args, .. } => args
            .iter()
            .any(|value| expr_references_field(value, base_key, wanted)),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => [cond.as_ref(), then_expr.as_ref(), else_expr.as_ref()]
            .iter()
            .any(|value| expr_references_field(value, base_key, wanted)),
        Expr::Assign { rhs, .. } => expr_references_field(rhs, base_key, wanted),
        _ => false,
    }
}

fn lvalue_references_symbol(value: &LValue, wanted: SymbolId) -> bool {
    match value {
        LValue::Var(symbol) => *symbol == wanted,
        LValue::Field { base, .. } => expr_references_symbol(base, wanted),
        LValue::Index { base, index } => {
            expr_references_symbol(base, wanted) || expr_references_symbol(index, wanted)
        }
    }
}

fn block_references_symbol(block: &Block, wanted: SymbolId) -> bool {
    block.stmts.iter().any(|stmt| match stmt {
        Stmt::Let { init, .. } => init
            .as_ref()
            .is_some_and(|value| expr_references_symbol(value, wanted)),
        Stmt::Assign { lhs, rhs, .. } => {
            lvalue_references_symbol(lhs, wanted) || expr_references_symbol(rhs, wanted)
        }
        Stmt::Expr { expr, .. } => expr_references_symbol(expr, wanted),
        Stmt::Return { value, .. } | Stmt::Throw { value, .. } => value
            .as_ref()
            .is_some_and(|value| expr_references_symbol(value, wanted)),
        _ => false,
    })
}

fn block_throws_symbol(block: &Block, wanted: SymbolId) -> bool {
    block.stmts.iter().any(|statement| match statement {
        Stmt::Throw {
            value: Some(Expr::VarRef { symbol, .. }),
            ..
        } => *symbol == wanted,
        Stmt::If {
            then_block,
            else_block,
            ..
        } => {
            block_throws_symbol(then_block, wanted)
                || else_block
                    .as_ref()
                    .is_some_and(|block| block_throws_symbol(block, wanted))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::ForEach { body, .. } => {
            block_throws_symbol(body, wanted)
        }
        Stmt::For {
            init, update, body, ..
        } => {
            block_throws_symbol(init, wanted)
                || block_throws_symbol(update, wanted)
                || block_throws_symbol(body, wanted)
        }
        Stmt::Try {
            try_block,
            catches,
            finally_block,
            ..
        } => {
            block_throws_symbol(try_block, wanted)
                || catches
                    .iter()
                    .any(|catch| block_throws_symbol(&catch.body, wanted))
                || finally_block
                    .as_ref()
                    .is_some_and(|block| block_throws_symbol(block, wanted))
        }
        Stmt::Switch {
            clauses, default, ..
        } => {
            clauses
                .iter()
                .any(|clause| block_throws_symbol(&clause.body, wanted))
                || default
                    .as_ref()
                    .is_some_and(|block| block_throws_symbol(block, wanted))
        }
        _ => false,
    })
}

fn block_assigns_symbol(block: &Block, wanted: SymbolId) -> bool {
    block.stmts.iter().any(|statement| match statement {
        Stmt::Assign {
            lhs: LValue::Var(symbol),
            ..
        } => *symbol == wanted,
        Stmt::If {
            then_block,
            else_block,
            ..
        } => {
            block_assigns_symbol(then_block, wanted)
                || else_block
                    .as_ref()
                    .is_some_and(|block| block_assigns_symbol(block, wanted))
        }
        Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::ForEach { body, .. } => block_assigns_symbol(body, wanted),
        Stmt::For {
            init, update, body, ..
        } => {
            block_assigns_symbol(init, wanted)
                || block_assigns_symbol(update, wanted)
                || block_assigns_symbol(body, wanted)
        }
        Stmt::Try {
            try_block,
            catches,
            finally_block,
            ..
        } => {
            block_assigns_symbol(try_block, wanted)
                || catches
                    .iter()
                    .any(|catch| block_assigns_symbol(&catch.body, wanted))
                || finally_block
                    .as_ref()
                    .is_some_and(|block| block_assigns_symbol(block, wanted))
        }
        Stmt::Switch {
            clauses, default, ..
        } => {
            clauses
                .iter()
                .any(|clause| block_assigns_symbol(&clause.body, wanted))
                || default
                    .as_ref()
                    .is_some_and(|block| block_assigns_symbol(block, wanted))
        }
        _ => false,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct ProcessBuilderIo {
    merge_error: bool,
    output_redirected: bool,
    error_redirected: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct ProcessIoStatus {
    merge_error: bool,
    output_redirected: bool,
    error_redirected: bool,
    output_drained: bool,
    error_drained: bool,
}

#[derive(Clone, Copy, Debug)]
enum ProcessStream {
    Output,
    Error,
}

enum ProcessRawEvent {
    Assign {
        symbol: SymbolId,
        rhs: Expr,
        offset: u32,
    },
    Call(CallExpr),
}

impl ProcessRawEvent {
    fn sort_key(&self) -> (u32, u8) {
        match self {
            Self::Assign { offset, .. } => (*offset, 0),
            Self::Call(call) => (call.span.start_byte, 1),
        }
    }
}

fn call_target_name(call: &CallExpr) -> Option<&str> {
    match &call.target {
        CallTarget::Named(name) => Some(name),
        CallTarget::Resolved(_) | CallTarget::Dynamic(_) => None,
    }
}

fn process_creation_status(
    expression: &Expr,
    builders: &HashMap<SymbolId, ProcessBuilderIo>,
) -> Option<ProcessIoStatus> {
    let expression = match expression {
        Expr::Cast { expr, .. } => expr.as_ref(),
        other => other,
    };
    let Expr::Call(call) = expression else {
        return None;
    };
    let name = call_target_name(call)?.rsplit('.').next()?;
    if name == "exec" {
        return Some(ProcessIoStatus::default());
    }
    if name != "start" {
        return None;
    }
    let builder = call
        .receiver
        .as_deref()
        .map(|receiver| builder_io_from_expr(receiver, builders))
        .unwrap_or_default();
    Some(ProcessIoStatus {
        merge_error: builder.merge_error,
        output_redirected: builder.output_redirected,
        error_redirected: builder.error_redirected,
        ..Default::default()
    })
}

fn builder_io_from_expr(
    expression: &Expr,
    builders: &HashMap<SymbolId, ProcessBuilderIo>,
) -> ProcessBuilderIo {
    match expression {
        Expr::VarRef { symbol, .. } => builders.get(symbol).copied().unwrap_or_default(),
        Expr::New { type_name, .. }
            if type_name.rsplit('.').next() == Some("ProcessBuilder") =>
        {
            ProcessBuilderIo::default()
        }
        Expr::Cast { expr, .. } => builder_io_from_expr(expr, builders),
        Expr::Call(call) => {
            let mut state = call
                .receiver
                .as_deref()
                .map(|receiver| builder_io_from_expr(receiver, builders))
                .unwrap_or_default();
            match call_target_name(call).and_then(|name| name.rsplit('.').next()) {
                Some("redirectErrorStream")
                    if call.args.first().is_some_and(|argument| {
                        matches!(
                            argument,
                            Expr::Literal {
                                kind: LiteralKind::Bool(true),
                                ..
                            }
                        )
                    }) =>
                {
                    state.merge_error = true;
                }
                Some("redirectOutput") => state.output_redirected = true,
                Some("redirectError") => state.error_redirected = true,
                Some("inheritIO") => {
                    state.output_redirected = true;
                    state.error_redirected = true;
                }
                _ => {}
            }
            state
        }
        _ => ProcessBuilderIo::default(),
    }
}

fn process_stream_source(
    expression: &Expr,
    processes: &HashMap<SymbolId, ProcessIoStatus>,
    streams: &HashMap<SymbolId, (SymbolId, ProcessStream)>,
) -> Option<(SymbolId, ProcessStream)> {
    match expression {
        Expr::VarRef { symbol, .. } => streams.get(symbol).copied(),
        Expr::Cast { expr, .. } => process_stream_source(expr, processes, streams),
        Expr::New { args, .. } => args
            .iter()
            .find_map(|argument| process_stream_source(argument, processes, streams)),
        Expr::Call(call) => {
            let name = call_target_name(call)
                .and_then(|name| name.rsplit('.').next())
                .unwrap_or_default();
            if matches!(name, "getInputStream" | "getErrorStream") {
                let process = call.receiver.as_deref().and_then(referenced_symbol)?;
                if processes.contains_key(&process) {
                    return Some((
                        process,
                        if name == "getInputStream" {
                            ProcessStream::Output
                        } else {
                            ProcessStream::Error
                        },
                    ));
                }
            }
            call.receiver
                .as_deref()
                .and_then(|receiver| process_stream_source(receiver, processes, streams))
                .or_else(|| {
                    call.args.iter().find_map(|argument| {
                        process_stream_source(argument, processes, streams)
                    })
                })
        }
        _ => None,
    }
}

fn expression_has_access_after_write(
    expression: &Expr,
    written: &mut HashSet<SymbolId>,
) -> bool {
    match expression {
        Expr::VarRef { symbol, .. } => written.contains(symbol),
        Expr::Literal { .. } | Expr::Opaque { .. } | Expr::Unknown { .. } => false,
        Expr::Unary { op, expr, .. } => {
            let conflict = expression_has_access_after_write(expr, written);
            if matches!(
                op,
                UnaryOp::PreIncrement
                    | UnaryOp::PostIncrement
                    | UnaryOp::PreDecrement
                    | UnaryOp::PostDecrement
            ) {
                if let Some(symbol) = referenced_symbol(expr) {
                    return conflict || !written.insert(symbol);
                }
            }
            conflict
        }
        Expr::Binary { lhs, rhs, .. }
        | Expr::IndexRead {
            base: lhs,
            index: rhs,
            ..
        }
        | Expr::Range {
            low: lhs,
            high: rhs,
            ..
        } => {
            expression_has_access_after_write(lhs, written)
                || expression_has_access_after_write(rhs, written)
        }
        Expr::FieldRead { base, .. } | Expr::Cast { expr: base, .. } => {
            expression_has_access_after_write(base, written)
        }
        Expr::Call(call) => {
            call.receiver
                .as_deref()
                .is_some_and(|receiver| expression_has_access_after_write(receiver, written))
                || call
                    .args
                    .iter()
                    .any(|argument| expression_has_access_after_write(argument, written))
                || matches!(&call.target, CallTarget::Dynamic(target) if expression_has_access_after_write(target, written))
        }
        Expr::New { args, .. }
        | Expr::Interp { parts: args, .. }
        | Expr::Collection { elements: args, .. } => args
            .iter()
            .any(|argument| expression_has_access_after_write(argument, written)),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            if expression_has_access_after_write(cond, written) {
                return true;
            }
            let mut then_written = written.clone();
            let mut else_written = written.clone();
            let conflict = expression_has_access_after_write(then_expr, &mut then_written)
                || expression_has_access_after_write(else_expr, &mut else_written);
            written.extend(then_written);
            written.extend(else_written);
            conflict
        }
        Expr::Assign { lhs, rhs, .. } => {
            if lvalue_has_access_after_write(lhs, written)
                || expression_has_access_after_write(rhs, written)
            {
                return true;
            }
            lvalue_written_symbol(lhs).is_some_and(|symbol| !written.insert(symbol))
        }
        // A lambda body executes in a distinct expression context.
        Expr::Lambda { .. } => false,
    }
}

fn lvalue_has_access_after_write(lhs: &LValue, written: &mut HashSet<SymbolId>) -> bool {
    match lhs {
        LValue::Var(_) => false,
        LValue::Field { base, .. } => expression_has_access_after_write(base, written),
        LValue::Index { base, index } => {
            expression_has_access_after_write(base, written)
                || expression_has_access_after_write(index, written)
        }
    }
}

fn lvalue_written_symbol(lhs: &LValue) -> Option<SymbolId> {
    match lhs {
        LValue::Var(symbol) => Some(*symbol),
        LValue::Field { .. } | LValue::Index { .. } => None,
    }
}

fn is_null_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Literal {
            kind: LiteralKind::Null,
            ..
        }
    )
}

fn is_create_temp_file_call(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Call(CallExpr {
            target: CallTarget::Named(name),
            ..
        }) if name == "File.createTempFile" || name == "java.io.File.createTempFile"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NullValueState {
    DefinitelyNull,
    Nullable,
    NonNull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NullSafetyEvent {
    DefiniteDereference,
    NullableDereference,
    RedundantCheck,
}

fn analyze_null_block(
    block: &Block,
    states: &mut HashMap<SymbolId, NullValueState>,
    events: &mut Vec<(NullSafetyEvent, Span)>,
) {
    for statement in &block.stmts {
        match statement {
            Stmt::Let { symbol, init, .. } => {
                if let Some(value) = init {
                    analyze_null_expr(value, states, events);
                    set_null_state(*symbol, value, states);
                }
            }
            Stmt::Assign { lhs, rhs, .. } => {
                analyze_null_expr(rhs, states, events);
                if let LValue::Var(symbol) = lhs {
                    set_null_state(*symbol, rhs, states);
                } else {
                    analyze_null_lvalue(lhs, states, events);
                }
            }
            Stmt::Expr { expr, .. } => analyze_null_expr(expr, states, events),
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                analyze_null_expr(cond, states, events);
                let refinement = null_comparison(cond);
                if let Some((symbol, _)) = refinement {
                    if states.get(&symbol) == Some(&NullValueState::NonNull) {
                        events.push((NullSafetyEvent::RedundantCheck, argument_span(cond)));
                    }
                }
                let mut then_states = states.clone();
                let mut else_states = states.clone();
                if let Some((symbol, null_in_then)) = refinement {
                    then_states.insert(
                        symbol,
                        if null_in_then {
                            NullValueState::DefinitelyNull
                        } else {
                            NullValueState::NonNull
                        },
                    );
                    else_states.insert(
                        symbol,
                        if null_in_then {
                            NullValueState::NonNull
                        } else {
                            NullValueState::DefinitelyNull
                        },
                    );
                }
                analyze_null_block(then_block, &mut then_states, events);
                if let Some(block) = else_block {
                    analyze_null_block(block, &mut else_states, events);
                }
            }
            Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
                analyze_null_expr(cond, states, events);
                let mut nested = states.clone();
                if let Some((symbol, null_in_body)) = null_comparison(cond) {
                    nested.insert(
                        symbol,
                        if null_in_body {
                            NullValueState::DefinitelyNull
                        } else {
                            NullValueState::NonNull
                        },
                    );
                }
                analyze_null_block(body, &mut nested, events);
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
                ..
            } => {
                let mut nested = states.clone();
                analyze_null_block(init, &mut nested, events);
                if let Some(cond) = cond {
                    analyze_null_expr(cond, &mut nested, events);
                }
                analyze_null_block(body, &mut nested, events);
                analyze_null_block(update, &mut nested, events);
            }
            Stmt::ForEach { iterable, body, .. } => {
                analyze_null_expr(iterable, states, events);
                analyze_null_block(body, &mut states.clone(), events);
            }
            Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
                if let Some(value) = value {
                    analyze_null_expr(value, states, events);
                }
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                analyze_null_block(try_block, &mut states.clone(), events);
                for catch in catches {
                    analyze_null_block(&catch.body, &mut states.clone(), events);
                }
                if let Some(block) = finally_block {
                    analyze_null_block(block, states, events);
                }
            }
            Stmt::Switch {
                scrutinee,
                clauses,
                default,
                ..
            } => {
                analyze_null_expr(scrutinee, states, events);
                for clause in clauses {
                    analyze_null_block(&clause.body, &mut states.clone(), events);
                }
                if let Some(block) = default {
                    analyze_null_block(block, &mut states.clone(), events);
                }
            }
            Stmt::Break { .. } | Stmt::Continue { .. } => {}
        }
    }
}

fn analyze_null_lvalue(
    value: &LValue,
    states: &mut HashMap<SymbolId, NullValueState>,
    events: &mut Vec<(NullSafetyEvent, Span)>,
) {
    match value {
        LValue::Var(_) => {}
        LValue::Field { base, .. } => analyze_null_dereference(base, states, events),
        LValue::Index { base, index } => {
            analyze_null_dereference(base, states, events);
            analyze_null_expr(index, states, events);
        }
    }
}

fn analyze_null_expr(
    expression: &Expr,
    states: &mut HashMap<SymbolId, NullValueState>,
    events: &mut Vec<(NullSafetyEvent, Span)>,
) {
    match expression {
        Expr::Call(call) => {
            if let Some(receiver) = &call.receiver {
                analyze_null_dereference(receiver, states, events);
            }
            for argument in &call.args {
                analyze_null_expr(argument, states, events);
            }
            if let CallTarget::Dynamic(target) = &call.target {
                analyze_null_expr(target, states, events);
            }
        }
        Expr::FieldRead { base, .. } => analyze_null_dereference(base, states, events),
        Expr::IndexRead { base, index, .. } => {
            analyze_null_dereference(base, states, events);
            analyze_null_expr(index, states, events);
        }
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => {
            analyze_null_expr(expr, states, events)
        }
        Expr::Binary { lhs, rhs, .. } => {
            analyze_null_expr(lhs, states, events);
            analyze_null_expr(rhs, states, events);
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            analyze_null_expr(cond, states, events);
            analyze_null_expr(then_expr, &mut states.clone(), events);
            analyze_null_expr(else_expr, &mut states.clone(), events);
        }
        Expr::Assign { lhs, rhs, .. } => {
            analyze_null_expr(rhs, states, events);
            if let LValue::Var(symbol) = lhs {
                set_null_state(*symbol, rhs, states);
            } else {
                analyze_null_lvalue(lhs, states, events);
            }
        }
        Expr::Interp { parts, .. }
        | Expr::Collection {
            elements: parts, ..
        } => {
            for part in parts {
                analyze_null_expr(part, states, events);
            }
        }
        Expr::Range { low, high, .. } => {
            analyze_null_expr(low, states, events);
            analyze_null_expr(high, states, events);
        }
        Expr::Lambda { body, .. } => {
            analyze_null_block(body, &mut states.clone(), events);
        }
        Expr::New { args, .. } => {
            for argument in args {
                analyze_null_expr(argument, states, events);
            }
        }
        Expr::VarRef { .. } | Expr::Literal { .. } | Expr::Opaque { .. } | Expr::Unknown { .. } => {
        }
    }
}

fn analyze_null_dereference(
    expression: &Expr,
    states: &mut HashMap<SymbolId, NullValueState>,
    events: &mut Vec<(NullSafetyEvent, Span)>,
) {
    if let Expr::VarRef { symbol, span, .. } = expression {
        match states.get(symbol) {
            Some(NullValueState::DefinitelyNull) => {
                events.push((NullSafetyEvent::DefiniteDereference, *span))
            }
            Some(NullValueState::Nullable) => {
                events.push((NullSafetyEvent::NullableDereference, *span))
            }
            _ => {}
        }
        states.insert(*symbol, NullValueState::NonNull);
    } else {
        analyze_null_expr(expression, states, events);
    }
}

fn set_null_state(
    symbol: SymbolId,
    expression: &Expr,
    states: &mut HashMap<SymbolId, NullValueState>,
) {
    let state = match expression {
        Expr::Literal {
            kind: LiteralKind::Null,
            ..
        } => Some(NullValueState::DefinitelyNull),
        Expr::Literal { .. } | Expr::New { .. } | Expr::Lambda { .. } => {
            Some(NullValueState::NonNull)
        }
        Expr::VarRef { symbol, .. } => states.get(symbol).copied(),
        Expr::Call(call) if call_is_known_nullable(call) => Some(NullValueState::Nullable),
        _ => None,
    };
    if let Some(state) = state {
        states.insert(symbol, state);
    } else {
        states.remove(&symbol);
    }
}

fn call_is_known_nullable(call: &CallExpr) -> bool {
    let CallTarget::Named(name) = &call.target else {
        return false;
    };
    matches!(
        name.rsplit('.').next(),
        Some(
            "getenv"
                | "getProperty"
                | "getParameter"
                | "getAttribute"
                | "getHeader"
                | "findViewById"
                | "poll"
                | "peek"
        )
    )
}

fn null_comparison(expression: &Expr) -> Option<(SymbolId, bool)> {
    let Expr::Binary { op, lhs, rhs, .. } = expression else {
        return None;
    };
    if !matches!(op, BinaryOp::Eq | BinaryOp::Ne) {
        return None;
    }
    let symbol = match (&**lhs, &**rhs) {
        (Expr::VarRef { symbol, .. }, value) if is_null_literal(value) => *symbol,
        (value, Expr::VarRef { symbol, .. }) if is_null_literal(value) => *symbol,
        _ => return None,
    };
    Some((symbol, matches!(op, BinaryOp::Eq)))
}

fn numeric_width(name: &str) -> Option<(u8, u8)> {
    match name {
        "byte" | "Byte" => Some((0, 8)),
        "short" | "Short" | "char" | "Character" => Some((0, 16)),
        "int" | "Integer" => Some((0, 32)),
        "long" | "Long" => Some((0, 64)),
        "float" | "Float" => Some((1, 32)),
        "double" | "Double" => Some((1, 64)),
        _ => None,
    }
}

fn expression_path(expr: &Expr, symbol_names: &HashMap<SymbolId, String>) -> Option<String> {
    match expr {
        Expr::VarRef { symbol, .. } => symbol_names.get(symbol).cloned(),
        Expr::FieldRead { base, field, .. } => Some(format!(
            "{}.{}",
            expression_path(base, symbol_names)?,
            field
        )),
        Expr::Cast { expr, .. } => expression_path(expr, symbol_names),
        _ => None,
    }
}

fn integer_literal_value(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Literal {
            kind: LiteralKind::Int(value),
            ..
        } => Some(*value),
        Expr::Unary {
            op: UnaryOp::Neg,
            expr,
            ..
        } => integer_literal_value(expr)?.checked_neg(),
        Expr::Cast { expr, .. } => integer_literal_value(expr),
        _ => None,
    }
}

/// Symbol identity, rather than spelling, keeps block and lambda shadows distinct.
struct HirTypes {
    symbols: HashMap<SymbolId, String>,
    names: HashMap<uniflow_hir::TypeId, String>,
    fields: HashMap<(String, String), String>,
}

impl HirTypes {
    fn new(program: &Program) -> Self {
        let names = program
            .types
            .iter()
            .map(|ty| (ty.id, ty.name.clone()))
            .collect::<HashMap<_, _>>();
        let mut fields = HashMap::new();
        for module in &program.modules {
            for item in &module.items {
                if let Item::Class(class) = item {
                    for field in &class.fields {
                        if let Some(ty) = field.ty.and_then(|id| names.get(&id)) {
                            fields.insert((class.name.clone(), field.name.clone()), ty.clone());
                        }
                    }
                }
            }
        }
        Self {
            symbols: collect_symbol_types(program),
            names,
            fields,
        }
    }

    fn bind(&mut self, symbol: SymbolId, ty: Option<uniflow_hir::TypeId>) {
        if let Some(name) = ty.and_then(|id| self.names.get(&id)) {
            self.symbols.insert(symbol, name.clone());
        }
    }

    fn resolve<'a>(&'a self, expr: &'a Expr) -> Option<&'a str> {
        match expr {
            Expr::VarRef { symbol, .. } => self.symbols.get(symbol).map(String::as_str),
            Expr::FieldRead { base, field, .. } => {
                let owner = self.resolve(base)?;
                self.fields
                    .get(&(owner.to_owned(), field.clone()))
                    .map(String::as_str)
            }
            Expr::Cast { ty: Some(ty), .. } => self.names.get(ty).map(String::as_str),
            Expr::Cast { expr, .. } => self.resolve(expr),
            Expr::New { type_name, .. } => Some(type_name),
            _ => None,
        }
    }
}

fn collect_symbol_types(program: &Program) -> HashMap<SymbolId, String> {
    let type_names = program
        .types
        .iter()
        .map(|ty| (ty.id, ty.name.clone()))
        .collect::<HashMap<_, _>>();
    let mut output = HashMap::new();
    for module in &program.modules {
        for item in &module.items {
            match item {
                Item::Function(function) => {
                    for param in &function.params {
                        add_symbol_type(param.symbol, param.ty, &type_names, &mut output);
                    }
                    collect_block_symbol_types(&function.body, &type_names, &mut output);
                }
                Item::Class(class) => {
                    for field in &class.fields {
                        if let Some(symbol) = field.symbol {
                            add_symbol_type(symbol, field.ty, &type_names, &mut output);
                        }
                    }
                    for method in &class.methods {
                        for param in &method.params {
                            add_symbol_type(param.symbol, param.ty, &type_names, &mut output);
                        }
                        collect_block_symbol_types(&method.body, &type_names, &mut output);
                    }
                }
                Item::GlobalVar(global) => {
                    if let Some(symbol) = global.symbol {
                        add_symbol_type(symbol, global.ty, &type_names, &mut output);
                    }
                }
            }
        }
    }
    output
}

fn add_symbol_type(
    symbol: SymbolId,
    ty: Option<uniflow_hir::TypeId>,
    names: &HashMap<uniflow_hir::TypeId, String>,
    output: &mut HashMap<SymbolId, String>,
) {
    if let Some(name) = ty.and_then(|id| names.get(&id)) {
        output.insert(symbol, name.clone());
    }
}

fn collect_block_symbol_types(
    block: &Block,
    names: &HashMap<uniflow_hir::TypeId, String>,
    output: &mut HashMap<SymbolId, String>,
) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Let { symbol, ty, .. } => {
                if let Some(name) = ty.and_then(|id| names.get(&id)) {
                    output.insert(*symbol, name.clone());
                }
            }
            Stmt::If {
                then_block,
                else_block,
                ..
            } => {
                collect_block_symbol_types(then_block, names, output);
                if let Some(block) = else_block {
                    collect_block_symbol_types(block, names, output);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::ForEach { body, .. } => {
                collect_block_symbol_types(body, names, output)
            }
            Stmt::For {
                init, update, body, ..
            } => {
                collect_block_symbol_types(init, names, output);
                collect_block_symbol_types(update, names, output);
                collect_block_symbol_types(body, names, output);
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                collect_block_symbol_types(try_block, names, output);
                for catch in catches {
                    collect_block_symbol_types(&catch.body, names, output);
                }
                if let Some(block) = finally_block {
                    collect_block_symbol_types(block, names, output);
                }
            }
            Stmt::Switch {
                clauses, default, ..
            } => {
                for clause in clauses {
                    collect_block_symbol_types(&clause.body, names, output);
                }
                if let Some(block) = default {
                    collect_block_symbol_types(block, names, output);
                }
            }
            _ => {}
        }
    }
}

fn collect_automatic_symbols(program: &Program) -> HashSet<SymbolId> {
    let static_symbols = program
        .symbols
        .iter()
        .filter(|symbol| {
            symbol
                .attributes
                .get("storage_duration")
                .is_some_and(|value| value == "static")
        })
        .map(|symbol| symbol.id)
        .collect::<HashSet<_>>();
    let mut symbols = HashSet::new();
    for module in &program.modules {
        for item in &module.items {
            match item {
                Item::Function(function) => {
                    symbols.extend(function.params.iter().map(|param| param.symbol));
                    collect_block_locals(&function.body, &static_symbols, &mut symbols);
                }
                Item::Class(class) => {
                    for method in &class.methods {
                        symbols.extend(method.params.iter().map(|param| param.symbol));
                        collect_block_locals(&method.body, &static_symbols, &mut symbols);
                    }
                }
                Item::GlobalVar(_) => {}
            }
        }
    }
    symbols
}

fn collect_block_locals(
    block: &Block,
    static_symbols: &HashSet<SymbolId>,
    output: &mut HashSet<SymbolId>,
) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Let { symbol, .. } => {
                if !static_symbols.contains(symbol) {
                    output.insert(*symbol);
                }
            }
            Stmt::If {
                then_block,
                else_block,
                ..
            } => {
                collect_block_locals(then_block, static_symbols, output);
                if let Some(block) = else_block {
                    collect_block_locals(block, static_symbols, output);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::ForEach { body, .. } => {
                collect_block_locals(body, static_symbols, output)
            }
            Stmt::For {
                init, update, body, ..
            } => {
                collect_block_locals(init, static_symbols, output);
                collect_block_locals(update, static_symbols, output);
                collect_block_locals(body, static_symbols, output);
            }
            Stmt::Switch {
                clauses, default, ..
            } => {
                for clause in clauses {
                    collect_block_locals(&clause.body, static_symbols, output);
                }
                if let Some(block) = default {
                    collect_block_locals(block, static_symbols, output);
                }
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                collect_block_locals(try_block, static_symbols, output);
                for catch in catches {
                    collect_block_locals(&catch.body, static_symbols, output);
                }
                if let Some(block) = finally_block {
                    collect_block_locals(block, static_symbols, output);
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

fn named_argument_index(call: &CallExpr, name: &str) -> Option<usize> {
    call.arg_names
        .iter()
        .position(|candidate| candidate.as_deref() == Some(name))
}

#[derive(Default)]
struct ResourceEvents {
    acquisitions: Vec<(SymbolId, Span)>,
    closed: HashSet<SymbolId>,
    close_in_try: Vec<(SymbolId, Span)>,
    lifecycle: Vec<ResourceLifecycleEvent>,
    lock_lifecycle: Vec<LockLifecycleEvent>,
    temp_files: Vec<TempFileEvent>,
}

enum ResourceLifecycleEvent {
    Acquire(SymbolId),
    Release(SymbolId),
    Use(SymbolId, Span),
}

enum LockLifecycleEvent {
    Acquire(SymbolId, Span),
    Release(SymbolId, Span),
    Sleep(Span),
}

enum TempFileEvent {
    Create(SymbolId, Span),
    Delete(SymbolId),
    Mkdir(SymbolId, Span),
}

fn collect_resource_block(
    block: &Block,
    try_depth: usize,
    finally_depth: usize,
    out: &mut ResourceEvents,
) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Let {
                symbol, init, span, ..
            } => {
                if init.as_ref().is_some_and(|value| !is_null_literal(value)) {
                    out.acquisitions.push((*symbol, *span));
                }
                if let Some(value) = init {
                    collect_resource_expr(value, try_depth, finally_depth, out);
                }
                if init.as_ref().is_some_and(is_create_temp_file_call) {
                    out.temp_files.push(TempFileEvent::Create(*symbol, *span));
                }
                if init.as_ref().is_some_and(|value| !is_null_literal(value)) {
                    out.lifecycle.push(ResourceLifecycleEvent::Acquire(*symbol));
                }
            }
            Stmt::Assign { lhs, rhs, span, .. } => {
                if let LValue::Var(symbol) = lhs {
                    if !is_null_literal(rhs) {
                        out.acquisitions.push((*symbol, *span));
                    }
                }
                collect_resource_expr(rhs, try_depth, finally_depth, out);
                if let LValue::Var(symbol) = lhs {
                    if is_create_temp_file_call(rhs) {
                        out.temp_files.push(TempFileEvent::Create(*symbol, *span));
                    }
                    if !is_null_literal(rhs) {
                        out.lifecycle.push(ResourceLifecycleEvent::Acquire(*symbol));
                    }
                }
            }
            Stmt::Expr { expr, .. } => collect_resource_expr(expr, try_depth, finally_depth, out),
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                collect_resource_expr(cond, try_depth, finally_depth, out);
                collect_resource_block(then_block, try_depth, finally_depth, out);
                if let Some(block) = else_block {
                    collect_resource_block(block, try_depth, finally_depth, out);
                }
            }
            Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
                collect_resource_expr(cond, try_depth, finally_depth, out);
                collect_resource_block(body, try_depth, finally_depth, out);
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
                ..
            } => {
                collect_resource_block(init, try_depth, finally_depth, out);
                if let Some(cond) = cond {
                    collect_resource_expr(cond, try_depth, finally_depth, out);
                }
                collect_resource_block(body, try_depth, finally_depth, out);
                collect_resource_block(update, try_depth, finally_depth, out);
            }
            Stmt::ForEach { iterable, body, .. } => {
                collect_resource_expr(iterable, try_depth, finally_depth, out);
                collect_resource_block(body, try_depth, finally_depth, out);
            }
            Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
                if let Some(value) = value {
                    collect_resource_expr(value, try_depth, finally_depth, out);
                }
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                collect_resource_block(try_block, try_depth + 1, finally_depth, out);
                for catch in catches {
                    collect_resource_block(&catch.body, try_depth + 1, finally_depth, out);
                }
                if let Some(block) = finally_block {
                    collect_resource_block(block, try_depth, finally_depth + 1, out);
                }
            }
            Stmt::Switch {
                scrutinee,
                clauses,
                default,
                ..
            } => {
                collect_resource_expr(scrutinee, try_depth, finally_depth, out);
                for clause in clauses {
                    collect_resource_block(&clause.body, try_depth, finally_depth, out);
                }
                if let Some(block) = default {
                    collect_resource_block(block, try_depth, finally_depth, out);
                }
            }
            Stmt::Break { .. } | Stmt::Continue { .. } => {}
        }
    }
}

fn collect_resource_expr(
    expr: &Expr,
    try_depth: usize,
    finally_depth: usize,
    out: &mut ResourceEvents,
) {
    match expr {
        Expr::Call(call) => {
            let final_name = match &call.target {
                CallTarget::Named(name) => name.rsplit('.').next(),
                CallTarget::Dynamic(_) | CallTarget::Resolved(_) => None,
            };
            if matches!(
                &call.target,
                CallTarget::Named(name)
                    if name == "Thread.sleep" || name == "java.lang.Thread.sleep"
            ) {
                out.lock_lifecycle
                    .push(LockLifecycleEvent::Sleep(call.span));
            }
            if let Some(symbol) = call.receiver.as_deref().and_then(referenced_symbol) {
                if call.args.is_empty() {
                    match final_name {
                        Some("lock" | "lockInterruptibly" | "tryLock") => out
                            .lock_lifecycle
                            .push(LockLifecycleEvent::Acquire(symbol, call.span)),
                        Some("unlock") => out
                            .lock_lifecycle
                            .push(LockLifecycleEvent::Release(symbol, call.span)),
                        Some("delete") => out.temp_files.push(TempFileEvent::Delete(symbol)),
                        Some("mkdir" | "mkdirs") => {
                            out.temp_files.push(TempFileEvent::Mkdir(symbol, call.span))
                        }
                        _ => {}
                    }
                }
                if call.args.is_empty()
                    && matches!(final_name, Some("close" | "release" | "recycle"))
                {
                    out.closed.insert(symbol);
                    if try_depth != 0 && finally_depth == 0 {
                        out.close_in_try.push((symbol, call.span));
                    }
                    out.lifecycle.push(ResourceLifecycleEvent::Release(symbol));
                } else if !matches!(final_name, Some("isClosed" | "isReleased" | "isRecycled")) {
                    out.lifecycle
                        .push(ResourceLifecycleEvent::Use(symbol, call.span));
                }
            }
            if let Some(receiver) = &call.receiver {
                collect_resource_expr(receiver, try_depth, finally_depth, out);
            }
            for arg in &call.args {
                collect_resource_expr(arg, try_depth, finally_depth, out);
            }
            if let CallTarget::Dynamic(target) = &call.target {
                collect_resource_expr(target, try_depth, finally_depth, out);
            }
        }
        Expr::Assign { lhs, rhs, span, .. } => {
            if let LValue::Var(symbol) = lhs {
                if !is_null_literal(rhs) {
                    out.acquisitions.push((*symbol, *span));
                }
            }
            collect_resource_expr(rhs, try_depth, finally_depth, out);
        }
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } | Expr::FieldRead { base: expr, .. } => {
            collect_resource_expr(expr, try_depth, finally_depth, out)
        }
        Expr::Binary { lhs, rhs, .. }
        | Expr::IndexRead {
            base: lhs,
            index: rhs,
            ..
        }
        | Expr::Range {
            low: lhs,
            high: rhs,
            ..
        } => {
            collect_resource_expr(lhs, try_depth, finally_depth, out);
            collect_resource_expr(rhs, try_depth, finally_depth, out);
        }
        Expr::New { args, .. }
        | Expr::Interp { parts: args, .. }
        | Expr::Collection { elements: args, .. } => {
            for arg in args {
                collect_resource_expr(arg, try_depth, finally_depth, out);
            }
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            collect_resource_expr(cond, try_depth, finally_depth, out);
            collect_resource_expr(then_expr, try_depth, finally_depth, out);
            collect_resource_expr(else_expr, try_depth, finally_depth, out);
        }
        // A lambda is a separate method-like region in the source rule.
        Expr::Lambda { .. }
        | Expr::VarRef { .. }
        | Expr::Literal { .. }
        | Expr::Opaque { .. }
        | Expr::Unknown { .. } => {}
    }
}

fn is_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Literal { .. })
}

fn has_sql_wildcard_text(text: &str) -> bool {
    text.contains("'%") || text.contains("%'")
}

fn has_plain_assignment(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        if *byte != b'=' {
            return false;
        }
        let previous = index.checked_sub(1).and_then(|at| bytes.get(at)).copied();
        let next = bytes.get(index + 1).copied();
        !matches!(
            previous,
            Some(b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' | b'!' | b'<' | b'>' | b'=')
        ) && next != Some(b'=')
    })
}

fn expr_has_sql_wildcard(expr: &Expr) -> bool {
    match expr {
        Expr::Literal {
            kind: LiteralKind::String(value),
            ..
        } => has_sql_wildcard_text(value),
        Expr::Binary { lhs, rhs, .. } => expr_has_sql_wildcard(lhs) || expr_has_sql_wildcard(rhs),
        Expr::Conditional {
            then_expr,
            else_expr,
            ..
        } => expr_has_sql_wildcard(then_expr) || expr_has_sql_wildcard(else_expr),
        Expr::Interp { parts, .. }
        | Expr::Collection {
            elements: parts, ..
        } => parts.iter().any(expr_has_sql_wildcard),
        Expr::Cast { expr, .. } => expr_has_sql_wildcard(expr),
        _ => false,
    }
}

fn expr_contains_marked_symbol(
    expr: &Expr,
    marked: &HashMap<SymbolId, bool>,
    fields: &HashSet<String>,
) -> bool {
    match expr {
        Expr::VarRef { symbol, .. } => marked.get(symbol).copied().unwrap_or(false),
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => {
            expr_contains_marked_symbol(expr, marked, fields)
        }
        Expr::FieldRead { base, field, .. } => {
            fields.contains(field) || expr_contains_marked_symbol(base, marked, fields)
        }
        Expr::Binary { lhs, rhs, .. }
        | Expr::IndexRead {
            base: lhs,
            index: rhs,
            ..
        }
        | Expr::Range {
            low: lhs,
            high: rhs,
            ..
        } => {
            expr_contains_marked_symbol(lhs, marked, fields)
                || expr_contains_marked_symbol(rhs, marked, fields)
        }
        Expr::Call(call) => {
            call.receiver
                .as_deref()
                .is_some_and(|value| expr_contains_marked_symbol(value, marked, fields))
                || call
                    .args
                    .iter()
                    .any(|value| expr_contains_marked_symbol(value, marked, fields))
        }
        Expr::New { args, .. }
        | Expr::Interp { parts: args, .. }
        | Expr::Collection { elements: args, .. } => args
            .iter()
            .any(|value| expr_contains_marked_symbol(value, marked, fields)),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => [cond.as_ref(), then_expr.as_ref(), else_expr.as_ref()]
            .iter()
            .any(|value| expr_contains_marked_symbol(value, marked, fields)),
        Expr::Assign { rhs, .. } => expr_contains_marked_symbol(rhs, marked, fields),
        Expr::Lambda { captures, .. } => captures
            .iter()
            .any(|capture| marked.get(&capture.source_symbol).copied().unwrap_or(false)),
        Expr::Literal { .. } | Expr::Opaque { .. } | Expr::Unknown { .. } => false,
    }
}

fn equality_result(op: BinaryOp, lhs: &Expr, rhs: &Expr) -> Option<bool> {
    let equal = if expression_fingerprint(lhs) == expression_fingerprint(rhs) {
        true
    } else {
        match (lhs, rhs) {
            (
                Expr::Literal {
                    kind: LiteralKind::Int(_),
                    ..
                },
                Expr::Literal {
                    kind: LiteralKind::Int(_),
                    ..
                },
            )
            | (
                Expr::Literal {
                    kind: LiteralKind::String(_),
                    ..
                },
                Expr::Literal {
                    kind: LiteralKind::String(_),
                    ..
                },
            )
            | (
                Expr::Literal {
                    kind: LiteralKind::Bool(_),
                    ..
                },
                Expr::Literal {
                    kind: LiteralKind::Bool(_),
                    ..
                },
            ) => false,
            _ => return None,
        }
    };
    Some(if op == BinaryOp::Eq { equal } else { !equal })
}

/// Stable within one HIR program: source locations and node IDs are omitted,
/// while resolved symbols keep shadowed identifiers distinct.
fn expression_fingerprint(expr: &Expr) -> String {
    match expr {
        Expr::VarRef { symbol, .. } => format!("v{}", symbol.0),
        Expr::Literal { kind, .. } => match kind {
            LiteralKind::Null => "null".into(),
            LiteralKind::Bool(value) => format!("bool:{value}"),
            LiteralKind::Int(value) => format!("int:{value}"),
            LiteralKind::Float(value) => format!("float:{:x}", value.to_bits()),
            LiteralKind::String(value) => format!("string:{value:?}"),
            LiteralKind::Bytes(value) => format!("bytes:{value:?}"),
        },
        Expr::Unary { op, expr, .. } => format!("unary:{op:?}({})", expression_fingerprint(expr)),
        Expr::Binary { op, lhs, rhs, .. } => format!(
            "binary:{op:?}({},{})",
            expression_fingerprint(lhs),
            expression_fingerprint(rhs)
        ),
        Expr::FieldRead { base, field, .. } => {
            format!("field:({}).{field}", expression_fingerprint(base))
        }
        Expr::IndexRead { base, index, .. } => format!(
            "index:({})[{}]",
            expression_fingerprint(base),
            expression_fingerprint(index)
        ),
        Expr::Call(call) => {
            let target = match &call.target {
                CallTarget::Resolved(symbol) => format!("resolved:{}", symbol.0),
                CallTarget::Named(name) => format!("named:{name}"),
                CallTarget::Dynamic(value) => format!("dynamic:{}", expression_fingerprint(value)),
            };
            let receiver = call
                .receiver
                .as_deref()
                .map(expression_fingerprint)
                .unwrap_or_default();
            let args = call
                .args
                .iter()
                .map(expression_fingerprint)
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "call:{}/{receiver}/{target}({args})",
                call.qualifier_is_explicit
            )
        }
        Expr::Lambda { .. } | Expr::Unknown { .. } => format!("unique:{expr:p}"),
        Expr::New {
            type_name, args, ..
        } => format!(
            "new:{type_name}({})",
            args.iter()
                .map(expression_fingerprint)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Expr::Cast { ty, expr, .. } => format!("cast:{ty:?}({})", expression_fingerprint(expr)),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => format!(
            "conditional:({},{},{})",
            expression_fingerprint(cond),
            expression_fingerprint(then_expr),
            expression_fingerprint(else_expr)
        ),
        Expr::Assign { lhs, rhs, .. } => format!(
            "assign:{}={}",
            lvalue_fingerprint(lhs),
            expression_fingerprint(rhs)
        ),
        Expr::Interp { parts, .. } => format!(
            "interp:({})",
            parts
                .iter()
                .map(expression_fingerprint)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Expr::Collection {
            container,
            elements,
            ..
        } => format!(
            "collection:{container:?}({})",
            elements
                .iter()
                .map(expression_fingerprint)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Expr::Range {
            low,
            high,
            exclusive,
            ..
        } => format!(
            "range:{exclusive}({},{})",
            expression_fingerprint(low),
            expression_fingerprint(high)
        ),
        Expr::Opaque { text, .. } => format!("opaque:{text}"),
    }
}

fn lvalue_fingerprint(value: &LValue) -> String {
    match value {
        LValue::Var(symbol) => format!("v{}", symbol.0),
        LValue::Field { base, field } => {
            format!("field:({}).{field}", expression_fingerprint(base))
        }
        LValue::Index { base, index } => format!(
            "index:({})[{}]",
            expression_fingerprint(base),
            expression_fingerprint(index)
        ),
    }
}

fn is_assignment_operand(expr: &Expr) -> bool {
    match expr {
        Expr::Assign { .. } => true,
        Expr::Cast { expr, .. } => is_assignment_operand(expr),
        _ => false,
    }
}

fn string_literal_value(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Literal {
            kind: LiteralKind::String(value),
            ..
        } => Some(value),
        _ => None,
    }
}

fn expression_has_string_matching(expr: &Expr, pattern: &str) -> bool {
    let Ok(regex) = Regex::new(pattern) else {
        return false;
    };
    fn visit(expr: &Expr, regex: &Regex) -> bool {
        match expr {
            Expr::Literal {
                kind: LiteralKind::String(value),
                ..
            } => regex.is_match(value),
            Expr::Unary { expr, .. }
            | Expr::Cast { expr, .. }
            | Expr::FieldRead { base: expr, .. } => visit(expr, regex),
            Expr::Binary { lhs, rhs, .. }
            | Expr::IndexRead {
                base: lhs,
                index: rhs,
                ..
            }
            | Expr::Range {
                low: lhs,
                high: rhs,
                ..
            } => visit(lhs, regex) || visit(rhs, regex),
            Expr::Call(call) => {
                call.receiver
                    .as_deref()
                    .is_some_and(|value| visit(value, regex))
                    || call.args.iter().any(|value| visit(value, regex))
            }
            Expr::New { args, .. }
            | Expr::Interp { parts: args, .. }
            | Expr::Collection { elements: args, .. } => {
                args.iter().any(|value| visit(value, regex))
            }
            Expr::Conditional {
                cond,
                then_expr,
                else_expr,
                ..
            } => visit(cond, regex) || visit(then_expr, regex) || visit(else_expr, regex),
            Expr::Assign { rhs, .. } => visit(rhs, regex),
            _ => false,
        }
    }
    visit(expr, &regex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BaselinePack;

    #[test]
    fn call_rule_index_keeps_exact_and_regex_callee_rules() {
        let pack = BaselinePack::from_yaml_str(
            r#"
id: call-index-test
title: Call index test
rules:
  - id: EXACT
    title: Exact callee
    languages: [java]
    severity: warning
    confidence: high
    matcher:
      callee: '^indexOf$'
  - id: QUALIFIED
    title: Qualified callee
    languages: [java]
    severity: warning
    confidence: high
    matcher:
      callee: '(^|\\.)DriverManager\\.getConnection$'
"#,
        )
        .expect("valid local call rules");
        let (generic, exact) = build_call_rule_index(&pack, &Language::Java);
        assert_eq!(exact.get("indexOf"), Some(&vec![0]));
        assert_eq!(generic, vec![1]);
    }

    #[test]
    fn source_regex_cache_is_shared_across_project_files() {
        let pack = BaselinePack::from_yaml_str(
            r#"
id: regex-cache-test
title: Regex cache test
rules:
  - id: MATCH
    title: Match dangerous API
    languages: [java]
    severity: warning
    confidence: high
    pattern: dangerous
"#,
        )
        .expect("valid local source rule");
        let mut cache = HashMap::new();
        let options = BaselineScanOptions::default();
        for path in ["One.java", "Two.java"] {
            let findings = pack.scan_source_rules_with_regex_cache(
                &Language::Java,
                Path::new(path),
                "dangerous();",
                false,
                &options,
                &mut cache,
            );
            assert_eq!(findings.len(), 1);
        }
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key("dangerous"));
    }
}
