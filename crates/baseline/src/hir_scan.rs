use crate::{
    deduplicate_findings, rule_message, BaselineFinding, BaselinePack, BaselineRule,
};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use uniflow_hir::{
    Block, CallExpr, CallTarget, Expr, Item, LValue, Language, LiteralKind, Program, Span, Stmt,
    SymbolId,
};

impl BaselinePack {
    /// Scan parsed HIR using structured call/argument constraints, then apply
    /// source regexes only for rules without structured matchers.
    pub fn scan_hir(
        &self,
        program: &Program,
        source_by_path: &HashMap<String, String>,
    ) -> Vec<BaselineFinding> {
        let mut scanner = HirScanner {
            pack: self,
            language: &program.language,
            file_paths: program
                .files
                .iter()
                .map(|file| (file.id.0, file.path.clone()))
                .collect(),
            source_by_path,
            findings: Vec::new(),
        };
        for module in &program.modules {
            for item in &module.items {
                scanner.visit_item(item);
            }
        }
        for (path, source) in source_by_path {
            scanner.findings.extend(self.scan_source_rules(
                &program.language,
                Path::new(path),
                source,
                true,
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
    findings: Vec<BaselineFinding>,
}

impl HirScanner<'_> {
    fn visit_item(&mut self, item: &Item) {
        match item {
            Item::Function(function) => self.visit_block(&function.body),
            Item::Class(class) => {
                for method in &class.methods {
                    self.visit_block(&method.body);
                }
            }
            Item::GlobalVar(global) => {
                if let Some(init) = &global.init {
                    self.visit_expr(init, ValueUse::Used);
                }
            }
        }
    }

    fn visit_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let { symbol, init, .. } => {
                if let Some(expr) = init {
                    self.visit_expr(expr, ValueUse::AssignedTo(*symbol));
                }
            }
            Stmt::Assign { lhs, rhs, .. } => {
                self.visit_lvalue(lhs);
                let usage = match lhs {
                    LValue::Var(symbol) => ValueUse::AssignedTo(*symbol),
                    _ => ValueUse::Used,
                };
                self.visit_expr(rhs, usage);
            }
            Stmt::Expr { expr, .. } => self.visit_expr(expr, ValueUse::Discarded),
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                self.visit_expr(cond, ValueUse::Used);
                self.visit_block(then_block);
                if let Some(block) = else_block {
                    self.visit_block(block);
                }
            }
            Stmt::While { cond, body, .. } => {
                self.visit_expr(cond, ValueUse::Used);
                self.visit_block(body);
            }
            Stmt::ForEach { iterable, body, .. } => {
                self.visit_expr(iterable, ValueUse::Used);
                self.visit_block(body);
            }
            Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
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
                    self.visit_block(&catch.body);
                }
                if let Some(block) = finally_block {
                    self.visit_block(block);
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
            Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => self.visit_expr(expr, usage),
            Expr::Binary { lhs, rhs, .. } => {
                self.visit_expr(lhs, ValueUse::Used);
                self.visit_expr(rhs, ValueUse::Used);
            }
            Expr::FieldRead { base, .. } => self.visit_expr(base, ValueUse::Used),
            Expr::IndexRead { base, index, .. } => {
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
            Expr::Lambda { body, .. } => self.visit_block(body),
            Expr::New { args, .. } => {
                for arg in args {
                    self.visit_expr(arg, ValueUse::Used);
                }
            }
        }
    }

    fn match_call(&mut self, callee: &str, call: &CallExpr, usage: ValueUse) {
        for rule in &self.pack.rules {
            if !rule.matcher.is_structured() {
                continue;
            }
            if !rule.languages.is_empty()
                && !rule.languages.iter().any(|item| item == self.language)
            {
                continue;
            }
            if rule_matches_call(rule, callee, call, usage) {
                self.push_finding(rule, callee, call.span);
            }
        }
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
        });
    }
}

fn rule_matches_call(rule: &BaselineRule, callee: &str, call: &CallExpr, usage: ValueUse) -> bool {
    let expr = if rule.matcher.callee.is_empty() {
        &rule.pattern
    } else {
        &rule.matcher.callee
    };
    if expr.is_empty() || Regex::new(expr).map_or(true, |regex| !regex.is_match(callee)) {
        return false;
    }
    let argc = call.args.len();
    if rule.matcher.min_args.is_some_and(|min| argc < min)
        || rule.matcher.max_args.is_some_and(|max| argc > max)
    {
        return false;
    }
    if rule.matcher.ignored_return && !matches!(usage, ValueUse::Discarded) {
        return false;
    }
    if rule.matcher.self_assignment {
        let ValueUse::AssignedTo(lhs) = usage else {
            return false;
        };
        let Some(Expr::VarRef { symbol: rhs, .. }) = call.args.first() else {
            return false;
        };
        if lhs != *rhs {
            return false;
        }
    }
    if rule
        .matcher
        .literal_args
        .iter()
        .any(|&idx| !call.args.get(idx).is_some_and(is_literal))
    {
        return false;
    }
    if rule
        .matcher
        .non_literal_args
        .iter()
        .any(|&idx| call.args.get(idx).is_none_or(is_literal))
    {
        return false;
    }
    for (index, pattern) in &rule.matcher.string_arg_patterns {
        let Some(value) = call.args.get(*index).and_then(string_literal_value) else {
            return false;
        };
        if Regex::new(pattern).map_or(true, |regex| !regex.is_match(value)) {
            return false;
        }
    }
    for (index, expected) in &rule.matcher.int_arg_values {
        if !call.args.get(*index).is_some_and(|arg| {
            matches!(
                arg,
                Expr::Literal {
                    kind: LiteralKind::Int(value),
                    ..
                } if value == expected
            )
        }) {
            return false;
        }
    }
    for (index, expected) in &rule.matcher.bool_arg_values {
        if !call.args.get(*index).is_some_and(|arg| {
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

fn named_argument_index(call: &CallExpr, name: &str) -> Option<usize> {
    call.arg_names
        .iter()
        .position(|candidate| candidate.as_deref() == Some(name))
}

fn is_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Literal { .. })
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
