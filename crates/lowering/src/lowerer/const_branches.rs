//! Compile-time-constant branch folding, run on each function's HIR body
//! before it is lowered.
//!
//! `if ((7 * 18) + num > 200) bar = "safe"; else bar = param;` with
//! `int num = 106;` can only ever take one branch. Lowering both made the
//! dead branch's data flow look live: a request parameter assigned only on a
//! never-taken path was reported as reaching the sink. Compilers fold these
//! (javac treats constant conditions specially), and so should a data-flow
//! analysis that wants to be precise.
//!
//! Deliberately narrow:
//! - only integer/boolean/string literals, arithmetic and comparisons, and
//!   locals whose *single* write in the function is such a constant;
//! - a local counts as constant only if nothing else ever writes it (no
//!   reassignment, `++`, compound assignment, loop variable, catch/for-each
//!   binding, or lambda capture);
//! - anything not provably constant keeps both branches, as before.
use std::collections::HashMap;
use uniflow_hir::{BinaryOp, Block, Expr, LValue, LiteralKind, Stmt, SymbolId, UnaryOp};

#[derive(Clone, Debug, PartialEq)]
enum Const {
    Int(i64),
    Bool(bool),
    Str(String),
}

/// Returns `body` with every provably constant `if`/`?:` reduced to the
/// branch that runs. Returns `None` when nothing was folded, so callers can
/// keep borrowing the original body.
pub(crate) fn fold_constant_branches(body: &Block) -> Option<Block> {
    let mut writes: HashMap<SymbolId, (usize, Option<Expr>)> = HashMap::new();
    count_writes_block(body, &mut writes);
    let mut constants: HashMap<SymbolId, Const> = HashMap::new();
    // Resolve single-write locals to constants; a constant may depend on an
    // earlier one (`int a = 3; int b = a * 2;`), so iterate to a fixpoint.
    loop {
        let before = constants.len();
        for (symbol, (count, init)) in &writes {
            if *count == 1 && !constants.contains_key(symbol) {
                if let Some(value) = init.as_ref().and_then(|expr| eval(expr, &constants)) {
                    constants.insert(*symbol, value);
                }
            }
        }
        if constants.len() == before {
            break;
        }
    }
    let mut changed = false;
    let folded = fold_block(body, &constants, &mut changed);
    changed.then_some(folded)
}

fn bump(writes: &mut HashMap<SymbolId, (usize, Option<Expr>)>, symbol: SymbolId, init: Option<&Expr>) {
    let entry = writes.entry(symbol).or_insert((0, None));
    entry.0 += 1;
    entry.1 = if entry.0 == 1 { init.cloned() } else { None };
}

fn count_writes_block(block: &Block, writes: &mut HashMap<SymbolId, (usize, Option<Expr>)>) {
    for stmt in &block.stmts {
        count_writes_stmt(stmt, writes);
    }
}

fn count_writes_stmt(stmt: &Stmt, writes: &mut HashMap<SymbolId, (usize, Option<Expr>)>) {
    match stmt {
        Stmt::Let { symbol, init, .. } => {
            // A declaration without initializer is not a write.
            if let Some(init) = init {
                bump(writes, *symbol, Some(init));
                count_writes_expr(init, writes);
            }
        }
        Stmt::Assign { lhs, rhs, .. } => {
            match lhs {
                LValue::Var(symbol) => bump(writes, *symbol, Some(rhs)),
                LValue::Field { base, .. } => count_writes_expr(base, writes),
                LValue::Index { base, index } => {
                    count_writes_expr(base, writes);
                    count_writes_expr(index, writes);
                }
            }
            count_writes_expr(rhs, writes);
        }
        Stmt::ForEach { item_symbol, iterable, body, .. } => {
            // Loop bindings are rewritten every iteration.
            bump(writes, *item_symbol, None);
            bump(writes, *item_symbol, None);
            count_writes_expr(iterable, writes);
            count_writes_block(body, writes);
        }
        _ => visit_stmt_children(stmt, &mut |child| match child {
            Child::Block(block) => count_writes_block(block, writes),
            Child::Expr(expr) => count_writes_expr(expr, writes),
        }),
    }
}

fn count_writes_expr(expr: &Expr, writes: &mut HashMap<SymbolId, (usize, Option<Expr>)>) {
    match expr {
        Expr::Assign { lhs, rhs, .. } => {
            if let LValue::Var(symbol) = lhs {
                // Assignment in expression position (`while ((x = f()) …)`):
                // never treat as a constant definition.
                bump(writes, *symbol, None);
                bump(writes, *symbol, None);
            }
            count_writes_expr(rhs, writes);
        }
        Expr::Unary { op, expr: inner, .. } => {
            if matches!(op, UnaryOp::PreIncrement | UnaryOp::PreDecrement | UnaryOp::PostIncrement | UnaryOp::PostDecrement) {
                if let Expr::VarRef { symbol, .. } = inner.as_ref() {
                    bump(writes, *symbol, None);
                    bump(writes, *symbol, None);
                }
            }
            count_writes_expr(inner, writes);
        }
        Expr::Lambda { captures, .. } => {
            // A captured local may be mutated by the lambda body; be
            // conservative about every capture.
            for capture in captures {
                bump(writes, capture.source_symbol, None);
                bump(writes, capture.source_symbol, None);
            }
        }
        _ => visit_expr_children(expr, &mut |child| count_writes_expr(child, writes)),
    }
}

enum Child<'a> {
    Block(&'a Block),
    Expr(&'a Expr),
}

/// Every nested block/expression of a statement, for the passes above that
/// only care about a few statement kinds.
fn visit_stmt_children<'a>(stmt: &'a Stmt, f: &mut impl FnMut(Child<'a>)) {
    match stmt {
        Stmt::Expr { expr, .. } => f(Child::Expr(expr)),
        Stmt::If { cond, then_block, else_block, .. } => {
            f(Child::Expr(cond));
            f(Child::Block(then_block));
            if let Some(else_block) = else_block {
                f(Child::Block(else_block));
            }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
            f(Child::Expr(cond));
            f(Child::Block(body));
        }
        Stmt::For { init, cond, update, body, .. } => {
            // A `for` loop's init/update blocks write the loop variable more
            // than once in effect; the counting pass sees both.
            f(Child::Block(init));
            if let Some(cond) = cond {
                f(Child::Expr(cond));
            }
            f(Child::Block(update));
            f(Child::Block(update));
            f(Child::Block(body));
        }
        Stmt::Return { value: Some(value), .. } | Stmt::Throw { value: Some(value), .. } => f(Child::Expr(value)),
        Stmt::Try { try_block, catches, finally_block, .. } => {
            f(Child::Block(try_block));
            for catch in catches {
                f(Child::Block(&catch.body));
            }
            if let Some(finally_block) = finally_block {
                f(Child::Block(finally_block));
            }
        }
        Stmt::Switch { scrutinee, clauses, default, .. } => {
            f(Child::Expr(scrutinee));
            for clause in clauses {
                for value in &clause.values {
                    f(Child::Expr(value));
                }
                f(Child::Block(&clause.body));
            }
            if let Some(default) = default {
                f(Child::Block(default));
            }
        }
        _ => {}
    }
}

fn visit_expr_children<'a>(expr: &'a Expr, f: &mut impl FnMut(&'a Expr)) {
    match expr {
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => f(expr),
        Expr::Binary { lhs, rhs, .. } => {
            f(lhs);
            f(rhs);
        }
        Expr::FieldRead { base, .. } => f(base),
        Expr::IndexRead { base, index, .. } => {
            f(base);
            f(index);
        }
        Expr::Call(call) => {
            if let Some(receiver) = &call.receiver {
                f(receiver);
            }
            for arg in &call.args {
                f(arg);
            }
        }
        Expr::New { args, .. } => args.iter().for_each(f),
        Expr::Conditional { cond, then_expr, else_expr, .. } => {
            f(cond);
            f(then_expr);
            f(else_expr);
        }
        Expr::Assign { rhs, .. } => f(rhs),
        Expr::Interp { parts, .. } => parts.iter().for_each(f),
        Expr::Collection { elements, .. } => elements.iter().for_each(f),
        Expr::Range { low, high, .. } => {
            f(low);
            f(high);
        }
        _ => {}
    }
}

fn eval(expr: &Expr, constants: &HashMap<SymbolId, Const>) -> Option<Const> {
    match expr {
        Expr::Literal { kind, .. } => match kind {
            LiteralKind::Int(value) => Some(Const::Int(*value)),
            LiteralKind::Bool(value) => Some(Const::Bool(*value)),
            LiteralKind::String(value) => Some(Const::Str(value.clone())),
            _ => None,
        },
        Expr::VarRef { symbol, .. } => constants.get(symbol).cloned(),
        Expr::Cast { expr, .. } => eval(expr, constants),
        Expr::Unary { op, expr, .. } => match (op, eval(expr, constants)?) {
            (UnaryOp::Not, Const::Bool(value)) => Some(Const::Bool(!value)),
            (UnaryOp::Neg, Const::Int(value)) => value.checked_neg().map(Const::Int),
            _ => None,
        },
        Expr::Binary { op, lhs, rhs, .. } => {
            // Short-circuit: `false && x` is constant even if `x` is not.
            let left = eval(lhs, constants);
            match (op, &left) {
                (BinaryOp::And, Some(Const::Bool(false))) => return Some(Const::Bool(false)),
                (BinaryOp::Or, Some(Const::Bool(true))) => return Some(Const::Bool(true)),
                _ => {}
            }
            let (left, right) = (left?, eval(rhs, constants)?);
            Some(match (op, left, right) {
                (BinaryOp::Add, Const::Int(a), Const::Int(b)) => Const::Int(a.checked_add(b)?),
                (BinaryOp::Sub, Const::Int(a), Const::Int(b)) => Const::Int(a.checked_sub(b)?),
                (BinaryOp::Mul, Const::Int(a), Const::Int(b)) => Const::Int(a.checked_mul(b)?),
                (BinaryOp::Div, Const::Int(a), Const::Int(b)) if b != 0 => Const::Int(a.checked_div(b)?),
                (BinaryOp::Mod, Const::Int(a), Const::Int(b)) if b != 0 => Const::Int(a.checked_rem(b)?),
                (BinaryOp::Add, Const::Str(a), Const::Str(b)) => Const::Str(a + &b),
                (BinaryOp::Eq, a, b) => Const::Bool(a == b),
                (BinaryOp::Ne, a, b) => Const::Bool(a != b),
                (BinaryOp::Lt, Const::Int(a), Const::Int(b)) => Const::Bool(a < b),
                (BinaryOp::Le, Const::Int(a), Const::Int(b)) => Const::Bool(a <= b),
                (BinaryOp::Gt, Const::Int(a), Const::Int(b)) => Const::Bool(a > b),
                (BinaryOp::Ge, Const::Int(a), Const::Int(b)) => Const::Bool(a >= b),
                (BinaryOp::And, Const::Bool(a), Const::Bool(b)) => Const::Bool(a && b),
                (BinaryOp::Or, Const::Bool(a), Const::Bool(b)) => Const::Bool(a || b),
                _ => return None,
            })
        }
        _ => None,
    }
}

fn truth(expr: &Expr, constants: &HashMap<SymbolId, Const>) -> Option<bool> {
    match eval(expr, constants)? {
        Const::Bool(value) => Some(value),
        _ => None,
    }
}

fn fold_block(block: &Block, constants: &HashMap<SymbolId, Const>, changed: &mut bool) -> Block {
    let mut stmts = Vec::with_capacity(block.stmts.len());
    for stmt in &block.stmts {
        match stmt {
            Stmt::If { cond, then_block, else_block, span, id } => match truth(cond, constants) {
                // Splice the taken branch into the enclosing block (symbols
                // are already resolved to unique ids, so no scope is lost)
                // and drop the other one.
                Some(true) => {
                    *changed = true;
                    stmts.extend(fold_block(then_block, constants, changed).stmts);
                }
                Some(false) => {
                    *changed = true;
                    if let Some(else_block) = else_block {
                        stmts.extend(fold_block(else_block, constants, changed).stmts);
                    }
                }
                None => stmts.push(Stmt::If {
                    id: *id,
                    cond: fold_expr(cond, constants, changed),
                    then_block: fold_block(then_block, constants, changed),
                    else_block: else_block.as_ref().map(|block| fold_block(block, constants, changed)),
                    span: *span,
                }),
            },
            other => stmts.push(fold_stmt(other, constants, changed)),
        }
    }
    Block { stmts, ..block.clone() }
}

fn fold_stmt(stmt: &Stmt, constants: &HashMap<SymbolId, Const>, changed: &mut bool) -> Stmt {
    let mut stmt = stmt.clone();
    match &mut stmt {
        Stmt::Let { init: Some(init), .. } => *init = fold_expr(init, constants, changed),
        Stmt::Assign { rhs, .. } => *rhs = fold_expr(rhs, constants, changed),
        Stmt::Expr { expr, .. } => *expr = fold_expr(expr, constants, changed),
        Stmt::Return { value: Some(value), .. } => *value = fold_expr(value, constants, changed),
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::ForEach { body, .. } => *body = fold_block(body, constants, changed),
        Stmt::For { body, .. } => *body = fold_block(body, constants, changed),
        Stmt::Try { try_block, catches, finally_block, .. } => {
            *try_block = fold_block(try_block, constants, changed);
            for catch in catches.iter_mut() {
                catch.body = fold_block(&catch.body, constants, changed);
            }
            if let Some(finally_block) = finally_block {
                *finally_block = fold_block(finally_block, constants, changed);
            }
        }
        Stmt::Switch { clauses, default, .. } => {
            for clause in clauses.iter_mut() {
                clause.body = fold_block(&clause.body, constants, changed);
            }
            if let Some(default) = default {
                *default = fold_block(default, constants, changed);
            }
        }
        _ => {}
    }
    stmt
}

/// `cond ? a : b` with a constant `cond` becomes the taken operand; other
/// expressions are left as they are (only their nested conditionals fold).
fn fold_expr(expr: &Expr, constants: &HashMap<SymbolId, Const>, changed: &mut bool) -> Expr {
    if let Expr::Conditional { cond, then_expr, else_expr, .. } = expr {
        if let Some(taken) = truth(cond, constants) {
            *changed = true;
            return fold_expr(if taken { then_expr } else { else_expr }, constants, changed);
        }
    }
    let mut expr = expr.clone();
    match &mut expr {
        Expr::Conditional { then_expr, else_expr, .. } => {
            **then_expr = fold_expr(then_expr, constants, changed);
            **else_expr = fold_expr(else_expr, constants, changed);
        }
        Expr::Binary { lhs, rhs, .. } => {
            **lhs = fold_expr(lhs, constants, changed);
            **rhs = fold_expr(rhs, constants, changed);
        }
        Expr::Call(call) => {
            for arg in call.args.iter_mut() {
                *arg = fold_expr(arg, constants, changed);
            }
        }
        Expr::Cast { expr: inner, .. } => **inner = fold_expr(inner, constants, changed),
        _ => {}
    }
    expr
}
