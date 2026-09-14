//! Database/storage boundary recovery.
//!
//! A database is not merely a deployment dependency: an untrusted value can
//! be persisted by one component and become dangerous only when another
//! component reads it later. This adapter emits resource facts and, when the
//! *same statically named table* is proven on both sides, a precise
//! call-site-to-call-site [`BoundaryFlowEdge`] for the taint bridge.
//!
//! Dynamic identifiers, joins, and ORM entities without a literal table
//! binding are deliberately not stitched to arbitrary storage resources.
//! Python ORM bindings are recovered only from SQLAlchemy's explicit
//! `__tablename__` or Django's explicit `Meta.db_table`, and Java/JPA only
//! from an explicit `@Table(name = "...")`; convention-derived names
//! intentionally remain unresolved.

use std::collections::HashMap;

use anyhow::Result;
use uniflow_ir::{Callee, Function, InstKind, Program, ValueId};
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, Confidence, EdgeKind, Evidence, FlowNodeRef, NodeKind,
    SystemGraph, SystemNode, ValueMappingKind,
};
use crate::ir_utils::{is_python_root_alias, resolve_string_sequence, resolve_value_root, StringPiece};

const WRITE_METHODS: &[&str] = &["insert", "update", "delete", "save", "persist", "upsert", "executeupdate"];
const READ_METHODS: &[&str] = &["select", "query", "find", "load", "read", "executequery"];

/// JDBC-style statement-preparation methods. A prepared statement's SQL is
/// given once, here, and its dynamic values arrive later through positional
/// `set*` binds on the *same object* — the classic pattern by which a write
/// is already safe from SQL injection at this call site, yet the value it
/// stores can still become dangerous when read back somewhere else in the
/// system later (see module docs).
const PREPARE_METHODS: &[&str] = &["preparestatement", "preparecall"];

/// JDBC positional parameter binders. Matched as an exact set (not a
/// `starts_with("set")` prefix) so an unrelated setter (`setName`,
/// `setEnabled`) on some other object never gets treated as a bind.
const SET_PARAM_METHODS: &[&str] = &[
    "setstring", "setint", "setlong", "setshort", "setbyte", "setfloat", "setdouble", "setboolean", "setobject",
    "setdate", "settime", "settimestamp", "setbigdecimal", "setbytes", "setarray", "setnstring",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction { Read, Write }

impl Direction {
    fn edge_kind(self) -> EdgeKind {
        match self { Self::Read => EdgeKind::ReadsResource, Self::Write => EdgeKind::WritesResource }
    }
    fn description(self) -> &'static str {
        match self { Self::Read => "read", Self::Write => "write" }
    }
}

/// An opaque per-program fact joined only after every language group has
/// been inspected. Its private fields prevent other adapters from inventing
/// unproven database correspondences.
#[derive(Clone, Debug)]
pub struct DatabaseOperation {
    table: String,
    direction: Direction,
    /// What value-shaped storage cell the statement proves. `None` means the
    /// call is still a useful resource fact, but is not safe to turn into a
    /// cross-component value flow (for example `DELETE`, `SELECT *`, joins,
    /// and complex projections).
    value_identity: Option<ValueIdentity>,
    language: uniflow_hir::Language,
    function: String,
    inst_id: u32,
    port: Port,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ValueIdentity {
    /// A table-oriented repository API explicitly moves an entire record.
    WholeRecord,
    /// A raw SQL statement names exactly one projected/written column.
    Column(String),
}

fn method_name(callee: &str) -> String { callee.rsplit('.').next().unwrap_or(callee).to_ascii_lowercase() }

fn looks_like_database_api(callee: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    ["db", "database", "sql", "jdbc", "dao", "repository", "entitymanager", "persistence", "orm"]
        .iter().any(|marker| lower.contains(marker))
}

fn literal_or_literal_skeleton(function: &Function, value: ValueId) -> Option<String> {
    let pieces = resolve_string_sequence(function, value);
    if pieces.is_empty() { return None; }
    let mut text = String::new();
    for piece in pieces {
        match piece {
            // A dynamic SQL value is fine: the full query argument is the
            // exact taint-carrying port. Identifier parsing below rejects it.
            StringPiece::Literal(part) => text.push_str(&part),
            StringPiece::Dynamic(_) => text.push_str(" ? "),
        }
    }
    Some(text)
}

fn normalize_table(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_matches(|c| matches!(c, '`' | '"' | '[' | ']'));
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$')) {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

fn normalize_column(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_matches(|c| matches!(c, '`' | '"' | '[' | ']'));
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')) {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

fn insert_column(raw_table: &str) -> Option<String> {
    let (_, columns) = raw_table.split_once('(')?;
    let columns = columns.split_once(')')?.0;
    if columns.contains(',') {
        return None;
    }
    normalize_column(columns)
}

/// Recovers only a simple statement target. A permissive partial SQL parser
/// would be worse than no stitch: it could create a false cross-service path.
fn sql_table(text: &str) -> Option<(Direction, String, Option<ValueIdentity>)> {
    let normalized = text.trim().to_ascii_lowercase();
    // Cross-table operators and multiple statements do not establish a
    // stable storage cell. Keep them out of the value bridge entirely.
    if [" join ", " union ", " intersect ", " except ", ";"].iter().any(|marker| normalized.contains(marker)) {
        return None;
    }
    let words = text.split_whitespace().collect::<Vec<_>>();
    let first = words.first()?.to_ascii_lowercase();
    let (direction, raw_table, value_identity) = match first.as_str() {
        "insert" if words.get(1)?.eq_ignore_ascii_case("into") => {
            let table = *words.get(2)?;
            (Direction::Write, table, insert_column(table).map(ValueIdentity::Column))
        }
        "update" => (Direction::Write, *words.get(1)?, None),
        "delete" if words.get(1)?.eq_ignore_ascii_case("from") => (Direction::Write, *words.get(2)?, None),
        "select" => {
            let from = words.iter().position(|word| word.eq_ignore_ascii_case("from"))?;
            // Only `SELECT single_column FROM table` is a value identity.
            // `*`, expressions, aliases, and multi-column projections need a
            // row/field model and must not be guessed as one taint value.
            let projection = words.get(1..from)?;
            let column = (projection.len() == 1)
                .then(|| normalize_column(projection[0]))
                .flatten()
                .map(ValueIdentity::Column);
            (Direction::Read, *words.get(from + 1)?, column)
        }
        _ => return None,
    };
    // `INSERT INTO profiles(value) ...` carries the column list in the
    // same token, while `UPDATE profiles SET ...` does not.
    let table = raw_table
        .split_once('(')
        .map(|(table, _)| table)
        .unwrap_or(raw_table)
        .trim_end_matches(|c: char| matches!(c, ',' | ';'));
    normalize_table(table).map(|table| (direction, table, value_identity))
}

fn literal_table_argument(function: &Function, value: ValueId) -> Option<String> {
    match resolve_string_sequence(function, value).as_slice() {
        [StringPiece::Literal(table)] => normalize_table(table),
        _ => None,
    }
}

/// Explicit ORM model -> table declarations emitted by language frontends.
/// A binding is deliberately absent for convention-derived names: a storage
/// bridge is only sound when source metadata itself fixes the table.
fn explicit_orm_table_bindings(program: &Program) -> HashMap<String, String> {
    let mut bindings: HashMap<String, String> = program
        .functions
        .iter()
        .filter_map(|function| {
            let owner = function.attrs.get("owner_type")?;
            let table = function
                .attrs
                .get("python.orm.table")
                .or_else(|| function.attrs.get("java.orm.table"))?;
            normalize_table(table).map(|table| (owner.clone(), table))
        })
        .collect();

    // An entity commonly consists solely of fields (or Lombok-generated
    // methods), leaving no Java method for the frontend to carry class
    // metadata through. Recover the same explicit `@Table(name = "...")`
    // fact directly from an on-disk source file in that case. Archive entries
    // and absent files are simply skipped; they are not fabricated.
    if program.language == uniflow_hir::Language::Java {
        for source_file in &program.source_files {
            let Ok(source) = std::fs::read_to_string(&source_file.path) else { continue };
            for (model, table) in explicit_jpa_tables_in_source(&source) {
                bindings.entry(model).or_insert(table);
            }
        }
    }
    bindings
}

fn explicit_jpa_tables_in_source(source: &str) -> Vec<(String, String)> {
    // JPA's @Table accepts other attributes before/after `name`; capture the
    // whole annotation argument list without attempting to interpret dynamic
    // Java expressions. The class must immediately follow its annotation
    // group, preventing a member annotation from becoming a model binding.
    let re = regex::Regex::new(
        r#"(?sx)
            @ (?: [A-Za-z_][A-Za-z0-9_.]* \. )? Table
            \s* \( (?P<args> [^)]* ) \)
            (?: \s* @ [A-Za-z_][A-Za-z0-9_.]* (?: \s* \( [^)]* \) )? )*
            \s* (?: public | protected | private | abstract | final | static | \s )*
            (?: class | record ) \s+ (?P<model>[A-Za-z_][A-Za-z0-9_]*)
        "#,
    )
    .expect("valid JPA entity declaration regex");
    let name_re = regex::Regex::new(r#"(?i)\bname\s*=\s*"([A-Za-z0-9_.$]+)""#)
        .expect("valid JPA table name regex");
    re.captures_iter(source)
        .filter_map(|caps| {
            let table = name_re.captures(caps.name("args")?.as_str())?.get(1)?.as_str();
            let model = caps.name("model")?.as_str();
            Some((model.to_string(), table.to_ascii_lowercase()))
        })
        .collect()
}

fn unique_explicit_orm_table(bindings: &HashMap<String, String>, model: &str) -> Option<String> {
    let mut tables = bindings
        .iter()
        .filter(|(bound_model, _)| {
            bound_model.as_str() == model
                || bound_model.rsplit('.').next() == model.rsplit('.').next()
        })
        .map(|(_, table)| table.clone())
        .collect::<Vec<_>>();
    tables.sort();
    tables.dedup();
    (tables.len() == 1).then(|| tables.pop().expect("one table after length check"))
}

fn bound_orm_model_table(function: &Function, value: ValueId, bindings: &HashMap<String, String>) -> Option<String> {
    let ty = function.value_types.get(&value)?;
    unique_explicit_orm_table(bindings, ty)
}

/// Extracts value-level ORM operations only where the model's source has an
/// explicit table declaration. `arg_names` preserves Python keyword names,
/// allowing `Model.objects.create(secret=input)` to be tied to the `secret`
/// column rather than an arbitrary whole-record value.
fn orm_call_operations(
    function: &Function,
    call: &uniflow_ir::CallInst,
    bindings: &HashMap<String, String>,
) -> Vec<(Direction, String, Option<ValueIdentity>, Port)> {
    let Callee::Static(callee) = &call.callee else { return Vec::new() };
    let method = method_name(callee);
    if let Some((model, _)) = callee.split_once(".objects.") {
        let Some(table) = unique_explicit_orm_table(bindings, model) else { return Vec::new() };
        return match method.as_str() {
            "create" | "update" => {
                let writes = call
                    .arg_names
                    .iter()
                    .enumerate()
                    .filter_map(|(index, name)| {
                        normalize_column(name.as_deref()?).map(|column| {
                            (Direction::Write, table.clone(), Some(ValueIdentity::Column(column)), Port::Arg(index))
                        })
                    })
                    .collect::<Vec<_>>();
                if writes.is_empty() {
                    vec![(Direction::Write, table, None, Port::Return)]
                } else {
                    writes
                }
            }
            "get" | "first" | "last" => vec![(Direction::Read, table, Some(ValueIdentity::WholeRecord), Port::Return)],
            "values" | "values_list" if call.args.len() == 1 => literal_table_argument(function, call.args[0])
                .and_then(|column| normalize_column(&column))
                .map(|column| vec![(Direction::Read, table, Some(ValueIdentity::Column(column)), Port::Return)])
                .unwrap_or_default(),
            "delete" => vec![(Direction::Write, table, None, Port::Return)],
            _ => Vec::new(),
        };
    }

    // SQLAlchemy's `session.add(model)` and an instance's `model.save()`
    // carry a whole model object. The static inferred model type and its
    // explicit table declaration make this precise without relying on a
    // session variable's spelling or framework import path.
    if matches!(method.as_str(), "add" | "persist" | "merge" | "save") {
        if let Some(&model) = call.args.first() {
            if let Some(table) = bound_orm_model_table(function, model, bindings) {
                return vec![(Direction::Write, table, Some(ValueIdentity::WholeRecord), Port::Arg(0))];
            }
        }
    }
    if method == "save" {
        if let Some(receiver) = call.receiver {
            if let Some(table) = bound_orm_model_table(function, receiver, bindings) {
                return vec![(Direction::Write, table, Some(ValueIdentity::WholeRecord), Port::Receiver)];
            }
        }
    }
    Vec::new()
}

/// The value's entire text, only when it resolves to one pure literal (no
/// concatenation) — unlike [`literal_or_literal_skeleton`], a genuine `?`
/// placeholder character in the source text must survive untouched, so a
/// dynamically-built value (which would otherwise be papered over with a
/// synthetic ` ? ` marker) must be rejected outright instead.
fn pure_literal_text(function: &Function, value: ValueId) -> Option<String> {
    match resolve_string_sequence(function, value).as_slice() {
        [StringPiece::Literal(text)] => Some(text.clone()),
        _ => None,
    }
}

/// One resolved `PreparedStatement`-shaped INSERT: the object identity the
/// later positional binds must match, the table, and a 1-based JDBC
/// parameter position -> column name map. Only `INSERT INTO t(cols) VALUES
/// (...)` with an *equal count* of columns and value-slots is accepted — a
/// mismatched count (a computed value list, a trailing default-value
/// expression, ...) is not something this can safely guess through, so it
/// is rejected rather than misattributed.
struct PreparedInsert {
    stmt_value: ValueId,
    table: String,
    /// 1-based JDBC parameter index -> column name, for slots that are
    /// exactly a `?` placeholder (a literal value in the same tuple
    /// position consumes no parameter index and is simply skipped).
    placeholders: HashMap<u32, String>,
}

fn split_top_level(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in text.chars() {
        match ch {
            '(' => { depth += 1; current.push(ch); }
            ')' => { depth -= 1; current.push(ch); }
            ',' if depth == 0 => { parts.push(std::mem::take(&mut current)); }
            _ => current.push(ch),
        }
    }
    parts.push(current);
    parts
}

fn parse_insert_placeholders(sql: &str) -> Option<(String, HashMap<u32, String>)> {
    let lower = sql.to_ascii_lowercase();
    if !lower.trim_start().starts_with("insert") {
        return None;
    }
    let into_at = lower.find("into")?;
    let after_into = &sql[into_at + "into".len()..];
    let open_cols = after_into.find('(')?;
    let close_cols = open_cols + after_into[open_cols..].find(')')?;
    let table = normalize_table(after_into[..open_cols].trim())?;
    let columns: Vec<String> = split_top_level(&after_into[open_cols + 1..close_cols])
        .iter()
        .map(|token| normalize_column(token))
        .collect::<Option<Vec<_>>>()?;

    let after_cols = &after_into[close_cols + 1..];
    let values_at = after_cols.to_ascii_lowercase().find("values")?;
    let after_values = &after_cols[values_at + "values".len()..];
    let open_vals = after_values.find('(')?;
    let close_vals = open_vals + after_values[open_vals..].find(')')?;
    let value_tokens = split_top_level(&after_values[open_vals + 1..close_vals]);

    if value_tokens.len() != columns.len() {
        return None;
    }
    let mut placeholders = HashMap::new();
    let mut position: u32 = 0;
    for (token, column) in value_tokens.iter().zip(columns.iter()) {
        if token.trim() == "?" {
            position += 1;
            placeholders.insert(position, column.clone());
        }
    }
    if placeholders.is_empty() {
        return None;
    }
    Some((table, placeholders))
}

fn discover_prepared_inserts(function: &Function) -> Vec<PreparedInsert> {
    let mut out = Vec::new();
    for block in &function.blocks {
        for inst in &block.insts {
            let InstKind::Call(call) = &inst.kind else { continue };
            let Callee::Static(name) = &call.callee else { continue };
            if !PREPARE_METHODS.contains(&method_name(name).as_str()) {
                continue;
            }
            let Some(&sql_arg) = call.args.first() else { continue };
            let Some(sql_text) = pure_literal_text(function, sql_arg) else { continue };
            let Some((table, placeholders)) = parse_insert_placeholders(&sql_text) else { continue };
            let Some(stmt_value) = call.dst else { continue };
            out.push(PreparedInsert { stmt_value, table, placeholders });
        }
    }
    out
}

fn const_int(function: &Function, value: ValueId) -> Option<i64> {
    function.blocks.iter().flat_map(|block| &block.insts).find_map(|inst| match &inst.kind {
        InstKind::ConstInt { dst, value: literal } if *dst == value => Some(*literal),
        _ => None,
    })
}

/// Resolves every positional bind (`stmt.setString(1, value)`) whose
/// receiver proves the *same object* as one of `prepared`'s statements, into
/// an ordinary write [`DatabaseOperation`] on the bound value's own port —
/// this is what lets a parameterized (injection-safe) write still register
/// as "this table/column was written with this value" for the storage
/// round-trip bridge.
fn discover_prepared_binds(function: &Function, prepared: &[PreparedInsert]) -> Vec<(String, String, u32, Port)> {
    let mut out = Vec::new();
    for block in &function.blocks {
        for inst in &block.insts {
            let InstKind::Call(call) = &inst.kind else { continue };
            let Callee::Static(name) = &call.callee else { continue };
            if !SET_PARAM_METHODS.contains(&method_name(name).as_str()) {
                continue;
            }
            let Some(receiver) = call.receiver else { continue };
            let receiver_root = resolve_value_root(function, receiver);
            let Some(prepared_stmt) = prepared.iter().find(|p| resolve_value_root(function, p.stmt_value) == receiver_root) else {
                continue;
            };
            let Some(&index_arg) = call.args.first() else { continue };
            let Some(position) = const_int(function, resolve_value_root(function, index_arg)).and_then(|n| u32::try_from(n).ok())
            else {
                continue;
            };
            let Some(column) = prepared_stmt.placeholders.get(&position) else { continue };
            if call.args.len() < 2 {
                continue;
            }
            out.push((prepared_stmt.table.clone(), column.clone(), inst.id.0, Port::Arg(1)));
        }
    }
    out
}

fn call_operation(function: &Function, kind: &InstKind) -> Option<(Direction, String, Option<ValueIdentity>, Port)> {
    let InstKind::Call(call) = kind else { return None };
    let Callee::Static(callee) = &call.callee else { return None };
    if PREPARE_METHODS.contains(&method_name(callee).as_str()) {
        // A prepare call's own literal SQL argument names the table but
        // never carries the actual value — that arrives later through a
        // positional bind on the same statement object, handled separately
        // by `discover_prepared_inserts`/`discover_prepared_binds`. Treating
        // it here too would (for a single-column INSERT) wrongly attribute
        // the write's value to the constant SQL-text argument itself.
        return None;
    }

    // Raw SQL provides operation and table proof even for `execute`.
    for (index, value) in call.args.iter().copied().enumerate() {
        if let Some((direction, table, value_identity)) = literal_or_literal_skeleton(function, value).and_then(|text| sql_table(&text)) {
            let port = match direction {
                Direction::Write => Port::Arg(index),
                // A SELECT's string argument describes the query, while
                // the value that can reach subsequent code is its result.
                Direction::Read => Port::Return,
            };
            return Some((direction, table, value_identity, port));
        }
    }
    if !looks_like_database_api(callee) { return None; }
    let direction = if WRITE_METHODS.contains(&method_name(callee).as_str()) {
        Direction::Write
    } else if READ_METHODS.contains(&method_name(callee).as_str()) {
        Direction::Read
    } else { return None };
    let table = literal_table_argument(function, *call.args.first()?)?;
    let port = match direction {
        Direction::Read => Port::Return,
        // `insert("profiles", value)`: do not taint the table identifier.
        Direction::Write => Port::Arg(if call.args.len() > 1 { 1 } else { 0 }),
    };
    Some((direction, table, Some(ValueIdentity::WholeRecord), port))
}

fn call_node_id(operation: &DatabaseOperation) -> String {
    format!("code:{}:{}#{}", operation.language.as_str(), operation.function, operation.inst_id)
}
fn table_node_id(table: &str) -> String { format!("database:table:{table}") }

/// Shared by both the generic call-shaped detector and the JDBC
/// `PreparedStatement` bind detector: records one resource fact and, for a
/// write/read pair sharing a table and value identity, leaves the operation
/// available for [`connect_operations_into`] to bridge afterward.
#[allow(clippy::too_many_arguments)]
fn record_operation(
    graph: &mut SystemGraph,
    operations: &mut Vec<DatabaseOperation>,
    language: &uniflow_hir::Language,
    function_name: &str,
    inst_id: u32,
    direction: Direction,
    table: String,
    value_identity: Option<ValueIdentity>,
    port: Port,
) -> Result<()> {
    let operation =
        DatabaseOperation { table: table.clone(), direction, value_identity, language: language.clone(), function: function_name.to_string(), inst_id, port };
    let call_id = call_node_id(&operation);
    let table_id = table_node_id(&table);
    graph.upsert_node(SystemNode::new(NodeKind::CallSite, call_id.clone(), function_name.to_string()));
    graph.upsert_node(SystemNode::new(NodeKind::DatabaseTable, table_id.clone(), table.clone()).with_attr("table", table.clone()));
    let (producer, consumer) = match direction { Direction::Write => (call_id, table_id), Direction::Read => (table_id, call_id) };
    graph.apply_boundary(
        BoundarySummary::new(direction.edge_kind(), producer, consumer, Confidence::Exact).with_evidence(Evidence::new(format!(
            "{function_name} performs a statically identified database {} of table {table:?}", direction.description()
        ))),
    )?;
    operations.push(operation);
    Ok(())
}

/// Records statically named database resource operations for one language
/// program. Call [`connect_operations_into`] after gathering all programs.
pub fn discover_into(graph: &mut SystemGraph, program: &Program) -> Result<Vec<DatabaseOperation>> {
    let mut operations = Vec::new();
    let orm_bindings = explicit_orm_table_bindings(program);
    for function in &program.functions {
        if is_python_root_alias(program, function) {
            continue;
        }
        for block in &function.blocks {
            for inst in &block.insts {
                if let Some((direction, table, value_identity, port)) = call_operation(function, &inst.kind) {
                    record_operation(graph, &mut operations, &program.language, &function.name, inst.id.0, direction, table, value_identity, port)?;
                    continue;
                }
                let InstKind::Call(call) = &inst.kind else { continue };
                for (direction, table, value_identity, port) in orm_call_operations(function, call, &orm_bindings) {
                    record_operation(graph, &mut operations, &program.language, &function.name, inst.id.0, direction, table, value_identity, port)?;
                }
            }
        }

        let prepared = discover_prepared_inserts(function);
        if !prepared.is_empty() {
            for (table, column, inst_id, port) in discover_prepared_binds(function, &prepared) {
                record_operation(
                    graph, &mut operations, &program.language, &function.name, inst_id, Direction::Write, table, Some(ValueIdentity::Column(column)), port,
                )?;
            }
        }
    }
    Ok(operations)
}

/// Adds storage-flow bridges after every language group was analyzed. Only
/// equal normalized table names *and the same explicit value identity* become
/// a data-flow edge; resource use alone is never evidence that all tables,
/// rows, or columns alias each other.
pub fn connect_operations_into(graph: &mut SystemGraph, operations: &[DatabaseOperation]) -> Result<()> {
    for write in operations.iter().filter(|operation| operation.direction == Direction::Write) {
        for read in operations.iter().filter(|operation| {
            operation.direction == Direction::Read
                && operation.table == write.table
                && operation.value_identity.is_some()
                && operation.value_identity == write.value_identity
        }) {
            let identity = match write.value_identity.as_ref().expect("filtered above") {
                ValueIdentity::WholeRecord => "an explicit whole-record operation".to_string(),
                ValueIdentity::Column(column) => format!("the same explicit column {column:?}"),
            };
            let mapping = BoundaryFlowEdge::new(
                ValueMappingKind::ValueToValue,
                FlowNodeRef::call_site_port(write.language.clone(), write.function.clone(), write.inst_id, write.port.clone()),
                FlowNodeRef::call_site_port(read.language.clone(), read.function.clone(), read.inst_id, read.port.clone()),
                Confidence::Exact,
            ).with_evidence(Evidence::new(format!("both database calls name table {:?} and {identity}", write.table)));
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::DataFlow, call_node_id(write), call_node_id(read), Confidence::Exact)
                    .with_evidence(Evidence::new(format!("stored value may flow from {} to {} through table {:?} using {identity}", write.function, read.function, write.table)))
                    .with_value_mapping(mapping),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    fn program(source: &str) -> Program {
        let hir = uniflow_lang_java::JavaParser::default().parse_file("A.java", source).unwrap();
        uniflow_lowering::lower_program(&hir)
    }

    fn python_program(source: &str) -> Program {
        let hir = uniflow_lang_python::PythonParser::default().parse_file("models.py", source).unwrap();
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn joins_only_calls_that_prove_the_same_sql_table() {
        let source = r#"class A {
            static void store(String value) { Db.execute("INSERT INTO profiles(value) VALUES ('" + value + "')"); }
            static String load() { return Db.query("SELECT value FROM profiles"); }
            static String other() { return Db.query("SELECT value FROM audit_log"); }
        }"#;
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &program(source)).unwrap();
        connect_operations_into(&mut graph, &operations).unwrap();
        assert_eq!(graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::WritesResource).count(), 1);
        assert_eq!(graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::ReadsResource).count(), 2);
        let mappings = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::DataFlow).flat_map(|(_, _, edge)| edge.value_mappings.iter()).collect::<Vec<_>>();
        assert_eq!(mappings.len(), 1, "unrelated tables must not be stitched together");
        assert_eq!(mappings[0].from.function, "A.store");
        assert_eq!(mappings[0].to.function, "A.load");
        assert!(mappings[0].from.call_site.is_some());
        assert!(mappings[0].to.call_site.is_some());
    }

    #[test]
    fn recognizes_literal_table_argument_apis() {
        let source = r#"class A {
            static void store(String value) { Db.save("profiles", value); }
            static String load() { return Db.find("profiles"); }
        }"#;
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &program(source)).unwrap();
        connect_operations_into(&mut graph, &operations).unwrap();
        assert!(graph.node("database:table:profiles").is_some());
        let mapping = graph.edges().flat_map(|(_, _, edge)| edge.value_mappings.iter()).next().unwrap();
        assert_eq!(mapping.from.port, Port::Arg(1));
        assert_eq!(mapping.to.port, Port::Return);
    }

    #[test]
    fn does_not_turn_wildcard_or_different_column_sql_into_value_flow() {
        let source = r#"class A {
            static void store(String value) { Db.execute("INSERT INTO profiles(value) VALUES ('" + value + "')"); }
            static String wildcard() { return Db.query("SELECT * FROM profiles"); }
            static String otherColumn() { return Db.query("SELECT email FROM profiles"); }
        }"#;
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &program(source)).unwrap();
        connect_operations_into(&mut graph, &operations).unwrap();
        assert_eq!(graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::ReadsResource).count(), 2);
        assert_eq!(graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::DataFlow).count(), 0);
    }

    #[test]
    fn python_sql_call_retains_a_discoverable_database_operation() {
        let hir = uniflow_lang_python::PythonParser::default()
            .parse_file("reader.py", "def load():\n    return Db.query(\"SELECT value FROM profiles\")\n")
            .unwrap();
        let ir = uniflow_lowering::lower_program(&hir);
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &ir).unwrap();
        assert_eq!(operations.len(), 1, "{ir:#?}");
    }

    #[test]
    fn django_orm_keyword_write_stitches_to_the_same_explicit_model_column_read() {
        let source = r#"
class Order:
    __tablename__ = "purchase_orders"
    def marker(self):
        return 1

def store(value):
    Order.objects.create(secret=value)

def load():
    return Order.objects.values("secret")
"#;
        let mut graph = SystemGraph::new();
        let ir = python_program(source);
        let operations = discover_into(&mut graph, &ir).expect("discover explicit ORM calls");
        connect_operations_into(&mut graph, &operations).expect("stitch same table column");

        assert!(operations.iter().any(|operation| {
            operation.direction == Direction::Write
                && operation.table == "purchase_orders"
                && operation.value_identity == Some(ValueIdentity::Column("secret".to_string()))
                && operation.port == Port::Arg(0)
        }), "{operations:?}");
        assert!(operations.iter().any(|operation| {
            operation.direction == Direction::Read
                && operation.table == "purchase_orders"
                && operation.value_identity == Some(ValueIdentity::Column("secret".to_string()))
        }), "{operations:?}");
        assert_eq!(graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::DataFlow).count(), 1);
    }

    #[test]
    fn convention_named_python_model_is_not_guessed_as_a_database_table() {
        let source = r#"
class Order:
    def marker(self):
        return 1

def store(value):
    Order.objects.create(secret=value)

def load():
    return Order.objects.values("secret")
"#;
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &python_program(source)).expect("inspect ORM calls");
        assert!(operations.is_empty(), "a class-name convention must not manufacture a table binding: {operations:?}");
        assert!(graph.nodes().all(|node| node.kind != NodeKind::DatabaseTable));
    }

    #[test]
    fn jpa_persist_of_an_explicitly_mapped_entity_stitches_to_a_whole_record_read() {
        let source = r#"
            @jakarta.persistence.Table(name = "purchase_orders")
            class Order {
                String marker() { return "ok"; }
                static void store(Order order) { EntityManager.persist(order); }
                static Object load() { return Db.find("purchase_orders"); }
            }
        "#;
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &program(source)).expect("discover JPA operation");
        connect_operations_into(&mut graph, &operations).expect("stitch record storage flow");
        assert!(operations.iter().any(|operation| {
            operation.direction == Direction::Write
                && operation.table == "purchase_orders"
                && operation.value_identity == Some(ValueIdentity::WholeRecord)
                && operation.function.ends_with(".store")
        }), "{operations:?}");
        assert_eq!(graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::DataFlow).count(), 1);
    }

    #[test]
    fn source_level_jpa_metadata_recovers_a_field_only_entity_without_guessing_defaults() {
        let bindings = explicit_jpa_tables_in_source(
            r#"
                @jakarta.persistence.Entity
                @jakarta.persistence.Table(schema = "app", name = "purchase_orders")
                public class Order { private String secret; }

                @jakarta.persistence.Entity
                public class ConventionOnly { private String secret; }
            "#,
        );
        assert_eq!(bindings, vec![("Order".to_string(), "purchase_orders".to_string())]);
    }

    #[test]
    fn a_jdbc_prepared_statement_bind_stitches_to_a_later_read() {
        // The write side is already injection-safe (a parameterized `?`,
        // never a concatenated literal) — a single-file scan would call it
        // harmless. It still becomes dangerous the moment `load()` hands the
        // stored value to an unsafe sink elsewhere in the program's lifetime.
        let source = r#"class A {
            static void store(Connection conn, String value) {
                PreparedStatement stmt = conn.prepareStatement("INSERT INTO profiles(value) VALUES (?)");
                stmt.setString(1, value);
                stmt.executeUpdate();
            }
            static String load() { return Db.query("SELECT value FROM profiles"); }
        }"#;
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &program(source)).unwrap();
        connect_operations_into(&mut graph, &operations).unwrap();

        let writes: Vec<_> = operations.iter().filter(|op| op.direction == Direction::Write).collect();
        assert_eq!(writes.len(), 1, "{writes:?}");
        assert_eq!(writes[0].value_identity, Some(ValueIdentity::Column("value".to_string())));
        assert_eq!(writes[0].port, Port::Arg(1), "must point at setString's value argument, not the SQL text");

        let mappings = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::DataFlow).flat_map(|(_, _, edge)| edge.value_mappings.iter()).collect::<Vec<_>>();
        assert_eq!(mappings.len(), 1, "{mappings:?}");
        assert_eq!(mappings[0].from.function, "A.store");
        assert_eq!(mappings[0].from.port, Port::Arg(1));
        assert_eq!(mappings[0].to.function, "A.load");
        assert_eq!(mappings[0].to.port, Port::Return);
    }

    #[test]
    fn binds_on_two_prepared_statement_objects_are_not_confused() {
        let source = r#"class A {
            static void store(String value, String other) {
                PreparedStatement stmt1 = Db.prepareStatement("INSERT INTO profiles(value) VALUES (?)");
                PreparedStatement stmt2 = Db.prepareStatement("INSERT INTO audit_log(value) VALUES (?)");
                stmt2.setString(1, other);
                stmt1.setString(1, value);
            }
            static String loadProfile() { return Db.query("SELECT value FROM profiles"); }
            static String loadAudit() { return Db.query("SELECT value FROM audit_log"); }
        }"#;
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &program(source)).unwrap();
        connect_operations_into(&mut graph, &operations).unwrap();

        assert_eq!(operations.iter().filter(|op| op.direction == Direction::Write).count(), 2, "{operations:?}");
        let flows: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::DataFlow).collect();
        assert_eq!(flows.len(), 2, "{flows:?}");
        let evidence_texts: Vec<String> = flows.iter().flat_map(|(_, _, edge)| edge.evidence.iter().map(|e| e.description.clone())).collect();
        assert!(evidence_texts.iter().any(|text| text.contains("\"profiles\"")), "{evidence_texts:?}");
        assert!(evidence_texts.iter().any(|text| text.contains("\"audit_log\"")), "{evidence_texts:?}");
        assert!(!evidence_texts.iter().any(|text| text.contains("profiles") && text.contains("audit_log")), "must not cross-wire the two statement objects: {evidence_texts:?}");
    }

    #[test]
    fn a_bind_whose_position_has_no_matching_placeholder_is_ignored() {
        // Only 1 placeholder exists; a bind at position 2 cannot be
        // attributed to any column and must not be guessed.
        let source = r#"class A {
            static void store(String value, String extra) {
                PreparedStatement stmt = Db.prepareStatement("INSERT INTO profiles(value) VALUES (?)");
                stmt.setString(1, value);
                stmt.setString(2, extra);
                stmt.executeUpdate();
            }
        }"#;
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &program(source)).unwrap();
        assert_eq!(operations.iter().filter(|op| op.direction == Direction::Write).count(), 1, "{operations:?}");
    }

    #[test]
    fn a_column_count_values_count_mismatch_is_rejected_rather_than_guessed() {
        let source = r#"class A {
            static void store(String value) {
                PreparedStatement stmt = Db.prepareStatement("INSERT INTO profiles(value, created_at) VALUES (?)");
                stmt.setString(1, value);
                stmt.executeUpdate();
            }
        }"#;
        let mut graph = SystemGraph::new();
        let operations = discover_into(&mut graph, &program(source)).unwrap();
        assert!(operations.iter().all(|op| op.direction != Direction::Write), "{operations:?}");
    }
}
