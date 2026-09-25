//! The precise layer: runs uniflow's own language frontends (the same
//! parsers the SAST engine uses) over first-party code and pulls out
//! resolved call targets — `yaml.load` for `from yaml import load as y;
//! y(...)`, `org.apache.commons.text.StringSubstitutor.replace` for a
//! statically imported member — plus a function-level call graph used to
//! show *how* a vulnerable call is reached from an entry point.
//!
//! This is additive to `crate::source`'s lexical layer, never a
//! replacement: frontends differ in coverage (e.g. Java constructor-chained
//! calls such as `new X().m()` aren't emitted as named calls, Go import
//! lists aren't populated), and a parse failure must degrade to lexical
//! results rather than lose the language entirely.
use crate::source::SourceFile;
use rayon::prelude::*;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use uniflow_hir::{Item, Language, Program};

#[derive(Debug, Clone)]
pub struct HirCall {
    /// Index into the analyzed `SourceFile` slice.
    pub file: usize,
    pub line: u32,
    pub target: String,
    /// Enclosing function node in [`CallGraph::nodes`], if any.
    pub function: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct FnNode {
    pub name: String,
}

#[derive(Debug, Default)]
pub struct CallGraph {
    pub nodes: Vec<FnNode>,
    callers: Vec<Vec<usize>>,
}

impl CallGraph {
    /// Shortest entry point → … → `node` chain, where an entry point is a
    /// function nothing in the analyzed code calls (a `main`, a route
    /// handler registered by a framework, an exported API). BFS backwards
    /// over caller edges; deterministic because callers are sorted.
    pub fn path_to(&self, node: usize) -> Vec<String> {
        let mut previous: HashMap<usize, usize> = HashMap::new();
        let mut queue = VecDeque::from([node]);
        let mut root = node;
        let mut visited = 0;
        while let Some(current) = queue.pop_front() {
            visited += 1;
            if self.callers[current].is_empty() || visited > 5_000 {
                root = current;
                break;
            }
            for &caller in &self.callers[current] {
                if caller != node && !previous.contains_key(&caller) {
                    previous.insert(caller, current);
                    queue.push_back(caller);
                }
            }
            root = current;
        }
        let mut chain = vec![self.nodes[root].name.clone()];
        let mut cursor = root;
        while let Some(&next) = previous.get(&cursor) {
            chain.push(self.nodes[next].name.clone());
            cursor = next;
        }
        chain.dedup();
        chain
    }
}

#[derive(Debug, Default)]
pub struct HirFacts {
    pub calls: Vec<HirCall>,
    pub graph: CallGraph,
    /// Set when the frontend failed and nothing could be extracted.
    pub error: Option<String>,
}

fn language(lang: crate::source::Lang) -> Option<Language> {
    use crate::source::Lang;
    Some(match lang {
        Lang::Python => Language::Python,
        Lang::JavaScript => Language::JavaScript,
        Lang::Java => Language::Java,
        Lang::Go => Language::Go,
        Lang::Rust => Language::Rust,
        Lang::Ruby => return None,
    })
}

/// Files a given frontend accepts — lexical-only extensions (Kotlin,
/// Scala, Vue, ...) are filtered out here.
fn frontend_accepts(lang: &Language, rel: &str) -> bool {
    let ext = rel.rsplit('.').next().unwrap_or_default().to_ascii_lowercase();
    match lang {
        Language::Java => ext == "java",
        Language::JavaScript => matches!(ext.as_str(), "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx"),
        Language::Python => ext == "py",
        Language::Go => ext == "go",
        Language::Rust => ext == "rs",
        _ => false,
    }
}

fn parse_guarded(f: impl FnOnce() -> anyhow::Result<Program>) -> Result<Program, String> {
    // Frontends are large and occasionally panic on exotic input; one bad
    // file must never take reachability (or the whole scan) down with it.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(program)) => Ok(program),
        Ok(Err(error)) => Err(format!("{error:#}")),
        Err(_) => Err("frontend panicked".to_string()),
    }
}

pub fn analyze(lang: crate::source::Lang, files: &[SourceFile], indices: &[usize]) -> HirFacts {
    let Some(language) = language(lang) else { return HirFacts::default() };
    let accepted: Vec<usize> = indices.iter().copied().filter(|&i| frontend_accepts(&language, &files[i].rel)).collect();
    if accepted.is_empty() {
        return HirFacts::default();
    }
    let entries: Vec<(String, String)> = accepted.iter().map(|&i| (files[i].rel.clone(), files[i].lines.join("\n"))).collect();

    // Whole-project parse first (cross-file name resolution for Java/
    // Python/JS); if the project parse fails, fall back to per-file parses
    // so one unparseable file costs only itself.
    let programs: Vec<Program> = match parse_guarded(|| uniflow_frontend::parse_project_sources(language.clone(), &entries)) {
        Ok(program) => vec![program],
        Err(project_error) => {
            let per_file: Vec<Program> = entries
                .par_iter()
                .filter_map(|(path, source)| parse_guarded(|| uniflow_frontend::parse_source(language.clone(), path, source)).ok())
                .collect();
            if per_file.is_empty() {
                return HirFacts { error: Some(project_error), ..Default::default() };
            }
            per_file
        }
    };

    let mut facts = HirFacts::default();
    for program in &programs {
        extract(program, files, &accepted, &mut facts);
    }
    link_graph(&mut facts);
    facts
}

/// Maps a HIR file path (which the frontend may have re-rooted to the
/// common source prefix) back to our `SourceFile` index.
fn file_index(program: &Program, files: &[SourceFile], accepted: &[usize]) -> HashMap<u32, usize> {
    let mut map = HashMap::new();
    for source in &program.files {
        let hir_path = source.path.replace('\\', "/");
        let hit = accepted
            .iter()
            .copied()
            .filter(|&i| files[i].rel == hir_path || files[i].rel.ends_with(&format!("/{hir_path}")) || hir_path.ends_with(&files[i].rel))
            .min_by_key(|&i| files[i].rel.len());
        if let Some(index) = hit {
            map.insert(source.id.0 as u32, index);
        }
    }
    map
}

fn extract(program: &Program, files: &[SourceFile], accepted: &[usize], facts: &mut HirFacts) {
    let by_file = file_index(program, files, accepted);
    let symbol_name = |id: u64| program.symbols.iter().find(|s| s.id.0 as u64 == id).map(|s| s.name.clone());
    let visit = |value: Value, function: Option<usize>, facts: &mut HirFacts| {
        let mut stack = vec![&value];
        while let Some(node) = stack.pop() {
            match node {
                Value::Object(map) => {
                    if let (Some(target), Some(span)) = (map.get("target"), map.get("span")) {
                        if map.contains_key("args") {
                            let name = match target {
                                Value::Object(t) if t.contains_key("Named") => t["Named"].as_str().map(str::to_string),
                                Value::Object(t) if t.contains_key("Resolved") => t["Resolved"].as_u64().and_then(symbol_name),
                                _ => None,
                            };
                            let file = span.get("file").and_then(Value::as_u64).and_then(|f| by_file.get(&(f as u32)).copied());
                            let line = span.get("start_line").and_then(Value::as_u64).unwrap_or(0) as u32;
                            if let (Some(target), Some(file)) = (name, file) {
                                if line > 0 {
                                    facts.calls.push(HirCall { file, line, target, function });
                                }
                            }
                        }
                    }
                    stack.extend(map.values());
                }
                Value::Array(items) => stack.extend(items.iter()),
                _ => {}
            }
        }
    };
    for module in &program.modules {
        for item in &module.items {
            match item {
                Item::Function(function) => {
                    let node = push_node(facts, &function.name);
                    if let Ok(value) = serde_json::to_value(&function.body) {
                        visit(value, Some(node), facts);
                    }
                }
                Item::Class(class) => {
                    for method in &class.methods {
                        let name = if method.name.contains('.') { method.name.clone() } else { format!("{}.{}", class.name, method.name) };
                        let node = push_node(facts, &name);
                        if let Ok(value) = serde_json::to_value(&method.body) {
                            visit(value, Some(node), facts);
                        }
                    }
                }
                Item::GlobalVar(global) => {
                    if let Ok(value) = serde_json::to_value(global) {
                        visit(value, None, facts);
                    }
                }
            }
        }
    }
}

fn push_node(facts: &mut HirFacts, name: &str) -> usize {
    facts.graph.nodes.push(FnNode { name: name.to_string() });
    facts.graph.callers.push(Vec::new());
    facts.graph.nodes.len() - 1
}

fn last_segment(name: &str) -> &str {
    name.rsplit(['.', '/']).next().unwrap_or(name)
}

/// Resolves call-target strings to function nodes by qualified-suffix
/// match (`a.util.parse` ↔ `util.parse`) through a last-segment index.
/// Heuristic by nature — dynamic dispatch and unresolved receivers
/// (`P().run`) simply produce no edge, which shortens a path rather than
/// inventing one.
fn link_graph(facts: &mut HirFacts) {
    let mut by_last: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, node) in facts.graph.nodes.iter().enumerate() {
        by_last.entry(last_segment(&node.name)).or_default().push(index);
    }
    let mut edges: Vec<(usize, usize)> = Vec::new();
    for call in &facts.calls {
        let Some(caller) = call.function else { continue };
        let Some(candidates) = by_last.get(last_segment(&call.target)) else { continue };
        for &callee in candidates {
            let name = &facts.graph.nodes[callee].name;
            let target = &call.target;
            let compatible = name == target
                || name.ends_with(&format!(".{target}"))
                || target.ends_with(&format!(".{name}"));
            if compatible && callee != caller {
                edges.push((caller, callee));
            }
        }
    }
    edges.sort_unstable();
    edges.dedup();
    for (caller, callee) in edges {
        facts.graph.callers[callee].push(caller);
    }
}
