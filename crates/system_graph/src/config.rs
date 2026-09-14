//! Configuration-resolution adapter: connects `getenv`-style reads found in
//! each language's own IR (`System.getenv("X")`, `os.getenv("X")`,
//! `os.environ.get("X")`, a bare `getenv("X")`, ...) to `EnvironmentVariable`
//! nodes recovered by the deployment adapters ([`crate::docker_compose`],
//! [`crate::kubernetes`]).
//!
//! This module only recognizes a *literal* environment-variable-name
//! argument (`getenv("SERVICE_URL")`); a dynamically-constructed name
//! (`getenv(prefix + suffix)`) is not resolved — there is nothing sound to
//! connect it to.

use anyhow::Result;
use uniflow_ir::{Callee, Function, InstKind, Program, ValueId};

use crate::graph::{BoundarySummary, Confidence, EdgeKind, Evidence, NodeKind, SystemGraph, SystemNode};

/// Callee-name suffixes recognized as "read an environment variable by
/// name", matched by suffix so a frontend's own fully-qualified form (e.g.
/// `java.lang.System.getenv`) still matches without needing the exact
/// prefix. Extending this table is the expected way to support another
/// language's convention — nothing else in this module is language-specific.
const GETENV_SUFFIXES: &[&str] = &[".getenv", "getenv", "os.environ.get", ".environ.get", "env.var", "env::var"];

pub(crate) fn is_getenv_call(callee_name: &str) -> bool {
    GETENV_SUFFIXES.iter().any(|suffix| callee_name == *suffix || callee_name.ends_with(suffix))
}

/// One recognized `getenv`-style call site with a literal argument.
#[derive(Clone, Debug)]
pub struct ConfigRead {
    pub function_name: String,
    pub inst_id: u32,
    pub env_var_name: String,
    /// The `ValueId` the call's result is bound to, within `function_name`'s
    /// own IR — used by adapters (e.g. [`crate::http`]) that need to trace
    /// this read forward into further string construction.
    pub result_value: ValueId,
}

/// Scans every function in `program` for a recognized `getenv`-style call
/// whose argument is a literal string.
pub fn scan_program(program: &Program) -> Vec<ConfigRead> {
    let mut reads = Vec::new();
    for function in &program.functions {
        let mut const_strings = std::collections::HashMap::new();
        for block in &function.blocks {
            for inst in &block.insts {
                if let InstKind::ConstString { dst, value } = &inst.kind {
                    const_strings.insert(*dst, value.clone());
                }
            }
        }
        for block in &function.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else { continue };
                let Callee::Static(name) = &call.callee else { continue };
                if !is_getenv_call(name) {
                    continue;
                }
                let Some(&arg0) = call.args.first() else { continue };
                let Some(literal) = const_strings.get(&arg0) else { continue };
                let Some(dst) = call.dst else { continue };
                reads.push(ConfigRead {
                    function_name: function.name.clone(),
                    inst_id: inst.id.0,
                    env_var_name: literal.clone(),
                    result_value: dst,
                });
            }
        }
    }
    reads
}

/// Records every recognized read from `program` into `graph` as a
/// `READS_CONFIG` edge from the call site to every same-named
/// `EnvironmentVariable` node already recovered by a deployment adapter (if
/// more than one service defines the same name, each is a distinct, valid
/// resolution target — that is not treated as an ambiguity to collapse).
pub fn discover_into(graph: &mut SystemGraph, program: &Program) -> Result<Vec<ConfigRead>> {
    let reads = scan_program(program);
    let language_tag = program.language.as_str();
    for read in &reads {
        let call_node_id = format!("code:{language_tag}:{}#{}", read.function_name, read.inst_id);
        graph.upsert_node(SystemNode::new(
            NodeKind::CallSite,
            call_node_id.clone(),
            format!("getenv(\"{}\")", read.env_var_name),
        ));

        let matches: Vec<String> = graph
            .nodes()
            .filter(|node| node.kind == NodeKind::EnvironmentVariable && node.name == read.env_var_name)
            .map(|node| node.id.clone())
            .collect();
        for env_node_id in matches {
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::ReadsConfig, call_node_id.clone(), env_node_id, Confidence::Exact).with_evidence(
                    Evidence::new(format!("{} reads getenv(\"{}\")", read.function_name, read.env_var_name)),
                ),
            )?;
        }
    }
    Ok(reads)
}

/// If `value` is the result of a recognized `getenv`-style call within
/// `function`, returns the literal environment-variable-name argument it
/// read.  Straight-line assignments naturally lower to `Copy`, so those are
/// followed. A `Phi` is followed only when *every* incoming value resolves
/// to the same environment-variable name; a conditional between different
/// names remains unknown rather than becoming an arbitrary configuration
/// resolution.
pub(crate) fn getenv_name_for_result(function: &Function, value: ValueId) -> Option<String> {
    let mut const_strings = std::collections::HashMap::new();
    let mut defs = std::collections::HashMap::new();
    for block in &function.blocks {
        for inst in &block.insts {
            if let InstKind::ConstString { dst, value } = &inst.kind {
                const_strings.insert(*dst, value.clone());
            }
            match &inst.kind {
                InstKind::Copy { dst, .. } | InstKind::Phi { dst, .. } => {
                    defs.insert(*dst, &inst.kind);
                }
                _ => {}
            }
        }
    }

    fn resolve(
        function: &Function,
        value: ValueId,
        const_strings: &std::collections::HashMap<ValueId, String>,
        defs: &std::collections::HashMap<ValueId, &InstKind>,
        visited: &mut std::collections::HashSet<ValueId>,
    ) -> Option<String> {
        if !visited.insert(value) {
            return None;
        }
        for block in &function.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else { continue };
                if call.dst != Some(value) {
                    continue;
                }
                let Callee::Static(name) = &call.callee else { continue };
                if !is_getenv_call(name) {
                    return None;
                }
                let &arg0 = call.args.first()?;
                return const_strings.get(&arg0).cloned();
            }
        }
        match defs.get(&value) {
            Some(InstKind::Copy { src, .. }) => resolve(function, *src, const_strings, defs, visited),
            Some(InstKind::Phi { inputs, .. }) if !inputs.is_empty() => {
                let first = resolve(function, inputs[0], const_strings, defs, visited)?;
                inputs[1..]
                    .iter()
                    .all(|input| resolve(function, *input, const_strings, defs, visited).as_deref() == Some(first.as_str()))
                    .then_some(first)
            }
            _ => None,
        }
    }

    resolve(function, value, &const_strings, &defs, &mut std::collections::HashSet::new())
}

/// The concrete literal value recovered for environment variable `name`, if
/// every `EnvironmentVariable` node with that name agrees on one value.
/// `None` when undefined, or defined with more than one distinct literal
/// value (ambiguous — callers should stay conservative rather than
/// arbitrarily pick one candidate).
pub fn resolve_env_literal(graph: &SystemGraph, name: &str) -> Option<String> {
    let mut values: Vec<&str> = graph
        .nodes()
        .filter(|node| node.kind == NodeKind::EnvironmentVariable && node.name == name)
        .filter_map(|node| node.attrs.get("value").map(String::as_str))
        .collect();
    values.sort_unstable();
    values.dedup();
    match values.as_slice() {
        [only] => Some((*only).to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    fn lower_java(source: &str) -> Program {
        let hir = uniflow_lang_java::JavaParser::default().parse_file("Probe.java", source).expect("parse java");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn recognizes_the_jdk_qualified_system_getenv_call() {
        let program = lower_java(
            r#"
class App {
    static void run() {
        String base = System.getenv("USER_SERVICE_URL");
    }
}
"#,
        );
        let reads = scan_program(&program);
        assert_eq!(reads.len(), 1, "{reads:?}");
        assert_eq!(reads[0].env_var_name, "USER_SERVICE_URL");
        assert_eq!(reads[0].function_name, "App.run");
    }

    #[test]
    fn resolves_a_getenv_read_to_a_compose_defined_value() {
        let program = lower_java(
            r#"
class App {
    static void run() {
        String base = System.getenv("USER_SERVICE_URL");
    }
}
"#,
        );
        let mut graph = SystemGraph::new();
        graph.upsert_node(SystemNode::new(NodeKind::EnvironmentVariable, "compose:env:api:USER_SERVICE_URL", "USER_SERVICE_URL").with_attr("value", "http://user:8080"));

        discover_into(&mut graph, &program).expect("discover config reads");
        let reads_config: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::ReadsConfig).collect();
        assert_eq!(reads_config.len(), 1, "{reads_config:?}");
        assert_eq!(reads_config[0].1.id, "compose:env:api:USER_SERVICE_URL");

        assert_eq!(resolve_env_literal(&graph, "USER_SERVICE_URL").as_deref(), Some("http://user:8080"));
        assert_eq!(resolve_env_literal(&graph, "UNKNOWN"), None);
    }

    #[test]
    fn ambiguous_values_across_services_resolve_to_none() {
        let mut graph = SystemGraph::new();
        graph.upsert_node(SystemNode::new(NodeKind::EnvironmentVariable, "a", "SERVICE_URL").with_attr("value", "http://one:8080"));
        graph.upsert_node(SystemNode::new(NodeKind::EnvironmentVariable, "b", "SERVICE_URL").with_attr("value", "http://two:8080"));
        assert_eq!(resolve_env_literal(&graph, "SERVICE_URL"), None);
    }

    #[test]
    fn follows_a_straight_line_assignment_of_a_getenv_result() {
        let program = lower_java(
            r#"
class App {
    static void run() {
        String raw = System.getenv("TOPIC");
        String topic = raw;
    }
}
"#,
        );
        let function = program.functions.iter().find(|function| function.name == "App.run").expect("run function");
        let copied = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find_map(|inst| match &inst.kind {
                InstKind::Copy { dst, .. } => Some(*dst),
                _ => None,
            })
            .expect("copy result");
        assert_eq!(getenv_name_for_result(function, copied).as_deref(), Some("TOPIC"));
    }
}
