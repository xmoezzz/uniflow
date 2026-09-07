use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_rules::{ApiMatcher, Port, RuleSet, SinkRule, SourceRule};
use uniflow_taint::analyze;
use uniflow_value_flow::build;

fn check(body: &str, expected: usize) -> uniflow_value_flow::FlowGraph {
    let rules = RuleSet {
        sources: vec![SourceRule { id: "expression-source".into(), language: Some(Language::Java),
            matcher: ApiMatcher { method_name: Some("input".into()), ..Default::default() },
            out: Port::Return, kind: "untrusted".into() }],
        sinks: vec![SinkRule { id: "expression-sink".into(), language: Some(Language::Java),
            matcher: ApiMatcher { method_name: Some("sink".into()), ..Default::default() },
            inputs: vec![Port::Arg(0)], kind: "untrusted".into() }],
        ..Default::default()
    };
    let source = format!("class Flow {{ void f(boolean flag, boolean other, String[] values) {{ {body} }} }}");
    let hir = parse_source(Language::Java, "Flow.java", &source).unwrap();
    let ir = lower_program(&hir);
    let graph = build(&ir, &rules);
    let findings = analyze(&graph, &rules);
    assert_eq!(findings.len(), expected, "{body}\n{findings:#?}");
    graph
}

#[test]
fn java_casts_preserve_taint_edges() {
    check("sink((String) input());", 1);
    check("sink((String) \"safe\");", 0);
}

#[test]
fn java_array_store_reaches_same_index_load() {
    let graph = check("values[0] = input(); sink(values[0]);", 1);
    // One source-level cell must not grow into synthetic [0][0]... paths
    // while materializing summaries back into their own function.
    let cells = graph.graph.node_weights().filter(|node| matches!(node, uniflow_value_flow::FlowNode::IndexCell { .. })).collect::<Vec<_>>();
    assert_eq!(cells.iter().filter(|node| matches!(node, uniflow_value_flow::FlowNode::IndexCell { abstract_key, .. } if abstract_key != "*")).count(), 1, "{cells:#?}");
    // Two wildcard projection cells are conservative aliases built by the
    // heap bridge, not additional concrete dereferences.
    assert!(cells.len() <= 3, "{cells:#?}");
    assert!(graph.solver_closure_iterations <= 3);
}

#[test]
fn java_clean_array_store_does_not_create_taint() {
    check("values[0] = \"safe\"; sink(values[0]);", 0);
}

#[test]
fn java_source_array_taints_element_load() {
    check("String[] local = input(); sink(local[0]);", 1);
}

#[test]
fn java_conditional_results_and_assignments_merge_both_arms() {
    check("sink(flag ? input() : \"safe\");", 1);
    check("sink(flag ? \"safe\" : input());", 1);
    check("sink(flag ? other ? \"safe\" : input() : \"safe\");", 1);
    check("String value=\"safe\"; String selected=flag ? (value=input()) : (value=\"safe\"); sink(value);", 1);
    check("String value=input(); String selected=flag ? (value=\"safe\") : \"safe\"; sink(value);", 1);
    check("String value=input(); String selected=flag ? (value=\"safe\") : (value=\"safe\"); sink(value);", 0);
    check("String value=\"safe\"; sink(flag ? (value=input()) : value);", 1);
}

#[test]
fn java_literal_conditional_executes_only_selected_arm() {
    check("sink(true ? \"safe\" : input());", 0);
    check("sink(false ? input() : \"safe\");", 0);
    check("sink(true ? input() : \"safe\");", 1);
    check("String value=\"safe\"; String selected=true ? \"safe\" : (value=input()); sink(value);", 0);
    check("String value=input(); String selected=false ? value : (value=\"safe\"); sink(value);", 0);
}
