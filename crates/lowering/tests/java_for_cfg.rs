use uniflow_ir::{Callee, InstKind, Terminator};
use uniflow_lang_java::JavaParser;
use uniflow_lowering::lower_program;
use uniflow_parser_core::SourceParser;

#[test]
fn for_continue_targets_update_and_backedge_targets_condition() {
    let source = "class Example { void run() { for (start(); ready(); step()) { mark(); continue; } after(); } }";
    let hir = JavaParser::default()
        .parse_file("Example.java", source)
        .unwrap();
    let ir = lower_program(&hir);
    let function = ir.find_function_by_name("Example.run").unwrap();
    let call_block = |suffix: &str| {
        function.blocks.iter().find(|block| block.insts.iter().any(|inst|
        matches!(&inst.kind, InstKind::Call(call) if matches!(&call.callee, Callee::Static(name) if name.ends_with(suffix)))))
        .unwrap_or_else(|| panic!("missing {suffix}: {function:#?}"))
    };
    let start = call_block("start");
    let ready = call_block("ready");
    let body = call_block("mark");
    let update = call_block("step");
    let after = call_block("after");
    assert!(matches!(start.term, Terminator::Goto(id) if id == ready.id));
    assert!(
        matches!(ready.term, Terminator::Branch { then_bb, else_bb, .. }
        if then_bb == body.id && else_bb == after.id)
    );
    assert!(matches!(body.term, Terminator::Goto(id) if id == update.id));
    assert!(matches!(update.term, Terminator::Goto(id) if id == ready.id));
}

#[test]
fn for_header_phi_contains_initial_and_updated_values() {
    let source = "class Example { void run() { String value = initial(); for (; ready(); value = next()) { consume(value); } } }";
    let hir = JavaParser::default()
        .parse_file("Example.java", source)
        .unwrap();
    let ir = lower_program(&hir);
    let function = ir.find_function_by_name("Example.run").unwrap();
    let next_value = function.blocks.iter().flat_map(|b| &b.insts).find_map(|inst| match &inst.kind {
        InstKind::Call(call) if matches!(&call.callee, Callee::Static(name) if name.ends_with("next")) => call.dst,
        _ => None,
    }).unwrap();
    let assigned = function
        .blocks
        .iter()
        .flat_map(|b| &b.insts)
        .find_map(|inst| match &inst.kind {
            InstKind::Copy { dst, src } if *src == next_value => Some(*dst),
            _ => None,
        })
        .unwrap();
    assert!(function.blocks.iter().flat_map(|b| &b.insts).any(|inst|
        matches!(&inst.kind, InstKind::Phi { inputs, .. } if inputs.len() == 2 && inputs.contains(&assigned))), "{function:#?}");
}

#[test]
fn nested_finally_overrides_return_and_unwinds_outer_cleanup() {
    let source = "class Example { int run() { try { try { return original(); } finally { return replacement(); } } finally { cleanup(); } } }";
    let hir = JavaParser::default()
        .parse_file("Example.java", source)
        .unwrap();
    let ir = lower_program(&hir);
    let function = ir.find_function_by_name("Example.run").unwrap();
    let mut current = function.blocks[0].id;
    let mut calls = Vec::new();
    let mut replacement = None;
    for _ in 0..function.blocks.len() + 1 {
        let block = function.blocks.iter().find(|b| b.id == current).unwrap();
        for inst in &block.insts {
            if let InstKind::Call(call) = &inst.kind {
                if let Callee::Static(name) = &call.callee {
                    calls.push(name.rsplit('.').next().unwrap().to_string());
                    if name.ends_with("replacement") {
                        replacement = call.dst;
                    }
                }
            }
        }
        match block.term {
            Terminator::Goto(next) => current = next,
            Terminator::Return(value) => {
                assert_eq!(calls, ["original", "replacement", "cleanup"]);
                assert!(replacement.is_some());
                assert_eq!(value, replacement);
                return;
            }
            _ => panic!("unexpected terminator: {block:#?}"),
        }
    }
    panic!("return was not reached");
}
