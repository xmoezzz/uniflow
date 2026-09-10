use uniflow_ir::{Callee, Function, InstKind, Terminator, ValueId};
use uniflow_lang_java::JavaParser;
use uniflow_lowering::lower_program;
use uniflow_parser_core::SourceParser;

fn lower(body: &str) -> Function {
    let source =
        format!("class Updates {{ int f(int i, int[] values, boolean flag) {{ {body} }} }}");
    let hir = JavaParser::default()
        .parse_file("Updates.java", &source)
        .unwrap();
    let ir = lower_program(&hir);
    uniflow_ir::validate_program(&ir).unwrap();
    ir.find_function_by_name("Updates.f").unwrap().clone()
}

fn steps(f: &Function) -> Vec<(ValueId, ValueId, bool)> {
    f.blocks
        .iter()
        .flat_map(|b| &b.insts)
        .filter_map(|i| match i.kind {
            InstKind::NumericStep {
                dst,
                src,
                increment,
            } => Some((dst, src, increment)),
            _ => None,
        })
        .collect()
}

#[test]
fn java_updates_return_old_or_new_value_and_write_back_in_argument_order() {
    for (body, postfix, increment) in [
        ("return i++;", true, true),
        ("return ++i;", false, true),
        ("return i--;", true, false),
        ("return --i;", false, false),
    ] {
        let f = lower(body);
        let [(new, old, direction)] = steps(&f)[..] else {
            panic!("{f:#?}")
        };
        assert_eq!(direction, increment);
        assert_ne!(new, old);
        assert!(f.blocks.iter().any(|b| matches!(b.term, Terminator::Return(Some(v)) if v == if postfix { old } else { new })));
        assert_eq!(f.value_types.get(&new).map(String::as_str), Some("int"));
    }
    let f = lower("consume(i++, ++i, i); return i;");
    let [(first, old, true), (second, prior, true)] = steps(&f)[..] else {
        panic!("{f:#?}")
    };
    assert_eq!(first, prior);
    let call = f.blocks.iter().flat_map(|b| &b.insts).find_map(|i| match &i.kind {
        InstKind::Call(c) if matches!(&c.callee, Callee::Static(n) if n.ends_with("consume")) => Some(c), _ => None,
    }).unwrap();
    assert_eq!(call.args, [old, second, second]);
}

#[test]
fn java_updates_evaluate_field_receiver_and_array_subscript_once() {
    for body in [
        "return receiver().count++;",
        "return values[nextIndex()]++;",
        "return values[i++]++;",
    ] {
        let f = lower(body);
        let instructions = f.blocks.iter().flat_map(|b| &b.insts).collect::<Vec<_>>();
        let calls = instructions
            .iter()
            .filter(|i| matches!(i.kind, InstKind::Call(_)))
            .count();
        assert_eq!(calls, usize::from(!body.contains("i++")), "{f:#?}");
        let (dst, old, _) = *steps(&f).last().unwrap();
        let load = instructions
            .iter()
            .find(|i| {
                matches!(i.kind,
            InstKind::LoadField { dst: d, .. } | InstKind::LoadIndex { dst: d, .. } if d == old)
            })
            .unwrap();
        assert!(
            instructions.iter().any(|i| match (&load.kind, &i.kind) {
                (
                    InstKind::LoadField {
                        base: a, field: x, ..
                    },
                    InstKind::StoreField {
                        base: b,
                        field: y,
                        src,
                    },
                ) => a == b && x == y && *src == dst,
                (
                    InstKind::LoadIndex {
                        base: a, index: x, ..
                    },
                    InstKind::StoreIndex {
                        base: b,
                        index: y,
                        src,
                    },
                ) => a == b && x == y && *src == dst,
                _ => false,
            }),
            "{f:#?}"
        );
    }
}

#[test]
fn java_updates_feed_branch_and_for_backedge_values() {
    let f = lower("if (flag) { i++; } else { --i; } return i;");
    let updates = steps(&f).iter().map(|s| s.0).collect::<Vec<_>>();
    assert_eq!(updates.len(), 2);
    assert!(f
        .blocks
        .iter()
        .flat_map(|b| &b.insts)
        .any(|i| matches!(&i.kind,
        InstKind::Phi { inputs, .. } if updates.iter().all(|v| inputs.contains(v)))));
    let f = lower("for (; flag; i++) { consume(i); } return i;");
    let [(new, old, true)] = steps(&f)[..] else {
        panic!("{f:#?}")
    };
    assert!(f
        .blocks
        .iter()
        .flat_map(|b| &b.insts)
        .any(|i| matches!(&i.kind,
        InstKind::Phi { dst, inputs } if *dst == old && inputs.contains(&new))));
}

#[test]
fn java_assignment_captures_location_before_rhs_update() {
    for body in ["values[i++] = i++; return i;", "return values[i++] = i++;"] {
        let f = lower(body);
        let [(first, old, true), (_, second_old, true)] = steps(&f)[..] else {
            panic!("{f:#?}")
        };
        assert_eq!(first, second_old);
        assert!(
            f.blocks
                .iter()
                .flat_map(|b| &b.insts)
                .any(|i| matches!(i.kind,
            InstKind::StoreIndex { index, src, .. } if index == old && src == first)),
            "{f:#?}"
        );
    }
    for body in [
        "receiver().count = nextValue(); return i;",
        "return receiver().count = nextValue();",
    ] {
        let f = lower(body);
        let calls = f
            .blocks
            .iter()
            .flat_map(|b| &b.insts)
            .filter_map(|i| match &i.kind {
                InstKind::Call(c) => match &c.callee {
                    Callee::Static(n) => n.rsplit('.').next(),
                    _ => None,
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(calls, ["receiver", "nextValue"]);
    }
}
