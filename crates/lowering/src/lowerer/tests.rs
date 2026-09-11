#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_lang_c::CParser;
    use uniflow_lang_cpp::CppParser;
    use uniflow_lang_python::PythonParser;
    use uniflow_parser_core::SourceParser;

    #[test]
    fn cpp_numeric_negation_is_preserved_as_an_explicit_ir_transform() {
        let hir = CppParser
            .parse_file(
                "numeric-neg.cpp",
                r#"
int neg_const() { return -1; }
int neg_var(int i) { return -i; }
"#,
            )
            .expect("parse C++ numeric negation");
        let ir = lower_program(&hir);

        let neg_const = ir.find_function_by_name("neg_const").expect("neg_const");
        let mut const_one = None;
        let mut const_neg = None;
        for inst in neg_const.blocks.iter().flat_map(|block| &block.insts) {
            match inst.kind {
                InstKind::ConstInt { dst, value: 1 } => const_one = Some(dst),
                InstKind::NumericNeg { dst, src } => const_neg = Some((dst, src)),
                _ => {}
            }
        }
        let one = const_one.expect("positive literal operand");
        let (negated, source) = const_neg.expect("explicit numeric negation");
        assert_eq!(source, one, "-1 must negate the literal operand in IR");
        assert_eq!(neg_const.value_types.get(&negated).map(String::as_str), Some("int"));

        let neg_var = ir.find_function_by_name("neg_var").expect("neg_var");
        let parameter = neg_var.params[0];
        assert!(neg_var
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .any(|inst| matches!(inst.kind, InstKind::NumericNeg { src, .. } if src == parameter)));
    }

    fn named_ir_value(function: &uniflow_ir::Function, name: &str) -> uniflow_ir::ValueId {
        function
            .attrs
            .get("value_names")
            .into_iter()
            .flat_map(|encoded| encoded.split('\u{1f}'))
            .find_map(|entry| {
                let (id, entry_name) = entry.split_once('=')?;
                (entry_name == name)
                    .then(|| id.parse::<u32>().ok().map(uniflow_ir::ValueId))
                    .flatten()
            })
            .unwrap_or_else(|| panic!("missing IR value named {name}"))
    }

    fn const_int_value(function: &uniflow_ir::Function, value: uniflow_ir::ValueId) -> Option<i64> {
        function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find_map(|inst| match inst.kind {
                InstKind::ConstInt { dst, value: constant } if dst == value => Some(constant),
                _ => None,
            })
    }

    #[test]
    fn lowering_preserves_fixed_and_vla_array_extent_values() {
        let hir = CParser
            .parse_file(
                "array_extents.c",
                "int run(int n) { int fixed[8]; int vla[n]; return fixed[0] + vla[0]; }",
            )
            .expect("parse array extents");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("run").expect("run function");

        let fixed = named_ir_value(function, "fixed");
        let fixed_extent = function
            .value_array_extent(fixed, 0)
            .flatten()
            .expect("fixed array extent");
        assert_eq!(const_int_value(function, fixed_extent), Some(8));

        let vla = named_ir_value(function, "vla");
        let vla_extent = function
            .value_array_extent(vla, 0)
            .flatten()
            .expect("VLA extent");
        assert_eq!(vla_extent, function.params[0], "VLA extent must reuse parameter SSA value");
    }

    #[test]
    fn lowering_propagates_remaining_multidimensional_extent_after_index() {
        let hir = CParser
            .parse_file(
                "matrix.c",
                "int run(void) { int matrix[2][3]; return matrix[1][2]; }",
            )
            .expect("parse matrix");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("run").expect("run function");
        let matrix = named_ir_value(function, "matrix");
        let extents = function.value_array_extents(matrix).expect("matrix extents");
        assert_eq!(extents.len(), 2);
        assert_eq!(
            const_int_value(function, extents[0].expect("outer extent")),
            Some(2)
        );
        assert_eq!(
            const_int_value(function, extents[1].expect("inner extent")),
            Some(3)
        );

        let row = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find_map(|inst| match inst.kind {
                InstKind::LoadIndex { dst, base, .. } if base == matrix => Some(dst),
                _ => None,
            })
            .expect("outer index load");
        let row_extents = function.value_array_extents(row).expect("row extents");
        assert_eq!(row_extents.len(), 1);
        assert_eq!(
            const_int_value(function, row_extents[0].expect("row extent")),
            Some(3)
        );
    }

    #[test]
    fn cpp_null_comparisons_lower_to_compare_predicates_not_phi_values() {
        let hir = CppParser
            .parse_file(
                "null-compare.cpp",
                r#"
void consume(int *p) {}
void run(int *p) {
    if (p == nullptr) { consume(p); }
    if (p != nullptr) { consume(p); }
}
"#,
            )
            .expect("parse C++ null comparisons");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("run").expect("run function");
        let mut comparisons = Vec::new();
        let mut null_values = std::collections::HashSet::new();
        let mut phi_outputs = std::collections::HashSet::new();
        for inst in function.blocks.iter().flat_map(|block| &block.insts) {
            match &inst.kind {
                InstKind::ConstString { dst, value } if value == "<null>" => {
                    null_values.insert(*dst);
                }
                InstKind::Compare { dst, lhs, rhs, op } => {
                    comparisons.push((*dst, *lhs, *rhs, *op));
                }
                InstKind::Phi { dst, .. } => {
                    phi_outputs.insert(*dst);
                }
                _ => {}
            }
        }
        assert_eq!(comparisons.len(), 2, "{function:#?}");
        assert!(
            comparisons.iter().any(|(_, lhs, rhs, op)| {
                *op == ComparisonOp::Eq
                    && (null_values.contains(lhs) || null_values.contains(rhs))
            }),
            "missing equality null predicate: {function:#?}"
        );
        assert!(
            comparisons.iter().any(|(_, lhs, rhs, op)| {
                *op == ComparisonOp::Ne
                    && (null_values.contains(lhs) || null_values.contains(rhs))
            }),
            "missing inequality null predicate: {function:#?}"
        );
        assert!(
            comparisons
                .iter()
                .all(|(dst, _, _, _)| !phi_outputs.contains(dst)),
            "comparison result must not be represented as a Phi value"
        );
        for block in &function.blocks {
            if let Terminator::Branch { cond, .. } = block.term {
                assert!(
                    comparisons.iter().any(|(dst, _, _, _)| *dst == cond),
                    "branch condition must consume an explicit Compare result: {block:#?}"
                );
            }
        }
    }

    #[test]
    fn javascript_es_import_aliases_lower_to_package_qualified_callees() {
        let hir = uniflow_lang_frontends::parse_file(
            Language::JavaScript,
            "imports.js",
            r#"
import * as child from "child_process";
import bluebird from "bluebird";
import { exec as run } from "child_process";
function execute(command, object) {
    child.spawn(command);
    bluebird.toFastProperties(object);
    run(command);
}
"#,
        )
        .expect("parse JavaScript imports");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("execute").expect("execute function");
        let callees = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| match &inst.kind {
                InstKind::Call(call) => match &call.callee {
                    Callee::Static(name) => Some(name.as_str()),
                    Callee::Dynamic(_) | Callee::Unknown => None,
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(callees.contains(&"child_process.spawn"), "{callees:?}");
        assert!(callees.contains(&"bluebird.toFastProperties"), "{callees:?}");
        assert!(callees.contains(&"child_process.exec"), "{callees:?}");
    }

    #[test]
    fn javascript_assigned_lambdas_keep_handler_and_variable_names() {
        let hir = uniflow_lang_frontends::parse_file(
            Language::JavaScript,
            "lambda-handlers.js",
            r#"
exports.handler = function(event) { return event; };
const localHandler = function(input) { return input; };
"#,
        )
        .expect("parse JavaScript assigned lambdas");
        let ir = lower_program(&hir);
        assert!(ir.find_function_by_name("exports.handler").is_some(), "{ir:#?}");
        assert!(ir.find_function_by_name("localHandler").is_some(), "{ir:#?}");
    }

    #[test]
    fn javascript_expression_composition_returns_a_first_class_value() {
        let hir = uniflow_lang_frontends::parse_file(
            Language::JavaScript,
            "composition.js",
            r#"
function format(name) {
    const message = "user:" + name;
    console.log(message, name);
    return message;
}
"#,
        )
        .expect("parse JavaScript composition");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("format").expect("format function");
        let composed = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(&call.callee, Callee::Static(name) if name == "__uniflow.compose.string") =>
                {
                    call.dst
                }
                _ => None,
            })
            .expect("composition call result");
        let stored = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find_map(|inst| match inst.kind {
                InstKind::Copy { dst, src } if src == composed => Some(dst),
                _ => None,
            })
            .expect("composition result stored in local");
        assert!(function.blocks.iter().flat_map(|block| &block.insts).any(|inst| {
            matches!(&inst.kind, InstKind::Call(call)
                if matches!(&call.callee, Callee::Static(name) if name.ends_with("console.log"))
                    && call.args.first() == Some(&stored))
        }), "{function:#?}");
    }

    #[test]
    fn javascript_map_descriptor_preserves_static_field_paths() {
        let hir = uniflow_lang_frontends::parse_file(
            Language::JavaScript,
            "map-descriptor.js",
            r#"
const argon = require("argon2");
function options() { return { type: argon.argon2id }; }
"#,
        )
        .expect("parse JavaScript map descriptor");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("options").expect("options function");
        let constants = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| match &inst.kind {
                InstKind::ConstString { value, .. } => Some(value.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            constants.iter().any(|value| value.contains("type argon.argon2id")),
            "{constants:?}"
        );
    }

    #[test]
    fn lowering_expands_python_destructuring_into_index_loads() {
        let src = r#"
def load_pair():
    return source()

def handle(payload):
    left, right = load_pair()
    for key, value in payload.items():
        right = value
    return right
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| matches!(&inst.kind, InstKind::LoadIndex { .. })));
    }

    #[test]
    fn lowering_preserves_resolved_python_callable_alias_targets() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    runner = load
    return runner(cmd)
".to_string(),
            ),
        ];
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_keeps_python_control_flow_inputs_live() {
        let src = r#"
from flask import request

def handle(items):
    if request.args.get("cmd"):
        pass
    for item in items:
        value = item
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| matches!(&inst.kind, InstKind::Call(_))));
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| matches!(&inst.kind, InstKind::Copy { .. })));
    }
    #[test]
    fn lowering_preserves_callable_field_value_targets() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

class Service:
    def handle(self, cmd):
        self.cb = load
        return self.cb(cmd)
".to_string(),
            ),
        ];
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.Service.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_preserves_indexed_callable_value_targets() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    handlers = [load]
    return handlers[0](cmd)
".to_string(),
            ),
        ];
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_preserves_alias_backed_callable_field_targets() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, load

def handle(cmd):
    svc = Service()
    alias = svc
    alias.cb = load
    return svc.cb(cmd)
".to_string(),
            ),
        ];
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_preserves_lambda_capture_bindings() {
        let src = r#"
def handle(cmd):
    cb = lambda x: cmd
    return cb("safe")
"#;
        let hir = uniflow_lang_python::PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let handle = ir.find_function_by_name("handle").expect("handle function");
        assert!(handle.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::StoreField { field, .. } => field == "__capture__cmd",
            _ => false,
        }));
        let lambda = ir.functions.iter().find(|func| func.name.contains("__lambda_")).expect("lambda function");
        assert_eq!(lambda.attrs.get("capture_names").map(|s| s.as_str()), Some("cmd"));
        assert_eq!(lambda.params.len(), 2);
    }

    #[test]
    fn lowering_preserves_lambda_callable_value_types() {
        let src = r#"
def handle(cmd):
    cb = lambda x: x
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.value_types.values().any(|ty| ty.contains("__lambda_")));
    }

    #[test]
    fn lowering_discovers_descriptor_lambda_functions_and_captures() {
        let hir = uniflow_lang_frontends::parse_file(
            uniflow_hir::Language::JavaScript,
            "lambda.js",
            "const prefix = source(); const cb = (x) => prefix + x; sink(cb('v'));",
        )
        .expect("parse descriptor closure");
        let ir = lower_program(&hir);
        let lambda = ir
            .functions
            .iter()
            .find(|function| function.name.contains("__lambda_"))
            .expect("descriptor lambda should lower as an invokable function");
        assert_eq!(
            lambda.attrs.get("capture_names").map(String::as_str),
            Some("prefix")
        );
        assert_eq!(lambda.params.len(), 2, "one explicit param plus one capture");
        let top = ir
            .find_function_by_name("__top_level__")
            .expect("top-level function");
        assert!(top
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .any(|inst| matches!(
                &inst.kind,
                InstKind::Call(CallInst {
                    callee: Callee::Dynamic(_),
                    ..
                })
            )));
    }

    #[test]
    fn lowering_versions_reassigned_variables() {
        let src = r#"
def handle(value):
    value = source()
    value = "safe"
    return value
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        let copies = func
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match inst.kind {
                InstKind::Copy { dst, .. } => Some(dst),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(copies.len() >= 2);
        assert_ne!(copies[copies.len() - 1], copies[copies.len() - 2]);
    }

    #[test]
    fn lowering_preserves_conditional_expression_inputs() {
        use uniflow_hir::Language;
        use uniflow_parser_core::{LangDescriptor, LexerSpec};

        let descriptor = LangDescriptor {
            lexer: LexerSpec {
                keywords: &["void", "int", "return"],
                ..LexerSpec::default()
            },
            type_before_name: true,
            ..LangDescriptor::new(Language::C)
        };
        let (hir, errors) = uniflow_parser_core::parse_program(
            &descriptor,
            "conditional.c",
            "int choose(int flag, int value) { int out = flag ? value : 0; return out; }",
        )
        .expect("generic parse");
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("choose").expect("function");
        assert!(function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .any(|inst| matches!(&inst.kind, InstKind::Phi { inputs, .. } if inputs.len() == 2)));
    }

    #[test]
    fn lowering_builds_cfg_for_if_else_and_inserts_phi() {
        let src = r#"
def handle(flag, value):
    if flag:
        value = source()
    else:
        value = "safe"
    return value
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.blocks.len() >= 4);
        assert!(func.blocks.iter().any(|block| matches!(&block.term, Terminator::Branch { .. })));
        assert!(func
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .any(|inst| matches!(&inst.kind, InstKind::Phi { .. })));
    }

    #[test]
    fn lowering_builds_loop_back_edge() {
        let src = r#"
def handle(flag, value):
    while flag:
        value = source()
    return value
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        let targets = func
            .blocks
            .iter()
            .filter_map(|block| match block.term {
                Terminator::Goto(target) => Some(target),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(targets.iter().any(|target| {
            func.blocks.iter().any(|block| block.id == *target && matches!(&block.term, Terminator::Branch { .. }))
        }));
    }

    #[test]
    fn lowering_preserves_source_case_and_break_cfg_markers() {
        let hir = CppParser
            .parse_file(
                "case-break.cpp",
                "int f(int x) { switch (x) { case 1: x++; case 2: break; } return x; }",
            )
            .expect("parse C++ case-break fixture");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("f").expect("f function");

        let case_markers = function
            .attrs
            .keys()
            .filter(|key| key.starts_with("uniflow.source-cfg.case."))
            .cloned()
            .collect::<Vec<_>>();
        let break_markers = function
            .attrs
            .keys()
            .filter(|key| key.starts_with("uniflow.source-cfg.break."))
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(
            case_markers.len(),
            2,
            "expected one source CFG marker per non-default case, attrs={:?}",
            function.attrs
        );
        assert_eq!(
            break_markers.len(),
            1,
            "expected source break terminator marker, attrs={:?}",
            function.attrs
        );
    }

    #[test]
    fn lowering_distinguishes_source_return_from_implicit_function_exit() {
        let explicit = CppParser
            .parse_file(
                "explicit-return.cpp",
                "int f(int x) { switch (x) { case 1: x++; } return x; }",
            )
            .expect("parse explicit return fixture");
        let implicit = CppParser
            .parse_file(
                "implicit-exit.cpp",
                "void f(int x) { switch (x) { case 1: x++; } }",
            )
            .expect("parse implicit exit fixture");

        let explicit_function = lower_program(&explicit)
            .find_function_by_name("f")
            .expect("explicit f")
            .clone();
        let implicit_function = lower_program(&implicit)
            .find_function_by_name("f")
            .expect("implicit f")
            .clone();

        assert!(explicit_function
            .attrs
            .keys()
            .any(|key| key.starts_with("uniflow.source-cfg.return.")));
        assert!(!implicit_function
            .attrs
            .keys()
            .any(|key| key.starts_with("uniflow.source-cfg.return.")));
    }

}
