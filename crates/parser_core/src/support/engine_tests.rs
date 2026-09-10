// Tests for the generic statement and expression engines. Each test uses a
// descriptor shaped like a real product language; the per-language crates pin
// their own descriptor separately.

use super::*;

#[test]
fn c_like_comment_masking_preserves_urls_strings_and_offsets() {
    let source = "call(\"https://example.test/a/*b*/\"); // trailing\nnext(); /* hidden */\n";
    let stripped = strip_c_like_comments(source);
    assert_eq!(stripped.len(), source.len());
    assert!(stripped.contains("\"https://example.test/a/*b*/\""));
    assert!(!stripped.contains("trailing"));
    assert!(!stripped.contains("hidden"));
    assert_eq!(
        stripped.find("next").expect("next offset"),
        source.find("next").expect("source next offset")
    );
}
use uniflow_hir::{Function, LValue, Stmt};

fn stmt_kinds(block: &Block) -> Vec<&'static str> {
    block
        .stmts
        .iter()
        .map(|stmt| match stmt {
            Stmt::Let { .. } => "let",
            Stmt::Assign { .. } => "assign",
            Stmt::Expr { .. } => "expr",
            Stmt::If { .. } => "if",
            Stmt::While { .. } => "while",
            Stmt::DoWhile { .. } => "dowhile",
            Stmt::ForEach { .. } => "foreach",
            Stmt::For { .. } => "for",
            Stmt::Switch { .. } => "switch",
            Stmt::Return { .. } => "return",
            Stmt::Throw { .. } => "throw",
            Stmt::Try { .. } => "try",
            Stmt::Break { .. } => "break",
            Stmt::Continue { .. } => "continue",
        })
        .collect()
}

fn only_function(program: &Program) -> &Function {
    program
        .modules
        .iter()
        .flat_map(|module| module.items.iter())
        .find_map(|item| match item {
            Item::Function(function) => Some(function),
            _ => None,
        })
        .expect("a function")
}

fn functions(program: &Program) -> Vec<&Function> {
    program
        .modules
        .iter()
        .flat_map(|module| module.items.iter())
        .filter_map(|item| match item {
            Item::Function(function) => Some(function),
            _ => None,
        })
        .collect()
}

fn classes(program: &Program) -> Vec<&uniflow_hir::Class> {
    program
        .modules
        .iter()
        .flat_map(|module| module.items.iter())
        .filter_map(|item| match item {
            Item::Class(class) => Some(class),
            _ => None,
        })
        .collect()
}

fn c_like() -> LangDescriptor {
    LangDescriptor {
        lexer: LexerSpec {
            keywords: &[
                "int", "char", "void", "float", "double", "return", "if", "else", "while", "for",
                "switch", "case", "default", "break", "continue", "try", "catch", "finally",
                "throw", "class", "new", "true", "false", "struct", "static", "const",
            ],
            ..LexerSpec::default()
        },
        type_before_name: true,
        ..LangDescriptor::new(Language::C)
    }
}

fn parsed(descriptor: &LangDescriptor, source: &str) -> Program {
    let (program, _) = parse_program(descriptor, "t.c", source).expect("parse");
    program
}

#[test]
fn parses_c_family_function() {
    let program = parsed(
        &c_like(),
        "int add(int a, int b) { int sum = a + b; return sum; }",
    );
    let function = only_function(&program);
    assert_eq!(function.name, "add");
    assert_eq!(function.params.len(), 2);
    assert_eq!(function.params[0].name, "a");
    assert_eq!(stmt_kinds(&function.body), vec!["let", "return"]);
}

#[test]
fn parses_pointer_and_generic_declarators() {
    let program = parsed(
        &c_like(),
        "char *copy(char *src, int n) { char buf[16]; return buf; }",
    );
    let function = only_function(&program);
    assert_eq!(function.params[0].name, "src");
    assert_eq!(stmt_kinds(&function.body), vec!["let", "return"]);
}

#[test]
fn parses_if_else_chain() {
    let program = parsed(
        &c_like(),
        "int f(int x) { if (x > 1) { return 2; } else if (x > 0) { return 1; } else { return 0; } }",
    );
    let function = only_function(&program);
    let Stmt::If {
        then_block,
        else_block,
        ..
    } = &function.body.stmts[0]
    else {
        panic!("expected if");
    };
    assert_eq!(stmt_kinds(then_block), vec!["return"]);
    let else_block = else_block.as_ref().expect("else");
    // The `else if` becomes a nested if inside the else block.
    assert_eq!(stmt_kinds(else_block), vec!["if"]);
}

#[test]
fn preserves_c_style_for_regions() {
    let program = parsed(
        &c_like(),
        "void f(void) { for (int i = 0; i < 10; i++) { puts(i); } }",
    );
    let function = only_function(&program);
    assert_eq!(stmt_kinds(&function.body), vec!["for"]);
    let Stmt::For {
        init,
        cond,
        update,
        body,
        init_is_scoped,
        ..
    } = &function.body.stmts[0]
    else {
        panic!("expected for");
    };
    assert!(*init_is_scoped);
    assert!(cond.is_some());
    assert_eq!(stmt_kinds(init), vec!["let"]);
    assert_eq!(stmt_kinds(body), vec!["expr"]);
    assert_eq!(stmt_kinds(update), vec!["assign"]);
}

#[test]
fn classic_for_keeps_empty_condition_and_multiple_declarators() {
    let program = parsed(
        &c_like(),
        "void f(void) { for (int i=0, j=1;; i++, j--) { break; } after(); }",
    );
    let function = only_function(&program);
    assert_eq!(stmt_kinds(&function.body), ["for", "expr"]);
    let Stmt::For {
        init,
        cond,
        update,
        body,
        ..
    } = &function.body.stmts[0]
    else {
        panic!("for")
    };
    assert!(cond.is_none());
    assert_eq!(stmt_kinds(init), ["let", "let"]);
    assert_eq!(stmt_kinds(update), ["assign", "assign"]);
    assert_eq!(stmt_kinds(body), ["break"]);
}

#[test]
fn parses_switch_with_fallthrough_marks() {
    let program = parsed(
        &c_like(),
        "int f(int c) { switch (c) { case 1: case 2: g(); break; default: h(); } }",
    );
    let function = only_function(&program);
    let Stmt::Switch {
        clauses,
        default,
        scrutinee,
        ..
    } = &function.body.stmts[0]
    else {
        panic!("expected switch, got {:?}", stmt_kinds(&function.body));
    };
    assert!(matches!(scrutinee, Expr::VarRef { .. }));
    assert_eq!(clauses.len(), 2);
    // `case 1:` has an empty body and falls into `case 2:`.
    assert!(clauses[0].fallthrough);
    assert!(!clauses[1].fallthrough);
    assert!(default.is_some());
}

#[test]
fn parses_try_catch_and_throw() {
    let program = parsed(
        &c_like(),
        "void f(void) { try { risky(); } catch (E e) { handle(e); } finally { done(); } throw new E(\"x\"); }",
    );
    let function = only_function(&program);
    assert_eq!(stmt_kinds(&function.body), vec!["try", "throw"]);
    let Stmt::Try {
        catches,
        finally_block,
        ..
    } = &function.body.stmts[0]
    else {
        panic!("expected try");
    };
    assert_eq!(catches.len(), 1);
    assert!(catches[0].symbol.is_some());
    assert!(finally_block.is_some());
}

#[test]
fn parses_expressions_with_precedence_and_spans() {
    let program = parsed(
        &c_like(),
        "int f(int a, int b) { int x = a + b * 2 - 1; int y = (a > b) ? a : b; return x + y; }",
    );
    let function = only_function(&program);
    let Stmt::Let { init, .. } = &function.body.stmts[0] else {
        panic!("expected let");
    };
    // `a + (b * 2)` groups by precedence, and the span covers the initializer.
    let Expr::Binary { op, lhs, span, .. } = init.as_ref().expect("init") else {
        panic!("expected binary");
    };
    assert_eq!(*op, BinaryOp::Sub);
    assert!(matches!(lhs.as_ref(), Expr::Binary { op, .. } if *op == BinaryOp::Add));
    assert!(span.end_byte > span.start_byte);
    let _ = function.body.stmts[1];
}

#[test]
fn parses_casts_and_method_chains() {
    let program = parsed(
        &c_like(),
        "void f(void) { char *p = (char *) src; String s = obj.getName().trim(); }",
    );
    let function = only_function(&program);
    let Stmt::Let { init, .. } = &function.body.stmts[0] else {
        panic!("expected let");
    };
    assert!(matches!(init.as_ref().expect("init"), Expr::Cast { .. }));
    let Stmt::Let { init, .. } = &function.body.stmts[1] else {
        panic!("expected let");
    };
    let Expr::Call(call) = init.as_ref().expect("init") else {
        panic!("expected call");
    };
    assert!(matches!(&call.target, CallTarget::Named(name) if name == "trim"));
    let receiver = call.receiver.as_ref().expect("receiver");
    assert!(matches!(
        &**receiver,
        Expr::Call(inner)
            if matches!(&inner.target, CallTarget::Named(name) if name == "getName")
    ));
}

#[test]
fn class_body_splits_fields_and_methods() {
    let program = parsed(
        &c_like(),
        "class Runner { int count; String name; public int run(int x) { return x + count; } }",
    );
    let class = classes(&program).into_iter().next().expect("class");
    assert_eq!(class.name, "Runner");
    assert_eq!(class.bases, Vec::<String>::new());
    let fields: Vec<&str> = class
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect();
    assert_eq!(fields, vec!["count", "name"]);
    assert_eq!(class.methods.len(), 1);
    assert_eq!(class.methods[0].name, "Runner.run");
    assert!(class.methods[0].is_method);
}

#[test]
fn prototype_without_body_is_recorded() {
    let program = parsed(
        &c_like(),
        "int external(int a); void f(void) { external(1); }",
    );
    let names: Vec<&str> = functions(&program)
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(names, vec!["external", "f"]);
}

// ---------------------------------------------------------- newline languages

fn newline_lang(language: Language) -> LangDescriptor {
    LangDescriptor {
        lexer: LexerSpec {
            line_comments: vec!["#"],
            block_comments: vec![],
            significant_newlines: true,
            keywords: &[
                "def", "end", "if", "else", "elsif", "unless", "while", "until", "do", "for", "in",
                "return", "break", "continue", "begin", "rescue", "ensure", "throw", "class",
                "true", "false", "nil", "then", "and", "or", "not", "new", "import", "from", "as",
                "include", "require", "using", "use", "load", "source",
            ],
            interp: if language == Language::Ruby {
                InterpStyle::HashBrace
            } else {
                InterpStyle::Dollar
            },
            interpolation_quotes: vec!['"'],
            ..LexerSpec::default()
        },
        kw: Keywords {
            if_kw: "if",
            else_if: &["elsif"],
            while_kw: "while",
            until: Some("until"),
            do_kw: Some("do"),
            for_kw: "for",
            in_kw: Some("in"),
            try_kw: Some("begin"),
            catch_kw: &["rescue"],
            finally_kw: &["ensure"],
            throw_kw: &["throw"],
            class_kw: &["class"],
            function_kw: &["def"],
            end_kw: &["end"],
            then_kw: &["then", "do"],
            ..Keywords::default()
        },
        ops: ExprOps {
            word_logic: true,
            ..ExprOps::default()
        },
        block_style: BlockStyle::EndKeyword,
        newline_terminated: true,
        type_before_name: false,
        implicit_call_parens: true,
        trailing_if: true,
        methods_qualified: true,
        ..LangDescriptor::new(language)
    }
}

fn parsed_newline(descriptor: &LangDescriptor, source: &str, path: &str) -> Program {
    let (program, _) = parse_program(descriptor, path, source).expect("parse");
    program
}

#[test]
fn newline_language_parses_def_and_control_flow() {
    let descriptor = newline_lang(Language::Ruby);
    let program = parsed_newline(
        &descriptor,
        "def run(cmd)\n  if cmd\n    system cmd\n  else\n    log \"none\"\n  end\n  return cmd\nend\n",
        "a.rb",
    );
    let function = only_function(&program);
    assert_eq!(function.name, "run");
    assert_eq!(function.params.len(), 1);
    assert_eq!(stmt_kinds(&function.body), vec!["if", "return"]);
}

#[test]
fn newline_one_statement_bodies_and_modifiers() {
    let descriptor = newline_lang(Language::Ruby);
    let program = parsed_newline(
        &descriptor,
        "def f(x)\n  return x if x\n  puts x\nend\n",
        "b.rb",
    );
    let function = only_function(&program);
    // `return x if x` parses as a guarded return statement.
    assert_eq!(stmt_kinds(&function.body), vec!["if", "expr"]);
}

#[test]
fn parses_for_each_over_collection() {
    let descriptor = newline_lang(Language::Ruby);
    let program = parsed_newline(
        &descriptor,
        "def f(items)\n  for item in items do\n    work item\n  end\nend\n",
        "c.rb",
    );
    let function = only_function(&program);
    let Stmt::ForEach {
        item_symbol,
        iterable,
        body,
        ..
    } = &function.body.stmts[0]
    else {
        panic!("expected foreach, got {:?}", stmt_kinds(&function.body));
    };
    assert_eq!(symbol_text(&program, *item_symbol), "item");
    assert!(matches!(iterable, Expr::VarRef { .. }));
    assert_eq!(stmt_kinds(body), vec!["expr"]);
}

#[test]
fn parses_begin_rescue_ensure() {
    let descriptor = newline_lang(Language::Ruby);
    let program = parsed_newline(
        &descriptor,
        "def f\n  begin\n    risky\n  rescue E => e\n    log e\n  ensure\n    cleanup\n  end\nend\n",
        "d.rb",
    );
    let function = only_function(&program);
    let Stmt::Try {
        try_block,
        catches,
        finally_block,
        ..
    } = &function.body.stmts[0]
    else {
        panic!("expected try, got {:?}", stmt_kinds(&function.body));
    };
    assert_eq!(stmt_kinds(try_block), vec!["expr"]);
    assert_eq!(catches.len(), 1);
    assert!(catches[0].symbol.is_some());
    assert_eq!(
        stmt_kinds(finally_block.as_ref().expect("finally")),
        vec!["expr"]
    );
}

#[test]
fn interpolation_becomes_interp_node_with_parts() {
    let descriptor = newline_lang(Language::Ruby);
    let (program, errors) = parse_program(
        &descriptor,
        "e.rb",
        "def f(dir)\n  system \"rm -rf #{dir}\"\nend\n",
    )
    .expect("parse");
    assert!(errors.is_empty(), "{:?}", errors);
    let function = only_function(&program);
    let Stmt::Expr { expr, .. } = &function.body.stmts[0] else {
        panic!("expected expression statement");
    };
    let Expr::Call(call) = expr else {
        panic!("expected call");
    };
    assert!(matches!(&call.target, CallTarget::Named(name) if name == "system"));
    let Expr::Interp { parts, .. } = &call.args[0] else {
        panic!("expected interpolation, got {:?}", call.args[0]);
    };
    assert_eq!(parts.len(), 2);
    assert!(
        matches!(&parts[0], Expr::Literal { kind: LiteralKind::String(text), .. } if text == "rm -rf ")
    );
    assert!(matches!(&parts[1], Expr::VarRef { .. }));
}

#[test]
fn compound_assignment_keeps_previous_value() {
    let descriptor = c_like();
    let program = parsed(&descriptor, "void f(void) { buf += tainted; }");
    let function = only_function(&program);
    let Stmt::Assign { lhs, rhs, .. } = &function.body.stmts[0] else {
        panic!("expected assign");
    };
    assert!(matches!(lhs, LValue::Var(_)));
    assert!(matches!(
        rhs,
        Expr::Binary {
            op: BinaryOp::Add,
            ..
        }
    ));
}

#[test]
fn increment_is_assignment_of_plus_one() {
    let program = parsed(&c_like(), "void f(void) { i++; }");
    let function = only_function(&program);
    let Stmt::Assign { rhs, .. } = &function.body.stmts[0] else {
        panic!("expected assignment statement");
    };
    assert!(matches!(
        rhs,
        Expr::Binary {
            op: BinaryOp::Add,
            ..
        }
    ));
}

#[test]
fn unterminated_construct_recovers() {
    let (program, errors) =
        parse_program(&c_like(), "bad.c", "void f(void) { int x = ; int y = 1; }")
            .expect("parser infrastructure");
    assert!(!errors.is_empty(), "a syntax error must be reported");
    // Parsing continued far enough to record the following declaration.
    let function = only_function(&program);
    assert!(function.body.stmts.len() >= 1);
}

#[test]
fn top_level_statements_land_in_module_function() {
    let descriptor = newline_lang(Language::Shell);
    let program = parsed_newline(&descriptor, "cd /tmp\nrm -rf \"$dir\"\n", "s.sh");
    let names: Vec<&str> = functions(&program)
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert!(
        names.contains(&TOP_LEVEL_FUNCTION),
        "module statements need a carrier function, got {:?}",
        names
    );
    let function = functions(&program)
        .into_iter()
        .find(|function| function.name == TOP_LEVEL_FUNCTION)
        .expect("module function");
    assert_eq!(stmt_kinds(&function.body), vec!["expr", "expr"]);
}

#[test]
fn imports_are_recorded() {
    let descriptor = newline_lang(Language::Python);
    let program = parsed_newline(&descriptor, "import os\nimport sys as system\n", "p.py");
    let imports: Vec<(&str, Option<&str>)> = program.modules[0]
        .imports
        .iter()
        .map(|import| (import.path.as_str(), import.alias.as_deref()))
        .collect();
    assert_eq!(imports.len(), 2);
    assert_eq!(imports[1].1, Some("system"));
}

#[test]
fn javascript_import_bindings_preserve_module_and_export_provenance() {
    let descriptor = newline_lang(Language::JavaScript);
    let program = parsed_newline(
        &descriptor,
        "import child from 'child_process'\nimport * as fs from 'fs'\nimport { exec as run, spawn } from 'child_process'\nimport 'bluebird'\n",
        "imports.js",
    );
    let imports = program.modules[0]
        .imports
        .iter()
        .map(|import| (import.path.as_str(), import.alias.as_deref()))
        .collect::<Vec<_>>();
    assert_eq!(
        imports,
        vec![
            ("child_process", Some("child")),
            ("fs", Some("fs")),
            ("child_process.exec", Some("run")),
            ("child_process.spawn", Some("spawn")),
            ("bluebird", None),
        ]
    );
}

fn symbol_text(program: &Program, symbol: SymbolId) -> String {
    program
        .symbols
        .iter()
        .find(|candidate| candidate.id == symbol)
        .map(|candidate| candidate.name.clone())
        .unwrap_or_default()
}
