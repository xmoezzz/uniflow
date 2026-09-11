#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    fn function_named<'a>(program: &'a uniflow_hir::Program, name: &str) -> &'a uniflow_hir::Function {
        program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == name => Some(function),
                _ => None,
            })
            .expect("function")
    }

    #[test]
    fn parses_c_switch_cases_default_and_break_structurally() {
        let source = "int f(int x) { switch (x) { case 1: x++; case 2: break; default: return x; } }";
        let program = CParser.parse_file("switch.c", source).expect("parse switch");
        let function = function_named(&program, "f");
        let switch = function
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Switch { clauses, default, .. } => Some((clauses, default)),
                _ => None,
            })
            .expect("structured switch");

        assert_eq!(switch.0.len(), 2);
        assert!(switch.0[0].fallthrough);
        assert!(matches!(switch.0[1].body.stmts.as_slice(), [Stmt::Break { .. }]));
        assert!(!switch.0[1].fallthrough);
        assert!(matches!(
            switch.1.as_ref().map(|block| block.stmts.as_slice()),
            Some([Stmt::Return { .. }])
        ));
        assert!(switch.0.iter().all(|clause| clause.span.start_byte > 0));
    }

    #[test]
    fn parses_single_statement_if_else_control_flow_structurally() {
        let source = "int f(int x, int y) { if (y) break; else return x; }";
        let program = CParser.parse_file("if.c", source).expect("parse if");
        let function = function_named(&program, "f");
        let statement = function.body.stmts.first().expect("if statement");
        let Stmt::If {
            then_block,
            else_block: Some(else_block),
            ..
        } = statement
        else {
            panic!("expected structured if/else, got {statement:?}");
        };
        assert!(matches!(then_block.stmts.as_slice(), [Stmt::Break { .. }]));
        assert!(matches!(else_block.stmts.as_slice(), [Stmt::Return { .. }]));
    }

    #[test]
    fn parses_struct_and_field_flow_starter() {
        let src = r#"
typedef struct Request {
  char *cmd;
} Request;

int main(void) {
  Request req;
  req.cmd = getenv("CMD");
  system(req.cmd);
  return 0;
}
"#;
        let program = CParser.parse_file("demo.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Class(class) if class.name == "Request")));
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn parses_heap_and_pointer_alias_starter() {
        let src = r#"
typedef struct Request {
  char *cmd;
} Request;

int main(void) {
  Request *req = (Request *)malloc(sizeof(Request));
  req->cmd = getenv("CMD");
  char *alias = req->cmd;
  char **pp = &alias;
  system(*pp);
  return 0;
}
"#;
        let program = CParser.parse_file("heap.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn preserves_nonstandard_allocator_and_realloc_as_named_calls() {
        let src = r#"
int run(void) {
  void *p = _aligned_malloc(64, 16);
  p = realloc(p, 128);
  return 0;
}
"#;
        let program = CParser.parse_file("realloc.c", src).expect("parse ok");
        let run = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(func) if func.name == "run" => Some(func),
                _ => None,
            })
            .expect("run function");
        assert!(run.body.stmts.iter().any(|stmt| matches!(
            stmt,
            Stmt::Let {
                init: Some(Expr::Call(call)),
                ..
            } if matches!(&call.target, uniflow_hir::CallTarget::Named(name) if name == "_aligned_malloc")
        )));
        assert!(run.body.stmts.iter().any(|stmt| matches!(
            stmt,
            Stmt::Assign {
                rhs: Expr::Call(call),
                ..
            } if matches!(&call.target, uniflow_hir::CallTarget::Named(name) if name == "realloc")
        )));
    }

    #[test]
    fn propagates_pointer_alias_assignment_starter() {
        let src = r#"
int main(void) {
  char *cmd = getenv("CMD");
  char *p = cmd;
  char **pp = &p;
  system(*pp);
  return 0;
}
"#;
        let program = CParser.parse_file("alias.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn propagates_deref_alias_to_field_path_starter() {
        let src = r#"
typedef struct Request {
  char *cmd;
} Request;

int main(void) {
  Request req;
  req.cmd = getenv("CMD");
  char *alias = req.cmd;
  char **pp = &alias;
  system(*pp);
  return 0;
}
"#;
        let program = CParser.parse_file("field_alias.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn parses_nested_struct_pointer_field_chain_starter() {
        let src = r#"
typedef struct DB { char *cmd; } DB;
typedef struct Request { DB *db; } Request;

int main(void) {
  Request *req = (Request *)malloc(sizeof(Request));
  req->db = (DB *)malloc(sizeof(DB));
  req->db->cmd = getenv("CMD");
  system(req->db->cmd);
  return 0;
}
"#;
        let program = CParser.parse_file("nested.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Class(class) if class.name == "Request")));
    }

    #[test]
    fn infers_alloc_type_from_sizeof_pointee_starter() {
        let src = r#"
typedef struct Request { char *cmd; } Request;

int main(void) {
  Request *req;
  req = malloc(sizeof(*req));
  req->cmd = getenv("CMD");
  system(req->cmd);
  return 0;
}
"#;
        let program = CParser.parse_file("sizeof_ptr.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn parses_pointer_member_read_as_field_read_not_relational_expression() {
        let src = r#"
typedef struct Item { int field; } Item;
int run(Item *p) {
  return p->field;
}
"#;
        let program = CParser.parse_file("pointer_member.c", src).expect("parse ok");
        let run = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(func) if func.name == "run" => Some(func),
                _ => None,
            })
            .expect("run function");
        assert!(matches!(
            run.body.stmts.as_slice(),
            [Stmt::Return {
                value: Some(Expr::FieldRead { field, .. }),
                ..
            }] if field == "field"
        ));
    }

    #[test]
    fn preserves_both_member_accesses_across_addition() {
        let src = r#"
typedef struct Item { int field; } Item;
int run(Item *left, Item *right) {
  return left->field + right[0].field;
}
"#;
        let program = CParser.parse_file("pointer_member_add.c", src).expect("parse ok");
        let run = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(func) if func.name == "run" => Some(func),
                _ => None,
            })
            .expect("run function");
        assert!(matches!(
            run.body.stmts.as_slice(),
            [Stmt::Return {
                value: Some(Expr::Binary {
                    op: BinaryOp::Add,
                    lhs,
                    rhs,
                    ..
                }),
                ..
            }]
                if matches!(lhs.as_ref(), Expr::FieldRead { field, .. } if field == "field")
                    && matches!(
                        rhs.as_ref(),
                        Expr::FieldRead { base, field, .. }
                            if field == "field" && matches!(base.as_ref(), Expr::IndexRead { .. })
                    )
        ));
    }

    #[test]
    fn infers_nested_heap_alloc_and_strdup_alias_starter() {
        let src = r#"
typedef struct Node {
  char *cmd;
  struct Node *next;
} Node;

int main(void) {
  char *cmd = getenv("CMD");
  Node *req = malloc(sizeof(*req));
  req->next = malloc(sizeof(*req->next));
  req->next->cmd = strdup(cmd);
  system(req->next->cmd);
  return 0;
}
"#;
        let program = CParser.parse_file("nested_heap.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn propagates_copy_alias_into_heap_field_starter() {
        let src = r#"
typedef struct DB { char *cmd; } DB;
typedef struct Request { DB *db; } Request;

int main(void) {
  char *cmd = getenv("CMD");
  Request *req = malloc(sizeof(*req));
  req->db = malloc(sizeof(*req->db));
  req->db->cmd = strdup(cmd);
  char *alias = req->db->cmd;
  system(alias);
  return 0;
}
"#;
        let program = CParser.parse_file("heap_field_alias.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn infers_copy_result_alias_from_mempcpy_assignment_starter() {
        let parser = CParser::default();
        let src = r#"
            int system(const char *cmd);
            char *getenv(const char *name);
            void *mempcpy(void *dst, const void *src, unsigned long n);
            void run(void) {
                char buf[64];
                char *cmd = getenv("CMD");
                char *p = mempcpy(buf, cmd, 4);
                system(p);
            }
        "#;
        let program = parser.parse_file("demo.c", src).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("mempcpy"));
        assert!(rendered.contains("system"));
    }

    #[test]
    fn infers_copy_result_alias_from_strcpy_assignment_starter() {
        let parser = CParser::default();
        let src = r#"
            int system(const char *cmd);
            char *getenv(const char *name);
            char *strcpy(char *dst, const char *src);
            void run(void) {
                char buf[64];
                char *cmd = getenv("CMD");
                char *p = strcpy(buf, cmd);
                system(p);
            }
        "#;
        let program = parser.parse_file("demo.c", src).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("strcpy"));
        assert!(rendered.contains("system"));
    }


    #[test]
    fn infers_alias_from_strtok_r_and_stpncpy_starter() {
        let env = CLikeEnv::default();
        let alias = infer_copy_result_alias("stpncpy(dst, src, 8)", &env);
        assert_eq!(alias.as_deref(), Some("dst"));
        let alias2 = infer_copy_result_alias(r#"strtok_r(cmd, ",", &save)"#, &env);
        assert_eq!(alias2.as_deref(), Some("cmd"));
    }


    #[test]
    fn resolves_copy_stmt_and_wild_return_pointer_starter() {
        let parser = CParser::default();
        let src = r#"
            int system(const char *cmd);
            char *getenv(const char *name);
            char *stpcpy(char *dst, const char *src);
            char *rawmemchr(const char *s, int c);
            void run(void) {
                char buf[64];
                char *cmd = getenv("CMD");
                stpcpy(buf, cmd);
                char *p = rawmemchr(buf, 'A');
                system(p);
            }
        "#;
        let program = parser.parse_file("demo.c", src).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("stpcpy"));
        assert!(rendered.contains("rawmemchr"));
    }

    #[test]
    fn infers_copy_result_alias_from_strstr_and_basename_starter() {
        let env = CLikeEnv::default();
        let alias = infer_copy_result_alias(r#"strstr(cmd, "x")"#, &env);
        assert_eq!(alias.as_deref(), Some("cmd"));
        let alias2 = infer_copy_result_alias("basename(path)", &env);
        assert_eq!(alias2.as_deref(), Some("path"));
    }

    #[test]
    fn infers_alias_from_memmem_and_strdupa_starter() {
        let env = CLikeEnv::default();
        let alias = infer_copy_result_alias(r#"memmem(buf, 8, needle, 2)"#, &env);
        assert_eq!(alias.as_deref(), Some("buf"));
        let alias2 = infer_copy_result_alias("strdupa(cmd)", &env);
        assert_eq!(alias2.as_deref(), Some("cmd"));
    }

    #[test]
    fn resolves_bcopy_and_nested_deref_chain_starter() {
        let parser = CParser::default();
        let src = r#"
            int system(const char *cmd);
            char *getenv(const char *name);
            void bcopy(const void *src, void *dst, unsigned long n);
            char *memmem(const void *haystack, unsigned long haystacklen, const void *needle, unsigned long needlelen);
            typedef struct Node { struct Node *next; char *cmd; } Node;
            void run(Node *head) {
                char *src = getenv("CMD");
                bcopy(src, head->next->cmd, 4);
                char *p = memmem(head->next->cmd, 4, "A", 1);
                system(p);
            }
        "#;
        let program = parser.parse_file("demo.c", src).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("memmem"));
        assert!(rendered.contains("head"));
    }


    #[test]
    fn preprocesses_macros_and_conditional_compilation() {
        let src = r#"
#define SOURCE getenv("CMD")
#define CALL(fn, arg) fn(arg)
#define ENABLED 1
int main(void) {
#if ENABLED
  char *cmd = SOURCE;
  CALL(system, cmd);
#else
  system("disabled");
#endif
  return 0;
}
"#;
        let program = CParser.parse_file("macro.c", src).expect("parse ok");
        let rendered = format!("{program:#?}");
        assert!(rendered.contains("getenv"));
        assert!(rendered.contains("system"));
        assert!(!rendered.contains("disabled"));
    }

    #[test]
    fn parses_array_and_pointer_declarators_without_losing_names() {
        let src = r#"
struct Request { const char *cmd; char data[64]; };
void run(const char *cmd, char buffer[64]) {
  char local[32];
  system(cmd);
}
"#;
        let program = CParser.parse_file("decl.c", src).expect("parse ok");
        let rendered = format!("{program:#?}");
        assert!(rendered.contains("cmd"));
        assert!(rendered.contains("buffer"));
        assert!(rendered.contains("local"));
    }

    #[test]
    fn preserves_array_extents_for_fixed_vla_multidimensional_and_unsized_declarators() {
        let program = CParser
            .parse_file(
                "array_extents.c",
                r#"
int run(int n, int p[][3]) {
  int fixed[8];
  int vla[n];
  int matrix[2][3];
  return 0;
}
"#,
            )
            .expect("parse array extent fixture");

        let symbol = |name: &str| {
            program
                .symbols
                .iter()
                .find(|symbol| symbol.name == name)
                .unwrap_or_else(|| panic!("missing symbol {name}"))
        };
        let literal = |extent: &Option<Expr>| match extent {
            Some(Expr::Literal {
                kind: uniflow_hir::LiteralKind::Int(value),
                ..
            }) => Some(*value),
            _ => None,
        };

        assert_eq!(symbol("fixed").array_extents.len(), 1);
        assert_eq!(literal(&symbol("fixed").array_extents[0]), Some(8));

        let n = symbol("n").id;
        assert!(matches!(
            symbol("vla").array_extents.as_slice(),
            [Some(Expr::VarRef { symbol, .. })] if *symbol == n
        ));

        let matrix = &symbol("matrix").array_extents;
        assert_eq!(matrix.len(), 2);
        assert_eq!(literal(&matrix[0]), Some(2));
        assert_eq!(literal(&matrix[1]), Some(3));

        let parameter = &symbol("p").array_extents;
        assert_eq!(parameter.len(), 2);
        assert!(parameter[0].is_none());
        assert_eq!(literal(&parameter[1]), Some(3));
    }

    #[test]
    fn parses_nested_function_pointer_parameter_lists() {
        let src = r#"
int apply(int (*callback)(const char *), const char *value) {
  return callback(value);
}
"#;
        let program = CParser.parse_file("callback.c", src).expect("parse ok");
        assert!(program.modules[0].items.iter().any(
            |item| matches!(item, Item::Function(function) if function.name == "apply")
        ));
    }

}

#[test]
fn preprocesses_stringification_token_pasting_and_variadic_macros() {
    let source = r#"
#define DECLARE(name) int generated_##name = 1
#define STRINGIFY(value) #value
#define CALL(fn, ...) fn(__VA_ARGS__)
DECLARE(counter);
const char *label = STRINGIFY(counter);
void run(void) { CALL(system, getenv("CMD")); }
"#;
    let out = preprocess_c_source(source);
    assert!(out.contains("generated_counter"), "{out}");
    assert!(out.contains("\"counter\""), "{out}");
    assert!(out.contains("system(getenv(\"CMD\"))"), "{out}");
}

#[test]
fn recognizes_function_pointer_typedefs_and_union_fields() {
    let source = r#"
typedef void (*Callback)(const char *);
typedef union Payload {
    const char *text;
    void *raw;
} Payload;
void sink(const char *value) { system(value); }
void run(Callback cb, Payload *payload) {
    Callback local = sink;
    cb(payload->text);
    local(payload->text);
}
"#;
    let program = CParser.parse_file("callback.c", source).expect("parse C");
    let rendered = format!("{program:#?}");
    assert!(rendered.contains("Payload"));
    assert!(rendered.contains("Dynamic"), "{rendered}");
    assert!(rendered.contains("sink"));
}

#[test]
fn normalizes_enums_compound_literals_and_designated_initializers() {
    let source = r#"
typedef enum Mode { MODE_A = 1, MODE_B = 2 } Mode;
struct Pair { int x; int y; };
void run() {
    struct Pair p = (struct Pair){ .x = 1, .y = 2 };
    consume(p.x);
}
"#;
    let normalized = normalize_c_surface(source);
    assert!(normalized.contains("typedef int Mode"));
    assert!(normalized.contains("__compound_struct_Pair(1, 2)"));
    let program = CParser.parse_file("aggregate.c", source).expect("parse C");
    let rendered = format!("{program:#?}");
    assert!(rendered.contains("__compound_struct_Pair"));
    assert!(rendered.contains("consume"));
}
