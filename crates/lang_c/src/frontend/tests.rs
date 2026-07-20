#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

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
