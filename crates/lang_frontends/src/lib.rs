//! Descriptor-driven pure-Rust frontends for UniFlow languages that do not use
//! one of the older specialized parsers. Every language owns a descriptor; the
//! shared parser only supplies recovery, HIR construction and common grammar.

use anyhow::{bail, Result};
use regex::Regex;
use uniflow_hir::{
    CallExpr, CallTarget, Class, CppValueSemantics, Expr, Import, Item, LValue, Language,
    LiteralKind, Param, ParamKind, Program, ProgramMerger, Span, Stmt, SymbolKind,
};
use uniflow_parser_core::{
    parse_program_with, BlockStyle, ExprOps, InterpStyle, Keywords, LangDescriptor, LangHooks,
    LexerSpec, Pg, SourceParser, TokKind,
};

#[derive(Clone, Debug)]
pub struct DescriptorParser {
    language: Language,
}

impl DescriptorParser {
    pub fn new(language: Language) -> Result<Self> {
        if descriptor(language.clone()).is_none() {
            bail!("no descriptor-driven frontend for {}", language.as_str());
        }
        Ok(Self { language })
    }
}

impl SourceParser for DescriptorParser {
    fn language(&self) -> Language {
        self.language.clone()
    }

    fn parse_file(&self, path: &str, source: &str) -> Result<Program> {
        parse_file(self.language.clone(), path, source)
    }
}

pub fn parse_file(language: Language, path: &str, source: &str) -> Result<Program> {
    let descriptor = descriptor(language.clone())
        .ok_or_else(|| anyhow::anyhow!("unsupported descriptor language: {}", language.as_str()))?;
    let prepared = match language {
        Language::Jsp => embedded_code_view(source, "<%", "%>", true),
        Language::Php => php_code_view(source),
        _ => source.to_string(),
    };
    let mut hooks = FrontendHooks {
        language: language.clone(),
    };
    let (mut program, _recoverable_errors) =
        parse_program_with(&descriptor, path, &prepared, &mut hooks)?;
    if language == Language::JavaScript {
        add_commonjs_imports(&mut program, source);
    }
    Ok(program)
}

fn add_commonjs_imports(program: &mut Program, source: &str) {
    let Some(module) = program.modules.first_mut() else {
        return;
    };
    let binding = Regex::new(
        r#"(?m)\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)(?:\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*))?"#,
    )
    .expect("valid CommonJS binding regex");
    let destructured = Regex::new(
        r#"(?m)\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"#,
    )
    .expect("valid CommonJS destructuring regex");
    let mut add =
        |path: String, alias: String| {
            if !module.imports.iter().any(|import| {
                import.path == path && import.alias.as_deref() == Some(alias.as_str())
            }) {
                module.imports.push(Import {
                    path,
                    alias: Some(alias),
                    span: Span::default(),
                });
            }
        };
    for captures in binding.captures_iter(source) {
        let package = captures[2].to_string();
        let path = captures
            .get(3)
            .map(|member| format!("{package}.{}", member.as_str()))
            .unwrap_or(package);
        add(path, captures[1].to_string());
    }
    for captures in destructured.captures_iter(source) {
        let package = captures[2].trim();
        for entry in captures[1].split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (imported, local) = entry
                .split_once(':')
                .map(|(imported, local)| (imported.trim(), local.trim()))
                .unwrap_or((entry, entry));
            if imported
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
                && local
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
            {
                add(format!("{package}.{imported}"), local.to_string());
            }
        }
    }
}

pub fn parse_project_sources(language: Language, entries: &[(String, String)]) -> Result<Program> {
    if entries.is_empty() {
        bail!("no supported source files found");
    }
    let mut project = ProgramMerger::new(language.clone());
    for (path, source) in entries {
        project.merge(parse_file(language.clone(), path, source)?);
    }
    Ok(project.finish())
}

struct FrontendHooks {
    language: Language,
}

impl LangHooks for FrontendHooks {
    fn item(&mut self, parser: &mut Pg<'_>) -> Result<bool> {
        if !matches!(self.language, Language::ObjC | Language::ObjCpp) {
            return Ok(false);
        }
        match parser.cur.text() {
            "@interface" | "@protocol" => {
                while !parser.cur.eof() && parser.cur.text() != "@end" {
                    parser.cur.advance();
                }
                if parser.cur.text() == "@end" {
                    parser.cur.advance();
                }
                Ok(true)
            }
            "@implementation" => {
                self.objective_c_implementation(parser)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn statement(&mut self, parser: &mut Pg<'_>) -> Result<Option<Stmt>> {
        if self.language == Language::Go && (parser.cur.at_kw("go") || parser.cur.at_kw("defer")) {
            let start = parser.cur.pos;
            parser.cur.advance();
            parser.cur.skip_newlines();
            let expr = parser.expression()?;
            return Ok(Some(Stmt::Expr {
                id: parser.b.alloc_stmt_id(),
                expr,
                span: parser.cur.span_from(start),
            }));
        }
        if self.language != Language::Sql {
            return Ok(None);
        }
        let command = parser.cur.current().text.to_ascii_lowercase();
        if !matches!(
            command.as_str(),
            "select" | "insert" | "update" | "delete" | "merge" | "call" | "exec" | "execute"
        ) {
            return Ok(None);
        }
        let start = parser.cur.pos;
        parser.cur.advance();
        let mut args = Vec::new();
        let mut first_identifier = None;
        while !parser.cur.eof() && !parser.cur.at(";") && !parser.cur.at_newline() {
            let token = parser.cur.current().clone();
            match token.kind {
                TokKind::Ident => {
                    parser.cur.advance();
                    let symbol = parser.resolve_or_create(token.bare_name(), SymbolKind::Local);
                    first_identifier.get_or_insert(symbol);
                    args.push(Expr::VarRef {
                        id: parser.b.alloc_expr_id(),
                        symbol,
                        span: parser.cur.span_of(&token),
                    });
                }
                TokKind::StringLit => {
                    parser.cur.advance();
                    args.push(Expr::Literal {
                        id: parser.b.alloc_expr_id(),
                        kind: LiteralKind::String(token.string_value()),
                        span: parser.cur.span_of(&token),
                    });
                }
                TokKind::IntLit => {
                    parser.cur.advance();
                    args.push(Expr::Literal {
                        id: parser.b.alloc_expr_id(),
                        kind: LiteralKind::Int(token.text.parse().unwrap_or_default()),
                        span: parser.cur.span_of(&token),
                    });
                }
                _ => {
                    parser.cur.advance();
                }
            }
        }
        let span = parser.cur.span_from(start);
        let expr = Expr::Call(CallExpr {
            id: parser.b.alloc_expr_id(),
            target: CallTarget::Named(format!("sql.{command}")),
            receiver: None,
            qualifier_is_explicit: false,
            args,
            arg_names: Vec::new(),
            span,
        });
        if command == "select" {
            if let Some(symbol) = first_identifier {
                return Ok(Some(Stmt::Assign {
                    id: parser.b.alloc_stmt_id(),
                    lhs: LValue::Var(symbol),
                    rhs: expr,
                    span,
                }));
            }
        }
        Ok(Some(Stmt::Expr {
            id: parser.b.alloc_stmt_id(),
            expr,
            span,
        }))
    }
}

impl FrontendHooks {
    fn objective_c_implementation(&mut self, parser: &mut Pg<'_>) -> Result<()> {
        let start = parser.cur.pos;
        parser.cur.advance();
        parser.cur.skip_newlines();
        let class_name = parser.cur.name();
        if class_name.is_empty() {
            parser
                .cur
                .error("expected Objective-C implementation class name");
            return Ok(());
        }
        parser.current_class = Some(class_name.clone());
        let class_symbol = parser.define(&class_name, SymbolKind::Class);
        let mut methods = Vec::new();
        while !parser.cur.eof() && parser.cur.text() != "@end" {
            parser.cur.skip_newlines();
            if parser.cur.text() == "@end" || parser.cur.eof() {
                break;
            }
            if parser.cur.at("-") || parser.cur.at("+") {
                if let Some(method) = self.objective_c_method(parser, &class_name)? {
                    methods.push(method);
                }
            } else {
                parser.cur.recover_to_statement();
                if parser.cur.at_end_of_stmt() {
                    parser.cur.advance();
                }
            }
        }
        if parser.cur.text() == "@end" {
            parser.cur.advance();
        }
        let span = parser.cur.span_from(start);
        parser.b.push_item(Item::Class(Class {
            name: class_name,
            symbol: Some(class_symbol),
            bases: Vec::new(),
            fields: Vec::new(),
            methods,
            span,
        }));
        parser.current_class = None;
        Ok(())
    }

    fn objective_c_method(
        &mut self,
        parser: &mut Pg<'_>,
        class_name: &str,
    ) -> Result<Option<uniflow_hir::Function>> {
        let start = parser.cur.pos;
        parser.cur.advance(); // `-` instance method or `+` class method.
        parser.cur.skip_newlines();
        let return_type = if parser.cur.eat("(") {
            let ty = parser.header_until(")");
            parser.cur.expect(")");
            Some(ty)
        } else {
            None
        };
        parser.cur.skip_newlines();
        if !parser.cur.at_name() {
            parser.cur.error("expected Objective-C method selector");
            parser.cur.recover_to_statement();
            return Ok(None);
        }

        let saved_scope = parser.sc.save();
        parser.sc.push();
        let receiver_symbol = parser.define("self", SymbolKind::Param);
        let receiver = Param {
            name: "self".to_string(),
            symbol: receiver_symbol,
            ty: Some(parser.b.ensure_type(class_name)),
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            cpp: CppValueSemantics::default(),
            span: parser.cur.span_from(start),
        };
        let mut selector = String::new();
        let mut params = Vec::new();
        loop {
            if !parser.cur.at_name() {
                break;
            }
            selector.push_str(&parser.cur.name());
            if !parser.cur.eat(":") {
                break;
            }
            selector.push(':');
            parser.cur.skip_newlines();
            let param_type = if parser.cur.eat("(") {
                let ty = parser.header_until(")");
                parser.cur.expect(")");
                Some(ty)
            } else {
                None
            };
            parser.cur.skip_newlines();
            let param_start = parser.cur.pos;
            let param_name = parser.cur.name_with_sigil();
            if param_name.is_empty() {
                parser
                    .cur
                    .error("expected Objective-C method parameter name");
                break;
            }
            let symbol = parser.define(&param_name, SymbolKind::Param);
            params.push(Param {
                name: param_name,
                symbol,
                ty: param_type.map(|ty| parser.b.ensure_type(&ty)),
                kind: ParamKind::Positional,
                has_default: false,
                keyword_only: false,
                cpp: CppValueSemantics::default(),
                span: parser.cur.span_from(param_start),
            });
            parser.cur.skip_newlines();
            if parser.cur.at("{") || parser.cur.at(";") {
                break;
            }
        }

        let saved_nested = parser.nested;
        parser.nested += 1;
        let stmts = if parser.cur.at("{") {
            parser.cur.advance();
            let stmts = parser.statements(self, &["}"])?;
            parser.cur.skip_newlines();
            parser.cur.expect("}");
            stmts
        } else {
            parser.cur.eat(";");
            Vec::new()
        };
        parser.nested = saved_nested;
        let mut function = parser.make_function(
            start,
            &selector,
            params,
            return_type,
            stmts,
            class_name.to_string(),
        );
        function.is_method = true;
        function.receiver = Some(receiver);
        parser.sc.restore(saved_scope);
        Ok(Some(function))
    }
}

const C_FAMILY_KEYWORDS: &[&str] = &[
    "abstract",
    "async",
    "await",
    "bool",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "false",
    "final",
    "finally",
    "float",
    "for",
    "foreach",
    "if",
    "implements",
    "import",
    "int",
    "interface",
    "internal",
    "long",
    "namespace",
    "new",
    "null",
    "override",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "sealed",
    "short",
    "static",
    "string",
    "struct",
    "switch",
    "this",
    "throw",
    "throws",
    "true",
    "try",
    "using",
    "var",
    "virtual",
    "void",
    "volatile",
    "while",
];

const SCRIPT_KEYWORDS: &[&str] = &[
    "and", "as", "begin", "break", "case", "catch", "class", "const", "continue", "def", "do",
    "done", "elif", "else", "elsif", "end", "ensure", "false", "fi", "finally", "for", "foreach",
    "from", "function", "if", "import", "in", "include", "let", "load", "local", "my", "nil",
    "not", "null", "or", "raise", "require", "rescue", "return", "source", "then", "throw", "true",
    "try", "unless", "until", "use", "var", "while",
];

const MODERN_KEYWORDS: &[&str] = &[
    "as",
    "async",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "data",
    "defer",
    "do",
    "else",
    "enum",
    "extension",
    "fallthrough",
    "false",
    "final",
    "fn",
    "for",
    "func",
    "fun",
    "go",
    "if",
    "impl",
    "import",
    "in",
    "interface",
    "internal",
    "let",
    "loop",
    "match",
    "mut",
    "new",
    "nil",
    "null",
    "open",
    "package",
    "private",
    "protocol",
    "public",
    "range",
    "return",
    "select",
    "static",
    "struct",
    "super",
    "switch",
    "this",
    "throw",
    "trait",
    "true",
    "try",
    "type",
    "use",
    "val",
    "var",
    "when",
    "where",
    "while",
];

const JAVASCRIPT_KEYWORDS: &[&str] = &[
    "as",
    "async",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "from",
    "function",
    "get",
    "if",
    "import",
    "in",
    "instanceof",
    "let",
    "new",
    "null",
    "of",
    "return",
    "set",
    "static",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "yield",
];

const SQL_KEYWORDS: &[&str] = &[
    "all", "and", "as", "asc", "between", "by", "call", "case", "create", "delete", "desc",
    "distinct", "drop", "else", "end", "exec", "execute", "exists", "false", "from", "full",
    "group", "having", "in", "inner", "insert", "into", "is", "join", "left", "like", "limit",
    "merge", "not", "null", "offset", "on", "or", "order", "outer", "right", "select", "set",
    "then", "true", "union", "update", "values", "when", "where", "with",
];

fn c_family(language: Language) -> LangDescriptor {
    LangDescriptor {
        lexer: LexerSpec {
            keywords: C_FAMILY_KEYWORDS,
            interp: if language == Language::CSharp {
                InterpStyle::Curly
            } else {
                InterpStyle::None
            },
            interp_prefixes: if language == Language::CSharp {
                vec!["$"]
            } else {
                Vec::new()
            },
            ..LexerSpec::default()
        },
        type_before_name: true,
        named_arguments: language == Language::CSharp,
        member_ops: &["?.", "::", "->"],
        decl_introducers: &["var", "const"],
        ..LangDescriptor::new(language)
    }
}

fn newline_braces(language: Language, function_kw: &'static [&'static str]) -> LangDescriptor {
    LangDescriptor {
        lexer: LexerSpec {
            line_comments: vec!["//"],
            block_comments: vec![("/*", "*/")],
            nest_block_comments: language == Language::Rust || language == Language::Swift,
            significant_newlines: true,
            keywords: MODERN_KEYWORDS,
            interp: match language {
                Language::Kotlin => InterpStyle::Dollar,
                Language::Swift => InterpStyle::BackslashParen,
                Language::JavaScript => InterpStyle::DollarBrace,
                _ => InterpStyle::None,
            },
            interpolation_quotes: match language {
                Language::Kotlin | Language::Swift => vec!['"'],
                Language::JavaScript => vec!['`'],
                _ => Vec::new(),
            },
            triple_quotes: if matches!(language, Language::Kotlin | Language::Swift) {
                vec!["\"\"\""]
            } else {
                Vec::new()
            },
            string_quotes: if language == Language::JavaScript {
                vec!['"', '\'', '`']
            } else {
                LexerSpec::default().string_quotes
            },
            dollar_idents: language == Language::JavaScript,
            ..LexerSpec::default()
        },
        kw: Keywords {
            function_kw,
            class_kw: &["class", "struct", "interface", "enum", "protocol", "trait"],
            switch_kw: &["switch", "when", "match", "select"],
            ..Keywords::default()
        },
        block_style: BlockStyle::Braces,
        newline_terminated: true,
        decl_introducers: &["let", "var", "val", "const"],
        type_annotation: Some(":"),
        type_before_name: false,
        member_ops: &["?.", "::"],
        optional_chaining: true,
        switch_falls_through: matches!(language, Language::Go | Language::JavaScript),
        ..LangDescriptor::new(language)
    }
}

fn script(language: Language) -> LangDescriptor {
    let (line_comments, interp) = match language {
        Language::Php => (vec!["//", "#"], InterpStyle::Dollar),
        Language::Ruby => (vec!["#"], InterpStyle::HashBrace),
        Language::Shell => (vec!["#"], InterpStyle::Dollar),
        _ => (vec!["//"], InterpStyle::None),
    };
    LangDescriptor {
        lexer: LexerSpec {
            line_comments,
            block_comments: if language == Language::Php {
                vec![("/*", "*/")]
            } else {
                vec![]
            },
            keywords: SCRIPT_KEYWORDS,
            significant_newlines: language != Language::Php,
            dollar_idents: matches!(
                language,
                Language::Php | Language::Shell | Language::JavaScript
            ),
            at_idents: language == Language::Ruby,
            colon_idents: language == Language::Ruby,
            here_docs: true,
            line_continuation: language == Language::Shell,
            interp,
            interpolation_quotes: vec!['"'],
            ..LexerSpec::default()
        },
        kw: Keywords {
            else_if: &["elsif", "elif", "elseif"],
            unless: (language == Language::Ruby).then_some("unless"),
            until: (language == Language::Ruby).then_some("until"),
            function_kw: if language == Language::Ruby {
                &["def"]
            } else {
                &["function"]
            },
            try_kw: if language == Language::Ruby {
                Some("begin")
            } else {
                Some("try")
            },
            catch_kw: if language == Language::Ruby {
                &["rescue"]
            } else {
                &["catch"]
            },
            finally_kw: if language == Language::Ruby {
                &["ensure"]
            } else {
                &["finally"]
            },
            throw_kw: &["throw", "raise"],
            end_kw: &["end", "fi", "done"],
            ..Keywords::default()
        },
        ops: ExprOps {
            word_logic: language == Language::Ruby,
            concat_op: (language == Language::Php).then_some("."),
            range_ops: if language == Language::Ruby {
                &["..", "..."]
            } else {
                &[]
            },
            ..ExprOps::default()
        },
        block_style: if language == Language::Php {
            BlockStyle::Braces
        } else {
            BlockStyle::EndKeyword
        },
        newline_terminated: language != Language::Php,
        named_arguments: language == Language::Ruby,
        decl_introducers: if language == Language::Shell {
            &["local"]
        } else {
            &["var", "my", "const"]
        },
        self_names: if language == Language::Php {
            &["$this"]
        } else {
            &["self"]
        },
        member_ops: if language == Language::Php {
            &["->", "?->", "::"]
        } else {
            &["&.", "::"]
        },
        implicit_call_parens: matches!(language, Language::Ruby | Language::Shell),
        trailing_if: language == Language::Ruby,
        trailing_while: language == Language::Ruby,
        ..LangDescriptor::new(language)
    }
}

pub fn descriptor(language: Language) -> Option<LangDescriptor> {
    Some(match language {
        Language::CSharp => c_family(language),
        Language::ObjC | Language::ObjCpp => {
            let mut descriptor = c_family(language);
            descriptor.lexer.at_idents = true;
            descriptor
        }
        Language::Kotlin => newline_braces(language, &["fun"]),
        Language::Swift => newline_braces(language, &["func"]),
        Language::Go => {
            let mut descriptor = newline_braces(language, &["func"]);
            descriptor.walrus = Some(":=");
            descriptor.receiver_in_parens = true;
            descriptor.type_annotation = None;
            descriptor
        }
        Language::JavaScript => {
            let mut descriptor = newline_braces(language, &["function"]);
            descriptor.lexer.keywords = JAVASCRIPT_KEYWORDS;
            descriptor.lexer.regex_literals = true;
            descriptor
        }
        Language::Jsp => {
            let mut descriptor = c_family(language);
            descriptor.lexer.significant_newlines = true;
            descriptor.newline_terminated = true;
            descriptor
        }
        Language::Sql => LangDescriptor {
            lexer: LexerSpec {
                line_comments: vec!["--"],
                block_comments: vec![("/*", "*/")],
                keywords: SQL_KEYWORDS,
                significant_newlines: true,
                case_insensitive_keywords: true,
                line_comment_needs_break: true,
                backtick_idents: true,
                ..LexerSpec::default()
            },
            ops: ExprOps {
                word_logic: true,
                relational_keywords: &["in", "is", "between", "like"],
                ..ExprOps::default()
            },
            block_style: BlockStyle::None,
            newline_terminated: true,
            c_style_for: false,
            ..LangDescriptor::new(language)
        },
        Language::Php | Language::Ruby | Language::Shell => script(language),
        Language::Rust => {
            let mut descriptor = newline_braces(language, &["fn"]);
            // Rust closures are `|args| ...` / `move |args| ...`; they never
            // use the generic `(...) => ...` syntax.  Keeping `=>` enabled here
            // forces the expression parser to scan every parenthesized Rust
            // expression looking for an arrow that cannot form a closure.
            descriptor.ops.lambda_arrows = &[];
            descriptor
        }
        _ => return None,
    })
}

/// Replace host-language text with spaces while preserving newlines and byte
/// offsets; only embedded code remains visible to the source parser.
fn embedded_code_view(source: &str, open: &str, close: &str, jsp: bool) -> String {
    let mut output = source
        .bytes()
        .map(|byte| {
            if byte == b'\n' || byte == b'\r' {
                byte
            } else {
                b' '
            }
        })
        .collect::<Vec<_>>();
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let Some(relative_start) = source[cursor..].find(open) else {
            break;
        };
        let start = cursor + relative_start;
        let code_start = start + open.len();
        let Some(relative_end) = source[code_start..].find(close) else {
            break;
        };
        let end = code_start + relative_end;
        let directive = jsp && bytes.get(code_start) == Some(&b'@');
        if !directive {
            let mut copy_start = code_start;
            if jsp && matches!(bytes.get(copy_start), Some(b'!' | b'=')) {
                copy_start += 1;
            }
            output[copy_start..end].copy_from_slice(&bytes[copy_start..end]);
        }
        cursor = end + close.len();
    }
    String::from_utf8(output).unwrap_or_else(|_| source.to_string())
}

fn php_code_view(source: &str) -> String {
    if !source.contains("<?") {
        return source.to_string();
    }
    let bytes = source.as_bytes();
    let mut output = bytes
        .iter()
        .map(|byte| {
            if matches!(byte, b'\n' | b'\r') {
                *byte
            } else {
                b' '
            }
        })
        .collect::<Vec<_>>();
    let mut cursor = 0usize;
    while cursor < source.len() {
        let Some(relative_start) = source[cursor..].find("<?") else {
            break;
        };
        let start = cursor + relative_start;
        let tail = &source[start..];
        if tail
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("<?xml"))
        {
            cursor = start + 2;
            continue;
        }
        let code_start = if tail
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("<?php"))
        {
            start + 5
        } else if tail.starts_with("<?=") {
            start + 3
        } else {
            start + 2
        };
        let Some(relative_end) = source[code_start..].find("?>") else {
            output[code_start..].copy_from_slice(&bytes[code_start..]);
            break;
        };
        let end = code_start + relative_end;
        output[code_start..end].copy_from_slice(&bytes[code_start..end]);
        cursor = end + 2;
    }
    String::from_utf8(output).unwrap_or_else(|_| source.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_function(program: &Program) -> bool {
        program
            .modules
            .iter()
            .flat_map(|module| &module.items)
            .any(|item| {
                matches!(item, Item::Function(_))
                    || matches!(item, Item::Class(class) if !class.methods.is_empty())
            })
    }

    #[test]
    fn parses_every_descriptor_language() {
        let cases = [
            (
                Language::CSharp,
                "class C { public string Run(string x) { return x; } }",
                "a.cs",
            ),
            (Language::ObjC, "char *run(char *x) { return x; }", "a.m"),
            (Language::ObjCpp, "char *run(char *x) { return x; }", "a.mm"),
            (
                Language::Kotlin,
                "fun run(x) { val y = x\n return y\n }",
                "a.kt",
            ),
            (
                Language::Swift,
                "func run(x) { let y = x\n return y\n }",
                "a.swift",
            ),
            (Language::Go, "func run(x) { y := x\n return y\n }", "a.go"),
            (
                Language::JavaScript,
                "function run(x) { const y = x; return y; }",
                "a.js",
            ),
            (
                Language::Jsp,
                "<html><% int run(int x) { return x; } %></html>",
                "a.jsp",
            ),
            (
                Language::Sql,
                "SELECT password FROM users WHERE id = user_id;",
                "a.sql",
            ),
            (
                Language::Php,
                "<?php function run($x) { $y = $x; return $y; } ?>",
                "a.php",
            ),
            (
                Language::Ruby,
                "def run(x)\n y = x\n return y\nend\n",
                "a.rb",
            ),
            (Language::Rust, "fn run(x) { let y = x; return y; }", "a.rs"),
            (
                Language::Shell,
                "function run() { local y=$x\n echo $y\n }",
                "a.sh",
            ),
        ];
        for (language, source, path) in cases {
            let program = parse_file(language.clone(), path, source).expect(language.as_str());
            assert_eq!(program.language, language, "{path}");
            assert!(
                has_function(&program),
                "no function carrier for {path}: {program:#?}"
            );
        }
    }

    #[test]
    fn rust_descriptor_skips_arrow_lambda_probes_and_keeps_pipe_closures() {
        let descriptor = descriptor(Language::Rust).expect("Rust descriptor");
        assert!(
            descriptor.ops.lambda_arrows.is_empty(),
            "Rust must not scan parenthesized expressions for arrow lambdas"
        );

        // Grow the lexical scope with many ordinary expressions before a real
        // closure.  Lambda probing must stay cheap as that scope grows, while
        // the eventual pipe closure must still see and capture the outer value.
        let mut source = String::from("fn run(prefix) { ");
        for index in 0..512 {
            source.push_str(&format!("let v{index} = prefix + {index}; "));
        }
        source.push_str("let value = (prefix + 1); let cb = |x| prefix + x; return cb; }");
        let program = parse_file(Language::Rust, "lambda_probe.rs", &source)
            .expect("Rust source should parse");
        let Some(Expr::Lambda { params, captures, .. }) = first_lambda(&program) else {
            panic!("expected Rust pipe closure: {program:#?}");
        };
        assert_eq!(params.len(), 1);
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].name, "prefix");
    }

    #[test]
    fn sql_statement_keeps_identifier_arguments() {
        let program = parse_file(Language::Sql, "query.sql", "SELECT secret FROM accounts;")
            .expect("sql parse");
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("top-level function");
        let Stmt::Assign {
            rhs: Expr::Call(call),
            ..
        } = &function.body.stmts[0]
        else {
            panic!("expected SQL projection assignment");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "sql.select"));
        assert!(call.args.len() >= 2);
    }

    #[test]
    fn jsp_host_markup_does_not_become_code() {
        let program = parse_file(
            Language::Jsp,
            "view.jsp",
            "<div>not_code()</div>\n<% int render(int value) { return value; } %>",
        )
        .expect("jsp parse");
        let names = program.modules[0]
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Function(function) => Some(function.name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(names.contains(&"render"));
        assert!(!names.contains(&"not_code"));
    }

    #[test]
    fn jsp_expression_tag_is_parsed_without_marker_token() {
        let program = parse_file(
            Language::Jsp,
            "value.jsp",
            "<div>host_call()</div><%= sink(value) %>",
        )
        .expect("JSP expression tag should parse");
        let top_level = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function)
                    if function.name == uniflow_parser_core::TOP_LEVEL_FUNCTION =>
                {
                    Some(function)
                }
                _ => None,
            })
            .expect("top-level JSP carrier");
        let debug = format!("{top_level:#?}");
        assert!(debug.contains("sink"));
        assert!(!debug.contains("host_call"));
    }

    #[test]
    fn php_short_tags_keep_code_and_ignore_xml_or_host_text() {
        let program = parse_file(
            Language::Php,
            "view.php",
            "<?xml version=\"1.0\"?><div>host_call()</div><? echo sink($value); ?><?= $value ?>",
        )
        .expect("PHP short tags should parse");
        let top_level = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function)
                    if function.name == uniflow_parser_core::TOP_LEVEL_FUNCTION =>
                {
                    Some(function)
                }
                _ => None,
            })
            .expect("top-level PHP carrier");
        let debug = format!("{top_level:#?}");
        assert!(debug.contains("sink"));
        assert!(!debug.contains("host_call"));
        assert!(!debug.contains("xml"));
    }

    #[test]
    fn php_superglobal_index_is_backed_by_a_source_call() {
        let program = parse_file(
            Language::Php,
            "request.php",
            "<?php function run() { system($_GET[\"cmd\"]); } ?>",
        )
        .expect("PHP superglobal should parse");
        let rendered = format!("{:#?}", program.modules);
        assert!(rendered.contains("php.superglobal.GET"), "{rendered}");
        assert!(rendered.contains("IndexRead"), "{rendered}");
        assert!(rendered.contains("system"), "{rendered}");
    }

    #[test]
    fn ruby_bare_parameterless_definition_is_not_top_level_code() {
        let program = parse_file(Language::Ruby, "worker.rb", "def run\n return 1\nend\n")
            .expect("ruby parse");
        let names = program.modules[0]
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Function(function) => Some(function.name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(names.contains(&"run"), "functions: {names:?}");
        assert!(!names.contains(&uniflow_parser_core::TOP_LEVEL_FUNCTION));
    }

    #[test]
    fn objective_c_message_send_preserves_selector_and_arguments() {
        let program = parse_file(
            Language::ObjC,
            "request.m",
            "id run(id request, id key) { return [request objectForKey:key]; }",
        )
        .expect("Objective-C source should parse");
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("run function");
        let Stmt::Return {
            value: Some(Expr::Call(call)),
            ..
        } = &function.body.stmts[0]
        else {
            panic!("expected returned Objective-C message call");
        };
        assert!(matches!(
            &call.target,
            CallTarget::Named(name) if name == "objectForKey:"
        ));
        assert!(call.receiver.is_some());
        assert_eq!(call.args.len(), 1);
    }

    #[test]
    fn objective_c_implementation_builds_typed_method_hir() {
        let program = parse_file(
            Language::ObjC,
            "handler.m",
            r#"
@implementation Handler
- (void)run:(id)request database:(id)database {
    id value = [request objectForKey:@"key"];
    [database executeQuery:value];
}
@end
"#,
        )
        .expect("Objective-C implementation should parse");
        let class = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) => Some(class),
                _ => None,
            })
            .expect("Handler class");
        assert_eq!(class.name, "Handler");
        assert_eq!(class.methods.len(), 1);
        let method = &class.methods[0];
        assert_eq!(method.name, "Handler.run:database:");
        assert!(method.receiver.is_some());
        assert_eq!(method.params.len(), 2);
        assert_eq!(method.body.stmts.len(), 2);
    }

    #[test]
    fn go_launch_and_defer_keep_call_expressions() {
        let program = parse_file(
            Language::Go,
            "worker.go",
            "func run(value string) {\n go send(value)\n defer close(value)\n }",
        )
        .expect("Go source should parse");
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("run function");
        let calls = function
            .body
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                Stmt::Expr {
                    expr: Expr::Call(call),
                    ..
                } => Some(call),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2);
        assert!(matches!(&calls[0].target, CallTarget::Named(name) if name == "send"));
        assert!(matches!(&calls[1].target, CallTarget::Named(name) if name == "close"));
    }

    #[test]
    fn rust_macro_invocation_is_a_call() {
        let program = parse_file(
            Language::Rust,
            "query.rs",
            "fn run(value) { sqlx_query!(value); }",
        )
        .expect("Rust source should parse");
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("run function");
        let Stmt::Expr {
            expr: Expr::Call(call),
            ..
        } = &function.body.stmts[0]
        else {
            panic!("expected Rust macro call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "sqlx_query!"));
        assert_eq!(call.args.len(), 1);
    }

    #[test]
    fn rust_turbofish_constructor_keeps_a_concrete_callee() {
        let program = parse_file(
            Language::Rust,
            "turbofish.rs",
            "fn run() { let map: HashMap<usize, String> = HashMap::<usize, String>::new(); }",
        )
        .expect("Rust source should parse");
        let rendered = format!("{program:#?}");
        assert!(rendered.contains("HashMap"));
        assert!(
            !rendered.contains("Unknown"),
            "turbofish must not become an unknown dynamic callee: {rendered}"
        );
    }

    #[test]
    fn rust_let_keeps_call_initializer() {
        let program = parse_file(
            Language::Rust,
            "source.rs",
            "fn run(dummy) { let value = var(\"X\"); }",
        )
        .expect("Rust source should parse");
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("run function");
        let Stmt::Let {
            init: Some(Expr::Call(call)),
            ..
        } = &function.body.stmts[0]
        else {
            panic!("expected Rust let with call initializer: {function:#?}");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "var"));
    }

    #[test]
    fn shell_newlines_separate_implicit_calls_inside_braces() {
        let program = parse_file(
            Language::Shell,
            "worker.sh",
            "function run() { local x\n read x\n eval $x\n }",
        )
        .expect("Shell source should parse");
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("run function");
        let call_names = function
            .body
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                Stmt::Expr {
                    expr: Expr::Call(call),
                    ..
                } => match &call.target {
                    CallTarget::Named(name) => Some(name.as_str()),
                    _ => None,
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(call_names, vec!["read", "eval"]);
    }

    #[test]
    fn shell_command_substitutions_preserve_nested_command_dependencies() {
        for substitution in ["$(taint_source dummy)", "`taint_source dummy`"] {
            let source = format!("function run() {{ local x\n x={substitution}\n sink $x\n }}");
            let program = parse_file(Language::Shell, "worker.sh", &source)
                .expect("Shell command substitution should parse");
            let function = program.modules[0]
                .items
                .iter()
                .find_map(|item| match item {
                    Item::Function(function) => Some(function),
                    _ => None,
                })
                .expect("run function");
            let assignment = function.body.stmts.iter().find_map(|stmt| match stmt {
                Stmt::Assign {
                    rhs: Expr::Call(call),
                    ..
                } if matches!(
                    &call.target,
                    CallTarget::Named(name) if name == "shell.command_substitution"
                ) =>
                {
                    Some(call)
                }
                _ => None,
            });
            let call = assignment.unwrap_or_else(|| {
                panic!("expected command-substitution call for {substitution}: {function:#?}")
            });
            assert!(matches!(
                call.args.first(),
                Some(Expr::Call(CallExpr {
                    target: CallTarget::Named(name),
                    ..
                })) if name == "taint_source"
            ));
        }
    }

    #[test]
    fn project_merge_remaps_descriptor_file_ids_and_function_ids() {
        let program = parse_project_sources(
            Language::Go,
            &[
                (
                    "first.go".to_string(),
                    "func first(x) { return x\n }".to_string(),
                ),
                (
                    "second.go".to_string(),
                    "func second(y) { return y\n }".to_string(),
                ),
            ],
        )
        .expect("Go project should parse");
        assert_eq!(program.files.len(), 2);
        assert_eq!(program.modules.len(), 2);
        assert_ne!(program.files[0].id, program.files[1].id);
        let functions = program
            .modules
            .iter()
            .flat_map(|module| &module.items)
            .filter_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(functions.len(), 2);
        assert_ne!(functions[0].id, functions[1].id);
        assert_ne!(functions[0].params[0].symbol, functions[1].params[0].symbol);
        assert_eq!(functions[0].span.file, program.files[0].id.0);
        assert_eq!(functions[1].span.file, program.files[1].id.0);
    }

    fn first_lambda(program: &Program) -> Option<&Expr> {
        program
            .modules
            .iter()
            .flat_map(|module| &module.items)
            .flat_map(|item| match item {
                Item::Function(function) => vec![function],
                Item::Class(class) => class.methods.iter().collect(),
                Item::GlobalVar(_) => Vec::new(),
            })
            .flat_map(|function| &function.body.stmts)
            .find_map(|stmt| match stmt {
                Stmt::Let {
                    init: Some(expr @ Expr::Lambda { .. }),
                    ..
                }
                | Stmt::Assign {
                    rhs: expr @ Expr::Lambda { .. },
                    ..
                } => Some(expr),
                _ => None,
            })
    }

    #[test]
    fn descriptor_closures_build_lambda_hir_and_capture_outer_values() {
        let cases = [
            (
                Language::CSharp,
                "var prefix = source(); var cb = x => prefix + x;",
                "lambda.cs",
            ),
            (
                Language::ObjC,
                "id run(id prefix) { id cb = ^(id x) { return prefix; }; return cb; }",
                "lambda.m",
            ),
            (
                Language::ObjCpp,
                "id run(id prefix) { id cb = ^(id x) { return prefix; }; return cb; }",
                "lambda.mm",
            ),
            (
                Language::Kotlin,
                "val prefix = source()\nval cb = { x -> prefix + x }\n",
                "lambda.kt",
            ),
            (
                Language::Swift,
                "let prefix = source()\nlet cb = { x in prefix + x }\n",
                "lambda.swift",
            ),
            (
                Language::JavaScript,
                "const prefix = source(); const cb = (x) => prefix + x;",
                "lambda.js",
            ),
            (
                Language::Go,
                "func run(prefix) { cb := func(x) { return prefix + x\n }\n return cb\n }",
                "lambda.go",
            ),
            (
                Language::Php,
                "<?php $prefix = source(); $cb = fn($x) => $prefix . $x; ?>",
                "lambda.php",
            ),
            (
                Language::Ruby,
                "prefix = source\ncb = ->(x) { prefix + x }\n",
                "lambda.rb",
            ),
            (
                Language::Rust,
                "fn run(prefix) { let cb = move |x| prefix + x; return cb; }",
                "lambda.rs",
            ),
        ];
        for (language, source, path) in cases {
            let program = parse_file(language.clone(), path, source)
                .unwrap_or_else(|error| panic!("{language:?} closure parse failed: {error}"));
            let lambda = first_lambda(&program)
                .unwrap_or_else(|| panic!("{language:?} did not produce Lambda HIR: {program:#?}"));
            let Expr::Lambda {
                params, captures, ..
            } = lambda
            else {
                unreachable!()
            };
            assert_eq!(params.len(), 1, "{language:?}");
            assert_eq!(captures.len(), 1, "{language:?}: {lambda:#?}");
            assert_eq!(captures[0].name.trim_start_matches('$'), "prefix");
        }
    }

    #[test]
    fn local_closure_invocation_stays_dynamic() {
        let program = parse_file(
            Language::JavaScript,
            "lambda.js",
            "const prefix = source(); const cb = (x) => prefix + x; sink(cb('v'));",
        )
        .expect("JavaScript closure should parse");
        let top = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("top-level function");
        let dynamic = top.body.stmts.iter().find_map(|stmt| match stmt {
            Stmt::Expr {
                expr: Expr::Call(sink),
                ..
            } => sink.args.first(),
            _ => None,
        });
        assert!(
            matches!(
                dynamic,
                Some(Expr::Call(CallExpr {
                    target: CallTarget::Dynamic(_),
                    ..
                }))
            ),
            "unexpected closure invocation HIR: {top:#?}"
        );
    }

    #[test]
    fn javascript_lambda_body_keeps_statements_after_nested_object_literals() {
        let program = parse_file(
            Language::JavaScript,
            "lambda.js",
            r#"exports.handler = function(event) {
  const response = { headers: { "Content-Type": "text/html" }, body: event };
  const html = "<div>" + event;
  return html;
};
"#,
        )
        .expect("JavaScript handler should parse");
        let Expr::Lambda { body, .. } = first_lambda(&program).expect("assigned handler lambda")
        else {
            unreachable!()
        };
        assert_eq!(
            body.stmts.len(),
            3,
            "nested map ended lambda early: {program:#?}"
        );
        let top = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "__top_level__" => Some(function),
                _ => None,
            })
            .expect("top-level carrier");
        assert_eq!(
            top.body.stmts.len(),
            1,
            "lambda statements escaped into module scope"
        );
    }

    #[test]
    fn parses_php_use_captures_and_go_literal_return_types() {
        let php = parse_file(
            Language::Php,
            "closure.php",
            "<?php $prefix = source(); $cb = function($x) use ($prefix) { return $prefix; }; ?>",
        )
        .expect("PHP long-form closure should parse");
        let Some(Expr::Lambda {
            params, captures, ..
        }) = first_lambda(&php)
        else {
            panic!("expected PHP lambda HIR: {php:#?}");
        };
        assert_eq!(params.len(), 1);
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].name, "prefix");

        let go = parse_file(
            Language::Go,
            "closure.go",
            "func run(prefix string) { cb := func(x string) (string, error) { return prefix\n }\n return cb\n }",
        )
        .expect("Go function literal result list should parse");
        let Some(Expr::Lambda {
            params,
            captures,
            body,
            ..
        }) = first_lambda(&go)
        else {
            panic!("expected Go lambda HIR: {go:#?}");
        };
        assert_eq!(params.len(), 1);
        assert_eq!(captures.len(), 1);
        assert!(!body.stmts.is_empty());
    }

    #[test]
    fn parses_csharp_delegate_and_kotlin_implicit_it() {
        let csharp = parse_file(
            Language::CSharp,
            "delegate.cs",
            "var prefix = source(); var cb = delegate(string x) { return prefix + x; };",
        )
        .expect("C# anonymous delegate should parse");
        let Some(Expr::Lambda {
            params, captures, ..
        }) = first_lambda(&csharp)
        else {
            panic!("expected C# delegate HIR: {csharp:#?}");
        };
        assert_eq!(params.len(), 1);
        assert_eq!(captures.len(), 1);

        let kotlin = parse_file(
            Language::Kotlin,
            "implicit.kt",
            "val prefix = source()\nval cb = { prefix + it }\n",
        )
        .expect("Kotlin implicit-it closure should parse");
        let Some(Expr::Lambda {
            params, captures, ..
        }) = first_lambda(&kotlin)
        else {
            panic!("expected Kotlin lambda HIR: {kotlin:#?}");
        };
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "it");
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].name, "prefix");
    }

    #[test]
    fn csharp_calls_preserve_named_argument_labels() {
        let program = parse_file(
            Language::CSharp,
            "named.cs",
            "void Run() { Execute(value: source(), commandText: safe); }",
        )
        .expect("C# named arguments should parse");
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) => Some(function),
                _ => None,
            })
            .expect("function");
        let call = function
            .body
            .stmts
            .iter()
            .find_map(|statement| match statement {
                Stmt::Expr {
                    expr: Expr::Call(call),
                    ..
                } => Some(call),
                _ => None,
            });
        assert_eq!(
            call.expect("Execute call").arg_names,
            vec![Some("value".to_string()), Some("commandText".to_string())]
        );
    }

    #[test]
    fn csharp_and_javascript_interpolation_preserve_value_dependencies() {
        let cases = [
            (
                Language::CSharp,
                "var input = source(); var command = $\"run {input}\";",
                "interp.cs",
            ),
            (
                Language::JavaScript,
                "const input = source(); const command = `run ${input}`;",
                "interp.js",
            ),
        ];
        for (language, source, path) in cases {
            let program = parse_file(language.clone(), path, source)
                .unwrap_or_else(|error| panic!("{language:?} interpolation parse failed: {error}"));
            let function = program.modules[0]
                .items
                .iter()
                .find_map(|item| match item {
                    Item::Function(function) => Some(function),
                    _ => None,
                })
                .expect("top-level function");
            let interpolated = function.body.stmts.iter().find_map(|stmt| match stmt {
                Stmt::Let {
                    init: Some(expr @ Expr::Interp { .. }),
                    ..
                } => Some(expr),
                _ => None,
            });
            let Some(Expr::Interp { parts, .. }) = interpolated else {
                panic!("expected {language:?} Interp HIR: {function:#?}");
            };
            assert!(parts.iter().any(|part| matches!(part, Expr::VarRef { .. })));
        }

        let javascript = parse_file(
            Language::JavaScript,
            "plain.js",
            "const text = \"literal ${notAnExpression}\";",
        )
        .expect("ordinary JavaScript string should parse");
        let rendered = format!("{javascript:#?}");
        assert!(!rendered.contains("Interp {"));
    }

    #[test]
    fn kotlin_and_swift_multiline_interpolation_preserve_value_dependencies() {
        let cases = [
            (
                Language::Kotlin,
                "fun run() {\n val input = source()\n val query = \"\"\"select\n$input\n\"\"\"\n sink(query)\n}",
                "multiline.kt",
            ),
            (
                Language::Swift,
                "func run() {\n let input = source()\n let query = \"\"\"select\n\\(input)\n\"\"\"\n sink(query)\n}",
                "multiline.swift",
            ),
        ];
        for (language, source, path) in cases {
            let program = parse_file(language.clone(), path, source)
                .unwrap_or_else(|error| panic!("{language:?} multiline parse failed: {error}"));
            let function = program.modules[0]
                .items
                .iter()
                .find_map(|item| match item {
                    Item::Function(function) => Some(function),
                    _ => None,
                })
                .expect("run function");
            let interpolated = function.body.stmts.iter().find_map(|stmt| match stmt {
                Stmt::Let {
                    init: Some(expr @ Expr::Interp { .. }),
                    ..
                } => Some(expr),
                _ => None,
            });
            let Some(Expr::Interp { parts, .. }) = interpolated else {
                panic!("expected multiline interpolation for {language:?}: {function:#?}");
            };
            assert!(parts.iter().any(|part| matches!(part, Expr::VarRef { .. })));
        }
    }

    #[test]
    fn javascript_does_not_treat_other_language_words_as_keywords() {
        let program = parse_file(
            Language::JavaScript,
            "keywords.js",
            "function run(data, go, defer, value) { data.location.href = value; go(defer); }",
        )
        .expect("JavaScript identifiers must parse");
        for name in ["data", "go", "defer", "value"] {
            assert!(
                program.symbols.iter().any(|symbol| symbol.name == name),
                "missing ordinary JavaScript identifier {name}: {program:#?}"
            );
        }
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("run function");
        let nested_field_root = function.body.stmts.iter().find_map(|stmt| match stmt {
            Stmt::Assign {
                lhs: LValue::Field { base, .. },
                ..
            } => match base.as_ref() {
                Expr::FieldRead { base, field, .. } if field == "location" => Some(base.as_ref()),
                _ => None,
            },
            _ => None,
        });
        assert!(
            matches!(nested_field_root, Some(Expr::VarRef { .. })),
            "field root lost identifier identity: {function:#?}"
        );
    }

    #[test]
    fn javascript_dollar_prefixed_identifiers_keep_parameter_identity() {
        let program = parse_file(
            Language::JavaScript,
            "angular.js",
            "function controller($scope, $sce) { $sce.trustAsHtml($scope.html); }",
        )
        .expect("JavaScript dollar-prefixed identifiers must parse");
        let function = program.modules[0]
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "controller" => Some(function),
                _ => None,
            })
            .expect("controller function");
        assert_eq!(
            function
                .params
                .iter()
                .map(|param| param.name.as_str())
                .collect::<Vec<_>>(),
            ["$scope", "$sce"]
        );
        assert!(function.body.stmts.iter().any(|stmt| {
            format!("{stmt:#?}").contains("trustAsHtml")
                && format!("{stmt:#?}").contains("FieldRead")
        }));
    }

    #[test]
    fn javascript_commonjs_bindings_become_module_import_aliases() {
        let program = parse_file(
            Language::JavaScript,
            "imports.js",
            r#"
const cp = require("child_process");
const Strategy = require("passport-jwt").Strategy;
const {spawn, spawnSync: runSync} = require('child_process');
function execute(input) { cp.spawn("sh", [input]); spawn("sh", [input]); runSync("sh", [input]); }
"#,
        )
        .expect("parse CommonJS aliases");
        let imports = &program.modules[0].imports;
        for (alias, path) in [
            ("cp", "child_process"),
            ("Strategy", "passport-jwt.Strategy"),
            ("spawn", "child_process.spawn"),
            ("runSync", "child_process.spawnSync"),
        ] {
            assert!(
                imports.iter().any(|import| {
                    import.alias.as_deref() == Some(alias) && import.path == path
                }),
                "missing {alias} -> {path}: {imports:#?}"
            );
        }
    }
}
