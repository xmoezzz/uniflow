// Unit tests for the configurable lexer. Each test pins one behaviour that a
// language frontend depends on.

use super::*;

fn c_like() -> LexerSpec {
    LexerSpec {
        keywords: &[
            "int", "char", "void", "return", "if", "else", "while", "for",
        ],
        ..LexerSpec::default()
    }
}

fn tokenize_with(spec: &LexerSpec, source: &str) -> Vec<Token> {
    Lexer::new(source, spec).tokenize()
}

fn kinds(source: &str, spec: &LexerSpec) -> Vec<String> {
    tokenize_with(spec, source)
        .into_iter()
        .filter(|token| token.kind != TokKind::Eof)
        .map(|token| format!("{:?}:{}", token.kind, token.text))
        .collect()
}

#[test]
fn lexes_c_like_comments_and_identifiers() {
    let spec = c_like();
    let got = kinds("int /* skip */ x; // trailing\ny", &spec);
    assert_eq!(got, vec!["Keyword:int", "Ident:x", "Symbol:;", "Ident:y",]);
}

#[test]
fn tracks_line_and_column() {
    let spec = c_like();
    let tokens = tokenize_with(&spec, "a;\n  bb;\n    ccc;");
    let token = tokens.iter().find(|t| t.text == "ccc").expect("token");
    assert_eq!(token.line, 3);
    assert_eq!(token.col, 5);
    assert_eq!(token.start, 13);
}

#[test]
fn counts_newlines_between_tokens_for_style_checks() {
    let spec = c_like();
    let tokens = tokenize_with(&spec, "a;\n\n\nb;");
    let token = tokens.iter().find(|t| t.text == "b").expect("token");
    assert_eq!(token.newlines_before, 3);
    let tokens = tokenize_with(&spec, "a; b;");
    let token = tokens.iter().find(|t| t.text == "b").expect("token");
    assert_eq!(token.newlines_before, 0);
    assert!(token.space_before);
}

#[test]
fn lexes_string_escapes_and_values() {
    let spec = c_like();
    let tokens = tokenize_with(&spec, "a = \"x\\ny\";");
    let token = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit)
        .expect("string");
    assert_eq!(token.string_value(), "x\ny");
}

#[test]
fn unterminated_string_does_not_swallow_file() {
    let spec = c_like();
    let tokens = tokenize_with(&spec, "a = \"oops\nb = 1;");
    // The literal must stop at the newline so `b` is still lexed.
    assert!(tokens.iter().any(|t| t.text == "b"), "{:?}", tokens);
}

#[test]
fn lexes_numeric_forms() {
    let spec = c_like();
    let tokens = tokenize_with(&spec, "0x1f 0b1010 0o17 1_000 3.14e-9 42");
    let numbers: Vec<&str> = tokens
        .iter()
        .filter(|t| matches!(t.kind, TokKind::IntLit | TokKind::FloatLit))
        .map(|t| t.text.as_str())
        .collect();
    assert_eq!(
        numbers,
        vec!["0x1f", "0b1010", "0o17", "1_000", "3.14e-9", "42"]
    );
    assert_eq!(int_literal_value("0x1f"), Some(31));
    assert_eq!(int_literal_value("1_000"), Some(1000));
    assert_eq!(int_literal_value("0b1010"), Some(10));
    assert_eq!(int_literal_value("0o17"), Some(15));
    assert_eq!(float_literal_value("3.14e-9"), Some(3.14e-9));
}

#[test]
fn c_style_octal_literal() {
    assert_eq!(int_literal_value("0755"), Some(493));
    assert_eq!(int_literal_value("0"), Some(0));
    assert_eq!(int_literal_value("10"), Some(10));
}

#[test]
fn dot_range_is_not_a_float() {
    let spec = LexerSpec {
        keywords: &[],
        ..LexerSpec::default()
    };
    let tokens = tokenize_with(&spec, "1..2");
    assert_eq!(tokens[0].kind, TokKind::IntLit);
    assert_eq!(tokens[1].text, "..");
}

#[test]
fn longest_match_operators() {
    let spec = LexerSpec {
        keywords: &[],
        ..LexerSpec::default()
    };
    let symbols: Vec<String> = tokenize_with(&spec, "a <<= b ??= c <= d .. e; f := g")
        .into_iter()
        .filter(|t| t.kind == TokKind::Symbol)
        .map(|t| t.text)
        .collect();
    let expected = vec!["<<=", "??=", "<=", "..", ";", ":="];
    assert_eq!(symbols, expected);
}

#[test]
fn js_template_literal_interpolation_keeps_expr_range() {
    let spec = LexerSpec {
        string_quotes: vec!['"', '\'', '`'],
        interp: InterpStyle::DollarBrace,
        interpolation_quotes: vec!['`'],
        ..LexerSpec::default()
    };
    let source = "cmd = \"ls \" + `rm ${dir} -f`;";
    let tokens = tokenize_with(&spec, source);
    let token = tokens
        .iter()
        .find(|t| t.text.starts_with('`'))
        .expect("template literal");
    assert_eq!(token.parts.len(), 3);
    assert_eq!(token.parts[0].text, "rm ");
    assert!(token.parts[1].is_expr);
    assert_eq!(token.parts[1].text, "dir");
    assert_eq!(token.parts[2].text, " -f");
    // The hole range must point at `dir` in the original source.
    let start = token.parts[1].start as usize;
    let end = token.parts[1].end as usize;
    assert_eq!(&source[start..end], "dir");
}

#[test]
fn ruby_hash_brace_interpolation_and_symbols() {
    let spec = LexerSpec {
        line_comments: vec!["#"],
        block_comments: vec![],
        interp: InterpStyle::HashBrace,
        interpolation_quotes: vec!['"'],
        colon_idents: true,
        question_idents: true,
        keywords: &["def", "end"],
        ..LexerSpec::default()
    };
    let source = "x = \"touch #{path}!\"\nfoo?\n:sym\n";
    let tokens = tokenize_with(&spec, source);
    let string = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit)
        .expect("string");
    assert_eq!(string.parts.len(), 3);
    assert_eq!(string.parts[1].text, "path");
    assert_eq!(string.string_value(), "touch !");
    assert!(tokens.iter().any(|t| t.text == "foo?"), "{:?}", tokens);
    assert!(tokens.iter().any(|t| t.text == ":sym"), "{:?}", tokens);
}

#[test]
fn php_dollar_identifiers_and_simple_interp() {
    let spec = LexerSpec {
        dollar_idents: true,
        interp: InterpStyle::Dollar,
        interpolation_quotes: vec!['"'],
        keywords: &["function", "echo"],
        ..LexerSpec::default()
    };
    let source = "$cmd = \"cat $file\";";
    let tokens = tokenize_with(&spec, source);
    assert_eq!(tokens[0].text, "$cmd");
    assert_eq!(tokens[0].bare_name(), "cmd");
    let string = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit)
        .expect("string");
    let holes: Vec<&str> = string
        .parts
        .iter()
        .filter(|p| p.is_expr)
        .map(|p| p.text.as_str())
        .collect();
    assert_eq!(holes, vec!["file"]);
}

#[test]
fn swift_backslash_paren_interpolation() {
    let spec = LexerSpec {
        interp: InterpStyle::BackslashParen,
        interpolation_quotes: vec!['"'],
        ..LexerSpec::default()
    };
    let source = "let cmd = \"rm \\(dir)/x\"";
    let tokens = tokenize_with(&spec, source);
    let string = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit)
        .expect("string");
    assert_eq!(string.parts[1].text, "dir");
    assert_eq!(string.parts[0].text, "rm ");
    assert_eq!(string.parts[2].text, "/x");
}

#[test]
fn python_fstring_with_escaped_braces_and_triple_quotes() {
    let spec = LexerSpec {
        line_comments: vec!["#"],
        block_comments: vec![],
        triple_quotes: vec!["\"\"\"", "'''"],
        interp_prefixes: vec!["f"],
        interp: InterpStyle::Curly,
        significant_newlines: true,
        ..LexerSpec::default()
    };
    let source = "x = f\"{{{path}}} ok\"\ny = \"\"\"body {z} end\"\"\"\n";
    let tokens = tokenize_with(&spec, source);
    let first = tokens
        .iter()
        .filter(|t| t.kind == TokKind::StringLit)
        .nth(0)
        .expect("fstring");
    assert_eq!(first.parts[0].text, "{", "{:?}", first.parts);
    assert_eq!(first.parts[1].text, "path");
    assert_eq!(first.parts[2].text, "} ok");
    let second = tokens
        .iter()
        .filter(|t| t.kind == TokKind::StringLit)
        .nth(1)
        .expect("triple");
    assert!(
        second.parts.is_empty(),
        "ordinary Python strings do not interpolate"
    );
    // Newlines are tokens for indentation-driven languages.
    assert!(tokens.iter().any(|t| t.kind == TokKind::Newline));
}

#[test]
fn interpolation_can_be_prefix_only() {
    let spec = LexerSpec {
        interp_prefixes: vec!["$"],
        interp: InterpStyle::Curly,
        ..LexerSpec::default()
    };
    let tokens = tokenize_with(&spec, "a = \"{plain}\"; b = $\"{value}\";");
    let strings = tokens
        .iter()
        .filter(|token| token.kind == TokKind::StringLit)
        .collect::<Vec<_>>();
    assert_eq!(strings.len(), 2);
    assert!(strings[0].parts.is_empty());
    assert!(strings[1]
        .parts
        .iter()
        .any(|part| part.is_expr && part.text == "value"));
}

#[test]
fn csharp_verbatim_interpolated_strings_keep_holes() {
    let spec = LexerSpec {
        interp_prefixes: vec!["$"],
        interp: InterpStyle::Curly,
        ..LexerSpec::default()
    };
    for source in [r#"$@"C:\dir\{value}""#, r#"@$"C:\dir\{value}""#] {
        let tokens = tokenize_with(&spec, source);
        let string = tokens
            .iter()
            .find(|token| token.kind == TokKind::StringLit)
            .expect("C# verbatim interpolated string");
        assert!(string
            .parts
            .iter()
            .any(|part| part.is_expr && part.text == "value"));
    }
}

#[test]
fn shell_heredoc_and_line_continuation() {
    let spec = LexerSpec {
        line_comments: vec!["#"],
        block_comments: vec![],
        dollar_idents: true,
        interp: InterpStyle::Dollar,
        here_docs: true,
        line_continuation: true,
        shebang: true,
        ..LexerSpec::default()
    };
    let source = "#!/bin/sh\ncat <<EOF > out\nhello $USER\nEOF\ncmd \\\n  --flag\n";
    let tokens = tokenize_with(&spec, source);
    let heredoc = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit)
        .expect("heredoc body");
    assert_eq!(heredoc.parts[0].text, "hello ");
    assert_eq!(heredoc.parts[1].text, "USER");
    // The backslash continuation must join the two command lines, so `flag` is
    // not preceded by a logical line break.
    let cmd_line = tokens.iter().find(|t| t.text == "flag").expect("flag");
    assert_eq!(cmd_line.newlines_before, 0, "{:?}", tokens);
}

#[test]
fn heredoc_not_confused_with_shift() {
    let spec = LexerSpec {
        here_docs: true,
        ..LexerSpec::default()
    };
    let tokens = tokenize_with(&spec, "x = a << 2;");
    assert!(tokens.iter().any(|t| t.text == "<<"));
    assert!(!tokens.iter().any(|t| t.kind == TokKind::StringLit));
}

#[test]
fn php_heredoc_with_tag() {
    let spec = LexerSpec {
        dollar_idents: true,
        here_docs: true,
        interp: InterpStyle::Dollar,
        ..LexerSpec::default()
    };
    let source = "$q = <<<SQL\nSELECT * FROM t WHERE id = $id\nSQL;\n";
    let tokens = tokenize_with(&spec, source);
    let heredoc = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit)
        .expect("heredoc");
    assert!(heredoc.parts.iter().any(|p| p.is_expr && p.text == "id"));
    assert!(tokens.iter().any(|t| t.text == ";"));
}

#[test]
fn objc_at_string_and_at_identifier() {
    let spec = LexerSpec {
        at_idents: true,
        keywords: &[
            "int",
            "return",
            "@interface",
            "@implementation",
            "@end",
            "@property",
        ],
        ..LexerSpec::default()
    };
    let source = "@interface Foo : NSObject\n- (id)run { return @\"done\"; }";
    let tokens = tokenize_with(&spec, source);
    assert_eq!(tokens[0].text, "@interface");
    assert!(tokens[0].is_keyword);
    let string = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit)
        .expect("nsstring");
    assert_eq!(string.string_value(), "done");
}

#[test]
fn sql_line_comment_requires_space() {
    let spec = LexerSpec {
        line_comments: vec!["--", "#"],
        block_comments: vec![("/*", "*/")],
        line_comment_needs_break: true,
        case_insensitive_keywords: true,
        keywords: &["select", "from", "where", "insert", "into"],
        ..LexerSpec::default()
    };
    let tokens = tokenize_with(&spec, "SELECT * -- drop\nFROM t;");
    assert_eq!(tokens[0].text, "SELECT");
    assert!(tokens[0].is_keyword, "keywords match case-insensitively");
    assert!(!tokens.iter().any(|t| t.text.contains("drop")));
    assert!(tokens.iter().any(|t| t.text == "FROM"), "{:?}", tokens);
    // `a--b` without a space is not a comment in standard SQL.
    let tokens = tokenize_with(&spec, "a--b");
    assert!(tokens.iter().any(|t| t.text == "b"), "{:?}", tokens);
}

#[test]
fn sql_backtick_quoted_identifier() {
    let spec = LexerSpec {
        keywords: &["select", "from"],
        backtick_idents: true,
        ..LexerSpec::default()
    };
    let tokens = tokenize_with(&spec, "SELECT `select` FROM t");
    let ident = tokens
        .iter()
        .find(|t| t.text.starts_with('`'))
        .expect("quoted id");
    assert_eq!(ident.kind, TokKind::Ident);
}

#[test]
fn unicode_identifiers_and_string_bytes_are_safe() {
    let spec = c_like();
    let tokens = tokenize_with(&spec, "变量 = \"héllo → 世界\";");
    assert_eq!(tokens[0].text, "变量");
    let string = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit)
        .expect("string");
    assert_eq!(string.string_value(), "héllo → 世界");
}

#[test]
fn scan_regex_produces_string_token() {
    let spec = LexerSpec {
        regex_literals: true,
        ..LexerSpec::default()
    };
    let source = "x = /ab[/]c/gi;";
    let mut lexer = Lexer::new(source, &spec);
    let tokens = lexer.tokenize();
    let slash = tokens.iter().find(|t| t.text == "/").expect("slash");
    let regex = lexer.scan_regex(slash.start).expect("regex");
    assert_eq!(regex.text, "/ab[/]c/gi");
    assert_eq!(regex.kind, TokKind::StringLit);
    assert!(lexer.scan_regex(0).is_none());
}

#[test]
fn tokenize_range_relexes_interpolation() {
    let spec = LexerSpec {
        string_quotes: vec!['"', '`'],
        interp: InterpStyle::DollarBrace,
        interpolation_quotes: vec!['`'],
        ..LexerSpec::default()
    };
    let source = "let t = `a ${obj.field + 1} b`;";
    let mut lexer = Lexer::new(source, &spec);
    let tokens = lexer.tokenize();
    let template = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit && !t.parts.is_empty())
        .expect("template");
    let sub = lexer.tokenize_range(template.parts[1].start, template.parts[1].end);
    let texts: Vec<&str> = sub.iter().map(|t| t.text.as_str()).collect();
    assert_eq!(texts, vec!["obj", ".", "field", "+", "1", ""]);
}

#[test]
fn raw_strings_and_verbatim_strings() {
    let spec = LexerSpec {
        raw_prefixes: vec!["r", "R"],
        ..LexerSpec::default()
    };
    let tokens = tokenize_with(&spec, "a = r\"C:\\path\\n\";");
    let string = tokens
        .iter()
        .find(|t| t.kind == TokKind::StringLit)
        .expect("string");
    assert_eq!(string.string_value(), "C:\\path\\n");
}

#[test]
fn block_comment_nesting() {
    let spec = LexerSpec {
        nest_block_comments: true,
        ..LexerSpec::default()
    };
    let tokens = tokenize_with(&spec, "a /* outer /* inner */ still */ b;");
    assert_eq!(tokens[1].text, "b", "{:?}", tokens);
}

#[test]
fn never_panics_on_binary_garbage() {
    let spec = LexerSpec {
        here_docs: true,
        dollar_idents: true,
        significant_newlines: true,
        ..LexerSpec::default()
    };
    let garbage = "\0\u{1}\u{feff}\"\"'''``<<~~@#$%^&*()_+";
    let tokens = tokenize_with(&spec, garbage);
    assert_eq!(tokens.last().map(|t| t.kind), Some(TokKind::Eof));
}
