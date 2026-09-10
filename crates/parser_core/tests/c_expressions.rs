use uniflow_parser_core::c_expressions::{CExpressionFactKind as K, CExpressionIndex};

fn count(source: &str, kind: K) -> usize {
    CExpressionIndex::parse(source)
        .facts
        .iter()
        .filter(|fact| fact.kind == kind)
        .count()
}

#[test]
fn c_expression_facts_ignore_comments_and_literals() {
    let source = "x = y++ + call(a, b ? c : d); /* z = q++ ? f() : g() */ const char *s = \"x++, f(a ? b : c)\";";
    assert_eq!(count(source, K::Assignment), 2);
    assert_eq!(count(source, K::Update), 1);
    assert_eq!(count(source, K::Call), 1);
    assert_eq!(count(source, K::Conditional), 1);
    assert_eq!(count(source, K::Comma), 1);
}

#[test]
fn c_expression_contexts_track_nested_calls_for_and_sizeof() {
    let index = CExpressionIndex::parse("for (i = 0, j = 0; i < n; ++i) use(update++, nested(KEY_ALL_ACCESS)); sizeof(value = read()); sizeof ++other;");
    let commas = index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Comma)
        .collect::<Vec<_>>();
    assert!(commas[0].inside_for_header);
    assert_eq!(commas[1].enclosing_calls, ["use"]);
    let dangerous = index
        .tokens
        .iter()
        .find(|token| token.text == "KEY_ALL_ACCESS")
        .unwrap();
    assert_eq!(
        index.nearest_call_name(dangerous.start as usize).as_deref(),
        Some("nested")
    );
    assert_eq!(
        index
            .facts
            .iter()
            .filter(|fact| fact.inside_sizeof
                && matches!(fact.kind, K::Assignment | K::Update | K::Call))
            .count(),
        3
    );
}

#[test]
fn c_expression_groups_are_smallest_balanced_owners() {
    let source = "result = (a + (b ? c : d));";
    let index = CExpressionIndex::parse(source);
    let binary = index
        .facts
        .iter()
        .find(|fact| fact.kind == K::Binary)
        .unwrap();
    let (open, close) = index.smallest_group(binary.offset).unwrap();
    assert_eq!(
        &source[index.tokens[open].start as usize..index.tokens[close].end as usize],
        "(a + (b ? c : d))"
    );
    for malformed in [
        "(",
        "f(a",
        "sizeof (x =",
        "a ? b",
        "RegOpenKeyEx(KEY_ALL_ACCESS",
    ] {
        let _ = CExpressionIndex::parse(malformed);
    }
}
