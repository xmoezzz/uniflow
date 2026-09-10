use uniflow_parser_core::sql_syntax::SqlSyntax;

#[test]
fn indexes_nested_if_branches_without_confusing_end_if() {
    let syntax = SqlSyntax::parse("IF a THEN IF b THEN x; END IF; ELSIF c THEN y; ELSE z; END IF;");
    assert_eq!(syntax.ifs.len(), 2);
    let outer = syntax
        .ifs
        .iter()
        .find(|item| item.branches.len() == 3)
        .unwrap();
    assert_eq!(
        syntax.normalized(outer.branches[0].condition.clone().unwrap()),
        "a"
    );
    assert_eq!(
        syntax.normalized(outer.branches[1].condition.clone().unwrap()),
        "c"
    );
    assert!(outer.branches[2].condition.is_none());
}

#[test]
fn balances_groups_and_splits_only_top_level_items() {
    let syntax = SqlSyntax::parse("value IN (a, fn(b, c), (d))");
    let open = syntax
        .tokens
        .iter()
        .position(|token| token.text == "(")
        .unwrap();
    let close = syntax.mates[open].unwrap();
    let parts = syntax.split_top_level(open + 1..close, ",");
    assert_eq!(parts.len(), 3);
    assert_eq!(
        syntax.normalized(parts[1].clone()),
        "fn\u{1f}(\u{1f}b\u{1f},\u{1f}c\u{1f})"
    );
    assert_eq!(syntax.normalized(syntax.trim_parens(parts[2].clone())), "d");
}

#[test]
fn ignores_comments_and_literals_and_indexes_begin_blocks() {
    let syntax =
        SqlSyntax::parse("-- IF fake THEN\nBEGIN text := 'END IF;'; /* BEGIN */ NULL; END;");
    assert!(syntax.ifs.is_empty());
    assert_eq!(syntax.blocks.len(), 1);
    assert_eq!(
        syntax.normalized(syntax.blocks[0].body.clone()),
        "text\u{1f}:=\u{1f}'end if;'\u{1f}null"
    );
}

#[test]
fn records_unexplained_disabled_annotations_and_recovery_errors() {
    let syntax =
        SqlSyntax::parse("-- %disabled\n-- %disabled infrastructure issue\nBEGIN (work; END;");
    assert_eq!(syntax.unexplained_disabled_tests, vec![0]);
    assert!(!syntax.parse_errors.is_empty());
}
