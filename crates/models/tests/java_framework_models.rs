use uniflow_hir::Language;
use uniflow_models::default_models_for;
use uniflow_rules::CallInfo;

fn java_call(
    callee: &str,
    receiver_type: &str,
    method_name: &str,
    arg_types: Vec<Option<&str>>,
) -> CallInfo {
    let arg_type_strings = arg_types
        .iter()
        .map(|item| item.map(|s| s.to_string()))
        .collect::<Vec<_>>();
    let arg_type_candidates = arg_type_strings
        .iter()
        .map(|item| item.clone().into_iter().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    CallInfo::new(
        callee,
        Some(receiver_type.to_string()),
        vec![receiver_type.to_string()],
        Some(method_name.to_string()),
        Some(arg_type_strings.len()),
        arg_type_strings,
        arg_type_candidates,
    )
}

#[test]
fn repository_read_heuristic_matches_find_by_prefix() {
    let rules = default_models_for(Language::Java);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "java-springdata-repository-read-heuristic")
        .expect("repository read heuristic");
    let call = java_call(
        "demo.repo.UserRepository.findByName",
        "demo.repo.UserRepository",
        "findByName",
        vec![Some("java.lang.String")],
    );
    assert!(rule.matcher.matches_call(&call));
}

#[test]
fn mapper_read_heuristic_matches_select_prefix() {
    let rules = default_models_for(Language::Java);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "java-mybatis-mapper-read-heuristic")
        .expect("mapper read heuristic");
    let call = java_call(
        "demo.mapper.UserMapper.selectByName",
        "demo.mapper.UserMapper",
        "selectByName",
        vec![Some("java.lang.String")],
    );
    assert!(rule.matcher.matches_call(&call));
}

#[test]
fn sqlsessiontemplate_update_sink_uses_second_argument() {
    let rules = default_models_for(Language::Java);
    let sink = rules
        .sinks
        .iter()
        .find(|rule| rule.id == "java-sqlsessiontemplate-update")
        .expect("sqlsessiontemplate update sink");
    let call = java_call(
        "org.mybatis.spring.SqlSessionTemplate.update",
        "org.mybatis.spring.SqlSessionTemplate",
        "update",
        vec![Some("java.lang.String"), Some("demo.User")],
    );
    assert!(sink.matcher.matches_call(&call));
    assert_eq!(sink.inputs.len(), 1);
}
