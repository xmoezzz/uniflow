use anyhow::Result;
use uniflow_hir::Language;
use uniflow_rules::{ApiMatcher, FlowSpec, Port, PropagatorRule, RuleSet, SanitizerRule, SinkRule, SourceRule, SummaryRule};

pub fn default_models_for(language: Language) -> RuleSet {
    match language {
        Language::Java => java_models(),
        Language::Python => python_models(),
        Language::C | Language::Cpp => c_like_models(language),
        Language::Unknown => RuleSet::default(),
    }
}

pub fn load_with_defaults(language: Language, user_yaml: Option<&str>) -> Result<RuleSet> {
    let mut rules = default_models_for(language);
    if let Some(text) = user_yaml {
        let user = RuleSet::from_yaml_str(text)?;
        rules.merge(user);
    }
    rules.validate()?;
    Ok(rules)
}

fn java_models() -> RuleSet {
    RuleSet {
        sources: vec![
            SourceRule {
                id: "java-http-request-param".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("javax.servlet.http.HttpServletRequest".to_string()),
                    method_name: Some("getParameter".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "java-http-request-header".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("javax.servlet.http.HttpServletRequest".to_string()),
                    method_name: Some("getHeader".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "java-http-request-querystring".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("javax.servlet.http.HttpServletRequest".to_string()),
                    method_name: Some("getQueryString".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "java-spring-requestparam".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("ServerRequest".to_string()),
                    method_name: Some("queryParam".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "java-spring-serverrequest-pathvariable".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("ServerRequest".to_string()),
                    method_name: Some("pathVariable".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "java-system-getenv".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.lang.System".to_string()),
                    method_name: Some("getenv".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "java-bufferedreader-readline".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.io.BufferedReader".to_string()),
                    method_name: Some("readLine".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "java-scanner-nextline".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.util.Scanner".to_string()),
                    method_name: Some("nextLine".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
        ],
        sinks: vec![
            SinkRule {
                id: "java-sql-statement-executequery".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.sql.Statement".to_string()),
                    method_name: Some("executeQuery".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-sql-statement-execute".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.sql.Statement".to_string()),
                    method_name: Some("execute".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-runtime-exec".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.lang.Runtime".to_string()),
                    method_name: Some("exec".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "java-connection-preparestatement".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.sql.Connection".to_string()),
                    method_name: Some("prepareStatement".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-jdbctemplate-query".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("JdbcTemplate".to_string()),
                    method_name: Some("query".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-jdbctemplate-update".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("JdbcTemplate".to_string()),
                    method_name: Some("update".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-jdbctemplate-queryforobject".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("JdbcTemplate".to_string()),
                    method_name: Some("queryForObject".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-entitymanager-createnativequery".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("EntityManager".to_string()),
                    method_name: Some("createNativeQuery".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-entitymanager-createquery".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("EntityManager".to_string()),
                    method_name: Some("createQuery".to_string()),
                    arg_count: Some(1),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-hibernate-session-createquery".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("Session".to_string()),
                    method_name: Some("createQuery".to_string()),
                    arg_count: Some(1),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-hibernate-session-createnativequery".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("Session".to_string()),
                    method_name: Some("createNativeQuery".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-jdbctemplate-queryforlist".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("JdbcTemplate".to_string()),
                    method_name: Some("queryForList".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-namedparameterjdbctemplate-query".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("NamedParameterJdbcTemplate".to_string()),
                    method_name: Some("query".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-namedparameterjdbctemplate-update".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("NamedParameterJdbcTemplate".to_string()),
                    method_name: Some("update".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-sqlsessiontemplate-selectone".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("SqlSessionTemplate".to_string()),
                    method_name: Some("selectOne".to_string()),
                    arg_count: Some(2),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(1)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-sqlsessiontemplate-selectlist".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("SqlSessionTemplate".to_string()),
                    method_name: Some("selectList".to_string()),
                    arg_count: Some(2),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(1)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-sqlsessiontemplate-insert".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("SqlSessionTemplate".to_string()),
                    method_name: Some("insert".to_string()),
                    arg_count: Some(2),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(1)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-sqlsessiontemplate-update".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("SqlSessionTemplate".to_string()),
                    method_name: Some("update".to_string()),
                    arg_count: Some(2),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(1)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "java-sqlsessiontemplate-delete".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("SqlSessionTemplate".to_string()),
                    method_name: Some("delete".to_string()),
                    arg_count: Some(2),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(1)],
                kind: "sql".to_string(),
            },
        ],
        sanitizers: vec![
            SanitizerRule {
                id: "java-escape-sql".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    method_name: Some("escapeSql".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                kind: "sql".to_string(),
            },
            SanitizerRule {
                id: "java-owasp-encode-forsql".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("Encode".to_string()),
                    method_name: Some("forSql".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                kind: "sql".to_string(),
            },
            SanitizerRule {
                id: "java-stringescapeutils-escapesql".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("StringEscapeUtils".to_string()),
                    method_name: Some("escapeSql".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                kind: "sql".to_string(),
            },
            SanitizerRule {
                id: "java-uri-create".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.net.URI".to_string()),
                    method_name: Some("create".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                kind: "generic".to_string(),
            },
        ],
        propagators: vec![
            PropagatorRule {
                id: "java-stringbuilder-append".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.lang.StringBuilder".to_string()),
                    method_name: Some("append".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                ],
            },
            PropagatorRule {
                id: "java-string-concat".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.lang.String".to_string()),
                    method_name: Some("concat".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
        ],
        summaries: vec![
            SummaryRule {
                id: "java-string-valueof".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.lang.String".to_string()),
                    method_name: Some("valueOf".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "java-stringbuilder-tostring".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.lang.StringBuilder".to_string()),
                    method_name: Some("toString".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "java-string-format".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.lang.String".to_string()),
                    method_name: Some("format".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "java-objects-requirenonnull".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.util.Objects".to_string()),
                    method_name: Some("requireNonNull".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "java-jpa-query-setparameter".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("Query".to_string()),
                    method_name: Some("setParameter".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(1), to: Port::Receiver },
                ],
            },
            SummaryRule {
                id: "java-jpa-query-getresultlist".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("Query".to_string()),
                    method_name: Some("getResultList".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "java-jpa-query-getsingleresult".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("Query".to_string()),
                    method_name: Some("getSingleResult".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "java-mybatis-sqlsession-selectone".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("SqlSession".to_string()),
                    method_name: Some("selectOne".to_string()),
                    arg_count: Some(2),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(1), to: Port::Return }],
            },
            SummaryRule {
                id: "java-mybatis-sqlsession-selectlist".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("SqlSession".to_string()),
                    method_name: Some("selectList".to_string()),
                    arg_count: Some(2),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(1), to: Port::Return }],
            },
            SummaryRule {
                id: "java-springdata-repository-read-heuristic".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*(Repository|Repo)$".to_string()),
                    method_regex: Some(r"^(find|read|get|query|select).*".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                    FlowSpec { from: Port::Arg(2), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "java-springdata-repository-save-heuristic".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*(Repository|Repo)$".to_string()),
                    method_regex: Some(r"^(save|insert|update|merge).*".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "java-mybatis-mapper-read-heuristic".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*Mapper$".to_string()),
                    method_regex: Some(r"^(find|read|get|query|select).*".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                    FlowSpec { from: Port::Arg(2), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "java-mybatis-mapper-write-heuristic".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*Mapper$".to_string()),
                    method_regex: Some(r"^(save|insert|update|merge).*".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
        ],
    }
}

fn python_models() -> RuleSet {
    RuleSet {
        sources: vec![
            SourceRule {
                id: "python-flask-request-args-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("flask.request.args".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-flask-request-form-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("flask.request.form".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-flask-request-headers-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("flask.request.headers".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-flask-request-cookies-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("flask.request.cookies".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-os-getenv".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("os".to_string()),
                    method_name: Some("getenv".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-django-request-get-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.GET".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-django-request-post-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.POST".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-django-request-cookies-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.COOKIES".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-django-querydict-getlist".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*request\.(GET|POST|COOKIES)$".to_string()),
                    method_name: Some("getlist".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-query-params".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.query_params".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-path-params".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.path_params".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-flask-request-json-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.json".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-request-values-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.values".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-request-headers-get-generic".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.headers".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-request-cookies-get-generic".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.cookies".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-request-json-get-generic".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.json".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-flask-session-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("session".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-os-environ-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("os.environ".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-starlette-headers-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("headers".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-flask-current-app-config-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("current_app.config".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-request-json-method".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request".to_string()),
                    method_name: Some("json".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-pathlib-read-text".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("read_text".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-flask-get-json".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request".to_string()),
                    method_name: Some("get_json".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-json-loads".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("json.loads".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-request-state-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request.state".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-app-state-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("app.state".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-query-param-wrapper".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("fastapi.Query".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-header-wrapper".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("fastapi.Header".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-cookie-wrapper".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("fastapi.Cookie".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-body-wrapper".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("fastapi.Body".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-form-wrapper".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("fastapi.Form".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-file-wrapper".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("fastapi.File".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-fastapi-uploadfile-read".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*UploadFile$".to_string()),
                    method_name: Some("read".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-request-form".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request".to_string()),
                    method_name: Some("form".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-request-body".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("request".to_string()),
                    method_name: Some("body".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-os-getenv".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("os.getenv".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-django-settings-getattr".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("django.conf.settings".to_string()),
                    ..Default::default()
                },
                out: Port::Receiver,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-flask-g-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*(flask\.)?g$".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-flask-current-app-extensions-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("current_app.extensions".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-contextvar-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*ContextVar$".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "python-yaml-safe-load".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("yaml.safe_load".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
        ],
        sinks: vec![
            SinkRule {
                id: "python-sql-execute".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("execute".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "python-sql-executemany".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("executemany".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "python-os-system".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("os".to_string()),
                    method_name: Some("system".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-os-popen".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("os".to_string()),
                    method_name: Some("popen".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-subprocess-run".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("subprocess".to_string()),
                    method_name: Some("run".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-subprocess-popen".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("subprocess".to_string()),
                    method_name: Some("Popen".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-subprocess-call".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("subprocess".to_string()),
                    method_name: Some("call".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-sqlalchemy-connection-execute".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("execute".to_string()),
                    receiver_regex: Some(".*(Connection|Session|Engine)$".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "python-subprocess-check-output".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("subprocess.check_output".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-subprocess-check-call".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("subprocess.check_call".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-asyncio-create-subprocess-shell".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("asyncio.create_subprocess_shell".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-sql-executescript".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("executescript".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "python-sqlalchemy-exec-driver-sql".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("exec_driver_sql".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "python-asyncio-create-subprocess-exec".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("asyncio.create_subprocess_exec".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-subprocess-getoutput".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("subprocess.getoutput".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "python-sqlalchemy-session-scalar".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("scalar".to_string()),
                    receiver_regex: Some(".*(Session|Connection|Engine)$".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "python-sqlalchemy-session-scalars".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("scalars".to_string()),
                    receiver_regex: Some(".*(Session|Connection|Engine)$".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "python-django-cursor-raw".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("raw".to_string()),
                    receiver_regex: Some(".*(Manager|QuerySet)$".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "sql".to_string(),
            },
        ],
        sanitizers: vec![
            SanitizerRule {
                id: "python-shlex-quote".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("shlex".to_string()),
                    method_name: Some("quote".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                kind: "command".to_string(),
            },
            SanitizerRule {
                id: "python-markupsafe-escape".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("markupsafe.escape".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                kind: "generic".to_string(),
            },
            SanitizerRule {
                id: "python-django-html-escape".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("django.utils.html.escape".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                kind: "generic".to_string(),
            },
        ],
        propagators: vec![
            PropagatorRule {
                id: "python-list-append".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("append".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                ],
            },
            PropagatorRule {
                id: "python-dict-setdefault".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("setdefault".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(1), to: Port::Receiver },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            PropagatorRule {
                id: "python-list-pop".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("pop".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                ],
            },
            PropagatorRule {
                id: "python-list-extend".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("list".to_string()),
                    method_name: Some("extend".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                ],
            },
            PropagatorRule {
                id: "python-set-add".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("set".to_string()),
                    method_name: Some("add".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                ],
            },
            PropagatorRule {
                id: "python-set-update".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("set".to_string()),
                    method_name: Some("update".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                ],
            },
            PropagatorRule {
                id: "python-dict-pop".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("dict".to_string()),
                    method_name: Some("pop".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                ],
            },
            PropagatorRule {
                id: "python-dict-update".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("update".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                ],
            },
            PropagatorRule {
                id: "python-contextvar-set".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*ContextVar$".to_string()),
                    method_name: Some("set".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                ],
            },
        ],
        summaries: vec![
            SummaryRule {
                id: "python-str".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("str".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-dict-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_type: Some("dict".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-copy-copy".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("copy.copy".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-copy-deepcopy".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("copy.deepcopy".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-format".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("format".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-join".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("join".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-pathlib-joinpath".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("joinpath".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-sqlalchemy-text".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("sqlalchemy.text".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-json-dumps".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("json.dumps".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-pydantic-model-dump".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("model_dump".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-pydantic-model-dump-json".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("model_dump_json".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-pydantic-model-copy".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("model_copy".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-pydantic-dict".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_name: Some("dict".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-dataclasses-asdict".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("dataclasses.asdict".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-dataclasses-replace".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("dataclasses.replace".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-flask-current-app-config-get-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("current_app.config".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-django-querydict-getlist-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*request\.(GET|POST|COOKIES)$".to_string()),
                    method_name: Some("getlist".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-sqlalchemy-query-chain-heuristic".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Query|Select)$".to_string()),
                    method_regex: Some(r"^(filter|filter_by|where|having|order_by|group_by|limit|offset|params|bindparams|from_statement|join|outerjoin|options|select_from|subquery|cte)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-fastapi-depends".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("fastapi.Depends".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-fastapi-params-depends".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("fastapi.params.Depends".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-fastapi-security".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("fastapi.Security".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-fastapi-param-wrapper-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_regex: Some(r"^(Query|Path|Header|Cookie|Body|Form|File)$".to_string()),
                    receiver_regex: Some(r"^(fastapi|fastapi\.params)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-fastapi-uploadfile-read-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*UploadFile$".to_string()),
                    method_name: Some("read".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-fastapi-backgroundtasks-add-task".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*BackgroundTasks$".to_string()),
                    method_name: Some("add_task".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                    FlowSpec { from: Port::Arg(1), to: Port::Receiver },
                    FlowSpec { from: Port::Arg(2), to: Port::Receiver },
                ],
            },
            SummaryRule {
                id: "python-request-multidict-getlist".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*(ImmutableMultiDict|Headers|QueryParams|MultiDict|FormData)$".to_string()),
                    method_name: Some("getlist".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-request-multidict-get".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*(ImmutableMultiDict|Headers|QueryParams|MultiDict|FormData)$".to_string()),
                    method_regex: Some(r"^(get|pop|setdefault)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-request-multidict-views".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*(ImmutableMultiDict|Headers|QueryParams|MultiDict|FormData)$".to_string()),
                    method_regex: Some(r"^(keys|values|items)$".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-sqlalchemy-session-factory".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_regex: Some(r"^(sessionmaker|scoped_session)$".to_string()),
                    receiver_regex: Some(r".*sqlalchemy.*".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-sqlalchemy-relationship".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_regex: Some(r"^(relationship|joinedload|selectinload|subqueryload|contains_eager|defaultload|load_only|raiseload|noload)$".to_string()),
                    receiver_regex: Some(r".*(sqlalchemy|orm).*$".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-django-related-manager-chain".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(RelatedManager|ManyRelatedManager)$".to_string()),
                    method_regex: Some(r"^(all|filter|exclude|select_related|prefetch_related|values|values_list|get|create|get_or_create|update_or_create|only|defer|distinct|iterator)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-pydantic-validate-family".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_regex: Some(r"^(model_validate|parse_obj|from_orm)$".to_string()),
                    receiver_regex: Some(r".*(BaseModel|SQLModel)$".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "python-flask-current-app-extensions-get-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_contains: Some("current_app.extensions".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-contextvar-get-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*ContextVar$".to_string()),
                    method_name: Some("get".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-sqlalchemy-execute-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_regex: Some(r"^(execute|exec_driver_sql|scalars|scalar|stream|stream_scalars|get)$".to_string()),
                    receiver_regex: Some(".*(Connection|Session|Engine|AsyncSession|sessionmaker|scoped_session|async_sessionmaker|async_scoped_session)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-sqlalchemy-result-fetch".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Result|ScalarResult|CursorResult|ChunkedIteratorResult|AsyncResult|AsyncScalarResult)$".to_string()),
                    method_regex: Some(r"^(first|one|one_or_none|all|fetchone|fetchall|scalar|scalar_one|scalar_one_or_none|mappings|values|partitions|tuples|unique)$".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-django-queryset-terminals".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Manager|QuerySet)$".to_string()),
                    method_regex: Some(r"^(first|last|earliest|latest)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-django-queryset-bool-terminals".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Manager|QuerySet)$".to_string()),
                    method_regex: Some(r"^(count|exists)$".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-sqlalchemy-session-mutators".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Session|AsyncSession|scoped_session|sessionmaker|async_sessionmaker)$".to_string()),
                    method_regex: Some(r"^(add|add_all|merge|flush|refresh|expire|expire_all|expunge|expunge_all)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-django-queryset-chain-heuristic".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Manager|QuerySet)$".to_string()),
                    method_regex: Some(r"^(filter|exclude|get|annotate|aggregate|order_by|values|values_list|select_related|prefetch_related|select_for_update|raw|get_or_create|update_or_create|all|none|only|defer|distinct|iterator|using|alias)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-django-queryset-bulk-ops".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Manager|QuerySet)$".to_string()),
                    method_regex: Some(r"^(in_bulk|bulk_create|bulk_update)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-django-related-shape-chain".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(RelatedManager|ManyRelatedManager)$".to_string()),
                    method_regex: Some(r"^(all|filter|exclude|select_related|prefetch_related|order_by|distinct)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-sqlalchemy-session-commit-shape".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Session|AsyncSession|scoped_session|sessionmaker|async_sessionmaker)$".to_string()),
                    method_regex: Some(r"^(commit|rollback|close)$".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-fastapi-websocket-receive-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*WebSocket$".to_string()),
                    method_regex: Some(r"^(receive_text|receive_bytes|receive_json)$".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            SummaryRule {
                id: "python-fastapi-websocket-send-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r".*WebSocket$".to_string()),
                    method_regex: Some(r"^(send_text|send_bytes|send_json)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Receiver },
                    FlowSpec { from: Port::Arg(0), to: Port::Receiver },
                ],
            },
            SummaryRule {
                id: "python-sqlalchemy-result-shape-chain".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Result|ScalarResult|CursorResult|ChunkedIteratorResult|AsyncResult|AsyncScalarResult)$".to_string()),
                    method_regex: Some(r"^(mappings|scalars|columns|unique|tuples)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-django-queryset-values-shape".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(".*(Manager|QuerySet)$".to_string()),
                    method_regex: Some(r"^(values|values_list)$".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Receiver, to: Port::Return },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-django-transaction-atomic-summary".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("django.db.transaction.atomic".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-list-comp".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("builtins.list_comp".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-dict-comp".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("builtins.dict_comp".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                    FlowSpec { from: Port::Arg(2), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-set-comp".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("builtins.set_comp".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-gen-expr".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("builtins.gen_expr".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "python-os-path-join".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    exact: Some("os.path.join".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                    FlowSpec { from: Port::Arg(2), to: Port::Return },
                ],
            },
        ],
    }
}

fn c_like_models(language: Language) -> RuleSet {
    let mut rules = RuleSet {
        sources: vec![
            SourceRule {
                id: "c-getenv".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("getenv".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "c-fgets-buffer".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("fgets".to_string()),
                    ..Default::default()
                },
                out: Port::Arg(0),
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "c-read-buffer".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("read".to_string()),
                    ..Default::default()
                },
                out: Port::Arg(1),
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "c-recv-buffer".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("recv".to_string()),
                    ..Default::default()
                },
                out: Port::Arg(1),
                kind: "generic".to_string(),
            },
            SourceRule {
                id: "c-getline-buffer".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("getline".to_string()),
                    ..Default::default()
                },
                out: Port::Arg(0),
                kind: "generic".to_string(),
            },
        ],
        sinks: vec![
            SinkRule {
                id: "c-system".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("system".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "c-popen".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("popen".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "c-execvp".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("execvp".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0), Port::Arg(1)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "c-execve".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("execve".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0), Port::Arg(1)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "c-execl".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("execl".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0), Port::Arg(1)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "c-execlp".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("execlp".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0), Port::Arg(1)],
                kind: "command".to_string(),
            },
            SinkRule {
                id: "c-sqlite3-exec".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("sqlite3_exec".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(1)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "c-pqexec".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("PQexec".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(1)],
                kind: "sql".to_string(),
            },
            SinkRule {
                id: "c-mysql-query".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("mysql_query".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(1)],
                kind: "sql".to_string(),
            },
        ],
        sanitizers: vec![
            SanitizerRule {
                id: "c-sql-escape".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    contains: Some("escape".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                kind: "generic".to_string(),
            },
        ],
        propagators: vec![],
        summaries: vec![
            SummaryRule {
                id: "c-snprintf".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("snprintf".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(2), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(3), to: Port::Arg(0) },
                ],
            },
            SummaryRule {
                id: "c-sprintf".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("sprintf".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(2), to: Port::Arg(0) },
                ],
            },
            SummaryRule {
                id: "c-strcpy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strcpy".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-strncpy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strncpy".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-memcpy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("memcpy".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-memmove".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("memmove".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-mempcpy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("mempcpy".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-strlcpy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strlcpy".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-strlcat".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strlcat".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-stpcpy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("stpcpy".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-stpncpy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("stpncpy".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-strstr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strstr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strcasestr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strcasestr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strpbrk".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strpbrk".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-basename".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("basename".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-dirname".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("dirname".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-rawmemchr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("rawmemchr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-memrchr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("memrchr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strchrnul".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strchrnul".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-index".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("index".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-rindex".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("rindex".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-realpath".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("realpath".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strtok".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strtok".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strtok-r".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strtok_r".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(1), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strsep".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strsep".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strdup".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strdup".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-strdupa".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strdupa".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strndupa".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strndupa".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-memccpy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("memccpy".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-bcopy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("bcopy".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Arg(1) }],
            },
            SummaryRule {
                id: "c-memmem".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("memmem".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strnstr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strnstr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
            },
            SummaryRule {
                id: "c-strcat".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strcat".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(0), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(0), to: Port::Return },
                ],
            },
            SummaryRule {
                id: "c-asprintf".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("asprintf".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec { from: Port::Arg(1), to: Port::Arg(0) },
                    FlowSpec { from: Port::Arg(2), to: Port::Arg(0) },
                ],
            },
        ],
    };

    if matches!(language, Language::Cpp) {
        rules.sources.push(SourceRule {
            id: "cpp-std-getenv".to_string(),
            language: Some(Language::Cpp),
            matcher: ApiMatcher {
                exact: Some("std.getenv".to_string()),
                ..Default::default()
            },
            out: Port::Return,
            kind: "generic".to_string(),
        });
        rules.sinks.push(SinkRule {
            id: "cpp-std-system".to_string(),
            language: Some(Language::Cpp),
            matcher: ApiMatcher {
                exact: Some("std.system".to_string()),
                ..Default::default()
            },
            inputs: vec![Port::Arg(0)],
            kind: "command".to_string(),
        });
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn python_models_include_django_terminals_and_session_mutators() {
        let rules = default_rules_for(Language::Python);
        let ids = rules
            .summaries
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<HashSet<_>>();
        assert!(ids.contains("python-django-queryset-terminals"));
        assert!(ids.contains("python-sqlalchemy-session-mutators"));
    }
}
