fn java_models() -> RuleSet {
    RuleSet {
        metadata: Vec::new(),
        sink_reports: Vec::new(),
        index_sinks: Vec::new(),
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
                    FlowSpec {
                        from: Port::Receiver,
                        to: Port::Receiver,
                    },
                    FlowSpec {
                        from: Port::Arg(0),
                        to: Port::Receiver,
                    },
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
                    FlowSpec {
                        from: Port::Receiver,
                        to: Port::Return,
                    },
                    FlowSpec {
                        from: Port::Arg(0),
                        to: Port::Return,
                    },
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
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "java-stringbuilder-tostring".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_type: Some("java.lang.StringBuilder".to_string()),
                    method_name: Some("toString".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Receiver,
                    to: Port::Return,
                }],
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
                    FlowSpec {
                        from: Port::Arg(0),
                        to: Port::Return,
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
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
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
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
                    FlowSpec {
                        from: Port::Receiver,
                        to: Port::Receiver,
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Receiver,
                    },
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
                flows: vec![FlowSpec {
                    from: Port::Receiver,
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "java-jpa-query-getsingleresult".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    receiver_contains: Some("Query".to_string()),
                    method_name: Some("getSingleResult".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Receiver,
                    to: Port::Return,
                }],
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
                flows: vec![FlowSpec {
                    from: Port::Arg(1),
                    to: Port::Return,
                }],
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
                flows: vec![FlowSpec {
                    from: Port::Arg(1),
                    to: Port::Return,
                }],
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
                    FlowSpec {
                        from: Port::Arg(0),
                        to: Port::Return,
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
                    FlowSpec {
                        from: Port::Arg(2),
                        to: Port::Return,
                    },
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
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
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
                    FlowSpec {
                        from: Port::Arg(0),
                        to: Port::Return,
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
                    FlowSpec {
                        from: Port::Arg(2),
                        to: Port::Return,
                    },
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
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
        ],
        sink_conditions: Vec::new(),
        call_conditions: Vec::new(),
        taint_transforms: Vec::new(),
        field_sources: Vec::new(),
        unused_return_sinks: Vec::new(),
        named_value_sources: Vec::new(),
        field_sinks: Vec::new(),
        field_sanitizers: Vec::new(),
        function_sources: Vec::new(),
        function_sinks: Vec::new(),
        model_dependencies: Vec::new(),
    }
}
