fn java_models() -> RuleSet {
    RuleSet {
        loop_sinks: Vec::new(),
        metadata: Vec::new(),
        sink_reports: Vec::new(),
        index_sinks: Vec::new(),
        call_site_sources: Vec::new(),
        call_site_sinks: Vec::new(),
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
        native_dataflow_rules: Vec::new(),
        model_dependencies: Vec::new(),
    }
}

/// Servlet-API models the legacy and MIT packs lack or model too loosely:
/// XSS through the response writer, trust-boundary writes into the session,
/// the rest of the request-input surface, and collection/array flows. Each
/// sink's `kind` names its weakness (`uniflow_rules::vuln_class`), so the
/// finding carries the right CWE without per-rule metadata.
fn java_servlet_models() -> RuleSet {
    let java = || Some(Language::Java);
    let request = "javax.servlet.http.HttpServletRequest";
    let mut rules = RuleSet::default();

    // Request input beyond getParameter/getHeader/getQueryString.
    for (id, method) in [
        ("java-http-request-parameter-values", "getParameterValues"),
        ("java-http-request-parameter-map", "getParameterMap"),
        ("java-http-request-parameter-names", "getParameterNames"),
        ("java-http-request-headers", "getHeaders"),
        ("java-http-request-header-names", "getHeaderNames"),
        ("java-http-request-cookies", "getCookies"),
        ("java-http-request-reader", "getReader"),
        ("java-http-request-input-stream", "getInputStream"),
        ("java-http-request-uri", "getRequestURI"),
        ("java-http-request-path-info", "getPathInfo"),
    ] {
        rules.sources.push(SourceRule {
            id: id.to_string(),
            language: java(),
            matcher: ApiMatcher { receiver_type: Some(request.to_string()), method_name: Some(method.to_string()), ..Default::default() },
            out: Port::Return,
            kind: "generic".to_string(),
        });
    }

    // XSS: output written to the HTTP response. Receiver provenance, not
    // type, is what separates this from a PrintWriter on a file.
    let response_stream = r"(?:javax|jakarta)\.servlet\.(?:http\.HttpServletResponse|ServletResponse)\.(?:getWriter|getOutputStream)$";
    for (id, receiver, methods, port) in [
        ("java-servlet-writer-print", r"^java\.io\.(?:PrintWriter|Writer)$", r"^(?:print|println|write|append)$", Port::Arg(0)),
        ("java-servlet-writer-format", r"^java\.io\.PrintWriter$", r"^(?:format|printf)$", Port::ArgsFrom(0)),
        ("java-servlet-output-stream-print", r"^(?:javax|jakarta)\.servlet\.ServletOutputStream$", r"^(?:print|println|write)$", Port::Arg(0)),
    ] {
        rules.sinks.push(SinkRule {
            id: id.to_string(),
            language: java(),
            matcher: ApiMatcher {
                receiver_regex: Some(receiver.to_string()),
                method_regex: Some(methods.to_string()),
                receiver_origin_regex: Some(response_stream.to_string()),
                ..Default::default()
            },
            inputs: vec![port],
            kind: "xss".to_string(),
        });
    }

    // SQL through frameworks: the query string argument of Spring JDBC
    // templates, JPA and Hibernate. (The raw JDBC `Statement`/`Connection`
    // sinks are in `java_models`.)
    for (id, receiver, methods) in [
        (
            "java-spring-jdbc-template",
            r"^org\.springframework\.jdbc\.core\.(?:JdbcTemplate|JdbcOperations|namedparam\.NamedParameterJdbcTemplate|namedparam\.NamedParameterJdbcOperations)$",
            r"^(?:query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForLong|queryForInt|queryForStream|update|batchUpdate|execute)$",
        ),
        (
            "java-jpa-entity-manager",
            r"^(?:javax|jakarta)\.persistence\.EntityManager$",
            r"^(?:createQuery|createNativeQuery)$",
        ),
        (
            "java-hibernate-session",
            r"^org\.hibernate\.(?:Session|SharedSessionContract|StatelessSession|query\.QueryProducer)$",
            r"^(?:createQuery|createSQLQuery|createNativeQuery|createFilter)$",
        ),
    ] {
        rules.sinks.push(SinkRule {
            id: id.to_string(),
            language: java(),
            matcher: ApiMatcher { receiver_regex: Some(receiver.to_string()), method_regex: Some(methods.to_string()), ..Default::default() },
            inputs: vec![Port::Arg(0)],
            kind: "sql".to_string(),
        });
    }

    // Trust boundary: untrusted data stored as trusted session state.
    rules.sinks.push(SinkRule {
        id: "java-http-session-set-attribute".to_string(),
        language: java(),
        matcher: ApiMatcher {
            receiver_regex: Some(r"^(?:javax|jakarta)\.servlet\.http\.HttpSession$".to_string()),
            method_regex: Some(r"^(?:setAttribute|putValue)$".to_string()),
            ..Default::default()
        },
        inputs: vec![Port::Arg(0), Port::Arg(1)],
        kind: "trust_boundary".to_string(),
    });

    // Collections, arrays and common value holders: element in, element out.
    let into_receiver = |id: &str, receiver: &str, methods: &str, from: Port| PropagatorRule {
        id: id.to_string(),
        language: java(),
        matcher: ApiMatcher { receiver_regex: Some(receiver.to_string()), method_regex: Some(methods.to_string()), ..Default::default() },
        flows: vec![FlowSpec { from, to: Port::Receiver }],
    };
    let out_of_receiver = |id: &str, receiver: &str, methods: &str| PropagatorRule {
        id: id.to_string(),
        language: java(),
        matcher: ApiMatcher { receiver_regex: Some(receiver.to_string()), method_regex: Some(methods.to_string()), ..Default::default() },
        flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
    };
    let collection = r"^java\.util\.(?:List|ArrayList|LinkedList|Collection|Set|HashSet|LinkedHashSet|TreeSet|Queue|Deque|ArrayDeque|Vector|Stack)$";
    let map = r"^java\.util\.(?:Map|HashMap|LinkedHashMap|TreeMap|Hashtable|concurrent\.ConcurrentHashMap|Properties)$";
    rules.propagators.extend([
        into_receiver("java-collection-add", collection, r"^(?:add|addFirst|addLast|offer|push|set|addAll)$", Port::ArgsFrom(0)),
        out_of_receiver("java-collection-get", collection, r"^(?:get|getFirst|getLast|peek|poll|pop|remove|element|toArray|iterator|stream|subList)$"),
        into_receiver("java-map-put", map, r"^(?:put|putIfAbsent|putAll|setProperty)$", Port::ArgsFrom(0)),
        out_of_receiver("java-map-get", map, r"^(?:get|getOrDefault|getProperty|values|entrySet|keySet|remove)$"),
        out_of_receiver("java-iterator-next", r"^java\.util\.(?:Iterator|ListIterator|Enumeration)$", r"^(?:next|nextElement)$"),
        out_of_receiver("java-map-entry-get", r"^java\.util\.Map\.Entry$", r"^(?:getKey|getValue)$"),
        out_of_receiver("java-cookie-get-value", r"^(?:javax|jakarta)\.servlet\.http\.Cookie$", r"^(?:getValue|getName)$"),
        into_receiver("java-process-builder-command", r"^java\.lang\.ProcessBuilder$", r"^command$", Port::ArgsFrom(0)),
    ]);
    // Strings: every value-producing method of a string carries the
    // receiver's data into its result (a substring of a tainted string is
    // tainted), and those that splice in arguments carry the arguments too.
    let strings = r"^java\.lang\.(?:String|StringBuilder|StringBuffer|CharSequence)$";
    rules.propagators.push(PropagatorRule {
        id: "java-string-derivations".to_string(),
        language: java(),
        matcher: ApiMatcher {
            receiver_regex: Some(strings.to_string()),
            method_regex: Some(r"^(?:substring|subSequence|trim|strip|stripLeading|stripTrailing|toLowerCase|toUpperCase|toString|intern|toCharArray|getBytes|split|lines|repeat|formatted|chars|codePoints|concat|replace|replaceAll|replaceFirst|translateEscapes|stripIndent|indent|reverse|insert)$".to_string()),
            ..Default::default()
        },
        flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
    });
    rules.propagators.push(PropagatorRule {
        id: "java-string-splice-args".to_string(),
        language: java(),
        matcher: ApiMatcher {
            receiver_regex: Some(strings.to_string()),
            method_regex: Some(r"^(?:concat|replace|replaceAll|replaceFirst|formatted|insert)$".to_string()),
            ..Default::default()
        },
        flows: vec![FlowSpec { from: Port::ArgsFrom(0), to: Port::Return }],
    });
    // `String.valueOf(x)`, `String.format(fmt, args)`, `new String(bytes)`,
    // `Arrays.copyOf(a, n)` and friends: arguments to result.
    rules.propagators.push(PropagatorRule {
        id: "java-string-factories".to_string(),
        language: java(),
        matcher: ApiMatcher {
            regex: Some(r"^java\.lang\.(?:String\.(?:valueOf|copyValueOf|format|join|init\^)|StringBuilder\.init\^|StringBuffer\.init\^)$|^java\.util\.(?:Arrays\.copyOf(?:Range)?|Objects\.(?:toString|requireNonNull|requireNonNullElse))$|^java\.util\.Base64\.(?:Encoder|Decoder)\.(?:encode|encodeToString|decode)$".to_string()),
            ..Default::default()
        },
        flows: vec![FlowSpec { from: Port::ArgsFrom(0), to: Port::Return }],
    });
    // Decoders reverse an encoding, so the decoded text carries the input's
    // data unchanged. (Encoders are deliberately absent: `URLEncoder.encode`
    // or an HTML encoder is a sanitizer for some sinks and must not be
    // modeled as plain propagation.)
    rules.propagators.push(PropagatorRule {
        id: "java-decoders".to_string(),
        language: java(),
        matcher: ApiMatcher {
            regex: Some(r"^java\.net\.URLDecoder\.decode$|^java\.net\.URI\.(?:create|init\^)$|^org\.apache\.commons\.codec\.binary\.Base64\.decode(?:Base64)?$".to_string()),
            ..Default::default()
        },
        flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }],
    });
    // `Arrays.asList(a...)`, `List.of(...)`, `String.join(sep, parts)`.
    rules.propagators.push(PropagatorRule {
        id: "java-collection-factories".to_string(),
        language: java(),
        matcher: ApiMatcher { regex: Some(r"^java\.util\.(?:Arrays\.asList|List\.of|Set\.of|Collections\.(?:singletonList|singleton|unmodifiableList))$|^java\.lang\.String\.join$".to_string()), ..Default::default() },
        flows: vec![FlowSpec { from: Port::ArgsFrom(0), to: Port::Return }],
    });
    rules
}
