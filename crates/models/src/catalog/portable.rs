fn portable_models(language: Language) -> RuleSet {
    let (source_pattern, sink_pattern, sanitizer_pattern, source_port, sink_port) = match language {
        Language::ObjC | Language::ObjCpp => (
            r"(?i)(?:objectForKey:|valueForKey:|stringForKey:|readDataOfLength:)$",
            r"(?i)(?:executeQuery:|executeUpdate:|evaluateJavaScript:|writeToFile:atomically:)$",
            r"(?i)(?:stringByAddingPercentEncodingWithAllowedCharacters:|escapedString|sanitize:)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::Kotlin | Language::Jsp => (
            r"(?i)(?:getParameter|getHeader|getenv|readLine|nextLine|queryParam)$",
            r"(?i)(?:executeQuery|execute|exec|prepareStatement|query|update)$",
            r"(?i)(?:escapeSql|forSql|encode|sanitize)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::CSharp => (
            r"(?i)(?:Console\.ReadLine|ReadLine|Environment\.GetEnvironmentVariable|GetEnvironmentVariable|Request\.(?:QueryString|Form|Headers).*Get)$",
            r"(?i)(?:Process\.Start|Start|SqlCommand|ExecuteSqlRaw|System\.Diagnostics\.Process\.Start|Response\.Write|Write)$",
            r"(?i)(?:HtmlEncode|UrlEncode|EscapeDataString|SqlParameter)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::Swift => (
            r"(?i)(?:readLine|getenv|UserDefaults.*string|URLSession.*data)$",
            r"(?i)(?:system|Process.*launch|NSExpression.*expression|executeQuery)$",
            r"(?i)(?:addingPercentEncoding|escaped|sanitize)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::Go => (
            r"(?i)(?:os\.Getenv|Getenv|Request\.FormValue|FormValue|Request\.PostFormValue|PostFormValue|bufio\..*ReadString|ReadString|io\.ReadAll|ReadAll)$",
            r"(?i)(?:exec\.Command|Command|CommandContext|DB\.(?:Exec|Query)|Exec|Query|Template\.HTML|HTML|fmt\.Fprintf|Fprintf)$",
            r"(?i)(?:url\.QueryEscape|html\.EscapeString|regexp\.QuoteMeta)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::JavaScript => (
            r"(?i)(?:prompt|readline|URLSearchParams\.get|Request\.(?:get|json|text)|localStorage\.getItem)$",
            r"(?i)(?:eval|Function|child_process\.(?:exec|execSync|spawn)|db\.(?:query|execute)|document\.write)$",
            r"(?i)(?:encodeURIComponent|escapeHtml|sanitize|DOMPurify\.sanitize)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::Sql => (
            r"^sql\.select$",
            r"^sql\.(?:insert|update|delete|execute|merge|call)$",
            r"^sql\.(?:quote|parameterize)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::Php => (
            r"(?i)(?:getenv|filter_input|readline|file_get_contents|php\.superglobal\.(?:GET|POST|COOKIE|REQUEST|FILES|SERVER|ENV))$",
            r"(?i)(?:eval|system|exec|shell_exec|passthru|mysqli_query|PDO\.(?:query|exec))$",
            r"(?i)(?:htmlspecialchars|urlencode|mysqli_real_escape_string|escapeshellarg)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::Ruby => (
            r"(?i)(?:gets|readline|ENV\.(?:fetch|get)|params\.(?:fetch|get))$",
            r"(?i)(?:eval|system|exec|spawn|Open3\..*|connection\.(?:execute|select_all))$",
            r"(?i)(?:ERB::Util\.html_escape|CGI\.escape|sanitize|quote)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::Rust => (
            r"(?i)(?:std::env::var|env::var|var|read_line|read_to_string|Request.*body|body)$",
            r"(?i)(?:Command::new|std::process::Command::new|sqlx::query!?|sqlx_query!|Connection\.execute|Html\.from_html_unchecked)$",
            r"(?i)(?:urlencoding::encode|html_escape|escape_default|sanitize)$",
            Port::Return,
            Port::Arg(0),
        ),
        Language::Shell => (
            r"(?i)(?:read|readarray|mapfile)$",
            r"(?i)(?:eval|bash|sh|zsh|source|curl|wget|ssh)$",
            r"(?i)(?:printf|shellescape)$",
            Port::Arg(0),
            Port::Arg(0),
        ),
        _ => return RuleSet::default(),
    };

    let prefix = language.as_str();
    RuleSet {
        metadata: Vec::new(),
        sink_reports: Vec::new(),
        index_sinks: Vec::new(),
        sources: vec![SourceRule {
            id: format!("{prefix}-portable-untrusted-input"),
            language: Some(language.clone()),
            matcher: ApiMatcher {
                regex: Some(source_pattern.to_string()),
                ..Default::default()
            },
            out: source_port,
            kind: "generic".to_string(),
        }],
        sinks: vec![SinkRule {
            id: format!("{prefix}-portable-dangerous-operation"),
            language: Some(language.clone()),
            matcher: ApiMatcher {
                regex: Some(sink_pattern.to_string()),
                ..Default::default()
            },
            inputs: vec![sink_port],
            kind: "generic".to_string(),
        }],
        unused_return_sinks: vec![],
        sanitizers: vec![SanitizerRule {
            id: format!("{prefix}-portable-encoding"),
            language: Some(language.clone()),
            matcher: ApiMatcher {
                regex: Some(sanitizer_pattern.to_string()),
                ..Default::default()
            },
            inputs: vec![Port::Arg(0)],
            outputs: vec![Port::Return],
            kind: "generic".to_string(),
        }],
        propagators: vec![PropagatorRule {
            id: format!("{prefix}-portable-builder-flow"),
            language: Some(language.clone()),
            matcher: ApiMatcher {
                method_regex: Some(
                    r"(?i)^(?:append|concat|format|join|replace|write|add)$".to_string(),
                ),
                ..Default::default()
            },
            flows: vec![
                FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                },
                FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Receiver,
                },
            ],
        }],
        summaries: vec![],
        sink_conditions: vec![],
        call_conditions: vec![],
        taint_transforms: vec![],
        field_sources: vec![],
        named_value_sources: vec![],
        field_sinks: vec![],
        field_sanitizers: vec![],
        function_sources: vec![],
        function_sinks: vec![],
        native_dataflow_rules: vec![],
        model_dependencies: vec![],
    }
}
