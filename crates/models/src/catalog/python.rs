fn python_models() -> RuleSet {
    RuleSet {
        loop_sinks: Vec::new(),
        metadata: Vec::new(),
        sink_reports: Vec::new(),
        index_sinks: Vec::new(),
        call_site_sources: Vec::new(),
        call_site_sinks: Vec::new(),
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
            // Werkzeug multidict accessors beyond `.get` (`getlist("x")`,
            // `to_dict()`, `keys()`/`values()`/`items()`, `lists()`): every
            // key and value they return is client-controlled.
            SourceRule {
                id: "python-flask-request-multidict-accessors".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r"^flask\.request\.(args|form|values|headers|cookies|files)$".to_string()),
                    method_regex: Some(r"^(getlist|to_dict|keys|values|items|lists)$".to_string()),
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
            // XPath evaluation over lxml trees/elements and compiled
            // `etree.XPath(...)` expressions: the expression string (arg 0).
            SinkRule {
                id: "python-lxml-xpath".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher { method_regex: Some(r"^(xpath|evaluate)$".to_string()), ..Default::default() },
                inputs: vec![Port::Arg(0)],
                kind: "xpath".to_string(),
            },
            SinkRule {
                id: "python-lxml-xpath-compile".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher { regex: Some(r"^(lxml\.)?etree\.(XPath|ETXPath|XPathEvaluator)$".to_string()), ..Default::default() },
                inputs: vec![Port::Arg(0)],
                kind: "xpath".to_string(),
            },
            // LDAP search filters: ldap3 `Connection.search(base, filter)`
            // and python-ldap `search_s/search_st/search_ext(_s)(base, scope,
            // filterstr)`; the search base is attacker-steerable too.
            SinkRule {
                id: "python-ldap3-search".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    receiver_regex: Some(r"(^|\.)ldap3(\.core\.connection)?\.Connection$".to_string()),
                    method_name: Some("search".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0), Port::Arg(1), Port::NamedArg("search_filter".to_string())],
                kind: "ldap".to_string(),
            },
            SinkRule {
                id: "python-ldap-search".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher { method_regex: Some(r"^search(_s|_st|_ext|_ext_s)$".to_string()), ..Default::default() },
                inputs: vec![Port::Arg(0), Port::Arg(2), Port::NamedArg("filterstr".to_string())],
                kind: "ldap".to_string(),
            },
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
            // `str`/`bytes` methods whose result is (part of) the receiver's
            // data, matched by name so they also apply when the receiver's
            // type isn't inferred (`request.path.split("/")`,
            // `request.query_string.decode()`). `replace`/`translate` are
            // deliberately absent: they carry sanitizer semantics elsewhere.
            SummaryRule {
                id: "python-string-methods".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    method_regex: Some(
                        r"^(split|rsplit|splitlines|partition|rpartition|decode|encode|strip|lstrip|rstrip|lower|upper|casefold|title|capitalize|swapcase|removeprefix|removesuffix|zfill|center|ljust|rjust|expandtabs|format_map)$"
                            .to_string(),
                    ),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Receiver, to: Port::Return }],
            },
            // URL decoding and parsing return the input's (decoded) content.
            SummaryRule {
                id: "python-urllib-parse-decoders".to_string(),
                language: Some(Language::Python),
                matcher: ApiMatcher {
                    regex: Some(r"^urllib\.parse\.(unquote|unquote_plus|unquote_to_bytes|parse_qs|parse_qsl|urlparse|urlsplit|urljoin)$".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec { from: Port::Arg(0), to: Port::Return }, FlowSpec { from: Port::Arg(1), to: Port::Return }],
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
        sink_conditions: Vec::new(),
        call_conditions: Vec::new(),
        taint_transforms: Vec::new(),
        // Attributes of Flask's request proxy that carry client-controlled
        // data directly (no accessor call): the path, the raw query string
        // and body, and the multidict/header containers themselves, whose
        // accessors (`getlist`, `keys()`, iteration) then inherit the taint.
        field_sources: [
            "path", "full_path", "url", "base_url", "url_root", "query_string", "data", "stream", "json", "files", "args", "form", "values", "headers", "cookies",
        ]
        .into_iter()
        .map(|field| FieldSourceRule {
            id: format!("python-flask-request-field-{field}"),
            language: Some(Language::Python),
            matcher: FieldMatcher { owner: Some("flask.request".to_string()), owner_regex: None, field: field.to_string() },
            kind: "generic".to_string(),
        })
        .collect(),
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
