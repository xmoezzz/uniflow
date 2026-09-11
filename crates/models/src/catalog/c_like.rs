fn c_like_models(language: Language) -> RuleSet {
    let mut rules = RuleSet {
        metadata: Vec::new(),
        sink_reports: Vec::new(),
        index_sinks: Vec::new(),
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
        sanitizers: vec![SanitizerRule {
            id: "c-sql-escape".to_string(),
            language: Some(language.clone()),
            matcher: ApiMatcher {
                contains: Some("escape".to_string()),
                ..Default::default()
            },
            inputs: vec![Port::Arg(0)],
            outputs: vec![Port::Return],
            kind: "generic".to_string(),
        }],
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
                    FlowSpec {
                        from: Port::Arg(2),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(3),
                        to: Port::Arg(0),
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(2),
                        to: Port::Arg(0),
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
                ],
            },
            SummaryRule {
                id: "c-strstr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strstr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strcasestr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strcasestr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strpbrk".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strpbrk".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-basename".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("basename".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-dirname".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("dirname".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-rawmemchr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("rawmemchr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-memrchr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("memrchr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strchrnul".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strchrnul".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-index".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("index".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-rindex".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("rindex".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-realpath".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("realpath".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strtok".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strtok".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strtok-r".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strtok_r".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(1),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strsep".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strsep".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strdup".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strdup".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strdupa".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strdupa".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strndupa".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strndupa".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-memccpy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("memccpy".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Return,
                    },
                ],
            },
            SummaryRule {
                id: "c-bcopy".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("bcopy".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Arg(1),
                }],
            },
            SummaryRule {
                id: "c-memmem".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("memmem".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strnstr".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strnstr".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            },
            SummaryRule {
                id: "c-strcat".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("strcat".to_string()),
                    ..Default::default()
                },
                flows: vec![
                    FlowSpec {
                        from: Port::Arg(0),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(0),
                        to: Port::Return,
                    },
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
                    FlowSpec {
                        from: Port::Arg(1),
                        to: Port::Arg(0),
                    },
                    FlowSpec {
                        from: Port::Arg(2),
                        to: Port::Arg(0),
                    },
                ],
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
    };

    if matches!(language, Language::C | Language::Cpp) {
        rules.native_dataflow_rules.push(NativeDataflowRule {
            id: "ANZU-ARRAY-INDEX".to_string(),
            language: Some(language.clone()),
        });
        rules.metadata.push(RuleMetadata {
            id: "ANZU-ARRAY-INDEX".to_string(),
            title: "ArrayIndexChecker2".to_string(),
            message: "Array index is less than zero".to_string(),
            severity: "warning".to_string(),
            cwe: Vec::new(),
            standards: vec!["0701000010130047".to_string()],
            translations: RuleTranslations {
                zh_cn: Some(LocalizedRuleText {
                    title: String::new(),
                    message: "数组索引小于0。".to_string(),
                }),
                en: Some(LocalizedRuleText {
                    title: "ArrayIndexChecker2".to_string(),
                    message: "Array index is less than zero".to_string(),
                }),
                zh_tw: None,
            },
        });
        rules.native_dataflow_rules.push(NativeDataflowRule {
            id: "ANZU-ARRAY-BOUND".to_string(),
            language: Some(language.clone()),
        });
        rules.metadata.push(RuleMetadata {
            id: "ANZU-ARRAY-BOUND".to_string(),
            title: "ArrayBoundChecker2".to_string(),
            message: "Array bound read/write exceeds size".to_string(),
            severity: "warning".to_string(),
            cwe: Vec::new(),
            standards: vec![
                "0201000010120009".to_string(),
                "0301000010120009".to_string(),
                "0501000010120009".to_string(),
                "1301000010120009".to_string(),
                "2401000010120009".to_string(),
                "0701000010130046".to_string(),
                "0601000010140037".to_string(),
            ],
            translations: RuleTranslations {
                zh_cn: Some(LocalizedRuleText {
                    title: String::new(),
                    message: "数组读写越界。".to_string(),
                }),
                en: Some(LocalizedRuleText {
                    title: "ArrayBoundChecker2".to_string(),
                    message: "Array bound read/write exceeds size".to_string(),
                }),
                zh_tw: None,
            },
        });
    }

    if matches!(language, Language::Cpp) {
        rules.native_dataflow_rules.push(NativeDataflowRule {
            id: "ANZU-ARGUMENT-VALIDATION".to_string(),
            language: Some(Language::Cpp),
        });
        rules.metadata.push(RuleMetadata {
            id: "ANZU-ARGUMENT-VALIDATION".to_string(),
            title: "ArgumentValidationChecker".to_string(),
            message: "Pointer argument '{}' might be null and should be validated.".to_string(),
            severity: "warning".to_string(),
            cwe: Vec::new(),
            standards: vec!["0101000010110430".to_string()],
            translations: RuleTranslations {
                zh_cn: Some(LocalizedRuleText {
                    title: String::new(),
                    message: "指针参数 ‘{}’需要确认是否为空指针。".to_string(),
                }),
                en: Some(LocalizedRuleText {
                    title: "ArgumentValidationChecker".to_string(),
                    message: "Pointer argument '{}' might be null and should be validated."
                        .to_string(),
                }),
                zh_tw: None,
            },
        });
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
