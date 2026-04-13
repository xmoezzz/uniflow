use uniflow_hir::Language;
use uniflow_models::default_models_for;
use uniflow_rules::{CallInfo, Port};

fn python_call(callee: &str, receiver_type: Option<&str>, method_name: &str, arg_count: usize) -> CallInfo {
    let receiver_type = receiver_type.map(|s| s.to_string());
    let receiver_type_candidates = receiver_type.iter().cloned().collect::<Vec<_>>();
    CallInfo::new(
        callee,
        receiver_type,
        receiver_type_candidates,
        Some(method_name.to_string()),
        Some(arg_count),
        vec![None; arg_count],
        vec![Vec::new(); arg_count],
    )
}

#[test]
fn python_list_pop_propagates_receiver_to_return() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .propagators
        .iter()
        .find(|rule| rule.id == "python-list-pop")
        .expect("python list.pop propagator");
    let call = python_call("items.pop", Some("list"), "pop", 0);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Receiver)));
}

#[test]
fn python_dict_update_propagates_argument_into_receiver() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .propagators
        .iter()
        .find(|rule| rule.id == "python-dict-update")
        .expect("python dict.update propagator");
    let call = python_call("payload.update", Some("dict"), "update", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Receiver)));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Receiver)));
}

#[test]
fn python_json_dumps_summarizes_first_argument_into_return() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-json-dumps")
        .expect("python json.dumps summary");
    let call = python_call("json.dumps", Some("json"), "dumps", 1);
    assert!(rule.matcher.matches_call(&call));
    assert_eq!(rule.flows.len(), 1);
    let only = &rule.flows[0];
    assert!(matches!(only.from, Port::Arg(0)));
    assert!(matches!(only.to, Port::Return));
}


#[test]
fn python_list_extend_propagates_argument_into_receiver() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .propagators
        .iter()
        .find(|rule| rule.id == "python-list-extend")
        .expect("python list.extend propagator");
    let call = python_call("items.extend", Some("list"), "extend", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Receiver)));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Receiver)));
}

#[test]
fn python_dict_get_summarizes_receiver_into_return() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-dict-get")
        .expect("python dict.get summary");
    let call = python_call("payload.get", Some("dict"), "get", 1);
    assert!(rule.matcher.matches_call(&call));
    assert_eq!(rule.flows.len(), 1);
    let only = &rule.flows[0];
    assert!(matches!(only.from, Port::Receiver));
    assert!(matches!(only.to, Port::Return));
}

#[test]
fn python_copy_copy_summarizes_first_argument_into_return() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-copy-copy")
        .expect("python copy.copy summary");
    let call = python_call("copy.copy", Some("copy"), "copy", 1);
    assert!(rule.matcher.matches_call(&call));
    assert_eq!(rule.flows.len(), 1);
    let only = &rule.flows[0];
    assert!(matches!(only.from, Port::Arg(0)));
    assert!(matches!(only.to, Port::Return));
}


#[test]
fn python_comprehension_summaries_flow_into_return() {
    let rules = default_models_for(Language::Python);
    let list_rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-list-comp")
        .expect("python list comp summary");
    let list_call = python_call("builtins.list_comp", None, "list_comp", 2);
    assert!(list_rule.matcher.matches_call(&list_call));
    assert!(list_rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
    assert!(list_rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(1)) && matches!(flow.to, Port::Return)));

    let dict_rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-dict-comp")
        .expect("python dict comp summary");
    let dict_call = python_call("builtins.dict_comp", None, "dict_comp", 3);
    assert!(dict_rule.matcher.matches_call(&dict_call));
    assert!(dict_rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(2)) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_fastapi_path_params_is_a_source() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .sources
        .iter()
        .find(|rule| rule.id == "python-fastapi-path-params")
        .expect("python fastapi path params source");
    let call = python_call("request.path_params.get", Some("starlette.request.path_params"), "get", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(matches!(rule.out, Port::Return));
}

#[test]
fn python_pydantic_model_dump_flows_receiver_to_return() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-pydantic-model-dump")
        .expect("python pydantic model_dump summary");
    let call = python_call("payload.model_dump", Some("app.Payload"), "model_dump", 0);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_dataclasses_asdict_flows_argument_to_return() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-dataclasses-asdict")
        .expect("python dataclasses.asdict summary");
    let call = python_call("dataclasses.asdict", Some("dataclasses"), "asdict", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_current_app_config_get_is_modeled() {
    let rules = default_models_for(Language::Python);
    let source = rules
        .sources
        .iter()
        .find(|rule| rule.id == "python-flask-current-app-config-get")
        .expect("python current_app.config source");
    let source_call = python_call("current_app.config.get", Some("flask.current_app.config"), "get", 1);
    assert!(source.matcher.matches_call(&source_call));

    let summary = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-flask-current-app-config-get-summary")
        .expect("python current_app.config summary");
    assert!(summary.matcher.matches_call(&source_call));
    assert!(summary.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_sqlalchemy_query_chain_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-sqlalchemy-query-chain-heuristic")
        .expect("python sqlalchemy query chain summary");
    let call = python_call("query.filter", Some("sqlalchemy.orm.Query"), "filter", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_fastapi_query_wrapper_is_modeled() {
    let rules = default_models_for(Language::Python);
    let source = rules
        .sources
        .iter()
        .find(|rule| rule.id == "python-fastapi-query-param-wrapper")
        .expect("python fastapi query source");
    let call = python_call("fastapi.Query", Some("fastapi"), "Query", 1);
    assert!(source.matcher.matches_call(&call));

    let summary = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-fastapi-param-wrapper-summary")
        .expect("python fastapi query summary");
    assert!(summary.matcher.matches_call(&call));
    assert!(summary.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_sqlalchemy_session_factory_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-sqlalchemy-session-factory")
        .expect("python sqlalchemy session factory summary");
    let call = python_call("sqlalchemy.orm.sessionmaker", Some("sqlalchemy.orm"), "sessionmaker", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_pydantic_validate_family_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-pydantic-validate-family")
        .expect("python pydantic validate summary");
    let call = python_call("Payload.model_validate", Some("pydantic.BaseModel"), "model_validate", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}


#[test]
fn python_fastapi_depends_summary_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-fastapi-depends")
        .expect("python fastapi depends summary");
    let call = python_call("fastapi.Depends", Some("fastapi"), "Depends", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_contextvar_get_is_modeled() {
    let rules = default_models_for(Language::Python);
    let source = rules
        .sources
        .iter()
        .find(|rule| rule.id == "python-contextvar-get")
        .expect("python contextvar source");
    let call = python_call("ctx.get", Some("contextvars.ContextVar"), "get", 0);
    assert!(source.matcher.matches_call(&call));

    let summary = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-contextvar-get-summary")
        .expect("python contextvar summary");
    assert!(summary.matcher.matches_call(&call));
    assert!(summary.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_sqlalchemy_result_fetch_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-sqlalchemy-result-fetch")
        .expect("python sqlalchemy result summary");
    let call = python_call("result.scalar_one", Some("sqlalchemy.engine.Result"), "scalar_one", 0);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_django_cookies_get_is_a_source() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .sources
        .iter()
        .find(|rule| rule.id == "python-django-request-cookies-get")
        .expect("python django cookies source");
    let call = python_call("request.COOKIES.get", Some("django.request.COOKIES"), "get", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(matches!(rule.out, Port::Return));
}


#[test]
fn python_fastapi_uploadfile_read_is_modeled() {
    let rules = default_models_for(Language::Python);
    let source = rules
        .sources
        .iter()
        .find(|rule| rule.id == "python-fastapi-uploadfile-read")
        .expect("python fastapi uploadfile source");
    let call = python_call("upload.read", Some("fastapi.UploadFile"), "read", 0);
    assert!(source.matcher.matches_call(&call));

    let summary = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-fastapi-uploadfile-read-summary")
        .expect("python fastapi uploadfile summary");
    assert!(summary.matcher.matches_call(&call));
    assert!(summary.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_backgroundtasks_add_task_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-fastapi-backgroundtasks-add-task")
        .expect("python backgroundtasks summary");
    let call = python_call("tasks.add_task", Some("fastapi.BackgroundTasks"), "add_task", 3);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Receiver)));
}

#[test]
fn python_request_multidict_getlist_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-request-multidict-getlist")
        .expect("python request multidict summary");
    let call = python_call("request.query_params.getlist", Some("starlette.datastructures.QueryParams"), "getlist", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}


#[test]
fn python_django_queryset_distinct_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-django-queryset-chain-heuristic")
        .expect("python django queryset chain summary");
    let call = python_call("queryset.distinct", Some("django.db.models.QuerySet"), "distinct", 0);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_sqlalchemy_contains_eager_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-sqlalchemy-relationship")
        .expect("python sqlalchemy relationship summary");
    let call = python_call("sqlalchemy.orm.contains_eager", Some("sqlalchemy.orm"), "contains_eager", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}


#[test]
fn python_request_multidict_get_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-request-multidict-get")
        .expect("python request multidict get summary");
    let call = python_call("request.query_params.get", Some("starlette.datastructures.QueryParams"), "get", 2);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_request_multidict_view_methods_are_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-request-multidict-views")
        .expect("python request multidict view summary");
    let call = python_call("request.headers.items", Some("starlette.datastructures.Headers"), "items", 0);
    assert!(rule.matcher.matches_call(&call));
}

#[test]
fn python_django_queryset_bulk_ops_are_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-django-queryset-bulk-ops")
        .expect("python django queryset bulk summary");
    let call = python_call("queryset.bulk_create", Some("django.db.models.QuerySet"), "bulk_create", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}


#[test]
fn python_contextvar_set_propagates_argument_into_receiver() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .propagators
        .iter()
        .find(|rule| rule.id == "python-contextvar-set")
        .expect("python contextvar.set propagator");
    let call = python_call("ctx.set", Some("contextvars.ContextVar"), "set", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Receiver)));
}

#[test]
fn python_django_related_shape_chain_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-django-related-shape-chain")
        .expect("python django related chain summary");
    let call = python_call("author.books.select_related", Some("django.db.models.ManyRelatedManager"), "select_related", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_sqlalchemy_session_commit_shape_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-sqlalchemy-session-commit-shape")
        .expect("python sqlalchemy session commit summary");
    let call = python_call("session.commit", Some("sqlalchemy.orm.Session"), "commit", 0);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}


#[test]
fn python_fastapi_websocket_receive_summary_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-fastapi-websocket-receive-summary")
        .expect("python fastapi websocket summary");
    let call = python_call("ws.receive_text", Some("starlette.websockets.WebSocket"), "receive_text", 0);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_django_transaction_atomic_summary_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-django-transaction-atomic-summary")
        .expect("python django transaction summary");
    let call = python_call("django.db.transaction.atomic", None, "atomic", 2);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_queryset_select_for_update_and_session_expire_are_modeled() {
    let rules = default_models_for(Language::Python);
    let queryset = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-django-queryset-chain-heuristic")
        .expect("python django queryset chain summary");
    let qs_call = python_call("queryset.select_for_update", Some("django.db.models.QuerySet"), "select_for_update", 0);
    assert!(queryset.matcher.matches_call(&qs_call));
    let session = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-sqlalchemy-session-mutators")
        .expect("python sqlalchemy session mutators");
    let session_call = python_call("session.expire", Some("sqlalchemy.orm.Session"), "expire", 1);
    assert!(session.matcher.matches_call(&session_call));
}


#[test]
fn python_fastapi_websocket_send_summary_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-fastapi-websocket-send-summary")
        .expect("python fastapi websocket send summary");
    let call = python_call("ws.send_text", Some("starlette.websockets.WebSocket"), "send_text", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Receiver)));
}

#[test]
fn python_sqlalchemy_result_shape_chain_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-sqlalchemy-result-shape-chain")
        .expect("python sqlalchemy result shape summary");
    let call = python_call("result.columns", Some("sqlalchemy.engine.Result"), "columns", 1);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(0)) && matches!(flow.to, Port::Return)));
}

#[test]
fn python_django_queryset_values_shape_is_modeled() {
    let rules = default_models_for(Language::Python);
    let rule = rules
        .summaries
        .iter()
        .find(|rule| rule.id == "python-django-queryset-values-shape")
        .expect("python django queryset values shape summary");
    let call = python_call("queryset.values", Some("django.db.models.QuerySet"), "values", 2);
    assert!(rule.matcher.matches_call(&call));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Receiver) && matches!(flow.to, Port::Return)));
    assert!(rule.flows.iter().any(|flow| matches!(flow.from, Port::Arg(1)) && matches!(flow.to, Port::Return)));
}
