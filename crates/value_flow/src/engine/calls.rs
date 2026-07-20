fn resolve_dynamic_internal_calls(
    fg: &mut FlowGraph,
    program: &Program,
    func_index: &FunctionIndex<'_>,
    rules: &RuleSet,
) {
    for func in &program.functions {
        let ret_node = *fg
            .function_returns
            .get(&func.id)
            .expect("return node must exist");
        for block in &func.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else {
                    continue;
                };
                let Callee::Dynamic(callee_value) = &call.callee else {
                    continue;
                };
                let Some(existing_meta) = fg.call_meta.get(&(func.id, inst.id)).cloned() else {
                    continue;
                };
                let mut resolved_targets = Vec::new();
                let mut candidates = Vec::new();
                if let Some(ty) = fg.value_types.get(&(func.id, *callee_value)) {
                    if looks_like_project_callable_type(ty) {
                        candidates.push(ty.clone());
                    }
                }
                candidates.extend(infer_dynamic_callee_names(fg, func.id, *callee_value, 64));
                candidates.sort();
                candidates.dedup();
                for name in candidates {
                    for callee_func in func_index.resolve_named_callable(
                        &name,
                        existing_meta.arg_count,
                        &existing_meta.arg_types,
                        &existing_meta.arg_type_candidates,
                    ) {
                        if !resolved_targets.iter().any(|existing| existing == &callee_func.name) {
                            resolved_targets.push(callee_func.name.clone());
                        }
                        connect_internal_call(fg, func.id, inst.id, call, callee_func, ret_node);
                    }
                }
                if resolved_targets.is_empty() {
                    for callee_func in func_index.resolve_call(&existing_meta) {
                        if !resolved_targets.iter().any(|existing| existing == &callee_func.name) {
                            resolved_targets.push(callee_func.name.clone());
                        }
                        connect_internal_call(fg, func.id, inst.id, call, callee_func, ret_node);
                    }
                }
                if resolved_targets.is_empty() {
                    continue;
                }
                fg.resolved_internal_targets
                    .insert((func.id, inst.id), resolved_targets.clone());
                if resolved_targets.len() == 1 {
                    let mut updated = existing_meta;
                    updated.callee_name = resolved_targets.first().cloned();
                    if let Some(name) = updated.callee_name.as_deref() {
                        let info = CallInfo::from_callee_name(name);
                        if updated.receiver_type.is_none() {
                            updated.receiver_type = info.receiver_type;
                        }
                        updated.method_name = info.method_name;
                    }
                    fg.call_meta.insert((func.id, inst.id), updated.clone());
                    connect_rule_summaries(fg, rules, func.id, inst.id, &updated);
                    attach_rule_sources_and_sinks(fg, rules, func.id, inst.id, &updated);
                }
            }
        }
    }
}


fn infer_dynamic_callee_names(
    fg: &FlowGraph,
    func: FunctionId,
    value: ValueId,
    max_depth: usize,
) -> Vec<String> {
    let query = DemandQuery {
        seeds: vec![DemandSeed::Value {
            func: func.0,
            value: value.0,
        }],
        direction: SparseDirection::Backward,
        engine: DemandEngine::Fixpoint,
        include_heap: true,
    };
    let summary = fg
        .contextual_demand_query_summary_auto(&query, max_depth, usize::MAX)
        .or_else(|| fg.demand_query_summary_auto(&query))
        .or_else(|| fg.demand_query_summary(&query, max_depth, usize::MAX))
        .unwrap_or_default();
    let mut out = Vec::new();
    for (func_id, value_id) in &summary.values {
        let func_id = FunctionId(*func_id);
        let value_id = ValueId(*value_id);
        let precise = precise_value_object_id(fg, func_id, value_id).is_some()
            || fg.value_points_to_object_ids_of(func_id, value_id).len() == 1;
        if !precise {
            continue;
        }
        if let Some(ty) = fg.value_types.get(&(func_id, value_id)) {
            if looks_like_project_callable_type(ty) {
                out.push(ty.clone());
            }
        }
    }
    for (func_id, _index, value_id) in &summary.params {
        let func_id = FunctionId(*func_id);
        let value_id = ValueId(*value_id);
        let precise = precise_value_object_id(fg, func_id, value_id).is_some()
            || fg.value_points_to_object_ids_of(func_id, value_id).len() == 1;
        if !precise {
            continue;
        }
        if let Some(ty) = fg.value_types.get(&(func_id, value_id)) {
            if looks_like_project_callable_type(ty) {
                out.push(ty.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn looks_like_project_callable_type(name: &str) -> bool {
    !name.is_empty()
        && name.contains('.')
        && !name.contains('<')
        && !name.ends_with("#ret")
        && name
            .split('.')
            .next_back()
            .is_some_and(|tail| tail.chars().next().is_some_and(|ch| ch.is_ascii_lowercase() || ch == '_'))
}

fn connect_rule_summaries(fg: &mut FlowGraph, rules: &RuleSet, func: FunctionId, inst: InstId, meta: &CallMeta) {
    let Some(call_info) = meta.as_call_info() else {
        return;
    };

    for rule in &rules.propagators {
        if language_matches(&rule.language, &fg.language) && rule.matcher.matches_call(&call_info) {
            connect_flow_specs(
                fg,
                func,
                inst,
                &call_info.callee_name,
                &rule.id,
                &rule.flows,
            );
        }
    }
    for rule in &rules.summaries {
        if language_matches(&rule.language, &fg.language) && rule.matcher.matches_call(&call_info) {
            connect_flow_specs(
                fg,
                func,
                inst,
                &call_info.callee_name,
                &rule.id,
                &rule.flows,
            );
        }
    }
}

fn connect_flow_specs(
    fg: &mut FlowGraph,
    func: FunctionId,
    inst: InstId,
    callee_name: &str,
    rule_id: &str,
    flows: &[FlowSpec],
) {
    for flow in flows {
        let from = get_or_create_call_port(
            fg,
            func,
            inst,
            flow.from.clone(),
            Some(callee_name.to_string()),
        );
        let to = get_or_create_call_port(
            fg,
            func,
            inst,
            flow.to.clone(),
            Some(callee_name.to_string()),
        );
        fg.graph.add_edge(
            from,
            to,
            FlowEdge {
                kind: EdgeKind::Summary {
                    rule_id: rule_id.to_string(),
                },
            },
        );
    }
}

fn attach_rule_sources_and_sinks(
    fg: &mut FlowGraph,
    rules: &RuleSet,
    func: FunctionId,
    inst: InstId,
    meta: &CallMeta,
) {
    let Some(call_info) = meta.as_call_info() else {
        return;
    };

    for rule in &rules.sources {
        if language_matches(&rule.language, &fg.language) && rule.matcher.matches_call(&call_info) {
            let src = fg.graph.add_node(FlowNode::SyntheticSource {
                func,
                inst,
                rule_id: rule.id.clone(),
                kind: rule.kind.clone(),
                out: rule.out.clone(),
            });
            fg.synthetic_sources.push(src);
            let out_port = get_or_create_call_port(
                fg,
                func,
                inst,
                rule.out.clone(),
                Some(call_info.callee_name.clone()),
            );
            fg.graph.add_edge(
                src,
                out_port,
                FlowEdge {
                    kind: EdgeKind::Source {
                        rule_id: rule.id.clone(),
                    },
                },
            );
        }
    }

    for rule in &rules.sinks {
        if language_matches(&rule.language, &fg.language) && rule.matcher.matches_call(&call_info) {
            for input in &rule.inputs {
                let sink = fg.graph.add_node(FlowNode::SyntheticSink {
                    func,
                    inst,
                    rule_id: rule.id.clone(),
                    kind: rule.kind.clone(),
                    input: input.clone(),
                });
                fg.synthetic_sinks.push(sink);
                let in_port = get_or_create_call_port(
                    fg,
                    func,
                    inst,
                    input.clone(),
                    Some(call_info.callee_name.clone()),
                );
                fg.graph.add_edge(
                    in_port,
                    sink,
                    FlowEdge {
                        kind: EdgeKind::Sink {
                            rule_id: rule.id.clone(),
                        },
                    },
                );
            }
        }
    }
}

fn get_or_create_call_port(
    fg: &mut FlowGraph,
    func: FunctionId,
    inst: InstId,
    port: Port,
    callee_name: Option<String>,
) -> NodeIndex {
    if let Some(existing) = fg.call_ports.get(&(func, inst, port.clone())).copied() {
        if let Some(name) = callee_name {
            if let FlowNode::CallPort { callee_name: slot, .. } = &mut fg.graph[existing] {
                if slot.is_none() {
                    *slot = Some(name);
                }
            }
        }
        return existing;
    }
    let node = fg.graph.add_node(FlowNode::CallPort {
        func,
        inst,
        port: port.clone(),
        callee_name,
    });
    fg.call_ports.insert((func, inst, port), node);
    node
}

fn static_callee_name(call: &CallInst) -> Option<String> {
    match &call.callee {
        Callee::Static(name) => Some(name.clone()),
        Callee::Dynamic(_) | Callee::Unknown => None,
    }
}

fn build_call_meta(fg: &FlowGraph, func: &Function, inst: InstId, call: &CallInst, span: Span) -> CallMeta {
    let callee_name = static_callee_name(call);
    let mut receiver_type = call
        .receiver
        .and_then(|value| fg.value_types.get(&(func.id, value)).cloned());
    if matches!(&fg.language, Language::Cpp) {
        receiver_type = receiver_type.map(|ty| cpp_receiver_owner_type(&ty));
    }
    let mut method_name = None;

    if let Some(name) = callee_name.as_deref() {
        let info = CallInfo::from_callee_name(name);
        if receiver_type.is_none() {
            receiver_type = info.receiver_type;
        }
        method_name = info.method_name;
    }

    let receiver_type_candidates = receiver_type
        .as_deref()
        .map(|ty| expand_receiver_type_candidates(&fg.type_hierarchy, ty, false))
        .unwrap_or_default();
    let arg_types = call
        .args
        .iter()
        .map(|value| fg.value_types.get(&(func.id, *value)).cloned())
        .collect::<Vec<_>>();
    let arg_type_candidates = arg_types
        .iter()
        .map(|ty| {
            ty.as_deref()
                .map(|name| expand_receiver_type_candidates(&fg.type_hierarchy, name, false))
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();

    CallMeta {
        func: func.id,
        inst,
        function_name: func.name.clone(),
        callee_name,
        receiver_type,
        receiver_type_candidates,
        method_name,
        arg_count: call.args.len(),
        arg_types,
        arg_type_candidates,
        span,
    }
}

fn cpp_receiver_owner_type(value: &str) -> String {
    let mut normalized = value
        .replace("std::", "")
        .replace("const ", "")
        .replace("volatile ", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches("&&")
        .trim_end_matches('&')
        .trim()
        .to_string();
    if let Some(open) = normalized.find('<') {
        let wrapper = normalized[..open].trim();
        if matches!(wrapper, "unique_ptr" | "shared_ptr" | "weak_ptr") {
            if let Some(close) = normalized.rfind('>') {
                normalized = normalized[open + 1..close].trim().to_string();
            }
        }
    }
    normalized
        .trim_end_matches('*')
        .trim()
        .to_string()
}

fn expand_receiver_type_candidates(
    type_hierarchy: &HashMap<String, Vec<String>>,
    ty: &str,
    include_descendants: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![ty.to_string()];
    while let Some(cur) = stack.pop() {
        if out.iter().any(|existing| existing == &cur) {
            continue;
        }
        if let Some(parents) = type_hierarchy.get(&cur) {
            for parent in parents {
                stack.push(parent.clone());
            }
        }
        out.push(cur);
    }
    if include_descendants {
        let mut changed = true;
        while changed {
            changed = false;
            for (child, parents) in type_hierarchy {
                if parents.iter().any(|parent| out.iter().any(|known| known == parent))
                    && !out.iter().any(|known| known == child)
                {
                    out.push(child.clone());
                    changed = true;
                }
            }
        }
    }
    out
}


