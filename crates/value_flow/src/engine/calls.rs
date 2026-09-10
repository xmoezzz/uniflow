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
                        if !resolved_targets
                            .iter()
                            .any(|existing| existing == &callee_func.name)
                        {
                            resolved_targets.push(callee_func.name.clone());
                        }
                        connect_internal_call(fg, func.id, inst.id, call, callee_func, ret_node);
                    }
                }
                if resolved_targets.is_empty() {
                    for callee_func in func_index.resolve_call(&existing_meta) {
                        if !resolved_targets
                            .iter()
                            .any(|existing| existing == &callee_func.name)
                        {
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
                    connect_rule_summaries(fg, rules, func.id, inst.id, call, &updated);
                    attach_rule_sources_and_sinks(fg, rules, func.id, inst.id, call, &updated);
                }
            }
        }
    }
}

/// Follow explicit local value/cell edges, not the region overlay. A known
/// callable address does not need a singleton *heap* points-to set. The latter
/// also contains its container and must not be used to reject the address.
fn explicit_local_callee_names(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    let Some(&seed) = fg.values.get(&(func, value)) else { return Vec::new(); };
    let mut pending = vec![seed];
    let mut visited = HashSet::new();
    let mut names = BTreeSet::new();
    while let Some(node) = pending.pop() {
        if !visited.insert(node) { continue; }
        match &fg.graph[node] {
            FlowNode::Value { func: owner, value } | FlowNode::Param { func: owner, value, .. } if *owner == func => {
                if let Some(name) = fg.value_types.get(&(*owner, *value)) {
                    if fg.function_names.values().any(|candidate| candidate == name) {
                        names.insert(name.clone());
                    }
                }
            }
            FlowNode::FieldCell { func: owner, .. } | FlowNode::IndexCell { func: owner, .. } if *owner == func => {}
            _ => continue,
        }
        for edge in fg.graph.edges_directed(node, petgraph::Direction::Incoming) {
            if matches!(edge.weight().kind,
                EdgeKind::Assign | EdgeKind::Phi | EdgeKind::LoadField { .. } |
                EdgeKind::LoadIndex | EdgeKind::StoreField { .. } | EdgeKind::StoreIndex |
                EdgeKind::ActualToFormal | EdgeKind::FormalToActual)
            {
                pending.push(edge.source());
            }
        }
    }
    names.into_iter().collect()
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
    let mut out = explicit_local_callee_names(fg, func, value);
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
    name.starts_with("__uniflow_lambda_")
        || (!name.is_empty()
            && name.contains('.')
            && !name.contains('<')
            && !name.ends_with("#ret")
            && name.split('.').next_back().is_some_and(|tail| {
                tail.chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_lowercase() || ch == '_')
            }))
}

fn connect_rule_summaries(
    fg: &mut FlowGraph,
    rules: &RuleSet,
    func: FunctionId,
    inst: InstId,
    call: &CallInst,
    meta: &CallMeta,
) {
    let Some(call_info) = meta.as_call_info() else {
        return;
    };

    for rule in &rules.propagators {
        if language_matches(&rule.language, &fg.language)
            && rule.matcher.matches_call(&call_info)
            && rules.call_condition_matches(&rule.id, &call_info)
        {
            connect_flow_specs(
                fg,
                func,
                inst,
                &call_info.callee_name,
                &rule.id,
                &rule.flows,
                call_info.arg_count.unwrap_or(0),
                call,
            );
        }
    }
    for rule in &rules.summaries {
        if language_matches(&rule.language, &fg.language)
            && rule.matcher.matches_call(&call_info)
            && rules.call_condition_matches(&rule.id, &call_info)
        {
            connect_flow_specs(
                fg,
                func,
                inst,
                &call_info.callee_name,
                &rule.id,
                &rule.flows,
                call_info.arg_count.unwrap_or(0),
                call,
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
    arg_count: usize,
    call: &CallInst,
) {
    for flow in flows {
        for from_port in expand_port(&flow.from, arg_count) {
            for to_port in expand_port(&flow.to, arg_count) {
                let Some(from) = get_or_create_rule_port(
                    fg,
                    func,
                    inst,
                    call.receiver,
                    from_port.clone(),
                    Some(callee_name.to_string()),
                ) else {
                    continue;
                };
                let Some(to) = get_or_create_rule_port(
                    fg,
                    func,
                    inst,
                    call.receiver,
                    to_port.clone(),
                    Some(callee_name.to_string()),
                ) else {
                    continue;
                };
                fg.graph.add_edge(
                    from,
                    to,
                    FlowEdge {
                        kind: EdgeKind::Summary {
                            rule_id: rule_id.to_string(),
                        },
                    },
                );

                // A flow into a receiver or argument models a write through a
                // mutable call port. Join that output back into the underlying
                // SSA value so a later call using the same object observes the
                // mutation (for example Map.put(value) followed by a bulk sink).
                let written_value = match &to_port {
                    Port::Receiver => call.receiver,
                    Port::Arg(index) => call.args.get(*index).copied(),
                    Port::NamedArg(name) => call
                        .arg_names
                        .iter()
                        .position(|candidate| candidate.as_deref() == Some(name.as_str()))
                        .and_then(|index| call.args.get(index).copied()),
                    Port::Return
                    | Port::NamedArgOrAll(_)
                    | Port::Member(_)
                    | Port::ArgsFrom(_)
                    | Port::ArgsRange { .. } => None,
                };
                if let Some(value) = written_value {
                    fg.graph.add_edge(
                        to,
                        value_node(fg, func, value),
                        FlowEdge {
                            kind: EdgeKind::CallPortToValue,
                        },
                    );
                }
            }
        }
    }
}

fn attach_rule_sources_and_sinks(
    fg: &mut FlowGraph,
    rules: &RuleSet,
    func: FunctionId,
    inst: InstId,
    call: &CallInst,
    meta: &CallMeta,
) {
    let Some(call_info) = meta.as_call_info() else {
        return;
    };

    for rule in &rules.sources {
        if language_matches(&rule.language, &fg.language)
            && rule.matcher.matches_call(&call_info)
            && rules.call_condition_matches(&rule.id, &call_info)
        {
            for output in expand_port(&rule.out, call.args.len()) {
                let src = fg.graph.add_node(FlowNode::SyntheticSource {
                    func,
                    inst,
                    rule_id: rule.id.clone(),
                    kind: rule.kind.clone(),
                    out: output.clone(),
                });
                fg.synthetic_sources.push(src);
                let Some(out_port) = get_or_create_rule_port(
                    fg,
                    func,
                    inst,
                    call.receiver,
                    output.clone(),
                    Some(call_info.callee_name.clone()),
                ) else {
                    continue;
                };
                fg.graph.add_edge(
                    src,
                    out_port,
                    FlowEdge {
                        kind: EdgeKind::Source {
                            rule_id: rule.id.clone(),
                        },
                    },
                );
                // Return ports already flow into their destination value. Sources
                // that write through an argument or receiver need the symmetric
                // output edge so later statements observe the produced data.
                let written_value = match output {
                    Port::Arg(index) => call.args.get(index).copied(),
                    Port::NamedArg(name) => call
                        .arg_names
                        .iter()
                        .position(|candidate| candidate.as_deref() == Some(name.as_str()))
                        .and_then(|index| call.args.get(index).copied()),
                    Port::Receiver => call.receiver,
                    Port::Return
                    | Port::NamedArgOrAll(_)
                    | Port::Member(_)
                    | Port::ArgsFrom(_)
                    | Port::ArgsRange { .. } => None,
                };
                if let Some(value) = written_value {
                    let dst = value_node(fg, func, value);
                    fg.graph.add_edge(
                        out_port,
                        dst,
                        FlowEdge {
                            kind: EdgeKind::CallPortToValue,
                        },
                    );
                }
            }
        }
    }

    for rule in &rules.sinks {
        if language_matches(&rule.language, &fg.language)
            && rule.matcher.matches_call(&call_info)
            && rules.call_condition_matches(&rule.id, &call_info)
        {
            let report_rule_id = rules.report_id_for_sink(&rule.id).to_string();
            for input in rule
                .inputs
                .iter()
                .flat_map(|input| expand_sink_input(input, call))
            {
                let sink = fg.graph.add_node(FlowNode::SyntheticSink {
                    func,
                    inst,
                    rule_id: report_rule_id.clone(),
                    kind: rule.kind.clone(),
                    input: input.clone(),
                });
                fg.synthetic_sinks.push(sink);
                let Some(in_port) = get_or_create_rule_port(
                    fg,
                    func,
                    inst,
                    call.receiver,
                    input,
                    Some(call_info.callee_name.clone()),
                ) else {
                    continue;
                };
                fg.graph.add_edge(
                    in_port,
                    sink,
                    FlowEdge {
                        kind: EdgeKind::Sink {
                            rule_id: report_rule_id.clone(),
                        },
                    },
                );
            }
        }
    }
}

fn attach_unused_return_sinks(
    fg: &mut FlowGraph,
    rules: &RuleSet,
    func: FunctionId,
    inst: InstId,
    call: &CallInst,
    meta: &CallMeta,
) {
    if meta.return_is_used {
        return;
    }
    let Some(call_info) = meta.as_call_info() else {
        return;
    };
    for rule in &rules.unused_return_sinks {
        if !language_matches(&rule.language, &fg.language)
            || !rules.sources.iter().any(|source| {
                language_matches(&source.language, &fg.language)
                    && source.kind == rule.source_kind
                    && source.out == Port::Return
                    && source.matcher.matches_call(&call_info)
                    && rules.call_condition_matches(&source.id, &call_info)
            })
        {
            continue;
        }
        let sink = fg.graph.add_node(FlowNode::SyntheticSink {
            func,
            inst,
            rule_id: rule.id.clone(),
            kind: rule.kind.clone(),
            input: Port::Return,
        });
        fg.synthetic_sinks.push(sink);
        let return_port = get_or_create_rule_port(
            fg,
            func,
            inst,
            call.receiver,
            Port::Return,
            meta.callee_name.clone(),
        )
        .expect("return ports do not require a receiver");
        fg.graph.add_edge(
            return_port,
            sink,
            FlowEdge {
                kind: EdgeKind::Sink {
                    rule_id: rule.id.clone(),
                },
            },
        );
    }
}

fn expand_sink_input(input: &Port, call: &CallInst) -> Vec<Port> {
    let Port::NamedArgOrAll(name) = input else {
        return expand_port(input, call.args.len());
    };
    if let Some(index) = call
        .arg_names
        .iter()
        .position(|candidate| candidate.as_deref() == Some(name.as_str()))
    {
        vec![Port::Arg(index)]
    } else {
        (0..call.args.len()).map(Port::Arg).collect()
    }
}

fn get_or_create_rule_port(
    fg: &mut FlowGraph,
    func: FunctionId,
    inst: InstId,
    receiver: Option<ValueId>,
    port: Port,
    callee_name: Option<String>,
) -> Option<NodeIndex> {
    if let Port::Member(member) = &port {
        let receiver = receiver?;
        let cell = ensure_field_cell(fg, func, receiver, member);
        fg.call_ports.insert((func, inst, port), cell);
        return Some(cell);
    }
    Some(get_or_create_call_port(fg, func, inst, port, callee_name))
}

fn get_or_create_call_port(
    fg: &mut FlowGraph,
    func: FunctionId,
    inst: InstId,
    port: Port,
    callee_name: Option<String>,
) -> NodeIndex {
    // Legacy JVM models use `receiver` for the object initialized by a
    // constructor. In SSA the same object is the constructor's return value.
    // Give both rule ports one node so sources, sinks and propagators agree.
    if port == Port::Receiver
        && callee_name.as_deref().is_some_and(|name| name.ends_with(".init^") || name == "init^")
    {
        let node = get_or_create_call_port(
            fg, func, inst, Port::Return, callee_name.clone(),
        );
        fg.call_ports.insert((func, inst, Port::Receiver), node);
        return node;
    }
    if let Some(existing) = fg.call_ports.get(&(func, inst, port.clone())).copied() {
        if let Some(name) = callee_name {
            if let FlowNode::CallPort {
                callee_name: slot, ..
            } = &mut fg.graph[existing]
            {
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

/// HIR lowers `new T(...)` as a static call named `T` whose destination has
/// type `T`. Legacy JVM rule packs model the same operation as `T.init^` and
/// attach receiver rules to the newly constructed object. Normalize only the
/// exact lowering shape so ordinary static factories keep their original name.
fn normalized_static_callee_name(
    fg: &FlowGraph,
    func: FunctionId,
    call: &CallInst,
) -> Option<String> {
    let name = static_callee_name(call)?;
    let is_jvm_constructor = matches!(fg.language, Language::Java | Language::Kotlin | Language::Jsp)
        && call.receiver.is_none()
        && call
            .dst
            .and_then(|dst| fg.value_types.get(&(func, dst)))
            .is_some_and(|ty| ty == &name);
    if is_jvm_constructor {
        Some(format!("{name}.init^"))
    } else {
        Some(name)
    }
}

fn build_call_meta(
    fg: &FlowGraph,
    func: &Function,
    inst: InstId,
    call: &CallInst,
    span: Span,
) -> CallMeta {
    let mut callee_name = normalized_static_callee_name(fg, func.id, call);
    let mut receiver_type = call
        .receiver
        .and_then(|value| fg.value_types.get(&(func.id, value)).cloned());
    if matches!(&fg.language, Language::Cpp) {
        receiver_type = receiver_type.map(|ty| cpp_receiver_owner_type(&ty));
    }
    let raw_receiver_constant = call
        .receiver
        .and_then(|value| fg.value_constants.get(&(func.id, value)).cloned());
    let receiver_symbol = raw_receiver_constant
        .as_deref()
        .and_then(external_symbol_name)
        .map(str::to_string)
        .or_else(|| {
            call.receiver
                .and_then(|value| fg.value_names.get(&(func.id, value)))
                .filter(|name| name.starts_with('$'))
                .cloned()
        });
    if let (Some(name), Some(symbol)) = (
        callee_name.as_ref(),
        receiver_symbol.as_deref(),
    ) {
        if !name.starts_with(&format!("{symbol}."))
            && !name.starts_with(&format!("{symbol}::"))
        {
            let method = CallInfo::from_callee_name(name)
                .method_name
                .unwrap_or_else(|| name.clone());
            callee_name = Some(format!("{symbol}.{method}"));
        }
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
    let receiver_parameter = call.receiver.and_then(|receiver| {
        let receiver_root = fg
            .value_alias_roots
            .get(&(func.id, receiver))
            .copied()
            .unwrap_or(receiver);
        func.params.iter().position(|parameter| {
            fg.value_alias_roots
                .get(&(func.id, *parameter))
                .copied()
                .unwrap_or(*parameter)
                == receiver_root
        })
    });
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
    let receiver_constant = raw_receiver_constant.filter(|value| external_symbol_name(value).is_none());
    let arg_constants = call
        .args
        .iter()
        .map(|value| {
            fg.value_constants
                .get(&(func.id, *value))
                .filter(|value| external_symbol_name(value).is_none())
                .cloned()
        })
        .collect::<Vec<_>>();
    let return_is_used = call
        .dst
        .is_some_and(|return_value| function_uses_value(func, return_value));

    CallMeta {
        func: func.id,
        inst,
        function_name: func.name.clone(),
        callee_name,
        receiver_type,
        receiver_type_candidates,
        receiver_parameter,
        method_name,
        arg_count: call.args.len(),
        arg_types,
        arg_type_candidates,
        receiver_constant,
        receiver_symbol,
        arg_constants,
        return_is_used,
        span,
    }
}

fn function_uses_value(func: &Function, value: ValueId) -> bool {
    func.blocks.iter().any(|block| {
        block.insts.iter().any(|inst| match &inst.kind {
            InstKind::ConstInt { .. } | InstKind::ConstString { .. } => false,
            InstKind::Copy { src, .. }
            | InstKind::NumericStep { src, .. }
            | InstKind::Move { src, .. }
            | InstKind::Cast { src, .. } => *src == value,
            InstKind::Lifetime { value: used, .. } => *used == value,
            InstKind::Phi { inputs, .. } => inputs.contains(&value),
            InstKind::LoadField { base, .. } => *base == value,
            InstKind::StoreField { base, src, .. } => *base == value || *src == value,
            InstKind::LoadIndex { base, index, .. } => *base == value || *index == value,
            InstKind::StoreIndex {
                base, index, src, ..
            } => *base == value || *index == value || *src == value,
            InstKind::Call(call) => {
                call.receiver == Some(value)
                    || call.args.contains(&value)
                    || matches!(call.callee, Callee::Dynamic(callee) if callee == value)
            }
        }) || match &block.term {
            Terminator::Branch { cond, .. } => *cond == value,
            Terminator::Return(used) | Terminator::Throw(used) => *used == Some(value),
            Terminator::Goto(_) | Terminator::Unreachable => false,
        }
    })
}

fn external_symbol_name(value: &str) -> Option<&str> {
    value
        .strip_prefix("<external-symbol:")
        .and_then(|value| value.strip_suffix('>'))
        .filter(|value| !value.is_empty())
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
    normalized.trim_end_matches('*').trim().to_string()
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
                if parents
                    .iter()
                    .any(|parent| out.iter().any(|known| known == parent))
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
