fn create_function_nodes(fg: &mut FlowGraph, func: &Function) {
    for (idx, param) in func.params.iter().copied().enumerate() {
        let param_node = fg.graph.add_node(FlowNode::Param {
            func: func.id,
            index: idx,
            value: param,
        });
        fg.function_params.insert((func.id, idx), param_node);
        let value_node = fg.graph.add_node(FlowNode::Value {
            func: func.id,
            value: param,
        });
        fg.values.insert((func.id, param), value_node);
        fg.graph.add_edge(
            param_node,
            value_node,
            FlowEdge {
                kind: EdgeKind::Assign,
            },
        );
    }

    for local in func.locals.iter().copied() {
        fg.values.entry((func.id, local)).or_insert_with(|| {
            fg.graph.add_node(FlowNode::Value {
                func: func.id,
                value: local,
            })
        });
    }

    let return_node = fg.graph.add_node(FlowNode::Return { func: func.id });
    fg.function_returns.insert(func.id, return_node);
}

fn value_node(fg: &FlowGraph, func: FunctionId, value: ValueId) -> NodeIndex {
    *fg.values
        .get(&(func, value))
        .expect("value node must be pre-created")
}

fn edge_value_to_value(
    fg: &mut FlowGraph,
    func: FunctionId,
    src: ValueId,
    dst: ValueId,
    kind: EdgeKind,
) {
    let src_node = value_node(fg, func, src);
    let dst_node = value_node(fg, func, dst);
    fg.graph.add_edge(src_node, dst_node, FlowEdge { kind });
}

fn connect_call_value_ports(fg: &mut FlowGraph, func: FunctionId, inst: InstId, call: &CallInst) {
    let callee_name = normalized_static_callee_name(fg, func, call);

    if let Some(receiver) = call.receiver {
        let port = Port::Receiver;
        let port_node = get_or_create_call_port(fg, func, inst, port.clone(), callee_name.clone());
        let src = value_node(fg, func, receiver);
        fg.graph.add_edge(
            src,
            port_node,
            FlowEdge {
                kind: EdgeKind::ValueToCallPort,
            },
        );
    }

    for (idx, arg) in call.args.iter().copied().enumerate() {
        let port = Port::Arg(idx);
        let port_node = get_or_create_call_port(fg, func, inst, port.clone(), callee_name.clone());
        let src = value_node(fg, func, arg);
        fg.graph.add_edge(
            src,
            port_node,
            FlowEdge {
                kind: EdgeKind::ValueToCallPort,
            },
        );
        if let Some(name) = call.arg_names.get(idx).and_then(Option::as_ref) {
            let named = get_or_create_call_port(
                fg,
                func,
                inst,
                Port::NamedArg(name.clone()),
                callee_name.clone(),
            );
            fg.graph.add_edge(
                src,
                named,
                FlowEdge {
                    kind: EdgeKind::ValueToCallPort,
                },
            );
        }
    }

    if let Some(dst) = call.dst {
        let port = Port::Return;
        let port_node = get_or_create_call_port(fg, func, inst, port, callee_name);
        let dst_node = value_node(fg, func, dst);
        fg.graph.add_edge(
            port_node,
            dst_node,
            FlowEdge {
                kind: EdgeKind::CallPortToValue,
            },
        );
    }
}

fn connect_lambda_capture_bindings(
    fg: &mut FlowGraph,
    caller_func: FunctionId,
    callee_value: ValueId,
    callee_func: &Function,
) {
    let canonical_callee = canonical_heap_value(fg, caller_func, callee_value);
    for (ir_index, capture_name) in capture_param_ir_indices(callee_func) {
        let field_name = format!("__capture__{capture_name}");
        let Some(field_cell) = fg
            .field_cells
            .get(&(caller_func, canonical_callee, field_name))
            .copied()
        else {
            continue;
        };
        let Some(param_node) = fg.function_params.get(&(callee_func.id, ir_index)).copied() else {
            continue;
        };
        fg.graph.add_edge(
            field_cell,
            param_node,
            FlowEdge {
                kind: EdgeKind::ActualToFormal,
            },
        );
    }
}

fn compute_actual_formal_bindings(
    call: &CallInst,
    callee_func: &Function,
) -> Vec<(Port, ValueId, usize)> {
    let mut bindings = Vec::new();
    let receiver_offset = function_receiver_offset(callee_func);
    if receiver_offset == 1 {
        if let Some(receiver) = call.receiver {
            if !callee_func.params.is_empty() {
                bindings.push((Port::Receiver, receiver, 0));
            }
        }
    }

    let specs = function_param_specs(callee_func);
    if specs.is_empty() {
        let param_offset = receiver_offset;
        for (idx, arg) in call.args.iter().copied().enumerate() {
            let ir_index = idx + param_offset;
            if ir_index < callee_func.params.len() {
                bindings.push((Port::Arg(idx), arg, ir_index));
            }
        }
        return bindings;
    }

    let mut consumed = Vec::<usize>::new();
    let positional_targets = specs
        .iter()
        .filter(|spec| spec.kind == ParamBindingKind::Positional && !spec.keyword_only)
        .map(|spec| spec.ir_index)
        .collect::<Vec<_>>();
    let vararg_target = specs
        .iter()
        .find(|spec| spec.kind == ParamBindingKind::VarArgs)
        .map(|spec| spec.ir_index);
    let kwarg_target = specs
        .iter()
        .find(|spec| spec.kind == ParamBindingKind::KwArgs)
        .map(|spec| spec.ir_index);
    let mut next_positional = 0usize;

    for (idx, arg) in call.args.iter().copied().enumerate() {
        let target_index =
            if let Some(name) = call.arg_names.get(idx).and_then(|name| name.as_deref()) {
                if let Some(spec) = specs
                    .iter()
                    .find(|spec| spec.name == name && spec.kind == ParamBindingKind::Positional)
                {
                    if consumed.iter().any(|existing| *existing == spec.ir_index) {
                        kwarg_target.or(vararg_target)
                    } else {
                        consumed.push(spec.ir_index);
                        Some(spec.ir_index)
                    }
                } else {
                    kwarg_target.or(vararg_target)
                }
            } else {
                while next_positional < positional_targets.len()
                    && consumed
                        .iter()
                        .any(|existing| *existing == positional_targets[next_positional])
                {
                    next_positional += 1;
                }
                if let Some(ir_index) = positional_targets.get(next_positional).copied() {
                    consumed.push(ir_index);
                    next_positional += 1;
                    Some(ir_index)
                } else {
                    vararg_target.or(kwarg_target)
                }
            };

        if let Some(ir_index) = target_index {
            if ir_index < callee_func.params.len() {
                bindings.push((Port::Arg(idx), arg, ir_index));
            }
        }
    }

    bindings
}

fn connect_cell_projected_values_to_dst(
    fg: &mut FlowGraph,
    cell: NodeIndex,
    dst_func: FunctionId,
    dst: ValueId,
    edge_kind: EdgeKind,
) {
    let dst_node = value_node(fg, dst_func, dst);
    fg.graph.add_edge(
        cell,
        dst_node,
        FlowEdge {
            kind: edge_kind.clone(),
        },
    );
    // Reaching stores are selected after alias/identity facts are available.
    // Eager bidirectional bindings here permanently equate every overwritten
    // value with the read, before strong-update eligibility can be established.
}

fn connect_python_container_semantics(
    fg: &mut FlowGraph,
    func: FunctionId,
    call: &CallInst,
    meta: &CallMeta,
    literal_index_keys: &HashMap<ValueId, String>,
) {
    let Some(receiver) = call.receiver else {
        return;
    };
    let Some(method) = meta.method_name.as_deref() else {
        return;
    };

    match method {
        "append" => {
            let Some(src) = call.args.get(0).copied() else {
                return;
            };
            let precise_key = next_precise_numeric_index_key(fg, func, receiver);
            for key in [precise_key.as_str(), "*"] {
                let cell = ensure_index_cell(fg, func, receiver, key);
                let src_node = value_node(fg, func, src);
                fg.graph.add_edge(
                    src_node,
                    cell,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
            }
        }
        "insert" => {
            let Some(src) = call.args.get(1).copied() else {
                return;
            };
            let key = call
                .args
                .get(0)
                .map(|index| abstract_index_key(literal_index_keys, *index))
                .unwrap_or_else(|| "*".to_string());
            for slot in [key.as_str(), "*"] {
                let cell = ensure_index_cell(fg, func, receiver, slot);
                let src_node = value_node(fg, func, src);
                fg.graph.add_edge(
                    src_node,
                    cell,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
            }
        }
        "extend" | "update" => {
            let Some(other) = call.args.get(0).copied() else {
                return;
            };
            let mut visited = HashSet::new();
            bridge_nested_heap_values(fg, func, receiver, func, other, &mut visited);
        }
        "get" => {
            let Some(dst) = call.dst else {
                return;
            };
            let key = call
                .args
                .get(0)
                .map(|index| abstract_index_key(literal_index_keys, *index))
                .unwrap_or_else(|| "*".to_string());
            let mut cells = index_cells_for_key(fg, func, receiver, &key);
            if cells.is_empty() {
                cells.push(ensure_index_cell(fg, func, receiver, &key));
            }
            for cell in cells {
                connect_cell_projected_values_to_dst(fg, cell, func, dst, EdgeKind::LoadIndex);
            }
            if let Some(default) = call.args.get(1).copied() {
                edge_value_to_value(fg, func, default, dst, EdgeKind::LoadIndex);
                propagate_object_identity_site(fg, func, default, func, dst);
                let mut visited = HashSet::new();
                bridge_nested_heap_values(fg, func, default, func, dst, &mut visited);
            }
        }
        "pop" => {
            let Some(dst) = call.dst else {
                return;
            };
            let key = if let Some(index) = call.args.get(0) {
                abstract_index_key(literal_index_keys, *index)
            } else if let Some(last_key) = last_precise_numeric_index_key(fg, func, receiver) {
                last_key
            } else {
                "*".to_string()
            };
            let mut cells = index_cells_for_key(fg, func, receiver, &key);
            if cells.is_empty() {
                cells.push(ensure_index_cell(fg, func, receiver, &key));
            }
            for cell in cells {
                connect_cell_projected_values_to_dst(fg, cell, func, dst, EdgeKind::LoadIndex);
            }
            if let Some(default) = call.args.get(1).copied() {
                edge_value_to_value(fg, func, default, dst, EdgeKind::LoadIndex);
                propagate_object_identity_site(fg, func, default, func, dst);
                let mut visited = HashSet::new();
                bridge_nested_heap_values(fg, func, default, func, dst, &mut visited);
            }
        }
        "setdefault" => {
            let key = call
                .args
                .get(0)
                .map(|index| abstract_index_key(literal_index_keys, *index))
                .unwrap_or_else(|| "*".to_string());
            let cell = ensure_index_cell(fg, func, receiver, &key);
            if let Some(default) = call.args.get(1).copied() {
                let src_node = value_node(fg, func, default);
                fg.graph.add_edge(
                    src_node,
                    cell,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
                let wildcard = ensure_index_cell(fg, func, receiver, "*");
                fg.graph.add_edge(
                    src_node,
                    wildcard,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
            }
            if let Some(dst) = call.dst {
                connect_cell_projected_values_to_dst(fg, cell, func, dst, EdgeKind::LoadIndex);
            }
        }
        "copy" | "__copy__" => {
            let Some(dst) = call.dst else {
                return;
            };
            let mut visited = HashSet::new();
            bridge_nested_heap_values(fg, func, receiver, func, dst, &mut visited);
        }
        _ => {}
    }
}

fn connect_internal_call(
    fg: &mut FlowGraph,
    caller_func: FunctionId,
    inst: InstId,
    call: &CallInst,
    callee_func: &Function,
    _caller_ret: NodeIndex,
) {
    if let Callee::Dynamic(callee_value) = &call.callee {
        connect_lambda_capture_bindings(fg, caller_func, *callee_value, callee_func);
    }

    let bindings = compute_actual_formal_bindings(call, callee_func);
    for (port, actual_value, ir_index) in &bindings {
        let Some(param_node) = fg
            .function_params
            .get(&(callee_func.id, *ir_index))
            .copied()
        else {
            continue;
        };
        let arg_port = get_or_create_call_port(
            fg,
            caller_func,
            inst,
            port.clone(),
            Some(callee_func.name.clone()),
        );
        fg.graph.add_edge(
            arg_port,
            param_node,
            FlowEdge {
                kind: EdgeKind::ActualToFormal,
            },
        );
        propagate_object_identity_site(
            fg,
            caller_func,
            *actual_value,
            callee_func.id,
            callee_func.params[*ir_index],
        );
    }

    if let Some(dst) = call.dst {
        let ret_port = get_or_create_call_port(
            fg,
            caller_func,
            inst,
            Port::Return,
            Some(callee_func.name.clone()),
        );
        let callee_ret = *fg
            .function_returns
            .get(&callee_func.id)
            .expect("callee return node must exist");
        fg.graph.add_edge(
            callee_ret,
            ret_port,
            FlowEdge {
                kind: EdgeKind::FormalToActual,
            },
        );
        let direct_sites = returned_direct_identity_sites(fg, callee_func);
        if direct_sites.len() == 1 {
            fg.object_identity_roots.insert((caller_func, dst), dst);
            fg.object_identity_sites
                .insert((caller_func, dst), direct_sites[0].clone());
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum ProjectionStep {
    Field(String),
    Index(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum ReturnedProjection {
    Param {
        ir_index: usize,
    },
    Path {
        ir_index: usize,
        steps: Vec<ProjectionStep>,
    },
}

fn returned_projections(fg: &FlowGraph, func: &Function) -> Vec<ReturnedProjection> {
    let literal_index_keys = compute_literal_index_keys(func, &fg.language);
    let mut defs = HashMap::new();
    for block in &func.blocks {
        for inst in &block.insts {
            match &inst.kind {
                InstKind::ConstInt { dst, .. }
                | InstKind::ConstString { dst, .. }
                | InstKind::Copy { dst, .. }
                | InstKind::NumericStep { dst, .. }
                | InstKind::Move { dst, .. }
                | InstKind::Cast { dst, .. }
                | InstKind::Phi { dst, .. }
                | InstKind::LoadField { dst, .. }
                | InstKind::LoadIndex { dst, .. } => {
                    defs.insert(*dst, &inst.kind);
                }
                InstKind::StoreField { .. }
                | InstKind::StoreIndex { .. }
                | InstKind::Call(_)
                | InstKind::Lifetime { .. } => {}
            }
        }
    }
    let param_roots = func
        .params
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, param)| {
            (
                idx,
                fg.value_alias_roots
                    .get(&(func.id, param))
                    .copied()
                    .unwrap_or(param),
            )
        })
        .collect::<Vec<_>>();

    fn append_step(proj: ReturnedProjection, step: ProjectionStep) -> ReturnedProjection {
        match proj {
            ReturnedProjection::Param { ir_index } => ReturnedProjection::Path {
                ir_index,
                steps: vec![step],
            },
            ReturnedProjection::Path {
                ir_index,
                mut steps,
            } => {
                steps.push(step);
                ReturnedProjection::Path { ir_index, steps }
            }
        }
    }

    fn walk_projection(
        fg: &FlowGraph,
        func: &Function,
        value: ValueId,
        defs: &HashMap<ValueId, &InstKind>,
        param_roots: &[(usize, ValueId)],
        literal_index_keys: &HashMap<ValueId, String>,
        visiting: &mut HashSet<ValueId>,
    ) -> Vec<ReturnedProjection> {
        if !visiting.insert(value) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let root = fg
            .value_alias_roots
            .get(&(func.id, value))
            .copied()
            .unwrap_or(value);
        for (idx, param_root) in param_roots {
            if *param_root == root {
                out.push(ReturnedProjection::Param { ir_index: *idx });
            }
        }
        if let Some(kind) = defs.get(&value) {
            match *kind {
                InstKind::Copy { src, .. }
                | InstKind::Move { src, .. }
                | InstKind::Cast { src, .. } => {
                    out.extend(walk_projection(
                        fg,
                        func,
                        *src,
                        defs,
                        param_roots,
                        literal_index_keys,
                        visiting,
                    ));
                }
                InstKind::Phi { inputs, .. } => {
                    for input in inputs {
                        out.extend(walk_projection(
                            fg,
                            func,
                            *input,
                            defs,
                            param_roots,
                            literal_index_keys,
                            visiting,
                        ));
                    }
                }
                InstKind::LoadField { base, field, .. } => {
                    for projection in walk_projection(
                        fg,
                        func,
                        *base,
                        defs,
                        param_roots,
                        literal_index_keys,
                        visiting,
                    ) {
                        out.push(append_step(
                            projection,
                            ProjectionStep::Field(field.clone()),
                        ));
                    }
                }
                InstKind::LoadIndex { base, index, .. } => {
                    let key = abstract_index_key(literal_index_keys, *index);
                    for projection in walk_projection(
                        fg,
                        func,
                        *base,
                        defs,
                        param_roots,
                        literal_index_keys,
                        visiting,
                    ) {
                        out.push(append_step(projection, ProjectionStep::Index(key.clone())));
                    }
                }
                InstKind::NumericStep { .. }
                | InstKind::ConstInt { .. }
                | InstKind::ConstString { .. }
                | InstKind::StoreField { .. }
                | InstKind::StoreIndex { .. }
                | InstKind::Call(_)
                | InstKind::Lifetime { .. } => {}
            }
        }
        visiting.remove(&value);
        out.sort();
        out.dedup();
        out
    }

    let mut out = Vec::new();
    for block in &func.blocks {
        let Terminator::Return(Some(value)) = &block.term else {
            continue;
        };
        let mut visiting = HashSet::new();
        out.extend(walk_projection(
            fg,
            func,
            *value,
            &defs,
            &param_roots,
            &literal_index_keys,
            &mut visiting,
        ));
    }
    out.sort();
    out.dedup();
    out
}

fn ensure_field_cell(
    fg: &mut FlowGraph,
    func: FunctionId,
    value: ValueId,
    field: &str,
) -> NodeIndex {
    let root = canonical_heap_value(fg, func, value);
    if let Some(existing) = fg
        .field_cells
        .get(&(func, root, field.to_string()))
        .copied()
    {
        return existing;
    }
    let node = fg.graph.add_node(FlowNode::FieldCell {
        func,
        block: BlockId(0),
        inst: InstId(0),
        base: root,
        field: field.to_string(),
    });
    fg.field_cells.insert((func, root, field.to_string()), node);
    let base_node = value_node(fg, func, value);
    fg.graph.add_edge(
        base_node,
        node,
        FlowEdge {
            kind: EdgeKind::LoadField {
                field: field.to_string(),
            },
        },
    );
    node
}

fn ensure_index_cell(fg: &mut FlowGraph, func: FunctionId, value: ValueId, key: &str) -> NodeIndex {
    let root = canonical_heap_value(fg, func, value);
    if let Some(existing) = fg.index_cells.get(&(func, root, key.to_string())).copied() {
        return existing;
    }
    let node = fg.graph.add_node(FlowNode::IndexCell {
        func,
        block: BlockId(0),
        inst: InstId(0),
        base: root,
        index: ValueId(u32::MAX),
        abstract_key: key.to_string(),
    });
    fg.index_cells.insert((func, root, key.to_string()), node);
    let base_node = value_node(fg, func, value);
    fg.graph.add_edge(
        base_node,
        node,
        FlowEdge {
            kind: EdgeKind::LoadIndex,
        },
    );
    node
}

fn index_cells_for_key(
    fg: &FlowGraph,
    func: FunctionId,
    value: ValueId,
    key: &str,
) -> Vec<NodeIndex> {
    let root = canonical_heap_value(fg, func, value);
    let mut out = Vec::new();
    if key == "*" {
        for ((cell_func, cell_root, _), node) in &fg.index_cells {
            if *cell_func == func && *cell_root == root && !out.contains(node) {
                out.push(*node);
            }
        }
        return out;
    }
    if let Some(node) = fg.index_cells.get(&(func, root, key.to_string())).copied() {
        out.push(node);
        return out;
    }
    if let Some(node) = fg.index_cells.get(&(func, root, "*".to_string())).copied() {
        out.push(node);
    }
    out
}

fn index_keys_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    let root = canonical_heap_value(fg, func, value);
    let mut out = Vec::new();
    for (cell_func, cell_root, key) in fg.index_cells.keys() {
        if *cell_func == func && *cell_root == root && !out.contains(key) {
            out.push(key.clone());
        }
    }
    out
}

fn next_precise_numeric_index_key(fg: &FlowGraph, func: FunctionId, value: ValueId) -> String {
    let mut next = 0usize;
    for key in index_keys_for_value(fg, func, value) {
        if let Ok(parsed) = key.parse::<usize>() {
            next = next.max(parsed.saturating_add(1));
        }
    }
    next.to_string()
}

fn last_precise_numeric_index_key(
    fg: &FlowGraph,
    func: FunctionId,
    value: ValueId,
) -> Option<String> {
    let mut best: Option<usize> = None;
    for key in index_keys_for_value(fg, func, value) {
        if let Ok(parsed) = key.parse::<usize>() {
            best = Some(best.map(|current| current.max(parsed)).unwrap_or(parsed));
        }
    }
    best.map(|value| value.to_string())
}

fn connect_container_value_copy(fg: &mut FlowGraph, func: FunctionId, src: ValueId, dst: ValueId) {
    let keys = index_keys_for_value(fg, func, src);
    if keys.is_empty() {
        let src_node = value_node(fg, func, src);
        let wildcard = ensure_index_cell(fg, func, dst, "*");
        fg.graph.add_edge(
            src_node,
            wildcard,
            FlowEdge {
                kind: EdgeKind::StoreIndex,
            },
        );
        return;
    }
    for key in keys {
        let dst_cell = ensure_index_cell(fg, func, dst, &key);
        for src_cell in index_cells_for_key(fg, func, src, &key) {
            fg.graph.add_edge(
                src_cell,
                dst_cell,
                FlowEdge {
                    kind: EdgeKind::StoreIndex,
                },
            );
        }
    }
}

fn connect_builtin_python_container_semantics(
    fg: &mut FlowGraph,
    func: FunctionId,
    call: &CallInst,
    meta: &CallMeta,
    literal_index_keys: &HashMap<ValueId, String>,
) {
    let Some(dst) = call.dst else {
        return;
    };
    let Some(callee_name) = meta.callee_name.as_deref() else {
        return;
    };

    match callee_name {
        "builtins.list" | "builtins.tuple" => {
            if call.args.len() == 1 {
                connect_container_value_copy(fg, func, call.args[0], dst);
                return;
            }
            for (idx, arg) in call.args.iter().copied().enumerate() {
                let key = idx.to_string();
                let cell = ensure_index_cell(fg, func, dst, &key);
                let src_node = value_node(fg, func, arg);
                fg.graph.add_edge(
                    src_node,
                    cell,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
                let wildcard = ensure_index_cell(fg, func, dst, "*");
                fg.graph.add_edge(
                    src_node,
                    wildcard,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
            }
        }
        "builtins.dict" => {
            if call.args.len() == 1 {
                connect_container_value_copy(fg, func, call.args[0], dst);
                return;
            }
            for pair in call.args.chunks(2) {
                let Some(key_value) = pair.get(0).copied() else {
                    continue;
                };
                let Some(src) = pair.get(1).copied() else {
                    continue;
                };
                let key = abstract_index_key(literal_index_keys, key_value);
                let cell = ensure_index_cell(fg, func, dst, &key);
                let src_node = value_node(fg, func, src);
                fg.graph.add_edge(
                    src_node,
                    cell,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
                let wildcard = ensure_index_cell(fg, func, dst, "*");
                fg.graph.add_edge(
                    src_node,
                    wildcard,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
            }
        }
        "builtins.set" => {
            if call.args.len() == 1 {
                connect_container_value_copy(fg, func, call.args[0], dst);
                return;
            }
            for (idx, arg) in call.args.iter().copied().enumerate() {
                let src_node = value_node(fg, func, arg);
                let wildcard = ensure_index_cell(fg, func, dst, "*");
                fg.graph.add_edge(
                    src_node,
                    wildcard,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
                let key = idx.to_string();
                let cell = ensure_index_cell(fg, func, dst, &key);
                fg.graph.add_edge(
                    src_node,
                    cell,
                    FlowEdge {
                        kind: EdgeKind::StoreIndex,
                    },
                );
            }
        }
        _ => {}
    }
}

fn connect_bidirectional_value_pair(
    fg: &mut FlowGraph,
    left_func: FunctionId,
    left_value: ValueId,
    right_func: FunctionId,
    right_value: ValueId,
) {
    let left = value_node(fg, left_func, left_value);
    let right = value_node(fg, right_func, right_value);
    connect_heap_binding(fg, left, right);
}

fn connect_heap_binding(fg: &mut FlowGraph, actual: NodeIndex, formal: NodeIndex) {
    if actual == formal { return; }
    if !fg.graph.edges_connecting(actual, formal).any(|edge| matches!(edge.weight().kind, EdgeKind::ActualToFormal)) {
        fg.graph.add_edge(actual, formal, FlowEdge { kind: EdgeKind::ActualToFormal });
    }
    if !fg.graph.edges_connecting(formal, actual).any(|edge| matches!(edge.weight().kind, EdgeKind::FormalToActual)) {
        fg.graph.add_edge(formal, actual, FlowEdge { kind: EdgeKind::FormalToActual });
    }
}

fn direct_cell_projected_values(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Outgoing) {
        match (&edge.weight().kind, &fg.graph[edge.target()]) {
            (EdgeKind::LoadField { .. } | EdgeKind::LoadIndex, FlowNode::Value { func, value }) => {
                if seen.insert((*func, *value)) {
                    out.push((*func, *value));
                }
            }
            _ => {}
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Incoming) {
        match (&edge.weight().kind, &fg.graph[edge.source()]) {
            (
                EdgeKind::StoreField { .. } | EdgeKind::StoreIndex,
                FlowNode::Value { func, value },
            ) => {
                if seen.insert((*func, *value)) {
                    out.push((*func, *value));
                }
            }
            _ => {}
        }
    }
    out
}

fn collect_transitive_cell_projected_values(
    fg: &FlowGraph,
    cell: NodeIndex,
    visited_cells: &mut HashSet<NodeIndex>,
    seen_values: &mut HashSet<(FunctionId, ValueId)>,
    out: &mut Vec<(FunctionId, ValueId)>,
) {
    if !visited_cells.insert(cell) {
        return;
    }
    for projected in direct_cell_projected_values(fg, cell) {
        if seen_values.insert(projected) {
            out.push(projected);
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Outgoing) {
        if !matches!(
            edge.weight().kind,
            EdgeKind::ActualToFormal | EdgeKind::FormalToActual
        ) {
            continue;
        }
        if matches!(
            fg.graph[edge.target()],
            FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }
        ) {
            collect_transitive_cell_projected_values(
                fg,
                edge.target(),
                visited_cells,
                seen_values,
                out,
            );
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Incoming) {
        if !matches!(
            edge.weight().kind,
            EdgeKind::ActualToFormal | EdgeKind::FormalToActual
        ) {
            continue;
        }
        if matches!(
            fg.graph[edge.source()],
            FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }
        ) {
            collect_transitive_cell_projected_values(
                fg,
                edge.source(),
                visited_cells,
                seen_values,
                out,
            );
        }
    }
}

fn all_cell_nodes(fg: &FlowGraph) -> Vec<NodeIndex> {
    let mut cells = fg.field_cells.values().copied().collect::<Vec<_>>();
    cells.extend(fg.index_cells.values().copied());
    cells.sort_unstable_by_key(|node| node.index());
    cells.dedup_by_key(|node| node.index());
    cells
}

fn alias_equivalent_cells(fg: &FlowGraph, cell: NodeIndex) -> Vec<NodeIndex> {
    let mut out = Vec::new();
    for candidate in all_cell_nodes(fg) {
        if candidate == cell
            || fg.cell_may_alias(cell, candidate)
        {
            out.push(candidate);
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn cell_projected_values(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    let mut out = Vec::new();
    let mut visited_cells = HashSet::new();
    let mut seen_values = HashSet::new();
    collect_transitive_cell_projected_values(
        fg,
        cell,
        &mut visited_cells,
        &mut seen_values,
        &mut out,
    );
    out
}

fn cell_abstract_identity_key(fg: &FlowGraph, cell: NodeIndex) -> Option<String> {
    match &fg.graph[cell] {
        FlowNode::FieldCell {
            func, base, field, ..
        } => {
            let site = value_identity_site(fg, *func, *base)?.trim().to_string();
            Some(format!("field:{}:{}", site, field))
        }
        FlowNode::IndexCell {
            func,
            base,
            abstract_key,
            ..
        } if abstract_key != "*" => {
            let site = value_identity_site(fg, *func, *base)?.trim().to_string();
            Some(format!("index:{}:{}", site, abstract_key))
        }
        _ => None,
    }
}

fn cell_allows_strong_update(fg: &FlowGraph, cell: NodeIndex) -> bool {
    let Some(memory_unit) = precise_memory_unit_key_for_cell(fg, cell) else {
        return false;
    };
    let alias_cells = alias_equivalent_cells(fg, cell);
    let must_alias_cells = alias_cells
        .iter()
        .copied()
        .filter(|candidate| fg.cell_must_alias(cell, *candidate))
        .collect::<Vec<_>>();
    if must_alias_cells.len() != 1 || must_alias_cells[0] != cell {
        return false;
    }
    if alias_cells
        .iter()
        .copied()
        .any(|candidate| candidate != cell && fg.cell_may_alias(cell, candidate))
    {
        return false;
    }
    let Some(memory_unit_object_id) = fg
        .points_to_object_ids
        .get(&format!("memunit:{}", memory_unit))
        .copied()
    else {
        return false;
    };
    let cell_object_ids = fg.cell_points_to_object_ids_of(cell);
    cell_object_ids.is_empty()
        || cell_object_ids
            .iter()
            .any(|id| *id == memory_unit_object_id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct DetailedStoreRecord {
    edge_idx: usize,
    origin_cell: usize,
    func: FunctionId,
    value: ValueId,
}

fn direct_cell_store_records(fg: &FlowGraph, cell: NodeIndex) -> Vec<DetailedStoreRecord> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Incoming) {
        match (&edge.weight().kind, &fg.graph[edge.source()]) {
            (
                EdgeKind::StoreField { .. } | EdgeKind::StoreIndex,
                FlowNode::Value { func, value },
            ) => {
                let key = DetailedStoreRecord {
                    edge_idx: edge.id().index(),
                    origin_cell: cell.index(),
                    func: *func,
                    value: *value,
                };
                if seen.insert(key) {
                    out.push(key);
                }
            }
            (EdgeKind::Summary { rule_id }, FlowNode::Value { func, value })
                if rule_id.contains("heap-write") =>
            {
                let key = DetailedStoreRecord {
                    edge_idx: edge.id().index(),
                    origin_cell: cell.index(),
                    func: *func,
                    value: *value,
                };
                if seen.insert(key) {
                    out.push(key);
                }
            }
            _ => {}
        }
    }
    out.sort_unstable_by_key(|record| record.edge_idx);
    out
}

fn transitive_cell_store_records(fg: &FlowGraph, cell: NodeIndex) -> Vec<DetailedStoreRecord> {
    let mut out = Vec::new();
    let mut visited_cells = HashSet::from([cell]);
    let mut seen_records = HashSet::new();
    let mut pending = vec![cell];
    while let Some(current) = pending.pop() {
        for record in direct_cell_store_records(fg, current) {
            if seen_records.insert(record) { out.push(record); }
        }
        let mut neighbors = alias_equivalent_cells(fg, current);
        for direction in [petgraph::Direction::Outgoing, petgraph::Direction::Incoming] {
            for edge in fg.graph.edges_directed(current, direction) {
                if !matches!(edge.weight().kind, EdgeKind::ActualToFormal | EdgeKind::FormalToActual) { continue; }
                let next = if direction == petgraph::Direction::Outgoing { edge.target() } else { edge.source() };
                if matches!(fg.graph[next], FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }) {
                    neighbors.push(next);
                }
            }
        }
        for neighbor in neighbors {
            if visited_cells.insert(neighbor) { pending.push(neighbor); }
        }
    }
    out.sort_unstable_by_key(|record| record.edge_idx);
    out.dedup();
    out
}

fn visible_direct_cell_store_records_before_edge(
    fg: &FlowGraph,
    cell: NodeIndex,
    cutoff_edge_idx: Option<usize>,
) -> Vec<(usize, FunctionId, ValueId)> {
    visible_cell_store_records(fg, cell, cutoff_edge_idx,
        transitive_cell_store_records(fg, cell), &mut HashMap::new())
}

fn all_transitive_cell_store_records(fg: &FlowGraph) -> HashMap<usize, BTreeSet<DetailedStoreRecord>> {
    let cells = all_cell_nodes(fg);
    let seeds = cells.iter().map(|cell| (cell.index(), direct_cell_store_records(fg, *cell).into_iter().collect())).collect();
    propagate_symmetric_labels(cells.into_iter(), seeds, |cell| {
        let mut neighbors = alias_equivalent_cells(fg, cell);
        for direction in [petgraph::Direction::Outgoing, petgraph::Direction::Incoming] {
            for edge in fg.graph.edges_directed(cell, direction) {
                if !matches!(edge.weight().kind, EdgeKind::ActualToFormal | EdgeKind::FormalToActual) { continue; }
                let next = if direction == petgraph::Direction::Outgoing { edge.target() } else { edge.source() };
                if matches!(fg.graph[next], FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }) { neighbors.push(next); }
            }
        }
        neighbors
    })
}

fn visible_cell_store_records(
    fg: &FlowGraph, cell: NodeIndex, cutoff_edge_idx: Option<usize>,
    mut records: Vec<DetailedStoreRecord>, strong: &mut HashMap<usize, bool>,
) -> Vec<(usize, FunctionId, ValueId)> {
    if let Some(cutoff) = cutoff_edge_idx {
        records.retain(|record| record.edge_idx < cutoff);
    }
    if records.is_empty() {
        return Vec::new();
    }
    records.sort_unstable_by_key(|record| record.edge_idx);
    records.dedup();

    let mut visible = Vec::<DetailedStoreRecord>::new();
    for record in records {
        let origin_cell = NodeIndex::new(record.origin_cell);
        if *strong.entry(origin_cell.index()).or_insert_with(|| cell_allows_strong_update(fg, origin_cell)) {
            visible.retain(|existing| {
                let existing_cell = NodeIndex::new(existing.origin_cell);
                !fg.cell_must_alias(origin_cell, existing_cell)
            });
        }
        visible.push(record);
    }

    if *strong.entry(cell.index()).or_insert_with(|| cell_allows_strong_update(fg, cell)) {
        let mut latest: Option<DetailedStoreRecord> = None;
        for record in visible {
            let origin_cell = NodeIndex::new(record.origin_cell);
            if fg.cell_must_alias(cell, origin_cell) {
                let replace = latest
                    .as_ref()
                    .map(|existing| record.edge_idx >= existing.edge_idx)
                    .unwrap_or(true);
                if replace {
                    latest = Some(record);
                }
            }
        }
        return latest
            .into_iter()
            .map(|record| (record.edge_idx, record.func, record.value))
            .collect();
    }

    // A may-alias/summary cell requires a weak update: preserve every possible
    // reaching store. Equal type/shape/region labels do not prove that a later
    // store overwrites an earlier one. The former per-label last-store map both
    // dropped feasible values and multiplied work by the inferred shape set.
    let mut out = visible
        .into_iter()
        .map(|record| (record.edge_idx, record.func, record.value))
        .collect::<Vec<_>>();
    out.sort_unstable_by_key(|(edge_idx, _, _)| *edge_idx);
    out.dedup();
    out
}

fn direct_cell_store_values_before_edge(
    fg: &FlowGraph,
    cell: NodeIndex,
    cutoff_edge_idx: Option<usize>,
) -> Vec<(FunctionId, ValueId)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (_edge_idx, func, value) in
        visible_direct_cell_store_records_before_edge(fg, cell, cutoff_edge_idx)
    {
        if seen.insert((func, value)) {
            out.push((func, value));
        }
    }
    out
}

fn direct_cell_store_values(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    let live = fg.cell_live_values_of(cell);
    if !live.is_empty() {
        return live;
    }
    direct_cell_store_values_before_edge(fg, cell, None)
}

fn region_candidate_cells(fg: &FlowGraph, region: &str) -> Vec<NodeIndex> {
    let mut out = fg.region_live_cells_of(region);
    if out.is_empty() {
        for (candidate_region, cells) in &fg.region_live_cells {
            if !memory_region_related(candidate_region, region) {
                continue;
            }
            out.extend(cells.iter().copied().map(NodeIndex::new));
        }
    }
    if out.is_empty() {
        for cell in all_cell_nodes(fg) {
            if fg
                .cell_memory_regions_of(cell)
                .iter()
                .any(|candidate| memory_region_related(candidate, region))
            {
                out.push(cell);
            }
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn suffix_to_access_path(suffix: &str) -> Option<String> {
    let trimmed = suffix.trim();
    if trimmed.is_empty() {
        return None;
    }
    let chars = trimmed.char_indices().collect::<Vec<_>>();
    let mut pos = 0usize;
    let mut labels = Vec::new();
    while pos < chars.len() {
        match chars[pos].1 {
            '.' => {
                pos += 1;
                let start = pos;
                while pos < chars.len() && chars[pos].1 != '.' && chars[pos].1 != '[' {
                    pos += 1;
                }
                let start_byte = chars.get(start).map(|(i, _)| *i).unwrap_or(trimmed.len());
                let end_byte = chars.get(pos).map(|(i, _)| *i).unwrap_or(trimmed.len());
                let field = trimmed[start_byte..end_byte].trim();
                if !field.is_empty() {
                    labels.push(format!("field:{}", field));
                }
            }
            '[' => {
                pos += 1;
                let start = pos;
                while pos < chars.len() && chars[pos].1 != ']' {
                    pos += 1;
                }
                let start_byte = chars.get(start).map(|(i, _)| *i).unwrap_or(trimmed.len());
                let end_byte = chars.get(pos).map(|(i, _)| *i).unwrap_or(trimmed.len());
                let key = trimmed[start_byte..end_byte].trim();
                if !key.is_empty() {
                    labels.push(format!("index:{}", key));
                }
                if pos < chars.len() && chars[pos].1 == ']' {
                    pos += 1;
                }
            }
            _ => pos += 1,
        }
    }
    (!labels.is_empty()).then_some(labels.join("."))
}

fn region_relative_access_paths(base_regions: &[String], region: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for base in base_regions {
        if !memory_region_has_boundary_prefix(base, region) {
            continue;
        }
        let Some(suffix) = region.strip_prefix(base) else {
            continue;
        };
        if let Some(path) = suffix_to_access_path(suffix) {
            out.insert(path);
        }
    }
    out.into_iter().collect()
}

fn value_root_memory_regions(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    let mut roots = memory_region_seed_for_value(fg, func, value);
    roots.sort();
    roots.dedup();
    roots
}

fn parse_access_path(path: &str) -> Vec<(String, String)> {
    path.split('.')
        .filter_map(|segment| {
            let trimmed = segment.trim();
            if let Some(field) = trimmed.strip_prefix("field:") {
                return Some(("field".to_string(), field.trim().to_string()));
            }
            if let Some(index) = trimmed.strip_prefix("index:") {
                return Some(("index".to_string(), index.trim().to_string()));
            }
            None
        })
        .filter(|(_, label)| !label.is_empty())
        .collect()
}

/// Resolve a summary against the function that produced it without allocating
/// new cells. Inferred region/shape paths are aliases, not additional source
/// dereferences. Re-instantiating them locally recursively invents heap shapes.
fn existing_cells_for_relative_path_from_value(
    fg: &FlowGraph, func: FunctionId, value: ValueId, path: &str,
) -> Vec<NodeIndex> {
    let segments = parse_access_path(path);
    let mut bases = vec![(func, value)];
    let mut cells = Vec::new();
    for (step, (kind, label)) in segments.iter().enumerate() {
        cells.clear();
        for (base_func, base_value) in &bases {
            let base = canonical_heap_value(fg, *base_func, *base_value);
            let cell = if kind == "field" {
                fg.field_cells.get(&(*base_func, base, label.clone()))
            } else {
                fg.index_cells.get(&(*base_func, base, label.clone()))
            };
            if let Some(cell) = cell { cells.push(*cell); }
        }
        cells.sort_unstable_by_key(|cell| cell.index());
        cells.dedup();
        // The last step asks for cells, not their contents. Expanding contents
        // here repeats a transitive bridge walk for every summary path.
        if cells.is_empty() || step + 1 == segments.len() { break; }
        bases = cells.iter().flat_map(|cell| cell_projected_values(fg, *cell)).collect();
        bases.sort_unstable(); bases.dedup();
    }
    cells
}

fn relative_path_candidate_cells_for_port(
    fg: &FlowGraph,
    port_node: NodeIndex,
    path: &str,
) -> Vec<NodeIndex> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let sources = fg.call_port_source_values(port_node);
    for (func, value) in sources {
        // A summary describes existing effects. Creating cells while querying
        // inferred paths feeds those cells back into the next shape summary,
        // inventing nested effects and an ever-growing solver universe. Actual
        // callee projections are materialized by the explicit heap bridge.
        for cell in existing_cells_for_relative_path_from_value(fg, func, value, path) {
            if seen.insert(cell) {
                out.push(cell);
            }
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn cell_store_values_before_edge(
    fg: &FlowGraph,
    cell: NodeIndex,
    cutoff_edge_idx: Option<usize>,
) -> Vec<(FunctionId, ValueId)> {
    // Visibility already walks the complete alias/bridge closure. Recursing
    // over that closure again reruns a whole-graph store query for every cell.
    direct_cell_store_values_before_edge(fg, cell, cutoff_edge_idx)
}

fn cell_store_values(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    cell_store_values_before_edge(fg, cell, None)
}

fn cell_values_for_flow_before_edge(
    fg: &FlowGraph,
    cell: NodeIndex,
    cutoff_edge_idx: Option<usize>,
) -> Vec<(FunctionId, ValueId)> {
    let stored = cell_store_values_before_edge(fg, cell, cutoff_edge_idx);
    if stored.is_empty() {
        cell_projected_values(fg, cell)
    } else {
        stored
    }
}

fn cell_values_for_flow(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    if let Some(live) = fg.cell_live_values.get(&cell.index()) {
        return if live.is_empty() { cell_projected_values(fg, cell) } else {
            live.iter().map(|(func, value)| (FunctionId(*func), ValueId(*value))).collect()
        };
    }
    cell_values_for_flow_before_edge(fg, cell, None)
}

fn bridge_nested_heap_values(
    fg: &mut FlowGraph,
    left_func: FunctionId,
    left_value: ValueId,
    right_func: FunctionId,
    right_value: ValueId,
    visited: &mut HashSet<(u32, u32, u32, u32)>,
) {
    let key = (left_func.0, left_value.0, right_func.0, right_value.0);
    if !visited.insert(key) {
        return;
    }

    let left_root = canonical_heap_value(fg, left_func, left_value);
    let right_root = canonical_heap_value(fg, right_func, right_value);

    let mut field_names = HashSet::new();
    for (func, base, field) in fg.field_cells.keys() {
        if (*func == left_func && *base == left_root)
            || (*func == right_func && *base == right_root)
        {
            field_names.insert(field.clone());
        }
    }

    for field in field_names {
        let left_cell = ensure_field_cell(fg, left_func, left_value, &field);
        let right_cell = ensure_field_cell(fg, right_func, right_value, &field);
        connect_heap_binding(fg, left_cell, right_cell);
        // Bridge source-level projections, not the global may-alias/live sets.
        // Inferred sets can already contain values from unrelated slots and
        // feeding them back here creates artificial recursive heap structure.
        let left_projected = direct_cell_projected_values(fg, left_cell);
        let right_projected = direct_cell_projected_values(fg, right_cell);
        for (lf, lv) in &left_projected {
            for (rf, rv) in &right_projected {
                if !heap_projection_values_compatible(fg, *lf, *lv, *rf, *rv) {
                    continue;
                }
                connect_bidirectional_value_pair(fg, *lf, *lv, *rf, *rv);
                bridge_nested_heap_values(fg, *lf, *lv, *rf, *rv, visited);
            }
        }
    }

    let mut index_keys = index_keys_for_value(fg, left_func, left_value);
    for key in index_keys_for_value(fg, right_func, right_value) {
        if !index_keys.contains(&key) {
            index_keys.push(key);
        }
    }
    // Unknown-index accesses already have a '*' key in the IR-derived cells.
    // Do not invent one for every object: it aliases all precise array slots
    // and even turns plain scalar/field values into synthetic containers.

    for key in index_keys {
        let mut left_cells = index_cells_for_key(fg, left_func, left_value, &key);
        if left_cells.is_empty() {
            left_cells.push(ensure_index_cell(fg, left_func, left_value, &key));
        }
        let mut right_cells = index_cells_for_key(fg, right_func, right_value, &key);
        if right_cells.is_empty() {
            right_cells.push(ensure_index_cell(fg, right_func, right_value, &key));
        }
        for left_cell in &left_cells {
            for right_cell in &right_cells {
                connect_heap_binding(fg, *left_cell, *right_cell);
                let left_projected = direct_cell_projected_values(fg, *left_cell);
                let right_projected = direct_cell_projected_values(fg, *right_cell);
                for (lf, lv) in &left_projected {
                    for (rf, rv) in &right_projected {
                        if !heap_projection_values_compatible(fg, *lf, *lv, *rf, *rv) {
                            continue;
                        }
                        connect_bidirectional_value_pair(fg, *lf, *lv, *rf, *rv);
                        bridge_nested_heap_values(fg, *lf, *lv, *rf, *rv, visited);
                    }
                }
            }
        }
    }
}

fn connect_returned_path_projection(
    fg: &mut FlowGraph,
    caller_func: FunctionId,
    actual_value: ValueId,
    steps: &[ProjectionStep],
    dst: ValueId,
) {
    if steps.is_empty() {
        let actual_node = value_node(fg, caller_func, actual_value);
        let dst_node = value_node(fg, caller_func, dst);
        fg.graph.add_edge(
            actual_node,
            dst_node,
            FlowEdge {
                kind: EdgeKind::Assign,
            },
        );
        propagate_object_identity_site(fg, caller_func, actual_value, caller_func, dst);
        let mut visited = HashSet::new();
        bridge_nested_heap_values(
            fg,
            caller_func,
            actual_value,
            caller_func,
            dst,
            &mut visited,
        );
        return;
    }

    let mut frontier = vec![(caller_func, actual_value)];
    for (step_idx, step) in steps.iter().enumerate() {
        let is_last = step_idx + 1 == steps.len();
        let mut next_frontier = Vec::new();
        let mut seen_values = HashSet::new();
        let mut seen_cells = HashSet::new();
        for (func, value) in &frontier {
            match step {
                ProjectionStep::Field(field) => {
                    let cell = ensure_field_cell(fg, *func, *value, field);
                    if !seen_cells.insert(cell) {
                        continue;
                    }
                    if is_last {
                        let dst_node = value_node(fg, caller_func, dst);
                        fg.graph.add_edge(
                            cell,
                            dst_node,
                            FlowEdge {
                                kind: EdgeKind::LoadField {
                                    field: field.clone(),
                                },
                            },
                        );
                    }
                    for projected in direct_cell_projected_values(fg, cell) {
                        if seen_values.insert(projected) {
                            if is_last {
                                let mut visited = HashSet::new();
                                connect_bidirectional_value_pair(
                                    fg,
                                    projected.0,
                                    projected.1,
                                    caller_func,
                                    dst,
                                );
                                propagate_object_identity_site(
                                    fg,
                                    projected.0,
                                    projected.1,
                                    caller_func,
                                    dst,
                                );
                                bridge_nested_heap_values(
                                    fg,
                                    projected.0,
                                    projected.1,
                                    caller_func,
                                    dst,
                                    &mut visited,
                                );
                            } else {
                                next_frontier.push(projected);
                            }
                        }
                    }
                }
                ProjectionStep::Index(key) => {
                    let mut cells = index_cells_for_key(fg, *func, *value, key);
                    if cells.is_empty() {
                        cells.push(ensure_index_cell(fg, *func, *value, key));
                    }
                    for cell in cells {
                        if !seen_cells.insert(cell) {
                            continue;
                        }
                        if is_last {
                            let dst_node = value_node(fg, caller_func, dst);
                            fg.graph.add_edge(
                                cell,
                                dst_node,
                                FlowEdge {
                                    kind: EdgeKind::LoadIndex,
                                },
                            );
                        }
                        for projected in direct_cell_projected_values(fg, cell) {
                            if seen_values.insert(projected) {
                                if is_last {
                                    let mut visited = HashSet::new();
                                    connect_bidirectional_value_pair(
                                        fg,
                                        projected.0,
                                        projected.1,
                                        caller_func,
                                        dst,
                                    );
                                    bridge_nested_heap_values(
                                        fg,
                                        projected.0,
                                        projected.1,
                                        caller_func,
                                        dst,
                                        &mut visited,
                                    );
                                } else {
                                    next_frontier.push(projected);
                                }
                            }
                        }
                    }
                }
            }
        }
        if is_last {
            break;
        }
        frontier = next_frontier;
        if frontier.is_empty() {
            break;
        }
    }
}

fn bridge_internal_heap_cells(fg: &mut FlowGraph, program: &Program) {
    for caller_func in &program.functions {
        for block in &caller_func.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else {
                    continue;
                };
                let Some(targets) = fg
                    .resolved_internal_targets
                    .get(&(caller_func.id, inst.id))
                    .cloned()
                else {
                    continue;
                };
                for target_name in targets {
                    let Some(callee_func) = program.find_function_by_name(&target_name) else {
                        continue;
                    };
                    let bindings = compute_actual_formal_bindings(call, callee_func);
                    let mut visited = HashSet::new();
                    for (_, actual_value, ir_index) in &bindings {
                        let Some(formal_value) = callee_func.params.get(*ir_index).copied() else {
                            continue;
                        };
                        bridge_nested_heap_values(
                            fg,
                            caller_func.id,
                            *actual_value,
                            callee_func.id,
                            formal_value,
                            &mut visited,
                        );
                    }
                    if let Some(dst) = call.dst {
                        for projection in returned_projections(fg, callee_func) {
                            match projection {
                                ReturnedProjection::Param { ir_index } => {
                                    let Some((_, actual_value, _)) =
                                        bindings.iter().find(|(_, _, idx)| *idx == ir_index)
                                    else {
                                        continue;
                                    };
                                    connect_returned_path_projection(
                                        fg,
                                        caller_func.id,
                                        *actual_value,
                                        &[],
                                        dst,
                                    );
                                }
                                ReturnedProjection::Path { ir_index, steps } => {
                                    let Some((_, actual_value, _)) =
                                        bindings.iter().find(|(_, _, idx)| *idx == ir_index)
                                    else {
                                        continue;
                                    };
                                    connect_returned_path_projection(
                                        fg,
                                        caller_func.id,
                                        *actual_value,
                                        &steps,
                                        dst,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
