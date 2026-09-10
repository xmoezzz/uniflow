#[derive(Clone, Debug)]
pub struct BuildProgress {
    pub stage: &'static str,
    pub detail: String,
}

pub fn build(program: &Program, rules: &RuleSet) -> FlowGraph {
    build_with_progress(program, rules, |_| {})
}

pub fn build_with_progress<F>(program: &Program, rules: &RuleSet, mut on_progress: F) -> FlowGraph
where
    F: FnMut(BuildProgress),
{
    on_progress(BuildProgress {
        stage: "init",
        detail: format!(
            "{} source files, {} functions",
            program.source_files.len(),
            program.functions.len()
        ),
    });
    let mut fg = FlowGraph::default();
    fg.language = program.language.clone();
    for file in &program.source_files {
        fg.file_paths.insert(file.id, file.path.clone());
    }
    for (ty, parents) in &program.type_hierarchy {
        fg.type_hierarchy.insert(ty.clone(), parents.clone());
    }
    let (lifetime_states, lifetime_block_states, lifetime_diagnostics) =
        analyze_program_lifetimes(program);
    fg.lifetime_states = lifetime_states;
    fg.lifetime_block_states = lifetime_block_states;
    fg.lifetime_diagnostics = lifetime_diagnostics;
    for function in &program.functions {
        for (value, semantics) in &function.value_cpp {
            fg.value_cpp
                .insert((function.id, *value), semantics.clone());
        }
    }

    on_progress(BuildProgress {
        stage: "create-function-nodes",
        detail: format!("{} functions", program.functions.len()),
    });
    for func in &program.functions {
        fg.function_names.insert(func.id, func.name.clone());
        fg.function_spans.insert(func.id, func.span);
        for (value, span) in &func.value_spans {
            fg.value_spans.insert((func.id, *value), *span);
        }
        for (value, ty) in &func.value_types {
            fg.value_types.insert((func.id, *value), ty.clone());
        }
        if let Some(names) = func.attrs.get("value_names") {
            for entry in names.split('\u{1f}') {
                let Some((value, name)) = entry.split_once('=') else {
                    continue;
                };
                let Ok(value) = value.parse::<u32>() else {
                    continue;
                };
                fg.value_names
                    .insert((func.id, ValueId(value)), name.to_string());
            }
        }
        if let Some(names) = func.attrs.get("param_names") {
            let receiver_offset = function_receiver_offset(func);
            for (value, name) in func.params.iter().skip(receiver_offset).zip(names.split('\u{1f}')) {
                if !name.is_empty() {
                    fg.value_names.insert((func.id, *value), name.to_string());
                }
            }
        }
        create_function_nodes(&mut fg, func);
        attach_function_sources_and_sinks(&mut fg, rules, func);
        attach_named_value_sources(&mut fg, rules, func);
    }

    on_progress(BuildProgress {
        stage: "index-functions",
        detail: format!("{} candidate callees", program.functions.len()),
    });
    let func_index = FunctionIndex::new(program);

    on_progress(BuildProgress {
        stage: "scan-function-bodies",
        detail: format!("{} functions", program.functions.len()),
    });
    for func in &program.functions {
        let ret_node = *fg
            .function_returns
            .get(&func.id)
            .expect("return node must exist");
        let alias_roots = compute_value_alias_representatives(func);
        let heap_alias_roots = compute_heap_alias_representatives(func);
        let (object_identity_roots, object_identity_sites) =
            compute_object_identity_representatives(func);
        let literal_index_keys = compute_literal_index_keys(func, &program.language);
        for (value, literal) in &literal_index_keys {
            let literal = if func
                .value_types
                .get(value)
                .is_some_and(|ty| matches!(ty.as_str(), "bool" | "boolean" | "Boolean" | "java.lang.Boolean"))
            {
                match literal.as_str() {
                    "0" => "false",
                    "1" => "true",
                    _ => literal,
                }
            } else {
                literal
            };
            fg.value_constants
                .insert((func.id, *value), literal.to_string());
        }
        for (value, root) in &alias_roots {
            fg.value_alias_roots.insert((func.id, *value), *root);
        }
        for (value, root) in &heap_alias_roots {
            fg.heap_alias_roots.insert((func.id, *value), *root);
        }
        for (value, root) in &object_identity_roots {
            fg.object_identity_roots.insert((func.id, *value), *root);
        }
        for (value, site) in &object_identity_sites {
            fg.object_identity_sites
                .insert((func.id, *value), site.clone());
        }
        let mut abstract_field_cells: HashMap<(ValueId, String), NodeIndex> = HashMap::new();
        let mut abstract_index_cells: HashMap<(ValueId, String), NodeIndex> = HashMap::new();

        for block in &func.blocks {
            let mut successors = match &block.term {
                uniflow_ir::Terminator::Goto(target) => vec![*target],
                uniflow_ir::Terminator::Branch {
                    then_bb, else_bb, ..
                } => vec![*then_bb, *else_bb],
                uniflow_ir::Terminator::Return(_)
                | uniflow_ir::Terminator::Throw(_)
                | uniflow_ir::Terminator::Unreachable => Vec::new(),
            };
            successors.extend(
                func.exception_edges
                    .iter()
                    .filter(|edge| edge.from == block.id)
                    .map(|edge| edge.unwind),
            );
            successors.sort_by_key(|block| block.0);
            successors.dedup();
            fg.block_successors
                .insert((func.id, block.id), successors);

            for (position, inst) in block.insts.iter().enumerate() {
                fg.inst_spans.insert((func.id, inst.id), inst.span);
                fg.inst_control_positions
                    .insert((func.id, inst.id), (block.id, position));
                match &inst.kind {
                    InstKind::ConstInt { .. } | InstKind::ConstString { .. } => {}
                    InstKind::Copy { dst, src } | InstKind::NumericStep { dst, src, .. } => {
                        edge_value_to_value(&mut fg, func.id, *src, *dst, EdgeKind::Assign);
                    }
                    InstKind::Move { dst, src } => {
                        edge_value_to_value(&mut fg, func.id, *src, *dst, EdgeKind::Assign);
                        // CFG-sensitive lifetime state is computed before graph materialization.
                    }
                    InstKind::Cast { dst, src, kind, .. } => {
                        let rule_id = match kind {
                            uniflow_ir::CppCastKind::Dynamic => "builtin.cpp.cast.dynamic",
                            uniflow_ir::CppCastKind::Reinterpret => "builtin.cpp.cast.reinterpret",
                            uniflow_ir::CppCastKind::Const => "builtin.cpp.cast.const",
                            uniflow_ir::CppCastKind::Static => "builtin.cpp.cast.static",
                        };
                        let src_node = value_node(&fg, func.id, *src);
                        let dst_node = value_node(&fg, func.id, *dst);
                        fg.graph.add_edge(
                            src_node,
                            dst_node,
                            FlowEdge {
                                kind: EdgeKind::Summary {
                                    rule_id: rule_id.to_string(),
                                },
                            },
                        );
                    }
                    InstKind::Lifetime { .. } => {
                        // Lifetime events are consumed by the CFG-sensitive lifetime solver.
                    }
                    InstKind::Phi { dst, inputs } => {
                        for input in inputs {
                            edge_value_to_value(&mut fg, func.id, *input, *dst, EdgeKind::Phi);
                        }
                    }
                    InstKind::LoadField { dst, base, field } => {
                        let canonical_base = canonical_heap_value(&fg, func.id, *base);
                        let field_key = (canonical_base, field.clone());
                        let field_cell = *abstract_field_cells
                            .entry(field_key.clone())
                            .or_insert_with(|| {
                                let node = fg.graph.add_node(FlowNode::FieldCell {
                                    func: func.id,
                                    block: block.id,
                                    inst: inst.id,
                                    base: canonical_base,
                                    field: field.clone(),
                                });
                                fg.field_cells
                                    .insert((func.id, canonical_base, field.clone()), node);
                                node
                            });
                        let base_node = value_node(&fg, func.id, *base);
                        fg.graph.add_edge(
                            base_node,
                            field_cell,
                            FlowEdge {
                                kind: EdgeKind::LoadField {
                                    field: field.clone(),
                                },
                            },
                        );
                        connect_cell_projected_values_to_dst(
                            &mut fg,
                            field_cell,
                            func.id,
                            *dst,
                            EdgeKind::LoadField {
                                field: field.clone(),
                            },
                        );
                        attach_field_sources(&mut fg, rules, func.id, inst.id, *base, field, *dst);
                    }
                    InstKind::StoreField { base, field, src } => {
                        let canonical_base = canonical_heap_value(&fg, func.id, *base);
                        let field_key = (canonical_base, field.clone());
                        let field_cell = *abstract_field_cells
                            .entry(field_key.clone())
                            .or_insert_with(|| {
                                let node = fg.graph.add_node(FlowNode::FieldCell {
                                    func: func.id,
                                    block: block.id,
                                    inst: inst.id,
                                    base: canonical_base,
                                    field: field.clone(),
                                });
                                fg.field_cells
                                    .insert((func.id, canonical_base, field.clone()), node);
                                node
                            });
                        let src_node = value_node(&fg, func.id, *src);
                        fg.graph.add_edge(
                            src_node,
                            field_cell,
                            FlowEdge {
                                kind: EdgeKind::StoreField {
                                    field: field.clone(),
                                },
                            },
                        );
                        attach_field_sinks(&mut fg, rules, func.id, inst.id, *base, field, *src);
                    }
                    InstKind::LoadIndex { dst, base, index } => {
                        let canonical_base = canonical_heap_value(&fg, func.id, *base);
                        let key = abstract_index_key(&literal_index_keys, *index);
                        let cell = *abstract_index_cells
                            .entry((canonical_base, key.clone()))
                            .or_insert_with(|| {
                                let node = fg.graph.add_node(FlowNode::IndexCell {
                                    func: func.id,
                                    block: block.id,
                                    inst: inst.id,
                                    base: canonical_base,
                                    index: *index,
                                    abstract_key: key.clone(),
                                });
                                fg.index_cells
                                    .insert((func.id, canonical_base, key.clone()), node);
                                node
                            });
                        let base_node = value_node(&fg, func.id, *base);
                        fg.graph.add_edge(
                            base_node,
                            cell,
                            FlowEdge {
                                kind: EdgeKind::LoadIndex,
                            },
                        );
                        connect_cell_projected_values_to_dst(
                            &mut fg,
                            cell,
                            func.id,
                            *dst,
                            EdgeKind::LoadIndex,
                        );
                        attach_index_sinks(
                            &mut fg,
                            rules,
                            func.id,
                            inst.id,
                            *base,
                            *index,
                            true,
                        );
                    }
                    InstKind::StoreIndex { base, index, src } => {
                        let canonical_base = canonical_heap_value(&fg, func.id, *base);
                        let key = abstract_index_key(&literal_index_keys, *index);
                        let cell = *abstract_index_cells
                            .entry((canonical_base, key.clone()))
                            .or_insert_with(|| {
                                let node = fg.graph.add_node(FlowNode::IndexCell {
                                    func: func.id,
                                    block: block.id,
                                    inst: inst.id,
                                    base: canonical_base,
                                    index: *index,
                                    abstract_key: key.clone(),
                                });
                                fg.index_cells
                                    .insert((func.id, canonical_base, key.clone()), node);
                                node
                            });
                        let src_node = value_node(&fg, func.id, *src);
                        fg.graph.add_edge(
                            src_node,
                            cell,
                            FlowEdge {
                                kind: EdgeKind::StoreIndex,
                            },
                        );
                        attach_index_sinks(
                            &mut fg,
                            rules,
                            func.id,
                            inst.id,
                            *base,
                            *index,
                            false,
                        );
                    }
                    InstKind::Call(call) => {
                        let meta = build_call_meta(&fg, func, inst.id, call, inst.span);
                        fg.call_meta.insert((func.id, inst.id), meta.clone());
                        connect_call_value_ports(&mut fg, func.id, inst.id, call);
                        connect_registered_lambda_captures(&mut fg, program, func.id, call);

                        connect_builtin_python_container_semantics(
                            &mut fg,
                            func.id,
                            call,
                            &meta,
                            &literal_index_keys,
                        );
                        connect_python_container_semantics(
                            &mut fg,
                            func.id,
                            call,
                            &meta,
                            &literal_index_keys,
                        );
                        connect_builtin_language_call_semantics(&mut fg, func, call);
                        let mut resolved_targets = Vec::new();
                        for callee_func in func_index.resolve_call(&meta) {
                            if !resolved_targets
                                .iter()
                                .any(|existing| existing == &callee_func.name)
                            {
                                resolved_targets.push(callee_func.name.clone());
                            }
                            connect_internal_call(
                                &mut fg,
                                func.id,
                                inst.id,
                                call,
                                callee_func,
                                ret_node,
                            );
                        }
                        if !resolved_targets.is_empty() {
                            fg.resolved_internal_targets
                                .insert((func.id, inst.id), resolved_targets);
                        } else if matches!(&program.language, uniflow_hir::Language::Cpp) {
                            connect_unknown_cpp_call_effects(&mut fg, func, call);
                            // Escape/consume effects are handled by the CFG-sensitive lifetime
                            // solver using typed reference and ownership semantics.
                        }
                        connect_rule_summaries(&mut fg, rules, func.id, inst.id, call, &meta);
                        attach_rule_sources_and_sinks(
                            &mut fg, rules, func.id, inst.id, call, &meta,
                        );
                        attach_unused_return_sinks(
                            &mut fg, rules, func.id, inst.id, call, &meta,
                        );
                    }
                }
            }

            match &block.term {
                Terminator::Return(Some(value)) => {
                    let src_node = value_node(&fg, func.id, *value);
                    fg.graph.add_edge(
                        src_node,
                        ret_node,
                        FlowEdge {
                            kind: EdgeKind::Assign,
                        },
                    );
                }
                Terminator::Throw(Some(value)) => {
                    // Preserve exceptional value flow for callers and catch summaries.  Control
                    // transfer is represented by Function::exception_edges; this edge only keeps
                    // the thrown payload visible to demand/taint queries.
                    let src_node = value_node(&fg, func.id, *value);
                    fg.graph.add_edge(
                        src_node,
                        ret_node,
                        FlowEdge {
                            kind: EdgeKind::Summary {
                                rule_id: "builtin.exception.throw".to_string(),
                            },
                        },
                    );
                }
                Terminator::Return(None)
                | Terminator::Throw(None)
                | Terminator::Goto(_)
                | Terminator::Branch { .. }
                | Terminator::Unreachable => {}
            }
        }

        // Bind an explicit thrown payload to the SSA value used by the selected catch parameter.
        // This keeps taint/value-flow intact across exceptional control transfer instead of
        // treating catch variables as unrelated fresh values.
        for edge in &func.exception_edges {
            let (Some(thrown), Some(caught)) = (edge.thrown_value, edge.catch_value) else {
                continue;
            };
            let src_node = value_node(&fg, func.id, thrown);
            let dst_node = value_node(&fg, func.id, caught);
            fg.graph.add_edge(
                src_node,
                dst_node,
                FlowEdge {
                    kind: EdgeKind::Summary {
                        rule_id: "builtin.exception.catch".to_string(),
                    },
                },
            );
        }
    }

    on_progress(BuildProgress {
        stage: "sparse-adjacency-1",
        detail: format!("{} graph nodes", fg.graph.node_count()),
    });
    materialize_sparse_data_adjacency(&mut fg);
    materialize_points_to_fixpoint(&mut fg);
    materialize_points_to_targets_fixpoint(&mut fg);
    materialize_points_to_object_ids(&mut fg);
    materialize_points_to_partitions(&mut fg);
    on_progress(BuildProgress {
        stage: "bridge-internal-heap-cells",
        detail: format!("{} functions", program.functions.len()),
    });
    // Return projections must exist before resolving a callback returned from
    // an internal function. Bridges only consult direct IR-derived cells.
    bridge_internal_heap_cells(&mut fg, program);
    materialize_sparse_data_adjacency(&mut fg);
    resolve_dynamic_internal_calls(&mut fg, program, &func_index, rules);
    materialize_sparse_data_adjacency(&mut fg);
    on_progress(BuildProgress {
        stage: "global-closure-1",
        detail: format!("{} functions", program.functions.len()),
    });
    materialize_global_solver_closure(&mut fg, program);
    // All existing structural bridges participate in the global closure.
    on_progress(BuildProgress {
        stage: "sparse-adjacency-3",
        detail: format!("{} graph nodes, {} edges", fg.graph.node_count(), fg.graph.edge_count()),
    });
    materialize_sparse_data_adjacency(&mut fg);
    on_progress(BuildProgress {
        stage: "done",
        detail: format!("{} graph nodes", fg.graph.node_count()),
    });

    fg
}

fn attach_named_value_sources(fg: &mut FlowGraph, rules: &RuleSet, func: &Function) {
    let synthetic_inst = InstId(u32::MAX);
    for rule in &rules.named_value_sources {
        if !language_matches(&rule.language, &fg.language) {
            continue;
        }
        for value in fg
            .value_names
            .iter()
            .filter(|((candidate, _), name)| {
                *candidate == func.id && rule.matches_name(name)
            })
            .map(|((_, value), _)| *value)
            .collect::<Vec<_>>()
        {
            let Some(&target) = fg.values.get(&(func.id, value)) else {
                continue;
            };
            let source = fg.graph.add_node(FlowNode::SyntheticSource {
                func: func.id,
                inst: synthetic_inst,
                rule_id: rule.id.clone(),
                kind: rule.kind.clone(),
                out: Port::Return,
            });
            fg.synthetic_sources.push(source);
            fg.graph.add_edge(
                source,
                target,
                FlowEdge {
                    kind: EdgeKind::Source {
                        rule_id: rule.id.clone(),
                    },
                },
            );
        }
    }
}

fn field_owner_candidates(fg: &FlowGraph, func: FunctionId, base: ValueId) -> Vec<String> {
    let mut owners = fg.value_types
        .get(&(func, base))
        .map(|owner| expand_receiver_type_candidates(&fg.type_hierarchy, owner, false))
        .unwrap_or_default();
    if let Some(symbol) = fg
        .value_constants
        .get(&(func, base))
        .and_then(|value| external_symbol_name(value))
    {
        if !owners.iter().any(|owner| owner == symbol) {
            owners.push(symbol.to_string());
        }
    }
    if let Some(name) = fg.value_names.get(&(func, base)) {
        if !owners.iter().any(|owner| owner == name) {
            owners.push(name.clone());
        }
    }
    owners
}

fn connect_registered_lambda_captures(
    fg: &mut FlowGraph,
    program: &Program,
    caller_func: FunctionId,
    call: &CallInst,
) {
    for argument in &call.args {
        let Some(function_name) = fg.value_types.get(&(caller_func, *argument)) else {
            continue;
        };
        let Some(callback) = program
            .functions
            .iter()
            .find(|function| function.name == *function_name && function.name.contains("__lambda_"))
        else {
            continue;
        };
        connect_lambda_capture_bindings(fg, caller_func, *argument, callback);
    }
}

fn attach_field_sources(
    fg: &mut FlowGraph,
    rules: &RuleSet,
    func: FunctionId,
    inst: InstId,
    base: ValueId,
    field: &str,
    dst: ValueId,
) {
    let owners = field_owner_candidates(fg, func, base);
    if owners.is_empty() {
        return;
    }
    for rule in &rules.field_sources {
        if !language_matches(&rule.language, &fg.language) || !rule.matcher.matches(&owners, field)
        {
            continue;
        }
        let source = fg.graph.add_node(FlowNode::SyntheticSource {
            func,
            inst,
            rule_id: rule.id.clone(),
            kind: rule.kind.clone(),
            out: Port::Member(field.to_string()),
        });
        fg.synthetic_sources.push(source);
        let destination = value_node(fg, func, dst);
        fg.graph.add_edge(
            source,
            destination,
            FlowEdge {
                kind: EdgeKind::Source {
                    rule_id: rule.id.clone(),
                },
            },
        );
    }
}

fn attach_field_sinks(
    fg: &mut FlowGraph,
    rules: &RuleSet,
    func: FunctionId,
    inst: InstId,
    base: ValueId,
    field: &str,
    src: ValueId,
) {
    let owners = field_owner_candidates(fg, func, base);
    if owners.is_empty() {
        return;
    }
    for rule in &rules.field_sinks {
        if !language_matches(&rule.language, &fg.language) || !rule.matcher.matches(&owners, field)
        {
            continue;
        }
        let sink = fg.graph.add_node(FlowNode::SyntheticSink {
            func,
            inst,
            rule_id: rule.id.clone(),
            kind: rule.kind.clone(),
            input: Port::Member(field.to_string()),
        });
        fg.synthetic_sinks.push(sink);
        let source = value_node(fg, func, src);
        fg.graph.add_edge(
            source,
            sink,
            FlowEdge {
                kind: EdgeKind::Sink {
                    rule_id: rule.id.clone(),
                },
            },
        );
    }
}

fn attach_index_sinks(
    fg: &mut FlowGraph,
    rules: &RuleSet,
    func: FunctionId,
    inst: InstId,
    base: ValueId,
    index: ValueId,
    is_load: bool,
) {
    for rule in &rules.index_sinks {
        if !language_matches(&rule.language, &fg.language) {
            continue;
        }
        if (is_load && !rule.on_load) || (!is_load && !rule.on_store) {
            continue;
        }
        if !rule.matches_base_name(fg.value_names.get(&(func, base)).map(String::as_str)) {
            continue;
        }
        if rule.direct_only && fg.value_constants.contains_key(&(func, index)) {
            continue;
        }
        let sink = fg.graph.add_node(FlowNode::SyntheticSink {
            func,
            inst,
            rule_id: rule.id.clone(),
            kind: rule.kind.clone(),
            input: Port::Member("<computed-index>".to_string()),
        });
        fg.synthetic_sinks.push(sink);
        fg.graph.add_edge(
            value_node(fg, func, index),
            sink,
            FlowEdge {
                kind: EdgeKind::Sink {
                    rule_id: rule.id.clone(),
                },
            },
        );
    }
}

fn attach_function_sources_and_sinks(fg: &mut FlowGraph, rules: &RuleSet, func: &Function) {
    let owners = func
        .attrs
        .get("owner_type")
        .map(|owner| expand_receiver_type_candidates(&fg.type_hierarchy, owner, false))
        .unwrap_or_default();
    let decorators = func
        .attrs
        .get("python.decorators")
        .map(|value| {
            value
                .split('\u{1f}')
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let receiver_offset = function_receiver_offset(func);
    let visible_args = func.params.len().saturating_sub(receiver_offset);
    let synthetic_inst = InstId(u32::MAX);

    for rule in &rules.function_sources {
        if !language_matches(&rule.language, &fg.language)
            || !rule.matcher.matches(&func.name, &owners, &decorators)
        {
            continue;
        }
        for output in expand_port(&rule.out, visible_args) {
            let Some(target) = function_rule_port_node(fg, func, receiver_offset, &output) else {
                continue;
            };
            let source = fg.graph.add_node(FlowNode::SyntheticSource {
                func: func.id,
                inst: synthetic_inst,
                rule_id: rule.id.clone(),
                kind: rule.kind.clone(),
                out: output,
            });
            fg.synthetic_sources.push(source);
            fg.graph.add_edge(
                source,
                target,
                FlowEdge {
                    kind: EdgeKind::Source {
                        rule_id: rule.id.clone(),
                    },
                },
            );
        }
    }
    for rule in &rules.function_sinks {
        if !language_matches(&rule.language, &fg.language)
            || !rule.matcher.matches(&func.name, &owners, &decorators)
        {
            continue;
        }
        for input in rule
            .inputs
            .iter()
            .flat_map(|input| expand_port(input, visible_args))
        {
            let Some(source) = function_rule_port_node(fg, func, receiver_offset, &input) else {
                continue;
            };
            let sink = fg.graph.add_node(FlowNode::SyntheticSink {
                func: func.id,
                inst: synthetic_inst,
                rule_id: rule.id.clone(),
                kind: rule.kind.clone(),
                input,
            });
            fg.synthetic_sinks.push(sink);
            fg.graph.add_edge(
                source,
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

fn function_rule_port_node(
    fg: &FlowGraph,
    func: &Function,
    receiver_offset: usize,
    port: &Port,
) -> Option<NodeIndex> {
    match port {
        Port::Receiver if receiver_offset == 1 => fg.function_params.get(&(func.id, 0)).copied(),
        Port::Arg(index) => fg
            .function_params
            .get(&(func.id, index + receiver_offset))
            .copied(),
        Port::Return => fg.function_returns.get(&func.id).copied(),
        Port::Receiver
        | Port::NamedArg(_)
        | Port::NamedArgOrAll(_)
        | Port::Member(_)
        | Port::ArgsFrom(_)
        | Port::ArgsRange { .. } => None,
    }
}

fn connect_builtin_language_call_semantics(
    fg: &mut FlowGraph,
    function: &Function,
    call: &CallInst,
) {
    let is_javascript_composition = matches!(fg.language, uniflow_hir::Language::JavaScript)
        && matches!(
            &call.callee,
            Callee::Static(name)
                if name == "__uniflow.compose.string" || name == "__uniflow.compose.map"
        );
    if is_javascript_composition {
        let (Some(dst), Some(input)) = (call.dst, call.args.first().copied()) else {
            return;
        };
        fg.graph.add_edge(
            value_node(fg, function.id, input),
            value_node(fg, function.id, dst),
            FlowEdge {
                kind: EdgeKind::Summary {
                    rule_id: "builtin.javascript.expression-composition".to_string(),
                },
            },
        );
        return;
    }
    let is_shell_command_substitution = matches!(fg.language, uniflow_hir::Language::Shell)
        && matches!(
            &call.callee,
            Callee::Static(name) if name == "shell.command_substitution"
        );
    if !is_shell_command_substitution {
        return;
    }
    let Some(dst) = call.dst else {
        return;
    };
    let dst_node = value_node(fg, function.id, dst);
    for input in call.receiver.iter().chain(call.args.iter()) {
        fg.graph.add_edge(
            value_node(fg, function.id, *input),
            dst_node,
            FlowEdge {
                kind: EdgeKind::Summary {
                    rule_id: "builtin.shell.command-substitution".to_string(),
                },
            },
        );
    }
}

fn connect_unknown_cpp_call_effects(fg: &mut FlowGraph, function: &Function, call: &CallInst) {
    let inputs = call
        .receiver
        .iter()
        .chain(call.args.iter())
        .copied()
        .collect::<Vec<_>>();

    if let Some(dst) = call.dst {
        let dst_node = value_node(fg, function.id, dst);
        for src in &inputs {
            fg.graph.add_edge(
                value_node(fg, function.id, *src),
                dst_node,
                FlowEdge {
                    kind: EdgeKind::Summary {
                        rule_id: "builtin.cpp.unknown-call.return".to_string(),
                    },
                },
            );
        }
    }

    // Non-const pointers/references and owning handles are possible out-parameters.  Join every
    // input into each writable argument/receiver so library wrappers and unresolved templates do
    // not silently drop side effects.  The relation is deliberately may-flow and can be replaced
    // by an explicit model when one is available.
    let writable = inputs
        .iter()
        .copied()
        .filter(|value| cpp_unknown_call_may_write(function, *value))
        .collect::<Vec<_>>();
    for dst in writable {
        let dst_node = value_node(fg, function.id, dst);
        for src in &inputs {
            if src == &dst {
                continue;
            }
            fg.graph.add_edge(
                value_node(fg, function.id, *src),
                dst_node,
                FlowEdge {
                    kind: EdgeKind::Summary {
                        rule_id: "builtin.cpp.unknown-call.write-effect".to_string(),
                    },
                },
            );
        }
    }
}

fn cpp_unknown_call_may_write(function: &Function, value: ValueId) -> bool {
    let cpp = function.value_cpp.get(&value);
    if cpp.is_some_and(|cpp| {
        cpp.reference_kind != uniflow_hir::CppReferenceKind::None
            || matches!(
                cpp.ownership,
                uniflow_hir::CppOwnershipKind::Unique
                    | uniflow_hir::CppOwnershipKind::Shared
                    | uniflow_hir::CppOwnershipKind::Weak
                    | uniflow_hir::CppOwnershipKind::Raw
            )
    }) {
        return true;
    }
    function.value_types.get(&value).is_some_and(|ty| {
        let compact = ty.replace(' ', "");
        (compact.contains('*') || compact.contains('&')) && !compact.starts_with("const")
    })
}

#[derive(Default)]
struct FunctionIndex<'a> {
    exact: HashMap<&'a str, Vec<&'a Function>>,
    exact_arity: HashMap<(String, usize), Vec<&'a Function>>,
    simple: HashMap<String, Vec<&'a Function>>,
    simple_arity: HashMap<(String, usize), Vec<&'a Function>>,
    owner_method: HashMap<(String, String), Vec<&'a Function>>,
    owner_method_arity: HashMap<(String, String, usize), Vec<&'a Function>>,
    type_hierarchy: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ParamBindingKind {
    Positional,
    VarArgs,
    KwArgs,
    Capture,
}

#[derive(Clone, Debug)]
struct ParamBindingSpec {
    name: String,
    kind: ParamBindingKind,
    has_default: bool,
    keyword_only: bool,
    ir_index: usize,
}

impl<'a> FunctionIndex<'a> {
    fn new(program: &'a Program) -> Self {
        let mut index = Self::default();
        index.type_hierarchy = program
            .type_hierarchy
            .iter()
            .map(|(child, parents)| (child.clone(), parents.clone()))
            .collect();
        for func in &program.functions {
            let supported_arities = function_supported_arities(func);
            index
                .exact
                .entry(func.name.as_str())
                .or_default()
                .push(func);
            for arity in &supported_arities {
                index
                    .exact_arity
                    .entry((func.name.clone(), *arity))
                    .or_default()
                    .push(func);
            }
            for key in candidate_names(&func.name) {
                index.simple.entry(key.clone()).or_default().push(func);
                for arity in &supported_arities {
                    index
                        .simple_arity
                        .entry((key.clone(), *arity))
                        .or_default()
                        .push(func);
                }
            }
            if let Some(method) = func
                .name
                .rsplit(|ch| ch == '.' || ch == ':')
                .find(|part| !part.is_empty())
            {
                let owner = func
                    .cpp
                    .as_ref()
                    .map(|cpp| cpp.owner.clone())
                    .or_else(|| func.attrs.get("owner_type").cloned());
                if let Some(owner) = owner {
                    index
                        .owner_method
                        .entry((owner.clone(), method.to_string()))
                        .or_default()
                        .push(func);
                    for arity in &supported_arities {
                        index
                            .owner_method_arity
                            .entry((owner.clone(), method.to_string(), *arity))
                            .or_default()
                            .push(func);
                    }
                }
            }
        }
        index
    }

    fn descendant_types(&self, owner: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut changed = true;
        while changed {
            changed = false;
            for (child, parents) in &self.type_hierarchy {
                if (parents
                    .iter()
                    .any(|parent| parent == owner || out.iter().any(|known| known == parent)))
                    && !out.iter().any(|known| known == child)
                {
                    out.push(child.clone());
                    changed = true;
                }
            }
        }
        out
    }

    fn resolve_named_callable(
        &self,
        name: &str,
        arg_count: usize,
        arg_types: &[Option<String>],
        arg_type_candidates: &[Vec<String>],
    ) -> Vec<&'a Function> {
        let meta = CallMeta {
            func: FunctionId(0),
            inst: InstId(0),
            function_name: String::new(),
            callee_name: Some(name.to_string()),
            receiver_type: None,
            receiver_type_candidates: Vec::new(),
            receiver_parameter: None,
            method_name: None,
            arg_count,
            arg_types: arg_types.to_vec(),
            arg_type_candidates: arg_type_candidates.to_vec(),
            receiver_constant: None,
            receiver_symbol: None,
            arg_constants: Vec::new(),
            return_is_used: false,
            span: Span::default(),
        };
        self.resolve_call(&meta)
    }

    fn resolve_call(&self, meta: &CallMeta) -> Vec<&'a Function> {
        let mut out: Vec<&'a Function> = Vec::new();
        if let Some(method_name) = meta.method_name.as_deref() {
            let static_owner = meta.receiver_type.as_deref();
            let mut owners = meta.receiver_type_candidates.clone();
            if let Some(owner) = static_owner {
                if !owners.iter().any(|candidate| candidate == owner) {
                    owners.push(owner.to_string());
                }
                let exact = self
                    .owner_method
                    .get(&(owner.to_string(), method_name.to_string()))
                    .cloned()
                    .unwrap_or_default();
                // Resolve the overload contract before removing abstract declarations.  A pure
                // virtual declaration is not a concrete call target, but it still establishes
                // dynamic dispatch and must therefore bring compatible overrides from derived
                // classes into the candidate set.
                let refined_contracts =
                    refine_by_argument_types(exact.clone(), meta, &self.type_hierarchy);
                let selected_contracts = if refined_contracts.is_empty() {
                    exact.clone()
                } else {
                    refined_contracts
                };
                let has_virtual_contract = selected_contracts.iter().any(|function| {
                    cpp_method_is_virtual(function) || cpp_method_is_pure_virtual(function)
                });
                let selected_exact = selected_contracts
                    .iter()
                    .copied()
                    .filter(|function| !cpp_method_is_pure_virtual(function))
                    .collect::<Vec<_>>();

                // Static binding is decided after overload filtering. A different non-virtual
                // overload must not suppress dispatch for the selected virtual signature.
                if !selected_exact.is_empty()
                    && selected_exact.iter().all(|function| {
                        cpp_method_is_final(function) || !cpp_method_is_virtual(function)
                    })
                {
                    return selected_exact;
                }
                if has_virtual_contract {
                    for descendant in self.descendant_types(owner) {
                        if !owners.iter().any(|candidate| candidate == &descendant) {
                            owners.push(descendant);
                        }
                    }
                }
            }
            owners.sort();
            owners.dedup();
            for owner in &owners {
                if let Some(found) = self.owner_method_arity.get(&(
                    owner.clone(),
                    method_name.to_string(),
                    meta.arg_count,
                )) {
                    for function in found {
                        if cpp_method_is_pure_virtual(function) {
                            continue;
                        }
                        if !out.iter().any(|existing| existing.id == function.id) {
                            out.push(*function);
                        }
                    }
                }
            }
            if out.is_empty() {
                for owner in &owners {
                    if let Some(found) = self
                        .owner_method
                        .get(&(owner.clone(), method_name.to_string()))
                    {
                        for function in found {
                            if cpp_method_is_pure_virtual(function) {
                                continue;
                            }
                            if !out.iter().any(|existing| existing.id == function.id) {
                                out.push(*function);
                            }
                        }
                    }
                }
            }
            let refined = refine_by_argument_types(out.clone(), meta, &self.type_hierarchy);
            if !refined.is_empty() {
                return refined;
            }
            if !out.is_empty() {
                return out;
            }
        }
        let Some(name) = meta.callee_name.as_deref() else {
            return out;
        };
        if let Some(found) = self.exact_arity.get(&(name.to_string(), meta.arg_count)) {
            let refined = refine_by_argument_types(found.clone(), meta, &self.type_hierarchy);
            if !refined.is_empty() {
                return refined;
            }
            return found.clone();
        }
        if let Some(found) = self.exact.get(name) {
            if found.len() == 1 {
                return found.clone();
            }
        }
        // Calls on unresolved global/module receivers are external. Falling
        // back to a same-suffix local function (Object.assign -> assign)
        // creates false interprocedural edges and cross-call taint.
        if meta.receiver_symbol.is_some() {
            return out;
        }
        for key in candidate_names(name) {
            if let Some(found) = self.simple_arity.get(&(key.clone(), meta.arg_count)) {
                for func in found {
                    if !out.iter().any(|existing| existing.id == func.id) {
                        out.push(*func);
                    }
                }
            }
        }
        let refined = refine_by_argument_types(out.clone(), meta, &self.type_hierarchy);
        if !refined.is_empty() {
            return refined;
        }
        if !out.is_empty() {
            return out;
        }
        for key in candidate_names(name) {
            if let Some(found) = self.simple.get(&key) {
                for func in found {
                    if !out.iter().any(|existing| existing.id == func.id) {
                        out.push(*func);
                    }
                }
            }
        }
        let refined = refine_by_argument_types(out.clone(), meta, &self.type_hierarchy);
        if !refined.is_empty() {
            return refined;
        }
        out
    }
}

fn cpp_method_is_virtual(function: &Function) -> bool {
    function
        .cpp
        .as_ref()
        .is_some_and(|cpp| cpp.is_virtual || cpp.is_override)
        || function
            .attrs
            .get("cpp.virtual")
            .is_some_and(|value| value == "true")
        || function
            .attrs
            .get("cpp.override")
            .is_some_and(|value| value == "true")
}

fn cpp_method_is_final(function: &Function) -> bool {
    function.cpp.as_ref().is_some_and(|cpp| cpp.is_final)
        || function
            .attrs
            .get("cpp.final")
            .is_some_and(|value| value == "true")
}

fn cpp_method_is_pure_virtual(function: &Function) -> bool {
    function.cpp.as_ref().is_some_and(|cpp| cpp.is_pure_virtual)
        || function
            .attrs
            .get("cpp.pure_virtual")
            .is_some_and(|value| value == "true")
}

fn refine_by_argument_types<'a>(
    funcs: Vec<&'a Function>,
    meta: &CallMeta,
    hierarchy: &HashMap<String, Vec<String>>,
) -> Vec<&'a Function> {
    if funcs.len() <= 1 {
        return funcs;
    }
    let mut best_score: Option<usize> = None;
    let mut out = Vec::new();
    for func in funcs {
        let Some(score) = score_function_signature(func, meta, hierarchy) else {
            continue;
        };
        match best_score {
            None => {
                best_score = Some(score);
                out.push(func);
            }
            Some(existing) if score > existing => {
                best_score = Some(score);
                out.clear();
                out.push(func);
            }
            Some(existing) if score == existing => {
                out.push(func);
            }
            _ => {}
        }
    }
    out
}

fn score_function_signature(
    func: &Function,
    meta: &CallMeta,
    hierarchy: &HashMap<String, Vec<String>>,
) -> Option<usize> {
    let expected = function_param_type_names(func);
    if expected.len() != meta.arg_count {
        return None;
    }
    let mut score = 0usize;
    let mut seen_known = false;
    for (idx, expected_ty) in expected.iter().enumerate() {
        let Some(expected_ty) = expected_ty.as_deref() else {
            continue;
        };
        let actual_ty = meta.arg_types.get(idx).and_then(|ty| ty.clone());
        let actual_candidates = meta
            .arg_type_candidates
            .get(idx)
            .cloned()
            .unwrap_or_default();
        let Some(actual_ty) = actual_ty else {
            continue;
        };
        seen_known = true;
        let Some(rank) =
            cpp_conversion_rank(&actual_ty, expected_ty, &actual_candidates, hierarchy)
        else {
            return None;
        };
        // Higher scores are better. Exact binding dominates qualification, inheritance and
        // arithmetic promotions; ellipsis/default handling remains in arity binding.
        score += 16usize.saturating_sub(rank);
    }
    Some(if seen_known { score } else { 0 })
}

fn cpp_conversion_rank(
    actual: &str,
    expected: &str,
    candidates: &[String],
    hierarchy: &HashMap<String, Vec<String>>,
) -> Option<usize> {
    let actual = normalize_cpp_type(actual);
    let expected = normalize_cpp_type(expected);
    if actual == expected {
        return Some(0);
    }
    if strip_cpp_cv_ref(&actual) == strip_cpp_cv_ref(&expected) {
        return Some(1);
    }
    if candidates
        .iter()
        .any(|candidate| normalize_cpp_type(candidate) == expected)
    {
        return Some(2);
    }
    let actual_unqualified = strip_cpp_cv_ref(&actual);
    let expected_unqualified = strip_cpp_cv_ref(&expected);
    let actual_base = strip_cpp_pointer(&actual_unqualified);
    let expected_base = strip_cpp_pointer(&expected_unqualified);
    if cpp_is_derived_from(actual_base, expected_base, hierarchy) {
        return Some(3);
    }
    if cpp_numeric_rank(&actual).is_some() && cpp_numeric_rank(&expected).is_some() {
        let a = cpp_numeric_rank(&actual).unwrap_or(0);
        let e = cpp_numeric_rank(&expected).unwrap_or(0);
        return Some(if a <= e { 4 } else { 5 });
    }
    if (actual.ends_with('*') && expected == "void*")
        || (actual == "nullptr_t" && expected.ends_with('*'))
    {
        return Some(6);
    }
    None
}

fn normalize_cpp_type(value: &str) -> String {
    value
        .replace("std::", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" *", "*")
        .replace(" &", "&")
}

fn strip_cpp_cv_ref(value: &str) -> String {
    value
        .replace("const ", "")
        .replace("volatile ", "")
        .trim_end_matches("&&")
        .trim_end_matches('&')
        .trim()
        .to_string()
}

fn strip_cpp_pointer(value: &str) -> &str {
    value.trim_end_matches('*').trim()
}

fn cpp_is_derived_from(
    actual: &str,
    expected: &str,
    hierarchy: &HashMap<String, Vec<String>>,
) -> bool {
    if actual == expected {
        return true;
    }
    let mut work = vec![actual.to_string()];
    let mut seen = HashSet::new();
    while let Some(current) = work.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        for parent in hierarchy.get(&current).into_iter().flatten() {
            if parent == expected {
                return true;
            }
            work.push(parent.clone());
        }
    }
    false
}

fn cpp_numeric_rank(value: &str) -> Option<u8> {
    match strip_cpp_cv_ref(value).as_str() {
        "bool" => Some(0),
        "char" | "signed char" | "unsigned char" | "short" | "unsigned short" => Some(1),
        "int" | "unsigned" | "unsigned int" => Some(2),
        "long" | "unsigned long" | "long long" | "unsigned long long" => Some(3),
        "float" => Some(4),
        "double" => Some(5),
        "long double" => Some(6),
        _ => None,
    }
}

fn function_param_type_names(func: &Function) -> Vec<Option<String>> {
    function_param_specs(func)
        .into_iter()
        .map(|spec| {
            func.params
                .get(spec.ir_index)
                .and_then(|value| func.value_types.get(value).cloned())
        })
        .collect()
}

fn function_receiver_offset(func: &Function) -> usize {
    func.attrs
        .get("has_receiver")
        .map(|value| value == "1")
        .unwrap_or_else(|| func.attrs.contains_key("owner_type")) as usize
}

fn function_param_specs(func: &Function) -> Vec<ParamBindingSpec> {
    let offset = function_receiver_offset(func);
    let names = func
        .attrs
        .get("param_names")
        .map(|value| {
            value
                .split('\u{1f}')
                .filter(|part| !part.is_empty())
                .map(|part| part.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let count = func
        .attrs
        .get("arity")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(names.len());
    if count == 0 {
        return Vec::new();
    }
    let kinds = func
        .attrs
        .get("param_kinds")
        .map(|value| {
            value
                .split('\u{1f}')
                .map(|part| part.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let defaults = func
        .attrs
        .get("param_defaults")
        .map(|value| {
            value
                .split('\u{1f}')
                .map(|part| part.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let keyword_only = func
        .attrs
        .get("param_keyword_only")
        .map(|value| {
            value
                .split('\u{1f}')
                .map(|part| part.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    (0..count)
        .map(|idx| ParamBindingSpec {
            name: names
                .get(idx)
                .cloned()
                .unwrap_or_else(|| format!("arg{idx}")),
            kind: match kinds.get(idx).map(|value| value.as_str()) {
                Some("var") => ParamBindingKind::VarArgs,
                Some("kw") => ParamBindingKind::KwArgs,
                Some("cap") => ParamBindingKind::Capture,
                _ => ParamBindingKind::Positional,
            },
            has_default: defaults.get(idx).is_some_and(|value| value == "1"),
            keyword_only: keyword_only.get(idx).is_some_and(|value| value == "1"),
            ir_index: idx + offset,
        })
        .collect()
}

fn function_supported_arities(func: &Function) -> Vec<usize> {
    let specs = function_param_specs(func);
    if specs.is_empty() {
        let visible = func
            .attrs
            .get("arity")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        return vec![visible];
    }

    let mut min = 0usize;
    let mut max = 0usize;
    for spec in specs {
        if spec.kind == ParamBindingKind::Positional {
            max += 1;
            if !spec.has_default {
                min += 1;
            }
        }
    }
    let mut out = (min..=max).collect::<Vec<_>>();
    if out.is_empty() {
        out.push(0);
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn function_capture_names(func: &Function) -> Vec<String> {
    func.attrs
        .get("capture_names")
        .map(|value| {
            value
                .split('\u{1f}')
                .filter(|part| !part.is_empty())
                .map(|part| part.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn capture_param_ir_indices(func: &Function) -> Vec<(usize, String)> {
    let offset = function_receiver_offset(func);
    let visible = function_param_specs(func).len();
    function_capture_names(func)
        .into_iter()
        .enumerate()
        .map(|(idx, name)| (offset + visible + idx, name))
        .collect()
}

fn candidate_names(name: &str) -> Vec<String> {
    fn push_surface(out: &mut Vec<String>, surface: &str) {
        out.push(surface.to_string());
        if let Some(last) = surface.rsplit('.').next() {
            out.push(last.to_string());
        }
        if let Some(last) = surface.rsplit("::").next() {
            out.push(last.to_string());
        }
        if let Some((_, tail)) = surface.rsplit_once('.') {
            out.push(tail.to_string());
        }
    }

    let mut out = Vec::new();
    push_surface(&mut out, name);
    // The C++ frontend gives each observed concrete template call a stable synthetic
    // identity (for example `identity__uniflow_tpl_int`).  Keep that identity in
    // contexts and reports, but also resolve it against the generic template body so
    // data flow does not fall back to an unknown-call summary.
    if let Some(marker) = name.find("__uniflow_tpl_") {
        push_surface(&mut out, &name[..marker]);
    }
    out.sort();
    out.dedup();
    out
}
