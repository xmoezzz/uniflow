#[derive(Clone, Debug)]
pub struct BuildProgress {
    pub stage: &'static str,
    pub detail: String,
}

/// Expensive whole-program capabilities that may be materialized while
/// building a flow graph.  The public `build` APIs intentionally request the
/// full set for backwards compatibility; project scans can derive the smaller
/// set actually required by the selected rules and the IR they are scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalysisCapabilities {
    pub points_to: bool,
    pub heap: bool,
    pub dynamic_calls: bool,
    pub global_closure: bool,
}

impl AnalysisCapabilities {
    pub const fn full() -> Self {
        Self {
            points_to: true,
            heap: true,
            dynamic_calls: true,
            global_closure: true,
        }
    }

    /// Derive the least expensive solver plan that preserves the selected
    /// taint rules.  Direct assignments and statically resolved calls are
    /// already connected during the initial graph build, so they do not need
    /// points-to/global closure. Heap projections and dynamic calls do.
    pub fn for_rules(program: &Program, rules: &RuleSet) -> Self {
        if !rules_require_flow(rules) {
            return Self {
                points_to: false,
                heap: false,
                dynamic_calls: false,
                global_closure: false,
            };
        }

        let mut program_has_heap = false;
        let mut program_has_dynamic_calls = false;
        let mut program_has_receiver_calls = false;
        for function in &program.functions {
            for block in &function.blocks {
                for inst in &block.insts {
                    match &inst.kind {
                        InstKind::LoadField { .. }
                        | InstKind::StoreField { .. }
                        | InstKind::LoadIndex { .. }
                        | InstKind::StoreIndex { .. } => program_has_heap = true,
                        InstKind::Call(call) => {
                            program_has_dynamic_calls |= matches!(call.callee, Callee::Dynamic(_));
                            program_has_receiver_calls |= call.receiver.is_some();
                        }
                        _ => {}
                    }
                }
            }
        }

        // Member-port rules only create a field cell when a call has a
        // receiver.  Do not let the presence of such a rule in the bundled
        // catalog force points-to/heap materialization for a program that has
        // neither a heap instruction nor a receiver call.
        let heap = program_has_heap || (program_has_receiver_calls && rules_require_heap(rules));
        let dynamic_calls = program_has_dynamic_calls;
        let points_to = heap || dynamic_calls;
        Self {
            points_to,
            heap,
            dynamic_calls,
            // Project/rule-driven scans keep the whole-program summary closure
            // lazy. Static calls are wired during the initial graph build,
            // heap projections are connected by `bridge_internal_heap_cells`,
            // and dynamic calls are resolved explicitly below. Demand queries
            // can still build contextual/function summaries on demand without
            // eagerly retaining every global closure table in memory.
            //
            // `build()` / `build_with_progress()` continue to request
            // `AnalysisCapabilities::full()` for callers that explicitly need
            // the historical fully-materialized graph.
            global_closure: false,
        }
    }
}

fn rules_require_flow(rules: &RuleSet) -> bool {
    !rules.sources.is_empty()
        || !rules.sinks.is_empty()
        || !rules.unused_return_sinks.is_empty()
        || !rules.sanitizers.is_empty()
        || !rules.taint_transforms.is_empty()
        || !rules.propagators.is_empty()
        || !rules.summaries.is_empty()
        || !rules.field_sources.is_empty()
        || !rules.named_value_sources.is_empty()
        || !rules.field_sinks.is_empty()
        || !rules.index_sinks.is_empty()
        || !rules.field_sanitizers.is_empty()
        || !rules.function_sources.is_empty()
        || !rules.function_sinks.is_empty()
}

fn port_requires_heap(port: &Port) -> bool {
    matches!(port, Port::Member(_))
}

fn rules_require_heap(rules: &RuleSet) -> bool {
    !rules.field_sources.is_empty()
        || !rules.field_sinks.is_empty()
        || !rules.index_sinks.is_empty()
        || !rules.field_sanitizers.is_empty()
        || rules.sources.iter().any(|rule| port_requires_heap(&rule.out))
        || rules
            .sinks
            .iter()
            .flat_map(|rule| &rule.inputs)
            .any(port_requires_heap)
        || rules
            .sanitizers
            .iter()
            .flat_map(|rule| rule.inputs.iter().chain(&rule.outputs))
            .any(port_requires_heap)
        || rules
            .taint_transforms
            .iter()
            .flat_map(|rule| rule.inputs.iter().chain(&rule.outputs))
            .any(port_requires_heap)
        || rules
            .propagators
            .iter()
            .flat_map(|rule| &rule.flows)
            .any(|flow| port_requires_heap(&flow.from) || port_requires_heap(&flow.to))
        || rules
            .summaries
            .iter()
            .flat_map(|rule| &rule.flows)
            .any(|flow| port_requires_heap(&flow.from) || port_requires_heap(&flow.to))
        || rules
            .function_sources
            .iter()
            .any(|rule| port_requires_heap(&rule.out))
        || rules
            .function_sinks
            .iter()
            .flat_map(|rule| &rule.inputs)
            .any(port_requires_heap)
}

pub fn build(program: &Program, rules: &RuleSet) -> FlowGraph {
    build_with_progress(program, rules, |_| {})
}

pub fn build_with_progress<F>(program: &Program, rules: &RuleSet, mut on_progress: F) -> FlowGraph
where
    F: FnMut(BuildProgress),
{
    // The public build API keeps the historical fully materialized graph
    // semantics. Rule-driven scans use `build_for_rules_with_progress`.
    let capabilities = AnalysisCapabilities::full();
    build_with_capabilities(program, rules, capabilities, &mut on_progress)
}

pub fn build_for_rules_with_progress<F>(
    program: &Program,
    rules: &RuleSet,
    mut on_progress: F,
) -> FlowGraph
where
    F: FnMut(BuildProgress),
{
    let capabilities = AnalysisCapabilities::for_rules(program, rules);
    build_with_capabilities_inner(program, rules, capabilities, false, &mut on_progress)
}

/// Builds the rule-driven graph used by a source scan.
///
/// Unlike the library API above, a scan need not materialize expensive
/// points-to, heap, and dynamic-call state when its source file contains no
/// modeled source/sink pair at all.  Such state cannot produce a taint
/// finding, while eagerly expanding it used to make a no-finding scan consume
/// unbounded time and memory on ordinary Rust crates.  Callers that expose a
/// complete graph to an external checker must use `build_with_capabilities`
/// instead.
pub fn build_for_scan_with_progress<F>(
    program: &Program,
    rules: &RuleSet,
    mut on_progress: F,
) -> FlowGraph
where
    F: FnMut(BuildProgress),
{
    let capabilities = AnalysisCapabilities::for_rules(program, rules);
    build_with_capabilities_inner(program, rules, capabilities, true, &mut on_progress)
}

pub fn build_with_capabilities<F>(
    program: &Program,
    rules: &RuleSet,
    capabilities: AnalysisCapabilities,
    mut on_progress: F,
) -> FlowGraph
where
    F: FnMut(BuildProgress),
{
    build_with_capabilities_inner(program, rules, capabilities, false, &mut on_progress)
}

fn build_with_capabilities_inner<F>(
    program: &Program,
    rules: &RuleSet,
    capabilities: AnalysisCapabilities,
    skip_unmatched_expensive_work: bool,
    mut on_progress: F,
) -> FlowGraph
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
    // A project taint scan does not need to instantiate every SSA value in a
    // repository.  Find the static call-chain slice before creating graph
    // nodes: a graph node carries significantly more state than an IR value,
    // and constructing millions of irrelevant nodes dominated both RSS and
    // wall time on large Python projects.
    let scan_function_slice = if skip_unmatched_expensive_work {
        static_taint_scan_function_slice(program, rules)
    } else {
        None
    };
    if let Some(active) = &scan_function_slice {
        on_progress(BuildProgress {
            stage: "slice-static-taint",
            detail: format!(
                "{} of {} functions on modeled static source/sink paths",
                active.len(),
                program.functions.len()
            ),
        });
    }
    let is_active = |function: &Function| {
        scan_function_slice
            .as_ref()
            .is_none_or(|active| active.contains(&function.id))
    };
    let active_function_count = scan_function_slice
        .as_ref()
        .map_or(program.functions.len(), HashSet::len);

    let mut fg = FlowGraph::default();
    fg.language = program.language.clone();
    // Lambda capture binding is visited for every call argument.  Searching
    // the complete function list there turned a large Python project into
    // calls × arguments × functions work before data-flow even started.
    let lambda_functions = program
        .functions
        .iter()
        .filter(|function| is_active(function))
        .filter(|function| function.name.contains("__lambda_"))
        .map(|function| (function.name.as_str(), function))
        .collect::<HashMap<_, _>>();
    let argument_validation_enabled = rules.native_dataflow_rules.iter().any(|rule| {
        rule.id == ANZU_ARGUMENT_VALIDATION_RULE_ID
            && language_matches(&rule.language, &program.language)
    });
    let array_index_enabled = rules.native_dataflow_rules.iter().any(|rule| {
        rule.id == ANZU_ARRAY_INDEX_RULE_ID && language_matches(&rule.language, &program.language)
    });
    let array_bound_enabled = rules.native_dataflow_rules.iter().any(|rule| {
        rule.id == ANZU_ARRAY_BOUND_RULE_ID && language_matches(&rule.language, &program.language)
    });
    let case_break_enabled = rules.native_dataflow_rules.iter().any(|rule| {
        rule.id == ANZU_CASE_BREAK_RULE_ID && language_matches(&rule.language, &program.language)
    });
    if argument_validation_enabled && matches!(program.language, Language::Cpp) {
        fg.nullness_before_insts = analyze_program_nullness(program);
    }
    if (array_index_enabled || array_bound_enabled)
        && matches!(program.language, Language::C | Language::Cpp)
    {
        fg.native_dataflow_diagnostics
            .extend(analyze_array_safety_diagnostics(
                program,
                array_index_enabled,
                array_bound_enabled,
            ));
    }
    if case_break_enabled && matches!(program.language, Language::C | Language::Cpp) {
        fg.native_dataflow_diagnostics
            .extend(analyze_case_break_diagnostics(program));
    }
    for file in &program.source_files {
        fg.file_paths.insert(file.id, file.path.clone());
    }
    for (ty, parents) in &program.type_hierarchy {
        fg.type_hierarchy.insert(ty.clone(), parents.clone());
    }
    if matches!(
        program.language,
        Language::C | Language::Cpp | Language::ObjC | Language::ObjCpp
    ) {
        let (lifetime_states, lifetime_block_states, lifetime_diagnostics) =
            analyze_program_lifetimes(program);
        fg.lifetime_states = lifetime_states;
        fg.lifetime_block_states = lifetime_block_states;
        fg.lifetime_diagnostics = lifetime_diagnostics;
    }
    for function in &program.functions {
        if !is_active(function) {
            continue;
        }
        for (value, semantics) in &function.value_cpp {
            fg.value_cpp
                .insert((function.id, *value), semantics.clone());
        }
    }

    on_progress(BuildProgress {
        stage: "create-function-nodes",
        detail: format!("{} functions", active_function_count),
    });
    for func in &program.functions {
        if !is_active(func) {
            continue;
        }
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
    let rule_index = RuleMatcherIndex::new(rules);

    on_progress(BuildProgress {
        stage: "scan-function-bodies",
        detail: format!("{} functions", active_function_count),
    });
    for func in &program.functions {
        if !is_active(func) {
            continue;
        }
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
                    InstKind::ConstInt { .. } | InstKind::ConstString { .. }
                    | InstKind::Compare { .. } => {}
                    InstKind::Copy { dst, src }
                    | InstKind::NumericStep { dst, src, .. }
                    | InstKind::NumericNeg { dst, src } => {
                        edge_value_to_value(&mut fg, func.id, *src, *dst, EdgeKind::Assign);
                    }
                    InstKind::Deref { dst, src } => {
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
                        connect_registered_lambda_captures(
                            &mut fg,
                            &lambda_functions,
                            func.id,
                            call,
                        );

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
                        let resolved_callees = func_index.resolve_call(&meta);
                        if argument_validation_enabled {
                            emit_argument_validation_diagnostics(
                                &mut fg,
                                func,
                                inst,
                                call,
                                &resolved_callees,
                            );
                        }
                        let mut resolved_targets = Vec::new();
                        for callee_func in resolved_callees {
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
                        connect_rule_summaries(
                            &mut fg,
                            rules,
                            &rule_index,
                            func.id,
                            inst.id,
                            call,
                            &meta,
                        );
                        attach_rule_sources_and_sinks(
                            &mut fg,
                            rules,
                            &rule_index,
                            func.id,
                            inst.id,
                            call,
                            &meta,
                        );
                        attach_unused_return_sinks(
                            &mut fg,
                            rules,
                            func.id,
                            inst.id,
                            call,
                            &meta,
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

    // A normal scan only needs the expensive heap/region overlays when a
    // modeled source can actually reach a modeled sink.  Determine that after
    // call models have been attached, but before the first sparse rebuild:
    // the rebuild itself materializes large region closure tables.
    let has_taint_query = !fg.synthetic_sources.is_empty() && !fg.synthetic_sinks.is_empty();
    let materialize_expensive_flow = !skip_unmatched_expensive_work || has_taint_query;
    // A source scan asks a reachability question, not for a reusable complete
    // alias/heap graph.  Building the latter for every matching source/sink
    // pair made otherwise ordinary Python repositories allocate global
    // object-shape and region closure state proportional to millions of IR
    // nodes.  Keep static calls and direct heap projection edges, which are
    // wired above, and use the bounded conservative cell graph below.
    let bounded_taint_scan = skip_unmatched_expensive_work && has_taint_query;
    on_progress(BuildProgress {
        stage: "sparse-adjacency-1",
        detail: format!("{} graph nodes", fg.graph.node_count()),
    });
    if bounded_taint_scan {
        materialize_sparse_taint_adjacency(&mut fg);
    } else if materialize_expensive_flow {
        materialize_sparse_data_adjacency(&mut fg);
    } else {
        materialize_sparse_data_adjacency_lightweight(&mut fg);
    }
    on_progress(BuildProgress {
        stage: "sparse-summary",
        detail: format!(
            "{} nodes, {} edges, {} sparse edges",
            fg.graph.node_count(),
            fg.graph.edge_count(),
            fg.sparse_successors.values().map(|v| v.len()).sum::<usize>()
        ),
    });
    if !materialize_expensive_flow
        && (capabilities.points_to || capabilities.heap || capabilities.dynamic_calls)
    {
        on_progress(BuildProgress {
            stage: "skip-unmatched-expensive-flow",
            detail: "no modeled source/sink pair in scan".to_string(),
        });
    }
    if bounded_taint_scan
        && (capabilities.points_to || capabilities.heap || capabilities.dynamic_calls)
    {
        on_progress(BuildProgress {
            stage: "bounded-taint-flow",
            detail: "skipping global alias/heap/dynamic overlays for project scan".to_string(),
        });
    }
    if capabilities.points_to && materialize_expensive_flow && !bounded_taint_scan {
        on_progress(BuildProgress {
            stage: "points-to",
            detail: format!("{} graph nodes", fg.graph.node_count()),
        });
        materialize_points_to_fixpoint(&mut fg);
        materialize_points_to_targets_fixpoint(&mut fg);
        materialize_points_to_object_ids(&mut fg);
        materialize_points_to_partitions(&mut fg);
        on_progress(BuildProgress {
            stage: "points-to-summary",
            detail: format!(
                "{} targets, {} objects",
                fg.node_points_to_targets.len(),
                fg.abstract_objects.len()
            ),
        });
    }
    if capabilities.heap && materialize_expensive_flow && !bounded_taint_scan {
        on_progress(BuildProgress {
            stage: "bridge-internal-heap-cells",
            detail: format!("{} functions", program.functions.len()),
        });
        // Return projections must exist before resolving a callback returned from
        // an internal function. Bridges only consult direct IR-derived cells.
        bridge_internal_heap_cells(&mut fg, program);
        materialize_sparse_data_adjacency(&mut fg);
    }
    if capabilities.dynamic_calls && materialize_expensive_flow && !bounded_taint_scan {
        on_progress(BuildProgress {
            stage: "resolve-dynamic-calls",
            detail: format!("{} functions", program.functions.len()),
        });
        resolve_dynamic_internal_calls(&mut fg, program, &func_index, rules, &rule_index);
        materialize_sparse_data_adjacency(&mut fg);
    }
    if capabilities.global_closure && !bounded_taint_scan {
        on_progress(BuildProgress {
            stage: "global-closure-1",
            detail: format!("{} functions", program.functions.len()),
        });
        materialize_global_solver_closure(&mut fg, program);
    }
    // All existing structural bridges participate in the global closure.
    on_progress(BuildProgress {
        stage: "sparse-adjacency-3",
        detail: format!("{} graph nodes, {} edges", fg.graph.node_count(), fg.graph.edge_count()),
    });
    if bounded_taint_scan {
        materialize_sparse_taint_adjacency(&mut fg);
    } else if materialize_expensive_flow {
        materialize_sparse_data_adjacency(&mut fg);
    } else {
        materialize_sparse_data_adjacency_lightweight(&mut fg);
    }
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
    lambda_functions: &HashMap<&str, &Function>,
    caller_func: FunctionId,
    call: &CallInst,
) {
    for argument in &call.args {
        let Some(function_name) = fg.value_types.get(&(caller_func, *argument)) else {
            continue;
        };
        let Some(callback) = lambda_functions.get(function_name.as_str()).copied() else {
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

/// Return the portion of a program which can lie on a *static* modeled
/// source-to-sink path. `None` means that a rule family needs a whole-program
/// graph (for example a named-value or field rule); an empty set is a proven
/// no-finding scan because no modeled call source or sink exists at all.
///
/// The slice is deliberately an over-approximation. Every function reachable
/// from a modeled source and able to reach a modeled sink is retained, so a
/// static interprocedural path is never removed merely for performance. Dynamic
/// call resolution remains a separate optional full-graph capability.
fn static_taint_scan_function_slice(
    program: &Program,
    rules: &RuleSet,
) -> Option<HashSet<FunctionId>> {
    // These rule forms can attach a source/sink without a call expression.
    // Do not guess a slice for them: preserving their full semantics matters
    // more than a memory saving on the uncommon configuration.
    if rules.named_value_sources.iter().any(|rule| language_matches(&rule.language, &program.language))
        || rules.field_sources.iter().any(|rule| language_matches(&rule.language, &program.language))
        || rules.field_sinks.iter().any(|rule| language_matches(&rule.language, &program.language))
        || rules.index_sinks.iter().any(|rule| language_matches(&rule.language, &program.language))
        || rules.function_sources.iter().any(|rule| language_matches(&rule.language, &program.language))
        || rules.function_sinks.iter().any(|rule| language_matches(&rule.language, &program.language))
    {
        return None;
    }

    let source_rules = rules
        .sources
        .iter()
        .filter(|rule| language_matches(&rule.language, &program.language))
        .collect::<Vec<_>>();
    let sink_rules = rules
        .sinks
        .iter()
        .filter(|rule| language_matches(&rule.language, &program.language))
        .collect::<Vec<_>>();
    if source_rules.is_empty() || sink_rules.is_empty() {
        return Some(HashSet::new());
    }

    let index = FunctionIndex::new(program);
    let mut source_functions = HashSet::new();
    let mut sink_functions = HashSet::new();
    let mut callers = HashMap::<FunctionId, Vec<FunctionId>>::new();
    let mut callees = HashMap::<FunctionId, Vec<FunctionId>>::new();

    for function in &program.functions {
        for block in &function.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else {
                    continue;
                };
                let Some(callee_name) = static_callee_name(call) else {
                    continue;
                };
                let mut info = CallInfo::from_callee_name(&callee_name);
                info.containing_function = Some(function.name.clone());
                info.arg_count = Some(call.args.len());
                info.arg_types = call
                    .args
                    .iter()
                    .map(|value| function.value_types.get(value).cloned())
                    .collect();
                if let Some(receiver) = call.receiver {
                    info.receiver_type = function.value_types.get(&receiver).cloned();
                    info.receiver_type_candidates = info
                        .receiver_type
                        .iter()
                        .cloned()
                        .collect();
                    info.receiver_parameter = function.params.iter().position(|value| *value == receiver);
                }

                if source_rules
                    .iter()
                    .any(|rule| rule.matcher.matches_call(&info))
                {
                    source_functions.insert(function.id);
                }
                if sink_rules
                    .iter()
                    .any(|rule| rule.matcher.matches_call(&info))
                {
                    sink_functions.insert(function.id);
                }

                // The same arity/type contract as the normal static resolver
                // gives the slice its conservative interprocedural boundary.
                let targets = index.resolve_named_callable(
                    &callee_name,
                    call.args.len(),
                    &info.arg_types,
                    &info.arg_type_candidates,
                );
                for target in targets {
                    callees.entry(function.id).or_default().push(target.id);
                    callers.entry(target.id).or_default().push(function.id);
                }
            }
        }
    }
    for neighbors in callers.values_mut().chain(callees.values_mut()) {
        neighbors.sort_unstable();
        neighbors.dedup();
    }
    if source_functions.is_empty() || sink_functions.is_empty() {
        return Some(HashSet::new());
    }

    // Taint can cross a call boundary in either direction: an argument enters
    // a callee, while a tainted return reaches its callers.  Compute the
    // static interprocedural component rather than treating the syntactic call
    // graph as a one-way data-flow graph.
    let mut connected = callees;
    for (function, parents) in callers {
        connected.entry(function).or_default().extend(parents);
    }
    for neighbors in connected.values_mut() {
        neighbors.sort_unstable();
        neighbors.dedup();
    }
    let reachable = traverse_function_slice(&source_functions, &connected);
    let can_reach_sink = traverse_function_slice(&sink_functions, &connected);
    Some(
        reachable
            .intersection(&can_reach_sink)
            .copied()
            .collect(),
    )
}

fn traverse_function_slice(
    roots: &HashSet<FunctionId>,
    neighbors: &HashMap<FunctionId, Vec<FunctionId>>,
) -> HashSet<FunctionId> {
    let mut visited = roots.clone();
    let mut queue = roots.iter().copied().collect::<VecDeque<_>>();
    while let Some(function) = queue.pop_front() {
        for next in neighbors.get(&function).into_iter().flatten() {
            if visited.insert(*next) {
                queue.push_back(*next);
            }
        }
    }
    visited
}

#[derive(Default)]
struct FunctionIndex<'a> {
    exact: HashMap<&'a str, Vec<&'a Function>>,
    exact_arity: HashMap<(String, usize), Vec<&'a Function>>,
    simple: HashMap<String, Vec<&'a Function>>,
    simple_arity: HashMap<(String, usize), Vec<&'a Function>>,
    owner_method: HashMap<(String, String), Vec<&'a Function>>,
    owner_method_arity: HashMap<(String, String, usize), Vec<&'a Function>>,
    closure_span_arity: HashMap<(u32, u32, u32, usize), Vec<&'a Function>>,
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
                index
                    .closure_span_arity
                    .entry((
                        func.span.file,
                        func.span.start_byte,
                        func.span.end_byte,
                        *arity,
                    ))
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

    fn closure_functions_at_spans(
        &self,
        spans: &[(u32, u32, u32)],
        arg_count: usize,
    ) -> Vec<&'a Function> {
        let mut out = Vec::new();
        for &(file, start, end) in spans {
            if let Some(functions) = self.closure_span_arity.get(&(file, start, end, arg_count)) {
                out.extend(functions.iter().copied());
            }
        }
        out.sort_by(|left, right| left.name.cmp(&right.name));
        out.dedup_by(|left, right| left.name == right.name);
        out
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
