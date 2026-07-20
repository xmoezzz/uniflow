fn is_sparse_data_edge(kind: &EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Assign
            | EdgeKind::Phi
            | EdgeKind::LoadField { .. }
            | EdgeKind::StoreField { .. }
            | EdgeKind::LoadIndex
            | EdgeKind::StoreIndex
            | EdgeKind::ValueToCallPort
            | EdgeKind::CallPortToValue
            | EdgeKind::ActualToFormal
            | EdgeKind::FormalToActual
            | EdgeKind::Summary { .. }
            | EdgeKind::Source { .. }
            | EdgeKind::Sink { .. }
    )
}

fn push_unique_index(map: &mut HashMap<usize, Vec<usize>>, src: usize, dst: usize) {
    let values = map.entry(src).or_default();
    if !values.contains(&dst) {
        values.push(dst);
    }
}

fn push_unique_labeled_index(
    map: &mut HashMap<usize, Vec<usize>>,
    labels: &mut HashMap<(usize, usize), String>,
    src: usize,
    dst: usize,
    label: String,
) {
    push_unique_index(map, src, dst);
    labels.entry((src, dst)).or_insert(label);
}

fn materialize_heap_value_adjacency(fg: &mut FlowGraph) {
    fg.heap_value_successors.clear();
    fg.heap_value_predecessors.clear();
    for (&(func, base, _), &cell) in &fg.field_cells {
        let Some(&base_node) = fg.values.get(&(func, base)) else {
            continue;
        };
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_index(&mut fg.heap_value_successors, base_node.index(), proj_node.index());
            push_unique_index(&mut fg.heap_value_predecessors, proj_node.index(), base_node.index());
        }
    }
    for (&(func, base, _), &cell) in &fg.index_cells {
        let Some(&base_node) = fg.values.get(&(func, base)) else {
            continue;
        };
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_index(&mut fg.heap_value_successors, base_node.index(), proj_node.index());
            push_unique_index(&mut fg.heap_value_predecessors, proj_node.index(), base_node.index());
        }
    }
    for values in fg.heap_value_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.heap_value_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
}

fn materialize_heap_object_adjacency(fg: &mut FlowGraph) {
    fg.heap_object_successors.clear();
    fg.heap_object_predecessors.clear();
    let mut all_cells = fg
        .field_cells
        .iter()
        .map(|(&(func, base, _), &cell)| (func, base, cell))
        .collect::<Vec<_>>();
    all_cells.extend(
        fg.index_cells
            .iter()
            .map(|(&(func, base, _), &cell)| (func, base, cell)),
    );
    for (func, base, cell) in all_cells {
        let Some(&base_node) = fg.values.get(&(func, base)) else {
            continue;
        };
        push_unique_index(&mut fg.heap_object_successors, base_node.index(), cell.index());
        push_unique_index(&mut fg.heap_object_predecessors, cell.index(), base_node.index());
        let projected = cell_values_for_flow(fg, cell);
        for (proj_func, proj_value) in projected {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_index(&mut fg.heap_object_successors, cell.index(), proj_node.index());
            push_unique_index(&mut fg.heap_object_predecessors, proj_node.index(), cell.index());
        }
    }
    for values in fg.heap_object_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.heap_object_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
}

fn materialize_object_graph_adjacency(fg: &mut FlowGraph) {
    fg.object_graph_successors.clear();
    fg.object_graph_predecessors.clear();
    fg.object_graph_labels.clear();
    fg.object_shape_labels.clear();

    for ((func, base, field), &cell) in &fg.field_cells {
        let Some(&base_node) = fg.values.get(&(*func, *base)) else {
            continue;
        };
        let label = format!("field:{}", field);
        fg.object_shape_labels.entry(base_node.index()).or_default().push(label.clone());
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_labeled_index(
                &mut fg.object_graph_successors,
                &mut fg.object_graph_labels,
                base_node.index(),
                proj_node.index(),
                label.clone(),
            );
            push_unique_labeled_index(
                &mut fg.object_graph_predecessors,
                &mut fg.object_graph_labels,
                proj_node.index(),
                base_node.index(),
                label.clone(),
            );
        }
    }

    for ((func, base, key), &cell) in &fg.index_cells {
        let Some(&base_node) = fg.values.get(&(*func, *base)) else {
            continue;
        };
        let label = format!("index:{}", key);
        fg.object_shape_labels.entry(base_node.index()).or_default().push(label.clone());
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_labeled_index(
                &mut fg.object_graph_successors,
                &mut fg.object_graph_labels,
                base_node.index(),
                proj_node.index(),
                label.clone(),
            );
            push_unique_labeled_index(
                &mut fg.object_graph_predecessors,
                &mut fg.object_graph_labels,
                proj_node.index(),
                base_node.index(),
                label.clone(),
            );
        }
    }

    for values in fg.object_graph_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.object_graph_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.object_shape_labels.values_mut() {
        values.sort();
        values.dedup();
    }
}

fn collect_object_shape_paths(
    fg: &FlowGraph,
    node: NodeIndex,
    prefix: String,
    depth: usize,
    seen_edges: &mut HashSet<(usize, usize)>,
    out: &mut BTreeSet<String>,
) {
    if depth == 0 {
        return;
    }
    for succ in fg.object_graph_successors_of(node) {
        let Some(label) = fg.object_graph_edge_label(node, succ) else {
            continue;
        };
        if !seen_edges.insert((node.index(), succ.index())) {
            continue;
        }
        let next = if prefix.is_empty() {
            label.to_string()
        } else {
            format!("{}.{}", prefix, label)
        };
        out.insert(next.clone());
        collect_object_shape_paths(fg, succ, next, depth.saturating_sub(1), seen_edges, out);
        seen_edges.remove(&(node.index(), succ.index()));
    }
}

fn materialize_object_shape_paths(fg: &mut FlowGraph) {
    fg.object_shape_paths.clear();
    let value_nodes = fg.values.values().copied().collect::<Vec<_>>();
    for node in value_nodes {
        let mut out = BTreeSet::new();
        let mut seen_edges = HashSet::new();
        collect_object_shape_paths(fg, node, String::new(), 4, &mut seen_edges, &mut out);
        if !out.is_empty() {
            fg.object_shape_paths.insert(node.index(), out.into_iter().collect());
        }
    }
}

fn shape_propagation_neighbors(fg: &FlowGraph, node: NodeIndex) -> Vec<NodeIndex> {
    let mut out = fg.object_graph_successors_of(node);
    out.extend(fg.object_graph_predecessors_of(node));
    out.extend(fg.heap_object_successors_of(node));
    out.extend(fg.heap_object_predecessors_of(node));
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Forward));
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Backward));
    out.sort_unstable_by_key(|n| n.index());
    out.dedup_by_key(|n| n.index());
    out
}

fn materialize_object_shape_fixpoint(fg: &mut FlowGraph) {
    let mut propagated = HashMap::<usize, BTreeSet<String>>::new();
    for (&node_idx, labels) in &fg.object_shape_paths {
        propagated
            .entry(node_idx)
            .or_default()
            .extend(labels.iter().cloned());
    }
    let mut changed = true;
    while changed {
        changed = false;
        let nodes = fg.graph.node_indices().collect::<Vec<_>>();
        for node in nodes {
            let mut merged = propagated.get(&node.index()).cloned().unwrap_or_default();
            for neighbor in shape_propagation_neighbors(fg, node) {
                if let Some(values) = propagated.get(&neighbor.index()) {
                    let before = merged.len();
                    merged.extend(values.iter().cloned());
                    if merged.len() > before {
                        changed = true;
                    }
                }
            }
            if !merged.is_empty() {
                let replace = propagated
                    .get(&node.index())
                    .map(|prev| prev != &merged)
                    .unwrap_or(true);
                if replace {
                    propagated.insert(node.index(), merged);
                    changed = true;
                }
            }
        }
    }
    fg.object_shape_paths = propagated
        .into_iter()
        .map(|(node_idx, values)| (node_idx, values.into_iter().collect()))
        .collect();
}

fn initial_memory_regions_for_node(fg: &FlowGraph, node: NodeIndex) -> BTreeSet<String> {
    let mut regions = BTreeSet::new();
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            for region in memory_region_seed_for_value(fg, *func, *value) {
                regions.insert(region);
            }
        }
        FlowNode::FieldCell { func, base, field, .. } => {
            let mut bases = fg.value_memory_regions_of(*func, *base);
            if bases.is_empty() {
                bases = memory_region_seed_for_value(fg, *func, *base);
            }
            for base_region in bases {
                regions.insert(format!("{}.{}", base_region, field));
            }
        }
        FlowNode::IndexCell { func, base, abstract_key, .. } => {
            let mut bases = fg.value_memory_regions_of(*func, *base);
            if bases.is_empty() {
                bases = memory_region_seed_for_value(fg, *func, *base);
            }
            for base_region in bases {
                regions.insert(format!("{}[{}]", base_region, abstract_key));
            }
        }
        FlowNode::CallPort { port, .. } => {
            regions.insert(format!("mem:port:{:?}", port));
        }
        _ => {}
    }
    for shape in fg.object_shape_paths_of(node) {
        if !shape.trim().is_empty() {
            regions.insert(normalized_memory_region(&shape));
        }
    }
    regions
}

fn memory_region_propagation_neighbors(fg: &FlowGraph, node: NodeIndex) -> Vec<NodeIndex> {
    let mut out = points_to_propagation_neighbors(fg, node);
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Forward));
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Backward));
    out.sort_unstable_by_key(|n| n.index());
    out.dedup_by_key(|n| n.index());
    out
}

fn materialize_memory_regions(fg: &mut FlowGraph) {
    fg.node_memory_regions.clear();
    fg.value_memory_regions.clear();
    fg.cell_memory_regions.clear();
    let mut regions = HashMap::<usize, BTreeSet<String>>::new();
    for node in fg.graph.node_indices() {
        let seeded = initial_memory_regions_for_node(fg, node);
        if !seeded.is_empty() {
            regions.insert(node.index(), seeded);
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        let nodes = fg.graph.node_indices().collect::<Vec<_>>();
        for node in nodes {
            let mut merged = regions.get(&node.index()).cloned().unwrap_or_default();
            for neighbor in memory_region_propagation_neighbors(fg, node) {
                if let Some(values) = regions.get(&neighbor.index()) {
                    let before = merged.len();
                    merged.extend(values.iter().cloned());
                    if merged.len() > before {
                        changed = true;
                    }
                }
            }
            if !merged.is_empty() {
                let replace = regions.get(&node.index()).map(|prev| prev != &merged).unwrap_or(true);
                if replace {
                    regions.insert(node.index(), merged);
                    changed = true;
                }
            }
        }
    }
    for (node_idx, values) in &regions {
        fg.node_memory_regions.insert(*node_idx, values.iter().cloned().collect());
    }
    for (&(func, value), &node) in &fg.values {
        if let Some(node_regions) = fg.node_memory_regions.get(&node.index()).cloned() {
            let mut merged = fg.value_memory_regions.remove(&(func, value)).unwrap_or_default();
            merged.extend(node_regions);
            merged.sort();
            merged.dedup();
            fg.value_memory_regions.insert((func, value), merged);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(node_regions) = fg.node_memory_regions.get(&cell.index()).cloned() {
            let mut merged = fg.cell_memory_regions.remove(&cell.index()).unwrap_or_default();
            merged.extend(node_regions);
            merged.sort();
            merged.dedup();
            fg.cell_memory_regions.insert(cell.index(), merged);
        }
    }
}

fn add_region_graph_edge(fg: &mut FlowGraph, src: usize, dst: usize) {
    if src == dst {
        return;
    }
    let succs = fg.region_graph_successors.entry(src).or_default();
    if !succs.iter().any(|existing| *existing == dst) {
        succs.push(dst);
    }
    let preds = fg.region_graph_predecessors.entry(dst).or_default();
    if !preds.iter().any(|existing| *existing == src) {
        preds.push(src);
    }
}

fn materialize_region_graph_adjacency(fg: &mut FlowGraph) {
    fg.region_graph_successors.clear();
    fg.region_graph_predecessors.clear();

    let mut region_to_nodes = BTreeMap::<String, BTreeSet<usize>>::new();
    for node in fg.graph.node_indices() {
        for region in fg.node_memory_regions_of(node) {
            region_to_nodes.entry(region).or_default().insert(node.index());
        }
    }

    let regions = region_to_nodes.keys().cloned().collect::<Vec<_>>();
    for (left_idx, left_region) in regions.iter().enumerate() {
        for right_region in regions.iter().skip(left_idx) {
            if !memory_region_related(left_region, right_region) {
                continue;
            }
            let Some(left_nodes) = region_to_nodes.get(left_region) else {
                continue;
            };
            let Some(right_nodes) = region_to_nodes.get(right_region) else {
                continue;
            };
            for left_node in left_nodes {
                for right_node in right_nodes {
                    if left_node == right_node {
                        continue;
                    }
                    add_region_graph_edge(fg, *left_node, *right_node);
                    add_region_graph_edge(fg, *right_node, *left_node);
                }
            }
        }
    }

    for values in fg.region_graph_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.region_graph_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
}

fn materialize_cell_live_state(fg: &mut FlowGraph) {
    fg.cell_live_values.clear();
    fg.cell_live_regions.clear();
    for cell in all_cell_nodes(fg) {
        let live = visible_direct_cell_store_records_before_edge(fg, cell, None);
        if !live.is_empty() {
            let mut values = live
                .iter()
                .map(|(_edge_idx, func, value)| (func.0, value.0))
                .collect::<Vec<_>>();
            values.sort_unstable();
            values.dedup();
            fg.cell_live_values.insert(cell.index(), values);
        }
        let mut regions = BTreeSet::new();
        for (_edge_idx, func, value) in &live {
            for region in fg.value_memory_regions_of(*func, *value) {
                regions.insert(region);
            }
        }
        if regions.is_empty() {
            for region in fg.cell_memory_regions_of(cell) {
                regions.insert(region);
            }
        }
        if !regions.is_empty() {
            fg.cell_live_regions.insert(cell.index(), regions.into_iter().collect());
        }
    }
}

fn materialize_region_live_state(fg: &mut FlowGraph) {
    fg.region_live_values.clear();
    fg.region_live_cells.clear();

    let mut live_values = BTreeMap::<String, BTreeSet<(u32, u32)>>::new();
    let mut live_cells = BTreeMap::<String, BTreeSet<usize>>::new();
    for cell in all_cell_nodes(fg) {
        let mut cell_regions = fg.cell_live_regions_of(cell);
        if cell_regions.is_empty() {
            cell_regions = fg.cell_memory_regions_of(cell);
        }
        let mut cell_values = fg.cell_live_values_of(cell);
        if cell_values.is_empty() {
            cell_values = direct_cell_store_values(fg, cell);
        }
        for region in cell_regions {
            for ancestor in memory_region_ancestor_chain(&region) {
                live_cells.entry(ancestor.clone()).or_default().insert(cell.index());
                for (func, value) in &cell_values {
                    live_values.entry(ancestor.clone()).or_default().insert((func.0, value.0));
                }
            }
        }
    }

    fg.region_live_values = live_values
        .into_iter()
        .map(|(region, values)| (region, values.into_iter().collect()))
        .collect();
    fg.region_live_cells = live_cells
        .into_iter()
        .map(|(region, cells)| (region, cells.into_iter().collect()))
        .collect();
}

fn materialize_cell_write_generations(fg: &mut FlowGraph) {
    fg.cell_write_generations.clear();
    let mut all_cells = fg.field_cells.values().copied().collect::<Vec<_>>();
    all_cells.extend(fg.index_cells.values().copied());
    all_cells.sort_unstable_by_key(|node| node.index());
    all_cells.dedup_by_key(|node| node.index());
    for cell in all_cells {
        let mut records = alias_equivalent_cells(fg, cell)
            .into_iter()
            .flat_map(|candidate| transitive_cell_store_records(fg, candidate))
            .filter(|record| {
                fg.graph
                    .edge_weight(petgraph::graph::EdgeIndex::new(record.edge_idx))
                    .is_some_and(|edge| matches!(&edge.kind, EdgeKind::StoreField { .. } | EdgeKind::StoreIndex))
            })
            .collect::<Vec<_>>();
        records.sort_unstable_by_key(|record| record.edge_idx);
        records.dedup_by_key(|record| record.edge_idx);
        if records.is_empty() {
            continue;
        }
        let generations = records
            .into_iter()
            .enumerate()
            .map(|(generation, record)| {
                let value = canonical_heap_value(fg, record.func, record.value);
                (generation as u64, record.func.0, value.0)
            })
            .collect::<Vec<_>>();
        fg.cell_write_generations.insert(cell.index(), generations);
    }
}

fn materialize_points_to_partitions(fg: &mut FlowGraph) {
    fg.value_points_to_classes.clear();
    fg.cell_points_to_classes.clear();
    fg.strong_update_cells.clear();
    let values = fg.values.keys().copied().collect::<Vec<_>>();
    for (func, value) in values {
        let classes = inferred_points_to_classes_for_value(fg, func, value);
        if !classes.is_empty() {
            fg.value_points_to_classes.insert((func, value), classes);
        }
    }
    let mut all_cells = fg.field_cells.values().copied().collect::<Vec<_>>();
    all_cells.extend(fg.index_cells.values().copied());
    all_cells.sort_unstable_by_key(|node| node.index());
    all_cells.dedup_by_key(|node| node.index());
    for cell in all_cells {
        if cell_allows_strong_update(fg, cell) {
            fg.strong_update_cells.insert(cell.index());
        }
        let mut classes = BTreeSet::new();
        match &fg.graph[cell] {
            FlowNode::FieldCell { func, base, field, .. } => {
                if let Some(site) = value_identity_site(fg, *func, *base) {
                    classes.insert(format!("cell-site:{}:{}", site.trim(), field));
                }
                if let Some(ty) = fg.value_types.get(&(*func, *base)) {
                    classes.insert(format!("cell-field:{}:{}", normalized_type_point_class(ty), field));
                }
            }
            FlowNode::IndexCell { func, base, abstract_key, .. } => {
                if let Some(site) = value_identity_site(fg, *func, *base) {
                    classes.insert(format!("cell-site:{}:[{}]", site.trim(), abstract_key));
                }
                if let Some(ty) = fg.value_types.get(&(*func, *base)) {
                    classes.insert(format!("cell-index:{}:[{}]", normalized_type_point_class(ty), abstract_key));
                }
            }
            _ => {}
        }
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            for class in inferred_points_to_classes_for_value(fg, proj_func, proj_value) {
                classes.insert(class);
            }
        }
        for class in inferred_shape_point_classes_for_node(fg, cell) {
            classes.insert(class);
        }
        if !classes.is_empty() {
            fg.cell_points_to_classes.insert(cell.index(), classes.into_iter().collect());
        }
    }
}

fn initial_node_points_to_classes(fg: &FlowGraph, node: NodeIndex) -> BTreeSet<String> {
    let mut classes = BTreeSet::new();
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            for class in inferred_points_to_classes_for_value(fg, *func, *value) {
                classes.insert(class);
            }
        }
        FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
            for class in fg.cell_points_to_classes_of(node) {
                classes.insert(class);
            }
        }
        _ => {}
    }
    classes
}

fn points_to_propagation_neighbors(fg: &FlowGraph, node: NodeIndex) -> Vec<NodeIndex> {
    let mut out = fg.sparse_neighbors_of(node, SparseDirection::Forward);
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Backward));
    out.extend(fg.heap_object_successors_of(node));
    out.extend(fg.heap_object_predecessors_of(node));
    out.extend(fg.object_graph_successors_of(node));
    out.extend(fg.object_graph_predecessors_of(node));
    out.extend(fg.region_graph_successors_of(node));
    out.extend(fg.region_graph_predecessors_of(node));
    out.sort_unstable_by_key(|n| n.index());
    out.dedup_by_key(|n| n.index());
    out
}

fn materialize_points_to_fixpoint(fg: &mut FlowGraph) {
    fg.node_points_to_classes.clear();
    let mut classes = HashMap::<usize, BTreeSet<String>>::new();
    for node in fg.graph.node_indices() {
        let seeded = initial_node_points_to_classes(fg, node);
        if !seeded.is_empty() {
            classes.insert(node.index(), seeded);
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        let nodes = fg.graph.node_indices().collect::<Vec<_>>();
        for node in nodes {
            let mut merged = classes.get(&node.index()).cloned().unwrap_or_default();
            for neighbor in points_to_propagation_neighbors(fg, node) {
                if let Some(values) = classes.get(&neighbor.index()) {
                    let before = merged.len();
                    merged.extend(values.iter().cloned());
                    if merged.len() != before {
                        changed = true;
                    }
                }
            }
            if !merged.is_empty() {
                let replace = classes
                    .get(&node.index())
                    .map(|prev| prev != &merged)
                    .unwrap_or(true);
                if replace {
                    classes.insert(node.index(), merged);
                    changed = true;
                }
            }
        }
    }
    for (node_idx, values) in &classes {
        fg.node_points_to_classes
            .insert(*node_idx, values.iter().cloned().collect());
    }
    for (&(func, value), &node) in &fg.values {
        if let Some(node_classes) = fg.node_points_to_classes.get(&node.index()).cloned() {
            let mut merged = fg.value_points_to_classes.remove(&(func, value)).unwrap_or_default();
            merged.extend(node_classes);
            merged.sort();
            merged.dedup();
            fg.value_points_to_classes.insert((func, value), merged);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(node_classes) = fg.node_points_to_classes.get(&cell.index()).cloned() {
            let mut merged = fg.cell_points_to_classes.remove(&cell.index()).unwrap_or_default();
            merged.extend(node_classes);
            merged.sort();
            merged.dedup();
            fg.cell_points_to_classes.insert(cell.index(), merged);
        }
    }
}

fn initial_node_points_to_targets(fg: &FlowGraph, node: NodeIndex) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            if let Some(site) = value_identity_site(fg, *func, *value) {
                targets.insert(format!("obj:site:{}", site.trim()));
            }
            for region in value_root_memory_regions(fg, *func, *value) {
                targets.insert(format!("obj:root:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.insert(format!("obj:value:{}:{}", func.0, value.0));
            }
        }
        FlowNode::Return { func } => {
            for region in fg.node_memory_regions_of(node) {
                targets.insert(format!("obj:return:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.insert(format!("obj:return-func:{}", func.0));
            }
        }
        FlowNode::CallPort { port, .. } => {
            for (src_func, src_value) in fg.call_port_source_values(node) {
                for target in fg.value_points_to_targets_of(src_func, src_value) {
                    targets.insert(target);
                }
                if let Some(site) = value_identity_site(fg, src_func, src_value) {
                    targets.insert(format!("obj:site:{}", site.trim()));
                }
            }
            for region in fg.node_memory_regions_of(node) {
                targets.insert(format!("obj:port:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.insert(format!("obj:port:{:?}", port));
            }
        }
        FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
            if let Some(key) = cell_abstract_identity_key(fg, node) {
                targets.insert(format!("cell:{}", key));
            }
            for region in fg.cell_memory_regions_of(node) {
                targets.insert(format!("cell:region:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.insert(format!("cell:node:{}", node.index()));
            }
        }
        FlowNode::SyntheticSource { rule_id, .. } => {
            targets.insert(format!("obj:synthetic-source:{}", rule_id));
        }
        FlowNode::SyntheticSink { rule_id, .. } => {
            targets.insert(format!("obj:synthetic-sink:{}", rule_id));
        }
    }
    targets
}

fn compute_points_to_targets_fixpoint_for_allowed_nodes(
    fg: &FlowGraph,
    allowed_nodes: Option<&HashSet<usize>>,
) -> HashMap<usize, Vec<String>> {
    let nodes = fg
        .graph
        .node_indices()
        .filter(|node| allowed_nodes.map(|allowed| allowed.contains(&node.index())).unwrap_or(true))
        .collect::<Vec<_>>();
    let allowed_lookup = nodes.iter().map(|node| node.index()).collect::<HashSet<_>>();
    let mut targets = HashMap::<usize, BTreeSet<String>>::new();
    let mut reverse = HashMap::<usize, BTreeSet<usize>>::new();
    for node in &nodes {
        let seeded = initial_node_points_to_targets(fg, *node);
        if !seeded.is_empty() {
            targets.insert(node.index(), seeded);
        }
    }
    for node in &nodes {
        for neighbor in points_to_propagation_neighbors(fg, *node) {
            if !allowed_lookup.contains(&neighbor.index()) {
                continue;
            }
            reverse.entry(neighbor.index()).or_default().insert(node.index());
        }
    }
    let mut queue = nodes.iter().map(|node| node.index()).collect::<VecDeque<_>>();
    let mut queued = queue.iter().copied().collect::<HashSet<_>>();
    while let Some(node_idx) = queue.pop_front() {
        queued.remove(&node_idx);
        let node = NodeIndex::new(node_idx);
        let mut merged = targets.get(&node_idx).cloned().unwrap_or_default();
        let before = merged.len();
        for neighbor in points_to_propagation_neighbors(fg, node) {
            if !allowed_lookup.contains(&neighbor.index()) {
                continue;
            }
            if let Some(values) = targets.get(&neighbor.index()) {
                merged.extend(values.iter().cloned());
            }
        }
        if merged.len() != before || !targets.contains_key(&node_idx) {
            targets.insert(node_idx, merged);
            if let Some(preds) = reverse.get(&node_idx) {
                for pred in preds {
                    if queued.insert(*pred) {
                        queue.push_back(*pred);
                    }
                }
            }
        }
    }
    targets
        .into_iter()
        .map(|(node_idx, values)| (node_idx, values.into_iter().collect::<Vec<_>>()))
        .collect()
}

fn materialize_points_to_targets_fixpoint(fg: &mut FlowGraph) {
    fg.node_points_to_targets = compute_points_to_targets_fixpoint_for_allowed_nodes(fg, None);
    fg.value_points_to_targets.clear();
    fg.cell_points_to_targets.clear();
    for (&(func, value), &node) in &fg.values {
        if let Some(node_targets) = fg.node_points_to_targets.get(&node.index()).cloned() {
            let mut merged = fg.value_points_to_targets.remove(&(func, value)).unwrap_or_default();
            merged.extend(node_targets);
            merged.sort();
            merged.dedup();
            fg.value_points_to_targets.insert((func, value), merged);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(node_targets) = fg.node_points_to_targets.get(&cell.index()).cloned() {
            let mut merged = fg.cell_points_to_targets.remove(&cell.index()).unwrap_or_default();
            merged.extend(node_targets);
            merged.sort();
            merged.dedup();
            fg.cell_points_to_targets.insert(cell.index(), merged);
        }
    }
}

fn compute_points_to_object_ids_fixpoint_for_allowed_nodes(
    fg: &mut FlowGraph,
    allowed_nodes: Option<&HashSet<usize>>,
) -> HashMap<usize, Vec<u32>> {
    let nodes = fg
        .graph
        .node_indices()
        .filter(|node| allowed_nodes.map(|allowed| allowed.contains(&node.index())).unwrap_or(true))
        .collect::<Vec<_>>();
    let allowed_lookup = nodes.iter().map(|node| node.index()).collect::<HashSet<_>>();
    let mut object_ids = HashMap::<usize, BTreeSet<u32>>::new();
    let mut reverse = HashMap::<usize, BTreeSet<usize>>::new();
    for node in &nodes {
        if let Some(ids) = fg.abstract_object_seed_nodes.get(&node.index()) {
            let seeded = ids.iter().copied().collect::<BTreeSet<_>>();
            if !seeded.is_empty() {
                object_ids.insert(node.index(), seeded);
            }
        }
    }
    for node in &nodes {
        let mut neighbors = points_to_propagation_neighbors(fg, *node);
        neighbors.extend(fg.object_successors_of(*node));
        neighbors.extend(fg.object_predecessors_of(*node));
        neighbors.sort_unstable_by_key(|idx| idx.index());
        neighbors.dedup_by_key(|idx| idx.index());
        for neighbor in neighbors {
            if !allowed_lookup.contains(&neighbor.index()) {
                continue;
            }
            reverse.entry(neighbor.index()).or_default().insert(node.index());
        }
    }
    let mut queue = nodes.iter().map(|node| node.index()).collect::<VecDeque<_>>();
    let mut queued = queue.iter().copied().collect::<HashSet<_>>();
    while let Some(node_idx) = queue.pop_front() {
        queued.remove(&node_idx);
        let node = NodeIndex::new(node_idx);
        let mut merged = object_ids.get(&node_idx).cloned().unwrap_or_default();
        let before = merged.len();
        let mut neighbors = points_to_propagation_neighbors(fg, node);
        neighbors.extend(fg.object_successors_of(node));
        neighbors.extend(fg.object_predecessors_of(node));
        neighbors.sort_unstable_by_key(|idx| idx.index());
        neighbors.dedup_by_key(|idx| idx.index());
        for neighbor in neighbors {
            if !allowed_lookup.contains(&neighbor.index()) {
                continue;
            }
            if let Some(values) = object_ids.get(&neighbor.index()) {
                merged.extend(values.iter().copied());
            }
        }
        if merged.len() != before || !object_ids.contains_key(&node_idx) {
            object_ids.insert(node_idx, merged);
            if let Some(preds) = reverse.get(&node_idx) {
                for pred in preds {
                    if queued.insert(*pred) {
                        queue.push_back(*pred);
                    }
                }
            }
        }
    }
    object_ids
        .into_iter()
        .map(|(node_idx, values)| (node_idx, values.into_iter().collect::<Vec<_>>()))
        .collect()
}


fn materialize_points_to_object_ids(fg: &mut FlowGraph) {
    materialize_abstract_object_catalog(fg);
    fg.node_points_to_object_ids.clear();
    fg.value_points_to_object_ids.clear();
    fg.cell_points_to_object_ids.clear();

    fg.node_points_to_object_ids = compute_points_to_object_ids_fixpoint_for_allowed_nodes(fg, None);
    for (&(func, value), &node) in &fg.values {
        if let Some(ids) = fg.node_points_to_object_ids.get(&node.index()).cloned() {
            fg.value_points_to_object_ids.insert((func, value), ids);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(ids) = fg.node_points_to_object_ids.get(&cell.index()).cloned() {
            fg.cell_points_to_object_ids.insert(cell.index(), ids);
        }
    }
}

fn cell_candidates_for_object_ids(fg: &FlowGraph, object_ids: &[u32]) -> Vec<NodeIndex> {
    if object_ids.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for cell in all_cell_nodes(fg) {
        let candidate_ids = fg.cell_points_to_object_ids_of(cell);
        if !candidate_ids.is_empty() && points_to_object_ids_overlap(object_ids, &candidate_ids) {
            out.push(cell);
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn cell_candidates_for_value_targets(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<NodeIndex> {
    let targets = fg.value_points_to_targets_of(func, value);
    if targets.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for cell in all_cell_nodes(fg) {
        let cell_targets = fg.cell_points_to_targets_of(cell);
        if !cell_targets.is_empty() && points_to_targets_overlap(&targets, &cell_targets) {
            out.push(cell);
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn materialize_contextual_solver_state(fg: &mut FlowGraph, program: &Program) {
    materialize_abstract_object_catalog(fg);
    fg.contextual_return_values.clear();
    fg.contextual_return_cells.clear();
    fg.contextual_points_to_targets.clear();
    fg.contextual_points_to_object_ids.clear();
    fg.contextual_node_points_to_targets.clear();
    fg.contextual_value_points_to_targets.clear();
    fg.contextual_cell_points_to_targets.clear();
    fg.contextual_node_points_to_object_ids.clear();
    fg.contextual_value_points_to_object_ids.clear();
    fg.contextual_cell_points_to_object_ids.clear();
    for func in &program.functions {
        for block in &func.blocks {
            for inst in &block.insts {
                let InstKind::Call(_call) = &inst.kind else {
                    continue;
                };
                let Some(base_context) = fg.call_context_key(func.id, inst.id) else {
                    continue;
                };
                for sensitivity in all_context_sensitivities() {
                    let context = fg.refine_call_context_for_sensitivity(base_context.clone(), *sensitivity);
                    let Some(summary) = fg.contextual_call_summary(
                        func.id,
                        inst.id,
                        *sensitivity,
                        SparseDirection::Forward,
                        16,
                        4096,
                        DemandEngine::Fixpoint,
                        true,
                    ) else {
                        continue;
                    };
                    let Some(call_summary) = fg.interprocedural_call_summary_with_sensitivity(
                        func.id,
                        inst.id,
                        *sensitivity,
                        16,
                        4096,
                        DemandEngine::Fixpoint,
                        true,
                    ) else {
                        continue;
                    };
                    let mut allowed_nodes = summary
                        .traversal
                        .visited
                        .iter()
                        .copied()
                        .filter(|node_idx| fg.node_matches_structural_call_context(NodeIndex::new(*node_idx), &context))
                        .collect::<HashSet<_>>();
                    for (ret_func, ret_value) in &call_summary.return_values {
                        if let Some(&node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                            allowed_nodes.insert(node.index());
                        }
                    }
                    for (ret_func, ret_value) in &call_summary.return_live_values {
                        if let Some(&node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                            allowed_nodes.insert(node.index());
                        }
                    }
                    for cell in &call_summary.return_cells {
                        allowed_nodes.insert(*cell as usize);
                    }
                    for (_ret_func, _ret_value, cell) in &call_summary.return_value_cells {
                        allowed_nodes.insert(*cell as usize);
                    }
                    let contextual_node_targets = compute_points_to_targets_fixpoint_for_allowed_nodes(fg, Some(&allowed_nodes));
                    let contextual_node_object_ids = compute_points_to_object_ids_fixpoint_for_allowed_nodes(fg, Some(&allowed_nodes));
                    let mut targets = fg
                        .contextual_points_to_targets
                        .remove(&context)
                        .unwrap_or_default()
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    let mut object_ids = fg
                        .contextual_points_to_object_ids
                        .remove(&context)
                        .unwrap_or_default()
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    let mut return_values = fg
                        .contextual_return_values
                        .remove(&context)
                        .unwrap_or_default()
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    let mut return_cells = fg
                        .contextual_return_cells
                        .remove(&context)
                        .unwrap_or_default()
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    for (node_idx, node_targets) in contextual_node_targets {
                        let node = NodeIndex::new(node_idx);
                        let mut merged_targets = fg
                            .contextual_node_points_to_targets
                            .remove(&(context.clone(), node_idx))
                            .unwrap_or_default()
                            .into_iter()
                            .collect::<BTreeSet<_>>();
                        merged_targets.extend(node_targets.iter().cloned());
                        let merged_targets_vec = merged_targets.iter().cloned().collect::<Vec<_>>();
                        fg.contextual_node_points_to_targets.insert((context.clone(), node_idx), merged_targets_vec.clone());
                        let mut node_object_ids = fg
                            .contextual_node_points_to_object_ids
                            .remove(&(context.clone(), node_idx))
                            .unwrap_or_default()
                            .into_iter()
                            .collect::<BTreeSet<_>>();
                        if let Some(ids) = contextual_node_object_ids.get(&node_idx) {
                            node_object_ids.extend(ids.iter().copied());
                        }
                        if !node_object_ids.is_empty() {
                            let ids = node_object_ids.iter().copied().collect::<Vec<_>>();
                            fg.contextual_node_points_to_object_ids.insert((context.clone(), node_idx), ids.clone());
                            object_ids.extend(ids.iter().copied());
                        }
                        targets.extend(merged_targets_vec.iter().cloned());
                        match &fg.graph[node] {
                            FlowNode::Value { func: value_func, value } | FlowNode::Param { func: value_func, value, .. } => {
                                fg.contextual_value_points_to_targets.insert((context.clone(), value_func.0, value.0), merged_targets_vec.clone());
                                if let Some(ids) = fg.contextual_node_points_to_object_ids.get(&(context.clone(), node_idx)).cloned() {
                                    fg.contextual_value_points_to_object_ids.insert((context.clone(), value_func.0, value.0), ids);
                                }
                            }
                            FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                                fg.contextual_cell_points_to_targets.insert((context.clone(), node_idx), merged_targets_vec.clone());
                                if let Some(ids) = fg.contextual_node_points_to_object_ids.get(&(context.clone(), node_idx)).cloned() {
                                    fg.contextual_cell_points_to_object_ids.insert((context.clone(), node_idx), ids);
                                }
                            }
                            _ => {}
                        }
                    }
                    for (ret_func, ret_value) in &call_summary.return_values {
                        return_values.insert((*ret_func, *ret_value));
                    }
                    for (ret_func, ret_value) in &call_summary.return_live_values {
                        return_values.insert((*ret_func, *ret_value));
                    }
                    for cell in &call_summary.return_cells {
                        return_cells.insert(*cell as usize);
                    }
                    for (_ret_func, _ret_value, cell) in &call_summary.return_value_cells {
                        return_cells.insert(*cell as usize);
                    }
                    fg.contextual_return_values.insert(context.clone(), return_values.into_iter().collect());
                    fg.contextual_return_cells.insert(context.clone(), return_cells.into_iter().collect());
                    fg.contextual_points_to_targets.insert(context.clone(), targets.into_iter().collect());
                    fg.contextual_points_to_object_ids.insert(context.clone(), object_ids.into_iter().collect());
                }
            }
        }
    }

    let covered_nodes = fg
        .contextual_node_points_to_targets
        .keys()
        .map(|(_, node_idx)| *node_idx)
        .chain(
            fg.contextual_node_points_to_object_ids
                .keys()
                .map(|(_, node_idx)| *node_idx),
        )
        .collect::<HashSet<_>>();
    let fallback_nodes = if covered_nodes.is_empty() {
        fg.graph.node_indices().map(|node| node.index()).collect::<HashSet<_>>()
    } else {
        fg.graph
            .node_indices()
            .map(|node| node.index())
            .filter(|node_idx| !covered_nodes.contains(node_idx))
            .collect::<HashSet<_>>()
    };
    if !fallback_nodes.is_empty() {
        let context = CallContextKey::default();
        let contextual_node_targets = compute_points_to_targets_fixpoint_for_allowed_nodes(fg, Some(&fallback_nodes));
        let contextual_node_object_ids = compute_points_to_object_ids_fixpoint_for_allowed_nodes(fg, Some(&fallback_nodes));
        let mut targets = BTreeSet::<String>::new();
        let mut object_ids = BTreeSet::<u32>::new();
        for (node_idx, node_targets) in contextual_node_targets {
            let node = NodeIndex::new(node_idx);
            let mut merged_targets = fg
                .contextual_node_points_to_targets
                .remove(&(context.clone(), node_idx))
                .unwrap_or_default()
                .into_iter()
                .collect::<BTreeSet<_>>();
            merged_targets.extend(node_targets.iter().cloned());
            let merged_targets_vec = merged_targets.iter().cloned().collect::<Vec<_>>();
            fg.contextual_node_points_to_targets
                .insert((context.clone(), node_idx), merged_targets_vec.clone());
            targets.extend(merged_targets_vec.iter().cloned());
            let mut merged_object_ids = fg
                .contextual_node_points_to_object_ids
                .remove(&(context.clone(), node_idx))
                .unwrap_or_default()
                .into_iter()
                .collect::<BTreeSet<_>>();
            if let Some(ids) = contextual_node_object_ids.get(&node_idx) {
                merged_object_ids.extend(ids.iter().copied());
            }
            if !merged_object_ids.is_empty() {
                let ids = merged_object_ids.iter().copied().collect::<Vec<_>>();
                fg.contextual_node_points_to_object_ids
                    .insert((context.clone(), node_idx), ids.clone());
                object_ids.extend(ids.iter().copied());
            }
            match &fg.graph[node] {
                FlowNode::Value { func: value_func, value } | FlowNode::Param { func: value_func, value, .. } => {
                    fg.contextual_value_points_to_targets
                        .insert((context.clone(), value_func.0, value.0), merged_targets_vec.clone());
                    if let Some(ids) = fg.contextual_node_points_to_object_ids.get(&(context.clone(), node_idx)).cloned() {
                        fg.contextual_value_points_to_object_ids
                            .insert((context.clone(), value_func.0, value.0), ids);
                    }
                }
                FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                    fg.contextual_cell_points_to_targets
                        .insert((context.clone(), node_idx), merged_targets_vec.clone());
                    if let Some(ids) = fg.contextual_node_points_to_object_ids.get(&(context.clone(), node_idx)).cloned() {
                        fg.contextual_cell_points_to_object_ids.insert((context.clone(), node_idx), ids);
                    }
                }
                _ => {}
            }
        }
        fg.contextual_points_to_targets.insert(context.clone(), targets.into_iter().collect());
        fg.contextual_points_to_object_ids.insert(context, object_ids.into_iter().collect());
    }
}


fn materialize_partitioned_points_to_state(fg: &mut FlowGraph, program: &Program) {
    materialize_contextual_solver_state(fg, program);
    aggregate_partitioned_points_to_state(fg);
}

fn aggregate_partitioned_points_to_state(fg: &mut FlowGraph) {
    fg.node_points_to_targets.clear();
    fg.value_points_to_targets.clear();
    fg.cell_points_to_targets.clear();
    fg.node_points_to_object_ids.clear();
    fg.value_points_to_object_ids.clear();
    fg.cell_points_to_object_ids.clear();

    let contextual_target_entries = fg
        .contextual_node_points_to_targets
        .iter()
        .map(|((_, node_idx), targets)| (*node_idx, targets.clone()))
        .collect::<Vec<_>>();
    let contextual_object_entries = fg
        .contextual_node_points_to_object_ids
        .iter()
        .map(|((_, node_idx), ids)| (*node_idx, ids.clone()))
        .collect::<Vec<_>>();

    let mut covered_nodes = HashSet::<usize>::new();
    for (node_idx, targets) in contextual_target_entries {
        covered_nodes.insert(node_idx);
        let mut merged = fg.node_points_to_targets.remove(&node_idx).unwrap_or_default();
        merged.extend(targets);
        merged.sort();
        merged.dedup();
        fg.node_points_to_targets.insert(node_idx, merged);
    }
    for (node_idx, ids) in contextual_object_entries {
        covered_nodes.insert(node_idx);
        let mut merged = fg.node_points_to_object_ids.remove(&node_idx).unwrap_or_default();
        merged.extend(ids);
        merged.sort_unstable();
        merged.dedup();
        fg.node_points_to_object_ids.insert(node_idx, merged);
    }

    let value_entries = fg.values.iter().map(|(&(func, value), &node)| (func, value, node.index())).collect::<Vec<_>>();
    for (func, value, node_idx) in value_entries {
        if let Some(targets) = fg.node_points_to_targets.get(&node_idx).cloned() {
            fg.value_points_to_targets.insert((func, value), targets);
        }
        if let Some(ids) = fg.node_points_to_object_ids.get(&node_idx).cloned() {
            fg.value_points_to_object_ids.insert((func, value), ids);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(targets) = fg.node_points_to_targets.get(&cell.index()).cloned() {
            fg.cell_points_to_targets.insert(cell.index(), targets);
        }
        if let Some(ids) = fg.node_points_to_object_ids.get(&cell.index()).cloned() {
            fg.cell_points_to_object_ids.insert(cell.index(), ids);
        }
    }
}

fn materialize_sparse_data_adjacency(fg: &mut FlowGraph) {
    fg.sparse_successors.clear();
    fg.sparse_predecessors.clear();
    fg.clear_sparse_caches();
    for edge in fg.graph.edge_references() {
        if !is_sparse_data_edge(&edge.weight().kind) {
            continue;
        }
        let src = edge.source().index();
        let dst = edge.target().index();
        fg.sparse_successors.entry(src).or_default().push(dst);
        fg.sparse_predecessors.entry(dst).or_default().push(src);
    }
    for values in fg.sparse_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.sparse_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    materialize_heap_value_adjacency(fg);
    materialize_heap_object_adjacency(fg);
    materialize_object_graph_adjacency(fg);
    materialize_object_shape_paths(fg);
    materialize_object_shape_fixpoint(fg);
    materialize_cell_write_generations(fg);
    materialize_memory_regions(fg);
    materialize_region_graph_adjacency(fg);
    materialize_memory_regions(fg);
    materialize_region_graph_adjacency(fg);
    materialize_cell_live_state(fg);
    materialize_region_live_state(fg);
    materialize_object_graph_adjacency(fg);
    materialize_object_shape_paths(fg);
    materialize_object_shape_fixpoint(fg);
    materialize_memory_regions(fg);
    materialize_region_graph_adjacency(fg);
    materialize_region_live_state(fg);
}

fn add_unique_summary_edge(fg: &mut FlowGraph, src: NodeIndex, dst: NodeIndex, rule_id: &str) -> bool {
    for edge in fg.graph.edges_connecting(src, dst) {
        if let EdgeKind::Summary { rule_id: existing } = &edge.weight().kind {
            if existing == rule_id {
                return false;
            }
        }
    }
    fg.graph.add_edge(
        src,
        dst,
        FlowEdge {
            kind: EdgeKind::Summary {
                rule_id: rule_id.to_string(),
            },
        },
    );
    true
}

fn connect_materialized_function_transfer_summaries(fg: &mut FlowGraph, program: &Program) -> usize {
    let mut pending_edges = Vec::<(NodeIndex, NodeIndex, String)>::new();
    for func in &program.functions {
        let Some(summary) = fg.function_transfer_summary(func.id, 16, 4096, DemandEngine::Fixpoint, true) else {
            continue;
        };
        let Some(&ret_node) = fg.function_returns.get(&func.id) else {
            continue;
        };
        for index in &summary.return_reachable_params {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                pending_edges.push((param_node, ret_node, "internal:function-return".to_string()));
            }
        }
        for (from_index, to_index) in &summary.param_to_param {
            if let (Some(&src), Some(&dst)) = (
                fg.function_params.get(&(func.id, *from_index)),
                fg.function_params.get(&(func.id, *to_index)),
            ) {
                pending_edges.push((src, dst, "internal:function-param".to_string()));
            }
        }
    }
    let mut added = 0usize;
    for (src, dst, rule_id) in pending_edges {
        if add_unique_summary_edge(fg, src, dst, &rule_id) {
            added += 1;
        }
    }
    added
}

fn connect_materialized_function_heap_effect_summaries(fg: &mut FlowGraph, program: &Program) -> usize {
    let mut pending_edges = Vec::<(NodeIndex, NodeIndex, String)>::new();
    for func in &program.functions {
        let Some(summary) = fg.function_heap_effect_summary(func.id, 16, 4096, DemandEngine::Fixpoint, true) else {
            continue;
        };
        let Some(&ret_node) = fg.function_returns.get(&func.id) else {
            continue;
        };
        for (index, cell) in &summary.param_to_read_cells {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let cell = NodeIndex::new(*cell as usize);
                if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                    pending_edges.push((param_node, cell, "internal:function-heap-read".to_string()));
                }
            }
        }
        for (index, region) in &summary.param_to_read_regions {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let mut candidates = summary
                    .param_to_read_cells
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, cell)| NodeIndex::new(*cell as usize))
                    .collect::<Vec<_>>();
                let object_ids = summary
                    .param_to_read_objects
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, object_id)| *object_id)
                    .collect::<Vec<_>>();
                candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                candidates.extend(region_candidate_cells(fg, region));
                for (path_index, path) in &summary.param_to_read_paths {
                    if path_index != index {
                        continue;
                    }
                    if let FlowNode::Param { value, .. } = &fg.graph[param_node] {
                        candidates.extend(candidate_cells_for_relative_path_from_value(fg, func.id, *value, path));
                    }
                }
                candidates.sort_unstable_by_key(|node| node.index());
                candidates.dedup_by_key(|node| node.index());
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                        continue;
                    }
                    pending_edges.push((param_node, cell, "internal:function-heap-read".to_string()));
                }
            }
        }
        for (index, cell) in &summary.param_to_write_cells {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let cell = NodeIndex::new(*cell as usize);
                if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                    pending_edges.push((param_node, cell, "internal:function-heap-write".to_string()));
                }
            }
        }
        for (index, region) in &summary.param_to_write_regions {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let mut candidates = summary
                    .param_to_write_cells
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, cell)| NodeIndex::new(*cell as usize))
                    .collect::<Vec<_>>();
                let object_ids = summary
                    .param_to_write_objects
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, object_id)| *object_id)
                    .collect::<Vec<_>>();
                candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                candidates.extend(region_candidate_cells(fg, region));
                for (path_index, path) in &summary.param_to_write_paths {
                    if path_index != index {
                        continue;
                    }
                    if let FlowNode::Param { value, .. } = &fg.graph[param_node] {
                        candidates.extend(candidate_cells_for_relative_path_from_value(fg, func.id, *value, path));
                    }
                }
                candidates.sort_unstable_by_key(|node| node.index());
                candidates.dedup_by_key(|node| node.index());
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                        continue;
                    }
                    pending_edges.push((param_node, cell, "internal:function-heap-write".to_string()));
                }
            }
        }
        for (index, cell) in &summary.param_to_return_cells {
            if let Some(_param_node) = fg.function_params.get(&(func.id, *index)) {
                let cell = NodeIndex::new(*cell as usize);
                if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                    pending_edges.push((cell, ret_node, "internal:function-heap-return".to_string()));
                }
            }
        }
        for (index, region) in &summary.param_to_return_regions {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let mut candidates = summary
                    .param_to_return_cells
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, cell)| NodeIndex::new(*cell as usize))
                    .collect::<Vec<_>>();
                let object_ids = summary
                    .param_to_return_objects
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, object_id)| *object_id)
                    .collect::<Vec<_>>();
                candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                candidates.extend(region_candidate_cells(fg, region));
                for (path_index, path) in &summary.param_to_return_paths {
                    if path_index != index {
                        continue;
                    }
                    if let FlowNode::Param { value, .. } = &fg.graph[param_node] {
                        candidates.extend(candidate_cells_for_relative_path_from_value(fg, func.id, *value, path));
                    }
                }
                candidates.sort_unstable_by_key(|node| node.index());
                candidates.dedup_by_key(|node| node.index());
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                        continue;
                    }
                    pending_edges.push((cell, ret_node, "internal:function-heap-return".to_string()));
                }
            }
        }
        for (_index, live_func, live_value) in &summary.param_to_return_live_values {
            if let Some(&live_value_node) = fg.values.get(&(FunctionId(*live_func), ValueId(*live_value))) {
                pending_edges.push((live_value_node, ret_node, "internal:function-live-return-value".to_string()));
            }
        }
        for (ret_func, ret_value, region) in &summary.return_value_regions {
            if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                let mut candidates = summary
                    .return_value_cells
                    .iter()
                    .filter(|(path_func, path_value, _)| path_func == ret_func && path_value == ret_value)
                    .map(|(_, _, cell)| NodeIndex::new(*cell as usize))
                    .collect::<Vec<_>>();
                let object_ids = summary
                    .return_value_objects
                    .iter()
                    .filter(|(path_func, path_value, _)| path_func == ret_func && path_value == ret_value)
                    .map(|(_, _, object_id)| *object_id)
                    .collect::<Vec<_>>();
                candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                candidates.extend(region_candidate_cells(fg, region));
                for (path_func, path_value, path) in &summary.return_value_paths {
                    if path_func != ret_func || path_value != ret_value {
                        continue;
                    }
                    candidates.extend(candidate_cells_for_relative_path_from_value(
                        fg,
                        FunctionId(*ret_func),
                        ValueId(*ret_value),
                        path,
                    ));
                }
                candidates.sort_unstable_by_key(|node| node.index());
                candidates.dedup_by_key(|node| node.index());
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                        continue;
                    }
                    pending_edges.push((ret_value_node, cell, "internal:function-return-value-region".to_string()));
                }
            }
        }
        for cell in &summary.return_cells {
            let cell = NodeIndex::new(*cell as usize);
            if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                pending_edges.push((cell, ret_node, "internal:function-heap-return".to_string()));
            }
        }
        for (live_func, live_value) in &summary.return_live_values {
            if let Some(&live_value_node) = fg.values.get(&(FunctionId(*live_func), ValueId(*live_value))) {
                pending_edges.push((live_value_node, ret_node, "internal:function-live-return-value".to_string()));
            }
        }
    }
    let mut added = 0usize;
    for (src, dst, rule_id) in pending_edges {
        if add_unique_summary_edge(fg, src, dst, &rule_id) {
            added += 1;
        }
    }
    added
}

fn connect_materialized_interprocedural_summaries(fg: &mut FlowGraph, program: &Program) -> usize {
    let mut pending_edges = Vec::<(NodeIndex, NodeIndex, String)>::new();
    for func in &program.functions {
        for block in &func.blocks {
            for inst in &block.insts {
                let InstKind::Call(_call) = &inst.kind else {
                    continue;
                };
                let Some(summary) = fg.interprocedural_call_summary(
                    func.id,
                    inst.id,
                    16,
                    4096,
                    DemandEngine::Fixpoint,
                    true,
                ) else {
                    continue;
                };
                let callee_name = fg
                    .call_meta
                    .get(&(func.id, inst.id))
                    .and_then(|meta| meta.callee_name.clone());
                let ret_port = get_or_create_call_port(
                    fg,
                    func.id,
                    inst.id,
                    Port::Return,
                    callee_name,
                );
                let mut port_nodes = BTreeMap::<String, NodeIndex>::new();
                for ((call_func, call_inst, port), node) in &fg.call_ports {
                    if *call_func == func.id && *call_inst == inst.id {
                        port_nodes.insert(format!("{:?}", port), *node);
                    }
                }
                for port_name in &summary.port_to_return {
                    if let Some(src) = port_nodes.get(port_name) {
                        pending_edges.push((*src, ret_port, "internal:return".to_string()));
                    }
                }
                for (src_name, dst_name) in &summary.port_to_port {
                    if let (Some(src), Some(dst)) = (port_nodes.get(src_name), port_nodes.get(dst_name)) {
                        pending_edges.push((*src, *dst, "internal:param".to_string()));
                    }
                }
                for (src_name, ret_func, ret_value) in &summary.port_to_return_values {
                    if let Some(src) = port_nodes.get(src_name) {
                        if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                            pending_edges.push((*src, ret_value_node, "internal:return-value-source".to_string()));
                            pending_edges.push((ret_value_node, ret_port, "internal:return-value".to_string()));
                        }
                    }
                }
                for (src_name, live_func, live_value) in &summary.port_to_return_live_values {
                    if let Some(src) = port_nodes.get(src_name) {
                        if let Some(&live_value_node) = fg.values.get(&(FunctionId(*live_func), ValueId(*live_value))) {
                            pending_edges.push((*src, live_value_node, "internal:heap-live-return-source".to_string()));
                            pending_edges.push((live_value_node, ret_port, "internal:heap-live-return".to_string()));
                        }
                    }
                }
                for (ret_func, ret_value) in &summary.return_values {
                    if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                        pending_edges.push((ret_value_node, ret_port, "internal:return-value".to_string()));
                    }
                }
                for (live_func, live_value) in &summary.return_live_values {
                    if let Some(&live_value_node) = fg.values.get(&(FunctionId(*live_func), ValueId(*live_value))) {
                        pending_edges.push((live_value_node, ret_port, "internal:heap-live-return".to_string()));
                    }
                }
                for cell in &summary.return_cells {
                    let cell_node = NodeIndex::new(*cell as usize);
                    pending_edges.push((cell_node, ret_port, "internal:heap-return".to_string()));
                }
                for (ret_func, ret_value, cell) in &summary.return_value_cells {
                    if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                        pending_edges.push((ret_value_node, NodeIndex::new(*cell as usize), "internal:return-value-region".to_string()));
                    }
                }
                for (src_name, ret_func, ret_value, region) in &summary.port_to_return_value_regions {
                    if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                        let mut candidates = summary
                            .return_value_cells
                            .iter()
                            .filter(|(path_func, path_value, _)| path_func == ret_func && path_value == ret_value)
                            .map(|(_, _, cell)| NodeIndex::new(*cell as usize))
                            .collect::<Vec<_>>();
                        let object_ids = summary
                            .port_to_return_value_objects
                            .iter()
                            .filter(|(path_src, path_func, path_value, _)| path_src == src_name && path_func == ret_func && path_value == ret_value)
                            .map(|(_, _, _, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                        candidates.extend(region_candidate_cells(fg, region));
                        if let Some(src) = port_nodes.get(src_name) {
                            for (path_src, path_func, path_value, path) in &summary.port_to_return_value_paths {
                                if path_src == src_name && path_func == ret_func && path_value == ret_value {
                                    candidates.extend(relative_path_candidate_cells_for_port(fg, *src, path));
                                }
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((ret_value_node, cell, "internal:return-value-region".to_string()));
                        }
                    }
                }
                for (ret_func, ret_value, region) in &summary.return_value_regions {
                    if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                        let object_ids = summary
                            .return_value_objects
                            .iter()
                            .filter(|(path_func, path_value, _)| path_func == ret_func && path_value == ret_value)
                            .map(|(_, _, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        let mut candidates = cell_candidates_for_object_ids(fg, &object_ids);
                        candidates.extend(region_candidate_cells(fg, region));
                        for (path_func, path_value, path) in &summary.return_value_paths {
                            if path_func == ret_func && path_value == ret_value {
                                candidates.extend(candidate_cells_for_relative_path_from_value(
                                    fg,
                                    FunctionId(*ret_func),
                                    ValueId(*ret_value),
                                    path,
                                ));
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((ret_value_node, cell, "internal:return-region-value".to_string()));
                        }
                    }
                }
                for (src_name, cell) in &summary.port_to_read_cells {
                    if let Some(src) = port_nodes.get(src_name) {
                        pending_edges.push((*src, NodeIndex::new(*cell as usize), "internal:heap-read".to_string()));
                    }
                }
                for (src_name, region) in &summary.port_to_read_regions {
                    if let Some(src) = port_nodes.get(src_name) {
                        let mut candidates = summary
                            .port_to_read_cells
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, cell)| NodeIndex::new(*cell as usize))
                            .collect::<Vec<_>>();
                        let object_ids = summary
                            .port_to_read_objects
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                        candidates.extend(region_candidate_cells(fg, region));
                        for (path_src, path) in &summary.port_to_read_paths {
                            if path_src == src_name {
                                candidates.extend(relative_path_candidate_cells_for_port(fg, *src, path));
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((*src, cell, "internal:heap-read".to_string()));
                        }
                    }
                }
                for (src_name, cell) in &summary.port_to_write_cells {
                    if let Some(src) = port_nodes.get(src_name) {
                        pending_edges.push((*src, NodeIndex::new(*cell as usize), "internal:heap-write".to_string()));
                    }
                }
                for (src_name, region) in &summary.port_to_write_regions {
                    if let Some(src) = port_nodes.get(src_name) {
                        let mut candidates = summary
                            .port_to_write_cells
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, cell)| NodeIndex::new(*cell as usize))
                            .collect::<Vec<_>>();
                        let object_ids = summary
                            .port_to_write_objects
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                        candidates.extend(region_candidate_cells(fg, region));
                        for (path_src, path) in &summary.port_to_write_paths {
                            if path_src == src_name {
                                candidates.extend(relative_path_candidate_cells_for_port(fg, *src, path));
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((*src, cell, "internal:heap-write".to_string()));
                        }
                    }
                }
                for (src_name, cell) in &summary.port_to_return_cells {
                    if let Some(src) = port_nodes.get(src_name) {
                        let cell = NodeIndex::new(*cell as usize);
                        pending_edges.push((*src, cell, "internal:heap-return-source".to_string()));
                        pending_edges.push((cell, ret_port, "internal:heap-return".to_string()));
                    }
                }
                for (src_name, region) in &summary.port_to_return_regions {
                    if let Some(src) = port_nodes.get(src_name) {
                        let mut candidates = summary
                            .port_to_return_cells
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, cell)| NodeIndex::new(*cell as usize))
                            .collect::<Vec<_>>();
                        let object_ids = summary
                            .port_to_return_objects
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                        candidates.extend(region_candidate_cells(fg, region));
                        for (path_src, path) in &summary.port_to_return_paths {
                            if path_src == src_name {
                                candidates.extend(relative_path_candidate_cells_for_port(fg, *src, path));
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((*src, cell, "internal:heap-return-source".to_string()));
                            pending_edges.push((cell, ret_port, "internal:heap-return".to_string()));
                        }
                    }
                }
            }
        }
    }
    let mut added = 0usize;
    for (src, dst, rule_id) in pending_edges {
        if add_unique_summary_edge(fg, src, dst, &rule_id) {
            added += 1;
        }
    }
    added
}

fn solver_iteration_cap(fg: &FlowGraph) -> usize {
    let graph_nodes = fg.graph.node_count().max(1);
    let graph_edges = fg.graph.edge_count().max(1);
    graph_nodes.saturating_add(graph_edges).saturating_mul(4).max(64)
}

fn materialize_unified_analysis_state(fg: &mut FlowGraph) {
    let mut previous_signature = None;
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        materialize_sparse_data_adjacency(fg);
        materialize_object_shape_paths(fg);
        materialize_object_shape_fixpoint(fg);
        materialize_cell_write_generations(fg);
        materialize_memory_regions(fg);
        materialize_region_graph_adjacency(fg);
        materialize_cell_live_state(fg);
        materialize_region_live_state(fg);
        materialize_object_graph_adjacency(fg);
        let signature = analysis_state_signature(fg);
        if previous_signature.as_ref() == Some(&signature) {
            break;
        }
        assert!(iterations <= solver_iteration_cap(fg), "unified analysis failed to converge");
        previous_signature = Some(signature);
    }
}

fn materialize_interprocedural_solver_closure(fg: &mut FlowGraph, program: &Program) {
    let mut previous_signature = None;
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        materialize_unified_analysis_state(fg);
        materialize_partitioned_points_to_state(fg, program);
        let added_function_edges = connect_materialized_function_transfer_summaries(fg, program);
        let added_heap_edges = connect_materialized_function_heap_effect_summaries(fg, program);
        let added_call_edges = connect_materialized_interprocedural_summaries(fg, program);
        materialize_unified_analysis_state(fg);
        materialize_partitioned_points_to_state(fg, program);
        let signature = analysis_state_signature(fg);
        if added_function_edges == 0 && added_heap_edges == 0 && added_call_edges == 0 && previous_signature.as_ref() == Some(&signature) {
            break;
        }
        assert!(iterations <= solver_iteration_cap(fg), "interprocedural solver failed to converge");
        previous_signature = Some(signature);
    }
    fg.solver_closure_iterations = iterations;
}

fn materialize_global_solver_closure(fg: &mut FlowGraph, program: &Program) {
    let mut previous_signature = None;
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        materialize_unified_analysis_state(fg);
        materialize_partitioned_points_to_state(fg, program);
        materialize_interprocedural_solver_closure(fg, program);
        materialize_unified_analysis_state(fg);
        materialize_partitioned_points_to_state(fg, program);
        let signature = analysis_state_signature(fg);
        if previous_signature.as_ref() == Some(&signature) {
            break;
        }
        assert!(iterations <= solver_iteration_cap(fg), "global solver failed to converge");
        previous_signature = Some(signature);
    }
    fg.global_solver_iterations = iterations;
}

