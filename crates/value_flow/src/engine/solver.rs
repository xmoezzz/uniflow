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

/// Edges whose endpoints denote the same may-referenced value/object.
///
/// Keep this intentionally stricter than `is_sparse_data_edge`: taint/value
/// flow answers "can information move from A to B?", while points-to/shape
/// propagation answers "can A and B denote the same object/content?". Mixing
/// those relations turns ordinary source/sink or projection reachability into
/// alias equivalence and creates very large Cartesian solver states.
fn is_identity_preserving_edge(
    fg: &FlowGraph,
    src: NodeIndex,
    dst: NodeIndex,
    kind: &EdgeKind,
) -> bool {
    match kind {
        EdgeKind::Assign
        | EdgeKind::Phi
        | EdgeKind::StoreField { .. }
        | EdgeKind::StoreIndex
        | EdgeKind::ValueToCallPort
        | EdgeKind::CallPortToValue
        | EdgeKind::ActualToFormal
        | EdgeKind::FormalToActual => true,
        EdgeKind::LoadField { .. } | EdgeKind::LoadIndex => {
            // A load edge has two distinct structural meanings in the graph:
            // `base -> cell` records the projection itself, while `cell -> dst`
            // (and a few direct value fallbacks) carries the projected contents.
            // Only the latter preserves object identity. Equating the base object
            // with each of its cells collapses nested object shapes and explodes
            // points-to/memory-region state.
            !matches!(
                (&fg.graph[src], &fg.graph[dst]),
                (
                    FlowNode::Value { .. },
                    FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }
                )
            )
        }
        _ => false,
    }
}

fn push_identity_pair(
    identity_neighbors: &mut HashMap<usize, Vec<usize>>,
    left: usize,
    right: usize,
) {
    if left == right {
        return;
    }
    push_unique_index(identity_neighbors, left, right);
    push_unique_index(identity_neighbors, right, left);
}

fn identity_propagation_neighbors(fg: &FlowGraph, node: NodeIndex) -> Vec<NodeIndex> {
    fg.identity_neighbors
        .get(&node.index())
        .map(|values| values.iter().copied().map(NodeIndex::new).collect())
        .unwrap_or_default()
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
            push_unique_index(
                &mut fg.heap_value_successors,
                base_node.index(),
                proj_node.index(),
            );
            push_unique_index(
                &mut fg.heap_value_predecessors,
                proj_node.index(),
                base_node.index(),
            );
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
            push_unique_index(
                &mut fg.heap_value_successors,
                base_node.index(),
                proj_node.index(),
            );
            push_unique_index(
                &mut fg.heap_value_predecessors,
                proj_node.index(),
                base_node.index(),
            );
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
        push_unique_index(
            &mut fg.heap_object_successors,
            base_node.index(),
            cell.index(),
        );
        push_unique_index(
            &mut fg.heap_object_predecessors,
            cell.index(),
            base_node.index(),
        );
        let projected = cell_values_for_flow(fg, cell);
        for (proj_func, proj_value) in projected {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_index(
                &mut fg.heap_object_successors,
                cell.index(),
                proj_node.index(),
            );
            push_unique_index(
                &mut fg.heap_object_predecessors,
                proj_node.index(),
                cell.index(),
            );
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

fn materialize_object_graph_adjacency(fg: &mut FlowGraph) -> bool {
    let previous_successors = std::mem::take(&mut fg.object_graph_successors);
    let previous_predecessors = std::mem::take(&mut fg.object_graph_predecessors);
    let previous_labels = std::mem::take(&mut fg.object_graph_labels);
    let previous_shape_labels = std::mem::take(&mut fg.object_shape_labels);

    for ((func, base, field), &cell) in &fg.field_cells {
        let Some(&base_node) = fg.values.get(&(*func, *base)) else {
            continue;
        };
        let label = format!("field:{}", field);
        fg.object_shape_labels
            .entry(base_node.index())
            .or_default()
            .push(label.clone());
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
        fg.object_shape_labels
            .entry(base_node.index())
            .or_default()
            .push(label.clone());
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

    fg.object_graph_successors != previous_successors
        || fg.object_graph_predecessors != previous_predecessors
        || fg.object_graph_labels != previous_labels
        || fg.object_shape_labels != previous_shape_labels
}

fn object_shape_suffixes(
    fg: &FlowGraph,
    node: NodeIndex,
    depth: usize,
    cache: &mut HashMap<(usize, usize), BTreeSet<String>>,
) -> BTreeSet<String> {
    if depth == 0 {
        return BTreeSet::new();
    }
    if let Some(paths) = cache.get(&(node.index(), depth)) {
        return paths.clone();
    }
    let mut out = BTreeSet::new();
    for succ in fg.object_graph_successors_of(node) {
        let Some(label) = fg.object_graph_edge_label(node, succ) else {
            continue;
        };
        out.insert(label.to_string());
        for suffix in object_shape_suffixes(fg, succ, depth - 1, cache) {
            out.insert(format!("{label}.{suffix}"));
        }
    }
    cache.insert((node.index(), depth), out.clone());
    out
}

fn materialize_object_shape_paths(fg: &mut FlowGraph) {
    fg.object_shape_paths.clear();
    let value_nodes = fg.values.values().copied().collect::<Vec<_>>();
    // Memoize bounded suffix languages, not every graph-edge trail. Alias
    // diamonds often spell the same path many times; recursive fields may
    // legitimately repeat an edge and are bounded by the remaining depth.
    let mut cache = HashMap::new();
    for node in value_nodes {
        let out = object_shape_suffixes(fg, node, 4, &mut cache);
        if !out.is_empty() {
            fg.object_shape_paths
                .insert(node.index(), out.into_iter().collect());
        }
    }
}

fn shape_propagation_neighbors(fg: &FlowGraph, node: NodeIndex) -> Vec<NodeIndex> {
    identity_propagation_neighbors(fg, node)
}

/// Both shape and region overlays intentionally propagate labels in both
/// directions. Their least fixed point is exactly the seed union of each
/// connected component; do not repeatedly clone/re-union every neighbor set.
fn propagate_symmetric_labels<T: Ord + Clone>(
    nodes: impl Iterator<Item = NodeIndex>,
    seeds: HashMap<usize, BTreeSet<T>>,
    neighbors: impl Fn(NodeIndex) -> Vec<NodeIndex>,
) -> HashMap<usize, BTreeSet<T>> {
    let mut seen = HashSet::new();
    let mut out = HashMap::new();
    for node in nodes {
        if !seen.insert(node.index()) {
            continue;
        }
        let mut component = Vec::new();
        let mut pending = vec![node];
        let mut labels = BTreeSet::new();
        while let Some(current) = pending.pop() {
            component.push(current.index());
            if let Some(values) = seeds.get(&current.index()) {
                labels.extend(values.iter().cloned());
            }
            for next in neighbors(current) {
                if seen.insert(next.index()) {
                    pending.push(next);
                }
            }
        }
        if !labels.is_empty() {
            for index in component {
                out.insert(index, labels.clone());
            }
        }
    }
    out
}

fn propagate_symmetric_sorted_labels<T: Ord + Clone>(
    nodes: &[NodeIndex],
    seeds: HashMap<usize, Vec<T>>,
    neighbors: impl Fn(NodeIndex) -> Vec<NodeIndex>,
) -> HashMap<usize, Vec<T>> {
    let mut seen = HashSet::with_capacity(nodes.len());
    let mut out = HashMap::with_capacity(nodes.len());
    for &node in nodes {
        if !seen.insert(node.index()) {
            continue;
        }
        let mut component = Vec::new();
        let mut pending = vec![node];
        let mut labels = Vec::new();
        while let Some(current) = pending.pop() {
            component.push(current.index());
            if let Some(values) = seeds.get(&current.index()) {
                labels.extend(values.iter().cloned());
            }
            for next in neighbors(current) {
                if seen.insert(next.index()) {
                    pending.push(next);
                }
            }
        }
        if !labels.is_empty() {
            labels.sort_unstable();
            labels.dedup();
            for index in component {
                out.insert(index, labels.clone());
            }
        }
    }
    out
}

fn materialize_object_shape_fixpoint(_fg: &mut FlowGraph) {
    // `materialize_object_shape_paths` already derives bounded paths from the
    // object graph. Re-broadcasting every path over identity components
    // creates one owned BTreeSet per value in a component, which is both
    // redundant and unbounded in project size. Identity/object reachability
    // remains available to queries through their dedicated sparse overlays.
}

fn memory_region_value_seed_cache(
    fg: &FlowGraph,
) -> HashMap<(FunctionId, ValueId), Vec<String>> {
    let mut keys = HashSet::with_capacity(fg.values.len());
    for node in fg.graph.node_indices() {
        match &fg.graph[node] {
            FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
                keys.insert((*func, *value));
            }
            FlowNode::FieldCell { func, base, .. } | FlowNode::IndexCell { func, base, .. } => {
                keys.insert((*func, *base));
            }
            _ => {}
        }
    }

    let mut seeds = HashMap::with_capacity(keys.len());
    for (func, value) in keys {
        seeds.insert((func, value), memory_region_seed_for_value(fg, func, value));
    }
    seeds
}

fn initial_memory_regions_for_node(
    fg: &FlowGraph,
    node: NodeIndex,
    value_seeds: &HashMap<(FunctionId, ValueId), Vec<String>>,
) -> Vec<String> {
    let mut regions = Vec::new();
    let mut value_or_param = false;
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            value_or_param = true;
            if let Some(seeded) = value_seeds.get(&(*func, *value)) {
                regions.extend_from_slice(seeded);
            }
        }
        FlowNode::FieldCell {
            func, base, field, ..
        } => {
            let mut bases = fg.value_memory_regions_of(*func, *base);
            if bases.is_empty() {
                bases = value_seeds.get(&(*func, *base)).cloned().unwrap_or_default();
            }
            for base_region in bases {
                regions.push(format!("{}.{}", base_region, field));
            }
        }
        FlowNode::IndexCell {
            func,
            base,
            abstract_key,
            ..
        } => {
            let mut bases = fg.value_memory_regions_of(*func, *base);
            if bases.is_empty() {
                bases = value_seeds.get(&(*func, *base)).cloned().unwrap_or_default();
            }
            for base_region in bases {
                regions.push(format!("{}[{}]", base_region, abstract_key));
            }
        }
        FlowNode::CallPort { port, .. } => {
            regions.push(format!("mem:port:{:?}", port));
        }
        _ => {}
    }
    // Value/parameter seeds already include both shape paths and labels. Do
    // not normalize the same strings a second time for the same node.
    if !value_or_param {
        for shape in fg.object_shape_paths_of(node) {
            if !shape.trim().is_empty() {
                regions.push(normalized_memory_region(&shape));
            }
        }
    }
    regions.sort_unstable();
    regions.dedup();
    regions
}

fn memory_region_propagation_neighbors(fg: &FlowGraph, node: NodeIndex) -> Vec<NodeIndex> {
    // Memory regions preserve the historical related-region closure, but
    // object identity does not. Keep the region backbone here instead of
    // feeding it back into points-to propagation.
    let mut out = identity_propagation_neighbors(fg, node);
    out.extend(fg.region_graph_connectivity_neighbors_of(node));
    out.sort_unstable_by_key(|n| n.index());
    out.dedup_by_key(|n| n.index());
    out
}

fn materialize_memory_regions(fg: &mut FlowGraph) -> bool {
    let previous_node_memory_regions = std::mem::take(&mut fg.node_memory_regions);
    let previous_value_memory_regions = std::mem::take(&mut fg.value_memory_regions);
    let previous_cell_memory_regions = std::mem::take(&mut fg.cell_memory_regions);
    let value_seeds = memory_region_value_seed_cache(fg);
    let nodes = fg.graph.node_indices().collect::<Vec<_>>();
    let mut regions = HashMap::<usize, Vec<String>>::new();
    for node in fg.graph.node_indices() {
        let seeded = initial_memory_regions_for_node(fg, node, &value_seeds);
        if !seeded.is_empty() {
            regions.insert(node.index(), seeded);
        }
    }
    let regions = propagate_symmetric_sorted_labels(&nodes, regions, |node| {
        memory_region_propagation_neighbors(fg, node)
    });
    fg.node_memory_regions = regions;
    for (&(func, value), &node) in &fg.values {
        if let Some(node_regions) = fg.node_memory_regions.get(&node.index()).cloned() {
            let mut merged = fg
                .value_memory_regions
                .remove(&(func, value))
                .unwrap_or_default();
            merged.extend(node_regions);
            merged.sort();
            merged.dedup();
            fg.value_memory_regions.insert((func, value), merged);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(node_regions) = fg.node_memory_regions.get(&cell.index()).cloned() {
            let mut merged = fg
                .cell_memory_regions
                .remove(&cell.index())
                .unwrap_or_default();
            merged.extend(node_regions);
            merged.sort();
            merged.dedup();
            fg.cell_memory_regions.insert(cell.index(), merged);
        }
    }
    fg.node_memory_regions != previous_node_memory_regions
        || fg.value_memory_regions != previous_value_memory_regions
        || fg.cell_memory_regions != previous_cell_memory_regions
}

fn region_find(parent: &mut [usize], node: usize) -> usize {
    let mut root = node;
    while parent[root] != root {
        root = parent[root];
    }
    let mut current = node;
    while parent[current] != current {
        let next = parent[current];
        parent[current] = root;
        current = next;
    }
    root
}

fn region_union_and_link(
    parent: &mut [usize],
    rank: &mut [u8],
    neighbors: &mut HashMap<usize, Vec<usize>>,
    left: usize,
    right: usize,
) {
    if left == right {
        return;
    }
    let mut left_root = region_find(parent, left);
    let mut right_root = region_find(parent, right);
    if left_root == right_root {
        return;
    }

    // `left` and `right` are always an actual logical region edge. Keeping
    // only edges that merge two components therefore builds a spanning forest
    // of the logical region graph instead of repeatedly materializing the same
    // connectivity through every shared label.
    neighbors.entry(left).or_default().push(right);
    neighbors.entry(right).or_default().push(left);

    if rank[left_root] < rank[right_root] {
        std::mem::swap(&mut left_root, &mut right_root);
    }
    parent[right_root] = left_root;
    if rank[left_root] == rank[right_root] {
        rank[left_root] = rank[left_root].saturating_add(1);
    }
}

fn materialize_region_graph_adjacency(fg: &mut FlowGraph) {
    fg.region_graph_successors.clear();
    fg.region_graph_predecessors.clear();
    fg.region_graph_direct_neighbors_cache.borrow_mut().clear();

    let node_count = fg.graph.node_count();
    let mut parent = (0..node_count).collect::<Vec<_>>();
    let mut rank = vec![0u8; node_count];
    let mut neighbors = HashMap::<usize, Vec<usize>>::new();
    let mut representatives = HashMap::<&str, usize>::new();

    // Equal regions are logical neighbors. Link only the first edge that
    // merges two connectivity components. This avoids building, sorting, and
    // deduplicating a region -> all-nodes index for every materialization.
    for node in fg.graph.node_indices() {
        if let Some(regions) = fg.node_memory_regions.get(&node.index()) {
            for region in regions {
                match representatives.entry(region.as_str()) {
                    std::collections::hash_map::Entry::Occupied(entry) => {
                        region_union_and_link(
                            &mut parent,
                            &mut rank,
                            &mut neighbors,
                            *entry.get(),
                            node.index(),
                        );
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(node.index());
                    }
                }
            }
        }
    }

    // The logical region graph is symmetric and is used by the build-time
    // solvers only for connected-component propagation. Expanding every
    // logical relation into every node pair creates dense cliques for common
    // regions and repeats the same links when nodes share several regions.
    // The union-find above/below retains only a deterministic spanning forest.
    // Every stored edge remains a real logical region edge, while exact one-hop
    // logical neighbors remain available lazily through the public queries.
    let mut regions = representatives.keys().copied().collect::<Vec<_>>();
    regions.sort_unstable();
    for region in regions {
        let Some(&representative) = representatives.get(region) else {
            continue;
        };

        // Proper boundary ancestors. `char_indices` keeps slicing valid for
        // non-ASCII region names while matching the exact `.` / `[` boundary
        // semantics used by `memory_region_related`.
        for (boundary, ch) in region.char_indices() {
            if ch != '.' && ch != '[' {
                continue;
            }
            let ancestor = &region[..boundary];
            let Some(&ancestor_representative) = representatives.get(ancestor) else {
                continue;
            };
            region_union_and_link(
                &mut parent,
                &mut rank,
                &mut neighbors,
                representative,
                ancestor_representative,
            );
        }
    }
    drop(representatives);
    for (node, mut adjacent) in neighbors {
        adjacent.sort_unstable();
        adjacent.dedup();
        adjacent.retain(|candidate| *candidate != node);
        if !adjacent.is_empty() {
            // Region relatedness is symmetric; both indexes have equal sets.
            fg.region_graph_predecessors.insert(node, adjacent.clone());
            fg.region_graph_successors.insert(node, adjacent);
        }
    }
}

fn materialize_memory_region_graph(fg: &mut FlowGraph) -> bool {
    let changed = materialize_memory_regions(fg);
    if changed {
        materialize_region_graph_adjacency(fg);
    }
    changed
}

fn materialize_cell_live_state_with_store_records(
    fg: &mut FlowGraph,
    records: &HashMap<usize, BTreeSet<DetailedStoreRecord>>,
) {
    fg.cell_live_values.clear();
    fg.cell_live_regions.clear();
    let mut strong = HashMap::new();
    for cell in all_cell_nodes(fg) {
        let live = visible_cell_store_records(
            fg,
            cell,
            None,
            records
                .get(&cell.index())
                .map(|r| r.iter().copied().collect())
                .unwrap_or_default(),
            &mut strong,
        );
        {
            let mut values = live
                .iter()
                .map(|(_edge_idx, func, value)| {
                    let value = canonical_heap_value(fg, *func, *value);
                    (func.0, value.0)
                })
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
            fg.cell_live_regions
                .insert(cell.index(), regions.into_iter().collect());
        }
    }
}

fn materialize_cell_live_state(fg: &mut FlowGraph) {
    let records = all_transitive_cell_store_records(fg);
    materialize_cell_live_state_with_store_records(fg, &records);
}

fn materialize_region_live_state(fg: &mut FlowGraph) {
    fg.region_live_values.clear();
    fg.region_live_cells.clear();

    let mut live = HashMap::<String, (Vec<usize>, Vec<(u32, u32)>)>::new();
    for cell in all_cell_nodes(fg) {
        let cell_index = cell.index();
        let cell_regions = fg
            .cell_live_regions
            .get(&cell_index)
            .filter(|regions| !regions.is_empty())
            .or_else(|| fg.cell_memory_regions.get(&cell_index));
        let Some(cell_regions) = cell_regions else {
            continue;
        };

        let direct_values;
        let cell_values: &[(u32, u32)] = match fg.cell_live_values.get(&cell_index) {
            Some(values) => values,
            None => {
                direct_values = direct_cell_store_values(fg, cell)
                    .into_iter()
                    .map(|(func, value)| (func.0, value.0))
                    .collect::<Vec<_>>();
                &direct_values
            }
        };
        let mut ancestors = Vec::new();
        for region in cell_regions {
            ancestors.extend(memory_region_ancestor_chain(region));
        }
        ancestors.sort_unstable();
        ancestors.dedup();
        for ancestor in ancestors {
            let (cells, values) = live.entry(ancestor.to_owned()).or_default();
            cells.push(cell_index);
            if !cell_values.is_empty() {
                values.extend_from_slice(cell_values);
            }
        }
    }

    let mut live_values = HashMap::with_capacity(live.len());
    let mut live_cells = HashMap::with_capacity(live.len());
    for (region, (cells, mut values)) in live {
        if !values.is_empty() {
            values.sort_unstable();
            values.dedup();
            live_values.insert(region.clone(), values);
        }
        live_cells.insert(region, cells);
    }
    fg.region_live_values = live_values;
    fg.region_live_cells = live_cells;
}

fn materialize_cell_write_generations_with_store_records(
    fg: &mut FlowGraph,
    transitive_records: &HashMap<usize, BTreeSet<DetailedStoreRecord>>,
) {
    fg.cell_write_generations.clear();
    let mut all_cells = fg.field_cells.values().copied().collect::<Vec<_>>();
    all_cells.extend(fg.index_cells.values().copied());
    all_cells.sort_unstable_by_key(|node| node.index());
    all_cells.dedup_by_key(|node| node.index());
    for cell in all_cells {
        let mut records = transitive_records
            .get(&cell.index())
            .into_iter()
            .flat_map(|records| records.iter().copied())
            .filter(|record| {
                fg.graph
                    .edge_weight(petgraph::graph::EdgeIndex::new(record.edge_idx))
                    .is_some_and(|edge| {
                        matches!(
                            &edge.kind,
                            EdgeKind::StoreField { .. } | EdgeKind::StoreIndex
                        )
                    })
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

fn materialize_cell_write_generations(fg: &mut FlowGraph) {
    let transitive_records = all_transitive_cell_store_records(fg);
    materialize_cell_write_generations_with_store_records(fg, &transitive_records);
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
            FlowNode::FieldCell {
                func, base, field, ..
            } => {
                if let Some(site) = value_identity_site(fg, *func, *base) {
                    classes.insert(format!("cell-site:{}:{}", site.trim(), field));
                }
                if let Some(ty) = fg.value_types.get(&(*func, *base)) {
                    classes.insert(format!(
                        "cell-field:{}:{}",
                        normalized_type_point_class(ty),
                        field
                    ));
                }
            }
            FlowNode::IndexCell {
                func,
                base,
                abstract_key,
                ..
            } => {
                if let Some(site) = value_identity_site(fg, *func, *base) {
                    classes.insert(format!("cell-site:{}:[{}]", site.trim(), abstract_key));
                }
                if let Some(ty) = fg.value_types.get(&(*func, *base)) {
                    classes.insert(format!(
                        "cell-index:{}:[{}]",
                        normalized_type_point_class(ty),
                        abstract_key
                    ));
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
            fg.cell_points_to_classes
                .insert(cell.index(), classes.into_iter().collect());
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
    let mut neighbors = identity_propagation_neighbors(fg, node);
    // Keep the points-to connectivity view aligned with the value-flow graph.
    // Identity edges are only one source of alias connectivity; sparse flow
    // edges are also part of the object-id fixpoint relation.
    if let Some(values) = fg.sparse_successors.get(&node.index()) {
        neighbors.extend(values.iter().copied().map(NodeIndex::new));
    }
    if let Some(values) = fg.sparse_predecessors.get(&node.index()) {
        neighbors.extend(values.iter().copied().map(NodeIndex::new));
    }
    neighbors.sort_by_key(|value| value.index());
    neighbors.dedup_by_key(|value| value.index());
    neighbors
}

/// Snapshot the symmetric points-to connectivity once for a contextual solver
/// refresh. Context partitions only restrict this graph to an allowed-node
/// subset; rebuilding and sorting the same neighbor lists for every call site
/// was a major multiplicative cost on project scans.
fn points_to_propagation_adjacency(fg: &FlowGraph) -> HashMap<usize, Vec<usize>> {
    let mut adjacency = HashMap::with_capacity(fg.graph.node_count());
    for node in fg.graph.node_indices() {
        adjacency.insert(
            node.index(),
            points_to_propagation_neighbors(fg, node)
                .into_iter()
                .map(|neighbor| neighbor.index())
                .collect(),
        );
    }
    adjacency
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
            let mut merged = fg
                .value_points_to_classes
                .remove(&(func, value))
                .unwrap_or_default();
            merged.extend(node_classes);
            merged.sort();
            merged.dedup();
            fg.value_points_to_classes.insert((func, value), merged);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(node_classes) = fg.node_points_to_classes.get(&cell.index()).cloned() {
            let mut merged = fg
                .cell_points_to_classes
                .remove(&cell.index())
                .unwrap_or_default();
            merged.extend(node_classes);
            merged.sort();
            merged.dedup();
            fg.cell_points_to_classes.insert(cell.index(), merged);
        }
    }
}

fn initial_node_points_to_targets(fg: &FlowGraph, node: NodeIndex) -> Vec<String> {
    let mut targets = Vec::new();
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            if let Some(site) = value_identity_site(fg, *func, *value) {
                targets.push(format!("obj:site:{}", site.trim()));
            }
            for region in value_root_memory_regions(fg, *func, *value) {
                targets.push(format!("obj:root:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.push(format!("obj:value:{}:{}", func.0, value.0));
            }
        }
        FlowNode::Return { func } => {
            for region in fg.node_memory_regions_of(node) {
                targets.push(format!("obj:return:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.push(format!("obj:return-func:{}", func.0));
            }
        }
        FlowNode::CallPort { port, .. } => {
            for (src_func, src_value) in fg.call_port_source_values(node) {
                for target in fg.value_points_to_targets_of(src_func, src_value) {
                    targets.push(target);
                }
                if let Some(site) = value_identity_site(fg, src_func, src_value) {
                    targets.push(format!("obj:site:{}", site.trim()));
                }
            }
            for region in fg.node_memory_regions_of(node) {
                targets.push(format!("obj:port:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.push(format!("obj:port:{:?}", port));
            }
        }
        FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
            if let Some(key) = cell_abstract_identity_key(fg, node) {
                targets.push(format!("cell:{}", key));
            }
            for region in fg.cell_memory_regions_of(node) {
                targets.push(format!("cell:region:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.push(format!("cell:node:{}", node.index()));
            }
        }
        FlowNode::SyntheticSource { rule_id, .. } => {
            targets.push(format!("obj:synthetic-source:{}", rule_id));
        }
        FlowNode::SyntheticSink { rule_id, .. } => {
            targets.push(format!("obj:synthetic-sink:{}", rule_id));
        }
    }
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn initial_node_points_to_target_seeds(fg: &FlowGraph) -> HashMap<usize, Vec<String>> {
    let mut seeds = HashMap::with_capacity(fg.graph.node_count());
    for node in fg.graph.node_indices() {
        let targets = initial_node_points_to_targets(fg, node);
        if !targets.is_empty() {
            seeds.insert(node.index(), targets);
        }
    }
    seeds
}

fn compute_points_to_targets_fixpoint_for_allowed_nodes(
    fg: &FlowGraph,
    allowed_nodes: Option<&HashSet<usize>>,
) -> HashMap<usize, Vec<String>> {
    let seeds = initial_node_points_to_target_seeds(fg);
    compute_points_to_targets_fixpoint_for_allowed_nodes_with_seeds(fg, allowed_nodes, &seeds)
}

fn compute_points_to_targets_fixpoint_for_allowed_nodes_with_seeds(
    fg: &FlowGraph,
    allowed_nodes: Option<&HashSet<usize>>,
    seeds: &HashMap<usize, Vec<String>>,
) -> HashMap<usize, Vec<String>> {
    let nodes = fg
        .graph
        .node_indices()
        .filter(|node| {
            allowed_nodes
                .map(|allowed| allowed.contains(&node.index()))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    let mut targets = HashMap::<usize, Vec<String>>::with_capacity(nodes.len());
    for node in &nodes {
        if let Some(seeded) = seeds.get(&node.index()) {
            targets.insert(node.index(), seeded.clone());
        }
    }
    let mut targets = propagate_symmetric_sorted_labels(&nodes, targets, |node| {
        let mut neighbors = points_to_propagation_neighbors(fg, node);
        if let Some(allowed) = allowed_nodes {
            neighbors.retain(|neighbor| allowed.contains(&neighbor.index()));
        }
        neighbors
    });
    for node in nodes {
        targets.entry(node.index()).or_default();
    }
    targets
}

/// Materialize target labels and abstract-object ids in the same connected
/// component walk. Both domains use the same identity-preserving points-to
/// connectivity. Keeping one walk also lets all contextual partitions share
/// one pre-sorted adjacency snapshot.
fn compute_points_to_partition_fixpoints_with_adjacency(
    fg: &FlowGraph,
    allowed_nodes: &HashSet<usize>,
    target_seeds: &HashMap<usize, Vec<String>>,
    adjacency: &HashMap<usize, Vec<usize>>,
) -> (HashMap<usize, Vec<String>>, HashMap<usize, Vec<u32>>) {
    let mut seen = HashSet::with_capacity(allowed_nodes.len());
    let mut targets = HashMap::with_capacity(allowed_nodes.len());
    let mut object_ids = HashMap::with_capacity(allowed_nodes.len());

    // Every contextual partition already supplies the exact induced node set.
    // Walking the whole graph here makes contextual materialization O(calls ×
    // graph-nodes) even when a call only visits a small slice of the graph.
    // Starting directly from the allowed set preserves the same induced
    // connectivity because expansion below still rejects neighbors outside
    // `allowed_nodes`.
    for &node_idx in allowed_nodes {
        if !seen.insert(node_idx) {
            continue;
        }

        let mut component = Vec::new();
        let mut pending = vec![node_idx];
        let mut component_targets = Vec::<String>::new();
        let mut component_object_ids = Vec::<u32>::new();
        while let Some(current) = pending.pop() {
            component.push(current);
            if let Some(values) = target_seeds.get(&current) {
                component_targets.extend(values.iter().cloned());
            }
            if let Some(ids) = fg.abstract_object_seed_nodes.get(&current) {
                component_object_ids.extend(ids.iter().copied());
            }
            if let Some(neighbors) = adjacency.get(&current) {
                for &next in neighbors {
                    if allowed_nodes.contains(&next) && seen.insert(next) {
                        pending.push(next);
                    }
                }
            }
        }

        component_targets.sort_unstable();
        component_targets.dedup();
        component_object_ids.sort_unstable();
        component_object_ids.dedup();
        for index in component {
            targets.insert(index, component_targets.clone());
            object_ids.insert(index, component_object_ids.clone());
        }
    }

    (targets, object_ids)
}

fn materialize_points_to_targets_fixpoint(fg: &mut FlowGraph) {
    fg.node_points_to_targets = compute_points_to_targets_fixpoint_for_allowed_nodes(fg, None);
    fg.value_points_to_targets.clear();
    fg.cell_points_to_targets.clear();
    for (&(func, value), &node) in &fg.values {
        if let Some(node_targets) = fg.node_points_to_targets.get(&node.index()).cloned() {
            let mut merged = fg
                .value_points_to_targets
                .remove(&(func, value))
                .unwrap_or_default();
            merged.extend(node_targets);
            merged.sort();
            merged.dedup();
            fg.value_points_to_targets.insert((func, value), merged);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(node_targets) = fg.node_points_to_targets.get(&cell.index()).cloned() {
            let mut merged = fg
                .cell_points_to_targets
                .remove(&cell.index())
                .unwrap_or_default();
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
        .filter(|node| {
            allowed_nodes
                .map(|allowed| allowed.contains(&node.index()))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    let mut object_ids = HashMap::<usize, Vec<u32>>::new();
    for node in &nodes {
        if let Some(ids) = fg.abstract_object_seed_nodes.get(&node.index()) {
            let mut seeded = ids.clone();
            seeded.sort_unstable();
            seeded.dedup();
            if !seeded.is_empty() {
                object_ids.insert(node.index(), seeded);
            }
        }
    }
    let mut object_ids = propagate_symmetric_sorted_labels(&nodes, object_ids, |node| {
        let mut neighbors = points_to_propagation_neighbors(fg, node);
        neighbors.extend(fg.object_successors_of(node));
        neighbors.extend(fg.object_predecessors_of(node));
        if let Some(allowed) = allowed_nodes {
            neighbors.retain(|neighbor| allowed.contains(&neighbor.index()));
        }
        neighbors
    });
    for node in nodes {
        object_ids.entry(node.index()).or_default();
    }
    object_ids
}

fn materialize_points_to_object_ids(fg: &mut FlowGraph) {
    materialize_abstract_object_catalog(fg);
    fg.node_points_to_object_ids.clear();
    fg.value_points_to_object_ids.clear();
    fg.cell_points_to_object_ids.clear();

    fg.node_points_to_object_ids =
        compute_points_to_object_ids_fixpoint_for_allowed_nodes(fg, None);
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

struct CellObjectIdIndex {
    by_object_id: HashMap<u32, Vec<NodeIndex>>,
    scan_catalog: Vec<(NodeIndex, Vec<u32>)>,
    seen_epochs: Vec<u32>,
    epoch: u32,
}

fn cell_candidates_by_object_id(fg: &FlowGraph) -> CellObjectIdIndex {
    let cells = all_cell_nodes(fg);
    let mut by_object_id = HashMap::<u32, Vec<NodeIndex>>::new();
    let mut scan_catalog = Vec::<(NodeIndex, Vec<u32>)>::with_capacity(cells.len());
    for &cell in &cells {
        let Some(object_ids) = fg.cell_points_to_object_ids.get(&cell.index()) else {
            continue;
        };
        if object_ids.is_empty() {
            continue;
        }
        let mut object_ids = object_ids.clone();
        object_ids.sort_unstable();
        object_ids.dedup();
        for object_id in &object_ids {
            by_object_id.entry(*object_id).or_default().push(cell);
        }
        scan_catalog.push((cell, object_ids));
    }
    for candidates in by_object_id.values_mut() {
        candidates.sort_unstable_by_key(|node| node.index());
        candidates.dedup_by_key(|node| node.index());
    }
    let seen_epochs = vec![
        0;
        cells
            .iter()
            .map(|node| node.index())
            .max()
            .map(|max| max + 1)
            .unwrap_or(0)
    ];
    CellObjectIdIndex {
        by_object_id,
        scan_catalog,
        seen_epochs,
        epoch: 0,
    }
}

fn sorted_object_ids_overlap(left: &[u32], right: &[u32]) -> bool {
    let mut left_index = 0usize;
    let mut right_index = 0usize;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn cell_object_id_query_prefers_scan(index: &CellObjectIdIndex, object_ids: &[u32]) -> bool {
    const ALWAYS_INDEXED_OBJECT_IDS: usize = 8;
    const PROBE_OBJECT_IDS: usize = 8;
    const SCAN_EXPANSION_FACTOR: usize = 2;

    if object_ids.len() <= ALWAYS_INDEXED_OBJECT_IDS || index.scan_catalog.is_empty() {
        return false;
    }

    let probe_len = object_ids.len().min(PROBE_OBJECT_IDS);
    let sampled_postings = object_ids[..probe_len]
        .iter()
        .map(|object_id| {
            index
                .by_object_id
                .get(object_id)
                .map_or(0usize, Vec::len)
        })
        .sum::<usize>();
    let estimated_postings = sampled_postings
        .saturating_mul(object_ids.len())
        .div_ceil(probe_len);

    object_ids.len() >= 32
        || estimated_postings
            >= index
                .scan_catalog
                .len()
                .saturating_mul(SCAN_EXPANSION_FACTOR)
}

fn cell_candidates_for_object_ids_indexed(
    index: &mut CellObjectIdIndex,
    object_ids: &[u32],
) -> Vec<NodeIndex> {
    if object_ids.is_empty() {
        return Vec::new();
    }
    if cell_object_id_query_prefers_scan(index, object_ids) {
        let mut sorted_object_ids = object_ids.to_vec();
        sorted_object_ids.sort_unstable();
        sorted_object_ids.dedup();
        return index
            .scan_catalog
            .iter()
            .filter_map(|(cell, candidate_ids)| {
                sorted_object_ids_overlap(&sorted_object_ids, candidate_ids).then_some(*cell)
            })
            .collect();
    }
    index.epoch = index.epoch.wrapping_add(1);
    if index.epoch == 0 {
        index.seen_epochs.fill(0);
        index.epoch = 1;
    }
    let epoch = index.epoch;
    let mut out = Vec::new();
    for object_id in object_ids {
        if let Some(candidates) = index.by_object_id.get(object_id) {
            for &candidate in candidates {
                let seen = &mut index.seen_epochs[candidate.index()];
                if *seen == epoch {
                    continue;
                }
                *seen = epoch;
                out.push(candidate);
            }
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out
}

fn cell_candidates_for_value_targets(
    fg: &FlowGraph,
    func: FunctionId,
    value: ValueId,
) -> Vec<NodeIndex> {
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

struct CellPointsToTargetIndex {
    by_target: HashMap<String, Vec<NodeIndex>>,
    seen_epochs: Vec<u32>,
    epoch: u32,
}

fn cell_candidates_by_points_to_target(fg: &FlowGraph) -> CellPointsToTargetIndex {
    let cells = all_cell_nodes(fg);
    let mut by_target = HashMap::<String, Vec<NodeIndex>>::new();
    for &cell in &cells {
        let Some(targets) = fg.cell_points_to_targets.get(&cell.index()) else {
            continue;
        };
        for target in targets {
            by_target.entry(target.clone()).or_default().push(cell);
        }
    }
    for candidates in by_target.values_mut() {
        candidates.sort_unstable_by_key(|node| node.index());
        candidates.dedup_by_key(|node| node.index());
    }
    let seen_epochs = vec![
        0;
        cells
            .iter()
            .map(|node| node.index())
            .max()
            .map(|max| max + 1)
            .unwrap_or(0)
    ];
    CellPointsToTargetIndex {
        by_target,
        seen_epochs,
        epoch: 0,
    }
}

fn cell_candidates_for_targets_indexed(
    index: &mut CellPointsToTargetIndex,
    targets: &[String],
) -> Vec<NodeIndex> {
    if targets.is_empty() {
        return Vec::new();
    }
    index.epoch = index.epoch.wrapping_add(1);
    if index.epoch == 0 {
        index.seen_epochs.fill(0);
        index.epoch = 1;
    }
    let epoch = index.epoch;
    let mut out = Vec::new();
    for target in targets {
        if let Some(candidates) = index.by_target.get(target) {
            for &candidate in candidates {
                let seen = &mut index.seen_epochs[candidate.index()];
                if *seen == epoch {
                    continue;
                }
                *seen = epoch;
                out.push(candidate);
            }
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out
}

fn cell_candidates_for_value_targets_indexed(
    fg: &FlowGraph,
    index: &mut CellPointsToTargetIndex,
    func: FunctionId,
    value: ValueId,
) -> Vec<NodeIndex> {
    let targets = fg.value_points_to_targets_of(func, value);
    cell_candidates_for_targets_indexed(index, &targets)
}

/// Merge two sorted vectors into one sorted, duplicate-free vector without
/// rebuilding a tree set. Both points-to fixpoints already materialize their
/// labels in sorted order, and contextual state is kept in the same canonical
/// form after every merge.
fn merge_sorted_unique_owned<T: Ord>(left: Vec<T>, right: Vec<T>) -> Vec<T> {
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    let mut merged = Vec::with_capacity(left.size_hint().0.saturating_add(right.size_hint().0));

    while left.peek().is_some() || right.peek().is_some() {
        let next = match (left.peek(), right.peek()) {
            (Some(left_value), Some(right_value)) => match left_value.cmp(right_value) {
                std::cmp::Ordering::Less => left.next(),
                std::cmp::Ordering::Greater => right.next(),
                std::cmp::Ordering::Equal => {
                    let value = left.next();
                    right.next();
                    value
                }
            },
            (Some(_), None) => left.next(),
            (None, Some(_)) => right.next(),
            (None, None) => None,
        };
        let Some(next) = next else {
            break;
        };
        if merged.last().map(|last| last != &next).unwrap_or(true) {
            merged.push(next);
        }
    }
    merged
}

fn materialize_contextual_solver_state(fg: &mut FlowGraph, program: &Program) -> bool {
    let catalog_changed = materialize_abstract_object_catalog(fg);
    // Initial target seeds depend on the aggregate points-to state, which is
    // immutable throughout one contextual rebuild. Build them once here and
    // reuse them for every context/sensitivity partition. The next solver
    // iteration recomputes this snapshot after aggregate state changes.
    let initial_target_seeds = initial_node_points_to_target_seeds(fg);
    let points_to_adjacency = points_to_propagation_adjacency(fg);
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
                // External model calls have no internal function summary. They
                // are covered by the fallback points-to partition below. Do
                // not traverse their entire source/sink graph once for every
                // sensitivity only to discard it when the callee is absent.
                if base_context.callee_funcs.is_empty() {
                    continue;
                }
                for sensitivity in all_context_sensitivities() {
                    let context =
                        fg.refine_call_context_for_sensitivity(base_context.clone(), *sensitivity);
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
                        .filter(|node_idx| {
                            fg.node_matches_structural_call_context(
                                NodeIndex::new(*node_idx),
                                &context,
                            )
                        })
                        .collect::<HashSet<_>>();
                    for (ret_func, ret_value) in &call_summary.return_values {
                        if let Some(&node) =
                            fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value)))
                        {
                            allowed_nodes.insert(node.index());
                        }
                    }
                    for (ret_func, ret_value) in &call_summary.return_live_values {
                        if let Some(&node) =
                            fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value)))
                        {
                            allowed_nodes.insert(node.index());
                        }
                    }
                    for cell in &call_summary.return_cells {
                        allowed_nodes.insert(*cell as usize);
                    }
                    for (_ret_func, _ret_value, cell) in &call_summary.return_value_cells {
                        allowed_nodes.insert(*cell as usize);
                    }
                    let (contextual_node_targets, contextual_node_object_ids) =
                        compute_points_to_partition_fixpoints_with_adjacency(
                            fg,
                            &allowed_nodes,
                            &initial_target_seeds,
                            &points_to_adjacency,
                        );
                    let mut targets = fg
                        .contextual_points_to_targets
                        .remove(&context)
                        .unwrap_or_default();
                    let mut object_ids = fg
                        .contextual_points_to_object_ids
                        .remove(&context)
                        .unwrap_or_default();
                    let mut return_values = fg
                        .contextual_return_values
                        .remove(&context)
                        .unwrap_or_default();
                    let mut return_cells = fg
                        .contextual_return_cells
                        .remove(&context)
                        .unwrap_or_default();
                    for (node_idx, node_targets) in contextual_node_targets {
                        let node = NodeIndex::new(node_idx);
                        let merged_targets_vec = merge_sorted_unique_owned(
                            fg
                            .contextual_node_points_to_targets
                            .remove(&(context.clone(), node_idx))
                            .unwrap_or_default(),
                            node_targets,
                        );
                        fg.contextual_node_points_to_targets
                            .insert((context.clone(), node_idx), merged_targets_vec.clone());
                        let ids = merge_sorted_unique_owned(
                            fg.contextual_node_points_to_object_ids
                                .remove(&(context.clone(), node_idx))
                                .unwrap_or_default(),
                            contextual_node_object_ids
                                .get(&node_idx)
                                .cloned()
                                .unwrap_or_default(),
                        );
                        if !ids.is_empty() {
                            fg.contextual_node_points_to_object_ids
                                .insert((context.clone(), node_idx), ids.clone());
                            object_ids = merge_sorted_unique_owned(object_ids, ids.clone());
                        }
                        targets =
                            merge_sorted_unique_owned(targets, merged_targets_vec.clone());
                        match &fg.graph[node] {
                            FlowNode::Value {
                                func: value_func,
                                value,
                            }
                            | FlowNode::Param {
                                func: value_func,
                                value,
                                ..
                            } => {
                                fg.contextual_value_points_to_targets.insert(
                                    (context.clone(), value_func.0, value.0),
                                    merged_targets_vec.clone(),
                                );
                                if !ids.is_empty() {
                                    fg.contextual_value_points_to_object_ids
                                        .insert((context.clone(), value_func.0, value.0), ids.clone());
                                }
                            }
                            FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                                fg.contextual_cell_points_to_targets.insert(
                                    (context.clone(), node_idx),
                                    merged_targets_vec.clone(),
                                );
                                if !ids.is_empty() {
                                    fg.contextual_cell_points_to_object_ids
                                        .insert((context.clone(), node_idx), ids.clone());
                                }
                            }
                            _ => {}
                        }
                    }
                    let mut new_return_values = call_summary.return_values.clone();
                    new_return_values.extend(call_summary.return_live_values.iter().copied());
                    new_return_values.sort_unstable();
                    new_return_values.dedup();
                    return_values =
                        merge_sorted_unique_owned(return_values, new_return_values);
                    let mut new_return_cells = call_summary
                        .return_cells
                        .iter()
                        .map(|cell| *cell as usize)
                        .chain(
                            call_summary
                                .return_value_cells
                                .iter()
                                .map(|(_, _, cell)| *cell as usize),
                        )
                        .collect::<Vec<_>>();
                    new_return_cells.sort_unstable();
                    new_return_cells.dedup();
                    return_cells = merge_sorted_unique_owned(return_cells, new_return_cells);
                    fg.contextual_return_values
                        .insert(context.clone(), return_values);
                    fg.contextual_return_cells
                        .insert(context.clone(), return_cells);
                    fg.contextual_points_to_targets
                        .insert(context.clone(), targets);
                    fg.contextual_points_to_object_ids
                        .insert(context.clone(), object_ids);
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
        fg.graph
            .node_indices()
            .map(|node| node.index())
            .collect::<HashSet<_>>()
    } else {
        fg.graph
            .node_indices()
            .map(|node| node.index())
            .filter(|node_idx| !covered_nodes.contains(node_idx))
            .collect::<HashSet<_>>()
    };
    if !fallback_nodes.is_empty() {
        let context = CallContextKey::default();
        let (contextual_node_targets, contextual_node_object_ids) =
            compute_points_to_partition_fixpoints_with_adjacency(
                fg,
                &fallback_nodes,
                &initial_target_seeds,
                &points_to_adjacency,
            );
        let mut targets = Vec::<String>::new();
        let mut object_ids = Vec::<u32>::new();
        for (node_idx, node_targets) in contextual_node_targets {
            let node = NodeIndex::new(node_idx);
            let merged_targets_vec = merge_sorted_unique_owned(
                fg.contextual_node_points_to_targets
                    .remove(&(context.clone(), node_idx))
                    .unwrap_or_default(),
                node_targets,
            );
            fg.contextual_node_points_to_targets
                .insert((context.clone(), node_idx), merged_targets_vec.clone());
            targets = merge_sorted_unique_owned(targets, merged_targets_vec.clone());
            let ids = merge_sorted_unique_owned(
                fg.contextual_node_points_to_object_ids
                    .remove(&(context.clone(), node_idx))
                    .unwrap_or_default(),
                contextual_node_object_ids
                    .get(&node_idx)
                    .cloned()
                    .unwrap_or_default(),
            );
            if !ids.is_empty() {
                fg.contextual_node_points_to_object_ids
                    .insert((context.clone(), node_idx), ids.clone());
                object_ids = merge_sorted_unique_owned(object_ids, ids.clone());
            }
            match &fg.graph[node] {
                FlowNode::Value {
                    func: value_func,
                    value,
                }
                | FlowNode::Param {
                    func: value_func,
                    value,
                    ..
                } => {
                    fg.contextual_value_points_to_targets.insert(
                        (context.clone(), value_func.0, value.0),
                        merged_targets_vec.clone(),
                    );
                    if !ids.is_empty() {
                        fg.contextual_value_points_to_object_ids
                            .insert((context.clone(), value_func.0, value.0), ids.clone());
                    }
                }
                FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                    fg.contextual_cell_points_to_targets
                        .insert((context.clone(), node_idx), merged_targets_vec.clone());
                    if !ids.is_empty() {
                        fg.contextual_cell_points_to_object_ids
                            .insert((context.clone(), node_idx), ids.clone());
                    }
                }
                _ => {}
            }
        }
        fg.contextual_points_to_targets
            .insert(context.clone(), targets);
        fg.contextual_points_to_object_ids
            .insert(context, object_ids);
    }

    catalog_changed
}

fn materialize_partitioned_points_to_state(fg: &mut FlowGraph, program: &Program) -> bool {
    // These tables are rebuilt from scratch below. Move the old values aside
    // instead of hashing/cloning the entire FlowGraph twice per fixed-point
    // refresh. Exact HashMap/HashSet equality still catches equal-size value
    // substitutions, which a size-only change detector would miss.
    let previous_contextual_return_values = std::mem::take(&mut fg.contextual_return_values);
    let previous_contextual_return_cells = std::mem::take(&mut fg.contextual_return_cells);
    let previous_contextual_points_to_targets =
        std::mem::take(&mut fg.contextual_points_to_targets);
    let previous_contextual_points_to_object_ids =
        std::mem::take(&mut fg.contextual_points_to_object_ids);
    let previous_contextual_node_points_to_targets =
        std::mem::take(&mut fg.contextual_node_points_to_targets);
    let previous_contextual_value_points_to_targets =
        std::mem::take(&mut fg.contextual_value_points_to_targets);
    let previous_contextual_cell_points_to_targets =
        std::mem::take(&mut fg.contextual_cell_points_to_targets);
    let previous_contextual_node_points_to_object_ids =
        std::mem::take(&mut fg.contextual_node_points_to_object_ids);
    let previous_contextual_value_points_to_object_ids =
        std::mem::take(&mut fg.contextual_value_points_to_object_ids);
    let previous_contextual_cell_points_to_object_ids =
        std::mem::take(&mut fg.contextual_cell_points_to_object_ids);

    let catalog_changed = materialize_contextual_solver_state(fg, program);

    // The contextual solver deliberately consumes the previous aggregate
    // points-to state while rebuilding contexts (for example call-port seeds),
    // so only move these aggregate tables after that phase has completed.
    let previous_node_points_to_targets = std::mem::take(&mut fg.node_points_to_targets);
    let previous_value_points_to_targets = std::mem::take(&mut fg.value_points_to_targets);
    let previous_cell_points_to_targets = std::mem::take(&mut fg.cell_points_to_targets);
    let previous_node_points_to_object_ids = std::mem::take(&mut fg.node_points_to_object_ids);
    let previous_value_points_to_object_ids =
        std::mem::take(&mut fg.value_points_to_object_ids);
    let previous_cell_points_to_object_ids =
        std::mem::take(&mut fg.cell_points_to_object_ids);

    aggregate_partitioned_points_to_state(fg);
    let changed = catalog_changed
        || fg.contextual_return_values != previous_contextual_return_values
        || fg.contextual_return_cells != previous_contextual_return_cells
        || fg.contextual_points_to_targets != previous_contextual_points_to_targets
        || fg.contextual_points_to_object_ids != previous_contextual_points_to_object_ids
        || fg.contextual_node_points_to_targets != previous_contextual_node_points_to_targets
        || fg.contextual_value_points_to_targets != previous_contextual_value_points_to_targets
        || fg.contextual_cell_points_to_targets != previous_contextual_cell_points_to_targets
        || fg.contextual_node_points_to_object_ids
            != previous_contextual_node_points_to_object_ids
        || fg.contextual_value_points_to_object_ids
            != previous_contextual_value_points_to_object_ids
        || fg.contextual_cell_points_to_object_ids
            != previous_contextual_cell_points_to_object_ids
        || fg.node_points_to_targets != previous_node_points_to_targets
        || fg.value_points_to_targets != previous_value_points_to_targets
        || fg.cell_points_to_targets != previous_cell_points_to_targets
        || fg.node_points_to_object_ids != previous_node_points_to_object_ids
        || fg.value_points_to_object_ids != previous_value_points_to_object_ids
        || fg.cell_points_to_object_ids != previous_cell_points_to_object_ids;
    if changed {
        fg.clear_sparse_caches();
    }
    changed
}

fn aggregate_partitioned_points_to_state(fg: &mut FlowGraph) {
    fg.node_points_to_targets.clear();
    fg.value_points_to_targets.clear();
    fg.cell_points_to_targets.clear();
    fg.node_points_to_object_ids.clear();
    fg.value_points_to_object_ids.clear();
    fg.cell_points_to_object_ids.clear();

    let mut covered_nodes = HashSet::<usize>::new();
    for ((_, node_idx), targets) in &fg.contextual_node_points_to_targets {
        covered_nodes.insert(*node_idx);
        fg.node_points_to_targets
            .entry(*node_idx)
            .or_default()
            .extend(targets.iter().cloned());
    }
    for targets in fg.node_points_to_targets.values_mut() {
        targets.sort();
        targets.dedup();
    }
    for ((_, node_idx), ids) in &fg.contextual_node_points_to_object_ids {
        covered_nodes.insert(*node_idx);
        fg.node_points_to_object_ids
            .entry(*node_idx)
            .or_default()
            .extend(ids.iter().copied());
    }
    for merged in fg.node_points_to_object_ids.values_mut() {
        merged.sort_unstable();
        merged.dedup();
    }

    let value_entries = fg
        .values
        .iter()
        .map(|(&(func, value), &node)| (func, value, node.index()))
        .collect::<Vec<_>>();
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

fn materialize_sparse_data_adjacency(fg: &mut FlowGraph) -> bool {
    // A missing map entry is an analyzed empty adjacency while this rebuild is
    // active.  Keeping one empty Vec in each direction for every graph node
    // made a 5M-node project allocate millions of hash entries before any
    // useful flow edge was examined.
    fg.sparse_adjacency_materialized = false;
    let previous_state = sparse_overlay_signature(fg);
    // Rebuilding these overlays while retaining their previous maps doubles
    // peak RSS on every post-points-to pass.  Keep a compact deterministic
    // fingerprint for convergence, then drop each old table before allocating
    // its replacement.
    fg.sparse_successors = HashMap::new();
    fg.sparse_predecessors = HashMap::new();
    fg.identity_neighbors = HashMap::new();
    fg.cell_live_values = HashMap::new();
    fg.cell_live_regions = HashMap::new();
    fg.heap_value_successors = HashMap::new();
    fg.heap_value_predecessors = HashMap::new();
    fg.heap_object_successors = HashMap::new();
    fg.heap_object_predecessors = HashMap::new();
    fg.object_graph_successors = HashMap::new();
    fg.object_graph_predecessors = HashMap::new();
    fg.object_graph_labels = HashMap::new();
    fg.object_shape_labels = HashMap::new();
    fg.object_shape_paths = HashMap::new();
    fg.cell_write_generations = HashMap::new();
    fg.region_live_values = HashMap::new();
    fg.region_live_cells = HashMap::new();
    // Alias state is immutable while the sparse edge set below is rebuilt.
    // Snapshot it once so store/load visibility, strong-update checks, and the
    // transitive store closure all share one O(cells^2) alias computation.
    let alias_snapshot = CellAliasSnapshot::build_for_sparse_flow(fg);
    let transitive_store_records =
        all_transitive_cell_store_records_with_alias_snapshot(fg, &alias_snapshot);
    let mut strong_update_cache = strong_update_cache_from_alias_snapshot(fg, &alias_snapshot);
    let mut loaded_identity_sites = Vec::<(FunctionId, ValueId, String)>::new();
    for edge in fg.graph.edge_references() {
        if !is_sparse_data_edge(&edge.weight().kind) {
            continue;
        }
        let src = edge.source().index();
        let dst = edge.target().index();
        match &edge.weight().kind {
            EdgeKind::StoreField { .. } | EdgeKind::StoreIndex
                if strong_update_cache
                    .get(&edge.target().index())
                    .copied()
                    .unwrap_or(false) =>
            {
                // The cell denotes its current contents. Earlier reads are
                // linked to their reaching store separately below.
                let visible = visible_cell_store_records(
                    fg,
                    edge.target(),
                    None,
                    transitive_store_records
                        .get(&edge.target().index())
                        .map(|records| records.iter().copied().collect())
                        .unwrap_or_default(),
                    &mut strong_update_cache,
                );
                if !visible.iter().any(|record| record.0 == edge.id().index()) {
                    continue;
                }
            }
            EdgeKind::LoadField { .. } | EdgeKind::LoadIndex
                if matches!(fg.graph[edge.source()], FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. })
                    && matches!(fg.graph[edge.target()], FlowNode::Value { .. }) =>
            {
                let visible = visible_cell_store_records(
                    fg,
                    edge.source(),
                    Some(edge.id().index()),
                    transitive_store_records
                        .get(&edge.source().index())
                        .map(|records| records.iter().copied().collect())
                        .unwrap_or_default(),
                    &mut strong_update_cache,
                );
                let mut sites = visible
                    .iter()
                    .filter_map(|(_, func, value)| value_identity_site(fg, *func, *value))
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                sites.sort_unstable();
                sites.dedup();
                if sites.len() == 1 {
                    if let FlowNode::Value { func, value } = fg.graph[edge.target()] {
                        loaded_identity_sites.push((func, value, sites.pop().expect("one site")));
                    }
                }

                if strong_update_cache
                    .get(&edge.source().index())
                    .copied()
                    .unwrap_or(false)
                    && !visible.is_empty()
                {
                    for (_, func, value) in visible {
                        if let Some(source) = fg.values.get(&(func, value)) {
                            fg.sparse_successors
                                .entry(source.index())
                                .or_default()
                                .push(dst);
                            fg.sparse_predecessors
                                .entry(dst)
                                .or_default()
                                .push(source.index());
                            push_identity_pair(&mut fg.identity_neighbors, source.index(), dst);
                        }
                    }
                    // The load result denotes the current contents of this
                    // cell even though sparse taint flow is rewired directly
                    // from the reaching store for strong updates.
                    push_identity_pair(&mut fg.identity_neighbors, edge.source().index(), dst);
                    continue;
                }
            }
            _ => {}
        }
        fg.sparse_successors.entry(src).or_default().push(dst);
        fg.sparse_predecessors.entry(dst).or_default().push(src);
        if is_identity_preserving_edge(fg, edge.source(), edge.target(), &edge.weight().kind) {
            push_identity_pair(&mut fg.identity_neighbors, src, dst);
        }
    }
    loaded_identity_sites.sort_unstable();
    loaded_identity_sites.dedup();
    let mut loaded_site_index = 0;
    while loaded_site_index < loaded_identity_sites.len() {
        let (func, value, _) = &loaded_identity_sites[loaded_site_index];
        let mut end = loaded_site_index + 1;
        while end < loaded_identity_sites.len()
            && loaded_identity_sites[end].0 == *func
            && loaded_identity_sites[end].1 == *value
        {
            end += 1;
        }
        if end == loaded_site_index + 1 {
            let (_, _, site) = &loaded_identity_sites[loaded_site_index];
            fg.object_identity_roots.insert((*func, *value), *value);
            fg.object_identity_sites
                .insert((*func, *value), site.clone());
        }
        loaded_site_index = end;
    }
    for values in fg.sparse_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.sparse_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.identity_neighbors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    // New bridge cells also need a cached empty result. Otherwise each heap
    // overlay rebuild repeats the same transitive store scan for empty cells.
    // The heap/object/shape overlays below do not mutate the graph, points-to
    // state, memory-region state, or cell alias connectivity. Reuse the same
    // transitive-store closure for live-state and write-generation materialization
    // instead of paying the O(cells^2) may-alias connectivity build twice.
    materialize_cell_live_state_with_store_records(fg, &transitive_store_records);
    materialize_heap_value_adjacency(fg);
    materialize_heap_object_adjacency(fg);
    materialize_object_graph_adjacency(fg);
    materialize_object_shape_paths(fg);
    materialize_object_shape_fixpoint(fg);
    materialize_cell_write_generations_with_store_records(fg, &transitive_store_records);
    let memory_region_changed = materialize_memory_region_graph(fg);
    // The first pass can create region-graph connectivity that becomes an
    // input to the second pass's symmetric propagation. Keep both passes;
    // `memory_region_graph_rebuilds_until_region_state_is_stable` covers it.
    if memory_region_changed {
        materialize_memory_region_graph(fg);
    }
    materialize_cell_live_state_with_store_records(fg, &transitive_store_records);
    materialize_region_live_state(fg);
    // The only input that can change the second object-graph build here is
    // the refreshed live-cell state. If its exact graph/label output is
    // unchanged, rebuilding shape paths and every memory-region seed is pure
    // duplicate work. A changed graph still follows the historical third
    // memory-region pass exactly.
    let object_graph_changed = materialize_object_graph_adjacency(fg);
    let mut memory_regions_changed_after_object_refresh = false;
    if object_graph_changed {
        materialize_object_shape_paths(fg);
        materialize_object_shape_fixpoint(fg);
        memory_regions_changed_after_object_refresh = materialize_memory_region_graph(fg);
    }
    if memory_regions_changed_after_object_refresh {
        materialize_region_live_state(fg);
    }

    // Most fixed-point refreshes are idempotent. Keep expensive demand and
    // function summary caches alive across an unchanged refresh, but invalidate
    // them as soon as either the sparse graph or any derived analysis state
    // actually advances.
    let state_changed = previous_state != sparse_overlay_signature(fg);
    if state_changed {
        fg.clear_sparse_caches();
    }
    fg.sparse_adjacency_materialized = true;
    state_changed
}

fn sparse_overlay_signature(fg: &FlowGraph) -> Vec<(usize, u64)> {
    macro_rules! table_signature {
        ($table:expr) => {
            ($table.len(), stable_hash_map_contents(&$table))
        };
    }
    vec![
        table_signature!(fg.sparse_successors),
        table_signature!(fg.sparse_predecessors),
        table_signature!(fg.identity_neighbors),
        table_signature!(fg.cell_live_values),
        table_signature!(fg.cell_live_regions),
        table_signature!(fg.heap_value_successors),
        table_signature!(fg.heap_value_predecessors),
        table_signature!(fg.heap_object_successors),
        table_signature!(fg.heap_object_predecessors),
        table_signature!(fg.object_graph_successors),
        table_signature!(fg.object_graph_predecessors),
        table_signature!(fg.object_graph_labels),
        table_signature!(fg.object_shape_labels),
        table_signature!(fg.object_shape_paths),
        table_signature!(fg.cell_write_generations),
        table_signature!(fg.region_live_values),
        table_signature!(fg.region_live_cells),
    ]
}

/// Builds only the direct sparse graph.  This is sufficient for a scan with
/// no modeled source/sink pair: no taint query can consume heap, object-shape,
/// or memory-region closure state.  Keeping those overlays lazy avoids
/// quadratic region tables merely to report an empty finding set.
fn materialize_sparse_data_adjacency_lightweight(fg: &mut FlowGraph) {
    fg.sparse_adjacency_materialized = false;
    fg.sparse_successors.clear();
    fg.sparse_predecessors.clear();
    fg.identity_neighbors.clear();
    for edge in fg.graph.edge_references() {
        if !is_sparse_data_edge(&edge.weight().kind) {
            continue;
        }
        let src = edge.source().index();
        let dst = edge.target().index();
        fg.sparse_successors.entry(src).or_default().push(dst);
        fg.sparse_predecessors.entry(dst).or_default().push(src);
        if is_identity_preserving_edge(fg, edge.source(), edge.target(), &edge.weight().kind) {
            push_identity_pair(&mut fg.identity_neighbors, src, dst);
        }
    }
    for values in fg.sparse_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.sparse_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.identity_neighbors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    fg.sparse_adjacency_materialized = true;
}

/// Materialize the bounded graph used by a project taint scan.
///
/// This deliberately keeps the direct IR data-flow edges (including field and
/// index reads/writes) but does not construct the whole-program alias, object
/// shape, or memory-region closures.  Those closures are useful for an
/// interactive/full checker query, but they are global analyses whose peak
/// memory is disproportionate to a source-to-sink scan of a large project.
/// The direct graph is conservative for a cell: every write remains visible to
/// every read, so it may produce an extra path but never removes a direct
/// taint path because of a strong-update decision.
fn materialize_sparse_taint_adjacency(fg: &mut FlowGraph) {
    // A FlowGraph can be reused by an embedding.  Do not retain a prior full
    // overlay when switching to the bounded scan plan: apart from making the
    // memory saving ineffective, query APIs would otherwise mix two plans.
    fg.cell_live_values.clear();
    fg.cell_live_regions.clear();
    fg.heap_value_successors.clear();
    fg.heap_value_predecessors.clear();
    fg.heap_object_successors.clear();
    fg.heap_object_predecessors.clear();
    fg.object_graph_successors.clear();
    fg.object_graph_predecessors.clear();
    fg.object_graph_labels.clear();
    fg.object_shape_labels.clear();
    fg.object_shape_paths.clear();
    fg.cell_write_generations.clear();
    fg.region_live_values.clear();
    fg.region_live_cells.clear();
    fg.region_graph_successors.clear();
    fg.region_graph_predecessors.clear();
    materialize_sparse_data_adjacency_lightweight(fg);
    fg.clear_sparse_caches();
}

fn add_unique_summary_edge(
    fg: &mut FlowGraph,
    src: NodeIndex,
    dst: NodeIndex,
    rule_id: &str,
) -> bool {
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

#[derive(Default)]
struct HeapEffectLookup<'a> {
    read_cells: HashMap<usize, Vec<NodeIndex>>,
    read_objects: HashMap<usize, Vec<u32>>,
    read_paths: HashMap<usize, Vec<&'a str>>,
    write_cells: HashMap<usize, Vec<NodeIndex>>,
    write_objects: HashMap<usize, Vec<u32>>,
    write_paths: HashMap<usize, Vec<&'a str>>,
    return_cells: HashMap<usize, Vec<NodeIndex>>,
    return_objects: HashMap<usize, Vec<u32>>,
    return_paths: HashMap<usize, Vec<&'a str>>,
    return_value_cells: HashMap<(u32, u32), Vec<NodeIndex>>,
    return_value_objects: HashMap<(u32, u32), Vec<u32>>,
    return_value_paths: HashMap<(u32, u32), Vec<&'a str>>,
}

impl<'a> HeapEffectLookup<'a> {
    fn new(summary: &'a FunctionHeapEffectSummary) -> Self {
        let mut lookup = Self::default();
        for &(index, cell) in &summary.param_to_read_cells {
            lookup
                .read_cells
                .entry(index)
                .or_default()
                .push(NodeIndex::new(cell as usize));
        }
        for &(index, object_id) in &summary.param_to_read_objects {
            lookup.read_objects.entry(index).or_default().push(object_id);
        }
        for (index, path) in &summary.param_to_read_paths {
            lookup.read_paths.entry(*index).or_default().push(path.as_str());
        }
        for &(index, cell) in &summary.param_to_write_cells {
            lookup
                .write_cells
                .entry(index)
                .or_default()
                .push(NodeIndex::new(cell as usize));
        }
        for &(index, object_id) in &summary.param_to_write_objects {
            lookup.write_objects.entry(index).or_default().push(object_id);
        }
        for (index, path) in &summary.param_to_write_paths {
            lookup.write_paths.entry(*index).or_default().push(path.as_str());
        }
        for &(index, cell) in &summary.param_to_return_cells {
            lookup
                .return_cells
                .entry(index)
                .or_default()
                .push(NodeIndex::new(cell as usize));
        }
        for &(index, object_id) in &summary.param_to_return_objects {
            lookup.return_objects.entry(index).or_default().push(object_id);
        }
        for (index, path) in &summary.param_to_return_paths {
            lookup.return_paths.entry(*index).or_default().push(path.as_str());
        }
        for &(func, value, cell) in &summary.return_value_cells {
            lookup
                .return_value_cells
                .entry((func, value))
                .or_default()
                .push(NodeIndex::new(cell as usize));
        }
        for &(func, value, object_id) in &summary.return_value_objects {
            lookup
                .return_value_objects
                .entry((func, value))
                .or_default()
                .push(object_id);
        }
        for (func, value, path) in &summary.return_value_paths {
            lookup
                .return_value_paths
                .entry((*func, *value))
                .or_default()
                .push(path.as_str());
        }
        lookup
    }
}

fn extend_cached_relative_path_cells<'a>(
    cache: &mut HashMap<(FunctionId, ValueId, &'a str), Vec<NodeIndex>>,
    candidates: &mut Vec<NodeIndex>,
    fg: &FlowGraph,
    func: FunctionId,
    value: ValueId,
    path: &'a str,
) {
    let key = (func, value, path);
    if let Some(cells) = cache.get(&key) {
        candidates.extend_from_slice(cells);
        return;
    }

    let segments = parse_access_path(path);
    let cells = existing_cells_for_parsed_relative_path_from_value(fg, func, value, &segments);
    candidates.extend_from_slice(&cells);
    cache.insert(key, cells);
}

fn common_heap_effect_candidates<'a>(
    fg: &FlowGraph,
    cell_object_id_index: &mut CellObjectIdIndex,
    relative_path_cells: &mut HashMap<(FunctionId, ValueId, &'a str), Vec<NodeIndex>>,
    func: FunctionId,
    value: ValueId,
    direct_cells: &[NodeIndex],
    object_ids: &[u32],
    paths: &[&'a str],
) -> Vec<NodeIndex> {
    let mut candidates = direct_cells.to_vec();
    candidates.extend(cell_candidates_for_object_ids_indexed(
        cell_object_id_index,
        object_ids,
    ));
    for &path in paths {
        extend_cached_relative_path_cells(
            relative_path_cells,
            &mut candidates,
            fg,
            func,
            value,
            path,
        );
    }
    candidates.sort_unstable_by_key(|node| node.index());
    candidates.dedup_by_key(|node| node.index());
    candidates
}

fn cached_region_candidate_cells<'a>(
    cache: &mut HashMap<&'a str, Vec<NodeIndex>>,
    fg: &FlowGraph,
    region: &'a str,
) -> Vec<NodeIndex> {
    if let Some(cells) = cache.get(region) {
        return cells.clone();
    }
    let cells = region_candidate_cells(fg, region);
    cache.insert(region, cells.clone());
    cells
}

fn cell_is_rooted_at_other_formal(
    fg: &FlowGraph,
    func: FunctionId,
    selected_index: usize,
    cell: NodeIndex,
    formal_indices_by_base: &HashMap<ValueId, Vec<usize>>,
) -> bool {
    let base = match fg.graph[cell] {
        FlowNode::FieldCell {
            func: owner, base, ..
        }
        | FlowNode::IndexCell {
            func: owner, base, ..
        } if owner == func => base,
        _ => return false,
    };
    formal_indices_by_base
        .get(&base)
        .is_some_and(|indices| indices.iter().any(|index| *index != selected_index))
}

fn connect_materialized_function_transfer_summaries(
    fg: &mut FlowGraph,
    program: &Program,
) -> usize {
    let mut pending_edges = Vec::<(NodeIndex, NodeIndex, String)>::new();
    for func in &program.functions {
        let Some(summary) =
            fg.function_transfer_summary(func.id, 16, 4096, DemandEngine::Fixpoint, true)
        else {
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
        // Do not materialize may-alias parameter relationships as direct value
        // transfer. Unknown reference parameters can share a heap object, but
        // that does not mean the value of parameter A flows into parameter B.
        // Heap mutations and returned projections are represented by their
        // dedicated summaries below; a direct edge here cross-taints unrelated
        // arguments and duplicates findings.
    }
    let mut added = 0usize;
    for (src, dst, rule_id) in pending_edges {
        if add_unique_summary_edge(fg, src, dst, &rule_id) {
            added += 1;
        }
    }
    added
}

fn connect_materialized_function_heap_effect_summaries(
    fg: &mut FlowGraph,
    program: &Program,
) -> usize {
    let mut pending_edges = Vec::<(NodeIndex, NodeIndex, String)>::new();
    let mut cell_object_id_index = cell_candidates_by_object_id(fg);
    let mut cell_points_to_target_index = cell_candidates_by_points_to_target(fg);
    let transitive_store_records = all_transitive_cell_store_records(fg);
    let mut strong_update_cache = HashMap::new();
    for func in &program.functions {
        let Some(summary) = fg.function_heap_effect_summary_with_store_snapshot(
            func.id,
            16,
            4096,
            DemandEngine::Fixpoint,
            true,
            &transitive_store_records,
            &mut strong_update_cache,
            &mut cell_points_to_target_index,
        )
        else {
            continue;
        };
        let lookup = HeapEffectLookup::new(&summary);
        let mut relative_path_cells = HashMap::new();
        let mut region_cells = HashMap::new();
        let mut read_common_candidates = HashMap::<usize, Vec<NodeIndex>>::new();
        let mut write_common_candidates = HashMap::<usize, Vec<NodeIndex>>::new();
        let mut return_common_candidates = HashMap::<usize, Vec<NodeIndex>>::new();
        let mut return_value_common_candidates = HashMap::<(u32, u32), Vec<NodeIndex>>::new();
        let mut formal_indices_by_base = HashMap::<ValueId, Vec<usize>>::new();
        for (index, value) in func.params.iter().copied().enumerate() {
            formal_indices_by_base.entry(value).or_default().push(index);
        }
        let Some(&ret_node) = fg.function_returns.get(&func.id) else {
            continue;
        };
        for (index, cell) in &summary.param_to_read_cells {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let cell = NodeIndex::new(*cell as usize);
                if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id)
                {
                    pending_edges.push((
                        param_node,
                        cell,
                        "internal:function-heap-read".to_string(),
                    ));
                }
            }
        }
        for (index, region) in &summary.param_to_read_regions {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let FlowNode::Param { value, .. } = &fg.graph[param_node] else {
                    continue;
                };
                let common = if let Some(candidates) = read_common_candidates.get(index) {
                    candidates.clone()
                } else {
                    let candidates = common_heap_effect_candidates(
                        fg,
                        &mut cell_object_id_index,
                        &mut relative_path_cells,
                        func.id,
                        *value,
                        lookup.read_cells.get(index).map(Vec::as_slice).unwrap_or(&[]),
                        lookup.read_objects.get(index).map(Vec::as_slice).unwrap_or(&[]),
                        lookup.read_paths.get(index).map(Vec::as_slice).unwrap_or(&[]),
                    );
                    read_common_candidates.insert(*index, candidates.clone());
                    candidates
                };
                let candidates = merge_sorted_unique_owned(
                    common,
                    cached_region_candidate_cells(&mut region_cells, fg, region),
                );
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id)
                    {
                        continue;
                    }
                    if cell_is_rooted_at_other_formal(
                        fg,
                        func.id,
                        *index,
                        cell,
                        &formal_indices_by_base,
                    ) {
                        continue;
                    }
                    pending_edges.push((
                        param_node,
                        cell,
                        "internal:function-heap-read".to_string(),
                    ));
                }
            }
        }
        for (index, cell) in &summary.param_to_write_cells {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let cell = NodeIndex::new(*cell as usize);
                if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id)
                {
                    pending_edges.push((
                        param_node,
                        cell,
                        "internal:function-heap-write".to_string(),
                    ));
                }
            }
        }
        for (index, region) in &summary.param_to_write_regions {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let FlowNode::Param { value, .. } = &fg.graph[param_node] else {
                    continue;
                };
                let common = if let Some(candidates) = write_common_candidates.get(index) {
                    candidates.clone()
                } else {
                    let candidates = common_heap_effect_candidates(
                        fg,
                        &mut cell_object_id_index,
                        &mut relative_path_cells,
                        func.id,
                        *value,
                        lookup.write_cells.get(index).map(Vec::as_slice).unwrap_or(&[]),
                        lookup.write_objects.get(index).map(Vec::as_slice).unwrap_or(&[]),
                        lookup.write_paths.get(index).map(Vec::as_slice).unwrap_or(&[]),
                    );
                    write_common_candidates.insert(*index, candidates.clone());
                    candidates
                };
                let candidates = merge_sorted_unique_owned(
                    common,
                    cached_region_candidate_cells(&mut region_cells, fg, region),
                );
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id)
                    {
                        continue;
                    }
                    if cell_is_rooted_at_other_formal(
                        fg,
                        func.id,
                        *index,
                        cell,
                        &formal_indices_by_base,
                    ) {
                        continue;
                    }
                    pending_edges.push((
                        param_node,
                        cell,
                        "internal:function-heap-write".to_string(),
                    ));
                }
            }
        }
        for (index, cell) in &summary.param_to_return_cells {
            if let Some(_param_node) = fg.function_params.get(&(func.id, *index)) {
                let cell = NodeIndex::new(*cell as usize);
                if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id)
                {
                    pending_edges.push((
                        cell,
                        ret_node,
                        "internal:function-heap-return".to_string(),
                    ));
                }
            }
        }
        for (index, region) in &summary.param_to_return_regions {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let FlowNode::Param { value, .. } = &fg.graph[param_node] else {
                    continue;
                };
                let common = if let Some(candidates) = return_common_candidates.get(index) {
                    candidates.clone()
                } else {
                    let candidates = common_heap_effect_candidates(
                        fg,
                        &mut cell_object_id_index,
                        &mut relative_path_cells,
                        func.id,
                        *value,
                        lookup.return_cells.get(index).map(Vec::as_slice).unwrap_or(&[]),
                        lookup.return_objects.get(index).map(Vec::as_slice).unwrap_or(&[]),
                        lookup.return_paths.get(index).map(Vec::as_slice).unwrap_or(&[]),
                    );
                    return_common_candidates.insert(*index, candidates.clone());
                    candidates
                };
                let candidates = merge_sorted_unique_owned(
                    common,
                    cached_region_candidate_cells(&mut region_cells, fg, region),
                );
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id)
                    {
                        continue;
                    }
                    pending_edges.push((
                        cell,
                        ret_node,
                        "internal:function-heap-return".to_string(),
                    ));
                }
            }
        }
        for (_index, live_func, live_value) in &summary.param_to_return_live_values {
            if let Some(&live_value_node) = fg
                .values
                .get(&(FunctionId(*live_func), ValueId(*live_value)))
            {
                pending_edges.push((
                    live_value_node,
                    ret_node,
                    "internal:function-live-return-value".to_string(),
                ));
            }
        }
        for (ret_func, ret_value, region) in &summary.return_value_regions {
            if let Some(&ret_value_node) =
                fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value)))
            {
                let key = (*ret_func, *ret_value);
                let common = if let Some(candidates) = return_value_common_candidates.get(&key) {
                    candidates.clone()
                } else {
                    let candidates = common_heap_effect_candidates(
                        fg,
                        &mut cell_object_id_index,
                        &mut relative_path_cells,
                        FunctionId(*ret_func),
                        ValueId(*ret_value),
                        lookup
                            .return_value_cells
                            .get(&key)
                            .map(Vec::as_slice)
                            .unwrap_or(&[]),
                        lookup
                            .return_value_objects
                            .get(&key)
                            .map(Vec::as_slice)
                            .unwrap_or(&[]),
                        lookup
                            .return_value_paths
                            .get(&key)
                            .map(Vec::as_slice)
                            .unwrap_or(&[]),
                    );
                    return_value_common_candidates.insert(key, candidates.clone());
                    candidates
                };
                let candidates = if common.is_empty() {
                    cached_region_candidate_cells(&mut region_cells, fg, region)
                } else {
                    common
                };
                let formal_index = (FunctionId(*ret_func) == func.id)
                    .then(|| {
                        func.params
                            .iter()
                            .position(|parameter| parameter.0 == *ret_value)
                    })
                    .flatten();
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id)
                    {
                        continue;
                    }
                    if formal_index.is_some_and(|index| {
                        cell_is_rooted_at_other_formal(
                            fg,
                            func.id,
                            index,
                            cell,
                            &formal_indices_by_base,
                        )
                    }) {
                        continue;
                    }
                    pending_edges.push((
                        ret_value_node,
                        cell,
                        "internal:function-return-value-region".to_string(),
                    ));
                }
            }
        }
        for cell in &summary.return_cells {
            let cell = NodeIndex::new(*cell as usize);
            if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id)
            {
                pending_edges.push((cell, ret_node, "internal:function-heap-return".to_string()));
            }
        }
        for (live_func, live_value) in &summary.return_live_values {
            if let Some(&live_value_node) = fg
                .values
                .get(&(FunctionId(*live_func), ValueId(*live_value)))
            {
                pending_edges.push((
                    live_value_node,
                    ret_node,
                    "internal:function-live-return-value".to_string(),
                ));
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
                let ret_port =
                    get_or_create_call_port(fg, func.id, inst.id, Port::Return, callee_name);
                let mut port_nodes = BTreeMap::<String, NodeIndex>::new();
                for ((call_func, call_inst, port), node) in &fg.call_ports {
                    if *call_func == func.id && *call_inst == inst.id {
                        port_nodes.insert(format!("{:?}", port), *node);
                    }
                }
                // Edges are committed after all summaries have been collected.
                // Resolve each (port, path) once in this immutable snapshot;
                // many region/object facts refer to the very same path.
                let mut path_cache = HashMap::<(NodeIndex, String), Vec<NodeIndex>>::new();
                let mut path_cells = |port: NodeIndex, path: &str| {
                    path_cache
                        .entry((port, path.to_string()))
                        .or_insert_with(|| relative_path_candidate_cells_for_port(fg, port, path))
                        .clone()
                };
                for port_name in &summary.port_to_return {
                    if let Some(src) = port_nodes.get(port_name) {
                        pending_edges.push((*src, ret_port, "internal:return".to_string()));
                    }
                }
                for (src_name, dst_name) in &summary.port_to_port {
                    if let (Some(src), Some(dst)) =
                        (port_nodes.get(src_name), port_nodes.get(dst_name))
                    {
                        pending_edges.push((*src, *dst, "internal:param".to_string()));
                    }
                }
                for (src_name, ret_func, ret_value) in &summary.port_to_return_values {
                    if let Some(src) = port_nodes.get(src_name) {
                        if let Some(&ret_value_node) =
                            fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value)))
                        {
                            pending_edges.push((
                                *src,
                                ret_value_node,
                                "internal:return-value-source".to_string(),
                            ));
                            pending_edges.push((
                                ret_value_node,
                                ret_port,
                                "internal:return-value".to_string(),
                            ));
                        }
                    }
                }
                for (src_name, live_func, live_value) in &summary.port_to_return_live_values {
                    if let Some(src) = port_nodes.get(src_name) {
                        if let Some(&live_value_node) = fg
                            .values
                            .get(&(FunctionId(*live_func), ValueId(*live_value)))
                        {
                            pending_edges.push((
                                *src,
                                live_value_node,
                                "internal:heap-live-return-source".to_string(),
                            ));
                            pending_edges.push((
                                live_value_node,
                                ret_port,
                                "internal:heap-live-return".to_string(),
                            ));
                        }
                    }
                }
                for (ret_func, ret_value) in &summary.return_values {
                    if let Some(&ret_value_node) =
                        fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value)))
                    {
                        pending_edges.push((
                            ret_value_node,
                            ret_port,
                            "internal:return-value".to_string(),
                        ));
                    }
                }
                for (live_func, live_value) in &summary.return_live_values {
                    if let Some(&live_value_node) = fg
                        .values
                        .get(&(FunctionId(*live_func), ValueId(*live_value)))
                    {
                        pending_edges.push((
                            live_value_node,
                            ret_port,
                            "internal:heap-live-return".to_string(),
                        ));
                    }
                }
                for cell in &summary.return_cells {
                    let cell_node = NodeIndex::new(*cell as usize);
                    pending_edges.push((cell_node, ret_port, "internal:heap-return".to_string()));
                }
                for (ret_func, ret_value, cell) in &summary.return_value_cells {
                    if let Some(&ret_value_node) =
                        fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value)))
                    {
                        pending_edges.push((
                            ret_value_node,
                            NodeIndex::new(*cell as usize),
                            "internal:return-value-region".to_string(),
                        ));
                    }
                }
                for (src_name, ret_func, ret_value, region) in &summary.port_to_return_value_regions
                {
                    if let Some(&ret_value_node) =
                        fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value)))
                    {
                        let mut candidates = summary
                            .return_value_cells
                            .iter()
                            .filter(|(path_func, path_value, _)| {
                                path_func == ret_func && path_value == ret_value
                            })
                            .map(|(_, _, cell)| NodeIndex::new(*cell as usize))
                            .collect::<Vec<_>>();
                        let object_ids = summary
                            .port_to_return_value_objects
                            .iter()
                            .filter(|(path_src, path_func, path_value, _)| {
                                path_src == src_name
                                    && path_func == ret_func
                                    && path_value == ret_value
                            })
                            .map(|(_, _, _, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                        candidates.extend(region_candidate_cells(fg, region));
                        if let Some(src) = port_nodes.get(src_name) {
                            for (path_src, path_func, path_value, path) in
                                &summary.port_to_return_value_paths
                            {
                                if path_src == src_name
                                    && path_func == ret_func
                                    && path_value == ret_value
                                {
                                    candidates.extend(path_cells(*src, path));
                                }
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((
                                ret_value_node,
                                cell,
                                "internal:return-value-region".to_string(),
                            ));
                        }
                    }
                }
                for (ret_func, ret_value, region) in &summary.return_value_regions {
                    if let Some(&ret_value_node) =
                        fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value)))
                    {
                        let object_ids = summary
                            .return_value_objects
                            .iter()
                            .filter(|(path_func, path_value, _)| {
                                path_func == ret_func && path_value == ret_value
                            })
                            .map(|(_, _, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        let mut candidates = cell_candidates_for_object_ids(fg, &object_ids);
                        candidates.extend(region_candidate_cells(fg, region));
                        for (path_func, path_value, path) in &summary.return_value_paths {
                            if path_func == ret_func && path_value == ret_value {
                                candidates.extend(existing_cells_for_relative_path_from_value(
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
                            pending_edges.push((
                                ret_value_node,
                                cell,
                                "internal:return-region-value".to_string(),
                            ));
                        }
                    }
                }
                for (src_name, cell) in &summary.port_to_read_cells {
                    if let Some(src) = port_nodes.get(src_name) {
                        pending_edges.push((
                            *src,
                            NodeIndex::new(*cell as usize),
                            "internal:heap-read".to_string(),
                        ));
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
                                candidates.extend(path_cells(*src, path));
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
                        pending_edges.push((
                            *src,
                            NodeIndex::new(*cell as usize),
                            "internal:heap-write".to_string(),
                        ));
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
                                candidates.extend(path_cells(*src, path));
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
                                candidates.extend(path_cells(*src, path));
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((
                                *src,
                                cell,
                                "internal:heap-return-source".to_string(),
                            ));
                            pending_edges.push((
                                cell,
                                ret_port,
                                "internal:heap-return".to_string(),
                            ));
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
    graph_nodes
        .saturating_add(graph_edges)
        .saturating_mul(4)
        .max(64)
}

fn materialize_unified_analysis_state(fg: &mut FlowGraph) -> bool {
    let mut iterations = 0usize;
    let mut any_changed = false;
    loop {
        iterations += 1;
        // The sparse refresh already rebuilds shape, region, live-cell and
        // object indexes. Repeating each rebuild here adds no transfer rule.
        let changed = materialize_sparse_data_adjacency(fg);
        any_changed |= changed;
        if !changed {
            break;
        }
        assert!(
            iterations <= solver_iteration_cap(fg),
            "unified analysis failed to converge"
        );
    }
    any_changed
}

fn materialize_interprocedural_solver_closure(fg: &mut FlowGraph, program: &Program) {
    materialize_unified_analysis_state(fg);
    materialize_partitioned_points_to_state(fg, program);
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        let added_function_edges = connect_materialized_function_transfer_summaries(fg, program);
        let added_heap_edges = connect_materialized_function_heap_effect_summaries(fg, program);
        let added_call_edges = connect_materialized_interprocedural_summaries(fg, program);
        let unified_changed = materialize_unified_analysis_state(fg);
        let partitioned_changed = materialize_partitioned_points_to_state(fg, program);
        if added_function_edges == 0
            && added_heap_edges == 0
            && added_call_edges == 0
            && !unified_changed
            && !partitioned_changed
        {
            break;
        }
        assert!(
            iterations <= solver_iteration_cap(fg),
            "interprocedural solver failed to converge"
        );
    }
    fg.solver_closure_iterations = iterations;
}

fn materialize_global_solver_closure(fg: &mut FlowGraph, program: &Program) {
    // This closure already iterates unified state, contextual partitions and
    // every transfer/heap/call summary until both edges and state stabilize.
    // Wrapping the same closure in another fixed-point loop only recomputes
    // the identical state and repeatedly discards valid query caches.
    materialize_interprocedural_solver_closure(fg, program);
    fg.global_solver_iterations = fg.solver_closure_iterations;
}
