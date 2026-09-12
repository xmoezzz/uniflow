fn ensure_alias_parent(parent: &mut HashMap<ValueId, ValueId>, value: ValueId) {
    parent.entry(value).or_insert(value);
}

fn find_alias_parent(parent: &mut HashMap<ValueId, ValueId>, value: ValueId) -> ValueId {
    let parent_value = *parent.entry(value).or_insert(value);
    if parent_value == value {
        value
    } else {
        let root = find_alias_parent(parent, parent_value);
        parent.insert(value, root);
        root
    }
}

fn union_alias_parent(parent: &mut HashMap<ValueId, ValueId>, left: ValueId, right: ValueId) {
    let left_root = find_alias_parent(parent, left);
    let right_root = find_alias_parent(parent, right);
    if left_root == right_root {
        return;
    }
    let keep = if left_root.0 <= right_root.0 { left_root } else { right_root };
    let merge = if keep == left_root { right_root } else { left_root };
    parent.insert(merge, keep);
}

fn finalize_alias_parent(parent: &mut HashMap<ValueId, ValueId>) -> HashMap<ValueId, ValueId> {
    let keys = parent.keys().copied().collect::<Vec<_>>();
    let mut out = HashMap::new();
    for value in keys {
        let root = find_alias_parent(parent, value);
        out.insert(value, root);
    }
    out
}

fn compute_value_alias_representatives(func: &Function) -> HashMap<ValueId, ValueId> {
    let mut parent = HashMap::new();
    for value in func.params.iter().chain(func.locals.iter()) {
        ensure_alias_parent(&mut parent, *value);
    }
    for block in &func.blocks {
        for inst in &block.insts {
            match &inst.kind {
                InstKind::Copy { dst, src }
                | InstKind::Cast {
                    dst,
                    src,
                    kind: uniflow_ir::CppCastKind::Static | uniflow_ir::CppCastKind::Dynamic | uniflow_ir::CppCastKind::Const,
                    ..
                } => {
                    ensure_alias_parent(&mut parent, *dst);
                    ensure_alias_parent(&mut parent, *src);
                    union_alias_parent(&mut parent, *dst, *src);
                }
                InstKind::Cast { dst, src, kind: uniflow_ir::CppCastKind::Reinterpret, .. } => {
                    // Reinterpret casts may alias but do not establish value equivalence.
                    ensure_alias_parent(&mut parent, *dst);
                    ensure_alias_parent(&mut parent, *src);
                }
                InstKind::Phi { dst, inputs } => {
                    ensure_alias_parent(&mut parent, *dst);
                    for input in inputs {
                        ensure_alias_parent(&mut parent, *input);
                        union_alias_parent(&mut parent, *dst, *input);
                    }
                }
                _ => {}
            }
        }
    }
    finalize_alias_parent(&mut parent)
}

fn compute_heap_alias_representatives(func: &Function) -> HashMap<ValueId, ValueId> {
    let mut parent = HashMap::new();
    for value in func.params.iter().chain(func.locals.iter()) {
        ensure_alias_parent(&mut parent, *value);
    }
    for block in &func.blocks {
        for inst in &block.insts {
            match &inst.kind {
                InstKind::Copy { dst, src } | InstKind::Move { dst, src } | InstKind::Cast { dst, src, .. } => {
                    ensure_alias_parent(&mut parent, *dst);
                    ensure_alias_parent(&mut parent, *src);
                    union_alias_parent(&mut parent, *dst, *src);
                }
                InstKind::Phi { dst, inputs } => {
                    ensure_alias_parent(&mut parent, *dst);
                    let mut roots = Vec::new();
                    for input in inputs {
                        ensure_alias_parent(&mut parent, *input);
                        roots.push(find_alias_parent(&mut parent, *input));
                    }
                    roots.sort_unstable();
                    roots.dedup();
                    if roots.len() == 1 {
                        union_alias_parent(&mut parent, *dst, roots[0]);
                    }
                }
                _ => {}
            }
        }
    }
    finalize_alias_parent(&mut parent)
}

fn canonical_value(alias_roots: &HashMap<ValueId, ValueId>, value: ValueId) -> ValueId {
    alias_roots.get(&value).copied().unwrap_or(value)
}

fn is_object_like_type(ty: &str) -> bool {
    let trimmed = ty.trim();
    if trimmed.is_empty() {
        return false;
    }
    if matches!(trimmed, "unknown" | "int" | "float" | "bool" | "str" | "bytes" | "None" | "none") {
        return false;
    }
    trimmed.contains('.')
        || trimmed.starts_with("list<")
        || trimmed.starts_with("dict<")
        || trimmed.starts_with("set<")
        || trimmed.starts_with("tuple<")
        || trimmed.starts_with("generator<")
        || trimmed.starts_with("typing.")
        || trimmed.chars().next().is_some_and(|ch| ch.is_ascii_uppercase())
}

fn looks_like_constructor_name(name: &str) -> bool {
    name.split('.').next_back().is_some_and(|tail| tail.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()))
}

fn compute_object_identity_representatives(func: &Function) -> (HashMap<ValueId, ValueId>, HashMap<ValueId, String>) {
    let mut roots = HashMap::new();
    let mut sites = HashMap::new();

    for (index, param) in func.params.iter().copied().enumerate() {
        if func
            .value_types
            .get(&param)
            .is_some_and(|ty| is_object_like_type(ty))
        {
            roots.insert(param, param);
            sites.insert(param, format!("f{}:param#{index}", func.id.0));
        }
    }

    for block in &func.blocks {
        for inst in &block.insts {
            let seeded = match &inst.kind {
                InstKind::Call(call) => call.dst.filter(|dst| {
                    func.value_types
                        .get(dst)
                        .is_some_and(|ty| is_object_like_type(ty))
                        || static_callee_name(call)
                            .as_deref()
                            .is_some_and(looks_like_constructor_name)
                }),
                // A heap load is not an allocation site. Its identity comes
                // from the reaching stored object(s), which are resolved once
                // cell alias/strong-update facts are available in the solver.
                InstKind::LoadField { .. } | InstKind::LoadIndex { .. } => None,
                _ => None,
            };
            if let Some(dst) = seeded {
                roots.entry(dst).or_insert(dst);
                sites.entry(dst).or_insert_with(|| format!("f{}:inst@{}", func.id.0, inst.id.0));
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block in &func.blocks {
            for inst in &block.insts {
                match &inst.kind {
                    InstKind::Copy { dst, src } | InstKind::Move { dst, src } | InstKind::Cast { dst, src, .. } => {
                        if let Some(root) = roots.get(src).copied() {
                            if roots.get(dst) != Some(&root) {
                                roots.insert(*dst, root);
                                changed = true;
                            }
                        }
                    }
                    InstKind::Phi { dst, inputs } => {
                        let mut candidates = inputs
                            .iter()
                            .filter_map(|input| roots.get(input).copied())
                            .collect::<Vec<_>>();
                        candidates.sort_unstable();
                        candidates.dedup();
                        if candidates.len() == 1 && roots.get(dst) != candidates.first() {
                            roots.insert(*dst, candidates[0]);
                            changed = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    (roots, sites)
}

fn canonical_heap_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> ValueId {
    fg.object_identity_roots
        .get(&(func, value))
        .copied()
        .or_else(|| fg.heap_alias_roots.get(&(func, value)).copied())
        .unwrap_or(value)
}

fn value_identity_site<'a>(fg: &'a FlowGraph, func: FunctionId, value: ValueId) -> Option<&'a str> {
    let root = fg.object_identity_roots.get(&(func, value)).copied().unwrap_or(value);
    fg.object_identity_sites.get(&(func, root)).map(|s| s.as_str())
}

fn identity_sites_definitely_distinct(left: Option<&str>, right: Option<&str>) -> bool {
    match (left.map(str::trim), right.map(str::trim)) {
        (Some(left), Some(right)) if left != right => left.contains(":inst@") && right.contains(":inst@"),
        _ => false,
    }
}

fn propagate_object_identity_site(
    fg: &mut FlowGraph,
    src_func: FunctionId,
    src_value: ValueId,
    dst_func: FunctionId,
    dst_value: ValueId,
) {
    let Some(site) = value_identity_site(fg, src_func, src_value).map(|s| s.to_string()) else {
        return;
    };
    fg.object_identity_roots.insert((dst_func, dst_value), dst_value);
    fg.object_identity_sites.insert((dst_func, dst_value), site);
}

fn returned_direct_identity_sites(fg: &FlowGraph, func: &Function) -> Vec<String> {
    let mut out = Vec::new();
    for block in &func.blocks {
        let Terminator::Return(Some(value)) = &block.term else {
            continue;
        };
        if let Some(site) = value_identity_site(fg, func.id, *value) {
            if !out.iter().any(|existing| existing == site) {
                out.push(site.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn object_types_compatible(left: Option<&str>, right: Option<&str>) -> bool {
    match (left.map(str::trim), right.map(str::trim)) {
        (Some(left), Some(right)) => {
            left == right
                || left.split('.').next_back() == right.split('.').next_back()
                || (left.starts_with("list<") && right.starts_with("list<"))
                || (left.starts_with("dict<") && right.starts_with("dict<"))
                || (left.starts_with("set<") && right.starts_with("set<"))
                || (left.starts_with("tuple<") && right.starts_with("tuple<"))
        }
        _ => true,
    }
}

fn normalized_type_point_class(ty: &str) -> String {
    let trimmed = ty.trim();
    let simple = trimmed.split('.').next_back().unwrap_or(trimmed);
    if let Some(base) = simple.split('<').next() {
        format!("type:{}", base)
    } else {
        format!("type:{}", simple)
    }
}

fn normalized_shape_point_class(shape: &str) -> String {
    let trimmed = shape.trim();
    let compact = trimmed
        .replace("field:", "f:")
        .replace("index:", "i:");
    format!("shape:{}", compact)
}

fn inferred_shape_point_classes_for_node(fg: &FlowGraph, node: NodeIndex) -> Vec<String> {
    let mut classes = BTreeSet::new();
    let mut shapes = fg.object_shape_paths_of(node);
    if shapes.is_empty() {
        shapes = fg.object_shape_labels_of(node);
    }
    shapes.sort();
    shapes.dedup();
    for shape in shapes.into_iter() {
        if !shape.trim().is_empty() {
            classes.insert(normalized_shape_point_class(&shape));
        }
    }
    classes.into_iter().collect()
}

fn normalized_memory_region(path: &str) -> String {
    let trimmed = path.trim();
    let mut compact = String::with_capacity(trimmed.len().saturating_add(4));
    compact.push_str("mem:");
    let mut cursor = 0usize;
    while cursor < trimmed.len() {
        let tail = &trimmed[cursor..];
        let field = tail.find("field:");
        let index = tail.find("index:");
        let (offset, pattern_len, replacement) = match (field, index) {
            (Some(field), Some(index)) if field <= index => (field, "field:".len(), '.'),
            (Some(_), Some(index)) => (index, "index:".len(), '['),
            (Some(field), None) => (field, "field:".len(), '.'),
            (None, Some(index)) => (index, "index:".len(), '['),
            (None, None) => {
                compact.push_str(tail);
                break;
            }
        };
        compact.push_str(&tail[..offset]);
        compact.push(replacement);
        cursor += offset + pattern_len;
    }
    compact
}

fn memory_region_seed_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    let mut regions = BTreeSet::new();
    if let Some(site) = value_identity_site(fg, func, value) {
        regions.insert(format!("mem:site:{}", site.trim()));
    }
    if let Some(ty) = fg.value_types.get(&(func, value)) {
        let trimmed = ty.trim();
        if !trimmed.is_empty() {
            regions.insert(format!("mem:{}", normalized_type_point_class(trimmed).replace("type:", "type:")));
        }
    }
    if let Some(&node) = fg.values.get(&(func, value)) {
        for shape in fg.object_shape_paths_of(node) {
            if !shape.trim().is_empty() {
                regions.insert(normalized_memory_region(&shape));
            }
        }
        for shape in fg.object_shape_labels_of(node) {
            if !shape.trim().is_empty() {
                regions.insert(normalized_memory_region(&shape));
            }
        }
    }
    if regions.is_empty() {
        regions.insert(format!("mem:value:{}:{}", func.0, value.0));
    }
    regions.into_iter().collect()
}

fn memory_regions_overlap(left: &[String], right: &[String]) -> bool {
    sets_overlap(left, right)
}

fn sets_overlap<T: Eq + Hash>(left: &[T], right: &[T]) -> bool {
    let (Some(first_left), Some(first_right)) = (left.first(), right.first()) else { return false; };
    // Propagated component sets frequently share their first element. Avoid
    // allocating a hash table for this overwhelmingly common positive case.
    if first_left == first_right { return true; }
    if left.len().saturating_mul(right.len()) <= 64 {
        return left.iter().any(|value| right.contains(value));
    }
    let (small, large) = if left.len() <= right.len() { (left, right) } else { (right, left) };
    let members = small.iter().collect::<HashSet<_>>();
    large.iter().any(|value| members.contains(value))
}

fn memory_region_has_boundary_prefix(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    child
        .strip_prefix(parent)
        .map(|suffix| suffix.starts_with('.') || suffix.starts_with('['))
        .unwrap_or(false)
}

fn memory_region_related(left: &str, right: &str) -> bool {
    memory_region_has_boundary_prefix(left, right) || memory_region_has_boundary_prefix(right, left)
}

fn memory_region_ancestor_chain(region: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut current = region.trim();
    while !current.is_empty() {
        out.push(current);
        if let Some(idx) = current.rfind('[') {
            current = &current[..idx];
            continue;
        }
        if let Some(idx) = current.rfind('.') {
            current = &current[..idx];
            continue;
        }
        break;
    }
    out
}

fn stable_hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn stable_hash_map_contents<K, V>(map: &HashMap<K, V>) -> u64
where
    K: Ord + Hash,
    V: Hash,
{
    let mut entries = map
        .iter()
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    stable_hash_value(&entries)
}

fn stable_hash_set_contents<T>(set: &HashSet<T>) -> u64
where
    T: Ord + Clone + Hash,
{
    let mut values = set.iter().cloned().collect::<Vec<_>>();
    values.sort();
    stable_hash_value(&values)
}

fn analysis_state_signature(fg: &FlowGraph) -> Vec<u64> {
    vec![
        fg.graph.edge_count() as u64,
        fg.object_shape_paths.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.node_memory_regions.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.value_memory_regions.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.cell_memory_regions.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.region_graph_successors.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.node_points_to_classes.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.node_points_to_targets.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.cell_live_values.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.cell_live_regions.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.region_live_values.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.region_live_cells.values().map(|values| values.len()).sum::<usize>() as u64,
        (fg.contextual_points_to_targets.values().map(|values| values.len()).sum::<usize>()
            + fg.contextual_points_to_object_ids.values().map(|values| values.len()).sum::<usize>()
            + fg.abstract_objects.len()
            + fg.object_seed_ids.len()) as u64,
        fg.strong_update_cells.len() as u64,
        fg.cell_write_generations.values().map(|values| values.len()).sum::<usize>() as u64,
        stable_hash_map_contents(&fg.object_shape_paths),
        stable_hash_map_contents(&fg.node_memory_regions),
        stable_hash_map_contents(&fg.value_memory_regions),
        stable_hash_map_contents(&fg.cell_memory_regions),
        stable_hash_map_contents(&fg.node_points_to_classes),
        stable_hash_map_contents(&fg.value_points_to_classes),
        stable_hash_map_contents(&fg.cell_points_to_classes),
        stable_hash_map_contents(&fg.node_points_to_targets),
        stable_hash_map_contents(&fg.value_points_to_targets),
        stable_hash_map_contents(&fg.cell_points_to_targets),
        stable_hash_map_contents(&fg.points_to_object_ids),
        stable_hash_map_contents(&fg.node_points_to_object_ids),
        stable_hash_map_contents(&fg.value_points_to_object_ids),
        stable_hash_map_contents(&fg.cell_points_to_object_ids),
        stable_hash_map_contents(&fg.contextual_node_points_to_targets),
        stable_hash_map_contents(&fg.contextual_value_points_to_targets),
        stable_hash_map_contents(&fg.contextual_cell_points_to_targets),
        stable_hash_map_contents(&fg.contextual_node_points_to_object_ids),
        stable_hash_map_contents(&fg.contextual_value_points_to_object_ids),
        stable_hash_map_contents(&fg.contextual_cell_points_to_object_ids),
        stable_hash_map_contents(&fg.contextual_points_to_targets),
        stable_hash_map_contents(&fg.contextual_points_to_object_ids),
        stable_hash_map_contents(&fg.contextual_return_values),
        stable_hash_map_contents(&fg.contextual_return_cells),
        stable_hash_map_contents(&fg.abstract_objects) ^ stable_hash_map_contents(&fg.object_seed_ids),
        stable_hash_set_contents(&fg.strong_update_cells),
        stable_hash_map_contents(&fg.cell_write_generations),
        stable_hash_map_contents(&fg.cell_live_values),
        stable_hash_map_contents(&fg.cell_live_regions),
        stable_hash_map_contents(&fg.region_live_values),
        stable_hash_map_contents(&fg.region_live_cells),
        stable_hash_map_contents(&fg.region_graph_successors),
    ]
}

fn inferred_points_to_classes_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    let mut classes = BTreeSet::new();
    if let Some(site) = value_identity_site(fg, func, value) {
        classes.insert(format!("site:{}", site.trim()));
    }
    if let Some(ty) = fg.value_types.get(&(func, value)) {
        let trimmed = ty.trim();
        if !trimmed.is_empty() {
            classes.insert(normalized_type_point_class(trimmed));
        }
    }
    if let Some(&node) = fg.values.get(&(func, value)) {
        for class in inferred_shape_point_classes_for_node(fg, node) {
            classes.insert(class);
        }
    }
    for region in memory_region_seed_for_value(fg, func, value) {
        classes.insert(region.replace("mem:", "region:"));
    }
    classes.into_iter().collect()
}

fn points_to_classes_overlap(left: &[String], right: &[String]) -> bool {
    sets_overlap(left, right)
}

fn points_to_targets_overlap(left: &[String], right: &[String]) -> bool {
    sets_overlap(left, right)
}

fn is_precise_points_to_target(target: &str) -> bool {
    target.starts_with("obj:site:") || target.starts_with("cell:field:") || target.starts_with("cell:index:")
}

fn points_to_object_ids_overlap(left: &[u32], right: &[u32]) -> bool {
    sets_overlap(left, right)
}

fn object_id_sets_definitely_disjoint(left: &[u32], right: &[u32]) -> bool {
    !left.is_empty() && !right.is_empty() && !points_to_object_ids_overlap(left, right)
}

fn stable_points_to_object_id_for_seed(seed: &AbstractObjectSeed) -> u32 {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    let raw = hasher.finish();
    ((raw ^ (raw >> 32)) as u32).max(1)
}

fn abstract_object_seed_to_target(seed: &AbstractObjectSeed) -> String {
    match seed {
        AbstractObjectSeed::ValueSite(site) => format!("obj:site:{}", site),
        AbstractObjectSeed::ValueRootRegion(region) => format!("obj:root:{}", region),
        AbstractObjectSeed::ValueRegion(region) => format!("obj:region:{}", region),
        AbstractObjectSeed::ReturnRegion(region) => format!("obj:return:{}", region),
        AbstractObjectSeed::CallPort(port) => format!("obj:port:{}", port),
        AbstractObjectSeed::CellIdentity(key) => format!("cell:{}", key),
        AbstractObjectSeed::MemoryUnit(unit) => format!("memunit:{}", unit),
        AbstractObjectSeed::CellRegion(region) => format!("cell:region:{}", region),
        AbstractObjectSeed::SyntheticSource(name) => format!("obj:synthetic-source:{}", name),
        AbstractObjectSeed::SyntheticSink(name) => format!("obj:synthetic-sink:{}", name),
    }
}

fn insert_abstract_object_seed(fg: &mut FlowGraph, seed: &AbstractObjectSeed) -> u32 {
    if let Some(id) = fg.object_seed_ids.get(seed).copied() {
        return id;
    }
    let target = abstract_object_seed_to_target(seed);
    let mut id = stable_points_to_object_id_for_seed(seed);
    while let Some(existing) = fg.abstract_objects.get(&id) {
        if existing.canonical_target == target {
            fg.object_seed_ids.insert(seed.clone(), id);
            fg.points_to_object_ids.insert(target, id);
            return id;
        }
        id = id.wrapping_add(1).max(1);
    }
    fg.object_seed_ids.insert(seed.clone(), id);
    fg.points_to_object_ids.insert(target.clone(), id);
    fg.abstract_objects.insert(id, abstract_object_info_for_target(id, &target));
    id
}

fn abstract_object_seeds_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<AbstractObjectSeed> {
    let mut out = Vec::new();
    if let Some(site) = value_identity_site(fg, func, value) {
        out.push(AbstractObjectSeed::ValueSite(site.trim().to_string()));
    }
    for region in value_root_memory_regions(fg, func, value) {
        out.push(AbstractObjectSeed::ValueRootRegion(region));
    }
    for region in fg.value_memory_regions_of(func, value) {
        out.push(AbstractObjectSeed::ValueRegion(region));
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn abstract_object_non_memory_seeds_for_cell(
    fg: &FlowGraph,
    cell: NodeIndex,
) -> Vec<AbstractObjectSeed> {
    let mut out = Vec::new();
    if let Some(key) = cell_abstract_identity_key(fg, cell) {
        out.push(AbstractObjectSeed::CellIdentity(key));
    }
    for region in fg.cell_memory_regions_of(cell) {
        out.push(AbstractObjectSeed::CellRegion(region));
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn abstract_object_seeds_for_cell(fg: &FlowGraph, cell: NodeIndex) -> Vec<AbstractObjectSeed> {
    let mut out = abstract_object_non_memory_seeds_for_cell(fg, cell);
    if let Some(unit) = precise_memory_unit_key_for_cell(fg, cell) {
        out.push(AbstractObjectSeed::MemoryUnit(unit));
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn abstract_object_seeds_for_node(fg: &FlowGraph, node: NodeIndex) -> Vec<AbstractObjectSeed> {
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            abstract_object_seeds_for_value(fg, *func, *value)
        }
        FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
            abstract_object_seeds_for_cell(fg, node)
        }
        _ => Vec::new(),
    }
}

fn seeded_abstract_object_seeds_by_node(
    fg: &FlowGraph,
) -> (
    BTreeSet<AbstractObjectSeed>,
    Vec<(usize, Vec<AbstractObjectSeed>)>,
) {
    let mut seeds = BTreeSet::new();
    let mut seeds_by_node = Vec::new();
    for node in fg.graph.node_indices() {
        let node_seeds = abstract_object_seeds_for_node(fg, node);
        if node_seeds.is_empty() {
            continue;
        }
        for seed in &node_seeds {
            seeds.insert(seed.clone());
        }
        seeds_by_node.push((node.index(), node_seeds));
    }
    (seeds, seeds_by_node)
}

fn canonical_abstract_object_keys_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    abstract_object_seeds_for_value(fg, func, value)
        .into_iter()
        .map(|seed| abstract_object_seed_to_target(&seed))
        .collect()
}

fn canonical_abstract_object_keys_for_cell(fg: &FlowGraph, cell: NodeIndex) -> Vec<String> {
    abstract_object_seeds_for_cell(fg, cell)
        .into_iter()
        .map(|seed| abstract_object_seed_to_target(&seed))
        .collect()
}

fn canonical_abstract_object_keys_for_node(fg: &FlowGraph, node: NodeIndex) -> Vec<String> {
    abstract_object_seeds_for_node(fg, node)
        .into_iter()
        .map(|seed| abstract_object_seed_to_target(&seed))
        .collect()
}

fn direct_seed_object_targets_for_node(fg: &FlowGraph, node: NodeIndex) -> Vec<String> {
    canonical_abstract_object_keys_for_node(fg, node)
}

fn abstract_object_catalog_input_snapshot(fg: &FlowGraph) -> AbstractObjectCatalogInputSnapshot {
    let mut nodes = Vec::new();
    for node in fg.graph.node_indices() {
        match &fg.graph[node] {
            FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
                let (shape_paths, shape_labels) = fg
                    .values
                    .get(&(*func, *value))
                    .map(|value_node| {
                        (
                            fg.object_shape_paths
                                .get(&value_node.index())
                                .cloned()
                                .unwrap_or_default(),
                            fg.object_shape_labels
                                .get(&value_node.index())
                                .cloned()
                                .unwrap_or_default(),
                        )
                    })
                    .unwrap_or_default();
                nodes.push(AbstractObjectCatalogNodeInput::Value {
                    node: node.index(),
                    func: *func,
                    value: *value,
                    identity_site: value_identity_site(fg, *func, *value)
                        .map(str::trim)
                        .map(str::to_string),
                    value_type: fg.value_types.get(&(*func, *value)).cloned(),
                    shape_paths,
                    shape_labels,
                    value_regions: fg
                        .value_memory_regions
                        .get(&(*func, *value))
                        .cloned()
                        .unwrap_or_default(),
                });
            }
            FlowNode::FieldCell {
                func,
                base,
                field,
                ..
            } => {
                nodes.push(AbstractObjectCatalogNodeInput::FieldCell {
                    node: node.index(),
                    func: *func,
                    base: *base,
                    field: field.clone(),
                    base_identity_site: value_identity_site(fg, *func, *base)
                        .map(str::trim)
                        .map(str::to_string),
                    cell_regions: fg
                        .cell_memory_regions
                        .get(&node.index())
                        .cloned()
                        .unwrap_or_default(),
                });
            }
            FlowNode::IndexCell {
                func,
                base,
                abstract_key,
                ..
            } => {
                nodes.push(AbstractObjectCatalogNodeInput::IndexCell {
                    node: node.index(),
                    func: *func,
                    base: *base,
                    abstract_key: abstract_key.clone(),
                    base_identity_site: value_identity_site(fg, *func, *base)
                        .map(str::trim)
                        .map(str::to_string),
                    cell_regions: fg
                        .cell_memory_regions
                        .get(&node.index())
                        .cloned()
                        .unwrap_or_default(),
                });
            }
            _ => {}
        }
    }
    AbstractObjectCatalogInputSnapshot { nodes }
}

fn materialize_abstract_object_catalog(fg: &mut FlowGraph) -> bool {
    let input_snapshot = abstract_object_catalog_input_snapshot(fg);
    if fg.abstract_object_catalog_input_snapshot.as_ref() == Some(&input_snapshot) {
        return false;
    }

    let previous_points_to_object_ids = std::mem::take(&mut fg.points_to_object_ids);
    let previous_object_seed_ids = std::mem::take(&mut fg.object_seed_ids);
    let previous_abstract_objects = std::mem::take(&mut fg.abstract_objects);
    let previous_abstract_object_seed_nodes = std::mem::take(&mut fg.abstract_object_seed_nodes);

    // Memory-unit identity is derived from the base value's stable object id.
    // Build all catalog-independent seeds first so ValueSite ids exist before
    // asking cells for their memory-unit keys. The previous single-pass cold
    // rebuild cleared `points_to_object_ids` and then tried to derive those
    // keys from the just-cleared map, silently dropping every MemoryUnit seed.
    let nodes = fg.graph.node_indices().collect::<Vec<_>>();
    let mut base_seeds = Vec::with_capacity(nodes.len().saturating_mul(2));
    let mut seeds_by_node = Vec::<(usize, Vec<AbstractObjectSeed>)>::with_capacity(nodes.len());
    let mut cell_positions = Vec::<(NodeIndex, usize)>::new();
    for node in nodes {
        let node_seeds = match &fg.graph[node] {
            FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
                abstract_object_seeds_for_value(fg, *func, *value)
            }
            FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                let position = seeds_by_node.len();
                cell_positions.push((node, position));
                abstract_object_non_memory_seeds_for_cell(fg, node)
            }
            _ => Vec::new(),
        };
        base_seeds.extend(node_seeds.iter().cloned());
        seeds_by_node.push((node.index(), node_seeds));
    }
    base_seeds.sort_unstable();
    base_seeds.dedup();
    for seed in base_seeds {
        insert_abstract_object_seed(fg, &seed);
    }

    // With ValueSite ids present, memory-unit keys are now stable and can be
    // materialized deterministically in their own collision-ordered pass.
    let mut memory_unit_seeds = Vec::with_capacity(cell_positions.len());
    for (cell, position) in cell_positions {
        let Some(unit) = precise_memory_unit_key_for_cell(fg, cell) else {
            continue;
        };
        let seed = AbstractObjectSeed::MemoryUnit(unit);
        memory_unit_seeds.push(seed.clone());
        seeds_by_node[position].1.push(seed);
    }
    memory_unit_seeds.sort_unstable();
    memory_unit_seeds.dedup();
    for seed in memory_unit_seeds {
        insert_abstract_object_seed(fg, &seed);
    }

    for (node_idx, node_seeds) in seeds_by_node {
        let mut seeded_ids = Vec::new();
        for seed in node_seeds {
            if let Some(id) = fg.object_seed_ids.get(&seed).copied() {
                seeded_ids.push(id);
            }
        }
        seeded_ids.sort_unstable();
        seeded_ids.dedup();
        if !seeded_ids.is_empty() {
            fg.abstract_object_seed_nodes
                .insert(node_idx, seeded_ids);
        }
    }

    fg.abstract_object_catalog_input_snapshot = Some(input_snapshot);
    fg.abstract_object_catalog_rebuilds = fg.abstract_object_catalog_rebuilds.saturating_add(1);
    fg.points_to_object_ids != previous_points_to_object_ids
        || fg.object_seed_ids != previous_object_seed_ids
        || fg.abstract_objects != previous_abstract_objects
        || fg.abstract_object_seed_nodes != previous_abstract_object_seed_nodes
}

fn abstract_object_kind_for_target(target: &str) -> String {
    if target.starts_with("memunit:") {
        "memory-unit".to_string()
    } else if target.starts_with("cell:") {
        "cell".to_string()
    } else if target.starts_with("obj:site:") {
        "site".to_string()
    } else if target.starts_with("obj:root:") {
        "root-region".to_string()
    } else if target.starts_with("obj:return:") || target.starts_with("obj:return-func:") {
        "return".to_string()
    } else if target.starts_with("obj:region:") {
        "region".to_string()
    } else if target.starts_with("obj:port:") {
        "call-port".to_string()
    } else if target.starts_with("obj:synthetic-source:") {
        "synthetic-source".to_string()
    } else if target.starts_with("obj:synthetic-sink:") {
        "synthetic-sink".to_string()
    } else {
        "value".to_string()
    }
}

fn abstract_object_info_for_target(id: u32, target: &str) -> AbstractObjectInfo {
    let identity_site = target
        .strip_prefix("obj:site:")
        .or_else(|| target.strip_prefix("cell:field:"))
        .or_else(|| target.strip_prefix("cell:index:"))
        .or_else(|| target.strip_prefix("memunit:field:"))
        .or_else(|| target.strip_prefix("memunit:index:"))
        .map(|value| value.split(':').next().unwrap_or(value).trim().to_string());
    let root_regions = if let Some(region) = target.strip_prefix("obj:root:") {
        vec![region.to_string()]
    } else if let Some(region) = target.strip_prefix("cell:region:") {
        vec![region.to_string()]
    } else if let Some(region) = target.strip_prefix("obj:return:") {
        vec![region.to_string()]
    } else if let Some(region) = target.strip_prefix("obj:port:") {
        vec![region.to_string()]
    } else if let Some(region) = target.strip_prefix("obj:region:") {
        vec![region.to_string()]
    } else {
        Vec::new()
    };
    AbstractObjectInfo {
        id,
        canonical_target: target.to_string(),
        kind: abstract_object_kind_for_target(target),
        identity_site,
        root_regions,
    }
}

fn precise_value_object_id(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Option<u32> {
    let site = value_identity_site(fg, func, value)?.trim().to_string();
    fg.points_to_object_ids.get(&format!("obj:site:{}", site)).copied()
}

fn precise_cell_object_id(fg: &FlowGraph, cell: NodeIndex) -> Option<u32> {
    if let Some(unit) = precise_memory_unit_key_for_cell(fg, cell) {
        if let Some(id) = fg.points_to_object_ids.get(&format!("memunit:{}", unit)).copied() {
            return Some(id);
        }
    }
    let key = cell_abstract_identity_key(fg, cell)?;
    fg.points_to_object_ids.get(&format!("cell:{}", key)).copied()
}

fn precise_memory_unit_key_for_cell(fg: &FlowGraph, cell: NodeIndex) -> Option<String> {
    match &fg.graph[cell] {
        FlowNode::FieldCell { func, base, field, .. } => {
            let base_object = precise_value_object_id(fg, *func, *base)?;
            Some(format!("mu:{base_object}:field:{field}"))
        }
        FlowNode::IndexCell { func, base, abstract_key, .. } if abstract_key != "*" => {
            let base_object = precise_value_object_id(fg, *func, *base)?;
            Some(format!("mu:{base_object}:index:{abstract_key}"))
        }
        _ => None,
    }
}

fn precise_memory_unit_cells(fg: &FlowGraph, unit_key: &str) -> Vec<NodeIndex> {
    let mut out = all_cell_nodes(fg)
        .into_iter()
        .filter(|candidate| precise_memory_unit_key_for_cell(fg, *candidate).as_deref() == Some(unit_key))
        .collect::<Vec<_>>();
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn target_sets_definitely_disjoint(left: &[String], right: &[String]) -> bool {
    !left.is_empty()
        && !right.is_empty()
        && !points_to_targets_overlap(left, right)
        && left.iter().all(|target| is_precise_points_to_target(target))
        && right.iter().all(|target| is_precise_points_to_target(target))
}

fn heap_projection_values_compatible(
    fg: &FlowGraph,
    left_func: FunctionId,
    left_value: ValueId,
    right_func: FunctionId,
    right_value: ValueId,
) -> bool {
    let left_site = value_identity_site(fg, left_func, left_value);
    let right_site = value_identity_site(fg, right_func, right_value);
    if left_site.is_some() && right_site.is_some() && left_site == right_site {
        return true;
    }
    if identity_sites_definitely_distinct(left_site, right_site) {
        return false;
    }
    let left_classes = inferred_points_to_classes_for_value(fg, left_func, left_value);
    let right_classes = inferred_points_to_classes_for_value(fg, right_func, right_value);
    if !left_classes.is_empty() && !right_classes.is_empty() && !points_to_classes_overlap(&left_classes, &right_classes) {
        let left_has_site = left_classes.iter().any(|value| value.starts_with("site:"));
        let right_has_site = right_classes.iter().any(|value| value.starts_with("site:"));
        if left_has_site || right_has_site {
            return false;
        }
    }
    let left_ty = fg.value_types.get(&(left_func, left_value)).map(|s| s.as_str());
    let right_ty = fg.value_types.get(&(right_func, right_value)).map(|s| s.as_str());
    object_types_compatible(left_ty, right_ty)
}

fn compute_literal_index_keys(func: &Function, language: &Language) -> HashMap<ValueId, String> {
    // A monotone lattice is essential here: a loop phi may initially see only
    // its literal entry value, then acquire a different backedge value. Keeping
    // the first literal would turn an unknown index into an exact heap cell.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum LiteralState { Pending, Known(String), Varying }
    fn join(left: LiteralState, right: LiteralState) -> LiteralState {
        match (left, right) {
            (LiteralState::Pending, state) | (state, LiteralState::Pending) => state,
            (LiteralState::Known(a), LiteralState::Known(b)) if a == b => LiteralState::Known(a),
            _ => LiteralState::Varying,
        }
    }
    let mut literals = func.params.iter().map(|v| (*v, LiteralState::Varying)).collect::<HashMap<_, _>>();
    let mut changed = true;
    while changed {
        changed = false;
        for block in &func.blocks {
            for inst in &block.insts {
                let state = |v: &ValueId| literals.get(v).cloned().unwrap_or(LiteralState::Pending);
                let (dst, next) = match &inst.kind {
                    InstKind::ConstInt { dst, value } => (*dst, LiteralState::Known(value.to_string())),
                    InstKind::ConstString { dst, value } => (*dst, LiteralState::Known(value.clone())),
                    InstKind::Copy { dst, src } | InstKind::Move { dst, src } | InstKind::Cast { dst, src, .. } => (*dst, state(src)),
                    InstKind::Deref { dst, .. } => (*dst, LiteralState::Varying),
                    InstKind::Compare { dst, .. } => (*dst, LiteralState::Varying),
                    InstKind::NumericStep { dst, src, increment } => {
                        let next = match state(src) {
                            LiteralState::Known(value) => value.parse::<i64>().ok()
                                .and_then(|value| numeric_step_literal(value, *increment,
                                    func.value_types.get(dst).map(String::as_str)))
                                .map(|v| LiteralState::Known(v.to_string())).unwrap_or(LiteralState::Varying),
                            other => other,
                        };
                        (*dst, next)
                    }
                    InstKind::NumericNeg { dst, src } => {
                        let next = match state(src) {
                            LiteralState::Known(value) => value
                                .parse::<i64>()
                                .ok()
                                .and_then(i64::checked_neg)
                                .map(|value| LiteralState::Known(value.to_string()))
                                .unwrap_or(LiteralState::Varying),
                            other => other,
                        };
                        (*dst, next)
                    }
                    InstKind::Phi { dst, inputs } => (*dst,
                        inputs.iter().map(state).fold(LiteralState::Pending, join)),
                    InstKind::LoadField { dst, base, field } => {
                        let next = match state(base) {
                            LiteralState::Known(value) => external_symbol_name(&value)
                                .map(|symbol| LiteralState::Known(format!("<external-symbol:{symbol}.{field}>")))
                                .unwrap_or(LiteralState::Varying),
                            other => other,
                        };
                        (*dst, next)
                    }
                    InstKind::LoadIndex { dst, base, index } => {
                        let next = match (state(base), state(index)) {
                            (LiteralState::Known(base), LiteralState::Known(index)) => {
                                external_symbol_name(&base)
                                    .map(|symbol| LiteralState::Known(format!("<external-symbol:{symbol}.{index}>")))
                                    .unwrap_or(LiteralState::Varying)
                            }
                            (LiteralState::Pending, _) | (_, LiteralState::Pending) => LiteralState::Pending,
                            _ => LiteralState::Varying,
                        };
                        (*dst, next)
                    }
                    InstKind::Call(call) => match call.dst {
                        Some(dst) if *language == Language::JavaScript => {
                            let next = match &call.callee {
                                Callee::Static(name) if name == "require" && !call.args.is_empty() => {
                                    match state(&call.args[0]) {
                                        LiteralState::Known(module) => LiteralState::Known(
                                            format!("<external-symbol:{module}>")
                                        ),
                                        other => other,
                                    }
                                }
                                Callee::Static(name)
                                    if (name == "__uniflow.compose.string"
                                        || name == "__uniflow.compose.map")
                                        && call.args.len() >= 2 =>
                                {
                                    state(&call.args[1])
                                }
                                Callee::Static(name) => {
                                    let receiver_symbol = call.receiver.and_then(|receiver| {
                                        match state(&receiver) {
                                            LiteralState::Known(value) => {
                                                external_symbol_name(&value).map(str::to_string)
                                            }
                                            _ => None,
                                        }
                                    });
                                    if let Some(receiver_symbol) = receiver_symbol {
                                        let prefix = format!("{receiver_symbol}.");
                                        let qualified = if name.starts_with(&prefix) {
                                            name.clone()
                                        } else {
                                            format!("{receiver_symbol}.{name}")
                                        };
                                        LiteralState::Known(format!("<external-symbol:{qualified}>"))
                                    } else if name.contains('.') || name.contains("::") {
                                        LiteralState::Known(format!("<external-symbol:{name}>"))
                                    } else {
                                        LiteralState::Varying
                                    }
                                }
                                Callee::Dynamic(_) | Callee::Unknown => LiteralState::Varying,
                            };
                            (dst, next)
                        }
                        Some(dst) => (dst, LiteralState::Varying),
                        None => continue,
                    },
                    InstKind::StoreField { .. } | InstKind::StoreIndex { .. } | InstKind::Lifetime { .. } => continue,
                };
                let previous = state(&dst);
                let next = join(previous.clone(), next);
                if next != previous {
                    literals.insert(dst, next);
                    changed = true;
                }
            }
        }
    }
    literals.into_iter().filter_map(|(v, state)| match state {
        LiteralState::Known(text) => Some((v, text)), _ => None,
    }).collect()
}

fn numeric_step_literal(value: i64, increment: bool, ty: Option<&str>) -> Option<i64> {
    let next = if increment { value.wrapping_add(1) } else { value.wrapping_sub(1) };
    Some(match ty? {
        "byte" | "Byte" | "java.lang.Byte" => next as i8 as i64,
        "short" | "Short" | "java.lang.Short" => next as i16 as i64,
        "char" | "Character" | "java.lang.Character" => next as u16 as i64,
        "int" | "Integer" | "java.lang.Integer" => next as i32 as i64,
        "long" | "Long" | "java.lang.Long" => next,
        // Do not guess floating-point rounding or the width of an unknown type.
        _ => return None,
    })
}

fn abstract_index_key(literal_keys: &HashMap<ValueId, String>, index: ValueId) -> String {
    literal_keys.get(&index).cloned().unwrap_or_else(|| "*".to_string())
}
