
fn merge_query_completeness(
    left: QueryCompleteness,
    right: QueryCompleteness,
) -> QueryCompleteness {
    fn rank(value: QueryCompleteness) -> u8 {
        match value {
            QueryCompleteness::Complete => 0,
            QueryCompleteness::HeapWidened => 1,
            QueryCompleteness::ContextLimitReached => 2,
            QueryCompleteness::DepthLimitReached => 3,
            QueryCompleteness::VisitLimitReached => 4,
        }
    }
    if rank(right) > rank(left) { right } else { left }
}

impl FlowGraph {
    pub fn ensure_value(&mut self, func: FunctionId, value: ValueId) -> NodeIndex {
        if let Some(node) = self.values.get(&(func, value)).copied() {
            return node;
        }
        let node = self.graph.add_node(FlowNode::Value { func, value });
        self.values.insert((func, value), node);
        node
    }

    pub fn materialize_sparse_data_adjacency(&mut self) {
        materialize_sparse_data_adjacency(self);
    }

    pub fn successors(&self, node: NodeIndex) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.neighbors_directed(node, petgraph::Direction::Outgoing)
    }

    pub fn sparse_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        if let Some(values) = self.sparse_successors.get(&node.index()) {
            return values.iter().copied().map(NodeIndex::new).collect();
        }
        self.graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .filter(|edge| is_sparse_data_edge(&edge.weight().kind))
            .map(|edge| edge.target())
            .collect()
    }

    pub fn sparse_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        if let Some(values) = self.sparse_predecessors.get(&node.index()) {
            return values.iter().copied().map(NodeIndex::new).collect();
        }
        self.graph
            .edges_directed(node, petgraph::Direction::Incoming)
            .filter(|edge| is_sparse_data_edge(&edge.weight().kind))
            .map(|edge| edge.source())
            .collect()
    }

    pub fn sparse_reachable_nodes(&self, seeds: &[NodeIndex], forward: bool, max_depth: usize) -> Vec<NodeIndex> {
        let direction = if forward {
            SparseDirection::Forward
        } else {
            SparseDirection::Backward
        };
        self.sparse_traversal(seeds, direction, max_depth, usize::MAX)
            .visited
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn sparse_neighbors_of(&self, node: NodeIndex, direction: SparseDirection) -> Vec<NodeIndex> {
        match direction {
            SparseDirection::Forward => self.sparse_successors_of(node),
            SparseDirection::Backward => self.sparse_predecessors_of(node),
        }
    }

    pub fn heap_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.heap_value_successors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn heap_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.heap_value_predecessors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }


    pub fn heap_object_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.heap_object_successors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn heap_object_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.heap_object_predecessors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn object_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        let mut out = self.heap_object_successors_of(node);
        out.extend(self.object_graph_successors_of(node));
        out.sort_unstable_by_key(|idx| idx.index());
        out.dedup_by_key(|idx| idx.index());
        out
    }

    pub fn object_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        let mut out = self.heap_object_predecessors_of(node);
        out.extend(self.object_graph_predecessors_of(node));
        out.sort_unstable_by_key(|idx| idx.index());
        out.dedup_by_key(|idx| idx.index());
        out
    }

    pub fn object_graph_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.object_graph_successors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn object_graph_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.object_graph_predecessors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn object_graph_edge_label(&self, src: NodeIndex, dst: NodeIndex) -> Option<&str> {
        self.object_graph_labels
            .get(&(src.index(), dst.index()))
            .map(|value| value.as_str())
    }

    pub fn object_shape_labels_of(&self, node: NodeIndex) -> Vec<String> {
        self.object_shape_labels.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn object_shape_paths_of(&self, node: NodeIndex) -> Vec<String> {
        self.object_shape_paths.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn node_memory_regions_of(&self, node: NodeIndex) -> Vec<String> {
        self.node_memory_regions.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn value_memory_regions_of(&self, func: FunctionId, value: ValueId) -> Vec<String> {
        self.value_memory_regions.get(&(func, value)).cloned().unwrap_or_default()
    }

    pub fn cell_memory_regions_of(&self, cell: NodeIndex) -> Vec<String> {
        self.cell_memory_regions.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn region_graph_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.region_graph_successors
            .get(&node.index())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn region_graph_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.region_graph_predecessors
            .get(&node.index())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn cell_live_values_of(&self, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
        self
            .cell_live_values
            .get(&cell.index())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(func, value)| (FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn cell_live_regions_of(&self, cell: NodeIndex) -> Vec<String> {
        self.cell_live_regions.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn region_live_values_of(&self, region: &str) -> Vec<(FunctionId, ValueId)> {
        self.region_live_values
            .get(region)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(func, value)| (FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn region_live_cells_of(&self, region: &str) -> Vec<NodeIndex> {
        self.region_live_cells
            .get(region)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn node_points_to_classes_of(&self, node: NodeIndex) -> Vec<String> {
        self.node_points_to_classes.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn value_points_to_classes_of(&self, func: FunctionId, value: ValueId) -> Vec<String> {
        self.value_points_to_classes
            .get(&(func, value))
            .cloned()
            .unwrap_or_default()
    }

    pub fn cell_points_to_classes_of(&self, cell: NodeIndex) -> Vec<String> {
        self.cell_points_to_classes.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn node_points_to_targets_of(&self, node: NodeIndex) -> Vec<String> {
        self.node_points_to_targets.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn value_points_to_targets_of(&self, func: FunctionId, value: ValueId) -> Vec<String> {
        self.value_points_to_targets
            .get(&(func, value))
            .cloned()
            .unwrap_or_default()
    }

    pub fn cell_points_to_targets_of(&self, cell: NodeIndex) -> Vec<String> {
        self.cell_points_to_targets.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn node_points_to_object_ids_of(&self, node: NodeIndex) -> Vec<u32> {
        self.node_points_to_object_ids.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn value_points_to_object_ids_of(&self, func: FunctionId, value: ValueId) -> Vec<u32> {
        self.value_points_to_object_ids
            .get(&(func, value))
            .cloned()
            .unwrap_or_default()
    }

    pub fn cell_points_to_object_ids_of(&self, cell: NodeIndex) -> Vec<u32> {
        self.cell_points_to_object_ids.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn contextual_node_points_to_targets_of(&self, context: &CallContextKey, node: NodeIndex) -> Vec<String> {
        self.contextual_node_points_to_targets
            .get(&(context.clone(), node.index()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_value_points_to_targets_of(&self, context: &CallContextKey, func: FunctionId, value: ValueId) -> Vec<String> {
        self.contextual_value_points_to_targets
            .get(&(context.clone(), func.0, value.0))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_cell_points_to_targets_of(&self, context: &CallContextKey, cell: NodeIndex) -> Vec<String> {
        self.contextual_cell_points_to_targets
            .get(&(context.clone(), cell.index()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_node_points_to_object_ids_of(&self, context: &CallContextKey, node: NodeIndex) -> Vec<u32> {
        self.contextual_node_points_to_object_ids
            .get(&(context.clone(), node.index()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_value_points_to_object_ids_of(&self, context: &CallContextKey, func: FunctionId, value: ValueId) -> Vec<u32> {
        self.contextual_value_points_to_object_ids
            .get(&(context.clone(), func.0, value.0))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_cell_points_to_object_ids_of(&self, context: &CallContextKey, cell: NodeIndex) -> Vec<u32> {
        self.contextual_cell_points_to_object_ids
            .get(&(context.clone(), cell.index()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_return_values_of(&self, context: &CallContextKey) -> Vec<(FunctionId, ValueId)> {
        self.contextual_return_values
            .get(context)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(func, value)| (FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn contextual_return_cells_of(&self, context: &CallContextKey) -> Vec<NodeIndex> {
        self.contextual_return_cells
            .get(context)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn contextual_points_to_object_ids_of(&self, context: &CallContextKey) -> Vec<u32> {
        self.contextual_points_to_object_ids
            .get(context)
            .cloned()
            .unwrap_or_default()
    }

    pub fn is_strong_update_cell(&self, cell: NodeIndex) -> bool {
        self.strong_update_cells.contains(&cell.index())
    }

    pub fn value_must_alias(
        &self,
        left_func: FunctionId,
        left_value: ValueId,
        right_func: FunctionId,
        right_value: ValueId,
    ) -> bool {
        if left_func == right_func && left_value == right_value {
            return true;
        }
        let left_precise = precise_value_object_id(self, left_func, left_value);
        let right_precise = precise_value_object_id(self, right_func, right_value);
        if left_precise.is_some() && right_precise.is_some() {
            return left_precise == right_precise;
        }
        let left_site = value_identity_site(self, left_func, left_value);
        let right_site = value_identity_site(self, right_func, right_value);
        if left_site.is_some() && right_site.is_some() {
            return left_site == right_site;
        }
        let left_object_ids = self.value_points_to_object_ids_of(left_func, left_value);
        let right_object_ids = self.value_points_to_object_ids_of(right_func, right_value);
        if !left_object_ids.is_empty()
            && left_object_ids == right_object_ids
            && left_object_ids.len() == 1
        {
            return true;
        }
        let left_targets = self.value_points_to_targets_of(left_func, left_value);
        let right_targets = self.value_points_to_targets_of(right_func, right_value);
        !left_targets.is_empty()
            && left_targets == right_targets
            && left_targets.len() == 1
            && left_targets.iter().all(|target| is_precise_points_to_target(target))
    }

    pub fn value_may_alias(
        &self,
        left_func: FunctionId,
        left_value: ValueId,
        right_func: FunctionId,
        right_value: ValueId,
    ) -> bool {
        let left_precise = precise_value_object_id(self, left_func, left_value);
        let right_precise = precise_value_object_id(self, right_func, right_value);
        if left_precise.is_some() && right_precise.is_some() {
            return left_precise == right_precise;
        }
        let left_site = value_identity_site(self, left_func, left_value);
        let right_site = value_identity_site(self, right_func, right_value);
        if left_site.is_some() && right_site.is_some() {
            return left_site == right_site;
        }
        if identity_sites_definitely_distinct(left_site, right_site) {
            return false;
        }
        let left_object_ids = self.value_points_to_object_ids_of(left_func, left_value);
        let right_object_ids = self.value_points_to_object_ids_of(right_func, right_value);
        if !left_object_ids.is_empty() && !right_object_ids.is_empty() {
            if points_to_object_ids_overlap(&left_object_ids, &right_object_ids) {
                return true;
            }
            if object_id_sets_definitely_disjoint(&left_object_ids, &right_object_ids) {
                return false;
            }
        }
        let left_targets = self.value_points_to_targets_of(left_func, left_value);
        let right_targets = self.value_points_to_targets_of(right_func, right_value);
        if !left_targets.is_empty() && !right_targets.is_empty() {
            if points_to_targets_overlap(&left_targets, &right_targets) {
                return true;
            }
            if target_sets_definitely_disjoint(&left_targets, &right_targets) {
                return false;
            }
        }
        let left_regions = self.value_memory_regions_of(left_func, left_value);
        let right_regions = self.value_memory_regions_of(right_func, right_value);
        if !left_regions.is_empty() && !right_regions.is_empty() && memory_regions_overlap(&left_regions, &right_regions) {
            return true;
        }
        let left_classes = self.value_points_to_classes_of(left_func, left_value);
        let right_classes = self.value_points_to_classes_of(right_func, right_value);
        if !left_classes.is_empty() && !right_classes.is_empty() {
            return points_to_classes_overlap(&left_classes, &right_classes);
        }
        let left_ty = self.value_types.get(&(left_func, left_value)).map(|s| s.as_str());
        let right_ty = self.value_types.get(&(right_func, right_value)).map(|s| s.as_str());
        object_types_compatible(left_ty, right_ty)
    }

    pub fn cell_must_alias(&self, left: NodeIndex, right: NodeIndex) -> bool {
        if left == right {
            return true;
        }
        let left_unit = precise_memory_unit_key_for_cell(self, left);
        let right_unit = precise_memory_unit_key_for_cell(self, right);
        if left_unit.is_some() && right_unit.is_some() {
            return left_unit == right_unit;
        }
        let left_precise = precise_cell_object_id(self, left);
        let right_precise = precise_cell_object_id(self, right);
        if left_precise.is_some() && right_precise.is_some() {
            return left_precise == right_precise;
        }
        let left_object_ids = self.cell_points_to_object_ids_of(left);
        let right_object_ids = self.cell_points_to_object_ids_of(right);
        if !left_object_ids.is_empty()
            && left_object_ids == right_object_ids
            && left_object_ids.len() == 1
        {
            return true;
        }
        let left_targets = self.cell_points_to_targets_of(left);
        let right_targets = self.cell_points_to_targets_of(right);
        !left_targets.is_empty()
            && left_targets == right_targets
            && left_targets.len() == 1
            && left_targets.iter().all(|target| is_precise_points_to_target(target))
    }

    pub fn cell_may_alias(&self, left: NodeIndex, right: NodeIndex) -> bool {
        if left == right {
            return true;
        }
        let left_unit = precise_memory_unit_key_for_cell(self, left);
        let right_unit = precise_memory_unit_key_for_cell(self, right);
        if left_unit.is_some() && right_unit.is_some() {
            return left_unit == right_unit;
        }
        let left_precise = precise_cell_object_id(self, left);
        let right_precise = precise_cell_object_id(self, right);
        if left_precise.is_some() && right_precise.is_some() {
            return left_precise == right_precise;
        }
        let left_object_ids = self.cell_points_to_object_ids_of(left);
        let right_object_ids = self.cell_points_to_object_ids_of(right);
        if !left_object_ids.is_empty() && !right_object_ids.is_empty() {
            if points_to_object_ids_overlap(&left_object_ids, &right_object_ids) {
                return true;
            }
            if object_id_sets_definitely_disjoint(&left_object_ids, &right_object_ids) {
                return false;
            }
        }
        let left_targets = self.cell_points_to_targets_of(left);
        let right_targets = self.cell_points_to_targets_of(right);
        if !left_targets.is_empty() && !right_targets.is_empty() {
            if points_to_targets_overlap(&left_targets, &right_targets) {
                return true;
            }
            if target_sets_definitely_disjoint(&left_targets, &right_targets) {
                return false;
            }
        }
        let left_regions = self.cell_memory_regions_of(left);
        let right_regions = self.cell_memory_regions_of(right);
        if !left_regions.is_empty() && !right_regions.is_empty() && memory_regions_overlap(&left_regions, &right_regions) {
            return true;
        }
        let left_classes = self.cell_points_to_classes_of(left);
        let right_classes = self.cell_points_to_classes_of(right);
        if !left_classes.is_empty() && !right_classes.is_empty() {
            return points_to_classes_overlap(&left_classes, &right_classes);
        }
        match (&self.graph[left], &self.graph[right]) {
            (
                FlowNode::FieldCell { func: lf, base: lb, field: lfield, .. },
                FlowNode::FieldCell { func: rf, base: rb, field: rfield, .. },
            ) if lfield == rfield => self.value_may_alias(*lf, *lb, *rf, *rb),
            (
                FlowNode::IndexCell { func: lf, base: lb, abstract_key: lkey, .. },
                FlowNode::IndexCell { func: rf, base: rb, abstract_key: rkey, .. },
            ) if lkey == rkey || lkey == "*" || rkey == "*" => self.value_may_alias(*lf, *lb, *rf, *rb),
            _ => false,
        }
    }

    fn demand_query_neighbors_of(
        &self,
        node: NodeIndex,
        direction: SparseDirection,
        include_heap: bool,
    ) -> Vec<NodeIndex> {
        let mut out = self.sparse_neighbors_of(node, direction);
        if include_heap {
            let heap = match direction {
                SparseDirection::Forward => self.heap_successors_of(node),
                SparseDirection::Backward => self.heap_predecessors_of(node),
            };
            for neighbor in heap {
                if !out.contains(&neighbor) {
                    out.push(neighbor);
                }
            }
            let object = match direction {
                SparseDirection::Forward => self.heap_object_successors_of(node),
                SparseDirection::Backward => self.heap_object_predecessors_of(node),
            };
            for neighbor in object {
                if !out.contains(&neighbor) {
                    out.push(neighbor);
                }
            }
            let object_graph = match direction {
                SparseDirection::Forward => self.object_graph_successors_of(node),
                SparseDirection::Backward => self.object_graph_predecessors_of(node),
            };
            for neighbor in object_graph {
                if !out.contains(&neighbor) {
                    out.push(neighbor);
                }
            }
            let region_graph = match direction {
                SparseDirection::Forward => self.region_graph_successors_of(node),
                SparseDirection::Backward => self.region_graph_predecessors_of(node),
            };
            for neighbor in region_graph {
                if !out.contains(&neighbor) {
                    out.push(neighbor);
                }
            }
        }
        out.sort_unstable_by_key(|node| node.index());
        out.dedup_by_key(|node| node.index());
        out
    }

    fn demand_query_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        include_heap: bool,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let mut seen = HashSet::new();
        let mut frontier = seeds.to_vec();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for node in frontier {
                if out.visited.len() >= max_visits {
                    out.frontier_cutoff = true;
                    out.completeness = QueryCompleteness::VisitLimitReached;
                    return out;
                }
                if !seen.insert(node) {
                    continue;
                }
                out.visited.push(node.index());
                layer.push(node.index());
                for neighbor in self.demand_query_neighbors_of(node, direction, include_heap) {
                    if !seen.contains(&neighbor) {
                        next.push(neighbor);
                    }
                }
            }
            if !layer.is_empty() {
                out.layers.push(layer);
            }
            frontier = next;
            depth += 1;
        }
        if !frontier.is_empty() {
            out.frontier_cutoff = true;
            out.completeness = QueryCompleteness::DepthLimitReached;
        }
        out
    }

    fn contextual_demand_query_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        include_heap: bool,
        context: &CallContextKey,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let mut seen = HashSet::new();
        let mut frontier = seeds
            .iter()
            .copied()
            .filter(|node| self.node_matches_call_context(*node, context))
            .collect::<Vec<_>>();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for node in frontier {
                if out.visited.len() >= max_visits {
                    out.frontier_cutoff = true;
                    out.completeness = QueryCompleteness::VisitLimitReached;
                    return out;
                }
                if !self.node_matches_call_context(node, context) || !seen.insert(node) {
                    continue;
                }
                out.visited.push(node.index());
                layer.push(node.index());
                for neighbor in self.demand_query_neighbors_of(node, direction, include_heap) {
                    if self.node_matches_call_context(neighbor, context) && !seen.contains(&neighbor) {
                        next.push(neighbor);
                    }
                }
            }
            if !layer.is_empty() {
                layer.sort_unstable();
                layer.dedup();
                out.layers.push(layer);
            }
            next.sort_unstable_by_key(|node| node.index());
            next.dedup_by_key(|node| node.index());
            frontier = next;
            depth += 1;
        }
        if !frontier.is_empty() {
            out.frontier_cutoff = true;
            out.completeness = QueryCompleteness::DepthLimitReached;
        }
        out
    }

    fn contextual_demand_query_fixpoint_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        include_heap: bool,
        context: &CallContextKey,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let (components, node_to_component, succ, pred) = self.demand_query_scc_index(include_heap);
        let component_allowed = components
            .iter()
            .enumerate()
            .map(|(component, members)| {
                (
                    component,
                    members
                        .iter()
                        .any(|member| self.node_matches_call_context(NodeIndex::new(*member), context)),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut frontier = seeds
            .iter()
            .filter(|seed| self.node_matches_call_context(**seed, context))
            .filter_map(|seed| node_to_component.get(seed.index()).copied())
            .filter(|component| *component != usize::MAX && component_allowed.get(component).copied().unwrap_or(false))
            .collect::<Vec<_>>();
        frontier.sort_unstable();
        frontier.dedup();
        let mut seen_components = HashSet::new();
        let mut seen_nodes = HashSet::new();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for component in frontier {
                if !seen_components.insert(component) {
                    continue;
                }
                let members = components.get(component).cloned().unwrap_or_default();
                for member in members {
                    let node = NodeIndex::new(member);
                    if !self.node_matches_call_context(node, context) {
                        continue;
                    }
                    if out.visited.len() >= max_visits {
                        out.frontier_cutoff = true;
                        out.completeness = QueryCompleteness::VisitLimitReached;
                        return out;
                    }
                    if seen_nodes.insert(member) {
                        out.visited.push(member);
                        layer.push(member);
                    }
                }
                let neighbors = match direction {
                    SparseDirection::Forward => succ.get(&component),
                    SparseDirection::Backward => pred.get(&component),
                };
                if let Some(neighbors) = neighbors {
                    for neighbor in neighbors {
                        if !seen_components.contains(neighbor)
                            && component_allowed.get(neighbor).copied().unwrap_or(false)
                        {
                            next.push(*neighbor);
                        }
                    }
                }
            }
            if !layer.is_empty() {
                layer.sort_unstable();
                layer.dedup();
                out.layers.push(layer);
            }
            next.sort_unstable();
            next.dedup();
            frontier = next;
            depth += 1;
        }
        if !frontier.is_empty() {
            out.frontier_cutoff = true;
            out.completeness = QueryCompleteness::DepthLimitReached;
        }
        out
    }

    pub fn sparse_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let mut seen = HashSet::new();
        let mut frontier = seeds.to_vec();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for node in frontier {
                if out.visited.len() >= max_visits {
                    out.frontier_cutoff = true;
                    out.completeness = QueryCompleteness::VisitLimitReached;
                    return out;
                }
                if !seen.insert(node) {
                    continue;
                }
                out.visited.push(node.index());
                layer.push(node.index());
                for neighbor in self.sparse_neighbors_of(node, direction) {
                    if !seen.contains(&neighbor) {
                        next.push(neighbor);
                    }
                }
            }
            if !layer.is_empty() {
                out.layers.push(layer);
            }
            frontier = next;
            depth += 1;
        }
        if !frontier.is_empty() {
            out.frontier_cutoff = true;
            out.completeness = QueryCompleteness::DepthLimitReached;
        }
        out
    }

    pub fn clear_sparse_caches(&self) {
        self.demand_summary_cache.borrow_mut().clear();
        self.demand_seed_summary_cache.borrow_mut().clear();
        self.demand_call_summary_cache.borrow_mut().clear();
        self.demand_fixpoint_summary_cache.borrow_mut().clear();
        self.demand_query_summary_cache.borrow_mut().clear();
        self.contextual_call_summary_cache.borrow_mut().clear();
        self.function_summary_cache.borrow_mut().clear();
        self.contextual_demand_query_cache.borrow_mut().clear();
        self.interprocedural_call_summary_cache.borrow_mut().clear();
        self.function_transfer_summary_cache.borrow_mut().clear();
        self.contextual_function_transfer_summary_cache.borrow_mut().clear();
        self.function_heap_effect_summary_cache.borrow_mut().clear();
        self.contextual_function_heap_effect_summary_cache.borrow_mut().clear();
    }

    fn summarize_sparse_traversal(&self, traversal: SparseTraversal) -> SparseValueSummary {
        let mut summary = SparseValueSummary {
            traversal,
            ..SparseValueSummary::default()
        };
        for idx in &summary.traversal.visited {
            let node = NodeIndex::new(*idx);
            match &self.graph[node] {
                FlowNode::Value { func, value } => summary.values.push((func.0, value.0)),
                FlowNode::Param { func, index, value } => summary.params.push((func.0, *index, value.0)),
                FlowNode::CallPort { func, inst, port, .. } => {
                    summary.call_ports.push((func.0, inst.0, format!("{:?}", port)));
                }
                _ => {}
            }
        }
        summary.values.sort_unstable();
        summary.values.dedup();
        summary.params.sort_unstable();
        summary.params.dedup();
        summary.call_ports.sort_unstable();
        summary.call_ports.dedup();
        summary
    }

    fn sparse_scc_index(
        &self,
    ) -> (Vec<Vec<usize>>, Vec<usize>, HashMap<usize, Vec<usize>>, HashMap<usize, Vec<usize>>) {
        let mut sparse = DiGraph::<(), ()>::new();
        for _ in 0..self.graph.node_count() {
            sparse.add_node(());
        }
        for (src, dsts) in &self.sparse_successors {
            for dst in dsts {
                sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
            }
        }
        let components = kosaraju_scc(&sparse)
            .into_iter()
            .map(|component| component.into_iter().map(|node| node.index()).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let mut node_to_component = vec![usize::MAX; self.graph.node_count()];
        for (component_idx, members) in components.iter().enumerate() {
            for member in members {
                if *member < node_to_component.len() {
                    node_to_component[*member] = component_idx;
                }
            }
        }
        let mut succ = HashMap::<usize, Vec<usize>>::new();
        let mut pred = HashMap::<usize, Vec<usize>>::new();
        for (src, dsts) in &self.sparse_successors {
            let Some(&src_component) = node_to_component.get(*src) else {
                continue;
            };
            if src_component == usize::MAX {
                continue;
            }
            for dst in dsts {
                let Some(&dst_component) = node_to_component.get(*dst) else {
                    continue;
                };
                if dst_component == usize::MAX || src_component == dst_component {
                    continue;
                }
                succ.entry(src_component).or_default().push(dst_component);
                pred.entry(dst_component).or_default().push(src_component);
            }
        }
        for values in succ.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        for values in pred.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        (components, node_to_component, succ, pred)
    }

    fn demand_query_scc_index(
        &self,
        include_heap: bool,
    ) -> (Vec<Vec<usize>>, Vec<usize>, HashMap<usize, Vec<usize>>, HashMap<usize, Vec<usize>>) {
        let mut sparse = DiGraph::<(), ()>::new();
        for _ in 0..self.graph.node_count() {
            sparse.add_node(());
        }
        for (src, dsts) in &self.sparse_successors {
            for dst in dsts {
                sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
            }
        }
        if include_heap {
            for (src, dsts) in &self.heap_value_successors {
                for dst in dsts {
                    sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
                }
            }
            for (src, dsts) in &self.heap_object_successors {
                for dst in dsts {
                    sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
                }
            }
            for (src, dsts) in &self.object_graph_successors {
                for dst in dsts {
                    sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
                }
            }
            for (src, dsts) in &self.region_graph_successors {
                for dst in dsts {
                    sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
                }
            }
        }
        let components = kosaraju_scc(&sparse)
            .into_iter()
            .map(|component| component.into_iter().map(|node| node.index()).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let mut node_to_component = vec![usize::MAX; self.graph.node_count()];
        for (component_idx, members) in components.iter().enumerate() {
            for member in members {
                if *member < node_to_component.len() {
                    node_to_component[*member] = component_idx;
                }
            }
        }
        let mut succ = HashMap::<usize, Vec<usize>>::new();
        let mut pred = HashMap::<usize, Vec<usize>>::new();
        let mut push_component_edges = |edges: &HashMap<usize, Vec<usize>>| {
            for (src, dsts) in edges {
                let Some(&src_component) = node_to_component.get(*src) else {
                    continue;
                };
                if src_component == usize::MAX {
                    continue;
                }
                for dst in dsts {
                    let Some(&dst_component) = node_to_component.get(*dst) else {
                        continue;
                    };
                    if dst_component == usize::MAX || src_component == dst_component {
                        continue;
                    }
                    succ.entry(src_component).or_default().push(dst_component);
                    pred.entry(dst_component).or_default().push(src_component);
                }
            }
        };
        push_component_edges(&self.sparse_successors);
        if include_heap {
            push_component_edges(&self.heap_value_successors);
            push_component_edges(&self.heap_object_successors);
            push_component_edges(&self.object_graph_successors);
            push_component_edges(&self.region_graph_successors);
        }
        for values in succ.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        for values in pred.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        (components, node_to_component, succ, pred)
    }

    fn demand_query_fixpoint_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        include_heap: bool,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let (components, node_to_component, succ, pred) = self.demand_query_scc_index(include_heap);
        let mut frontier = seeds
            .iter()
            .filter_map(|seed| node_to_component.get(seed.index()).copied())
            .filter(|component| *component != usize::MAX)
            .collect::<Vec<_>>();
        frontier.sort_unstable();
        frontier.dedup();
        let mut seen_components = HashSet::new();
        let mut seen_nodes = HashSet::new();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for component in frontier {
                if !seen_components.insert(component) {
                    continue;
                }
                let members = components.get(component).cloned().unwrap_or_default();
                for member in members {
                    if out.visited.len() >= max_visits {
                        out.frontier_cutoff = true;
                        out.completeness = QueryCompleteness::VisitLimitReached;
                        return out;
                    }
                    if seen_nodes.insert(member) {
                        out.visited.push(member);
                        layer.push(member);
                    }
                }
                let neighbors = match direction {
                    SparseDirection::Forward => succ.get(&component),
                    SparseDirection::Backward => pred.get(&component),
                };
                if let Some(neighbors) = neighbors {
                    for neighbor in neighbors {
                        if !seen_components.contains(neighbor) {
                            next.push(*neighbor);
                        }
                    }
                }
            }
            if !layer.is_empty() {
                layer.sort_unstable();
                layer.dedup();
                out.layers.push(layer);
            }
            next.sort_unstable();
            next.dedup();
            frontier = next;
            depth += 1;
        }
        if !frontier.is_empty() {
            out.frontier_cutoff = true;
            out.completeness = QueryCompleteness::DepthLimitReached;
        }
        out
    }

    pub fn sparse_fixpoint_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseTraversal {
        self.demand_query_fixpoint_traversal(seeds, direction, max_depth, max_visits, false)
    }

    pub fn demand_fixpoint_summary_from_seeds(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let mut key_seeds = seeds.iter().map(|seed| seed.index()).collect::<Vec<_>>();
        key_seeds.sort_unstable();
        key_seeds.dedup();
        let key = (key_seeds, direction, max_depth, max_visits);
        if let Some(cached) = self.demand_fixpoint_summary_cache.borrow().get(&key).cloned() {
            return cached;
        }
        let traversal = self.sparse_fixpoint_traversal(seeds, direction, max_depth, max_visits);
        let summary = self.summarize_sparse_traversal(traversal);
        self.demand_fixpoint_summary_cache.borrow_mut().insert(key, summary.clone());
        summary
    }

    pub fn demand_fixpoint_value_summary(
        &self,
        func: FunctionId,
        value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let seed = value_node(self, func, value);
        self.demand_fixpoint_summary_from_seeds(&[seed], direction, max_depth, max_visits)
    }

    pub fn demand_fixpoint_call_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let mut seeds = self
            .call_ports
            .iter()
            .filter_map(|((call_func, call_inst, _port), node)| {
                (*call_func == func && *call_inst == inst).then_some(*node)
            })
            .collect::<Vec<_>>();
        seeds.sort_unstable_by_key(|node| node.index());
        seeds.dedup();
        if seeds.is_empty() {
            return None;
        }
        Some(self.demand_fixpoint_summary_from_seeds(&seeds, direction, max_depth, max_visits))
    }

    pub fn demand_fixpoint_reaches_value(
        &self,
        src_func: FunctionId,
        src_value: ValueId,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let summary = self.demand_fixpoint_value_summary(src_func, src_value, direction, max_depth, max_visits);
        summary
            .values
            .iter()
            .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
    }

    pub fn demand_fixpoint_reaches_any_value(
        &self,
        src_func: FunctionId,
        src_value: ValueId,
        targets: &[(FunctionId, ValueId)],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let summary = self.demand_fixpoint_value_summary(src_func, src_value, direction, max_depth, max_visits);
        targets.iter().any(|(dst_func, dst_value)| {
            summary
                .values
                .iter()
                .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
                || summary
                    .params
                    .iter()
                    .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
        })
    }

    pub fn demand_fixpoint_call_port_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        port: Port,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let seed = self.call_ports.get(&(func, inst, port))?.to_owned();
        Some(self.demand_fixpoint_summary_from_seeds(&[seed], direction, max_depth, max_visits))
    }

    pub fn demand_fixpoint_call_port_reaches_value(
        &self,
        func: FunctionId,
        inst: InstId,
        port: Port,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.demand_fixpoint_call_port_summary(func, inst, port, direction, max_depth, max_visits) else {
            return false;
        };
        summary
            .values
            .iter()
            .any(|(summary_func, summary_value)| *summary_func == dst_func.0 && *summary_value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(summary_func, _index, summary_value)| *summary_func == dst_func.0 && *summary_value == dst_value.0)
    }

    pub fn resolve_demand_seed_nodes(&self, seeds: &[DemandSeed]) -> Vec<NodeIndex> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for seed in seeds {
            match seed {
                DemandSeed::Node(index) => {
                    if *index < self.graph.node_count() {
                        let node = NodeIndex::new(*index);
                        if seen.insert(node.index()) {
                            out.push(node);
                        }
                    }
                }
                DemandSeed::Value { func, value } => {
                    if let Some(node) = self.values.get(&(FunctionId(*func), ValueId(*value))).copied() {
                        if seen.insert(node.index()) {
                            out.push(node);
                        }
                    }
                }
                DemandSeed::Call { func, inst } => {
                    let mut call_nodes = self
                        .call_ports
                        .iter()
                        .filter_map(|((call_func, call_inst, _), node)| {
                            (*call_func == FunctionId(*func) && *call_inst == InstId(*inst)).then_some(*node)
                        })
                        .collect::<Vec<_>>();
                    call_nodes.sort_unstable_by_key(|node| node.index());
                    call_nodes.dedup();
                    for node in call_nodes {
                        if seen.insert(node.index()) {
                            out.push(node);
                        }
                    }
                }
                DemandSeed::CallPort { func, inst, port } => {
                    if let Some(node) = self.call_ports.get(&(FunctionId(*func), InstId(*inst), port.clone())).copied() {
                        if seen.insert(node.index()) {
                            out.push(node);
                        }
                    }
                }
            }
        }
        out.sort_unstable_by_key(|node| node.index());
        out.dedup_by_key(|node| node.index());
        out
    }

    pub fn demand_query_summary(
        &self,
        query: &DemandQuery,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let key = (query.clone(), max_depth, max_visits);
        if let Some(cached) = self.demand_query_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let seeds = self.resolve_demand_seed_nodes(&query.seeds);
        if seeds.is_empty() {
            return None;
        }
        let traversal = match query.engine {
            DemandEngine::Sparse => self.demand_query_traversal(&seeds, query.direction, max_depth, max_visits, query.include_heap),
            DemandEngine::Fixpoint => self.demand_query_fixpoint_traversal(&seeds, query.direction, max_depth, max_visits, query.include_heap),
        };
        let summary = self.summarize_sparse_traversal(traversal);
        self.demand_query_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn demand_query_reachable_values(
        &self,
        query: &DemandQuery,
        max_depth: usize,
        max_visits: usize,
    ) -> Vec<(FunctionId, ValueId)> {
        self.demand_query_summary(query, max_depth, max_visits)
            .map(|summary| {
                summary
                    .values
                    .into_iter()
                    .map(|(func, value)| (FunctionId(func), ValueId(value)))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub fn demand_query_reaches_value(
        &self,
        query: &DemandQuery,
        dst_func: FunctionId,
        dst_value: ValueId,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.demand_query_summary(query, max_depth, max_visits) else {
            return false;
        };
        summary
            .values
            .iter()
            .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
    }

    pub fn demand_query_reaches_any_value(
        &self,
        query: &DemandQuery,
        targets: &[(FunctionId, ValueId)],
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.demand_query_summary(query, max_depth, max_visits) else {
            return false;
        };
        targets.iter().any(|(dst_func, dst_value)| {
            summary
                .values
                .iter()
                .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
                || summary
                    .params
                    .iter()
                    .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
        })
    }

    fn call_port_source_values(&self, port_node: NodeIndex) -> Vec<(FunctionId, ValueId)> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for edge in self.graph.edges_directed(port_node, petgraph::Direction::Incoming) {
            if !matches!(edge.weight().kind, EdgeKind::ValueToCallPort) {
                continue;
            }
            if let FlowNode::Value { func, value } = self.graph[edge.source()] {
                if seen.insert((func, value)) {
                    out.push((func, value));
                }
            }
        }
        out.sort_unstable();
        out
    }

    fn function_param_arity(&self, func: FunctionId) -> usize {
        self.function_params
            .keys()
            .filter_map(|(summary_func, index)| (*summary_func == func).then_some(*index))
            .max()
            .map(|max_index| max_index + 1)
            .unwrap_or(0)
    }

    fn candidate_function_matches_call_signature(&self, candidate_func: FunctionId, meta: &CallMeta) -> bool {
        let arity = self.function_param_arity(candidate_func);
        if arity != 0 && !(arity == meta.arg_count || arity == meta.arg_count + 1 || arity + 1 == meta.arg_count) {
            return false;
        }
        if let Some(callee_name) = meta.callee_name.as_ref() {
            if let Some(candidate_name) = self.function_names.get(&candidate_func) {
                if candidate_name != callee_name && !candidate_name.ends_with(&format!(".{callee_name}")) {
                    return false;
                }
            }
        }
        true
    }

    fn exact_callee_ids_for_call(&self, func: FunctionId, inst: InstId) -> Vec<FunctionId> {
        let mut out = BTreeSet::new();
        for ((call_func, call_inst, _port), node) in &self.call_ports {
            if *call_func != func || *call_inst != inst {
                continue;
            }
            for edge in self.graph.edges_directed(*node, petgraph::Direction::Outgoing) {
                if !matches!(edge.weight().kind, EdgeKind::ActualToFormal) {
                    continue;
                }
                if let FlowNode::Param { func: callee_func, .. } = self.graph[edge.target()] {
                    out.insert(callee_func);
                }
            }
        }
        out.into_iter().collect()
    }

    fn refine_call_context_for_sensitivity(
        &self,
        mut context: CallContextKey,
        sensitivity: ContextSensitivity,
    ) -> CallContextKey {
        match sensitivity {
            ContextSensitivity::None => CallContextKey::default(),
            ContextSensitivity::CallSite => {
                context.receiver_classes.clear();
                context.receiver_shapes.clear();
                context.arg_classes.clear();
                context.arg_shapes.clear();
                context
            }
            ContextSensitivity::Receiver => {
                context.arg_classes.clear();
                context.arg_shapes.clear();
                context.call_sites.clear();
                context
            }
            ContextSensitivity::ReceiverAndArgs => {
                context.call_sites.clear();
                context
            }
            ContextSensitivity::CallString2 => context,
            ContextSensitivity::ReceiverArgsAndCallSite => context,
        }
    }

    fn node_matches_structural_call_context(&self, node: NodeIndex, context: &CallContextKey) -> bool {
        let allowed_funcs = context
            .callee_funcs
            .iter()
            .copied()
            .map(FunctionId)
            .chain(context.call_sites.iter().map(|(func, _)| FunctionId(*func)))
            .collect::<BTreeSet<_>>();
        let allowed_sites = context.call_sites.iter().copied().collect::<BTreeSet<_>>();
        match &self.graph[node] {
            FlowNode::Value { func, .. }
            | FlowNode::Param { func, .. }
            | FlowNode::Return { func }
            | FlowNode::FieldCell { func, .. }
            | FlowNode::IndexCell { func, .. } => {
                allowed_funcs.is_empty() || allowed_funcs.contains(func)
            }
            FlowNode::CallPort { func, inst, .. }
            | FlowNode::SyntheticSource { func, inst, .. }
            | FlowNode::SyntheticSink { func, inst, .. } => {
                allowed_sites.is_empty() || allowed_sites.contains(&(func.0, inst.0))
            }
        }
    }

    fn node_matches_call_context(&self, node: NodeIndex, context: &CallContextKey) -> bool {
        if !self.node_matches_structural_call_context(node, context) {
            return false;
        }
        let contextual_node_targets = self.contextual_node_points_to_targets_of(context, node);
        if !contextual_node_targets.is_empty() {
            let node_targets = self.node_points_to_targets_of(node);
            if !node_targets.is_empty() && !points_to_targets_overlap(&contextual_node_targets, &node_targets) {
                match &self.graph[node] {
                    FlowNode::CallPort { .. } | FlowNode::Return { .. } => {}
                    _ => return false,
                }
            }
        } else if let Some(context_targets) = self.contextual_points_to_targets.get(context) {
            let node_targets = self.node_points_to_targets_of(node);
            if !context_targets.is_empty() && !node_targets.is_empty() && !points_to_targets_overlap(context_targets, &node_targets) {
                match &self.graph[node] {
                    FlowNode::CallPort { .. } | FlowNode::Return { .. } => {}
                    _ => return false,
                }
            }
        }
        let contextual_node_object_ids = self.contextual_node_points_to_object_ids_of(context, node);
        if !contextual_node_object_ids.is_empty() {
            let node_object_ids = self.node_points_to_object_ids_of(node);
            if !node_object_ids.is_empty() && !points_to_object_ids_overlap(&contextual_node_object_ids, &node_object_ids) {
                match &self.graph[node] {
                    FlowNode::CallPort { .. } | FlowNode::Return { .. } => {}
                    _ => return false,
                }
            }
        } else if let Some(context_object_ids) = self.contextual_points_to_object_ids.get(context) {
            let node_object_ids = self.node_points_to_object_ids_of(node);
            if !context_object_ids.is_empty() && !node_object_ids.is_empty() && !points_to_object_ids_overlap(context_object_ids, &node_object_ids) {
                match &self.graph[node] {
                    FlowNode::CallPort { .. } | FlowNode::Return { .. } => {}
                    _ => return false,
                }
            }
        }
        true
    }

    fn filter_sparse_summary_to_context(
        &self,
        mut summary: SparseValueSummary,
        context: &CallContextKey,
    ) -> SparseValueSummary {
        let callee_funcs = context
            .callee_funcs
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let call_sites = context.call_sites.iter().copied().collect::<BTreeSet<_>>();
        if !callee_funcs.is_empty() {
            summary
                .params
                .retain(|(func, _, _)| callee_funcs.contains(func));
        }
        if !call_sites.is_empty() {
            summary
                .call_ports
                .retain(|(func, inst, _)| call_sites.contains(&(*func, *inst)));
        }
        if !call_sites.is_empty() {
            summary.traversal.visited.retain(|idx| self.node_matches_call_context(NodeIndex::new(*idx), context));
            for layer in &mut summary.traversal.layers {
                layer.retain(|idx| self.node_matches_call_context(NodeIndex::new(*idx), context));
            }
            summary.traversal.layers.retain(|layer| !layer.is_empty());
            if !callee_funcs.is_empty() {
                let caller_funcs = call_sites.iter().map(|(func, _)| *func).collect::<BTreeSet<_>>();
                summary.values.retain(|(func, _)| caller_funcs.contains(func) || callee_funcs.contains(func));
            }
        }
        summary
    }

    pub fn call_context_key(&self, func: FunctionId, inst: InstId) -> Option<CallContextKey> {
        let callee_funcs = self.exact_callee_ids_for_call(func, inst);
        let mut callee_names = callee_funcs
            .iter()
            .filter_map(|callee_func| self.function_names.get(callee_func).cloned())
            .collect::<Vec<_>>();
        callee_names.sort();
        callee_names.dedup();

        let mut receiver_classes = BTreeSet::new();
        let mut receiver_shapes = BTreeSet::new();
        let mut arg_classes = BTreeMap::<usize, BTreeSet<String>>::new();
        let mut arg_shapes = BTreeMap::<usize, BTreeSet<String>>::new();
        for ((call_func, call_inst, port), node) in &self.call_ports {
            if *call_func != func || *call_inst != inst {
                continue;
            }
            let mut port_classes = self.node_points_to_classes_of(*node);
            let mut port_shapes = self.object_shape_paths_of(*node);
            port_shapes.extend(self.node_memory_regions_of(*node));
            let sources = self.call_port_source_values(*node);
            for (src_func, src_value) in sources {
                if port_classes.is_empty() {
                    port_classes.extend(self.value_points_to_classes_of(src_func, src_value));
                }
                let src_node = value_node(self, src_func, src_value);
                port_shapes.extend(self.object_shape_paths_of(src_node));
                port_shapes.extend(self.value_memory_regions_of(src_func, src_value));
            }
            // Context identity must be stable across later heap/region materialization.
            // Wildcard index projections are derived conservative aliases rather than
            // intrinsic receiver/argument shapes; including them makes the same call
            // site acquire a different key after the heap bridge is built.
            port_shapes.retain(|shape| !shape.contains("[*") && shape != "mem:[*");
            port_classes.sort();
            port_classes.dedup();
            port_shapes.sort();
            port_shapes.dedup();
            match port {
                Port::Receiver => {
                    for class in port_classes {
                        receiver_classes.insert(class);
                    }
                    for shape in port_shapes {
                        receiver_shapes.insert(shape);
                    }
                }
                Port::Arg(index) => {
                    let class_entry = arg_classes.entry(*index).or_default();
                    for class in port_classes {
                        class_entry.insert(class);
                    }
                    let shape_entry = arg_shapes.entry(*index).or_default();
                    for shape in port_shapes {
                        shape_entry.insert(shape);
                    }
                }
                _ => {}
            }
        }

        if callee_names.is_empty() && callee_funcs.is_empty() && receiver_classes.is_empty() && receiver_shapes.is_empty() && arg_classes.is_empty() && arg_shapes.is_empty() {
            return None;
        }

        let max_arg = arg_classes
            .keys()
            .chain(arg_shapes.keys())
            .copied()
            .max();
        let (arg_classes, arg_shapes) = if let Some(max_arg) = max_arg {
            (
                (0..=max_arg)
                    .map(|index| arg_classes.remove(&index).map(|values| values.into_iter().collect()).unwrap_or_default())
                    .collect::<Vec<Vec<String>>>(),
                (0..=max_arg)
                    .map(|index| arg_shapes.remove(&index).map(|values| values.into_iter().collect()).unwrap_or_default())
                    .collect::<Vec<Vec<String>>>(),
            )
        } else {
            (Vec::new(), Vec::new())
        };

        Some(CallContextKey {
            callee_names,
            callee_funcs: callee_funcs.iter().map(|func| func.0).collect(),
            receiver_classes: receiver_classes.into_iter().collect(),
            receiver_shapes: receiver_shapes.into_iter().collect(),
            arg_classes,
            arg_shapes,
            call_sites: vec![(func.0, inst.0)],
        })
    }

    pub fn contextual_call_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        sensitivity: ContextSensitivity,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        if matches!(sensitivity, ContextSensitivity::None) {
            return self.demand_call_summary(func, inst, direction, max_depth, max_visits);
        }
        let context = self.refine_call_context_for_sensitivity(self.call_context_key(func, inst)?, sensitivity);
        let key = (context.clone(), direction, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self.contextual_call_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let seeds = self.resolve_demand_seed_nodes(&[DemandSeed::Call { func: func.0, inst: inst.0 }]);
        if seeds.is_empty() {
            return None;
        }
        let traversal = match engine {
            DemandEngine::Sparse => self.contextual_demand_query_traversal(&seeds, direction, max_depth, max_visits, include_heap, &context),
            DemandEngine::Fixpoint => self.contextual_demand_query_fixpoint_traversal(&seeds, direction, max_depth, max_visits, include_heap, &context),
        };
        let summary = self.filter_sparse_summary_to_context(self.summarize_sparse_traversal(traversal), &context);
        self.contextual_call_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn contextual_call_reaches_value(
        &self,
        func: FunctionId,
        inst: InstId,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> bool {
        let Some(summary) = self.contextual_call_summary(
            func,
            inst,
            ContextSensitivity::ReceiverArgsAndCallSite,
            direction,
            max_depth,
            max_visits,
            engine,
            include_heap,
        ) else {
            return false;
        };
        summary
            .values
            .iter()
            .any(|(func_id, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func_id, _index, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
    }

    pub fn function_param_summary(
        &self,
        func: FunctionId,
        index: usize,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        let key = (
            func.0,
            format!("param:{index}"),
            direction,
            max_depth,
            max_visits,
            engine,
            include_heap,
        );
        if let Some(cached) = self.function_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let node = self.function_params.get(&(func, index)).copied()?;
        let query = DemandQuery {
            seeds: vec![DemandSeed::Node(node.index())],
            direction,
            engine,
            include_heap,
        };
        let summary = self.demand_query_summary(&query, max_depth, max_visits)?;
        self.function_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn function_return_summary(
        &self,
        func: FunctionId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        let key = (
            func.0,
            "return".to_string(),
            direction,
            max_depth,
            max_visits,
            engine,
            include_heap,
        );
        if let Some(cached) = self.function_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let node = self.function_returns.get(&func).copied()?;
        let query = DemandQuery {
            seeds: vec![DemandSeed::Node(node.index())],
            direction,
            engine,
            include_heap,
        };
        let summary = self.demand_query_summary(&query, max_depth, max_visits)?;
        self.function_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    fn call_seed_contexts(&self, seeds: &[DemandSeed], sensitivity: ContextSensitivity) -> Vec<CallContextKey> {
        if matches!(sensitivity, ContextSensitivity::None) {
            return Vec::new();
        }
        let mut contexts = seeds
            .iter()
            .filter_map(|seed| match seed {
                DemandSeed::Call { func, inst } | DemandSeed::CallPort { func, inst, .. } => {
                    self.call_context_key(FunctionId(*func), InstId(*inst))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        contexts.sort();
        contexts.dedup();
        for context in &mut contexts {
            *context = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        }
        if matches!(sensitivity, ContextSensitivity::CallString2) {
            let mut all_sites = contexts.iter().flat_map(|ctx| ctx.call_sites.clone()).collect::<Vec<_>>();
            all_sites.sort();
            all_sites.dedup();
            if all_sites.len() > 2 {
                all_sites = all_sites[all_sites.len().saturating_sub(2)..].to_vec();
            }
            for context in &mut contexts {
                context.call_sites = all_sites.clone();
            }
        }
        contexts.sort();
        contexts.dedup();
        contexts
    }

    fn intersect_sparse_summaries(
        &self,
        mut base: SparseValueSummary,
        filter: &SparseValueSummary,
    ) -> SparseValueSummary {
        let visited = filter.traversal.visited.iter().copied().collect::<HashSet<_>>();
        if !visited.is_empty() {
            base.traversal.visited.retain(|idx| visited.contains(idx));
            for layer in &mut base.traversal.layers {
                layer.retain(|idx| visited.contains(idx));
            }
            base.traversal.layers.retain(|layer| !layer.is_empty());
        }
        let values = filter.values.iter().copied().collect::<HashSet<_>>();
        if !values.is_empty() {
            base.values.retain(|value| values.contains(value));
        }
        let params = filter.params.iter().copied().collect::<HashSet<_>>();
        if !params.is_empty() {
            base.params.retain(|value| params.contains(value));
        }
        let call_ports = filter.call_ports.iter().cloned().collect::<HashSet<_>>();
        if !call_ports.is_empty() {
            base.call_ports.retain(|value| call_ports.contains(value));
        }
        base
    }


    fn union_sparse_summaries(
        &self,
        summaries: impl IntoIterator<Item = SparseValueSummary>,
    ) -> Option<SparseValueSummary> {
        let mut iter = summaries.into_iter();
        let mut base = iter.next()?;
        let mut visited = base.traversal.visited.iter().copied().collect::<BTreeSet<_>>();
        let mut values = base.values.iter().copied().collect::<BTreeSet<_>>();
        let mut params = base.params.iter().copied().collect::<BTreeSet<_>>();
        let mut call_ports = base.call_ports.iter().cloned().collect::<BTreeSet<_>>();
        let mut layer_nodes = base
            .traversal
            .layers
            .iter()
            .flat_map(|layer| layer.iter().copied())
            .collect::<BTreeSet<_>>();
        for summary in iter {
            visited.extend(summary.traversal.visited.iter().copied());
            values.extend(summary.values.iter().copied());
            params.extend(summary.params.iter().copied());
            call_ports.extend(summary.call_ports.iter().cloned());
            layer_nodes.extend(summary.traversal.layers.iter().flat_map(|layer| layer.iter().copied()));
            base.traversal.frontier_cutoff |= summary.traversal.frontier_cutoff;
            base.traversal.completeness = merge_query_completeness(
                base.traversal.completeness,
                summary.traversal.completeness,
            );
        }
        base.traversal.visited = visited.into_iter().collect();
        base.traversal.layers = if layer_nodes.is_empty() {
            Vec::new()
        } else {
            vec![layer_nodes.into_iter().collect()]
        };
        base.values = values.into_iter().collect();
        base.params = params.into_iter().collect();
        base.call_ports = call_ports.into_iter().collect();
        Some(base)
    }

    pub fn recommended_context_sensitivity(&self, query: &DemandQuery) -> ContextSensitivity {
        let mut has_callsite = false;
        let mut has_receiver = false;
        let mut arg_count = 0usize;
        let mut has_shape_rich_context = false;
        for seed in &query.seeds {
            match seed {
                DemandSeed::Call { func, inst } => {
                    has_callsite = true;
                    if let Some(ctx) = self.call_context_key(FunctionId(*func), InstId(*inst)) {
                        has_shape_rich_context |= !ctx.receiver_shapes.is_empty() || ctx.arg_shapes.iter().any(|paths| !paths.is_empty());
                    }
                }
                DemandSeed::CallPort { func, inst, port } => {
                    has_callsite = true;
                    if let Some(ctx) = self.call_context_key(FunctionId(*func), InstId(*inst)) {
                        has_shape_rich_context |= !ctx.receiver_shapes.is_empty() || ctx.arg_shapes.iter().any(|paths| !paths.is_empty());
                    }
                    match port {
                        Port::Receiver => has_receiver = true,
                        Port::Arg(_) => arg_count += 1,
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if has_callsite && has_shape_rich_context {
            ContextSensitivity::ReceiverArgsAndCallSite
        } else if query.include_heap && has_receiver && arg_count > 0 {
            ContextSensitivity::ReceiverArgsAndCallSite
        } else if has_callsite && has_receiver {
            ContextSensitivity::ReceiverArgsAndCallSite
        } else if has_callsite && arg_count > 1 {
            ContextSensitivity::CallString2
        } else if has_callsite {
            ContextSensitivity::CallSite
        } else if query.include_heap {
            ContextSensitivity::ReceiverAndArgs
        } else {
            ContextSensitivity::None
        }
    }

    pub fn recommended_demand_engine(&self, query: &DemandQuery) -> DemandEngine {
        let has_call_seed = query.seeds.iter().any(|seed| matches!(seed, DemandSeed::Call { .. } | DemandSeed::CallPort { .. }));
        let has_node_seed = query.seeds.iter().any(|seed| matches!(seed, DemandSeed::Node(_)));
        if query.include_heap || has_call_seed {
            DemandEngine::Fixpoint
        } else if query.direction == SparseDirection::Backward && (query.seeds.len() > 1 || has_node_seed) {
            DemandEngine::Fixpoint
        } else {
            DemandEngine::Sparse
        }
    }

    pub fn recommended_budget_profile(&self, query: &DemandQuery) -> QueryBudgetProfile {
        let has_call_seed = query.seeds.iter().any(|seed| matches!(seed, DemandSeed::Call { .. } | DemandSeed::CallPort { .. }));
        let has_node_seed = query.seeds.iter().any(|seed| matches!(seed, DemandSeed::Node(_)));
        let has_shape_rich_context = query.seeds.iter().any(|seed| match seed {
            DemandSeed::Call { func, inst } => self
                .call_context_key(FunctionId(*func), InstId(*inst))
                .map(|ctx| !ctx.receiver_shapes.is_empty() || ctx.arg_shapes.iter().any(|paths| !paths.is_empty()))
                .unwrap_or(false),
            DemandSeed::CallPort { func, inst, .. } => self
                .call_context_key(FunctionId(*func), InstId(*inst))
                .map(|ctx| !ctx.receiver_shapes.is_empty() || ctx.arg_shapes.iter().any(|paths| !paths.is_empty()))
                .unwrap_or(false),
            _ => false,
        });
        if query.include_heap && has_call_seed && has_shape_rich_context {
            QueryBudgetProfile::Exhaustive
        } else if query.include_heap && has_call_seed {
            QueryBudgetProfile::Deep
        } else if query.include_heap || has_call_seed || has_node_seed {
            QueryBudgetProfile::Standard
        } else {
            QueryBudgetProfile::Light
        }
    }

    pub fn recommended_query_limits(&self, query: &DemandQuery) -> (usize, usize) {
        match self.recommended_budget_profile(query) {
            QueryBudgetProfile::Light => {
                if query.direction == SparseDirection::Backward {
                    (14, 4096)
                } else {
                    (10, 2048)
                }
            }
            QueryBudgetProfile::Standard => (18, 8192),
            QueryBudgetProfile::Deep => (24, 16384),
            QueryBudgetProfile::Exhaustive => (28, 24576),
        }
    }

    pub fn solver_plan_for_query(&self, query: &DemandQuery) -> SolverPlan {
        let mut planned = query.clone();
        planned.engine = self.recommended_demand_engine(query);
        let context_sensitivity = self.recommended_context_sensitivity(&planned);
        let budget_profile = self.recommended_budget_profile(&planned);
        let (max_depth, max_visits) = self.recommended_query_limits(&planned);
        SolverPlan {
            query: planned,
            context_sensitivity,
            budget_profile,
            max_depth,
            max_visits,
        }
    }

    pub fn execute_solver_plan(&self, plan: &SolverPlan) -> Option<SparseValueSummary> {
        if matches!(plan.context_sensitivity, ContextSensitivity::None) {
            self.demand_query_summary(&plan.query, plan.max_depth, plan.max_visits)
        } else {
            self.contextual_demand_query_summary(
                &plan.query,
                plan.context_sensitivity,
                plan.max_depth,
                plan.max_visits,
            )
        }
    }

    pub fn solver_reaches_value(&self, plan: &SolverPlan, dst_func: FunctionId, dst_value: ValueId) -> bool {
        let Some(summary) = self.execute_solver_plan(plan) else {
            return false;
        };
        summary.values.iter().any(|(func_id, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
            || summary.params.iter().any(|(func_id, _index, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
    }

    pub fn solver_reaches_any_value(&self, plan: &SolverPlan, targets: &[(FunctionId, ValueId)]) -> bool {
        let Some(summary) = self.execute_solver_plan(plan) else {
            return false;
        };
        let targets = targets.iter().map(|(func, value)| (func.0, value.0)).collect::<HashSet<_>>();
        summary.values.iter().any(|pair| targets.contains(pair))
            || summary.params.iter().any(|(func, _index, value)| targets.contains(&(*func, *value)))
    }

    pub fn demand_query_summary_auto(&self, query: &DemandQuery) -> Option<SparseValueSummary> {
        let plan = self.solver_plan_for_query(query);
        self.execute_solver_plan(&plan)
    }

    pub fn demand_query_reaches_value_auto(
        &self,
        query: &DemandQuery,
        dst_func: FunctionId,
        dst_value: ValueId,
    ) -> bool {
        let Some(summary) = self.demand_query_summary_auto(query) else {
            return false;
        };
        summary.values.iter().any(|(func_id, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
            || summary.params.iter().any(|(func_id, _index, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
    }

    pub fn demand_query_reaches_any_value_auto(
        &self,
        query: &DemandQuery,
        targets: &[(FunctionId, ValueId)],
    ) -> bool {
        let Some(summary) = self.demand_query_summary_auto(query) else {
            return false;
        };
        let targets = targets.iter().map(|(func, value)| (func.0, value.0)).collect::<HashSet<_>>();
        summary.values.iter().any(|pair| targets.contains(pair))
            || summary.params.iter().any(|(func, _index, value)| targets.contains(&(*func, *value)))
    }

    pub fn contextual_demand_query_summary_auto(
        &self,
        query: &DemandQuery,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let mut plan = self.solver_plan_for_query(query);
        plan.max_depth = plan.max_depth.max(max_depth);
        plan.max_visits = plan.max_visits.max(max_visits);
        self.execute_solver_plan(&plan)
    }

    pub fn contextual_demand_query_reaches_value_auto(
        &self,
        query: &DemandQuery,
        dst_func: FunctionId,
        dst_value: ValueId,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let sensitivity = self.recommended_context_sensitivity(query);
        self.contextual_demand_query_reaches_value(query, sensitivity, dst_func, dst_value, max_depth, max_visits)
    }

    pub fn contextual_demand_query_summary(
        &self,
        query: &DemandQuery,
        sensitivity: ContextSensitivity,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        if matches!(sensitivity, ContextSensitivity::None) {
            return self.demand_query_summary(query, max_depth, max_visits);
        }
        let contexts = self.call_seed_contexts(&query.seeds, sensitivity);
        let key = (query.clone(), sensitivity, contexts.clone(), max_depth, max_visits);
        if let Some(cached) = self.contextual_demand_query_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let seeds = self.resolve_demand_seed_nodes(&query.seeds);
        if seeds.is_empty() {
            return None;
        }
        let summary = if contexts.is_empty() {
            self.demand_query_summary(query, max_depth, max_visits)?
        } else {
            let mut contextual_summaries = Vec::new();
            for context in contexts {
                let traversal = match query.engine {
                    DemandEngine::Sparse => self.contextual_demand_query_traversal(&seeds, query.direction, max_depth, max_visits, query.include_heap, &context),
                    DemandEngine::Fixpoint => self.contextual_demand_query_fixpoint_traversal(&seeds, query.direction, max_depth, max_visits, query.include_heap, &context),
                };
                contextual_summaries.push(self.filter_sparse_summary_to_context(self.summarize_sparse_traversal(traversal), &context));
            }
            self.union_sparse_summaries(contextual_summaries)?
        };
        self.contextual_demand_query_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn contextual_demand_query_reaches_value(
        &self,
        query: &DemandQuery,
        sensitivity: ContextSensitivity,
        dst_func: FunctionId,
        dst_value: ValueId,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.contextual_demand_query_summary(query, sensitivity, max_depth, max_visits) else {
            return false;
        };
        summary.values.iter().any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
    }

    pub fn function_transfer_summary(
        &self,
        func: FunctionId,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<FunctionTransferSummary> {
        let key = (func.0, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self.function_transfer_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let backward_return = self.function_return_summary(
            func,
            SparseDirection::Backward,
            max_depth,
            max_visits,
            engine,
            include_heap,
        )?;
        let mut return_reachable_params = backward_return
            .params
            .iter()
            .filter_map(|(summary_func, index, _value)| (*summary_func == func.0).then_some(*index))
            .collect::<Vec<_>>();
        return_reachable_params.sort_unstable();
        return_reachable_params.dedup();

        let mut param_indices = self
            .function_params
            .keys()
            .filter_map(|(summary_func, index)| (*summary_func == func).then_some(*index))
            .collect::<Vec<_>>();
        param_indices.sort_unstable();
        param_indices.dedup();

        let mut param_to_param = BTreeSet::new();
        let mut param_forward_summaries = BTreeMap::new();
        for index in &param_indices {
            if let Some(summary) = self.function_param_summary(
                func,
                *index,
                SparseDirection::Forward,
                max_depth,
                max_visits,
                engine,
                include_heap,
            ) {
                for (summary_func, target_index, _value) in &summary.params {
                    if *summary_func == func.0 && *target_index != *index {
                        param_to_param.insert((*index, *target_index));
                    }
                }
                param_forward_summaries.insert(*index, summary);
            }
        }

        let mut return_values = backward_return
            .values
            .iter()
            .copied()
            .filter(|(summary_func, _value)| *summary_func == func.0)
            .collect::<Vec<_>>();
        return_values.sort_unstable();
        return_values.dedup();

        let return_value_set = return_values.iter().copied().collect::<BTreeSet<_>>();
        let mut param_to_return_values = BTreeSet::new();
        for (index, summary) in &param_forward_summaries {
            for (summary_func, summary_value) in &summary.values {
                if return_value_set.contains(&(*summary_func, *summary_value)) {
                    param_to_return_values.insert((*index, *summary_func, *summary_value));
                }
            }
        }

        let summary = FunctionTransferSummary {
            func: func.0,
            return_reachable_params,
            param_to_param: param_to_param.into_iter().collect(),
            param_to_return_values: param_to_return_values.into_iter().collect(),
            return_values,
        };
        self.function_transfer_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    fn contextual_function_param_summary(
        &self,
        func: FunctionId,
        index: usize,
        context: &CallContextKey,
        sensitivity: ContextSensitivity,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        let refined = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        let node = self.function_params.get(&(func, index)).copied()?;
        let seeds = vec![node];
        let traversal = match engine {
            DemandEngine::Sparse => self.contextual_demand_query_traversal(&seeds, direction, max_depth, max_visits, include_heap, &refined),
            DemandEngine::Fixpoint => self.contextual_demand_query_fixpoint_traversal(&seeds, direction, max_depth, max_visits, include_heap, &refined),
        };
        Some(self.filter_sparse_summary_to_context(self.summarize_sparse_traversal(traversal), &refined))
    }

    fn contextual_function_return_summary(
        &self,
        func: FunctionId,
        context: &CallContextKey,
        sensitivity: ContextSensitivity,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        let refined = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        let node = self.function_returns.get(&func).copied()?;
        let seeds = vec![node];
        let traversal = match engine {
            DemandEngine::Sparse => self.contextual_demand_query_traversal(&seeds, direction, max_depth, max_visits, include_heap, &refined),
            DemandEngine::Fixpoint => self.contextual_demand_query_fixpoint_traversal(&seeds, direction, max_depth, max_visits, include_heap, &refined),
        };
        Some(self.filter_sparse_summary_to_context(self.summarize_sparse_traversal(traversal), &refined))
    }

    pub fn contextual_function_transfer_summary(
        &self,
        func: FunctionId,
        context: &CallContextKey,
        sensitivity: ContextSensitivity,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<FunctionTransferSummary> {
        let refined = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        let key = (
            func.0,
            refined,
            sensitivity,
            max_depth,
            max_visits,
            engine,
            include_heap,
        );
        if let Some(cached) = self
            .contextual_function_transfer_summary_cache
            .borrow()
            .get(&key)
            .cloned()
        {
            return Some(cached);
        }

        // Transfer relations are computed from the converged callee graph. Context selects and
        // caches the applicable summary; it must not recursively rebuild the same demand closure.
        let summary = self.function_transfer_summary(
            func,
            max_depth,
            max_visits,
            engine,
            include_heap,
        )?;
        self.contextual_function_transfer_summary_cache
            .borrow_mut()
            .insert(key, summary.clone());
        Some(summary)
    }

    pub fn function_heap_effect_summary(
        &self,
        func: FunctionId,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<FunctionHeapEffectSummary> {
        let key = (func.0, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self.function_heap_effect_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let transfer = self.function_transfer_summary(func, max_depth, max_visits, engine, include_heap)?;
        let mut param_indices = self
            .function_params
            .keys()
            .filter_map(|(summary_func, index)| (*summary_func == func).then_some(*index))
            .collect::<Vec<_>>();
        param_indices.sort_unstable();
        param_indices.dedup();

        let mut param_to_read_regions = BTreeSet::new();
        let mut param_to_read_paths = BTreeSet::new();
        let mut param_to_read_cells = BTreeSet::new();
        let mut param_to_read_objects = BTreeSet::new();
        let mut param_to_write_regions = BTreeSet::new();
        let mut param_to_write_paths = BTreeSet::new();
        let mut param_to_write_cells = BTreeSet::new();
        let mut param_to_write_objects = BTreeSet::new();
        let mut param_to_return_regions = BTreeSet::new();
        let mut param_to_return_paths = BTreeSet::new();
        let mut param_to_return_cells = BTreeSet::new();
        let mut param_to_return_objects = BTreeSet::new();
        let mut param_to_return_live_values = BTreeSet::new();
        let mut return_regions = BTreeSet::new();
        let mut return_paths = BTreeSet::new();
        let mut return_cells = BTreeSet::new();
        let mut return_objects = BTreeSet::new();
        let mut return_value_regions = BTreeSet::new();
        let mut return_value_paths = BTreeSet::new();
        let mut return_value_cells = BTreeSet::new();
        let mut return_value_objects = BTreeSet::new();
        let mut return_live_values = BTreeSet::new();

        for (summary_func, summary_value) in &transfer.return_values {
            if *summary_func != func.0 {
                continue;
            }
            let value_func = FunctionId(*summary_func);
            let value_id = ValueId(*summary_value);
            let root_regions = value_root_memory_regions(self, value_func, value_id);
            for region in self.value_memory_regions_of(value_func, value_id) {
                return_regions.insert(region.clone());
                return_value_regions.insert((*summary_func, *summary_value, region.clone()));
                for path in region_relative_access_paths(&root_regions, &region) {
                    return_paths.insert(path.clone());
                    return_value_paths.insert((*summary_func, *summary_value, path));
                }
            }
            for object_id in self.value_points_to_object_ids_of(value_func, value_id) {
                return_objects.insert(object_id);
                return_value_objects.insert((*summary_func, *summary_value, object_id));
            }
            for cell in cell_candidates_for_value_targets(self, value_func, value_id) {
                return_cells.insert(cell.index() as u32);
                return_value_cells.insert((*summary_func, *summary_value, cell.index() as u32));
            }
        }

        for index in &param_indices {
            let Some(summary) = self.function_param_summary(
                func,
                *index,
                SparseDirection::Forward,
                max_depth,
                max_visits,
                engine,
                include_heap,
            ) else {
                continue;
            };
            let reachable_values = summary.values.iter().copied().collect::<BTreeSet<_>>();
            let reachable_params = summary
                .params
                .iter()
                .map(|(f, _i, v)| (*f, *v))
                .collect::<BTreeSet<_>>();
            let Some(&param_node) = self.function_params.get(&(func, *index)) else {
                continue;
            };
            let param_value = match &self.graph[param_node] {
                FlowNode::Param { value, .. } => *value,
                _ => continue,
            };
            let param_root_regions = value_root_memory_regions(self, func, param_value);
            for visited in &summary.traversal.visited {
                let node = NodeIndex::new(*visited);
                match &self.graph[node] {
                    FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                        for region in self.cell_memory_regions_of(node) {
                            param_to_read_regions.insert((*index, region.clone()));
                            for path in region_relative_access_paths(&param_root_regions, &region) {
                                param_to_read_paths.insert((*index, path));
                            }
                        }
                        param_to_read_cells.insert((*index, node.index() as u32));
                        for object_id in self.cell_points_to_object_ids_of(node) {
                            param_to_read_objects.insert((*index, object_id));
                        }
                        let writes = self
                            .cell_live_values_of(node)
                            .into_iter()
                            .chain(cell_store_values(self, node).into_iter())
                            .map(|(f, v)| (f.0, v.0))
                            .collect::<BTreeSet<_>>();
                        if !writes.is_empty()
                            && (writes.iter().any(|pair| reachable_values.contains(pair))
                                || writes.iter().any(|pair| reachable_params.contains(pair)))
                        {
                            for region in self.cell_memory_regions_of(node) {
                                param_to_write_regions.insert((*index, region.clone()));
                                for path in region_relative_access_paths(&param_root_regions, &region) {
                                    param_to_write_paths.insert((*index, path));
                                }
                            }
                            param_to_write_cells.insert((*index, node.index() as u32));
                            for object_id in self.cell_points_to_object_ids_of(node) {
                                param_to_write_objects.insert((*index, object_id));
                            }
                        }
                    }
                    _ => {}
                }
            }
            for (from_index, summary_func, summary_value) in &transfer.param_to_return_values {
                if *from_index != *index {
                    continue;
                }
                let value_func = FunctionId(*summary_func);
                let value_id = ValueId(*summary_value);
                for region in self.value_memory_regions_of(value_func, value_id) {
                    param_to_return_regions.insert((*index, region.clone()));
                    for path in region_relative_access_paths(&param_root_regions, &region) {
                        param_to_return_paths.insert((*index, path));
                    }
                }
                for object_id in self.value_points_to_object_ids_of(value_func, value_id) {
                    param_to_return_objects.insert((*index, object_id));
                }
                for cell in cell_candidates_for_value_targets(self, value_func, value_id) {
                    param_to_return_cells.insert((*index, cell.index() as u32));
                }
            }
        }

        for (index, region) in &param_to_return_regions {
            for (live_func, live_value) in self.region_live_values_of(region) {
                param_to_return_live_values.insert((*index, live_func.0, live_value.0));
            }
        }
        for region in &return_regions {
            for (live_func, live_value) in self.region_live_values_of(region) {
                return_live_values.insert((live_func.0, live_value.0));
            }
        }

        let summary = FunctionHeapEffectSummary {
            func: func.0,
            context: None,
            sensitivity: None,
            param_to_read_regions: param_to_read_regions.into_iter().collect(),
            param_to_read_paths: param_to_read_paths.into_iter().collect(),
            param_to_read_cells: param_to_read_cells.into_iter().collect(),
            param_to_read_objects: param_to_read_objects.into_iter().collect(),
            param_to_write_regions: param_to_write_regions.into_iter().collect(),
            param_to_write_paths: param_to_write_paths.into_iter().collect(),
            param_to_write_cells: param_to_write_cells.into_iter().collect(),
            param_to_write_objects: param_to_write_objects.into_iter().collect(),
            param_to_return_regions: param_to_return_regions.into_iter().collect(),
            param_to_return_paths: param_to_return_paths.into_iter().collect(),
            param_to_return_cells: param_to_return_cells.into_iter().collect(),
            param_to_return_objects: param_to_return_objects.into_iter().collect(),
            param_to_return_live_values: param_to_return_live_values.into_iter().collect(),
            return_regions: return_regions.into_iter().collect(),
            return_paths: return_paths.into_iter().collect(),
            return_cells: return_cells.into_iter().collect(),
            return_objects: return_objects.into_iter().collect(),
            return_value_regions: return_value_regions.into_iter().collect(),
            return_value_paths: return_value_paths.into_iter().collect(),
            return_value_cells: return_value_cells.into_iter().collect(),
            return_value_objects: return_value_objects.into_iter().collect(),
            return_live_values: return_live_values.into_iter().collect(),
        };
        self.function_heap_effect_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn contextual_function_heap_effect_summary(
        &self,
        func: FunctionId,
        context: &CallContextKey,
        sensitivity: ContextSensitivity,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<FunctionHeapEffectSummary> {
        let refined = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        let key = (
            func.0,
            refined.clone(),
            sensitivity,
            max_depth,
            max_visits,
            engine,
            include_heap,
        );
        if let Some(cached) = self
            .contextual_function_heap_effect_summary_cache
            .borrow()
            .get(&key)
            .cloned()
        {
            return Some(cached);
        }

        // Heap effects are properties of the callee body. Re-running contextual demand queries for
        // every parameter recursively rebuilds the same closure and can explode on receiver/argument
        // contexts. Project the already converged context-insensitive heap summary and attach the
        // normalized context metadata instead. Call-site precision remains represented by the
        // contextual transfer summary and by the context key used to cache this projection.
        let mut summary = self.function_heap_effect_summary(
            func,
            max_depth,
            max_visits,
            engine,
            include_heap,
        )?;
        summary.context = Some(refined.clone());
        summary.sensitivity = Some(sensitivity);
        self.contextual_function_heap_effect_summary_cache
            .borrow_mut()
            .insert(key, summary.clone());
        Some(summary)
    }

    pub fn interprocedural_call_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<InterproceduralCallSummary> {
        self.interprocedural_call_summary_with_sensitivity(
            func,
            inst,
            ContextSensitivity::ReceiverArgsAndCallSite,
            max_depth,
            max_visits,
            engine,
            include_heap,
        )
    }

    pub fn interprocedural_call_summary_with_sensitivity(
        &self,
        func: FunctionId,
        inst: InstId,
        sensitivity: ContextSensitivity,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<InterproceduralCallSummary> {
        let context = self
            .call_context_key(func, inst)
            .map(|context| self.refine_call_context_for_sensitivity(context, sensitivity))?;
        let key = (context.clone(), sensitivity, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self.interprocedural_call_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }

        let mut callee_ids = context
            .callee_funcs
            .iter()
            .copied()
            .map(FunctionId)
            .collect::<Vec<_>>();
        if callee_ids.is_empty() {
            callee_ids = self
                .exact_callee_ids_for_call(func, inst)
                .into_iter()
                .collect::<Vec<_>>();
        }
        callee_ids.sort();
        callee_ids.dedup();
        if callee_ids.is_empty() {
            return None;
        }

        let mut port_to_params = BTreeMap::<String, BTreeSet<usize>>::new();
        let mut param_to_ports = BTreeMap::<usize, BTreeSet<String>>::new();
        for ((call_func, call_inst, port), node) in &self.call_ports {
            if *call_func != func || *call_inst != inst {
                continue;
            }
            let port_name = format!("{:?}", port);
            for edge in self.graph.edges_directed(*node, petgraph::Direction::Outgoing) {
                if !matches!(edge.weight().kind, EdgeKind::ActualToFormal) {
                    continue;
                }
                if let FlowNode::Param { func: param_func, index, .. } = self.graph[edge.target()] {
                    if callee_ids.iter().any(|candidate| *candidate == param_func) {
                        port_to_params.entry(port_name.clone()).or_default().insert(index);
                        param_to_ports.entry(index).or_default().insert(port_name.clone());
                    }
                }
            }
        }

        let mut port_to_return = BTreeSet::new();
        let mut port_to_param = BTreeSet::new();
        let mut port_to_port = BTreeSet::new();
        let mut port_to_return_values = BTreeSet::new();
        let mut port_to_return_live_values = BTreeSet::new();
        let mut port_to_return_value_regions = BTreeSet::new();
        let mut port_to_return_value_paths = BTreeSet::new();
        let mut port_to_return_value_objects = BTreeSet::new();
        let mut port_to_read_regions = BTreeSet::new();
        let mut port_to_read_paths = BTreeSet::new();
        let mut port_to_read_cells = BTreeSet::new();
        let mut port_to_read_objects = BTreeSet::new();
        let mut port_to_write_regions = BTreeSet::new();
        let mut port_to_write_paths = BTreeSet::new();
        let mut port_to_write_cells = BTreeSet::new();
        let mut port_to_write_objects = BTreeSet::new();
        let mut port_to_return_regions = BTreeSet::new();
        let mut port_to_return_paths = BTreeSet::new();
        let mut port_to_return_cells = BTreeSet::new();
        let mut port_to_return_objects = BTreeSet::new();
        let mut return_values = BTreeSet::new();
        let mut return_live_values = BTreeSet::new();
        let mut return_value_regions = BTreeSet::new();
        let mut return_value_paths = BTreeSet::new();
        let mut return_value_cells = BTreeSet::new();
        let mut return_value_objects = BTreeSet::new();
        let mut return_paths = BTreeSet::new();
        let mut return_cells = BTreeSet::new();
        let mut return_objects = BTreeSet::new();
        for callee_func in &callee_ids {
            let Some(transfer) = self.contextual_function_transfer_summary(
                *callee_func,
                &context,
                sensitivity,
                max_depth,
                max_visits,
                engine,
                include_heap,
            ) else {
                continue;
            };
            let heap_effects = self.contextual_function_heap_effect_summary(
                *callee_func,
                &context,
                sensitivity,
                max_depth,
                max_visits,
                engine,
                include_heap,
            );
            for value in &transfer.return_values {
                return_values.insert(*value);
            }
            if let Some(effects) = &heap_effects {
                for (summary_func, summary_value, region) in &effects.return_value_regions {
                    return_value_regions.insert((*summary_func, *summary_value, region.clone()));
                }
                for (summary_func, summary_value, path) in &effects.return_value_paths {
                    return_value_paths.insert((*summary_func, *summary_value, path.clone()));
                }
                for (summary_func, summary_value, cell) in &effects.return_value_cells {
                    return_value_cells.insert((*summary_func, *summary_value, *cell));
                }
                for (summary_func, summary_value, object_id) in &effects.return_value_objects {
                    return_value_objects.insert((*summary_func, *summary_value, *object_id));
                    return_objects.insert(*object_id);
                }
                for object_id in &effects.return_objects {
                    return_objects.insert(*object_id);
                }
                for path in &effects.return_paths {
                    return_paths.insert(path.clone());
                }
                for cell in &effects.return_cells {
                    return_cells.insert(*cell);
                }
                for (summary_func, summary_value) in &effects.return_live_values {
                    return_live_values.insert((*summary_func, *summary_value));
                }
            }
            for (port_name, params) in &port_to_params {
                if params.iter().any(|index| transfer.return_reachable_params.iter().any(|target| target == index)) {
                    port_to_return.insert(port_name.clone());
                }
                for (from_index, summary_func, summary_value) in &transfer.param_to_return_values {
                    if params.contains(from_index) {
                        port_to_return_values.insert((port_name.clone(), *summary_func, *summary_value));
                    }
                }
                for (from_index, to_index) in &transfer.param_to_param {
                    if !params.contains(from_index) {
                        continue;
                    }
                    port_to_param.insert((port_name.clone(), *to_index));
                    if let Some(target_ports) = param_to_ports.get(to_index) {
                        for target_port in target_ports {
                            port_to_port.insert((port_name.clone(), target_port.clone()));
                        }
                    }
                }
                if let Some(effects) = &heap_effects {
                    for (from_index, region) in &effects.param_to_read_regions {
                        if params.contains(from_index) {
                            port_to_read_regions.insert((port_name.clone(), region.clone()));
                        }
                    }
                    for (from_index, path) in &effects.param_to_read_paths {
                        if params.contains(from_index) {
                            port_to_read_paths.insert((port_name.clone(), path.clone()));
                        }
                    }
                    for (from_index, cell) in &effects.param_to_read_cells {
                        if params.contains(from_index) {
                            port_to_read_cells.insert((port_name.clone(), *cell));
                        }
                    }
                    for (from_index, object_id) in &effects.param_to_read_objects {
                        if params.contains(from_index) {
                            port_to_read_objects.insert((port_name.clone(), *object_id));
                        }
                    }
                    for (from_index, region) in &effects.param_to_write_regions {
                        if params.contains(from_index) {
                            port_to_write_regions.insert((port_name.clone(), region.clone()));
                        }
                    }
                    for (from_index, path) in &effects.param_to_write_paths {
                        if params.contains(from_index) {
                            port_to_write_paths.insert((port_name.clone(), path.clone()));
                        }
                    }
                    for (from_index, cell) in &effects.param_to_write_cells {
                        if params.contains(from_index) {
                            port_to_write_cells.insert((port_name.clone(), *cell));
                        }
                    }
                    for (from_index, object_id) in &effects.param_to_write_objects {
                        if params.contains(from_index) {
                            port_to_write_objects.insert((port_name.clone(), *object_id));
                        }
                    }
                    for (from_index, region) in &effects.param_to_return_regions {
                        if params.contains(from_index) {
                            port_to_return_regions.insert((port_name.clone(), region.clone()));
                        }
                    }
                    for (from_index, path) in &effects.param_to_return_paths {
                        if params.contains(from_index) {
                            port_to_return_paths.insert((port_name.clone(), path.clone()));
                        }
                    }
                    for (from_index, cell) in &effects.param_to_return_cells {
                        if params.contains(from_index) {
                            port_to_return_cells.insert((port_name.clone(), *cell));
                        }
                    }
                    for (from_index, object_id) in &effects.param_to_return_objects {
                        if params.contains(from_index) {
                            port_to_return_objects.insert((port_name.clone(), *object_id));
                        }
                    }
                    for (from_index, summary_func, summary_value) in &effects.param_to_return_live_values {
                        if params.contains(from_index) {
                            port_to_return_live_values.insert((port_name.clone(), *summary_func, *summary_value));
                        }
                    }
                    for (from_index, summary_func, summary_value) in &transfer.param_to_return_values {
                        if !params.contains(from_index) {
                            continue;
                        }
                        for region in self.value_memory_regions_of(FunctionId(*summary_func), ValueId(*summary_value)) {
                            port_to_return_value_regions.insert((port_name.clone(), *summary_func, *summary_value, region));
                        }
                        for (_ret_func, _ret_value, path) in effects
                            .return_value_paths
                            .iter()
                            .filter(|(ret_func, ret_value, _)| *ret_func == *summary_func && *ret_value == *summary_value)
                        {
                            port_to_return_value_paths.insert((port_name.clone(), *summary_func, *summary_value, path.clone()));
                        }
                        for (_ret_func, _ret_value, object_id) in effects
                            .return_value_objects
                            .iter()
                            .filter(|(ret_func, ret_value, _)| *ret_func == *summary_func && *ret_value == *summary_value)
                        {
                            port_to_return_value_objects.insert((port_name.clone(), *summary_func, *summary_value, *object_id));
                        }
                    }
                }
            }
        }

        let summary = InterproceduralCallSummary {
            caller_func: func.0,
            inst: inst.0,
            sensitivity: Some(sensitivity),
            callee_names: context.callee_names.clone(),
            callee_funcs: callee_ids.iter().map(|func| func.0).collect(),
            context,
            port_to_return: port_to_return.into_iter().collect(),
            port_to_param: port_to_param.into_iter().collect(),
            port_to_port: port_to_port.into_iter().collect(),
            port_to_return_values: port_to_return_values.into_iter().collect(),
            port_to_return_live_values: port_to_return_live_values.into_iter().collect(),
            port_to_return_value_regions: port_to_return_value_regions.into_iter().collect(),
            port_to_return_value_paths: port_to_return_value_paths.into_iter().collect(),
            port_to_return_value_objects: port_to_return_value_objects.into_iter().collect(),
            port_to_read_regions: port_to_read_regions.into_iter().collect(),
            port_to_read_paths: port_to_read_paths.into_iter().collect(),
            port_to_read_cells: port_to_read_cells.into_iter().collect(),
            port_to_read_objects: port_to_read_objects.into_iter().collect(),
            port_to_write_regions: port_to_write_regions.into_iter().collect(),
            port_to_write_paths: port_to_write_paths.into_iter().collect(),
            port_to_write_cells: port_to_write_cells.into_iter().collect(),
            port_to_write_objects: port_to_write_objects.into_iter().collect(),
            port_to_return_regions: port_to_return_regions.into_iter().collect(),
            port_to_return_paths: port_to_return_paths.into_iter().collect(),
            port_to_return_cells: port_to_return_cells.into_iter().collect(),
            port_to_return_objects: port_to_return_objects.into_iter().collect(),
            return_values: return_values.into_iter().collect(),
            return_live_values: return_live_values.into_iter().collect(),
            return_value_regions: return_value_regions.into_iter().collect(),
            return_value_paths: return_value_paths.into_iter().collect(),
            return_value_cells: return_value_cells.into_iter().collect(),
            return_value_objects: return_value_objects.into_iter().collect(),
            return_paths: return_paths.into_iter().collect(),
            return_cells: return_cells.into_iter().collect(),
            return_objects: return_objects.into_iter().collect(),
        };
        self.interprocedural_call_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn cell_write_generations_of(&self, cell: NodeIndex) -> Vec<(u64, FunctionId, ValueId)> {
        self.cell_write_generations
            .get(&cell.index())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(generation, func, value)| (generation, FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn demand_summary_from_seeds(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let mut key_seeds = seeds.iter().map(|seed| seed.index()).collect::<Vec<_>>();
        key_seeds.sort_unstable();
        key_seeds.dedup();
        let key = (key_seeds, direction, max_depth, max_visits);
        if let Some(cached) = self.demand_seed_summary_cache.borrow().get(&key).cloned() {
            return cached;
        }
        let traversal = self.sparse_traversal(seeds, direction, max_depth, max_visits);
        let summary = self.summarize_sparse_traversal(traversal);
        self.demand_seed_summary_cache.borrow_mut().insert(key, summary.clone());
        summary
    }

    pub fn demand_summary_from_node(
        &self,
        seed: NodeIndex,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let key = (seed.index(), direction, max_depth, max_visits);
        if let Some(cached) = self.demand_summary_cache.borrow().get(&key).cloned() {
            return cached;
        }
        let summary = self.summarize_sparse_traversal(self.sparse_traversal(&[seed], direction, max_depth, max_visits));
        self.demand_summary_cache.borrow_mut().insert(key, summary.clone());
        summary
    }

    pub fn demand_multi_value_summary(
        &self,
        seeds: &[(FunctionId, ValueId)],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let nodes = seeds
            .iter()
            .filter_map(|(func, value)| self.values.get(&(*func, *value)).copied())
            .collect::<Vec<_>>();
        self.demand_summary_from_seeds(&nodes, direction, max_depth, max_visits)
    }

    pub fn demand_reachable_values(
        &self,
        func: FunctionId,
        value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Vec<(FunctionId, ValueId)> {
        let summary = self.demand_value_summary(func, value, direction, max_depth, max_visits);
        summary
            .values
            .into_iter()
            .map(|(func, value)| (FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn demand_reaches_value(
        &self,
        src_func: FunctionId,
        src_value: ValueId,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let summary = self.demand_value_summary(src_func, src_value, direction, max_depth, max_visits);
        summary
            .values
            .iter()
            .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
    }

    pub fn demand_reaches_any_value(
        &self,
        src_func: FunctionId,
        src_value: ValueId,
        targets: &[(FunctionId, ValueId)],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let summary = self.demand_value_summary(src_func, src_value, direction, max_depth, max_visits);
        targets.iter().any(|(dst_func, dst_value)| {
            summary
                .values
                .iter()
                .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
                || summary
                    .params
                    .iter()
                    .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
        })
    }

    pub fn demand_call_port_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        port: Port,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let seed = self.call_ports.get(&(func, inst, port))?.to_owned();
        Some(self.demand_summary_from_node(seed, direction, max_depth, max_visits))
    }

    pub fn demand_call_port_reaches_value(
        &self,
        func: FunctionId,
        inst: InstId,
        port: Port,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.demand_call_port_summary(func, inst, port, direction, max_depth, max_visits) else {
            return false;
        };
        summary
            .values
            .iter()
            .any(|(summary_func, summary_value)| *summary_func == dst_func.0 && *summary_value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(summary_func, _index, summary_value)| *summary_func == dst_func.0 && *summary_value == dst_value.0)
    }

    pub fn demand_call_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let key = ((func.0, inst.0), direction, max_depth, max_visits);
        if let Some(cached) = self.demand_call_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let mut seeds = self
            .call_ports
            .iter()
            .filter_map(|((call_func, call_inst, _port), node)| {
                (*call_func == func && *call_inst == inst).then_some(*node)
            })
            .collect::<Vec<_>>();
        seeds.sort_unstable_by_key(|node| node.index());
        seeds.dedup();
        if seeds.is_empty() {
            return None;
        }
        let summary = self.demand_summary_from_seeds(&seeds, direction, max_depth, max_visits);
        self.demand_call_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn demand_value_summary(
        &self,
        func: FunctionId,
        value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let seed = value_node(self, func, value);
        self.demand_summary_from_node(seed, direction, max_depth, max_visits)
    }

    pub fn call_info(&self, func: FunctionId, inst: InstId) -> Option<CallInfo> {
        self.call_meta.get(&(func, inst)).and_then(|meta| meta.as_call_info())
    }

    pub fn node_label_map(&self) -> BTreeMap<usize, String> {
        let mut out = BTreeMap::new();
        for idx in self.graph.node_indices() {
            out.insert(idx.index(), self.describe_node(idx));
        }
        out
    }
    pub fn stats(&self) -> FlowStats {
        let static_calls = self
            .call_meta
            .values()
            .filter(|meta| meta.callee_name.is_some())
            .count();
        let dynamic_calls = self.call_meta.len().saturating_sub(static_calls);
        let resolved_internal_calls = self.resolved_internal_targets.len();
        let unresolved_static_calls = self
            .call_meta
            .iter()
            .filter(|(key, meta)| meta.callee_name.is_some() && !self.resolved_internal_targets.contains_key(key))
            .count();
        let value_nodes = self
            .graph
            .node_indices()
            .filter(|idx| matches!(self.graph[*idx], FlowNode::Value { .. } | FlowNode::Param { .. } | FlowNode::Return { .. }))
            .count();
        let sparse_data_edges = self
            .sparse_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let heap_value_edges = self
            .heap_value_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let heap_object_edges = self
            .heap_object_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let object_graph_edges = self
            .object_graph_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let region_graph_edges = self
            .region_graph_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let object_shape_nodes = self.object_shape_labels.len();
        let object_shape_paths = self.object_shape_paths.values().map(|values| values.len()).sum();
        let memory_regions = self.value_memory_regions.len() + self.cell_memory_regions.len() + self.node_memory_regions.len();
        let live_cell_values = self.cell_live_values.values().map(|values| values.len()).sum();
        let live_cell_regions = self.cell_live_regions.values().map(|values| values.len()).sum();
        let live_region_values = self.region_live_values.values().map(|values| values.len()).sum();
        let live_region_cells = self.region_live_cells.values().map(|values| values.len()).sum();
        let points_to_classes = self.value_points_to_classes.len() + self.cell_points_to_classes.len() + self.node_points_to_classes.len();
        let points_to_targets = self.value_points_to_targets.len() + self.cell_points_to_targets.len() + self.node_points_to_targets.len();
        let points_to_objects = self.abstract_objects.len() + self.value_points_to_object_ids.len() + self.cell_points_to_object_ids.len() + self.node_points_to_object_ids.len();
        let cell_write_generations = self.cell_write_generations.values().map(|values| values.len()).sum();
        let contextual_states = self.contextual_points_to_targets.len()
            + self.contextual_points_to_object_ids.len()
            + self.contextual_return_values.len()
            + self.contextual_return_cells.len()
            + self.contextual_node_points_to_targets.len()
            + self.contextual_value_points_to_targets.len()
            + self.contextual_cell_points_to_targets.len();
        let contextual_points_to_objects = self.contextual_points_to_object_ids.len()
            + self.contextual_node_points_to_object_ids.len()
            + self.contextual_value_points_to_object_ids.len()
            + self.contextual_cell_points_to_object_ids.len();
        let cached_sparse_summaries = self.demand_summary_cache.borrow().len()
            + self.demand_seed_summary_cache.borrow().len()
            + self.demand_call_summary_cache.borrow().len()
            + self.demand_fixpoint_summary_cache.borrow().len();
        let cached_demand_queries = self.demand_query_summary_cache.borrow().len();
        let cached_contextual_queries = self.contextual_demand_query_cache.borrow().len();
        let cached_contextual_summaries = self.contextual_call_summary_cache.borrow().len();
        let cached_function_summaries = self.function_summary_cache.borrow().len();
        let cached_interprocedural_summaries = self.interprocedural_call_summary_cache.borrow().len();
        let cached_transfer_summaries = self.function_transfer_summary_cache.borrow().len()
            + self.contextual_function_transfer_summary_cache.borrow().len();
        let cached_heap_effect_summaries = self.function_heap_effect_summary_cache.borrow().len()
            + self.contextual_function_heap_effect_summary_cache.borrow().len();
        let solver_closure_iterations = self.solver_closure_iterations;
        let global_solver_iterations = self.global_solver_iterations;
        FlowStats {
            files: self.file_paths.len(),
            functions: self.function_names.len(),
            value_nodes,
            total_nodes: self.graph.node_count(),
            total_edges: self.graph.edge_count(),
            sparse_data_edges,
            heap_value_edges,
            heap_object_edges,
            object_graph_edges,
            region_graph_edges,
            object_shape_nodes,
            object_shape_paths,
            object_identity_values: self.object_identity_roots.len(),
            points_to_classes,
            points_to_targets,
            points_to_objects,
            strong_update_cells: self.strong_update_cells.len(),
            cell_write_generations,
            contextual_states,
            contextual_points_to_objects,
            solver_closure_iterations,
            global_solver_iterations,
            memory_regions,
            live_cell_values,
            live_cell_regions,
            live_region_values,
            live_region_cells,
            cached_sparse_summaries,
            cached_demand_queries,
            cached_contextual_queries,
            cached_contextual_summaries,
            cached_function_summaries,
            cached_interprocedural_summaries,
            cached_transfer_summaries,
            cached_heap_effect_summaries,
            static_calls,
            dynamic_calls,
            resolved_internal_calls,
            unresolved_static_calls,
            synthetic_sources: self.synthetic_sources.len(),
            synthetic_sinks: self.synthetic_sinks.len(),
        }
    }

    pub fn call_report(&self) -> Vec<CallReport> {
        let mut out = self
            .call_meta
            .iter()
            .map(|(key, meta)| CallReport {
                function_name: self.function_name(meta.func).to_string(),
                location: self.location_text(meta.func, meta.inst),
                callee_name: meta.callee_name.clone(),
                receiver_type: meta.receiver_type.clone(),
                receiver_type_candidates: meta.receiver_type_candidates.clone(),
                method_name: meta.method_name.clone(),
                arg_count: meta.arg_count,
                arg_types: meta.arg_types.clone(),
                arg_type_candidates: meta.arg_type_candidates.clone(),
                is_dynamic: meta.callee_name.is_none(),
                resolved_internal_targets: self
                    .resolved_internal_targets
                    .get(key)
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        out.sort_by(|a, b| a.location.cmp(&b.location).then_with(|| a.function_name.cmp(&b.function_name)));
        out
    }


    pub fn describe_node(&self, idx: NodeIndex) -> String {
        match &self.graph[idx] {
            FlowNode::Param { func, index, value } => {
                let identity = value_identity_site(self, *func, *value)
                    .map(|site| format!(" [oid={site}]"))
                    .unwrap_or_default();
                format!(
                    "param {}#{} v{}{}",
                    self.function_name(*func),
                    index,
                    value.0,
                    identity,
                )
            },
            FlowNode::Return { func } => format!("return {}", self.function_name(*func)),
            FlowNode::Value { func, value } => {
                let ty_suffix = self
                    .value_types
                    .get(&(*func, *value))
                    .map(|ty| format!(":{ty}"))
                    .unwrap_or_default();
                let identity = value_identity_site(self, *func, *value)
                    .map(|site| format!(" [oid={site}]"))
                    .unwrap_or_default();
                format!("value {}::v{}{}{}", self.function_name(*func), value.0, ty_suffix, identity)
            },
            FlowNode::CallPort { func, inst, port, callee_name } => {
                let location = self.location_text(*func, *inst);
                let callee = callee_name.clone().unwrap_or_else(|| "<dynamic>".to_string());
                format!(
                    "call-port {} {:?} {} {}",
                    self.function_name(*func),
                    port.clone(),
                    callee,
                    location
                )
            }
            FlowNode::FieldCell { func, base, field, .. } => {
                format!("field-cell {} base=v{} .{}", self.function_name(*func), base.0, field)
            }
            FlowNode::IndexCell { func, base, index, abstract_key, .. } => {
                format!("index-cell {} base=v{} idx=v{} key={}", self.function_name(*func), base.0, index.0, abstract_key)
            }
            FlowNode::SyntheticSource { func, inst, rule_id, kind, out } => {
                format!(
                    "source {} [{}] {:?} {} {}",
                    rule_id,
                    kind,
                    out,
                    self.function_name(*func),
                    self.location_text(*func, *inst)
                )
            }
            FlowNode::SyntheticSink { func, inst, rule_id, kind, input } => {
                format!(
                    "sink {} [{}] {:?} {} {}",
                    rule_id,
                    kind,
                    input,
                    self.function_name(*func),
                    self.location_text(*func, *inst)
                )
            }
        }
    }

    pub fn describe_edge(&self, from: NodeIndex, to: NodeIndex) -> String {
        if let Some(edge) = self.graph.edges_connecting(from, to).next() {
            format!("{:?}", edge.weight().kind)
        } else {
            "<no-edge>".to_string()
        }
    }

    pub fn function_name(&self, func: FunctionId) -> &str {
        self.function_names
            .get(&func)
            .map(|s| s.as_str())
            .unwrap_or("<unknown-func>")
    }

    pub fn location_text(&self, func: FunctionId, inst: InstId) -> String {
        let Some(span) = self.inst_spans.get(&(func, inst)) else {
            return "@unknown".to_string();
        };
        self.span_text(span)
    }

    pub fn span_text(&self, span: &Span) -> String {
        let path = self
            .file_paths
            .get(&span.file)
            .cloned()
            .unwrap_or_else(|| format!("file#{}", span.file));
        if span.start_line == 0 && span.end_line == 0 && span.start_col == 0 && span.end_col == 0 {
            return if self.file_paths.contains_key(&span.file) {
                format!("@{}", path)
            } else {
                "@unknown".to_string()
            };
        }
        format!("@{}:{}:{}", path, span.start_line, span.start_col)
    }
}

