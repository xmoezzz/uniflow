impl FunctionLoweringContext<'_> {
    #[allow(clippy::too_many_arguments)]
    fn lower_abrupt_transfer(
        &mut self,
        kind: AbruptTransfer,
        term: Terminator,
        current_id: BlockId,
        insts: Vec<Instruction>,
        value_map: HashMap<SymbolId, ValueId>,
        symbol_types: &mut HashMap<SymbolId, String>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) -> (Vec<BasicBlock>, HashMap<SymbolId, ValueId>) {
        let cleanup = self.finally_stack.iter().rposition(|frame| match kind {
            AbruptTransfer::Return => true,
            AbruptTransfer::Break => self.break_stack.len() <= frame.break_depth,
            AbruptTransfer::Continue => self.continue_stack.len() <= frame.continue_depth,
        });
        let Some(index) = cleanup else {
            if let Terminator::Goto(target) = &term {
                if self.watched_edge_targets.contains(target) {
                    self.edge_environments.entry(*target).or_default().push(value_map.clone());
                }
            }
            return (vec![BasicBlock { id: current_id, insts, term }], value_map);
        };
        // Remove this frame while executing its body. Abrupt completion of the
        // finalizer overrides the pending transfer and still unwinds outer frames.
        let frames = self.finally_stack.split_off(index);
        let frame = &frames[0];
        let resume = self.alloc_block_id();
        self.watched_edge_targets.insert(resume);
        let visible = value_map.keys().copied().collect::<HashSet<_>>();
        let (mut blocks, fallback_env) = self.lower_stmt_sequence_with_prefix(
            &frame.body.stmts, current_id, insts, value_map, Terminator::Goto(resume),
            symbol_types, locals, value_types, value_spans,
        );
        let edges = self.edge_environments.remove(&resume).unwrap_or_default();
        self.watched_edge_targets.remove(&resume);
        let final_env = if edges.is_empty() {
            // No normal finalizer completion: its return/throw/jump wins.
            fallback_env
        } else {
            let (mut env, phis) = self.merge_edge_environments(
                edges, frame.body.span, symbol_types, locals, value_types, value_spans,
            );
            env.retain(|symbol, _| visible.contains(symbol));
            let (mut continuation, env) = self.lower_abrupt_transfer(
                kind, term, resume, phis, env, symbol_types, locals, value_types, value_spans,
            );
            blocks.append(&mut continuation);
            env
        };
        self.finally_stack.extend(frames);
        (blocks, final_env)
    }
}
