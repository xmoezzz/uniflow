// Order-, index- and key-sensitive modeling of *method-local* Java
// collections.
//
// The generic Java collection models are "element into receiver, receiver
// into result" (`java-collection-add` / `java-collection-get`, `java-map-put`
// / `java-map-get`): one taint for the whole collection. That is the right
// default for a collection that escapes, is filled in a loop or is indexed
// by an unknown value, but it makes `list.get(1)` tainted by element 0 and
// `map.get("a")` tainted by the value under "b" — the single largest source
// of Java false positives on the OWASP Benchmark.
//
// This pass replays a collection's operations in program order when — and
// only when — the collection is provably local and every operation is
// decidable:
//   * it is created by a known constructor in this method (no copy
//     constructor);
//   * every use of it (and its copies) is a supported method call with it as
//     the receiver, in the constructor's basic block, after the constructor;
//   * every index/key argument is a literal (through copies);
//   * it never escapes: not passed as an argument, stored, returned, thrown,
//     merged by a phi or used in another block.
// For such a collection each read (`get`, `remove`, `set`/`put` returning the
// previous value, `getOrDefault`) gets an edge from exactly the stored
// element(s), and every rule-pack propagator/summary is skipped for its calls
// (all of a JDK collection call's effects are replayed here). Anything outside those conditions keeps the generic model, so
// the refinement can only remove impossible flows, never lose a possible one.

#[derive(Default)]
struct JavaCollectionPlan {
    /// Read-like call → the values whose data reaches its result.
    loads: HashMap<InstId, Vec<ValueId>>,
    /// Calls modeled precisely here; generic collection propagators must skip them.
    precise: HashSet<InstId>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalCollectionKind {
    List,
    Map,
}

fn java_local_collection_kind(callee: &str) -> Option<LocalCollectionKind> {
    match callee {
        "java.util.ArrayList" | "java.util.LinkedList" | "java.util.Vector" => Some(LocalCollectionKind::List),
        "java.util.HashMap" | "java.util.LinkedHashMap" | "java.util.TreeMap" | "java.util.Hashtable" => Some(LocalCollectionKind::Map),
        _ => None,
    }
}

/// Literal integer / string value of `value`, through copies (the
/// function-wide literal lattice from `compute_literal_index_keys`), with
/// the declared type deciding whether a numeric literal is an `int` index or
/// an object key — `list.remove(0)` and `list.remove("0")` are different
/// operations in Java.
fn java_literal(func: &Function, literals: &HashMap<ValueId, String>, value: ValueId) -> Option<(bool, String)> {
    let literal = literals.get(&value)?;
    let is_int = func
        .value_types
        .get(&value)
        .is_some_and(|ty| matches!(ty.as_str(), "int" | "long" | "short" | "byte" | "Integer" | "java.lang.Integer"));
    Some((is_int, literal.clone()))
}

fn plan_java_local_collections(func: &Function, literals: &HashMap<ValueId, String>) -> JavaCollectionPlan {
    let mut plan = JavaCollectionPlan::default();
    for (block_index, block) in func.blocks.iter().enumerate() {
        for (inst_index, inst) in block.insts.iter().enumerate() {
            let InstKind::Call(call) = &inst.kind else { continue };
            let (Callee::Static(callee), Some(dst)) = (&call.callee, call.dst) else { continue };
            let Some(kind) = java_local_collection_kind(callee) else { continue };
            // `new ArrayList<>()` / `new HashMap<>(16)`; a copy constructor
            // (`new ArrayList<>(other)`) starts with unknown contents.
            let only_capacity = call.args.iter().all(|arg| java_literal(func, literals, *arg).is_some_and(|(is_int, _)| is_int));
            if call.args.len() > 1 || !only_capacity {
                continue;
            }
            if let Some(local) = replay_local_collection(func, literals, block_index, inst_index, dst, kind) {
                plan.loads.extend(local.loads);
                plan.precise.extend(local.precise);
            }
        }
    }
    plan
}

fn replay_local_collection(
    func: &Function,
    literals: &HashMap<ValueId, String>,
    block_index: usize,
    ctor_index: usize,
    object: ValueId,
    kind: LocalCollectionKind,
) -> Option<JavaCollectionPlan> {
    let block = &func.blocks[block_index];
    let mut aliases = HashSet::from([object]);
    let mut list: Vec<ValueId> = Vec::new();
    let mut map: Vec<(String, ValueId)> = Vec::new();
    let mut plan = JavaCollectionPlan::default();

    for inst in &block.insts[ctor_index + 1..] {
        match &inst.kind {
            InstKind::Copy { dst, src } | InstKind::Move { dst, src } | InstKind::Cast { dst, src, .. } if aliases.contains(src) => {
                aliases.insert(*dst);
                continue;
            }
            InstKind::Call(call) if call.receiver.is_some_and(|receiver| aliases.contains(&receiver)) => {
                if call.args.iter().any(|arg| aliases.contains(arg)) {
                    return None;
                }
                let Callee::Static(callee) = &call.callee else { return None };
                let method = callee.rsplit('.').next().unwrap_or(callee.as_str());
                let lit = |position: usize| call.args.get(position).and_then(|arg| java_literal(func, literals, *arg));
                let int_arg = |position: usize| lit(position).filter(|(is_int, _)| *is_int).and_then(|(_, text)| text.parse::<usize>().ok());
                let loads: Vec<ValueId> = match (kind, method, call.args.len()) {
                    (LocalCollectionKind::List, "add" | "addLast" | "offer" | "offerLast", 1) => {
                        list.push(call.args[0]);
                        Vec::new()
                    }
                    (LocalCollectionKind::List, "addFirst" | "push" | "offerFirst", 1) => {
                        list.insert(0, call.args[0]);
                        Vec::new()
                    }
                    (LocalCollectionKind::List, "add", 2) => {
                        let index = int_arg(0).filter(|index| *index <= list.len())?;
                        list.insert(index, call.args[1]);
                        Vec::new()
                    }
                    (LocalCollectionKind::List, "set", 2) => {
                        let index = int_arg(0).filter(|index| *index < list.len())?;
                        vec![std::mem::replace(&mut list[index], call.args[1])]
                    }
                    (LocalCollectionKind::List, "get", 1) => {
                        let index = int_arg(0)?;
                        list.get(index).copied().into_iter().collect()
                    }
                    (LocalCollectionKind::List, "remove", 1) => {
                        // Only positional removal is decidable; remove(Object)
                        // would need value equality.
                        let index = int_arg(0)?;
                        if index < list.len() { vec![list.remove(index)] } else { Vec::new() }
                    }
                    (LocalCollectionKind::List, "getFirst" | "peek" | "peekFirst" | "element", 0) => list.first().copied().into_iter().collect(),
                    (LocalCollectionKind::List, "getLast" | "peekLast", 0) => list.last().copied().into_iter().collect(),
                    (LocalCollectionKind::List, "removeFirst" | "poll" | "pollFirst" | "pop", 0) => {
                        if list.is_empty() { Vec::new() } else { vec![list.remove(0)] }
                    }
                    (LocalCollectionKind::List, "removeLast" | "pollLast", 0) => list.pop().into_iter().collect(),
                    (LocalCollectionKind::List, "size" | "isEmpty", 0) => Vec::new(),
                    (LocalCollectionKind::List, "clear", 0) => {
                        list.clear();
                        Vec::new()
                    }
                    (LocalCollectionKind::Map, "put", 2) => {
                        let (_, key) = lit(0)?;
                        match map.iter_mut().find(|(existing, _)| *existing == key) {
                            Some(entry) => vec![std::mem::replace(&mut entry.1, call.args[1])],
                            None => {
                                map.push((key, call.args[1]));
                                Vec::new()
                            }
                        }
                    }
                    (LocalCollectionKind::Map, "putIfAbsent", 2) => {
                        let (_, key) = lit(0)?;
                        match map.iter().find(|(existing, _)| *existing == key) {
                            Some((_, value)) => vec![*value],
                            None => {
                                map.push((key, call.args[1]));
                                Vec::new()
                            }
                        }
                    }
                    (LocalCollectionKind::Map, "get", 1) => {
                        let (_, key) = lit(0)?;
                        map.iter().filter(|(existing, _)| *existing == key).map(|(_, value)| *value).collect()
                    }
                    (LocalCollectionKind::Map, "getOrDefault", 2) => {
                        let (_, key) = lit(0)?;
                        match map.iter().find(|(existing, _)| *existing == key) {
                            Some((_, value)) => vec![*value],
                            None => vec![call.args[1]],
                        }
                    }
                    (LocalCollectionKind::Map, "remove", 1) => {
                        let (_, key) = lit(0)?;
                        let position = map.iter().position(|(existing, _)| *existing == key);
                        position.map(|position| map.remove(position).1).into_iter().collect()
                    }
                    (LocalCollectionKind::Map, "containsKey" | "size" | "isEmpty", _) => Vec::new(),
                    (LocalCollectionKind::Map, "clear", 0) => {
                        map.clear();
                        Vec::new()
                    }
                    // Iterators, streams, views, bulk operations, sorting,
                    // toString, … — not replayed: fall back to the generic model.
                    _ => return None,
                };
                plan.precise.insert(inst.id);
                if call.dst.is_some() && !loads.is_empty() {
                    plan.loads.insert(inst.id, loads);
                }
            }
            other => {
                if uniflow_ir::used_values(other).iter().any(|value| aliases.contains(value)) {
                    return None;
                }
            }
        }
    }

    // No use after this block, and none leaves through the terminator.
    let term_uses = |term: &Terminator| match term {
        Terminator::Branch { cond, .. } => vec![*cond],
        Terminator::Return(value) | Terminator::Throw(value) => value.iter().copied().collect(),
        _ => Vec::new(),
    };
    if term_uses(&block.term).iter().any(|value| aliases.contains(value)) {
        return None;
    }
    for (index, other) in func.blocks.iter().enumerate() {
        if index == block_index {
            continue;
        }
        let used = other.insts.iter().any(|inst| uniflow_ir::used_values(&inst.kind).iter().any(|value| aliases.contains(value)))
            || term_uses(&other.term).iter().any(|value| aliases.contains(value));
        if used {
            return None;
        }
    }
    Some(plan)
}

/// Rule id recorded on precise element edges (visible in finding paths).
const JAVA_LOCAL_COLLECTION_RULE: &str = "java-local-collection";

fn connect_java_local_collection_loads(fg: &mut FlowGraph, func: FunctionId, call: &CallInst, loads: &[ValueId]) {
    let Some(dst) = call.dst else { return };
    for element in loads {
        edge_value_to_value(fg, func, *element, dst, EdgeKind::Summary { rule_id: JAVA_LOCAL_COLLECTION_RULE.to_string() });
    }
}
