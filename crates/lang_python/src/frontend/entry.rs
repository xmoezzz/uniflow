pub fn parse_project_sources(entries: &[(String, String)]) -> Result<Program> {
    parse_project_sources_with_progress(entries, &|| {})
}

/// Parse a Python project and invoke `on_module_parsed` once for every module
/// that has made it through the independent, parallel module phase.  Building
/// the cross-module symbol index necessarily happens first, so callers can
/// keep that stage distinct from file-parse progress.
pub fn parse_project_sources_with_progress(
    entries: &[(String, String)],
    on_module_parsed: &(dyn Fn() + Sync),
) -> Result<Program> {
    let index = Arc::new(PyProjectIndex::build(entries));
    let worker_count = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .min(entries.len().max(1));

    // Each module only reads the shared base `index` (never a prior module's
    // mutated copy), so per-module parsing is independent and safe to run
    // concurrently; only the final merge below must preserve file order.
    let mut project = uniflow_hir::ProgramMerger::new(Language::Python);
    if worker_count <= 1 || entries.len() <= 1 {
        // A one-file project still needs the same enlarged stack as parallel
        // workers. Running it directly on the caller thread made a deep file
        // abort despite the index pool itself being configured correctly.
        thread::scope(|scope| -> Result<()> {
            let project = &mut project;
            let index = Arc::clone(&index);
            let worker = thread::Builder::new()
                .stack_size(PYTHON_ANALYSIS_STACK_SIZE)
                .spawn_scoped(scope, move || {
                    for (path, source) in entries {
                            let parsed = parse_python_module(&index, path, source)?;
                            on_module_parsed();
                            project.merge(parsed);
                    }
                    Ok(())
                })
                .expect("failed to spawn Python parser worker thread");
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("Python parser worker panicked"))?
        })?
    } else {
        let next_entry = std::sync::atomic::AtomicUsize::new(0);
        let completed_entries = std::sync::atomic::AtomicUsize::new(0);
        let progress_step = (entries.len() / 100).max(1);
        // Keep only a small, bounded set of module HIRs live. The previous
        // design retained one full Program per source file, then merged all
        // of them at the end. Large Python projects therefore held both the
        // complete per-file HIR collection and the eventual project HIR at
        // once. Merge in source order as worker results arrive instead.
        thread::scope(|scope| -> Result<()> {
            let queue_bound = worker_count.saturating_mul(2).max(1);
            let (sender, receiver) = std::sync::mpsc::sync_channel(queue_bound);
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let index = Arc::clone(&index);
                let next_entry = &next_entry;
                let completed_entries = &completed_entries;
                let sender = sender.clone();
                // Deeply nested or generated source can drive parsing well
                // past a default stack (this is why `main` itself runs on an
                // oversized-stack thread — see `crates/cli/src/main.rs`), and
                // scoped threads do NOT inherit their spawning thread's stack
                // size, so it must be set explicitly here too.
                handles.push(
                    thread::Builder::new()
                        .stack_size(PYTHON_ANALYSIS_STACK_SIZE)
                        .spawn_scoped(scope, move || -> Result<()> {
                            loop {
                                let entry = next_entry.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let Some((path, source)) = entries.get(entry) else { break; };
                                let parsed = parse_python_module(&index, path, source)?;
                                sender.send((entry, parsed))
                                    .map_err(|_| anyhow::anyhow!("Python project parser receiver stopped early"))?;
                                on_module_parsed();
                                let completed = completed_entries.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                if completed % progress_step == 0 || completed == entries.len() {
                                    eprintln!("uniflow: parsing Python modules {}/{}", completed, entries.len());
                                }
                            }
                            Ok(())
                        })
                        .expect("failed to spawn Python parser worker thread"),
                );
            }
            let mut next_to_merge = 0usize;
            let mut pending = BTreeMap::new();
            for _ in 0..entries.len() {
                let (entry, parsed) = receiver
                    .recv()
                    .map_err(|_| anyhow::anyhow!("Python project parser stopped before producing every module"))?;
                pending.insert(entry, parsed);
                while let Some(parsed) = pending.remove(&next_to_merge) {
                    project.merge(parsed);
                    next_to_merge += 1;
                }
            }
            for handle in handles {
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("Python parser worker panicked"))??;
            }
            Ok(())
        })?
    };
    Ok(project.finish())
}

// Python executes imported modules before the importing module's function
// bodies become callable.  Use a per-module index snapshot so recursive
// import side effects are visible while preserving the source-order
// snapshots stored for other modules.
fn parse_python_module(index: &Arc<PyProjectIndex>, path: &str, source: &str) -> Result<Program> {
    let module_name = python_module_name_from_path(path);
    let mut effective_index = (**index).clone();
    effective_index.apply_imported_module_effects(&module_name, &mut HashSet::new());
    let effective_index = Arc::new(effective_index);
    parse_python_file(path, source, Some(&effective_index))
}

impl SourceParser for PythonParser {
    fn language(&self) -> Language {
        Language::Python
    }

    fn parse_file(&self, path: &str, source: &str) -> Result<uniflow_hir::Program> {
        parse_python_file(path, source, None)
    }
}

fn python_module_name_from_path(path: &str) -> String {
    let fallback = module_name_from_path(path);
    let raw_parts = Path::new(path)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(os) => Some(os.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();

    if raw_parts.is_empty() {
        return fallback;
    }

    let mut parts = if let Some(pos) = raw_parts
        .iter()
        .rposition(|part| matches!(part.as_str(), "examples" | "src" | "tests"))
    {
        let tail = raw_parts[pos + 1..].to_vec();
        if tail.len() > 1 {
            tail[1..].to_vec()
        } else {
            tail
        }
    } else {
        raw_parts
    };

    if let Some(last) = parts.last_mut() {
        if let Some(stripped) = last.strip_suffix(".py") {
            *last = stripped.to_string();
        }
    }
    if parts.last().is_some_and(|part| part == "__init__") {
        parts.pop();
    }
    parts.retain(|part| !part.is_empty() && part != "." && part != "..");
    if parts.is_empty() {
        fallback
    } else {
        parts.join(".")
    }
}

fn parse_python_file(
    path: &str,
    source: &str,
    project_index: Option<&Arc<PyProjectIndex>>,
) -> Result<Program> {
    let module_name = python_module_name_from_path(path);
    let standalone = project_index.is_none();
    let local_entries;
    let local_index;
    let effective_project_index = if let Some(index) = project_index {
        Some(index)
    } else {
        local_entries = vec![(path.to_string(), source.to_string())];
        local_index = Arc::new(PyProjectIndex::build(&local_entries));
        Some(&local_index)
    };
    let mut builder = ModuleBuilder::new(Language::Python, path, &module_name);
    let import_map = parse_imports(source, &mut builder, &module_name);
    let classes = extract_classes(source);
    let mut known_classes = classes.iter().map(|class| class.name.clone()).collect::<HashSet<_>>();
    if let Some(index) = effective_project_index {
        known_classes.extend(index.classes_by_simple.keys().cloned());
    }
    let mut class_field_index = effective_project_index
        .map(|index| PyClassFieldIndex::from_project(Arc::clone(&index.field_types)))
        .unwrap_or_default();

    for class in &classes {
        let item = parse_class(
            &mut builder,
            class,
            &import_map,
            &known_classes,
            &class_field_index,
            &module_name,
            effective_project_index,
        );
        let mut field_types = HashMap::new();
        for field in &item.fields {
            if let Some(ty_name) = field.ty.and_then(|id| builder.find_type_name(id)) {
                field_types.insert(field.name.clone(), ty_name.to_string());
            }
        }
        class_field_index.set_fields(item.name.clone(), field_types);
        builder.push_item(Item::Class(item));
    }

    let emit_root_name_alias = !standalone
        && Path::new(path)
            .parent()
            .is_none_or(|parent| parent.as_os_str().is_empty());
    for func in extract_functions_at_indent(source, 0, 1) {
        let parsed = parse_function(
            &mut builder,
            &func,
            &import_map,
            &known_classes,
            None,
            &[],
            &HashMap::new(),
            &class_field_index,
            &module_name,
            effective_project_index,
            None,
            None,
        );
        let ParsedFunction { function, synthetic_functions, .. } = parsed;
        if emit_root_name_alias && function.name != func.name {
            let mut alias = function.clone();
            alias.name = func.name.clone();
            builder.push_item(Item::Function(alias));
        }
        builder.push_item(Item::Function(function));
        for synthetic in synthetic_functions {
            builder.push_item(Item::Function(synthetic));
        }
    }

    let mut program = builder.finish();
    if standalone {
        let prefix = format!("{module_name}.");
        for module in &mut program.modules {
            for item in &mut module.items {
                match item {
                    Item::Function(function) => {
                        if let Some(stripped) = function.name.strip_prefix(&prefix) {
                            if !stripped.contains('.') {
                                function.name = stripped.to_string();
                            }
                        }
                    }
                    Item::Class(class) => {
                        if let Some(stripped) = class.name.strip_prefix(&prefix) {
                            class.name = stripped.to_string();
                        }
                        for method in &mut class.methods {
                            if let Some(stripped) = method.name.strip_prefix(&prefix) {
                                method.name = stripped.to_string();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(program)
}
