pub fn parse_project_sources(entries: &[(String, String)]) -> Result<Program> {
    let index = PyProjectIndex::build(entries);
    let mut project = Program::empty(Language::Python);
    for (path, source) in entries {
        // Python executes imported modules before the importing module's
        // function bodies become callable.  Use a per-module index snapshot so
        // recursive import side effects are visible while preserving the
        // source-order snapshots stored for other modules.
        let module_name = python_module_name_from_path(path);
        let mut effective_index = index.clone();
        effective_index.apply_imported_module_effects(&module_name, &mut HashSet::new());
        let parsed = parse_python_file(path, source, Some(&effective_index))?;
        project.merge(parsed);
    }
    Ok(project)
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

fn parse_python_file(path: &str, source: &str, project_index: Option<&PyProjectIndex>) -> Result<Program> {
    let module_name = python_module_name_from_path(path);
    let standalone = project_index.is_none();
    let local_entries;
    let local_index;
    let effective_project_index = if let Some(index) = project_index {
        Some(index)
    } else {
        local_entries = vec![(path.to_string(), source.to_string())];
        local_index = PyProjectIndex::build(&local_entries);
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
        .map(|index| index.field_types.clone())
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
        class_field_index.insert(item.name.clone(), field_types);
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
