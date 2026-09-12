
#[derive(Default)]
pub struct JavaParser;

impl SourceParser for JavaParser {
    fn language(&self) -> Language {
        Language::Java
    }

    fn parse_file(&self, path: &str, source: &str) -> Result<uniflow_hir::Program> {
        self.parse_file_with_index(path, source, None)
    }



}

#[derive(Clone, Debug, Default)]
struct JavaProjectIndex {
    fqns_by_simple: HashMap<String, Vec<String>>,
    fqns_by_package: HashMap<String, Vec<String>>,
    class_bases: HashMap<String, Vec<String>>,
    field_types: HashMap<String, HashMap<String, String>>,
    method_returns: HashMap<(String, String, usize), Vec<IndexedMethodReturn>>,
}

#[derive(Clone, Debug)]
struct IndexedMethodReturn {
    param_types: Vec<String>,
    return_type: String,
}

impl JavaProjectIndex {
    fn add_class(&mut self, package_name: Option<&str>, simple_name: &str) {
        let fqn = qualify_local_class_name(package_name, simple_name);
        self.fqns_by_simple
            .entry(simple_name.to_string())
            .or_default()
            .push(fqn.clone());
        let package_key = package_name.unwrap_or_default().to_string();
        self.fqns_by_package.entry(package_key).or_default().push(fqn);
    }

    fn finalize(&mut self) {
        for values in self.fqns_by_simple.values_mut() {
            values.sort();
            values.dedup();
        }
        for values in self.fqns_by_package.values_mut() {
            values.sort();
            values.dedup();
        }
    }

    fn add_class_details(
        &mut self,
        class_name: &str,
        bases: Vec<String>,
        fields: HashMap<String, String>,
        methods: Vec<IndexedMethodReturnEntry>,
    ) {
        if !bases.is_empty() {
            self.class_bases.insert(class_name.to_string(), bases);
        }
        if !fields.is_empty() {
            self.field_types.insert(class_name.to_string(), fields);
        }
        for method in methods {
            self.method_returns
                .entry((class_name.to_string(), method.name, method.param_types.len()))
                .or_default()
                .push(IndexedMethodReturn {
                    param_types: method.param_types,
                    return_type: method.return_type,
                });
        }
    }

    fn from_sources(entries: &[(String, String)]) -> Self {
        let mut index = Self::default();
        for (_, source) in entries {
            let stripped = strip_c_like_comments(source);
            let package_name = parse_package(&stripped);
            if let Some(class_decl) = detect_class_decl(&stripped) {
                index.add_class(package_name.as_deref(), &class_decl.simple_name);
            }
        }
        index.finalize();

        let snapshot = Arc::new(index.clone());
        for (path, source) in entries {
            let stripped = strip_c_like_comments(source);
            let package_name = parse_package(&stripped);
            let Some(class_decl) = detect_class_decl(&stripped) else {
                continue;
            };
            let class_name = qualify_local_class_name(package_name.as_deref(), &class_decl.simple_name);
            let mut builder = ModuleBuilder::new(Language::Java, path, &class_name);
            let resolver = parse_imports(
                &stripped,
                &mut builder,
                JavaResolver::new(
                    package_name.clone(),
                    class_decl.simple_name.clone(),
                    class_name.clone(),
                    Some(Arc::clone(&snapshot)),
                ),
            );
            let class_body = extract_class_body(&stripped).unwrap_or(stripped.as_str());
            let fields = extract_fields(&mut builder, class_body, &resolver)
                .into_iter()
                .map(|field| (field.field.name.clone(), field.qualified_ty.clone()))
                .collect::<HashMap<_, _>>();
            let methods = extract_methods(class_body)
                .into_iter()
                .filter_map(|method_text| {
                    let sig = parse_method_signature(method_text.signature.trim(), &class_decl.simple_name)?;
                    let return_ty = if sig.is_constructor {
                        class_name.clone()
                    } else {
                        resolver.qualify_type_name(sig.return_type.as_deref().unwrap_or("Object"))
                    };
                    let param_types = sig
                        .param_types
                        .iter()
                        .map(|ty| resolver.qualify_type_name(ty))
                        .collect::<Vec<_>>();
                    Some(IndexedMethodReturnEntry {
                        name: sig.method_name,
                        param_types,
                        return_type: return_ty,
                    })
                })
                .collect::<Vec<_>>();
            let bases = class_decl
                .bases
                .into_iter()
                .map(|base| resolver.qualify_type_name(&base))
                .collect::<Vec<_>>();
            index.add_class_details(&class_name, bases, fields, methods);
        }
        index
    }

    fn resolve_same_package(&self, package_name: Option<&str>, simple_name: &str) -> Option<String> {
        let package_key = package_name.unwrap_or_default();
        let candidates = self.fqns_by_package.get(package_key)?;
        candidates
            .iter()
            .find(|fqn| fqn.rsplit('.').next() == Some(simple_name))
            .cloned()
    }

    fn resolve_wildcard(&self, package_name: &str, simple_name: &str) -> Option<String> {
        let candidates = self.fqns_by_package.get(package_name)?;
        candidates
            .iter()
            .find(|fqn| fqn.rsplit('.').next() == Some(simple_name))
            .cloned()
    }

    fn resolve_unique_simple(&self, simple_name: &str) -> Option<String> {
        let candidates = self.fqns_by_simple.get(simple_name)?;
        if candidates.len() == 1 {
            Some(candidates[0].clone())
        } else {
            None
        }
    }

    fn field_type(&self, owner_type: &str, field_name: &str) -> Option<String> {
        let mut stack = vec![owner_type.to_string()];
        let mut seen = Vec::<String>::new();
        while let Some(cur) = stack.pop() {
            if seen.iter().any(|item| item == &cur) {
                continue;
            }
            seen.push(cur.clone());
            if let Some(fields) = self.field_types.get(&cur) {
                if let Some(found) = fields.get(field_name) {
                    return Some(found.clone());
                }
            }
            if let Some(parents) = self.class_bases.get(&cur) {
                for parent in parents {
                    stack.push(parent.clone());
                }
            }
        }
        None
    }

    fn method_return_type(
        &self,
        owner_type: &str,
        method_name: &str,
        arg_count: Option<usize>,
        arg_types: Option<&[Option<String>]>,
    ) -> Option<String> {
        let mut stack = vec![owner_type.to_string()];
        let mut seen = Vec::<String>::new();
        while let Some(cur) = stack.pop() {
            if seen.iter().any(|item| item == &cur) {
                continue;
            }
            seen.push(cur.clone());
            if let Some(arg_count) = arg_count {
                if let Some(found) = self
                    .method_returns
                    .get(&(cur.clone(), method_name.to_string(), arg_count))
                {
                    if let Some(best) = select_best_method_return(found, arg_types, &self.class_bases) {
                        return Some(best);
                    }
                }
            }
            let matches = self
                .method_returns
                .iter()
                .filter(|((owner, name, _), _)| owner == &cur && name == method_name)
                .flat_map(|(_, infos)| infos.iter())
                .map(|info| info.return_type.clone())
                .collect::<Vec<_>>();
            let mut unique = matches;
            unique.sort();
            unique.dedup();
            if unique.len() == 1 {
                return unique.into_iter().next();
            }
            if let Some(parents) = self.class_bases.get(&cur) {
                for parent in parents {
                    stack.push(parent.clone());
                }
            }
        }
        None
    }
}

pub fn parse_project_sources(entries: &[(String, String)]) -> Result<Program> {
    let index = Arc::new(JavaProjectIndex::from_sources(entries));
    let worker_count = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .min(entries.len().max(1));

    // `index` is only ever read (never mutated) once built, so parsing each
    // file against it is independent; only the final merge must preserve
    // file order.
    let parsed = if worker_count <= 1 || entries.len() <= 1 {
        entries
            .iter()
            .map(|(path, source)| {
                JavaParser::default().parse_file_with_index(path, source, Some(Arc::clone(&index)))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let chunk_size = entries.len().div_ceil(worker_count);
        thread::scope(|scope| -> Result<Vec<Program>> {
            let mut handles = Vec::with_capacity(worker_count);
            for chunk in entries.chunks(chunk_size) {
                let index = Arc::clone(&index);
                // Deeply nested or generated source can drive parsing well
                // past a default stack (this is why `main` itself runs on an
                // oversized-stack thread — see `crates/cli/src/main.rs`), and
                // scoped threads do NOT inherit their spawning thread's stack
                // size, so it must be set explicitly here too.
                handles.push(
                    thread::Builder::new()
                        .stack_size(1 << 28)
                        .spawn_scoped(scope, move || -> Result<Vec<Program>> {
                            chunk
                                .iter()
                                .map(|(path, source)| {
                                    JavaParser::default().parse_file_with_index(
                                        path,
                                        source,
                                        Some(Arc::clone(&index)),
                                    )
                                })
                                .collect()
                        })
                        .expect("failed to spawn Java parser worker thread"),
                );
            }
            let mut parsed = Vec::with_capacity(entries.len());
            for handle in handles {
                parsed.extend(
                    handle
                        .join()
                        .map_err(|_| anyhow::anyhow!("Java parser worker panicked"))??,
                );
            }
            Ok(parsed)
        })?
    };

    let mut project = uniflow_hir::ProgramMerger::new(Language::Java);
    for program in parsed {
        project.merge(program);
    }
    Ok(project.finish())
}

impl JavaParser {
    fn parse_file_with_index(
        &self,
        path: &str,
        source: &str,
        project_index: Option<Arc<JavaProjectIndex>>,
    ) -> Result<Program> {
        let source = strip_c_like_comments(source);
        let package_name = parse_package(&source);
        let class_decl = detect_class_decl(&source);
        let simple_class_name = class_decl
            .as_ref()
            .map(|decl| decl.simple_name.clone())
            .unwrap_or_else(|| module_name_from_path(path));
        let class_name = qualify_local_class_name(package_name.as_deref(), &simple_class_name);

        let mut builder = ModuleBuilder::new(Language::Java, path, &class_name);
        let resolver = parse_imports(
            &source,
            &mut builder,
            JavaResolver::new(
                package_name.clone(),
                simple_class_name.clone(),
                class_name.clone(),
                project_index,
            ),
        );

        let class_symbol = builder.add_symbol(&class_name, SymbolKind::Class);
        let body_range = extract_class_body_range(&source).unwrap_or(0..source.len());
        let class_body = &source[body_range.clone()];
        let class_body_base = span_from_offsets(
            builder.file_id(), &source, body_range.start, body_range.start,
        );
        let mut parsed_fields = extract_fields(&mut builder, class_body, &resolver);
        for field in &mut parsed_fields {
            field.field.span = offset_java_span(class_body_base, field.field.span);
        }
        let fields = parsed_fields
            .iter()
            .map(|field| field.field.clone())
            .collect::<Vec<_>>();

        let mut methods = Vec::new();
        for mut method_text in extract_methods(class_body) {
            method_text.span = offset_java_span(class_body_base, method_text.span);
            method_text.signature_span = offset_java_span(class_body_base, method_text.signature_span);
            method_text.body_span = offset_java_span(class_body_base, method_text.body_span);
            if let Some(method) = parse_method(
                &mut builder,
                &class_name,
                &simple_class_name,
                &method_text,
                &resolver,
                &parsed_fields,
            ) {
                methods.push(method);
            }
        }

        let class_span = class_decl
            .as_ref()
            .map(|decl| decl.span)
            .unwrap_or_else(default_span);
        let bases = class_decl
            .map(|decl| {
                decl.bases
                    .into_iter()
                    .map(|base| resolver.qualify_type_name(&base))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        builder.push_item(Item::Class(Class {
            name: class_name,
            symbol: Some(class_symbol),
            bases,
            fields,
            methods,
            span: class_span,
        }));

        Ok(builder.finish())
    }
}
