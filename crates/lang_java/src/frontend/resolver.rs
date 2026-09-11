#[derive(Clone, Debug)]
struct JavaResolver {
    package_name: Option<String>,
    simple_class_name: String,
    class_name: String,
    exact_imports: HashMap<String, Vec<String>>,
    wildcard_imports: Vec<String>,
    static_exact_imports: HashMap<String, Vec<String>>,
    static_wildcard_imports: Vec<String>,
    // Every file in a project consults the same class/member index. Keeping
    // this behind Arc avoids cloning the complete index once per parser and
    // once per file during project analysis.
    project_index: Option<Arc<JavaProjectIndex>>,
}

impl JavaResolver {
    fn new(
        package_name: Option<String>,
        simple_class_name: String,
        class_name: String,
        project_index: Option<Arc<JavaProjectIndex>>,
    ) -> Self {
        Self {
            package_name,
            simple_class_name,
            class_name,
            exact_imports: HashMap::new(),
            wildcard_imports: Vec::new(),
            static_exact_imports: HashMap::new(),
            static_wildcard_imports: Vec::new(),
            project_index,
        }
    }

    fn qualify_type_name(&self, name: &str) -> String {
        if let Some(element) = name.trim().strip_suffix("[]") {
            return format!("{}[]", self.qualify_type_name(element.trim()));
        }
        let trimmed = normalize_java_type_name(name.trim());
        if trimmed.is_empty() {
            return name.trim().to_string();
        }
        if is_java_primitive_or_builtin(trimmed) || trimmed.contains('.') || trimmed.ends_with("[]") {
            return trimmed.to_string();
        }
        if trimmed == self.simple_class_name {
            return self.class_name.clone();
        }
        if let Some(found) = unique_import_match(&self.exact_imports, trimmed) {
            return found;
        }
        if let Some(index) = &self.project_index {
            if let Some(found) = index.resolve_same_package(self.package_name.as_deref(), trimmed) {
                return found;
            }
            if let Some(found) = resolve_unique_wildcard_type(index, &self.wildcard_imports, trimmed) {
                return found;
            }
            if let Some(found) = index.resolve_unique_simple(trimmed) {
                return found;
            }
        }
        let implicit = default_java_qualifier(trimmed);
        if implicit.starts_with("java.lang.") {
            return implicit;
        }
        if self.wildcard_imports.len() == 1 {
            return format!("{}.{}", self.wildcard_imports[0], trimmed);
        }
        if let Some(pkg) = &self.package_name {
            return format!("{pkg}.{trimmed}");
        }
        default_java_qualifier(trimmed)
    }

    fn qualify_method_target(&self, receiver_type: &str, method: &str) -> String {
        format!("{}.{}", self.qualify_type_name(receiver_type), method)
    }

    fn lookup_field_type(&self, owner_type: &str, field_name: &str) -> Option<String> {
        self.project_index
            .as_ref()
            .and_then(|index| index.field_type(&self.qualify_type_name(owner_type), field_name))
    }

    fn lookup_method_return_type(
        &self,
        owner_type: &str,
        method_name: &str,
        arg_count: Option<usize>,
        arg_types: Option<&[Option<String>]>,
    ) -> Option<String> {
        let owner = self.qualify_type_name(owner_type);
        if let Some(index) = &self.project_index {
            let found = index.method_return_type(
                &owner,
                method_name,
                arg_count,
                arg_types,
            );
            let simple = owner.rsplit('.').next().unwrap_or(&owner);
            if found.is_some() || index.fqns_by_simple.get(simple).is_some_and(|names| names.contains(&owner)) {
                return found;
            }
        }
        uniflow_hir::java_api::java_api_return_type(&owner, method_name, arg_count?).map(str::to_string)
    }

    fn resolve_static_member_call(&self, member_name: &str) -> Option<String> {
        if let Some(exact) = unique_import_match(&self.static_exact_imports, member_name) {
            return Some(exact);
        }
        if self.static_wildcard_imports.len() == 1 {
            return Some(format!("{}.{}", self.static_wildcard_imports[0], member_name));
        }
        None
    }
}
