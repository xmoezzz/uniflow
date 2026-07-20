
#[derive(Default)]
pub struct PythonParser;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StaticNamespaceMethodKind {
    Get,
    Pop,
    SetDefault,
}

#[derive(Clone, Debug, Default)]
struct PyProjectIndex {
    modules: HashSet<String>,
    classes_by_simple: HashMap<String, Vec<String>>,
    classes_by_module: HashMap<String, HashSet<String>>,
    class_bases: HashMap<String, Vec<String>>,
    class_methods: HashMap<String, HashSet<String>>,
    functions_by_simple: HashMap<String, Vec<String>>,
    functions_by_module: HashMap<String, HashSet<String>>,
    modules_by_parent: HashMap<String, HashSet<String>>,
    module_reexports: HashMap<String, HashMap<String, String>>,
    module_wildcard_imports: HashMap<String, Vec<String>>,
    module_value_types: HashMap<String, HashMap<String, String>>,
    module_symbol_aliases: HashMap<String, HashMap<String, String>>,
    module_exports_all: HashMap<String, HashSet<String>>,
    module_import_effect_member_values: HashMap<String, HashMap<String, HashMap<String, String>>>,
    module_import_effect_class_patches: HashMap<String, HashMap<String, HashMap<String, String>>>,
    typed_dict_classes: HashSet<String>,
    named_tuple_classes: HashSet<String>,
    protocol_classes: HashSet<String>,
    class_type_params: HashMap<String, Vec<String>>,
    class_base_type_args: HashMap<String, HashMap<String, Vec<String>>>,
    field_types: HashMap<String, HashMap<String, String>>,
    property_setters: HashMap<String, HashSet<String>>,
    property_deleters: HashMap<String, HashSet<String>>,
    method_returns: HashMap<String, HashMap<String, String>>,
    top_level_returns: HashMap<String, String>,
    top_level_functions: HashMap<String, PyFunctionText>,
    method_texts: HashMap<String, PyFunctionText>,
    module_imports: HashMap<String, PyImports>,
}

impl PyProjectIndex {
    fn build(entries: &[(String, String)]) -> Self {
        let mut index = Self::default();
        let mut class_entries = Vec::new();
        let mut top_level_entries = Vec::new();
        let mut module_entries = Vec::new();
        for (path, source) in entries {
            let module_name = python_module_name_from_path(path);
            index.modules.insert(module_name.clone());
            if let Some((parent, leaf)) = module_name.rsplit_once('.') {
                index
                    .modules_by_parent
                    .entry(parent.to_string())
                    .or_default()
                    .insert(leaf.to_string());
            }
            let is_package = path.ends_with("/__init__.py") || path == "__init__.py";
            let imports = parse_imports_shallow_for_module_kind(source, &module_name, is_package);
            let exports_all = parse_module_exports_all(source);
            if !exports_all.is_empty() {
                index.module_exports_all.insert(module_name.clone(), exports_all);
            }
            index.module_imports.insert(module_name.clone(), imports.clone());
            module_entries.push((module_name.clone(), imports.clone(), source.clone()));
            if !imports.aliases.is_empty() {
                index
                    .module_reexports
                    .entry(module_name.clone())
                    .or_default()
                    .extend(imports.aliases.clone());
            }
            if !imports.wildcard_bases.is_empty() {
                index
                    .module_wildcard_imports
                    .entry(module_name.clone())
                    .or_default()
                    .extend(imports.wildcard_bases.clone());
            }
            for class in extract_classes(source) {
                let qualified = format!("{module_name}.{}", class.name);
                index
                    .classes_by_simple
                    .entry(class.name.clone())
                    .or_default()
                    .push(qualified.clone());
                index
                    .classes_by_module
                    .entry(module_name.clone())
                    .or_default()
                    .insert(class.name.clone());
                let qualified_bases = class
                    .bases
                    .iter()
                    .map(|base| qualify_type_name(&module_name, base, &imports, Some(&index)).unwrap_or_else(|| base.clone()))
                    .collect::<Vec<_>>();
                let class_type_params = infer_class_type_params(&class.bases);
                let base_type_args = infer_class_base_type_args(&class.bases, &module_name, &imports, &index);
                let is_typed_dict = qualified_bases.iter().any(|base| is_typed_dict_base_name(base));
                let is_named_tuple = qualified_bases.iter().any(|base| is_named_tuple_base_name(base));
                let is_protocol = qualified_bases.iter().any(|base| is_protocol_base_name(base));
                index.class_bases.insert(qualified.clone(), qualified_bases);
                if !class_type_params.is_empty() {
                    index.class_type_params.insert(qualified.clone(), class_type_params);
                }
                if !base_type_args.is_empty() {
                    index.class_base_type_args.insert(qualified.clone(), base_type_args);
                }
                if is_typed_dict {
                    index.typed_dict_classes.insert(qualified.clone());
                }
                if is_named_tuple {
                    index.named_tuple_classes.insert(qualified.clone());
                }
                if is_protocol {
                    index.protocol_classes.insert(qualified.clone());
                }
                let methods = extract_functions_at_indent(&class.body, class.indent + 4, class.start_line + 1);
                for method in &methods {
                    index.method_texts.insert(format!("{qualified}.{}", method.name), method.clone());
                }
                let method_names = methods
                    .iter()
                    .map(|method| method.name.clone())
                    .collect::<HashSet<_>>();
                let property_setters = methods
                    .iter()
                    .filter_map(|method| property_decorator_target(method, "setter"))
                    .collect::<HashSet<_>>();
                let property_deleters = methods
                    .iter()
                    .filter_map(|method| property_decorator_target(method, "deleter"))
                    .collect::<HashSet<_>>();
                index.class_methods.insert(qualified.clone(), method_names);
                if !property_setters.is_empty() {
                    index.property_setters.insert(qualified.clone(), property_setters);
                }
                if !property_deleters.is_empty() {
                    index.property_deleters.insert(qualified.clone(), property_deleters);
                }
                class_entries.push((module_name.clone(), imports.clone(), class, qualified));
            }
            for (name, fields, kind) in extract_functional_type_decls(source, &module_name, &imports, &index) {
                let qualified = format!("{module_name}.{name}");
                index
                    .classes_by_simple
                    .entry(name.clone())
                    .or_default()
                    .push(qualified.clone());
                index
                    .classes_by_module
                    .entry(module_name.clone())
                    .or_default()
                    .insert(name);
                index.class_bases.entry(qualified.clone()).or_default();
                if !fields.is_empty() {
                    index.field_types.entry(qualified.clone()).or_default().extend(fields);
                }
                match kind.as_str() {
                    "typed_dict" => {
                        index.typed_dict_classes.insert(qualified);
                    }
                    "named_tuple" => {
                        index.named_tuple_classes.insert(qualified);
                    }
                    _ => {}
                }
            }
            for func in extract_functions_at_indent(source, 0, 1) {
                let qualified = format!("{module_name}.{}", func.name);
                index.top_level_functions.insert(qualified.clone(), func.clone());
                index
                    .functions_by_simple
                    .entry(func.name.clone())
                    .or_default()
                    .push(qualified.clone());
                index
                    .functions_by_module
                    .entry(module_name.clone())
                    .or_default()
                    .insert(func.name.clone());
                top_level_entries.push((module_name.clone(), imports.clone(), func, qualified));
            }
        }

        for _ in 0..4 {
            let mut changed = false;
            for (module_name, imports, class, qualified) in &class_entries {
                let current_fields = index.field_types.get(qualified).cloned().unwrap_or_default();
                let inferred = infer_project_class_fields(class, module_name, imports, &index, &current_fields);
                let slot = index.field_types.entry(qualified.clone()).or_default();
                for (field, ty) in inferred {
                    if slot.get(&field) != Some(&ty) {
                        slot.insert(field, ty);
                        changed = true;
                    }
                }

                let current_fields = index.field_types.get(qualified).cloned().unwrap_or_default();
                let inferred_returns = infer_project_method_returns(class, module_name, imports, &index, &current_fields);
                let return_slot = index.method_returns.entry(qualified.clone()).or_default();
                for (sig, ty) in inferred_returns {
                    if return_slot.get(&sig) != Some(&ty) {
                        return_slot.insert(sig, ty);
                        changed = true;
                    }
                }
            }
            for (module_name, imports, func, qualified) in &top_level_entries {
                let base_ty = infer_project_top_level_return(func, module_name, imports, &index);
                let decorated_callable_ty = decorate_project_callable_type(func, module_name, imports, &index, qualified);
                for arity in python_callable_arities(&parse_python_param_specs(&func.params), false) {
                    let ty = project_callable_return_from_type(&index, &decorated_callable_ty, arity)
                        .or_else(|| base_ty.clone());
                    if let Some(ty) = ty {
                        let key = top_level_signature_key(qualified, arity);
                        if index.top_level_returns.get(&key) != Some(&ty) {
                            index.top_level_returns.insert(key, ty);
                            changed = true;
                        }
                    }
                }
            }
            for (module_name, imports, source) in &module_entries {
                let (inferred_values, inferred_aliases, module_member_values, class_field_patches) =
                    infer_project_module_bindings(source, module_name, imports, &index);
                let value_slot = index.module_value_types.entry(module_name.clone()).or_default();
                for (name, ty) in inferred_values {
                    if value_slot.get(&name) != Some(&ty) {
                        value_slot.insert(name, ty);
                        changed = true;
                    }
                }
                let alias_slot = index.module_symbol_aliases.entry(module_name.clone()).or_default();
                for (name, path) in inferred_aliases {
                    if alias_slot.get(&name) != Some(&path) {
                        alias_slot.insert(name, path);
                        changed = true;
                    }
                }
                for (target_module, members) in module_member_values {
                    if target_module == *module_name {
                        let member_slot = index.module_value_types.entry(target_module).or_default();
                        for (name, ty) in members {
                            if member_slot.get(&name) != Some(&ty) {
                                member_slot.insert(name, ty);
                                changed = true;
                            }
                        }
                        continue;
                    }
                    let effect_slot = index
                        .module_import_effect_member_values
                        .entry(module_name.clone())
                        .or_default()
                        .entry(target_module)
                        .or_default();
                    for (name, ty) in members {
                        if effect_slot.get(&name) != Some(&ty) {
                            effect_slot.insert(name, ty);
                            changed = true;
                        }
                    }
                }
                for (class_name, fields) in class_field_patches {
                    if class_name == *module_name || class_name.starts_with(&format!("{module_name}.")) {
                        let field_slot = index.field_types.entry(class_name).or_default();
                        for (field, ty) in fields {
                            if field_slot.get(&field) != Some(&ty) {
                                field_slot.insert(field, ty);
                                changed = true;
                            }
                        }
                        continue;
                    }
                    let effect_slot = index
                        .module_import_effect_class_patches
                        .entry(module_name.clone())
                        .or_default()
                        .entry(class_name)
                        .or_default();
                    for (field, ty) in fields {
                        if effect_slot.get(&field) != Some(&ty) {
                            effect_slot.insert(field, ty);
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }

        // Materialize final cross-module execution effects after the fixed
        // point has converged. During inference these effects remain staged so
        // imports can still observe source execution order; the completed index
        // should expose the final monkey-patched module/class state directly.
        for (module_name, _, _) in &module_entries {
            let mut visited = HashSet::new();
            index.apply_imported_module_effects(module_name, &mut visited);
        }

        index
    }

    fn function_path_exists(&self, path: &str) -> bool {
        let mut visited = HashSet::new();
        let canonical = self.resolve_canonical_member_path(path, &mut visited);
        let Some((module, name)) = canonical.rsplit_once('.') else {
            return false;
        };
        self.functions_by_module
            .get(module)
            .is_some_and(|members| members.contains(name))
    }

    fn resolve_simple_class(&self, name: &str) -> Option<String> {
        let candidates = self.classes_by_simple.get(name)?;
        if candidates.len() == 1 {
            candidates.first().cloned()
        } else {
            None
        }
    }

    fn resolve_simple_function(&self, name: &str) -> Option<String> {
        let candidates = self.functions_by_simple.get(name)?;
        if candidates.len() == 1 {
            candidates.first().cloned()
        } else {
            None
        }
    }

    fn resolve_module_member(&self, module: &str, name: &str) -> Option<String> {
        let mut visited = HashSet::new();
        self.resolve_module_member_inner(module, name, &mut visited)
    }

    fn resolve_module_member_inner(
        &self,
        module: &str,
        name: &str,
        visited: &mut HashSet<String>,
    ) -> Option<String> {
        let marker = format!("{module}::{name}");
        if !visited.insert(marker) {
            return None;
        }

        let has_local_definition = self
            .classes_by_module
            .get(module)
            .is_some_and(|members| members.contains(name))
            || self
                .functions_by_module
                .get(module)
                .is_some_and(|members| members.contains(name));
        if !has_local_definition {
            if let Some(mapped) = self
                .module_reexports
                .get(module)
                .and_then(|exports| exports.get(name))
                .cloned()
            {
                return Some(mapped);
            }
        }

        if self
            .module_exports_all
            .get(module)
            .is_some_and(|exports| exports.contains(name))
        {
            if let Some(mapped) = self
                .module_reexports
                .get(module)
                .and_then(|exports| exports.get(name))
                .cloned()
            {
                return Some(mapped);
            }
        }

        let mut candidates = Vec::new();
        if self
            .classes_by_module
            .get(module)
            .is_some_and(|members| members.contains(name))
        {
            candidates.push(format!("{module}.{name}"));
        }
        if self
            .functions_by_module
            .get(module)
            .is_some_and(|members| members.contains(name))
        {
            candidates.push(format!("{module}.{name}"));
        }
        if self
            .module_value_types
            .get(module)
            .is_some_and(|members| members.contains_key(name))
        {
            candidates.push(format!("{module}.{name}"));
        }
        if let Some(mapped) = self
            .module_symbol_aliases
            .get(module)
            .and_then(|aliases| aliases.get(name))
            .cloned()
        {
            candidates.push(mapped);
        }
        if self
            .modules_by_parent
            .get(module)
            .is_some_and(|members| members.contains(name))
        {
            candidates.push(format!("{module}.{name}"));
        }
        if let Some(mapped) = self
            .module_reexports
            .get(module)
            .and_then(|exports| exports.get(name))
            .cloned()
        {
            candidates.push(mapped);
        }
        if let Some(bases) = self.module_wildcard_imports.get(module) {
            for base in bases {
                if let Some(exports) = self.module_exports_all.get(base) {
                    if !exports.contains(name) {
                        continue;
                    }
                }
                if let Some(mapped) = self.resolve_module_member_inner(base, name, visited) {
                    candidates.push(mapped);
                }
            }
        }
        candidates.sort();
        candidates.dedup();
        if candidates.len() == 1 {
            candidates.into_iter().next()
        } else {
            None
        }
    }

    fn module_exists(&self, name: &str) -> bool {
        self.modules.contains(name)
    }

    fn class_exists(&self, name: &str) -> bool {
        let lookup = split_project_instantiated_type(name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| name.to_string());
        self.class_bases.contains_key(&lookup)
            || self.class_methods.contains_key(&lookup)
            || self.field_types.contains_key(&lookup)
            || self
                .classes_by_module
                .get(lookup.rsplit_once('.').map(|(module, _)| module).unwrap_or(""))
                .is_some_and(|members| lookup.rsplit_once('.').is_some_and(|(_, leaf)| members.contains(leaf)))
    }

    fn is_typed_dict_class(&self, class_name: &str) -> bool {
        self.is_typed_dict_class_inner(class_name, &mut HashSet::new())
    }

    fn is_typed_dict_class_inner(&self, class_name: &str, visited: &mut HashSet<String>) -> bool {
        if !visited.insert(class_name.to_string()) {
            return false;
        }
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        self.typed_dict_classes.contains(&lookup)
            || self
                .class_bases
                .get(&lookup)
                .into_iter()
                .flatten()
                .any(|base| self.is_typed_dict_class_inner(base, visited))
    }

    #[cfg(test)]
    fn is_named_tuple_class(&self, class_name: &str) -> bool {
        self.is_named_tuple_class_inner(class_name, &mut HashSet::new())
    }

    #[cfg(test)]
    fn is_named_tuple_class_inner(&self, class_name: &str, visited: &mut HashSet<String>) -> bool {
        if !visited.insert(class_name.to_string()) {
            return false;
        }
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        self.named_tuple_classes.contains(&lookup)
            || self
                .class_bases
                .get(&lookup)
                .into_iter()
                .flatten()
                .any(|base| self.is_named_tuple_class_inner(base, visited))
    }

    fn is_protocol_class(&self, class_name: &str) -> bool {
        self.is_protocol_class_inner(class_name, &mut HashSet::new())
    }

    fn is_protocol_class_inner(&self, class_name: &str, visited: &mut HashSet<String>) -> bool {
        if !visited.insert(class_name.to_string()) {
            return false;
        }
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        self.protocol_classes.contains(&lookup)
            || self
                .class_bases
                .get(&lookup)
                .into_iter()
                .flatten()
                .any(|base| self.is_protocol_class_inner(base, visited))
    }

    fn typed_dict_key_type(&self, class_name: &str, key: &str) -> Option<String> {
        self.is_typed_dict_class(class_name)
            .then(|| self.field_type(class_name, key))
            .flatten()
    }

    fn typed_dict_value_type(&self, class_name: &str) -> Option<String> {
        if !self.is_typed_dict_class(class_name) {
            return None;
        }
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        let mut values = self
            .field_types
            .get(&lookup)
            .into_iter()
            .flat_map(|fields| fields.values().cloned())
            .map(|ty| ty.trim().to_string())
            .filter(|ty| !ty.is_empty())
            .collect::<Vec<_>>();
        values.sort();
        values.dedup();
        match values.len() {
            0 => None,
            1 => values.into_iter().next(),
            _ => Some(values.join("|")),
        }
    }

    fn typed_dict_method_return_type(&self, class_name: &str, method: &str) -> Option<String> {
        if !self.is_typed_dict_class(class_name) {
            return None;
        }
        match method {
            "keys" => Some("generator<str>".to_string()),
            "values" => Some(format!(
                "generator<{}>",
                self.typed_dict_value_type(class_name)
                    .unwrap_or_else(|| "unknown".to_string())
            )),
            "items" => Some(format!(
                "generator<tuple<str|{}>>",
                self.typed_dict_value_type(class_name)
                    .unwrap_or_else(|| "unknown".to_string())
            )),
            _ => None,
        }
    }

    fn class_base_type_substitution(&self, class_name: &str, base: &str) -> HashMap<String, String> {
        if let Some((lookup, args)) = split_project_instantiated_type(class_name) {
            if lookup == base {
                let params = self.class_type_params.get(base).cloned().unwrap_or_default();
                let mapping = project_instantiated_type_mapping(&params, &args);
                if !mapping.is_empty() {
                    return mapping;
                }
            }
            let own_params = self.class_type_params.get(&lookup).cloned().unwrap_or_default();
            let own_mapping = project_instantiated_type_mapping(&own_params, &args);
            let base_args = self
                .class_base_type_args
                .get(&lookup)
                .and_then(|bases| bases.get(base))
                .cloned()
                .unwrap_or_default();
            if !base_args.is_empty() {
                let resolved_args = base_args
                    .into_iter()
                    .map(|arg| substitute_project_type_params_in_type(&arg, &own_mapping))
                    .collect::<Vec<_>>();
                let params = self.class_type_params.get(base).cloned().unwrap_or_default();
                let mapping = project_instantiated_type_mapping(&params, &resolved_args);
                if !mapping.is_empty() {
                    return mapping;
                }
            }
        }
        let params = self.class_type_params.get(base).cloned().unwrap_or_default();
        let args = self
            .class_base_type_args
            .get(class_name)
            .and_then(|bases| bases.get(base))
            .cloned()
            .unwrap_or_default();
        project_instantiated_type_mapping(&params, &args)
    }

    fn field_type(&self, class_name: &str, field: &str) -> Option<String> {
        self.field_type_inner(class_name, field, &mut HashSet::new())
    }

    fn field_type_inner(&self, class_name: &str, field: &str, visited: &mut HashSet<String>) -> Option<String> {
        if !visited.insert(class_name.to_string()) {
            return None;
        }
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        if let Some(mut ty) = self.field_types.get(&lookup).and_then(|fields| fields.get(field)).cloned() {
            let subst = self.class_base_type_substitution(class_name, &lookup);
            if !subst.is_empty() {
                ty = substitute_project_type_params_in_type(&ty, &subst);
            }
            ty = substitute_self_type_in_type(&ty, class_name);
            let is_type_parameter = self
                .class_type_params
                .get(&lookup)
                .is_some_and(|params| params.iter().any(|param| param == &ty));
            if !is_type_parameter {
                if let Some((module_name, _)) = lookup.rsplit_once('.') {
                    if let Some(imports) = self.module_imports.get(module_name) {
                        if let Some(normalized) = normalize_python_annotation_type(&ty, module_name, imports, Some(self)) {
                            ty = normalized;
                        }
                    }
                }
            }
            return Some(ty);
        }
        for base in self.class_bases.get(&lookup).into_iter().flatten() {
            if let Some(mut ty) = self.field_type_inner(base, field, visited) {
                let subst = self.class_base_type_substitution(class_name, base);
                if !subst.is_empty() {
                    ty = substitute_project_type_params_in_type(&ty, &subst);
                }
                ty = substitute_self_type_in_type(&ty, class_name);
                return Some(ty);
            }
        }
        None
    }

    fn method_return(&self, class_name: &str, method: &str, arg_count: usize) -> Option<String> {
        self.method_return_inner(class_name, method, arg_count, &mut HashSet::new())
    }

    fn method_path(&self, class_name: &str, method: &str) -> Option<String> {
        self.method_path_inner(class_name, method, &mut HashSet::new())
    }

    fn class_has_method(&self, class_name: &str, method: &str) -> bool {
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        self.class_methods
            .get(&lookup)
            .is_some_and(|methods| methods.contains(method))
            || self
                .class_bases
                .get(&lookup)
                .into_iter()
                .flatten()
                .any(|base| self.class_has_method(base, method))
    }

    fn class_has_property_setter(&self, class_name: &str, field: &str) -> bool {
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        self.property_setters
            .get(&lookup)
            .is_some_and(|fields| fields.contains(field))
            || self
                .class_bases
                .get(&lookup)
                .into_iter()
                .flatten()
                .any(|base| self.class_has_property_setter(base, field))
    }

    fn unique_class_with_method(&self, method: &str) -> Option<String> {
        let mut matches = self
            .class_methods
            .iter()
            .filter_map(|(class_name, methods)| methods.contains(method).then_some(class_name.clone()))
            .collect::<Vec<_>>();
        matches.sort();
        matches.dedup();
        (matches.len() == 1).then(|| matches.remove(0))
    }

    fn unique_class_with_property_setter(&self, field: &str) -> Option<String> {
        let mut matches = self
            .property_setters
            .iter()
            .filter_map(|(class_name, fields)| fields.contains(field).then_some(class_name.clone()))
            .collect::<Vec<_>>();
        matches.sort();
        matches.dedup();
        (matches.len() == 1).then(|| matches.remove(0))
    }

    fn unique_class_with_property_deleter(&self, field: &str) -> Option<String> {
        let mut matches = self
            .property_deleters
            .iter()
            .filter_map(|(class_name, fields)| fields.contains(field).then_some(class_name.clone()))
            .collect::<Vec<_>>();
        matches.sort();
        matches.dedup();
        (matches.len() == 1).then(|| matches.remove(0))
    }

    fn class_has_property_deleter(&self, class_name: &str, field: &str) -> bool {
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        self.property_deleters
            .get(&lookup)
            .is_some_and(|fields| fields.contains(field))
            || self
                .class_bases
                .get(&lookup)
                .into_iter()
                .flatten()
                .any(|base| self.class_has_property_deleter(base, field))
    }

    fn method_path_inner(&self, class_name: &str, method: &str, visited: &mut HashSet<String>) -> Option<String> {
        if !visited.insert(class_name.to_string()) {
            return None;
        }
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        let direct = format!("{lookup}.{method}");
        if self
            .class_methods
            .get(&lookup)
            .is_some_and(|methods| methods.contains(method))
        {
            return Some(self.resolve_canonical_member_path(&direct, &mut HashSet::new()));
        }
        for base in self.class_bases.get(&lookup).into_iter().flatten() {
            if let Some(path) = self.method_path_inner(base, method, visited) {
                return Some(path);
            }
        }
        None
    }

    fn method_return_inner(&self, class_name: &str, method: &str, arg_count: usize, visited: &mut HashSet<String>) -> Option<String> {
        if !visited.insert(class_name.to_string()) {
            return None;
        }
        let lookup = split_project_instantiated_type(class_name)
            .map(|(base, _)| base)
            .unwrap_or_else(|| class_name.to_string());
        let key = method_signature_key(method, arg_count);
        if let Some(mut ty) = self
            .method_returns
            .get(&lookup)
            .and_then(|methods| methods.get(&key))
            .cloned()
        {
            let subst = self.class_base_type_substitution(class_name, &lookup);
            if !subst.is_empty() {
                ty = substitute_project_type_params_in_type(&ty, &subst);
            }
            return Some(substitute_self_type_in_type(&ty, class_name));
        }
        for base in self.class_bases.get(&lookup).into_iter().flatten() {
            if let Some(mut ty) = self.method_return_inner(base, method, arg_count, visited) {
                let subst = self.class_base_type_substitution(class_name, base);
                if !subst.is_empty() {
                    ty = substitute_project_type_params_in_type(&ty, &subst);
                }
                ty = substitute_self_type_in_type(&ty, class_name);
                return Some(ty);
            }
        }
        None
    }

    fn module_value_type(&self, module: &str, name: &str) -> Option<String> {
        self.module_value_types
            .get(module)
            .and_then(|values| values.get(name))
            .cloned()
    }

    fn module_symbol_alias(&self, module: &str, name: &str) -> Option<String> {
        self.module_symbol_aliases
            .get(module)
            .and_then(|values| values.get(name))
            .cloned()
    }

    fn module_value_type_by_path(&self, path: &str) -> Option<String> {
        let (module, name) = path.rsplit_once('.')?;
        self.module_value_type(module, name)
    }

    fn top_level_return(&self, function_name: &str, arg_count: usize) -> Option<String> {
        let key = top_level_signature_key(function_name, arg_count);
        if let Some(ret) = self.top_level_returns.get(&key).cloned() {
            if ret.split('|').any(|part| part.trim() == "None") && ret.split('|').any(|part| part.trim() != "None") {
                return None;
            }
            return Some(ret);
        }
        let mut visited = HashSet::new();
        let canonical = self.resolve_canonical_member_path(function_name, &mut visited);
        if canonical != function_name {
            let canonical_key = top_level_signature_key(&canonical, arg_count);
            if let Some(ret) = self.top_level_returns.get(&canonical_key).cloned() {
                if ret.split('|').any(|part| part.trim() == "None") && ret.split('|').any(|part| part.trim() != "None") {
                    return None;
                }
                return Some(ret);
            }
        }
        None
    }

    fn top_level_function_text(&self, path: &str) -> Option<&PyFunctionText> {
        let mut visited = HashSet::new();
        let canonical = self.resolve_canonical_member_path(path, &mut visited);
        self.top_level_functions.get(path).or_else(|| self.top_level_functions.get(&canonical))
    }

    fn method_text(&self, path: &str) -> Option<&PyFunctionText> {
        let mut visited = HashSet::new();
        let canonical = self.resolve_canonical_member_path(path, &mut visited);
        self.method_texts.get(path).or_else(|| self.method_texts.get(&canonical))
    }

    fn module_imports_for(&self, module: &str) -> Option<&PyImports> {
        self.module_imports.get(module)
    }

    fn apply_imported_module_effects(&mut self, module: &str, visited: &mut HashSet<String>) {
        if !visited.insert(module.to_string()) {
            return;
        }
        if let Some(imports) = self.module_imports.get(module).cloned() {
            for path in imports.aliases.values() {
                for imported_module in import_effect_modules_for_alias_path(self, path) {
                    self.apply_imported_module_effects(&imported_module, visited);
                }
            }
            for base in imports.wildcard_bases {
                for imported_module in import_effect_modules_for_alias_path(self, &base) {
                    self.apply_imported_module_effects(&imported_module, visited);
                }
            }
        }
        if let Some(member_effects) = self.module_import_effect_member_values.get(module).cloned() {
            for (target_module, members) in member_effects {
                let slot = self.module_value_types.entry(target_module).or_default();
                for (name, ty) in members {
                    slot.insert(name, ty);
                }
            }
        }
        if let Some(class_effects) = self.module_import_effect_class_patches.get(module).cloned() {
            for (class_name, fields) in class_effects {
                let slot = self.field_types.entry(class_name).or_default();
                for (field, ty) in fields {
                    slot.insert(field, ty);
                }
            }
        }
    }

    fn resolve_canonical_member_path(&self, path: &str, visited: &mut HashSet<String>) -> String {
        if !visited.insert(path.to_string()) {
            return path.to_string();
        }
        let Some((module, name)) = path.rsplit_once('.') else {
            return path.to_string();
        };
        let Some(mapped) = self.resolve_module_member_inner(module, name, &mut HashSet::new()) else {
            return path.to_string();
        };
        if mapped == path {
            return path.to_string();
        }
        self.resolve_canonical_member_path(&mapped, visited)
    }
}

