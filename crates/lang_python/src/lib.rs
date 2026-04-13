use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use uniflow_hir::{
    BinaryOp, Block, CallTarget, CatchClause, Class, Expr, ExprId, Field, Item, LambdaCapture, Language, LValue, Param, ParamKind,
    Program, Span, Stmt, SymbolId, SymbolKind, UnaryOp,
};
use uniflow_parser_core::{
    default_span, ensure_known_symbol, is_int_literal, is_string_literal, module_name_from_path,
    new_call, new_call_with_arg_names, new_dynamic_call_with_arg_names, new_field_read, new_int, new_string, new_var_ref, parse_call_parts,
    span_from_line_range, split_last_top_level_dot, split_once_top_level, split_top_level_commas,
    ModuleBuilder, SourceParser,
};

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
            let imports = parse_imports_shallow_for_module(source, &module_name);
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

    fn is_named_tuple_class(&self, class_name: &str) -> bool {
        self.is_named_tuple_class_inner(class_name, &mut HashSet::new())
    }

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
            return Some(substitute_self_type_in_type(&ty, class_name));
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
            return Some(ret);
        }
        let mut visited = HashSet::new();
        let canonical = self.resolve_canonical_member_path(function_name, &mut visited);
        if canonical != function_name {
            let canonical_key = top_level_signature_key(&canonical, arg_count);
            if let Some(ret) = self.top_level_returns.get(&canonical_key).cloned() {
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

pub fn parse_project_sources(entries: &[(String, String)]) -> Result<Program> {
    let index = PyProjectIndex::build(entries);
    let mut project = Program::empty(Language::Python);
    for (path, source) in entries {
        let parsed = parse_python_file(path, source, Some(&index))?;
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
    let mut builder = ModuleBuilder::new(Language::Python, path, &module_name);
    let import_map = parse_imports(source, &mut builder, &module_name);
    let classes = extract_classes(source);
    let mut known_classes = classes.iter().map(|class| class.name.clone()).collect::<HashSet<_>>();
    if let Some(index) = project_index {
        known_classes.extend(index.classes_by_simple.keys().cloned());
    }
    let mut class_field_index = project_index
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
            project_index,
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
            project_index,
            None,
            None,
        );
        let ParsedFunction { function, synthetic_functions, .. } = parsed;
        builder.push_item(Item::Function(function));
        for synthetic in synthetic_functions {
            builder.push_item(Item::Function(synthetic));
        }
    }

    Ok(builder.finish())
}

#[derive(Clone, Debug)]
struct PyFunctionText {
    name: String,
    params: String,
    body: String,
    start_line: u32,
    end_line: u32,
    decorators: Vec<String>,
}

#[derive(Clone, Debug)]
struct PyClassText {
    name: String,
    bases: Vec<String>,
    body: String,
    start_line: u32,
    end_line: u32,
    indent: usize,
}

#[derive(Clone, Debug, Default)]
struct ProjectFunctionSummary {
    return_type: Option<String>,
    writeback_types: HashMap<String, String>,
    writeback_callables: HashMap<String, String>,
    local_field_writes: HashMap<String, HashMap<String, String>>,
    precise_index_type_writes: HashMap<String, HashMap<String, String>>,
    precise_index_callable_writes: HashMap<String, HashMap<String, String>>,
}

#[derive(Clone, Debug)]
struct ParsedFunction {
    function: uniflow_hir::Function,
    discovered_fields: Vec<Field>,
    synthetic_functions: Vec<uniflow_hir::Function>,
}

#[derive(Clone, Debug, Default)]
struct PyImports {
    aliases: HashMap<String, String>,
    wildcard_bases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PyParamKind {
    Positional,
    VarArgs,
    KwArgs,
}

#[derive(Clone, Debug)]
struct PyParamSpec {
    name: String,
    kind: PyParamKind,
    has_default: bool,
    keyword_only: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PyCallArgSpread {
    None,
    Star,
    StarStar,
}

#[derive(Clone, Debug)]
struct PyCallArgText {
    name: Option<String>,
    expr: String,
    spread: PyCallArgSpread,
}

fn parse_python_param_specs(param_text: &str) -> Vec<PyParamSpec> {
    let mut out = Vec::new();
    let mut keyword_only = false;
    for raw in split_top_level_commas(param_text) {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "/" {
            continue;
        }
        if trimmed == "*" {
            keyword_only = true;
            continue;
        }
        let (kind, raw_name) = if let Some(rest) = trimmed.strip_prefix("**") {
            (PyParamKind::KwArgs, rest.trim())
        } else if let Some(rest) = trimmed.strip_prefix('*') {
            keyword_only = true;
            (PyParamKind::VarArgs, rest.trim())
        } else {
            (PyParamKind::Positional, trimmed)
        };
        let has_default = split_once_top_level(raw_name, '=').is_some();
        let before_default = split_once_top_level(raw_name, '=')
            .map(|(left, _)| left.trim().to_string())
            .unwrap_or_else(|| raw_name.trim().to_string());
        let name = split_once_top_level(&before_default, ':')
            .map(|(left, _)| left.trim().to_string())
            .unwrap_or(before_default)
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }
        let is_keyword_only = keyword_only && kind == PyParamKind::Positional;
        out.push(PyParamSpec {
            name,
            kind,
            has_default,
            keyword_only: is_keyword_only,
        });
    }
    out
}

fn python_callable_arities(param_specs: &[PyParamSpec], drop_receiver: bool) -> Vec<usize> {
    let specs = if drop_receiver && !param_specs.is_empty() {
        &param_specs[1..]
    } else {
        param_specs
    };
    let mut min = 0usize;
    let mut max = 0usize;
    for spec in specs {
        match spec.kind {
            PyParamKind::Positional => {
                max += 1;
                if !spec.has_default {
                    min += 1;
                }
            }
            PyParamKind::VarArgs | PyParamKind::KwArgs => {}
        }
    }
    (min..=max).collect()
}

fn parse_python_call_args_detailed(arg_text: &str) -> Vec<PyCallArgText> {
    split_top_level_commas(arg_text)
        .into_iter()
        .filter_map(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            if let Some((left, right)) = split_python_keyword_arg(trimmed) {
                return Some(PyCallArgText {
                    name: Some(left),
                    expr: normalize_python_argument_expr(&right),
                    spread: PyCallArgSpread::None,
                });
            }
            let spread = if trimmed.starts_with("**") {
                PyCallArgSpread::StarStar
            } else if trimmed.starts_with('*') {
                PyCallArgSpread::Star
            } else {
                PyCallArgSpread::None
            };
            Some(PyCallArgText {
                name: None,
                expr: normalize_python_argument_expr(trimmed),
                spread,
            })
        })
        .collect()
}

fn resolve_relative_import_base(current_module: &str, raw_base: &str) -> String {
    let trimmed = raw_base.trim();
    if !trimmed.starts_with('.') {
        return trimmed.to_string();
    }
    let leading_dots = trimmed.chars().take_while(|ch| *ch == '.').count();
    let suffix = trimmed[leading_dots..].trim_matches('.');
    let mut parts = current_module
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if !parts.is_empty() {
        parts.pop();
    }
    let pops = leading_dots.saturating_sub(1);
    for _ in 0..pops {
        if !parts.is_empty() {
            parts.pop();
        }
    }
    if !suffix.is_empty() {
        parts.extend(suffix.split('.').filter(|part| !part.is_empty()));
    }
    if parts.is_empty() {
        trimmed.trim_start_matches('.').to_string()
    } else {
        parts.join(".")
    }
}

fn canonicalize_project_path(index: &PyProjectIndex, path: &str) -> String {
    if path.contains('.') {
        index.resolve_canonical_member_path(path, &mut HashSet::new())
    } else {
        path.to_string()
    }
}

fn parse_destructuring_targets(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    let inner = if (trimmed.starts_with('(') && trimmed.ends_with(')')) || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
        &trimmed[1..trimmed.len().saturating_sub(1)]
    } else {
        trimmed
    };
    let parts = split_top_level_commas(inner)
        .into_iter()
        .map(|part| part.trim().to_string())
        .filter(|part| is_simple_ident(part))
        .collect::<Vec<_>>();
    if parts.len() >= 2 { parts } else { Vec::new() }
}

fn parse_tuple_type_elements(text: &str) -> Option<Vec<String>> {
    let inner = text.strip_prefix("tuple<")?.strip_suffix('>')?;
    let elems = inner.split('|').map(|part| part.trim().to_string()).filter(|part| !part.is_empty()).collect::<Vec<_>>();
    if elems.is_empty() { None } else { Some(elems) }
}

fn infer_simple_destructured_types(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Vec<Option<String>> {
    let trimmed = text.trim();
    if (trimmed.starts_with('(') && trimmed.ends_with(')')) || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner).into_iter().filter(|item| !item.trim().is_empty()).collect::<Vec<_>>();
        if items.len() >= 2 {
            return items.into_iter().map(|item| infer_simple_python_type(&item, imports, env, known_classes)).collect();
        }
    }
    if let Some(ty) = infer_simple_python_type(trimmed, imports, env, known_classes) {
        if let Some(elems) = destructure_type_elements(&ty) {
            return elems.into_iter().map(Some).collect();
        }
    }
    Vec::new()
}

fn destructure_type_elements(ty: &str) -> Option<Vec<String>> {
    if let Some(items) = parse_tuple_type_elements(ty) {
        return Some(items);
    }
    if let Some(inner) = ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some(items) = parse_tuple_type_elements(inner) {
            return Some(items);
        }
    }
    None
}

fn new_unpack_symbol(builder: &mut ModuleBuilder, prefix: &str, line_no: u32, slot: usize) -> SymbolId {
    builder.add_symbol(&format!("__py_{}_{}_{}", prefix, line_no, slot), SymbolKind::Local)
}

fn build_unpack_index_expr(
    builder: &mut ModuleBuilder,
    source_symbol: SymbolId,
    index: usize,
    line_no: u32,
) -> Expr {
    with_line_span(
        Expr::IndexRead {
            id: builder.alloc_expr_id(),
            base: Box::new(with_line_span(new_var_ref(builder, source_symbol), builder.file_id(), line_no)),
            index: Box::new(new_int(builder, index as i64)),
            span: default_span(),
        },
        builder.file_id(),
        line_no,
    )
}

fn extend_destructuring_bindings(
    builder: &mut ModuleBuilder,
    out: &mut Vec<Stmt>,
    targets: &[String],
    source_symbol: SymbolId,
    inferred_types: &[Option<String>],
    env: &mut PyEnv,
    line_no: u32,
) {
    let span = span_from_line_range(builder.file_id(), line_no, line_no);
    for (idx, target) in targets.iter().enumerate() {
        let existed_before = env.vars.contains_key(target);
        let symbol = if let Some(existing) = env.vars.get(target).copied() {
            existing
        } else {
            let created = ensure_known_symbol(builder, &mut env.vars, target, SymbolKind::Local);
            env.vars.insert(target.clone(), created);
            created
        };
        let rhs = build_unpack_index_expr(builder, source_symbol, idx, line_no);
        let inferred_ty = inferred_types.get(idx).and_then(|ty| ty.clone());
        if let Some(ty) = inferred_ty.clone() {
            env.types.insert(target.clone(), ty);
        }
        if !existed_before {
            out.push(Stmt::Let {
                id: builder.alloc_stmt_id(),
                symbol,
                ty: inferred_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                init: Some(rhs),
                span,
            });
        } else {
            out.push(Stmt::Assign {
                id: builder.alloc_stmt_id(),
                lhs: LValue::Var(symbol),
                rhs,
                span,
            });
        }
    }
}

fn bind_comprehension_target_env(
    builder: &mut ModuleBuilder,
    env: &mut PyEnv,
    target_text: &str,
    item_ty: Option<&str>,
    line_no: u32,
    slot_base: usize,
) {
    let trimmed = target_text.trim();
    let destructured = parse_destructuring_targets(trimmed);
    if destructured.is_empty() {
        if is_simple_ident(trimmed) {
            env.vars.insert(trimmed.to_string(), new_unpack_symbol(builder, "comp_item", line_no, slot_base));
            if let Some(ty) = item_ty {
                env.types.insert(trimmed.to_string(), ty.to_string());
            }
        }
        return;
    }
    let target_types = item_ty.and_then(destructure_type_elements).unwrap_or_default();
    for (idx, target) in destructured.into_iter().enumerate() {
        env.vars.insert(target.clone(), new_unpack_symbol(builder, "comp_item", line_no, slot_base + idx));
        if let Some(ty) = target_types.get(idx) {
            env.types.insert(target, ty.clone());
        }
    }
}

fn bind_comprehension_target_types_only(env: &mut PyEnv, target_text: &str, item_ty: Option<&str>) {
    let trimmed = target_text.trim();
    let destructured = parse_destructuring_targets(trimmed);
    if destructured.is_empty() {
        if is_simple_ident(trimmed) {
            if let Some(ty) = item_ty {
                env.types.insert(trimmed.to_string(), ty.to_string());
            }
        }
        return;
    }
    let target_types = item_ty.and_then(destructure_type_elements).unwrap_or_default();
    for (idx, target) in destructured.into_iter().enumerate() {
        if let Some(ty) = target_types.get(idx) {
            env.types.insert(target, ty.clone());
        }
    }
}

fn infer_project_destructured_types(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Vec<Option<String>> {
    let trimmed = text.trim();
    if (trimmed.starts_with('(') && trimmed.ends_with(')')) || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner).into_iter().filter(|item| !item.trim().is_empty()).collect::<Vec<_>>();
        if items.len() >= 2 {
            return items.into_iter().map(|item| infer_project_expr_type(&item, module_name, imports, index, current_fields, current_class)).collect();
        }
    }
    if let Some(ty) = infer_project_expr_type(trimmed, module_name, imports, index, current_fields, current_class) {
        if let Some(elems) = parse_tuple_type_elements(&ty) {
            return elems.into_iter().map(Some).collect();
        }
    }
    Vec::new()
}

fn parse_imports_shallow(source: &str) -> PyImports {
    parse_imports_shallow_for_module(source, "")
}

fn parse_imports_shallow_for_module(source: &str, module_name: &str) -> PyImports {
    let mut imports = PyImports::default();

    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("import ") {
            for part in split_top_level_commas(rest) {
                let entry = part.trim();
                if entry.is_empty() {
                    continue;
                }
                let (path, alias) = if let Some((lhs, rhs)) = entry.split_once(" as ") {
                    (lhs.trim(), Some(rhs.trim().to_string()))
                } else {
                    (entry, None)
                };
                let path = resolve_relative_import_base(module_name, path);
                let alias = alias.unwrap_or_else(|| {
                    path.split('.')
                        .next()
                        .unwrap_or(path.as_str())
                        .to_string()
                });
                imports.aliases.insert(alias, path);
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("from ") {
            let Some((base, names)) = rest.split_once(" import ") else {
                continue;
            };
            let base = resolve_relative_import_base(module_name, base.trim());
            for part in split_top_level_commas(names) {
                let entry = part.trim();
                if entry.is_empty() {
                    continue;
                }
                if entry == "*" {
                    imports.wildcard_bases.push(base.to_string());
                    continue;
                }
                let (name, alias) = if let Some((lhs, rhs)) = entry.split_once(" as ") {
                    (lhs.trim(), Some(rhs.trim().to_string()))
                } else {
                    (entry, None)
                };
                let full = if name == "." || name.is_empty() {
                    base.to_string()
                } else {
                    format!("{base}.{name}")
                };
                let alias = alias.unwrap_or_else(|| name.to_string());
                imports.aliases.insert(alias, full);
            }
        }
    }

    imports
}

fn parse_imports(source: &str, builder: &mut ModuleBuilder, module_name: &str) -> PyImports {
    let imports = parse_imports_shallow_for_module(source, module_name);
    for (alias, path) in &imports.aliases {
        builder.add_import(path, Some(alias.clone()));
    }
    for base in &imports.wildcard_bases {
        builder.add_import(&format!("{base}.*"), Some("*".to_string()));
    }
    imports
}

fn parse_module_exports_all(source: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if let Some((left, right)) = split_once_top_level(line, '=') {
            if left.trim() != "__all__" {
                continue;
            }
            let rhs = right.trim();
            if !(rhs.starts_with('[') && rhs.ends_with(']')) && !(rhs.starts_with('(') && rhs.ends_with(')')) {
                continue;
            }
            let inner = &rhs[1..rhs.len().saturating_sub(1)];
            for item in split_top_level_commas(inner) {
                let value = item.trim();
                if is_string_literal(value) && value.len() >= 2 {
                    out.insert(value[1..value.len() - 1].to_string());
                }
            }
        }
    }
    out
}

fn canonicalize_prefixed_project_path(index: &PyProjectIndex, path: &str) -> Option<String> {
    let mut parts = path.split('.').filter(|part| !part.is_empty());
    let first = parts.next()?;
    let mut current = first.to_string();
    for part in parts {
        if index.module_exists(&current) {
            if let Some(member) = index.resolve_module_member(&current, part) {
                current = member;
                continue;
            }
        }
        current = format!("{current}.{part}");
    }
    Some(canonicalize_project_path(index, &current))
}

fn resolve_prefixed_imported_name(name: &str, imports: &PyImports, env: &PyEnv) -> Option<String> {
    let (head, tail) = split_once_top_level(name, '.')?;
    let head = head.trim();
    let tail = tail.trim();
    if head.is_empty() || tail.is_empty() {
        return None;
    }
    if let Some(base) = imports.aliases.get(head) {
        return canonicalize_prefixed_project_path(&env.project_index, &format!("{base}.{tail}"));
    }
    if let Some(base) = env.project_index.resolve_module_member(&env.current_module, head) {
        return canonicalize_prefixed_project_path(&env.project_index, &format!("{base}.{tail}"));
    }
    if env.project_index.module_exists(head) {
        return canonicalize_prefixed_project_path(&env.project_index, name);
    }
    None
}

fn resolve_imported_name(name: &str, imports: &PyImports, env: &PyEnv) -> Option<String> {
    if let Some(prefixed) = resolve_prefixed_imported_name(name, imports, env) {
        return Some(prefixed);
    }
    if let Some(mapped) = imports.aliases.get(name) {
        return Some(canonicalize_project_path(&env.project_index, mapped));
    }
    let mut candidates = Vec::new();
    for base in &imports.wildcard_bases {
        if let Some(member) = env.project_index.resolve_module_member(base, name) {
            candidates.push(canonicalize_project_path(&env.project_index, &member));
        } else {
            candidates.push(canonicalize_project_path(&env.project_index, &format!("{base}.{name}")));
        }
    }
    if let Some(in_module) = env.project_index.resolve_module_member(&env.current_module, name) {
        candidates.push(canonicalize_project_path(&env.project_index, &in_module));
    }
    if let Some(unique) = env.project_index.resolve_simple_class(name) {
        candidates.push(canonicalize_project_path(&env.project_index, &unique));
    }
    if let Some(unique_fn) = env.project_index.resolve_simple_function(name) {
        candidates.push(canonicalize_project_path(&env.project_index, &unique_fn));
    }
    candidates.sort();
    candidates.dedup();
    if candidates.len() == 1 {
        return candidates.into_iter().next();
    }
    None
}

fn qualify_class_name(module_name: &str, class_name: &str, project_index: Option<&PyProjectIndex>) -> String {
    project_index
        .and_then(|index| index.resolve_module_member(module_name, class_name))
        .unwrap_or_else(|| class_name.to_string())
}

fn qualify_type_name(
    module_name: &str,
    name: &str,
    imports: &PyImports,
    project_index: Option<&PyProjectIndex>,
) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((base, _inner)) = split_python_generic_annotation(trimmed) {
        if base != trimmed {
            return qualify_type_name(module_name, &base, imports, project_index);
        }
    }
    if let Some(index) = project_index {
        if let Some(mapped) = imports.aliases.get(trimmed) {
            return Some(canonicalize_project_path(index, mapped));
        }
        if trimmed.contains('.') {
            if let Some((head, tail)) = split_once_top_level(trimmed, '.') {
                if let Some(mapped) = imports.aliases.get(head.trim()) {
                    return canonicalize_prefixed_project_path(index, &format!("{}.{}", mapped, tail.trim()));
                }
            }
            return Some(canonicalize_project_path(index, trimmed));
        }
        if let Some(in_module) = index.resolve_module_member(module_name, trimmed) {
            return Some(canonicalize_project_path(index, &in_module));
        }
        if let Some(unique) = index.resolve_simple_class(trimmed) {
            return Some(canonicalize_project_path(index, &unique));
        }
        if let Some(unique_fn) = index.resolve_simple_function(trimmed) {
            return Some(canonicalize_project_path(index, &unique_fn));
        }
    }
    if let Some(mapped) = imports.aliases.get(trimmed) {
        return Some(mapped.clone());
    }
    if trimmed.contains('.') {
        return Some(trimmed.to_string());
    }
    Some(trimmed.to_string())
}

fn split_python_generic_annotation(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    if !trimmed.ends_with(']') {
        return None;
    }
    let mut depth_paren = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_angle = 0usize;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '<' => depth_angle += 1,
            '>' => depth_angle = depth_angle.saturating_sub(1),
            '[' if depth_paren == 0 && depth_brace == 0 && depth_angle == 0 => {
                let base = trimmed[..idx].trim();
                let inner = &trimmed[idx + 1..trimmed.len().saturating_sub(1)];
                if !base.is_empty() {
                    return Some((base.to_string(), inner.to_string()));
                }
                return None;
            }
            _ => {}
        }
    }
    None
}


fn is_builtin_generic_type_name(name: &str) -> bool {
    matches!(
        name,
        "list" | "set" | "dict" | "tuple" | "generator" | "callable" | "defaultdict" | "deque"
    )
}

fn split_project_instantiated_type(text: &str) -> Option<(String, Vec<String>)> {
    let trimmed = text.trim();
    if !trimmed.ends_with('>') {
        return None;
    }
    let mut depth_paren = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_bracket = 0usize;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '<' if depth_paren == 0 && depth_brace == 0 && depth_bracket == 0 => {
                let base = trimmed[..idx].trim();
                if base.is_empty() || !base.contains('.') || is_builtin_generic_type_name(base) {
                    return None;
                }
                let inner = &trimmed[idx + 1..trimmed.len().saturating_sub(1)];
                let args = split_top_level_commas(inner)
                    .into_iter()
                    .map(|part| part.trim().to_string())
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>();
                if args.is_empty() {
                    return None;
                }
                return Some((base.to_string(), args));
            }
            _ => {}
        }
    }
    None
}

fn project_instantiated_type_mapping(
    params: &[String],
    args: &[String],
) -> HashMap<String, String> {
    params
        .iter()
        .cloned()
        .zip(args.iter().cloned())
        .filter(|(param, arg)| !param.is_empty() && !arg.is_empty())
        .collect()
}

fn infer_class_type_params(raw_bases: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in raw_bases {
        let Some((base, inner)) = split_python_generic_annotation(raw) else {
            continue;
        };
        if !matches!(
            base.as_str(),
            "Generic" | "typing.Generic" | "Protocol" | "typing.Protocol" | "typing_extensions.Protocol"
        ) && !base.ends_with(".Generic")
            && !base.ends_with(".Protocol")
        {
            continue;
        }
        for part in split_top_level_commas(&inner) {
            let name = part.trim();
            if is_simple_ident(name) && !out.iter().any(|existing| existing == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn infer_class_base_type_args(
    raw_bases: &[String],
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    for raw in raw_bases {
        let Some((base, inner)) = split_python_generic_annotation(raw) else {
            continue;
        };
        let Some(canonical_base) = qualify_type_name(module_name, &base, imports, Some(index)) else {
            continue;
        };
        let args = split_top_level_commas(&inner)
            .into_iter()
            .filter_map(|part| {
                let part = part.trim();
                if part.is_empty() {
                    return None;
                }
                normalize_python_annotation_type(part, module_name, imports, Some(index))
                    .or_else(|| qualify_type_name(module_name, part, imports, Some(index)))
                    .or_else(|| Some(part.to_string()))
            })
            .collect::<Vec<_>>();
        if !args.is_empty() {
            out.insert(canonical_base, args);
        }
    }
    out
}

fn has_top_level_separator(text: &str, separator: char) -> bool {
    let mut depth_paren = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_angle = 0usize;
    for ch in text.chars() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '<' => depth_angle += 1,
            '>' => depth_angle = depth_angle.saturating_sub(1),
            _ if ch == separator && depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && depth_angle == 0 => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn split_top_level_separator(text: &str, separator: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth_paren = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_angle = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '<' => depth_angle += 1,
            '>' => depth_angle = depth_angle.saturating_sub(1),
            _ if ch == separator && depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && depth_angle == 0 => {
                out.push(text[start..idx].trim().to_string());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    out.push(text[start..].trim().to_string());
    out
}

fn split_angle_type_args(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    if !trimmed.ends_with('>') {
        return None;
    }
    let mut depth_paren = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_angle = 0usize;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '<' if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && depth_angle == 0 => {
                let base = trimmed[..idx].trim();
                let inner = &trimmed[idx + 1..trimmed.len().saturating_sub(1)];
                if !base.is_empty() {
                    return Some((base.to_string(), inner.to_string()));
                }
                return None;
            }
            '<' => depth_angle += 1,
            '>' => depth_angle = depth_angle.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn substitute_project_type_params_in_type(ty: &str, mapping: &HashMap<String, String>) -> String {
    let trimmed = ty.trim();
    if trimmed.is_empty() || mapping.is_empty() {
        return trimmed.to_string();
    }
    if let Some(mapped) = mapping.get(trimmed) {
        return mapped.clone();
    }
    if has_top_level_separator(trimmed, '|') {
        let parts = split_top_level_separator(trimmed, '|')
            .into_iter()
            .map(|part| substitute_project_type_params_in_type(&part, mapping))
            .collect::<Vec<_>>();
        return parts.join("|");
    }
    if let Some((base, inner)) = split_angle_type_args(trimmed) {
        let separator = if base == "tuple" { '|' } else { ',' };
        let sep = separator.to_string();
        let parts = split_top_level_separator(&inner, separator)
            .into_iter()
            .map(|part| substitute_project_type_params_in_type(&part, mapping))
            .collect::<Vec<_>>();
        return format!("{base}<{}>", parts.join(&sep));
    }
    trimmed.to_string()
}


fn substitute_self_type_in_type(ty: &str, concrete_class: &str) -> String {
    let trimmed = ty.trim();
    if matches!(trimmed, "Self" | "typing.Self" | "typing_extensions.Self") {
        return concrete_class.to_string();
    }
    if has_top_level_separator(trimmed, '|') {
        let parts = split_top_level_separator(trimmed, '|')
            .into_iter()
            .map(|part| substitute_self_type_in_type(&part, concrete_class))
            .collect::<Vec<_>>();
        return parts.join("|");
    }
    if let Some(inner) = trimmed.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
        return format!("list<{}>", substitute_self_type_in_type(inner, concrete_class));
    }
    if let Some(inner) = trimmed.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
        return format!("set<{}>", substitute_self_type_in_type(inner, concrete_class));
    }
    if let Some(inner) = trimmed.strip_prefix("generator<").and_then(|rest| rest.strip_suffix('>')) {
        return format!("generator<{}>", substitute_self_type_in_type(inner, concrete_class));
    }
    if let Some(inner) = trimmed.strip_prefix("callable<").and_then(|rest| rest.strip_suffix('>')) {
        return format!("callable<{}>", substitute_self_type_in_type(inner, concrete_class));
    }
    if let Some(inner) = trimmed.strip_prefix("tuple<").and_then(|rest| rest.strip_suffix('>')) {
        let parts = split_top_level_commas(inner)
            .into_iter()
            .map(|part| substitute_self_type_in_type(&part, concrete_class))
            .collect::<Vec<_>>();
        return format!("tuple<{}>", parts.join("|"));
    }
    if let Some(inner) = trimmed.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some((key, value)) = split_once_top_level(inner, ',') {
            return format!(
                "dict<{},{}>",
                substitute_self_type_in_type(key.trim(), concrete_class),
                substitute_self_type_in_type(value.trim(), concrete_class)
            );
        }
    }
    trimmed.to_string()
}

fn split_python_keyword_arg(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    if ["==", "!=", ">=", "<=", ":="]
        .iter()
        .any(|token| trimmed.contains(token))
    {
        return None;
    }
    let (left, right) = split_once_top_level(trimmed, '=')?;
    if !is_simple_ident(left.trim()) {
        return None;
    }
    Some((left.trim().to_string(), right.trim().to_string()))
}

fn normalize_python_argument_expr(text: &str) -> String {
    let trimmed = text.trim();
    if let Some(inner) = trimmed.strip_prefix("await ") {
        return normalize_python_argument_expr(inner);
    }
    if let Some(inner) = trimmed.strip_prefix("**") {
        return inner.trim().to_string();
    }
    if let Some(inner) = trimmed.strip_prefix('*') {
        return inner.trim().to_string();
    }
    if let Some((_, right)) = split_python_keyword_arg(trimmed) {
        return right;
    }
    trimmed.to_string()
}

fn split_python_call_args(arg_text: &str) -> Vec<String> {
    parse_python_call_args_detailed(arg_text)
        .into_iter()
        .map(|arg| arg.expr)
        .collect()
}

fn parse_static_sequence_items(text: &str) -> Option<Vec<String>> {
    let trimmed = text.trim();
    if (trimmed.starts_with('(') && trimmed.ends_with(')')) || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner)
            .into_iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>();
        return Some(items);
    }
    None
}

fn parse_static_mapping_entries(text: &str) -> Option<Vec<(String, String)>> {
    let trimmed = text.trim();
    let mut out = Vec::new();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        for entry in split_top_level_commas(inner).into_iter().filter(|part| !part.trim().is_empty()) {
            if let Some((key_text, value_text)) = split_once_top_level(&entry, ':') {
                if let Some(key) = strip_python_string_literal(&key_text).or_else(|| {
                    let key = key_text.trim();
                    is_simple_ident(key).then(|| key.to_string())
                }) {
                    out.push((key, value_text.trim().to_string()));
                }
            }
        }
        return (!out.is_empty()).then_some(out);
    }
    if let Some((dict_callee, dict_args)) = parse_call_parts(trimmed) {
        let dict_name = dict_callee.trim();
        if dict_name == "dict" || dict_name == "builtins.dict" {
            for entry in parse_python_call_args_detailed(&dict_args) {
                if entry.spread == PyCallArgSpread::StarStar {
                    if let Some(items) = parse_static_mapping_entries(&entry.expr) {
                        out.extend(items);
                    }
                    continue;
                }
                if let Some(name) = entry.name {
                    out.push((name, entry.expr.trim().to_string()));
                }
            }
            return (!out.is_empty()).then_some(out);
        }
    }
    None
}

fn current_super_type(env: &PyEnv) -> Option<String> {
    env.current_class_bases
        .first()
        .cloned()
        .or_else(|| env.current_class.clone())
}

fn current_project_super_type(index: &PyProjectIndex, current_class: Option<&str>) -> Option<String> {
    let class_name = current_class?;
    index
        .class_bases
        .get(class_name)
        .and_then(|bases| bases.first().cloned())
        .or_else(|| Some(class_name.to_string()))
}

fn descriptor_access_type(index: &PyProjectIndex, ty: &str) -> Option<String> {
    index
        .method_return(ty, "__get__", 2)
        .or_else(|| index.method_return(ty, "__get__", 1))
}

fn direct_field_access_type(index: &PyProjectIndex, owner_type: &str, field: &str) -> Option<String> {
    let ty = index.field_type(owner_type, field)?;
    descriptor_access_type(index, &ty).or(Some(ty))
}

fn direct_local_field_access_type(env: &PyEnv, owner_name: &str, field: &str) -> Option<String> {
    let raw = env
        .local_field_types
        .get(owner_name)
        .and_then(|fields| fields.get(field))
        .cloned()?;
    descriptor_access_type(&env.project_index, &raw).or(Some(raw))
}

fn direct_env_field_access_type(env: &PyEnv, field: &str) -> Option<String> {
    let raw = env.field_types.get(field).cloned()?;
    descriptor_access_type(&env.project_index, &raw).or(Some(raw))
}

fn remove_precise_container_slot(env: &mut PyEnv, receiver_text: &str, slot_key: &str) {
    let Some(base) = canonical_container_path(env, receiver_text) else {
        return;
    };
    let mut remove_types = false;
    if let Some(slots) = env.precise_index_types.get_mut(&base) {
        slots.remove(slot_key);
        remove_types = slots.is_empty();
    }
    if remove_types {
        env.precise_index_types.remove(&base);
    }
    let mut remove_calls = false;
    if let Some(slots) = env.precise_index_callables.get_mut(&base) {
        slots.remove(slot_key);
        remove_calls = slots.is_empty();
    }
    if remove_calls {
        env.precise_index_callables.remove(&base);
    }
}


fn infer_project_callable_result_type_from_expr(
    callable_text: &str,
    arg_count: usize,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let trimmed = callable_text.trim();
    if trimmed == "None" {
        return None;
    }
    if let Some(path) = infer_project_symbol_path(trimmed, module_name, imports, index) {
        if let Some(ret) = project_callable_return_from_type(index, &path, arg_count) {
            return Some(ret);
        }
    }
    let ty = infer_project_expr_type(trimmed, module_name, imports, index, current_fields, current_class)?;
    project_callable_return_from_type(index, &ty, arg_count)
}

fn infer_simple_callable_result_type_from_expr(
    callable_text: &str,
    arg_count: usize,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = callable_text.trim();
    if trimmed == "None" {
        return None;
    }
    if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
        if let Some(ret) = project_callable_return_from_type(&env.project_index, &path, arg_count) {
            return Some(ret);
        }
    }
    let ty = infer_simple_python_type(trimmed, imports, env, known_classes)?;
    project_callable_return_from_type(&env.project_index, &ty, arg_count)
}

fn infer_project_iterable_item_type(
    iterable_text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let trimmed = iterable_text.trim();
    if trimmed.starts_with("range(") {
        return Some("int".to_string());
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        if callee_text == "enumerate" {
            let first_arg = args.iter().find(|arg| !arg.trim().is_empty())?;
            let item_ty = infer_project_iterable_item_type(first_arg, module_name, imports, index, current_fields, current_class)
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("tuple<int|{}>", item_ty));
        }
        if callee_text == "zip" {
            let item_types = args
                .iter()
                .filter(|arg| !arg.trim().is_empty())
                .filter_map(|arg| infer_project_iterable_item_type(arg, module_name, imports, index, current_fields, current_class))
                .collect::<Vec<_>>();
            if !item_types.is_empty() {
                return Some(format!("tuple<{}>", item_types.join("|")));
            }
        }
        if callee_text == "map" {
            let iterables = args.iter().skip(1).filter(|arg| !arg.trim().is_empty()).collect::<Vec<_>>();
            if !iterables.is_empty() {
                if let Some(ret) = infer_project_callable_result_type_from_expr(&args[0], iterables.len(), module_name, imports, index, current_fields, current_class) {
                    return Some(ret);
                }
                return infer_project_iterable_item_type(iterables[0], module_name, imports, index, current_fields, current_class);
            }
        }
        if callee_text == "filter" {
            let first_iterable = args.iter().skip(1).find(|arg| !arg.trim().is_empty())?;
            return infer_project_iterable_item_type(first_iterable, module_name, imports, index, current_fields, current_class);
        }
        if matches!(callee_text.as_str(), "iter" | "aiter" | "reversed" | "next" | "anext" | "sorted") {
            let first_arg = args.iter().find(|arg| !arg.trim().is_empty())?;
            return infer_project_iterable_item_type(first_arg, module_name, imports, index, current_fields, current_class);
        }
    }
    let iterable_ty = infer_project_expr_type(trimmed, module_name, imports, index, current_fields, current_class)?;
    if let Some((base, method)) = split_last_top_level_dot(trimmed) {
        if let Some(base_ty) = infer_project_expr_type(&base, module_name, imports, index, current_fields, current_class) {
            if let Some(td_item) = index.typed_dict_method_return_type(&base_ty, &method) {
                if method == "items" {
                    return td_item
                        .strip_prefix("generator<")
                        .and_then(|rest| rest.strip_suffix('>'))
                        .map(|item| item.to_string());
                }
                if method == "values" || method == "keys" {
                    return td_item
                        .strip_prefix("generator<")
                        .and_then(|rest| rest.strip_suffix('>'))
                        .map(|item| item.to_string());
                }
            }
            if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                if let Some((key, value)) = split_once_top_level(inner, ',') {
                    let key = key.trim();
                    let value = value.trim();
                    if method == "items" {
                        return Some(format!("tuple<{}|{}>", key, value));
                    }
                    if method == "values" {
                        return Some(value.to_string());
                    }
                    if method == "keys" {
                        return Some(key.to_string());
                    }
                }
            }
        }
    }
    if let Some(inner) = iterable_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = iterable_ty.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = iterable_ty.strip_prefix("generator<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = iterable_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some((key, _)) = split_once_top_level(inner, ',') {
            return Some(key.trim().to_string());
        }
    }
    if let Some(items) = parse_tuple_type_elements(&iterable_ty) {
        if items.len() == 1 {
            return items.first().cloned();
        }
    }
    iterable_item_type_from_project_type(index, &iterable_ty, &mut HashSet::new())
}

fn infer_project_expr_type(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let trimmed = text.trim();
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return infer_project_expr_type(&inner, module_name, imports, index, current_fields, current_class);
    }
    if let Some(inner) = trimmed.strip_prefix("await ") {
        return infer_project_expr_type(inner, module_name, imports, index, current_fields, current_class);
    }
    if trimmed == "super()" {
        return current_project_super_type(index, current_class);
    }
    if (trimmed == "self" || trimmed == "cls") && current_class.is_some() {
        return current_class.map(|name| name.to_string());
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '[', ']') {
        let result_ty = infer_project_expr_type(&result_expr, module_name, imports, index, current_fields, current_class)
            .or_else(|| infer_project_iterable_item_type(&iterable_text, module_name, imports, index, current_fields, current_class))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("list<{}>", result_ty));
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '{', '}') {
        if let Some((key_text, value_text)) = split_once_top_level(&result_expr, ':') {
            let key_ty = infer_project_expr_type(&key_text, module_name, imports, index, current_fields, current_class)
                .unwrap_or_else(|| "unknown".to_string());
            let value_ty = infer_project_expr_type(&value_text, module_name, imports, index, current_fields, current_class)
                .or_else(|| infer_project_iterable_item_type(&iterable_text, module_name, imports, index, current_fields, current_class))
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("dict<{},{}>", key_ty, value_ty));
        }
        let result_ty = infer_project_expr_type(&result_expr, module_name, imports, index, current_fields, current_class)
            .or_else(|| infer_project_iterable_item_type(&iterable_text, module_name, imports, index, current_fields, current_class))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("set<{}>", result_ty));
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '(', ')') {
        let result_ty = infer_project_expr_type(&result_expr, module_name, imports, index, current_fields, current_class)
            .or_else(|| infer_project_iterable_item_type(&iterable_text, module_name, imports, index, current_fields, current_class))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("generator<{}>", result_ty));
    }
    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner)
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .collect::<Vec<_>>();
        if items.len() >= 2 {
            let parts = items
                .into_iter()
                .map(|item| {
                    infer_project_expr_type(&item, module_name, imports, index, current_fields, current_class)
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .collect::<Vec<_>>();
            return Some(format!("tuple<{}>", parts.join("|")));
        }
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner)
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .collect::<Vec<_>>();
        if let Some(first) = items.into_iter().next() {
            if let Some(item) = infer_project_expr_type(&first, module_name, imports, index, current_fields, current_class) {
                return Some(format!("list<{}>", item));
            }
        }
        return Some("list".to_string());
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.contains(':') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let first = split_top_level_commas(inner).into_iter().find(|item| !item.trim().is_empty());
        if let Some(entry) = first {
            if let Some((key, value)) = split_once_top_level(&entry, ':') {
                let key_ty = infer_project_expr_type(&key, module_name, imports, index, current_fields, current_class)
                    .unwrap_or_else(|| "unknown".to_string());
                let value_ty = infer_project_expr_type(&value, module_name, imports, index, current_fields, current_class)
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("dict<{},{}>", key_ty, value_ty));
            }
        }
        return Some("dict".to_string());
    }
    if let Some((base, index_expr)) = split_last_top_level_index(trimmed) {
        if let Some(base_ty) = infer_project_expr_type(&base, module_name, imports, index, current_fields, current_class) {
            if let Some(key) = parse_python_string_literal_content(&index_expr) {
                if let Some(field_ty) = index.typed_dict_key_type(&base_ty, &key) {
                    return Some(field_ty);
                }
            }
            if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                return Some(inner.to_string());
            }
            if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                if let Some((_, value)) = split_once_top_level(inner, ',') {
                    return Some(value.trim().to_string());
                }
            }
            if let Some(elems) = parse_tuple_type_elements(&base_ty) {
                if let Ok(idx) = index_expr.trim().parse::<usize>() {
                    if idx < elems.len() {
                        return Some(elems[idx].clone());
                    }
                }
            }
            if let Some(ret) = index.method_return(&base_ty, "__getitem__", 1) {
                return Some(ret);
            }
        }
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        let arg_count = args.len();
        if callee_text == "getattr" {
            if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
                return infer_project_expr_type(&synthetic_attr_expr_text(&base, &field), module_name, imports, index, current_fields, current_class);
            }
        }
        if let Some(module_path) = static_python_imported_module_path(trimmed, module_name, imports, index, None) {
            return Some(module_path);
        }
        if callee_text == "hasattr" {
            return Some("bool".to_string());
        }
        if matches!(callee_text.as_str(), "TypeVar" | "typing.TypeVar") {
            if let Some(bound_expr) = args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "bound").then_some(value)
            }) {
                if let Some(bound_ty) = infer_project_expr_type(&bound_expr, module_name, imports, index, current_fields, current_class)
                    .or_else(|| normalize_python_annotation_type(&bound_expr, module_name, imports, Some(index)))
                {
                    return Some(bound_ty);
                }
            }
            for arg in args.iter().skip(1) {
                if split_python_keyword_arg(arg).is_some() {
                    continue;
                }
                if let Some(ty) = infer_project_expr_type(arg, module_name, imports, index, current_fields, current_class)
                    .or_else(|| normalize_python_annotation_type(arg, module_name, imports, Some(index)))
                {
                    return Some(ty);
                }
            }
        }
        if matches!(callee_text.as_str(), "NewType" | "typing.NewType") {
            if let Some(base_expr) = args.get(1) {
                if let Some(base_ty) = infer_project_expr_type(base_expr, module_name, imports, index, current_fields, current_class)
                    .or_else(|| normalize_python_annotation_type(base_expr, module_name, imports, Some(index)))
                {
                    return Some(base_ty);
                }
            }
        }
        if matches!(callee_text.as_str(), "field" | "dataclasses.field" | "Field" | "pydantic.Field" | "sqlmodel.Field" | "attr.ib" | "attr.field" | "attrs.field") {
            let default_factory = args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "default_factory" || name == "factory").then_some(value)
            });
            if let Some(factory) = default_factory {
                let factory = factory.trim();
                match factory {
                    "list" => return Some("list".to_string()),
                    "dict" => return Some("dict".to_string()),
                    "set" => return Some("set".to_string()),
                    "tuple" => return Some("tuple".to_string()),
                    _ => {}
                }
                if let Some(ty) = infer_project_expr_type(factory, module_name, imports, index, current_fields, current_class)
                    .or_else(|| normalize_python_annotation_type(factory, module_name, imports, Some(index)))
                {
                    return Some(ty);
                }
            }
            if let Some(default_expr) = args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "default").then_some(value)
            }) {
                if default_expr.trim() != "None" {
                    if let Some(default_ty) = infer_project_expr_type(&default_expr, module_name, imports, index, current_fields, current_class) {
                        return Some(default_ty);
                    }
                }
            }
        }
        if matches!(callee_text.as_str(), "Factory" | "attr.Factory" | "attrs.Factory") {
            if let Some(first) = args.get(0) {
                if let Some(ty) = infer_project_expr_type(first, module_name, imports, index, current_fields, current_class) {
                    return Some(ty);
                }
            }
        }
        let resolved_callee = resolve_imported_name(&callee_text, imports, &PyEnv::default());
        let is_dependency_wrapper = matches!(callee_text.as_str(), "Depends" | "Security" | "Query" | "Path" | "Header" | "Cookie" | "Body" | "Form" | "File")
            || matches!(resolved_callee.as_deref(), Some("fastapi.Depends" | "fastapi.Security" | "fastapi.params.Depends" | "fastapi.params.Security" | "fastapi.Query" | "fastapi.Path" | "fastapi.Header" | "fastapi.Cookie" | "fastapi.Body" | "fastapi.Form" | "fastapi.File" | "fastapi.params.Query" | "fastapi.params.Path" | "fastapi.params.Header" | "fastapi.params.Cookie" | "fastapi.params.Body" | "fastapi.params.Form" | "fastapi.params.File"));
        if is_dependency_wrapper {
            if let Some(first) = args.get(0) {
                if let Some(callable_path) = infer_project_symbol_path(first, module_name, imports, index) {
                    if let Some(ret) = index.top_level_return(&callable_path, 0).or_else(|| project_callable_return_from_type(index, &callable_path, 0)) {
                        return Some(ret);
                    }
                    if let Some(ty) = index.module_value_type_by_path(&callable_path) {
                        return Some(ty);
                    }
                    return Some(callable_path);
                }
                if first.trim() != "..." && first.trim() != "None" {
                    if let Some(default_ty) = infer_project_expr_type(first, module_name, imports, index, current_fields, current_class) {
                        return Some(default_ty);
                    }
                }
            }
        }
        if matches!(callee_text.as_str(), "next" | "anext") {
            if let Some(first) = args.get(0) {
                return infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class);
            }
        }
        if matches!(callee_text.as_str(), "iter" | "aiter" | "reversed") {
            if let Some(first) = args.get(0) {
                if let Some(base_ty) = infer_project_expr_type(first, module_name, imports, index, current_fields, current_class) {
                    let method = if callee_text == "aiter" { "__aiter__" } else { "__iter__" };
                    if let Some(ret) = index.method_return(&base_ty, method, 0) {
                        return Some(ret);
                    }
                }
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("generator<{}>", item));
            }
        }
        if matches!(callee_text.as_str(), "enumerate" | "zip" | "map" | "filter") {
            let item = infer_project_iterable_item_type(trimmed, module_name, imports, index, current_fields, current_class)
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("generator<{}>", item));
        }
        if callee_text == "sorted" {
            if let Some(first) = args.get(0) {
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .or_else(|| infer_project_expr_type(first, module_name, imports, index, current_fields, current_class))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{}>", item));
            }
            return Some("list".to_string());
        }
        if callee_text == "any" || callee_text == "all" {
            return Some("bool".to_string());
        }
        if callee_text == "list" {
            if let Some(first) = args.get(0) {
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .or_else(|| infer_project_expr_type(first, module_name, imports, index, current_fields, current_class))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{}>", item));
            }
            return Some("list".to_string());
        }
        if callee_text == "set" {
            if let Some(first) = args.get(0) {
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .or_else(|| infer_project_expr_type(first, module_name, imports, index, current_fields, current_class))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("set<{}>", item));
            }
            return Some("set".to_string());
        }
        if callee_text == "tuple" {
            if let Some(first) = args.get(0) {
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .or_else(|| infer_project_expr_type(first, module_name, imports, index, current_fields, current_class))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("tuple<{}>", item));
            }
            return Some("tuple".to_string());
        }
        if callee_text == "dict" {
            return Some("dict".to_string());
        }
        if let Some(relation_ty) = infer_relation_constructor_type(&callee_text, &args, module_name, imports, index, current_fields, current_class) {
            return Some(relation_ty);
        }
        let resolved_callee = imports.aliases.get(&callee_text).cloned();
        if callee_text == "functools.partial" || resolved_callee.as_deref() == Some("functools.partial") {
            if let Some(first) = args.get(0) {
                if let Some(path) = infer_project_symbol_path(first, module_name, imports, index) {
                    return Some(path);
                }
            }
        }
        if let Some(relation_ty) = infer_relation_constructor_type(&callee_text, &args, module_name, imports, index, current_fields, current_class) {
            return Some(relation_ty);
        }
        if let Some(mapped) = imports.aliases.get(&callee_text) {
            let canonical = canonicalize_project_path(index, mapped);
            if let Some(ret) = index.top_level_return(&canonical, arg_count) {
                return Some(ret);
            }
            if let Some(ty) = index.module_value_type_by_path(&canonical) {
                return Some(ty);
            }
            return Some(canonical);
        }
        if let Some(prefixed) = canonicalize_prefixed_project_path(index, &callee_text) {
            if let Some(ret) = index.top_level_return(&prefixed, arg_count) {
                return Some(ret);
            }
            if let Some(ty) = index.module_value_type_by_path(&prefixed) {
                return Some(ty);
            }
            return Some(prefixed);
        }
        if let Some(in_module) = index.resolve_module_member(module_name, &callee_text) {
            let canonical = canonicalize_project_path(index, &in_module);
            if let Some(ret) = index.top_level_return(&canonical, arg_count) {
                return Some(ret);
            }
            if let Some(ty) = index.module_value_type_by_path(&canonical) {
                return Some(ty);
            }
            return Some(canonical);
        }
        if let Some(unique) = index.resolve_simple_class(&callee_text) {
            return Some(canonicalize_project_path(index, &unique));
        }
        if let Some(unique_fn) = index.resolve_simple_function(&callee_text) {
            if let Some(ret) = index.top_level_return(&unique_fn, arg_count) {
                return Some(ret);
            }
            return Some(canonicalize_project_path(index, &unique_fn));
        }
        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if let Some(base_ty) = infer_project_expr_type(&prefix, module_name, imports, index, current_fields, current_class) {
                if let Some(ret) = index.method_return(&base_ty, &method, arg_count) {
                    return Some(ret);
                }
                if index.module_exists(&base_ty) {
                    if let Some(member) = index.resolve_module_member(&base_ty, &method) {
                        let canonical = canonicalize_project_path(index, &member);
                        if let Some(ret) = index.top_level_return(&canonical, arg_count) {
                            return Some(ret);
                        }
                        if let Some(ty) = index.module_value_type_by_path(&canonical) {
                            return Some(ty);
                        }
                        return Some(canonical);
                    }
                }
                if method == "get" || method == "pop" || method == "setdefault" {
                    if let Some(first_arg) = args.get(0) {
                        if let Some(key) = parse_python_string_literal_content(first_arg) {
                            if let Some(field_ty) = index.typed_dict_key_type(&base_ty, &key) {
                                return Some(field_ty);
                            }
                        }
                    }
                    if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                        if let Some((_, value)) = split_once_top_level(inner, ',') {
                            return Some(value.trim().to_string());
                        }
                    }
                }
                if let Some(ret) = index.typed_dict_method_return_type(&base_ty, &method) {
                    return Some(ret);
                }
                if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                    if let Some((key, value)) = split_once_top_level(inner, ',') {
                        let key = key.trim();
                        let value = value.trim();
                        if method == "keys" {
                            return Some(format!("generator<{}>", key));
                        }
                        if method == "values" {
                            return Some(format!("generator<{}>", value));
                        }
                        if method == "items" {
                            return Some(format!("generator<tuple<{}|{}>>", key, value));
                        }
                    }
                }
                if method == "pop" {
                    if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                        return Some(inner.to_string());
                    }
                }
                if method == "copy" {
                    return Some(base_ty);
                }
                if method == "dumps" && base_ty == "json" {
                    return Some("str".to_string());
                }
                return Some(format!("{base_ty}.{method}#ret"));
            }
        }
        if let Some(class_name) = current_class {
            if let Some(ret) = index.method_return(class_name, &callee_text, arg_count) {
                return Some(ret);
            }
        }
        let current_function = format!("{module_name}.{callee_text}");
        if let Some(ret) = index.top_level_return(&current_function, arg_count) {
            return Some(ret);
        }
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        if base == "self" {
            if let Some(ty) = current_fields.get(&field).cloned() {
                return descriptor_access_type(index, &ty).or(Some(ty));
            }
            if let Some(class_name) = current_class {
                if let Some(ty) = direct_field_access_type(index, class_name, &field) {
                    return Some(ty);
                }
            }
        }
        if let Some(base_ty) = infer_project_expr_type(&base, module_name, imports, index, current_fields, current_class) {
            if let Some(ty) = direct_field_access_type(index, &base_ty, &field) {
                return Some(ty);
            }
            if index.module_exists(&base_ty) {
                if let Some(member) = index.resolve_module_member(&base_ty, &field) {
                    let canonical = canonicalize_project_path(index, &member);
                    if let Some(ty) = index.module_value_type_by_path(&canonical) {
                        return Some(ty);
                    }
                    return Some(canonical);
                }
            }
            return Some(format!("{base_ty}.{field}"));
        }
    }
    if let Some(mapped) = imports.aliases.get(trimmed) {
        let canonical = canonicalize_project_path(index, mapped);
        if let Some(ty) = index.module_value_type_by_path(&canonical) {
            return Some(ty);
        }
        return Some(canonical);
    }
    if let Some(in_module) = index.resolve_module_member(module_name, trimmed) {
        let canonical = canonicalize_project_path(index, &in_module);
        if let Some(ty) = index.module_value_type_by_path(&canonical) {
            return Some(ty);
        }
        return Some(canonical);
    }
    if let Some(unique) = index.resolve_simple_class(trimmed) {
        return Some(canonicalize_project_path(index, &unique));
    }
    if let Some(unique_fn) = index.resolve_simple_function(trimmed) {
        return Some(canonicalize_project_path(index, &unique_fn));
    }
    None
}

fn infer_project_class_fields(
    class: &PyClassText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    existing: &HashMap<String, String>,
) -> HashMap<String, String> {
    let current_class = qualify_class_name(module_name, &class.name, Some(index));
    let current_bases = class
        .bases
        .iter()
        .map(|base| qualify_type_name(module_name, base, imports, Some(index)).unwrap_or_else(|| base.clone()))
        .collect::<Vec<_>>();
    let mut fields = existing.clone();
    for (field, ty) in infer_project_class_body_fields(class, module_name, imports, index) {
        fields.entry(field).or_insert(ty);
    }
    for method in extract_functions_at_indent(&class.body, class.indent + 4, class.start_line + 1) {
        let (mut env, known_classes) = seed_project_inference_env(
            &method,
            module_name,
            imports,
            index,
            Some(&current_class),
            &current_bases,
            &fields,
        );
        for raw_line in method.body.lines() {
            apply_project_summary_line_effects(raw_line.trim(), imports, &mut env, &known_classes);
        }
        for (field, ty) in env.field_types.clone() {
            fields.insert(field, ty);
        }
        if function_has_decorator(&method, "property") {
            for raw_line in method.body.lines() {
                let line = raw_line.trim();
                if let Some(rest) = line.strip_prefix("return ") {
                    if let Some(ty) = infer_simple_python_type(rest, imports, &env, &known_classes) {
                        fields.insert(method.name.clone(), ty);
                        break;
                    }
                }
            }
        }
        if let Some(property_name) = property_decorator_target(&method, "setter") {
            if let Some(ty) = env.field_types.get(&property_name).cloned() {
                fields.insert(property_name, ty);
            }
        }
    }
    fields
}

fn method_signature_key(method: &str, arg_count: usize) -> String {
    format!("{method}#{arg_count}")
}

fn top_level_signature_key(function_name: &str, arg_count: usize) -> String {
    format!("{function_name}#{arg_count}")
}


fn resolve_relative_python_module(anchor_module: &str, spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    if !trimmed.starts_with('.') {
        return Some(trimmed.to_string());
    }
    let leading = trimmed.chars().take_while(|ch| *ch == '.').count();
    let suffix = trimmed[leading..].trim_matches('.');
    let mut parts = anchor_module
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if !parts.is_empty() {
        parts.pop();
    }
    for _ in 1..leading {
        if !parts.is_empty() {
            parts.pop();
        }
    }
    if !suffix.is_empty() {
        parts.extend(suffix.split('.').filter(|part| !part.is_empty()));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

fn static_python_imported_module_path(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: Option<&PyEnv>,
) -> Option<String> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee_text = callee_text.trim();
    let resolved_callee = env
        .and_then(|env| resolve_imported_name(callee_text, imports, env))
        .or_else(|| imports.aliases.get(callee_text).cloned());
    let is_import_module = callee_text == "importlib.import_module"
        || resolved_callee.as_deref() == Some("importlib.import_module");
    let is_dunder_import = callee_text == "__import__";
    if !is_import_module && !is_dunder_import {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let mut target = strip_python_string_literal(args.get(0)?)?;
    let package = args.iter().find_map(|arg| {
        let (name, value) = split_once_top_level(arg, '=')?;
        (name.trim() == "package").then(|| strip_python_string_literal(&value)).flatten()
    });
    if target.starts_with('.') {
        let anchor = package.as_deref().unwrap_or(module_name);
        target = resolve_relative_python_module(anchor, &target)?;
    }
    if is_dunder_import {
        let has_fromlist = args.iter().any(|arg| {
            split_once_top_level(arg, '=')
                .is_some_and(|(name, value)| name.trim() == "fromlist" && value.trim() != "[]" && value.trim() != "()")
        });
        if !has_fromlist {
            target = target.split('.').next()?.to_string();
        }
    }
    if index.module_exists(&target) {
        Some(target)
    } else {
        Some(canonicalize_project_path(index, &target))
    }
}

fn static_python_partial_target_path(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee_text = callee_text.trim();
    let resolved_callee = resolve_imported_name(callee_text, imports, env);
    let is_partial = callee_text == "functools.partial" || resolved_callee.as_deref() == Some("functools.partial");
    if !is_partial {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let target = args.get(0)?;
    infer_project_callable_value_type(target, imports, env, known_classes)
}


fn import_effect_modules_for_alias_path(index: &PyProjectIndex, path: &str) -> Vec<String> {
    let canonical_path = canonicalize_project_path(index, path);
    if index.module_exists(&canonical_path) {
        return vec![canonical_path];
    }
    let mut out = Vec::new();
    if let Some((module, _)) = canonical_path.rsplit_once('.') {
        out.push(module.to_string());
    }
    if out.is_empty() {
        out.push(canonical_path);
    }
    out
}

fn apply_project_module_import_line_effects(
    line: &str,
    module_name: &str,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) {
    let line_imports = parse_imports_shallow_for_module(line, module_name);
    for path in line_imports.aliases.values() {
        for imported_module in import_effect_modules_for_alias_path(index, path) {
            if env.executed_modules.insert(imported_module.clone()) {
                env.project_index
                    .apply_imported_module_effects(&imported_module, &mut HashSet::new());
            }
        }
    }
    for (alias, path) in line_imports.aliases {
        let canonical_path = canonicalize_project_path(&env.project_index, &path);
        let ty = env
            .project_index
            .module_value_type_by_path(&path)
            .or_else(|| env.project_index.module_value_type_by_path(&canonical_path))
            .unwrap_or_else(|| canonical_path.clone());
        env.types.insert(alias.clone(), ty.clone());
        if let Some(call_path) = callable_path_from_type(&env.project_index, &ty) {
            env.callable_aliases.insert(alias.clone(), call_path);
        } else if env.project_index.function_path_exists(&canonical_path) || env.project_index.class_exists(&canonical_path) {
            env.callable_aliases.insert(alias.clone(), canonical_path.clone());
        } else {
            env.callable_aliases.remove(&alias);
        }
    }
}

fn summary_skip_range_end(start_line: u32, skip_ranges: &[(u32, u32)]) -> Option<u32> {
    skip_ranges
        .iter()
        .find_map(|(start, end)| (*start == start_line).then_some(*end))
}

fn infer_project_module_bindings_lines_structured(
    lines: &[PyBodyLine],
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
    skip_ranges: &[(u32, u32)],
) -> bool {
    let mut idx = 0usize;
    while idx < lines.len() {
        let raw_line = &lines[idx];
        if let Some(end_line) = summary_skip_range_end(raw_line.line_no, skip_ranges) {
            while idx < lines.len() && lines[idx].line_no <= end_line {
                idx += 1;
            }
            continue;
        }
        let line = raw_line.text.trim();
        if line.is_empty() || line.starts_with('#') {
            idx += 1;
            continue;
        }
        if line.starts_with("import ") || line.starts_with("from ") {
            apply_project_module_import_line_effects(line, module_name, index, env);
            idx += 1;
            continue;
        }

        if line.starts_with("if ") {
            let mut fallthrough_paths = Vec::new();
            let mut current_false_env = env.clone();
            let mut next_idx = idx;
            let mut cursor = idx;
            let mut saw_else = false;
            loop {
                let header = lines[cursor].text.trim();
                if header.starts_with("if ") || header.starts_with("elif ") {
                    let cond_text = header
                        .split_once(' ')
                        .map(|(_, rest)| rest)
                        .and_then(|rest| rest.strip_suffix(':'))
                        .map(|rest| rest.trim().to_string())
                        .unwrap_or_else(|| "True".to_string());
                    let body_start = cursor + 1;
                    let body_end = summary_find_nested_block_end(lines, body_start, lines[cursor].indent);
                    let mut branch_env = current_false_env.clone();
                    apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut branch_env);
                    let branch_live = infer_project_module_bindings_lines_structured(
                        &lines[body_start..body_end],
                        module_name,
                        imports,
                        index,
                        &mut branch_env,
                        known_classes,
                        skip_ranges,
                    );
                    if branch_live {
                        fallthrough_paths.push(branch_env);
                    }
                    apply_runtime_condition_refinements(&cond_text, false, imports, known_classes, &mut current_false_env);
                    next_idx = body_end;
                    let Some(next_header_idx) = next_code_line(lines, body_end) else {
                        break;
                    };
                    if lines[next_header_idx].indent != raw_line.indent {
                        break;
                    }
                    let next_header = lines[next_header_idx].text.trim();
                    if next_header.starts_with("elif ") {
                        cursor = next_header_idx;
                        continue;
                    }
                    if next_header == "else:" {
                        let else_start = next_header_idx + 1;
                        let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                        let mut else_env = current_false_env.clone();
                        let else_live = infer_project_module_bindings_lines_structured(
                            &lines[else_start..else_end],
                            module_name,
                            imports,
                            index,
                            &mut else_env,
                            known_classes,
                            skip_ranges,
                        );
                        if else_live {
                            fallthrough_paths.push(else_env);
                        }
                        next_idx = else_end;
                        saw_else = true;
                    }
                    break;
                }
                break;
            }
            if !saw_else {
                fallthrough_paths.push(current_false_env);
            }
            if fallthrough_paths.is_empty() {
                return false;
            }
            *env = merge_py_env_paths(env, &fallthrough_paths);
            idx = next_idx;
            continue;
        }

        if line == "try:" {
            let base_env = env.clone();
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut try_env = base_env.clone();
            let try_live = infer_project_module_bindings_lines_structured(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                &mut try_env,
                known_classes,
                skip_ranges,
            );
            let mut success_env = try_env.clone();
            let mut fallthrough_paths = Vec::new();
            if try_live {
                fallthrough_paths.push(try_env.clone());
            }
            let mut next_idx = body_end;
            let mut finally_header_idx = None;
            while let Some(header_idx) = next_code_line(lines, next_idx) {
                if lines[header_idx].indent != raw_line.indent {
                    break;
                }
                let header = lines[header_idx].text.trim();
                if header.starts_with("except") {
                    let spec = header
                        .strip_prefix("except")
                        .and_then(|rest| rest.strip_suffix(':'))
                        .map(|rest| rest.trim().to_string())
                        .unwrap_or_default();
                    let (ty_text, sym_text) = if let Some((lhs, rhs)) = split_once_top_level_str(&spec, " as ", false) {
                        (Some(lhs), Some(rhs))
                    } else if spec.is_empty() {
                        (None, None)
                    } else {
                        (Some(spec), None)
                    };
                    let catch_start = header_idx + 1;
                    let catch_end = summary_find_nested_block_end(lines, catch_start, raw_line.indent);
                    let mut catch_env = base_env.clone();
                    if let (Some(name), Some(ty_name)) = (
                        sym_text.as_deref().filter(|name| is_simple_ident(name)),
                        ty_text.as_deref().and_then(|name| {
                            qualify_type_name(&env.current_module, name, imports, Some(&env.project_index))
                                .or_else(|| qualify_type_name(&env.current_module, name, imports, None))
                        }),
                    ) {
                        catch_env.types.insert(name.to_string(), canonicalize_project_path(&env.project_index, &ty_name));
                    }
                    let catch_live = infer_project_module_bindings_lines_structured(
                        &lines[catch_start..catch_end],
                        module_name,
                        imports,
                        index,
                        &mut catch_env,
                        known_classes,
                        skip_ranges,
                    );
                    if catch_live {
                        fallthrough_paths.push(catch_env);
                    }
                    next_idx = catch_end;
                    continue;
                }
                if header == "else:" {
                    let else_start = header_idx + 1;
                    let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                    if try_live {
                        let mut else_env = success_env.clone();
                        let else_live = infer_project_module_bindings_lines_structured(
                            &lines[else_start..else_end],
                            module_name,
                            imports,
                            index,
                            &mut else_env,
                            known_classes,
                            skip_ranges,
                        );
                        if else_live {
                            success_env = else_env;
                            if let Some(first) = fallthrough_paths.first_mut() {
                                *first = success_env.clone();
                            }
                        } else if !fallthrough_paths.is_empty() {
                            fallthrough_paths.remove(0);
                        }
                    }
                    next_idx = else_end;
                    continue;
                }
                if header == "finally:" {
                    finally_header_idx = Some(header_idx);
                    break;
                }
                break;
            }
            if let Some(finally_idx) = finally_header_idx {
                let finally_start = finally_idx + 1;
                let finally_end = summary_find_nested_block_end(lines, finally_start, raw_line.indent);
                let incoming_live = !fallthrough_paths.is_empty();
                let mut finally_env = if incoming_live {
                    merge_py_env_paths(&base_env, &fallthrough_paths)
                } else {
                    base_env.clone()
                };
                let finally_live = infer_project_module_bindings_lines_structured(
                    &lines[finally_start..finally_end],
                    module_name,
                    imports,
                    index,
                    &mut finally_env,
                    known_classes,
                    skip_ranges,
                );
                idx = finally_end;
                if incoming_live && finally_live {
                    *env = finally_env;
                    continue;
                }
                return false;
            }
            idx = next_idx;
            if fallthrough_paths.is_empty() {
                return false;
            }
            *env = merge_py_env_paths(&base_env, &fallthrough_paths);
            continue;
        }

        if line.starts_with("for ") || line.starts_with("async for ") {
            let header = line.strip_prefix("async ").unwrap_or(line);
            let rest = header
                .strip_prefix("for ")
                .and_then(|value| value.strip_suffix(':'))
                .map(|value| value.trim().to_string())
                .unwrap_or_default();
            let (target_text, iterable_text) = split_once_top_level_str(&rest, " in ", false)
                .unwrap_or_else(|| ("item".to_string(), rest));
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut loop_env = env.clone();
            bind_project_summary_loop_target(&target_text, &iterable_text, imports, &mut loop_env, known_classes);
            let loop_live = infer_project_module_bindings_lines_structured(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                &mut loop_env,
                known_classes,
                skip_ranges,
            );
            let mut merged_paths = vec![env.clone()];
            if loop_live {
                merged_paths.push(loop_env);
            }
            let mut next_idx = body_end;
            if body_end < lines.len() {
                let next_header = lines[body_end].text.trim();
                if lines[body_end].indent == raw_line.indent && next_header == "else:" {
                    let else_start = body_end + 1;
                    let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                    let mut else_env = env.clone();
                    let else_live = infer_project_module_bindings_lines_structured(
                        &lines[else_start..else_end],
                        module_name,
                        imports,
                        index,
                        &mut else_env,
                        known_classes,
                        skip_ranges,
                    );
                    if else_live {
                        merged_paths.push(else_env);
                    }
                    next_idx = else_end;
                }
            }
            *env = merge_py_env_paths(env, &merged_paths);
            idx = next_idx;
            continue;
        }

        if line.starts_with("while ") {
            let cond_text = line
                .strip_prefix("while ")
                .and_then(|rest| rest.strip_suffix(':'))
                .map(|rest| rest.trim().to_string())
                .unwrap_or_else(|| "True".to_string());
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut loop_env = env.clone();
            apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut loop_env);
            let loop_live = infer_project_module_bindings_lines_structured(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                &mut loop_env,
                known_classes,
                skip_ranges,
            );
            let mut merged_paths = vec![env.clone()];
            if loop_live {
                merged_paths.push(loop_env);
            }
            let mut next_idx = body_end;
            if body_end < lines.len() {
                let next_header = lines[body_end].text.trim();
                if lines[body_end].indent == raw_line.indent && next_header == "else:" {
                    let else_start = body_end + 1;
                    let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                    let mut else_env = env.clone();
                    let else_live = infer_project_module_bindings_lines_structured(
                        &lines[else_start..else_end],
                        module_name,
                        imports,
                        index,
                        &mut else_env,
                        known_classes,
                        skip_ranges,
                    );
                    if else_live {
                        merged_paths.push(else_env);
                    }
                    next_idx = else_end;
                }
            }
            *env = merge_py_env_paths(env, &merged_paths);
            idx = next_idx;
            continue;
        }

        if line.starts_with("with ") || line.starts_with("async with ") {
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut with_env = env.clone();
            apply_project_summary_with_alias_bindings(line, imports, &mut with_env, known_classes);
            let with_live = infer_project_module_bindings_lines_structured(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                &mut with_env,
                known_classes,
                skip_ranges,
            );
            if !with_live {
                return false;
            }
            *env = with_env;
            idx = body_end;
            continue;
        }

        if line.starts_with("raise ") || line == "raise" {
            return false;
        }
        apply_project_summary_line_effects(line, imports, env, known_classes);
        apply_direct_call_summary_effects(
            line,
            module_name,
            imports,
            index,
            env,
            known_classes,
            None,
        );
        idx += 1;
    }
    true
}

fn infer_project_symbol_path_in_env(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(path) = static_python_imported_module_path(trimmed, module_name, imports, index, Some(env)) {
        return Some(path);
    }
    if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
        return Some(canonicalize_project_path(index, &path));
    }
    if let Some(mapped) = env.callable_aliases.get(trimmed) {
        return Some(canonicalize_project_path(index, mapped));
    }
    if let Some(ty) = resolve_dotted_type(trimmed, imports, env, known_classes) {
        let canonical = canonicalize_project_path(index, &ty);
        if index.function_path_exists(&canonical) || index.module_exists(&canonical) {
            return Some(canonical);
        }
    }
    infer_project_symbol_path(trimmed, module_name, imports, index)
}

fn infer_project_module_bindings(
    source: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> (
    HashMap<String, String>,
    HashMap<String, String>,
    HashMap<String, HashMap<String, String>>,
    HashMap<String, HashMap<String, String>>,
) {
    let mut values = HashMap::new();
    let mut aliases = HashMap::new();
    let mut env = PyEnv::default();
    env.current_module = module_name.to_string();
    env.current_function = format!("{module_name}.<module>");
    env.project_index = index.clone();
    env.executed_modules.insert(module_name.to_string());
    if let Some(classes) = index.classes_by_module.get(module_name) {
        for class_name in classes {
            env.types.insert(class_name.clone(), format!("{module_name}.{class_name}"));
        }
    }
    for function in extract_functions_at_indent(source, 0, 1) {
        let qualified = format!("{module_name}.{}", function.name);
        let decorated_callable_ty = decorate_project_callable_type(&function, module_name, imports, index, &qualified);
        env.types.insert(function.name.clone(), decorated_callable_ty.clone());
        if let Some(path) = callable_path_from_type(index, &decorated_callable_ty)
            .or_else(|| index.function_path_exists(&qualified).then(|| qualified.clone()))
        {
            env.callable_aliases.insert(function.name.clone(), path);
        }
        values.insert(function.name.clone(), decorated_callable_ty);
    }
    let known_classes = infer_project_known_classes(index);
    let body_lines = collect_py_body_lines(source, 1);
    let skip_ranges = extract_functions_at_indent(source, 0, 1)
        .into_iter()
        .map(|func| (func.start_line, func.end_line))
        .chain(extract_classes(source).into_iter().map(|class| (class.start_line, class.end_line)))
        .collect::<Vec<_>>();
    let _ = infer_project_module_bindings_lines_structured(
        &body_lines,
        module_name,
        imports,
        index,
        &mut env,
        &known_classes,
        &skip_ranges,
    );

    for (name, ty) in &env.types {
        if is_simple_ident(name) {
            values.insert(name.clone(), canonicalize_project_path(index, ty));
        }
    }
    for (name, path) in &env.callable_aliases {
        if is_simple_ident(name) {
            aliases.insert(name.clone(), canonicalize_project_path(index, path));
        }
    }

    let mut module_member_values: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut class_field_patches: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (base_name, fields) in &env.local_field_types {
        let Some(owner_ty) = env.types.get(base_name).cloned() else {
            continue;
        };
        let owner_ty = canonicalize_project_path(index, &owner_ty);
        if index.module_exists(&owner_ty) {
            let slot = module_member_values.entry(owner_ty).or_default();
            for (field, ty) in fields {
                slot.insert(field.clone(), canonicalize_project_path(index, ty));
            }
            continue;
        }
        if index.class_exists(&owner_ty) {
            let slot = class_field_patches.entry(owner_ty).or_default();
            for (field, ty) in fields {
                slot.insert(field.clone(), canonicalize_project_path(index, ty));
            }
        }
    }

    (values, aliases, module_member_values, class_field_patches)
}

fn normalize_python_annotation_type(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    project_index: Option<&PyProjectIndex>,
) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(inner) = trimmed.strip_prefix("Optional[").and_then(|rest| rest.strip_suffix(']')) {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("typing.Optional[").and_then(|rest| rest.strip_suffix(']')) {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("Annotated[").and_then(|rest| rest.strip_suffix(']')) {
        let parts = split_top_level_commas(inner);
        return parts.first().and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index));
    }
    if let Some(inner) = trimmed.strip_prefix("typing.Annotated[").and_then(|rest| rest.strip_suffix(']')) {
        let parts = split_top_level_commas(inner);
        return parts.first().and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index));
    }
    if let Some(inner) = trimmed.strip_prefix("typing_extensions.Annotated[").and_then(|rest| rest.strip_suffix(']')) {
        let parts = split_top_level_commas(inner);
        return parts.first().and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index));
    }
    if let Some(inner) = trimmed.strip_prefix("Optional[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Optional[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if has_top_level_separator(trimmed, '|') {
        for part in split_top_level_separator(trimmed, '|') {
            let part = part.trim();
            if matches!(part, "None" | "NoneType") {
                continue;
            }
            if let Some(ty) = normalize_python_annotation_type(part, module_name, imports, project_index) {
                return Some(ty);
            }
        }
    }
    if let Some(inner) = trimmed.strip_prefix("Union[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Union[").and_then(|rest| rest.strip_suffix(']')))
    {
        for part in split_top_level_commas(inner) {
            let part = part.trim();
            if matches!(part, "None" | "NoneType") {
                continue;
            }
            if let Some(ty) = normalize_python_annotation_type(part, module_name, imports, project_index) {
                return Some(ty);
            }
        }
    }
    if let Some(inner) = trimmed.strip_prefix("ClassVar[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.ClassVar[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Final[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Final[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Required[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("NotRequired[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Required[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.NotRequired[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.Required[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.NotRequired[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if matches!(trimmed, "Never" | "typing.Never" | "typing_extensions.Never" | "NoReturn" | "typing.NoReturn") {
        return Some("none".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("TypeIs[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.TypeIs[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.TypeIs[").and_then(|rest| rest.strip_suffix(']')))
    {
        let _ = inner;
        return Some("bool".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("Literal[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Literal[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.Literal[").and_then(|rest| rest.strip_suffix(']')))
    {
        let parts = split_top_level_commas(inner);
        if let Some(first) = parts.first() {
            let first = first.trim();
            if is_string_literal(first) {
                return Some("str".to_string());
            }
            if is_int_literal(first) {
                return Some("int".to_string());
            }
            if matches!(first, "True" | "False") {
                return Some("bool".to_string());
            }
            return normalize_python_annotation_type(first, module_name, imports, project_index);
        }
    }
    if matches!(trimmed, "LiteralString" | "typing.LiteralString" | "typing_extensions.LiteralString") {
        return Some("str".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("TypeGuard[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.TypeGuard[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.TypeGuard[").and_then(|rest| rest.strip_suffix(']')))
    {
        let _ = inner;
        return Some("bool".to_string());
    }
    if matches!(trimmed, "Self" | "typing.Self" | "typing_extensions.Self") {
        return Some("Self".to_string());
    }
    if matches!(trimmed, "TypedDict" | "typing.TypedDict" | "typing_extensions.TypedDict") {
        return Some("dict".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("type[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("Type[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Type[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("list[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("List[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.List[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Sequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Sequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Sequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("MutableSequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.MutableSequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.MutableSequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Collection[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Collection[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Collection[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Iterable[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Iterable[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Iterable[").and_then(|rest| rest.strip_suffix(']')))
    {
        let item = normalize_python_annotation_type(inner, module_name, imports, project_index)
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("list<{item}>"));
    }
    if let Some(inner) = trimmed.strip_prefix("set[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("Set[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Set[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("MutableSet[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.MutableSet[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.MutableSet[").and_then(|rest| rest.strip_suffix(']')))
    {
        let item = normalize_python_annotation_type(inner, module_name, imports, project_index)
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("set<{item}>"));
    }
    if let Some(inner) = trimmed.strip_prefix("tuple[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("Tuple[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Tuple[").and_then(|rest| rest.strip_suffix(']')))
    {
        let items = split_top_level_commas(inner)
            .into_iter()
            .filter_map(|part| normalize_python_annotation_type(&part, module_name, imports, project_index))
            .collect::<Vec<_>>();
        if !items.is_empty() {
            return Some(format!("tuple<{}>", items.join("|")));
        }
    }
    if let Some(inner) = trimmed.strip_prefix("Iterator[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Iterator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Iterator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("AsyncIterator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.AsyncIterator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.AsyncIterator[").and_then(|rest| rest.strip_suffix(']')))
    {
        let item = normalize_python_annotation_type(inner, module_name, imports, project_index)
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("generator<{item}>"));
    }
    if let Some(inner) = trimmed.strip_prefix("Generator[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Generator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("AsyncGenerator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.AsyncGenerator[").and_then(|rest| rest.strip_suffix(']')))
    {
        let item = split_top_level_commas(inner)
            .into_iter()
            .next()
            .and_then(|part| normalize_python_annotation_type(&part, module_name, imports, project_index))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("generator<{item}>"));
    }
    if let Some(inner) = trimmed.strip_prefix("Awaitable[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Awaitable[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Awaitable[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("Coroutine[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Coroutine[").and_then(|rest| rest.strip_suffix(']')))
    {
        let parts = split_top_level_commas(inner);
        if let Some(ret) = parts.get(2).and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index)) {
            return Some(ret);
        }
    }
    if let Some(inner) = trimmed.strip_prefix("Concatenate[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Concatenate[").and_then(|rest| rest.strip_suffix(']')))
    {
        let parts = split_top_level_commas(inner);
        if let Some(last) = parts.last() {
            return normalize_python_annotation_type(last, module_name, imports, project_index);
        }
    }
    if let Some(inner) = trimmed.strip_prefix("Unpack[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Unpack[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.Unpack[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("Callable[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Callable[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Callable[").and_then(|rest| rest.strip_suffix(']')))
    {
        if let Some((_params, ret)) = split_once_top_level(inner, ',') {
            let ret = normalize_python_annotation_type(ret.trim(), module_name, imports, project_index)
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("callable<{}>", ret));
        }
        return Some("callable<unknown>".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("dict[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("Dict[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Dict[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Mapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Mapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.MutableMapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("MutableMapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Mapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.MutableMapping[").and_then(|rest| rest.strip_suffix(']')))
    {
        let parts = split_top_level_commas(inner);
        let key_ty = parts
            .first()
            .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
            .unwrap_or_else(|| "unknown".to_string());
        let value_ty = parts
            .get(1)
            .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("dict<{key_ty},{value_ty}>"));
    }
    if let Some((base, inner)) = split_python_generic_annotation(trimmed) {
        if matches!(base.as_str(), "defaultdict" | "DefaultDict" | "typing.DefaultDict" | "collections.defaultdict") {
            let parts = split_top_level_commas(&inner);
            let key_ty = parts
                .first()
                .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
                .unwrap_or_else(|| "unknown".to_string());
            let value_ty = parts
                .get(1)
                .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("dict<{},{}>", key_ty, value_ty));
        }
        if matches!(base.as_str(), "deque" | "Deque" | "typing.Deque" | "collections.deque") {
            let parts = split_top_level_commas(&inner);
            let item = parts
                .first()
                .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("list<{}>", item));
        }
        if matches!(base.as_str(), "Counter" | "typing.Counter" | "collections.Counter") {
            let parts = split_top_level_commas(&inner);
            let item = parts
                .first()
                .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("dict<{},int>", item));
        }
        if matches!(base.as_str(), "Mapped" | "sqlalchemy.orm.Mapped" | "DynamicMapped" | "WriteOnlyMapped" | "InstrumentedAttribute" | "MappedColumn") {
            let parts = split_top_level_commas(&inner);
            if let Some(first) = parts.first() {
                return normalize_python_annotation_type(first, module_name, imports, project_index);
            }
        }
        if matches!(base.as_str(), "QuerySet" | "Manager" | "django.db.models.QuerySet" | "django.db.models.Manager") {
            let parts = split_top_level_commas(&inner);
            if let Some(first) = parts.first() {
                let item = normalize_python_annotation_type(first, module_name, imports, project_index)
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{item}>"));
            }
        }
        if matches!(base.as_str(), "TypeAliasType" | "typing.TypeAliasType" | "typing_extensions.TypeAliasType") {
            let parts = split_top_level_commas(&inner);
            if let Some(target) = parts.get(1) {
                return normalize_python_annotation_type(target, module_name, imports, project_index);
            }
        }
        if let Some(index) = project_index {
            if let Some(canonical_base) = qualify_type_name(module_name, &base, imports, Some(index)) {
                if index.class_exists(&canonical_base) || index.is_protocol_class(&canonical_base) {
                    let args = split_top_level_commas(&inner)
                        .into_iter()
                        .filter_map(|part| normalize_python_annotation_type(&part, module_name, imports, project_index))
                        .collect::<Vec<_>>();
                    if !args.is_empty() {
                        return Some(format!("{}<{}>", canonical_base, args.join(",")));
                    }
                    return Some(canonical_base);
                }
            }
        }
    }
    if let Some(index) = project_index {
        if let Some(mapped) = imports.aliases.get(trimmed) {
            let canonical = canonicalize_project_path(index, mapped);
            if let Some(ty) = index.module_value_type_by_path(&canonical) {
                return Some(canonicalize_project_path(index, &ty));
            }
        }
        if let Some(in_module) = index.resolve_module_member(module_name, trimmed) {
            let canonical = canonicalize_project_path(index, &in_module);
            if let Some(ty) = index.module_value_type_by_path(&canonical) {
                return Some(canonicalize_project_path(index, &ty));
            }
        }
        if trimmed.contains('.') {
            if let Some(canonical) = canonicalize_prefixed_project_path(index, trimmed) {
                if let Some(ty) = index.module_value_type_by_path(&canonical) {
                    return Some(canonicalize_project_path(index, &ty));
                }
            }
        }
    }
    if matches!(trimmed, "str" | "int" | "float" | "bool" | "bytes") {
        return Some(trimmed.to_string());
    }
    qualify_type_name(module_name, trimmed, imports, project_index)
}

fn parse_class_body_annotated_field(line: &str) -> Option<(String, String, Option<String>)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.contains(":=") {
        return None;
    }
    let (left, rest) = split_once_top_level(trimmed, ':')?;
    let name = left.trim();
    if !is_simple_ident(name) {
        return None;
    }
    if let Some((annotation, value)) = split_once_top_level(&rest, '=') {
        return Some((
            name.to_string(),
            annotation.trim().to_string(),
            Some(value.trim().to_string()),
        ));
    }
    Some((name.to_string(), rest.trim().to_string(), None))
}

fn is_typed_dict_base_name(name: &str) -> bool {
    matches!(name, "TypedDict" | "typing.TypedDict" | "typing_extensions.TypedDict")
        || name.ends_with(".TypedDict")
}

fn is_named_tuple_base_name(name: &str) -> bool {
    matches!(name, "NamedTuple" | "typing.NamedTuple") || name.ends_with(".NamedTuple")
}

fn is_protocol_base_name(name: &str) -> bool {
    matches!(name, "Protocol" | "typing.Protocol" | "typing_extensions.Protocol")
        || name.ends_with(".Protocol")
}

fn parse_python_string_literal_content(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let first = bytes[0] as char;
    let last = *bytes.last()? as char;
    if (first == '\'' || first == '"') && first == last {
        return Some(trimmed[1..trimmed.len().saturating_sub(1)].to_string());
    }
    None
}

fn extract_functional_type_decls(
    source: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> Vec<(String, HashMap<String, String>, String)> {
    let mut out = Vec::new();
    for raw_line in source.lines() {
        let indent = raw_line.chars().take_while(|c| c.is_whitespace()).count();
        let line = raw_line.trim();
        if indent != 0 || line.is_empty() || line.starts_with('#') || line.starts_with("def ") || line.starts_with("class ") || line.starts_with('@') {
            continue;
        }
        let Some((left, right)) = split_once_top_level(line, '=') else { continue; };
        let name = left.trim();
        if !is_simple_ident(name) {
            continue;
        }
        let Some((callee_text, arg_text)) = parse_call_parts(right.trim()) else { continue; };
        let args = split_python_call_args(&arg_text);
        if matches!(callee_text.as_str(), "TypedDict" | "typing.TypedDict" | "typing_extensions.TypedDict") {
            let declared_name = args.get(0).and_then(|arg| parse_python_string_literal_content(arg));
            if declared_name.as_deref() != Some(name) {
                continue;
            }
            let mut fields = HashMap::new();
            if let Some(spec_text) = args.get(1) {
                let spec = spec_text.trim();
                if spec.starts_with('{') && spec.ends_with('}') {
                    let inner = &spec[1..spec.len().saturating_sub(1)];
                    for entry in split_top_level_commas(inner) {
                        let Some((key, value)) = split_once_top_level(&entry, ':') else { continue; };
                        let Some(field_name) = parse_python_string_literal_content(&key) else { continue; };
                        if let Some(field_ty) = normalize_python_annotation_type(&value, module_name, imports, Some(index)) {
                            fields.insert(field_name, field_ty);
                        }
                    }
                }
            }
            out.push((name.to_string(), fields, "typed_dict".to_string()));
            continue;
        }
        if matches!(callee_text.as_str(), "NamedTuple" | "typing.NamedTuple") {
            let declared_name = args.get(0).and_then(|arg| parse_python_string_literal_content(arg));
            if declared_name.as_deref() != Some(name) {
                continue;
            }
            let mut fields = HashMap::new();
            if let Some(spec_text) = args.get(1) {
                let spec = spec_text.trim();
                if spec.starts_with('[') && spec.ends_with(']') {
                    let inner = &spec[1..spec.len().saturating_sub(1)];
                    for entry in split_top_level_commas(inner) {
                        let entry = entry.trim();
                        if !entry.starts_with('(') || !entry.ends_with(')') {
                            continue;
                        }
                        let pair = &entry[1..entry.len().saturating_sub(1)];
                        let parts = split_top_level_commas(pair);
                        if parts.len() < 2 {
                            continue;
                        }
                        let Some(field_name) = parse_python_string_literal_content(&parts[0]) else { continue; };
                        if let Some(field_ty) = normalize_python_annotation_type(&parts[1], module_name, imports, Some(index)) {
                            fields.insert(field_name, field_ty);
                        }
                    }
                }
            }
            out.push((name.to_string(), fields, "named_tuple".to_string()));
        }
    }
    out
}

fn infer_relation_target_type(
    target_expr: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let trimmed = target_expr.trim();
    if let Some(lit) = strip_python_string_literal(trimmed) {
        if let Some(ty) = normalize_python_annotation_type(&lit, module_name, imports, Some(index)) {
            return Some(ty);
        }
        return qualify_type_name(module_name, &lit, imports, Some(index));
    }
    infer_project_expr_type(trimmed, module_name, imports, index, current_fields, current_class)
        .or_else(|| normalize_python_annotation_type(trimmed, module_name, imports, Some(index)))
}

fn infer_relation_constructor_type(
    callee_text: &str,
    args: &[String],
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let base_callee = split_last_top_level_dot(callee_text)
        .map(|(_, tail)| tail)
        .unwrap_or_else(|| callee_text.to_string());
    let singular = matches!(
        base_callee.as_str(),
        "relationship" | "ForeignKey" | "OneToOneField" | "Mapped" | "mapped_column"
    );
    let mut plural = matches!(base_callee.as_str(), "ManyToManyField");
    if !singular && !plural {
        return None;
    }
    let target_arg = args.iter().find_map(|arg| {
        if let Some((name, value)) = split_python_keyword_arg(arg) {
            if matches!(name.as_str(), "argument" | "to" | "model" | "target") {
                return Some(value);
            }
            return None;
        }
        Some(arg.clone())
    })?;
    let mut target_ty = infer_relation_target_type(&target_arg, module_name, imports, index, current_fields, current_class)?;
    if target_ty == "self" {
        if let Some(current_class) = current_class {
            target_ty = current_class.to_string();
        }
    }
    for arg in args {
        if let Some((name, value)) = split_python_keyword_arg(arg) {
            if name == "uselist" && matches!(value.trim(), "True" | "1") {
                plural = true;
            }
            if name == "collection_class" && matches!(value.trim(), "list" | "set" | "InstrumentedList") {
                plural = true;
            }
        }
    }
    if plural {
        target_ty = format!("list<{}>", target_ty);
    }
    Some(target_ty)
}

fn infer_project_class_body_fields(
    class: &PyClassText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    for raw_line in class.body.lines() {
        let indent = raw_line.chars().take_while(|c| c.is_whitespace()).count();
        let line = raw_line.trim();
        if indent != class.indent + 4
            || line.is_empty()
            || line.starts_with('#')
            || line.starts_with("def ")
            || line.starts_with("async def ")
            || line.starts_with('@')
            || line.starts_with("class ")
        {
            continue;
        }
        if let Some((name, annotation, value)) = parse_class_body_annotated_field(line) {
            if let Some(ty) = normalize_python_annotation_type(&annotation, module_name, imports, Some(index))
                .or_else(|| value.as_deref().and_then(|expr| infer_project_expr_type(expr, module_name, imports, index, &HashMap::new(), None)))
            {
                fields.insert(name, ty);
            }
            continue;
        }
        if let Some((left, right)) = split_once_top_level(line, '=') {
            let name = left.trim();
            if !name.contains('.') && is_simple_ident(name) {
                if let Some(ty) = infer_project_expr_type(&right, module_name, imports, index, &HashMap::new(), None) {
                    fields.insert(name.to_string(), ty);
                }
            }
        }
    }
    fields
}

fn normalize_py_decorator_name(text: &str) -> String {
    let trimmed = text.trim().trim_start_matches('@').trim();
    trimmed
        .split_once('(')
        .map(|(name, _)| name.trim().to_string())
        .unwrap_or_else(|| trimmed.to_string())
}

fn function_has_decorator(func: &PyFunctionText, decorator: &str) -> bool {
    func.decorators.iter().any(|raw| {
        let name = normalize_py_decorator_name(raw);
        name == decorator || name.ends_with(&format!(".{decorator}"))
    })
}

fn property_decorator_target(func: &PyFunctionText, suffix: &str) -> Option<String> {
    let needle = format!(".{suffix}");
    func.decorators.iter().find_map(|raw| {
        let name = normalize_py_decorator_name(raw);
        let base = name.strip_suffix(&needle)?;
        base.rsplit('.').next().map(|part| part.to_string())
    })
}

fn parse_python_name_declaration(line: &str, prefix: &str) -> Option<Vec<String>> {
    let rest = line.trim().strip_prefix(prefix)?.trim();
    if rest.is_empty() {
        return None;
    }
    let names = split_top_level_commas(rest)
        .into_iter()
        .map(|name| name.trim().to_string())
        .filter(|name| is_simple_ident(name))
        .collect::<Vec<_>>();
    (!names.is_empty()).then_some(names)
}

fn seed_declared_global_name(
    builder: Option<&mut ModuleBuilder>,
    env: &mut PyEnv,
    name: &str,
) {
    let symbol = if let Some(existing) = env.vars.get(name).copied() {
        existing
    } else if let Some(builder) = builder {
        let created = builder.add_symbol(name, SymbolKind::Local);
        env.vars.insert(name.to_string(), created);
        created
    } else if let Some(existing) = env.capturable_vars.get(name).copied() {
        env.vars.insert(name.to_string(), existing);
        existing
    } else {
        return;
    };
    env.capturable_vars.entry(name.to_string()).or_insert(symbol);
    if let Some(member) = env.project_index.resolve_module_member(&env.current_module, name) {
        let canonical = canonicalize_project_path(&env.project_index, &member);
        if env.project_index.function_path_exists(&canonical) {
            env.callable_aliases.insert(name.to_string(), env.project_index.resolve_canonical_member_path(&canonical, &mut HashSet::new()));
            env.types.insert(name.to_string(), canonical);
        } else if env.project_index.class_exists(&canonical) || env.project_index.module_exists(&canonical) {
            env.types.insert(name.to_string(), canonical);
        } else if let Some(ty) = env.project_index.module_value_type_by_path(&member) {
            env.types.insert(name.to_string(), ty);
        }
    }
}

fn infer_project_known_classes(index: &PyProjectIndex) -> HashSet<String> {
    let mut out = index.classes_by_simple.keys().cloned().collect::<HashSet<_>>();
    for names in index.classes_by_module.values() {
        out.extend(names.iter().cloned());
    }
    out
}

fn seed_project_inference_env(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
) -> (PyEnv, HashSet<String>) {
    let mut env = PyEnv::default();
    env.current_module = module_name.to_string();
    env.current_class = current_class.map(|value| value.to_string());
    env.current_class_bases = current_class_bases.to_vec();
    env.current_function = current_class
        .map(|owner| format!("{owner}.{}", func.name))
        .unwrap_or_else(|| format!("{module_name}.{}", func.name));
    env.project_index = index.clone();
    env.executed_modules.insert(module_name.to_string());
    env.field_types = current_fields.clone();
    if let Some(owner) = current_class {
        env.class_field_index.insert(owner.to_string(), current_fields.clone());
    }

    let param_specs = parse_python_param_specs(&func.params);
    let is_staticmethod = function_has_decorator(func, "staticmethod");
    let is_classmethod = function_has_decorator(func, "classmethod");
    for (idx, spec) in param_specs.iter().enumerate() {
        let treat_as_receiver = idx == 0
            && current_class.is_some()
            && !is_staticmethod
            && (spec.name == "self" || spec.name == "cls" || is_classmethod);
        if treat_as_receiver {
            if let Some(owner) = current_class {
                env.types.insert(spec.name.clone(), owner.to_string());
            }
            env.self_name = Some(spec.name.clone());
            env.local_object_aliases.insert(spec.name.clone(), spec.name.clone());
        }
    }

    for (alias, path) in &imports.aliases {
        if let Some(ty) = index.module_value_type_by_path(path) {
            env.types.insert(alias.clone(), ty);
        } else {
            env.types.insert(alias.clone(), canonicalize_project_path(index, path));
        }
    }

    (env, infer_project_known_classes(index))
}

fn decorate_project_callable_type(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    base_callable_ty: &str,
) -> String {
    let mut current = canonicalize_project_path(index, base_callable_ty);
    for raw in func.decorators.iter().rev() {
        let normalized = normalize_py_decorator_name(raw);
        if matches!(
            normalized.as_str(),
            "staticmethod" | "classmethod" | "property"
        ) || normalized.ends_with(".setter")
            || normalized.ends_with(".deleter")
        {
            continue;
        }
        let target_expr = raw
            .trim()
            .strip_prefix('@')
            .map(|value| value.trim())
            .unwrap_or_else(|| raw.trim());
        let decorator_expr = if let Some((callee_text, _)) = parse_call_parts(target_expr) {
            callee_text
        } else {
            target_expr.to_string()
        };
        let Some(path) = infer_project_symbol_path(&decorator_expr, module_name, imports, index) else {
            continue;
        };
        let canonical = canonicalize_project_path(index, &path);
        if let Some(ret) = index.top_level_return(&canonical, 1) {
            current = canonicalize_project_path(index, &ret);
        }
    }
    current
}

fn project_callable_return_from_type(
    index: &PyProjectIndex,
    callable_ty: &str,
    arg_count: usize,
) -> Option<String> {
    if let Some(ret) = callable_ty.strip_prefix("callable<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(ret.to_string());
    }
    let canonical = canonicalize_project_path(index, callable_ty);
    if index.function_path_exists(&canonical) {
        return index.top_level_return(&canonical, arg_count);
    }
    index.method_return(&canonical, "__call__", arg_count)
}

fn seed_project_inference_env_with_outer(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
    outer_env: Option<&PyEnv>,
) -> (PyEnv, HashSet<String>) {
    let (mut env, known_classes) = seed_project_inference_env(
        func,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
    );
    if let Some(outer) = outer_env {
        env.types.extend(outer.types.clone());
        env.callable_aliases.extend(outer.callable_aliases.clone());
        env.local_object_aliases.extend(outer.local_object_aliases.clone());
        env.executed_modules.extend(outer.executed_modules.clone());
        for (name, fields) in &outer.local_field_types {
            env.local_field_types
                .entry(name.clone())
                .or_default()
                .extend(fields.clone());
        }
        for (name, slots) in &outer.precise_index_types {
            env.precise_index_types
                .entry(name.clone())
                .or_default()
                .extend(slots.clone());
        }
        for (name, slots) in &outer.precise_index_callables {
            env.precise_index_callables
                .entry(name.clone())
                .or_default()
                .extend(slots.clone());
        }
        env.capturable_vars.extend(outer.capturable_vars.clone());
        env.capturable_vars.extend(outer.vars.clone());
    }
    (env, known_classes)
}


fn summary_find_nested_block_end(lines: &[PyBodyLine], start_idx: usize, header_indent: usize) -> usize {
    let mut idx = start_idx;
    while idx < lines.len() {
        let trimmed = lines[idx].text.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') && lines[idx].indent <= header_indent {
            break;
        }
        idx += 1;
    }
    idx
}

fn bind_project_summary_loop_target(
    target_text: &str,
    iterable_text: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let destructured_targets = parse_destructuring_targets(target_text.trim());
    let item_ty = infer_iterable_item_type(iterable_text, imports, env, known_classes);
    if destructured_targets.is_empty() {
        let name = target_text.trim();
        if is_simple_ident(name) {
            if let Some(ty) = item_ty.clone() {
                env.types.insert(name.to_string(), ty.clone());
                if let Some(path) = callable_path_from_type(&env.project_index, &ty) {
                    env.callable_aliases.insert(name.to_string(), path);
                } else {
                    env.callable_aliases.remove(name);
                }
            }
        }
        return;
    }
    if let Some(target_types) = item_ty.as_deref().and_then(destructure_type_elements) {
        for (target, ty) in destructured_targets.into_iter().zip(target_types.into_iter()) {
            env.types.insert(target.clone(), ty.clone());
            if let Some(path) = callable_path_from_type(&env.project_index, &ty) {
                env.callable_aliases.insert(target, path);
            }
        }
    }
}

fn apply_project_summary_with_alias_bindings(
    header_text: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let inner = header_text
        .trim()
        .strip_prefix("async with ")
        .or_else(|| header_text.trim().strip_prefix("with "))
        .and_then(|rest| rest.strip_suffix(':'))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_default();
    for item in split_top_level_commas(&inner).into_iter().filter(|part| !part.trim().is_empty()) {
        let Some((expr_text, alias_text)) = split_once_top_level_str(&item, " as ", false) else {
            continue;
        };
        let alias = alias_text.trim();
        if !is_simple_ident(alias) {
            continue;
        }
        let inferred_ty = context_manager_alias_type(&expr_text, imports, env, known_classes)
            .or_else(|| infer_simple_python_type(&expr_text, imports, env, known_classes));
        if let Some(ty) = inferred_ty {
            env.types.insert(alias.to_string(), ty);
        }
        if let Some(path) = infer_project_callable_value_type(&expr_text, imports, env, known_classes) {
            env.callable_aliases.insert(alias.to_string(), path);
        } else {
            env.callable_aliases.remove(alias);
        }
        env.local_object_aliases.remove(alias);
        env.local_field_types.remove(alias);
        populate_precise_container_slots_from_expr(env, alias, &expr_text, imports, known_classes);
    }
}

fn infer_project_function_summary_lines_flat(
    lines: &[PyBodyLine],
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
    nested_map: &HashMap<u32, PyFunctionText>,
    nested_summaries: &mut HashMap<String, ProjectFunctionSummary>,
    summary: &mut ProjectFunctionSummary,
    rebound_names: &mut HashSet<String>,
    generator_item: &mut Option<String>,
) -> bool {
    let mut idx = 0usize;
    while idx < lines.len() {
        let raw_line = &lines[idx];
        let line = raw_line.text.trim();
        if line.is_empty() || line.starts_with('#') {
            idx += 1;
            continue;
        }
        if let Some(nested) = nested_map.get(&raw_line.line_no) {
            let nested_summary = infer_project_function_summary_with_locals(
                nested,
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                Some(env),
            );
            let qualified_name = format!("{}.{}", env.current_function, nested.name);
            nested_summaries.insert(qualified_name.clone(), nested_summary.clone());
            let decorated_callable_ty = decorate_project_callable_type(
                nested,
                module_name,
                imports,
                index,
                &qualified_name,
            );
            env.types.insert(nested.name.clone(), decorated_callable_ty.clone());
            if let Some(path) = callable_path_from_type(index, &decorated_callable_ty)
                .or_else(|| index.function_path_exists(&qualified_name).then(|| qualified_name.clone()))
            {
                env.callable_aliases.insert(nested.name.clone(), path);
            }
            while idx < lines.len() && lines[idx].line_no <= nested.end_line {
                idx += 1;
            }
            continue;
        }
        if let Some(names) = parse_python_name_declaration(line, "global ") {
            for name in names {
                rebound_names.insert(name);
            }
        }
        if let Some(names) = parse_python_name_declaration(line, "nonlocal ") {
            for name in names {
                rebound_names.insert(name);
            }
        }

        if line.starts_with("if ") {
            let mut fallthrough_paths = Vec::new();
            let mut current_false_env = env.clone();
            let mut next_idx = idx;
            let mut cursor = idx;
            let mut saw_else = false;
            loop {
                let header = lines[cursor].text.trim();
                if header.starts_with("if ") || header.starts_with("elif ") {
                    let cond_text = header
                        .split_once(' ')
                        .map(|(_, rest)| rest)
                        .and_then(|rest| rest.strip_suffix(':'))
                        .map(|rest| rest.trim().to_string())
                        .unwrap_or_else(|| "True".to_string());
                    let body_start = cursor + 1;
                    let body_end = summary_find_nested_block_end(lines, body_start, lines[cursor].indent);
                    let mut branch_env = current_false_env.clone();
                    apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut branch_env);
                    let branch_live = infer_project_function_summary_lines_flat(
                        &lines[body_start..body_end],
                        module_name,
                        imports,
                        index,
                        current_class,
                        current_class_bases,
                        current_fields,
                        &mut branch_env,
                        known_classes,
                        nested_map,
                        nested_summaries,
                        summary,
                        rebound_names,
                        generator_item,
                    );
                    if branch_live {
                        fallthrough_paths.push(branch_env);
                    }
                    apply_runtime_condition_refinements(&cond_text, false, imports, known_classes, &mut current_false_env);
                    next_idx = body_end;
                    let Some(next_header_idx) = next_code_line(lines, body_end) else {
                        break;
                    };
                    if lines[next_header_idx].indent != raw_line.indent {
                        break;
                    }
                    let next_header = lines[next_header_idx].text.trim();
                    if next_header.starts_with("elif ") {
                        cursor = next_header_idx;
                        continue;
                    }
                    if next_header == "else:" {
                        let else_start = next_header_idx + 1;
                        let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                        let mut else_env = current_false_env.clone();
                        let else_live = infer_project_function_summary_lines_flat(
                            &lines[else_start..else_end],
                            module_name,
                            imports,
                            index,
                            current_class,
                            current_class_bases,
                            current_fields,
                            &mut else_env,
                            known_classes,
                            nested_map,
            nested_summaries,
                            summary,
                            rebound_names,
                            generator_item,
                        );
                        if else_live {
                            fallthrough_paths.push(else_env);
                        }
                        next_idx = else_end;
                        saw_else = true;
                    }
                    break;
                }
                break;
            }
            if !saw_else {
                fallthrough_paths.push(current_false_env);
            }
            if fallthrough_paths.is_empty() {
                return false;
            }
            *env = merge_py_env_paths(env, &fallthrough_paths);
            idx = next_idx;
            continue;
        }

        if line == "try:" {
            let base_env = env.clone();
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut try_env = base_env.clone();
            let try_live = infer_project_function_summary_lines_flat(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                &mut try_env,
                known_classes,
                nested_map,
                nested_summaries,
                summary,
                rebound_names,
                generator_item,
            );
            let mut success_env = try_env.clone();
            let mut fallthrough_paths = Vec::new();
            if try_live {
                fallthrough_paths.push(try_env.clone());
            }
            let mut next_idx = body_end;
            let mut finally_header_idx = None;
            while let Some(header_idx) = next_code_line(lines, next_idx) {
                if lines[header_idx].indent != raw_line.indent {
                    break;
                }
                let header = lines[header_idx].text.trim();
                if header.starts_with("except") {
                    let spec = header
                        .strip_prefix("except")
                        .and_then(|rest| rest.strip_suffix(':'))
                        .map(|rest| rest.trim().to_string())
                        .unwrap_or_default();
                    let (ty_text, sym_text) = if let Some((lhs, rhs)) = split_once_top_level_str(&spec, " as ", false) {
                        (Some(lhs), Some(rhs))
                    } else if spec.is_empty() {
                        (None, None)
                    } else {
                        (Some(spec), None)
                    };
                    let catch_start = header_idx + 1;
                    let catch_end = summary_find_nested_block_end(lines, catch_start, raw_line.indent);
                    let mut catch_env = base_env.clone();
                    if let (Some(name), Some(ty_name)) = (
                        sym_text.as_deref().filter(|name| is_simple_ident(name)),
                        ty_text.as_deref().and_then(|name| {
                            qualify_type_name(&env.current_module, name, imports, Some(&env.project_index))
                                .or_else(|| qualify_type_name(&env.current_module, name, imports, None))
                        }),
                    ) {
                        catch_env.types.insert(name.to_string(), canonicalize_project_path(&env.project_index, &ty_name));
                    }
                    let catch_live = infer_project_function_summary_lines_flat(
                        &lines[catch_start..catch_end],
                        module_name,
                        imports,
                        index,
                        current_class,
                        current_class_bases,
                        current_fields,
                        &mut catch_env,
                        known_classes,
                        nested_map,
                        nested_summaries,
                        summary,
                        rebound_names,
                        generator_item,
                    );
                    if catch_live {
                        fallthrough_paths.push(catch_env);
                    }
                    next_idx = catch_end;
                    continue;
                }
                if header == "else:" {
                    let else_start = header_idx + 1;
                    let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                    if try_live {
                        let mut else_env = success_env.clone();
                        let else_live = infer_project_function_summary_lines_flat(
                            &lines[else_start..else_end],
                            module_name,
                            imports,
                            index,
                            current_class,
                            current_class_bases,
                            current_fields,
                            &mut else_env,
                            known_classes,
                            nested_map,
            nested_summaries,
                            summary,
                            rebound_names,
                            generator_item,
                        );
                        if else_live {
                            success_env = else_env;
                            if let Some(first) = fallthrough_paths.first_mut() {
                                *first = success_env.clone();
                            }
                        } else if !fallthrough_paths.is_empty() {
                            fallthrough_paths.remove(0);
                        }
                    }
                    next_idx = else_end;
                    continue;
                }
                if header == "finally:" {
                    finally_header_idx = Some(header_idx);
                    break;
                }
                break;
            }
            if let Some(finally_idx) = finally_header_idx {
                let finally_start = finally_idx + 1;
                let finally_end = summary_find_nested_block_end(lines, finally_start, raw_line.indent);
                let incoming_live = !fallthrough_paths.is_empty();
                let mut finally_env = if incoming_live {
                    merge_py_env_paths(&base_env, &fallthrough_paths)
                } else {
                    base_env.clone()
                };
                let finally_live = infer_project_function_summary_lines_flat(
                    &lines[finally_start..finally_end],
                    module_name,
                    imports,
                    index,
                    current_class,
                    current_class_bases,
                    current_fields,
                    &mut finally_env,
                    known_classes,
                    nested_map,
            nested_summaries,
                    summary,
                    rebound_names,
                    generator_item,
                );
                idx = finally_end;
                if incoming_live && finally_live {
                    *env = finally_env;
                    continue;
                }
                return false;
            }
            idx = next_idx;
            if fallthrough_paths.is_empty() {
                return false;
            }
            *env = merge_py_env_paths(&base_env, &fallthrough_paths);
            continue;
        }

        if line.starts_with("for ") || line.starts_with("async for ") {
            let header = line.strip_prefix("async ").unwrap_or(line);
            let rest = header
                .strip_prefix("for ")
                .and_then(|value| value.strip_suffix(':'))
                .map(|value| value.trim().to_string())
                .unwrap_or_default();
            let (target_text, iterable_text) = split_once_top_level_str(&rest, " in ", false)
                .unwrap_or_else(|| ("item".to_string(), rest));
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut loop_env = env.clone();
            bind_project_summary_loop_target(&target_text, &iterable_text, imports, &mut loop_env, known_classes);
            let loop_live = infer_project_function_summary_lines_flat(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                &mut loop_env,
                known_classes,
                nested_map,
                nested_summaries,
                summary,
                rebound_names,
                generator_item,
            );
            let mut merged_paths = vec![env.clone()];
            if loop_live {
                merged_paths.push(loop_env);
            }
            let mut next_idx = body_end;
            if body_end < lines.len() {
                let next_header = lines[body_end].text.trim();
                if lines[body_end].indent == raw_line.indent && next_header == "else:" {
                    let else_start = body_end + 1;
                    let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                    let mut else_env = env.clone();
                    let else_live = infer_project_function_summary_lines_flat(
                        &lines[else_start..else_end],
                        module_name,
                        imports,
                        index,
                        current_class,
                        current_class_bases,
                        current_fields,
                        &mut else_env,
                        known_classes,
                        nested_map,
                        nested_summaries,
                        summary,
                        rebound_names,
                        generator_item,
                    );
                    if else_live {
                        merged_paths.push(else_env);
                    }
                    next_idx = else_end;
                }
            }
            *env = merge_py_env_paths(env, &merged_paths);
            idx = next_idx;
            continue;
        }

        if line.starts_with("while ") {
            let cond_text = line
                .strip_prefix("while ")
                .and_then(|rest| rest.strip_suffix(':'))
                .map(|rest| rest.trim().to_string())
                .unwrap_or_else(|| "True".to_string());
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut loop_env = env.clone();
            apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut loop_env);
            let loop_live = infer_project_function_summary_lines_flat(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                &mut loop_env,
                known_classes,
                nested_map,
                nested_summaries,
                summary,
                rebound_names,
                generator_item,
            );
            let mut merged_paths = vec![env.clone()];
            if loop_live {
                merged_paths.push(loop_env);
            }
            let mut next_idx = body_end;
            if body_end < lines.len() {
                let next_header = lines[body_end].text.trim();
                if lines[body_end].indent == raw_line.indent && next_header == "else:" {
                    let else_start = body_end + 1;
                    let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                    let mut else_env = env.clone();
                    let else_live = infer_project_function_summary_lines_flat(
                        &lines[else_start..else_end],
                        module_name,
                        imports,
                        index,
                        current_class,
                        current_class_bases,
                        current_fields,
                        &mut else_env,
                        known_classes,
                        nested_map,
                        nested_summaries,
                        summary,
                        rebound_names,
                        generator_item,
                    );
                    if else_live {
                        merged_paths.push(else_env);
                    }
                    next_idx = else_end;
                }
            }
            *env = merge_py_env_paths(env, &merged_paths);
            idx = next_idx;
            continue;
        }

        if line.starts_with("with ") || line.starts_with("async with ") {
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut with_env = env.clone();
            apply_project_summary_with_alias_bindings(line, imports, &mut with_env, known_classes);
            let with_live = infer_project_function_summary_lines_flat(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                &mut with_env,
                known_classes,
                nested_map,
                nested_summaries,
                summary,
                rebound_names,
                generator_item,
            );
            if !with_live {
                return false;
            }
            *env = with_env;
            idx = body_end;
            continue;
        }

        if let Some(rest) = line.strip_prefix("yield from ") {
            if let Some(ty) = infer_iterable_item_type(rest, imports, env, known_classes)
                .or_else(|| infer_simple_python_type(rest, imports, env, known_classes))
            {
                *generator_item = Some(merge_container_type(generator_item.as_deref(), &ty));
            }
            idx += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("yield ") {
            let ty = infer_simple_python_type(rest, imports, env, known_classes)
                .unwrap_or_else(|| "unknown".to_string());
            *generator_item = Some(merge_container_type(generator_item.as_deref(), &ty));
            idx += 1;
            continue;
        }
        if line == "yield" {
            *generator_item = Some(merge_container_type(generator_item.as_deref(), "unknown"));
            idx += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("return ") {
            if generator_item.is_none() {
                if let Some(ty) = infer_simple_python_type(rest, imports, env, known_classes) {
                    summary.return_type = Some(merge_container_type(summary.return_type.as_deref(), &ty));
                }
            }
            return false;
        }
        if line == "return" {
            return false;
        }
        if line.starts_with("raise ") || line == "raise" || line == "break" || line == "continue" {
            return false;
        }
        if let Some((left, _)) = split_once_top_level(line, '=') {
            let normalized_left = synthetic_static_namespace_access_text(left.trim())
                .unwrap_or_else(|| left.trim().to_string());
            let target = normalized_left.trim();
            if is_simple_ident(target) && rebound_names.contains(target) {
                apply_project_summary_line_effects(line, imports, env, known_classes);
                if let Some(ty) = env.types.get(target).cloned() {
                    summary.writeback_types.insert(target.to_string(), ty);
                }
                if let Some(path) = env.callable_aliases.get(target).cloned() {
                    summary.writeback_callables.insert(target.to_string(), path);
                }
                idx += 1;
                continue;
            }
        }
        if let Some(rest) = line.strip_prefix("del ") {
            let mut captured = false;
            for target in split_top_level_commas(rest) {
                let target = target.trim();
                if is_simple_ident(target) && rebound_names.contains(target) {
                    captured = true;
                    summary.writeback_types.remove(target);
                    summary.writeback_callables.remove(target);
                }
            }
            if captured {
                apply_project_summary_line_effects(line, imports, env, known_classes);
                idx += 1;
                continue;
            }
        }
        apply_project_summary_line_effects(line, imports, env, known_classes);
        apply_direct_call_summary_effects(
            line,
            module_name,
            imports,
            index,
            env,
            known_classes,
            Some(nested_summaries),
        );
        idx += 1;
    }
    true
}

fn project_summary_writeback_heads(
    func: &PyFunctionText,
    env: &PyEnv,
    outer_env: Option<&PyEnv>,
    rebound_names: &HashSet<String>,
) -> HashSet<String> {
    let mut heads = rebound_names.clone();
    for spec in parse_python_param_specs(&func.params) {
        heads.insert(spec.name);
    }
    if let Some(self_name) = env.self_name.as_ref() {
        heads.insert(self_name.clone());
    }
    if let Some(outer) = outer_env {
        heads.extend(outer.types.keys().cloned());
        heads.extend(outer.callable_aliases.keys().cloned());
        heads.extend(outer.local_object_aliases.keys().cloned());
        heads.extend(outer.local_field_types.keys().filter(|name| is_simple_ident(name)).cloned());
        heads.extend(outer.precise_index_types.keys().filter(|name| is_simple_ident(name)).cloned());
        heads.extend(outer.precise_index_callables.keys().filter(|name| is_simple_ident(name)).cloned());
        if let Some(self_name) = outer.self_name.as_ref() {
            heads.insert(self_name.clone());
        }
    }
    heads
}

fn project_summary_root_head(root: &str) -> String {
    let trimmed = root.trim();
    if let Some((base, _)) = split_last_top_level_index(trimmed) {
        return project_summary_root_head(&base);
    }
    if let Some((base, _)) = split_last_top_level_dot(trimmed) {
        return project_summary_root_head(&base);
    }
    trimmed.to_string()
}

fn project_summary_root_is_writeback_candidate(root: &str, allowed_heads: &HashSet<String>) -> bool {
    let head = project_summary_root_head(root);
    !head.is_empty() && allowed_heads.contains(&head)
}

fn infer_project_function_summary_bundle_with_locals(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
    outer_env: Option<&PyEnv>,
) -> (ProjectFunctionSummary, HashMap<String, ProjectFunctionSummary>) {
    let (mut env, known_classes) = seed_project_inference_env_with_outer(
        func,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
        outer_env,
    );
    let mut summary = ProjectFunctionSummary::default();
    let mut nested_summaries: HashMap<String, ProjectFunctionSummary> = HashMap::new();
    let body_lines = collect_py_body_lines(&func.body, func.start_line + 1);
    let required_indent = current_body_indent(&body_lines);
    let nested_map = extract_functions_at_indent(&func.body, required_indent, func.start_line + 1)
        .into_iter()
        .map(|nested| (nested.start_line, nested))
        .collect::<HashMap<_, _>>();
    let mut rebound_names = HashSet::new();
    let mut generator_item: Option<String> = None;
    let _ = infer_project_function_summary_lines_flat(
        &body_lines,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
        &mut env,
        &known_classes,
        &nested_map,
        &mut nested_summaries,
        &mut summary,
        &mut rebound_names,
        &mut generator_item,
    );
    let allowed_writeback_heads = project_summary_writeback_heads(func, &env, outer_env, &rebound_names);
    for (root, fields) in &env.local_field_types {
        if project_summary_root_is_writeback_candidate(root, &allowed_writeback_heads) {
            summary.local_field_writes.insert(root.clone(), fields.clone());
        }
    }
    for (root, slots) in &env.precise_index_types {
        if project_summary_root_is_writeback_candidate(root, &allowed_writeback_heads) {
            summary.precise_index_type_writes.insert(root.clone(), slots.clone());
        }
    }
    for (root, slots) in &env.precise_index_callables {
        if project_summary_root_is_writeback_candidate(root, &allowed_writeback_heads) {
            summary.precise_index_callable_writes.insert(root.clone(), slots.clone());
        }
    }
    if let Some(item_ty) = generator_item {
        summary.return_type = Some(format!("generator<{}>", item_ty));
    }
    (summary, nested_summaries)
}

fn infer_project_function_summary_with_locals(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
    outer_env: Option<&PyEnv>,
) -> ProjectFunctionSummary {
    infer_project_function_summary_bundle_with_locals(
        func,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
        outer_env,
    )
    .0
}

fn infer_project_function_text_context_by_callable_path(
    callable_path: &str,
    index: &PyProjectIndex,
) -> Option<(PyFunctionText, String, Option<String>)> {
    if let Some(func) = index.top_level_function_text(callable_path) {
        let (owner_module, _) = callable_path.rsplit_once('.')?;
        return Some((func.clone(), owner_module.to_string(), None));
    }
    if let Some(func) = index.method_text(callable_path) {
        let (owner_class, _) = callable_path.rsplit_once('.')?;
        let (owner_module, _) = owner_class.rsplit_once('.')?;
        return Some((func.clone(), owner_module.to_string(), Some(owner_class.to_string())));
    }
    let mut owner_path = callable_path.to_string();
    while let Some((prefix, _)) = owner_path.rsplit_once('.') {
        owner_path = prefix.to_string();
        if let Some(owner) = index.top_level_function_text(&owner_path) {
            let (owner_module, _) = owner_path.rsplit_once('.')?;
            let body_lines = collect_py_body_lines(&owner.body, owner.start_line + 1);
            let required_indent = current_body_indent(&body_lines);
            for nested in extract_functions_at_indent(&owner.body, required_indent, owner.start_line + 1) {
                if format!("{owner_path}.{}", nested.name) == callable_path {
                    return Some((nested, owner_module.to_string(), None));
                }
            }
        }
        if let Some(owner) = index.method_text(&owner_path) {
            let (owner_class, _) = owner_path.rsplit_once('.')?;
            let (owner_module, _) = owner_class.rsplit_once('.')?;
            let body_lines = collect_py_body_lines(&owner.body, owner.start_line + 1);
            let required_indent = current_body_indent(&body_lines);
            for nested in extract_functions_at_indent(&owner.body, required_indent, owner.start_line + 1) {
                if format!("{owner_path}.{}", nested.name) == callable_path {
                    return Some((nested, owner_module.to_string(), Some(owner_class.to_string())));
                }
            }
        }
    }
    None
}

fn infer_project_summary_by_callable_path(
    callable_path: &str,
    index: &PyProjectIndex,
) -> Option<ProjectFunctionSummary> {
    if let Some(func) = index.top_level_function_text(callable_path) {
        let (owner_module, _) = callable_path.rsplit_once('.')?;
        let imports = index.module_imports_for(owner_module)?;
        let (summary, nested) = infer_project_function_summary_bundle_with_locals(
            func,
            owner_module,
            imports,
            index,
            None,
            &[],
            &HashMap::new(),
            None,
        );
        return nested.get(callable_path).cloned().or(Some(summary));
    }
    if let Some(func) = index.method_text(callable_path) {
        let (owner_class, _) = callable_path.rsplit_once('.')?;
        let (owner_module, _) = owner_class.rsplit_once('.')?;
        let imports = index.module_imports_for(owner_module)?;
        let current_fields = index.field_types.get(owner_class).cloned().unwrap_or_default();
        let class_bases = index.class_bases.get(owner_class).cloned().unwrap_or_default();
        let (summary, nested) = infer_project_function_summary_bundle_with_locals(
            func,
            owner_module,
            imports,
            index,
            Some(owner_class),
            &class_bases,
            &current_fields,
            None,
        );
        return nested.get(callable_path).cloned().or(Some(summary));
    }
    let mut owner_path = callable_path.to_string();
    while let Some((prefix, _)) = owner_path.rsplit_once('.') {
        owner_path = prefix.to_string();
        if let Some(func) = index.top_level_function_text(&owner_path) {
            let (owner_module, _) = owner_path.rsplit_once('.')?;
            let imports = index.module_imports_for(owner_module)?;
            let (_, nested) = infer_project_function_summary_bundle_with_locals(
                func,
                owner_module,
                imports,
                index,
                None,
                &[],
                &HashMap::new(),
                None,
            );
            return nested.get(callable_path).cloned();
        }
        if let Some(func) = index.method_text(&owner_path) {
            let (owner_class, _) = owner_path.rsplit_once('.')?;
            let (owner_module, _) = owner_class.rsplit_once('.')?;
            let imports = index.module_imports_for(owner_module)?;
            let current_fields = index.field_types.get(owner_class).cloned().unwrap_or_default();
            let class_bases = index.class_bases.get(owner_class).cloned().unwrap_or_default();
            let (_, nested) = infer_project_function_summary_bundle_with_locals(
                func,
                owner_module,
                imports,
                index,
                Some(owner_class),
                &class_bases,
                &current_fields,
                None,
            );
            return nested.get(callable_path).cloned();
        }
    }
    None
}

fn infer_project_function_return_with_locals(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
) -> Option<String> {
    infer_project_function_summary_with_locals(
        func,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
        None,
    )
    .return_type
}

fn infer_project_top_level_return(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> Option<String> {
    infer_project_function_return_with_locals(func, module_name, imports, index, None, &[], &HashMap::new())
}

fn infer_project_module_values(
    source: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> HashMap<String, String> {
    infer_project_module_bindings(source, module_name, imports, index).0
}

fn infer_project_symbol_path(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.contains('[') || trimmed.contains('{') {
        return None;
    }
    if let Some(module_path) = static_python_imported_module_path(trimmed, module_name, imports, index, None) {
        return Some(module_path);
    }
    if trimmed.contains('(') {
        return None;
    }
    if let Some(mapped) = imports.aliases.get(trimmed) {
        return Some(canonicalize_project_path(index, mapped));
    }
    if let Some(prefixed) = canonicalize_prefixed_project_path(index, trimmed) {
        if prefixed != trimmed || index.module_exists(trimmed) || trimmed.contains('.') {
            return Some(prefixed);
        }
    }
    if let Some(in_module) = index.resolve_module_member(module_name, trimmed) {
        return Some(canonicalize_project_path(index, &in_module));
    }
    if let Some(unique) = index.resolve_simple_class(trimmed) {
        return Some(canonicalize_project_path(index, &unique));
    }
    if let Some(unique_fn) = index.resolve_simple_function(trimmed) {
        return Some(canonicalize_project_path(index, &unique_fn));
    }
    None
}


fn infer_project_callable_path(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> Option<String> {
    let path = infer_project_symbol_path(text, module_name, imports, index)?;
    if index.function_path_exists(&path) {
        Some(index.resolve_canonical_member_path(&path, &mut HashSet::new()))
    } else {
        None
    }
}

fn project_method_static_path(index: &PyProjectIndex, class_name: &str, method: &str) -> Option<String> {
    index
        .method_path(class_name, method)
        .or_else(|| index.class_has_method(class_name, method).then(|| format!("{class_name}.{method}")))
}

fn callable_path_from_type(index: &PyProjectIndex, ty: &str) -> Option<String> {
    if index.function_path_exists(ty) {
        return Some(index.resolve_canonical_member_path(ty, &mut HashSet::new()));
    }
    project_method_static_path(index, ty, "__call__")
}

fn iterable_item_type_from_project_type(index: &PyProjectIndex, ty: &str, visited: &mut HashSet<String>) -> Option<String> {
    if !visited.insert(ty.to_string()) {
        return None;
    }
    if let Some(inner) = ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = ty.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some((key, _)) = split_once_top_level(inner, ',') {
            return Some(key.trim().to_string());
        }
    }
    if let Some(inner) = ty.strip_prefix("generator<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(items) = parse_tuple_type_elements(ty) {
        if items.len() == 1 {
            return items.first().cloned();
        }
    }
    if let Some(iter_ty) = index.method_return(ty, "__iter__", 0) {
        if let Some(item) = iterable_item_type_from_project_type(index, &iter_ty, visited) {
            return Some(item);
        }
        if let Some(next_ty) = index.method_return(&iter_ty, "__next__", 0) {
            return Some(next_ty);
        }
    }
    if let Some(next_ty) = index.method_return(ty, "__next__", 0) {
        return Some(next_ty);
    }
    if let Some(iter_ty) = index.method_return(ty, "__aiter__", 0) {
        if let Some(item) = iterable_item_type_from_project_type(index, &iter_ty, visited) {
            return Some(item);
        }
        if let Some(next_ty) = index.method_return(&iter_ty, "__anext__", 0) {
            return Some(next_ty);
        }
    }
    if let Some(next_ty) = index.method_return(ty, "__anext__", 0) {
        return Some(next_ty);
    }
    None
}

fn infer_project_callable_value_type(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = text.trim();
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return infer_project_callable_value_type(&inner, imports, env, known_classes);
    }
    if let Some(synthetic) = synthetic_static_namespace_access_text(trimmed) {
        return infer_project_callable_value_type(&synthetic, imports, env, known_classes);
    }
    if let Some((synthetic, _kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        if let Some(mapped) = infer_project_callable_value_type(&synthetic, imports, env, known_classes) {
            return Some(mapped);
        }
        if let Some(default_expr) = default_value {
            return infer_project_callable_value_type(&default_expr, imports, env, known_classes);
        }
    }
    if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
        let synthetic = synthetic_attr_expr_text(&base, &field);
        if let Some(mapped) = infer_project_callable_value_type(&synthetic, imports, env, known_classes) {
            return Some(mapped);
        }
    }
    if let Some(path) = static_python_partial_target_path(trimmed, imports, env, known_classes) {
        return Some(path);
    }
    if let Some(mapped) = env.callable_aliases.get(trimmed) {
        return Some(mapped.clone());
    }
    if let Some((base, index_expr)) = split_last_top_level_index(trimmed) {
        if let Some(slot_key) = parse_static_index_slot_key(&index_expr) {
            if let Some(mapped) = precise_container_slot_callable(env, &base, &slot_key) {
                return Some(mapped);
            }
        }
        if let Some(base_ty) = resolve_dotted_type(&base, imports, env, known_classes) {
            if let Some(ret_ty) = env.project_index.method_return(&base_ty, "__getitem__", 1) {
                if let Some(path) = callable_path_from_type(&env.project_index, &ret_ty) {
                    return Some(path);
                }
            }
        }
    }
    if let Some(path) = infer_project_callable_path(trimmed, &env.current_module, imports, &env.project_index) {
        return Some(path);
    }
    if let Some(ty) = resolve_dotted_type(trimmed, imports, env, known_classes) {
        if env.project_index.function_path_exists(&ty) {
            return Some(env.project_index.resolve_canonical_member_path(&ty, &mut HashSet::new()));
        }
        if let Some(call_path) = env.project_index.method_path(&ty, "__call__") {
            return Some(call_path);
        }
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        if matches!(callee_text.as_str(), "next" | "anext") {
            if let Some(first) = args.get(0) {
                if let Some(item_ty) = infer_iterable_item_type(first, imports, env, known_classes) {
                    if let Some(path) = callable_path_from_type(&env.project_index, &item_ty) {
                        return Some(path);
                    }
                }
            }
        }
        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if method == "pop" {
                if args.is_empty() {
                    if let Some(slot_key) = last_precise_list_slot(env, &prefix) {
                        if let Some(mapped) = precise_container_slot_callable(env, &prefix, &slot_key) {
                            return Some(mapped);
                        }
                    }
                } else if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                    if let Some(mapped) = precise_container_slot_callable(env, &prefix, &slot_key) {
                        return Some(mapped);
                    }
                }
            }
            if method == "get" || method == "setdefault" || method == "pop" {
                if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                    if let Some(mapped) = precise_container_slot_callable(env, &prefix, &slot_key) {
                        return Some(mapped);
                    }
                }
            }
            if let Some(base_ty) = resolve_dotted_type(&prefix, imports, env, known_classes) {
                if method == "pop" {
                    if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                        let candidate = inner.trim();
                        if env.project_index.function_path_exists(candidate) {
                            return Some(env.project_index.resolve_canonical_member_path(candidate, &mut HashSet::new()));
                        }
                    }
                }
                if method == "get" || method == "pop" || method == "setdefault" {
                    if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                        if let Some((_, value)) = split_once_top_level(inner, ',') {
                            let candidate = value.trim();
                            if env.project_index.function_path_exists(candidate) {
                                return Some(env.project_index.resolve_canonical_member_path(candidate, &mut HashSet::new()));
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some((prefix, method)) = split_last_top_level_dot(trimmed) {
        let candidate = if prefix == "super()" {
            env.current_class_bases
                .first()
                .map(|base| format!("{base}.{method}"))
        } else if env.self_name.as_deref() == Some(prefix.as_str()) {
            env.current_class
                .as_ref()
                .map(|class_name| format!("{class_name}.{method}"))
        } else if let Some(base_ty) = resolve_dotted_type(&prefix, imports, env, known_classes) {
            Some(format!("{base_ty}.{method}"))
        } else {
            None
        };
        if let Some(candidate) = candidate {
            if env.project_index.function_path_exists(&candidate) {
                return Some(env.project_index.resolve_canonical_member_path(&candidate, &mut HashSet::new()));
            }
            if let Some((owner, method)) = candidate.rsplit_once('.') {
                if let Some(path) = env.project_index.method_path(owner, method) {
                    return Some(path);
                }
            }
        }
    }
    None
}

fn wrap_expr_with_explicit_type(builder: &mut ModuleBuilder, expr: Expr, ty_name: &str) -> Expr {
    Expr::Cast {
        id: builder.alloc_expr_id(),
        ty: Some(builder.ensure_type(ty_name)),
        expr: Box::new(expr),
        span: default_span(),
    }
}

fn infer_project_module_aliases(
    source: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> HashMap<String, String> {
    infer_project_module_bindings(source, module_name, imports, index).1
}

fn infer_project_method_returns(
    class: &PyClassText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
) -> HashMap<String, String> {
    let current_class = qualify_class_name(module_name, &class.name, Some(index));
    let current_bases = class
        .bases
        .iter()
        .map(|base| qualify_type_name(module_name, base, imports, Some(index)).unwrap_or_else(|| base.clone()))
        .collect::<Vec<_>>();
    let mut returns = HashMap::new();
    for method in extract_functions_at_indent(&class.body, class.indent + 4, class.start_line + 1) {
        let receiver_adjusted = !function_has_decorator(&method, "staticmethod");
        let arities = python_callable_arities(&parse_python_param_specs(&method.params), receiver_adjusted);
        let base_ty = infer_project_function_return_with_locals(
            &method,
            module_name,
            imports,
            index,
            Some(&current_class),
            &current_bases,
            current_fields,
        );
        let method_path = format!("{}.{}", current_class, method.name);
        let decorated_callable_ty = decorate_project_callable_type(&method, module_name, imports, index, &method_path);
        for arity in &arities {
            if let Some(ty) = project_callable_return_from_type(index, &decorated_callable_ty, *arity)
                .or_else(|| base_ty.clone())
            {
                let key = method_signature_key(&method.name, *arity);
                returns.entry(key).or_insert(ty);
            }
        }
    }
    returns
}

fn extract_classes(source: &str) -> Vec<PyClassText> {
    let lines: Vec<&str> = source.lines().collect();
    let class_re = Regex::new(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)(?:\(([^)]*)\))?\s*:")
        .expect("valid regex");
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx < lines.len() {
        let line = lines[idx];
        let Some(caps) = class_re.captures(line) else {
            idx += 1;
            continue;
        };
        let indent = line.chars().take_while(|c| c.is_whitespace()).count();
        if indent != 0 {
            idx += 1;
            continue;
        }
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("Class").to_string();
        let bases = caps
            .get(2)
            .map(|m| split_top_level_commas(m.as_str()))
            .unwrap_or_default();
        let start_line = idx as u32 + 1;

        idx += 1;
        let mut body_lines = Vec::new();
        let mut end_line = start_line;
        while idx < lines.len() {
            let next = lines[idx];
            if next.trim().is_empty() {
                body_lines.push(next.to_string());
                end_line = idx as u32 + 1;
                idx += 1;
                continue;
            }
            let next_indent = next.chars().take_while(|c| c.is_whitespace()).count();
            if next_indent <= indent {
                break;
            }
            body_lines.push(next.to_string());
            end_line = idx as u32 + 1;
            idx += 1;
        }

        out.push(PyClassText {
            name,
            bases,
            body: body_lines.join("\n"),
            start_line,
            end_line,
            indent,
        });
    }

    out
}

fn extract_functions_at_indent(source: &str, required_indent: usize, base_line: u32) -> Vec<PyFunctionText> {
    let mut out = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let def_re = Regex::new(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*:")
        .expect("valid regex");

    let mut idx = 0usize;
    let mut pending_decorators: Vec<String> = Vec::new();
    while idx < lines.len() {
        let line = lines[idx];
        let indent = line.chars().take_while(|c| c.is_whitespace()).count();
        let trimmed = line.trim();
        if indent == required_indent && trimmed.starts_with('@') {
            pending_decorators.push(trimmed.to_string());
            idx += 1;
            continue;
        }
        let Some(caps) = def_re.captures(line) else {
            if indent == required_indent && !trimmed.is_empty() && !trimmed.starts_with('#') {
                pending_decorators.clear();
            }
            idx += 1;
            continue;
        };
        if indent != required_indent {
            idx += 1;
            continue;
        }
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("function").to_string();
        let params = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
        let start_line = base_line + idx as u32;
        let decorators = std::mem::take(&mut pending_decorators);

        idx += 1;
        let mut body_lines = Vec::new();
        let mut end_line = start_line;
        while idx < lines.len() {
            let next = lines[idx];
            if next.trim().is_empty() {
                body_lines.push(next.to_string());
                end_line = base_line + idx as u32;
                idx += 1;
                continue;
            }
            let next_indent = next.chars().take_while(|c| c.is_whitespace()).count();
            if next_indent <= indent {
                break;
            }
            body_lines.push(next.to_string());
            end_line = base_line + idx as u32;
            idx += 1;
        }

        out.push(PyFunctionText {
            name,
            params,
            body: body_lines.join("\n"),
            start_line,
            end_line,
            decorators,
        });
    }

    out
}

fn parse_class(
    builder: &mut ModuleBuilder,
    class: &PyClassText,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    class_field_index: &HashMap<String, HashMap<String, String>>,
    module_name: &str,
    project_index: Option<&PyProjectIndex>,
) -> Class {
    let mut methods = Vec::new();
    let mut field_map = HashMap::<String, Field>::new();
    let mut field_types = HashMap::<String, String>::new();
    let qualified_class_name = qualify_class_name(module_name, &class.name, project_index);

    for (idx, raw_line) in class.body.lines().enumerate() {
        let indent = raw_line.chars().take_while(|c| c.is_whitespace()).count();
        if indent != class.indent + 4 {
            continue;
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("def ") || line.starts_with('@') {
            continue;
        }
        if let Some((name, annotation, value)) = parse_class_body_annotated_field(line) {
            let inferred = normalize_python_annotation_type(&annotation, module_name, imports, project_index)
                .or_else(|| value.as_deref().and_then(|expr| infer_simple_python_type(expr, imports, &PyEnv::default(), known_classes)));
            let ty = inferred.as_ref().map(|ty| builder.ensure_type(ty));
            let span = span_from_line_range(builder.file_id(), class.start_line + 1 + idx as u32, class.start_line + 1 + idx as u32);
            if let Some(inferred) = inferred {
                field_types.insert(name.clone(), inferred);
            }
            field_map.entry(name.clone()).or_insert(Field {
                name: name.clone(),
                symbol: Some(builder.add_symbol(&name, SymbolKind::Field)),
                ty,
                span,
            });
            continue;
        }
        if let Some((left, right)) = split_once_top_level(line, '=') {
            let name = left.trim();
            if !name.contains('.') && is_simple_ident(name) {
                let inferred = project_index
                    .and_then(|index| infer_project_expr_type(&right, module_name, imports, index, &field_types, Some(&qualified_class_name)))
                    .or_else(|| infer_simple_python_type(&right, imports, &PyEnv::default(), known_classes));
                let ty = inferred.as_ref().map(|ty| builder.ensure_type(ty));
                let span = span_from_line_range(builder.file_id(), class.start_line + 1 + idx as u32, class.start_line + 1 + idx as u32);
                if let Some(inferred) = inferred {
                    field_types.insert(name.to_string(), inferred);
                }
                field_map.entry(name.to_string()).or_insert(Field {
                    name: name.to_string(),
                    symbol: Some(builder.add_symbol(name, SymbolKind::Field)),
                    ty,
                    span,
                });
            }
        }
    }

    for method in extract_functions_at_indent(&class.body, class.indent + 4, class.start_line + 1) {
        let parsed = parse_function(
            builder,
            &method,
            imports,
            known_classes,
            Some(&qualified_class_name),
            &class
                .bases
                .iter()
                .map(|base| qualify_type_name(module_name, base, imports, project_index).unwrap_or_else(|| base.clone()))
                .collect::<Vec<_>>(),
            &field_types,
            class_field_index,
            module_name,
            project_index,
            None,
            None,
        );
        let ParsedFunction { function, discovered_fields, synthetic_functions } = parsed;
        for field in discovered_fields {
            field_map.entry(field.name.clone()).or_insert(field);
        }
        if function_has_decorator(&method, "property") {
            if let Some(ret_ty) = function.return_type.and_then(|id| builder.find_type_name(id)).map(|name| name.to_string()) {
                let span = span_from_line_range(builder.file_id(), method.start_line, method.end_line);
                field_types.insert(method.name.clone(), ret_ty.clone());
                field_map.entry(method.name.clone()).or_insert(Field {
                    name: method.name.clone(),
                    symbol: Some(builder.add_symbol(&method.name, SymbolKind::Field)),
                    ty: Some(builder.ensure_type(&ret_ty)),
                    span,
                });
            }
        }
        if let Some(property_name) = property_decorator_target(&method, "setter")
            .or_else(|| property_decorator_target(&method, "deleter"))
        {
            if let Some(ret_ty) = field_types.get(&property_name).cloned() {
                let span = span_from_line_range(builder.file_id(), method.start_line, method.end_line);
                field_map.entry(property_name.clone()).or_insert(Field {
                    name: property_name.clone(),
                    symbol: Some(builder.add_symbol(&property_name, SymbolKind::Field)),
                    ty: Some(builder.ensure_type(&ret_ty)),
                    span,
                });
            }
        }
        for field in field_map.values() {
            if let Some(ty) = field.ty.and_then(|id| builder.find_type_name(id)) {
                field_types.insert(field.name.clone(), ty.to_string());
            }
        }
        for synthetic in synthetic_functions {
            builder.push_item(Item::Function(synthetic));
        }
        methods.push(function);
    }

    Class {
        name: qualified_class_name.clone(),
        symbol: Some(builder.add_symbol(&class.name, SymbolKind::Class)),
        bases: class
            .bases
            .iter()
            .map(|base| qualify_type_name(module_name, base, imports, project_index).unwrap_or_else(|| base.clone()))
            .collect(),
        fields: field_map.into_values().collect(),
        methods,
        span: span_from_line_range(builder.file_id(), class.start_line, class.end_line),
    }
}

fn parse_function(
    builder: &mut ModuleBuilder,
    func: &PyFunctionText,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    class_name: Option<&str>,
    class_bases: &[String],
    class_field_types: &HashMap<String, String>,
    class_field_index: &HashMap<String, HashMap<String, String>>,
    module_name: &str,
    project_index: Option<&PyProjectIndex>,
    qualified_name: Option<&str>,
    outer_env: Option<&PyEnv>,
) -> ParsedFunction {
    let mut env = PyEnv::default();
    env.current_class = class_name.map(|name| name.to_string());
    env.current_class_bases = class_bases.to_vec();
    env.field_types = class_field_types.clone();
    env.class_field_index = class_field_index.clone();
    env.current_module = module_name.to_string();
    let qualified_function_name = qualified_name
        .map(|name| name.to_string())
        .unwrap_or_else(|| {
            if let Some(class_name) = class_name {
                format!("{class_name}.{}", func.name)
            } else {
                format!("{module_name}.{}", func.name)
            }
        });
    env.current_function = qualified_function_name.clone();
    env.project_index = project_index.cloned().unwrap_or_default();
    if let Some(outer_env) = outer_env {
        env.capturable_vars = outer_env.vars.clone();
        env.types.extend(outer_env.types.clone());
        env.callable_aliases.extend(outer_env.callable_aliases.clone());
    }
    let mut params = Vec::new();
    let mut receiver = None;
    let param_specs = parse_python_param_specs(&func.params);
    let is_staticmethod = function_has_decorator(func, "staticmethod");
    let is_classmethod = function_has_decorator(func, "classmethod");

    for (idx, spec) in param_specs.iter().enumerate() {
        let symbol = builder.add_symbol(&spec.name, SymbolKind::Param);
        env.vars.insert(spec.name.clone(), symbol);
        let treat_as_receiver = idx == 0
            && class_name.is_some()
            && !is_staticmethod
            && (spec.name == "self" || spec.name == "cls" || is_classmethod);
        if treat_as_receiver {
            let ty = class_name.map(|name| builder.ensure_type(name));
            if let Some(class_name) = class_name {
                env.types.insert(spec.name.clone(), class_name.to_string());
            }
            env.self_name = Some(spec.name.clone());
            env.self_symbol = Some(symbol);
            receiver = Some(Param {
                name: spec.name.clone(),
                symbol,
                ty,
                kind: ParamKind::Positional,
                has_default: spec.has_default,
                keyword_only: spec.keyword_only,
                span: span_from_line_range(builder.file_id(), func.start_line, func.start_line),
            });
            continue;
        }
        params.push(Param {
            name: spec.name.clone(),
            symbol,
            ty: None,
            kind: match spec.kind {
                PyParamKind::Positional => ParamKind::Positional,
                PyParamKind::VarArgs => ParamKind::VarArgs,
                PyParamKind::KwArgs => ParamKind::KwArgs,
            },
            has_default: spec.has_default,
            keyword_only: spec.keyword_only,
            span: span_from_line_range(builder.file_id(), func.start_line, func.start_line),
        });
    }

    let stmts = parse_body(builder, &func.body, imports, known_classes, &mut env, func.start_line + 1);
    let receiver_adjusted = class_name.is_some() && !is_staticmethod;
    let return_key = method_signature_key(
        &func.name,
        python_callable_arities(&param_specs, receiver_adjusted)
            .into_iter()
            .next_back()
            .unwrap_or(0),
    );
    let body = Block {
        id: builder.alloc_block_id(),
        stmts,
        span: span_from_line_range(builder.file_id(), func.start_line, func.end_line),
    };

    let name = if let Some(class_name) = class_name {
        format!("{class_name}.{}", func.name)
    } else {
        func.name.clone()
    };
    let symbol_kind = if class_name.is_some() {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    };

    let mut synthetic_functions = std::mem::take(&mut env.synthetic_functions);
    collect_block_lambda_functions(builder, &body, &qualified_function_name, &mut synthetic_functions);

    let mut function = uniflow_hir::Function {
            id: builder.alloc_function_id(),
            name: qualified_name.map(|name| name.to_string()).unwrap_or(name),
            symbol: Some(builder.add_symbol(&func.name, symbol_kind)),
            params,
            captures: Vec::new(),
            return_type: class_name
                .and_then(|owner| project_index.and_then(|index| index.method_returns.get(owner)))
                .and_then(|methods| methods.get(&return_key))
                .map(|ty| builder.ensure_type(ty)),
            body,
            is_method: class_name.is_some() && qualified_name.is_none() && !is_staticmethod,
            receiver,
            span: span_from_line_range(builder.file_id(), func.start_line, func.end_line),
        };

    if let Some(outer_env) = outer_env {
        finalize_nested_function_captures(builder, &mut function, outer_env);
    }

    ParsedFunction {
        function,
        discovered_fields: env.discovered_fields.into_values().collect(),
        synthetic_functions,
    }
}

#[derive(Clone, Default)]
struct PyEnv {
    vars: HashMap<String, SymbolId>,
    capturable_vars: HashMap<String, SymbolId>,
    types: HashMap<String, String>,
    callable_aliases: HashMap<String, String>,
    field_types: HashMap<String, String>,
    local_field_types: HashMap<String, HashMap<String, String>>,
    local_object_aliases: HashMap<String, String>,
    precise_index_types: HashMap<String, HashMap<String, String>>,
    precise_index_callables: HashMap<String, HashMap<String, String>>,
    current_class: Option<String>,
    current_class_bases: Vec<String>,
    self_name: Option<String>,
    self_symbol: Option<SymbolId>,
    discovered_fields: HashMap<String, Field>,
    class_field_index: HashMap<String, HashMap<String, String>>,
    current_module: String,
    current_function: String,
    synthetic_functions: Vec<uniflow_hir::Function>,
    project_index: PyProjectIndex,
    executed_modules: HashSet<String>,
}

#[derive(Clone, Debug)]
struct PyBodyLine {
    indent: usize,
    text: String,
    line_no: u32,
}

fn collect_py_body_lines(body: &str, first_line: u32) -> Vec<PyBodyLine> {
    body.lines()
        .enumerate()
        .map(|(idx, raw_line)| PyBodyLine {
            indent: raw_line.chars().take_while(|c| c.is_whitespace()).count(),
            text: raw_line.to_string(),
            line_no: first_line + idx as u32,
        })
        .collect()
}

fn next_code_line(lines: &[PyBodyLine], mut idx: usize) -> Option<usize> {
    while idx < lines.len() {
        let trimmed = lines[idx].text.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

fn current_body_indent(lines: &[PyBodyLine]) -> usize {
    lines.iter()
        .filter_map(|line| {
            let trimmed = line.text.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                Some(line.indent)
            }
        })
        .min()
        .unwrap_or(0)
}

fn is_clause_continuation_header(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("elif ") || trimmed == "else:" || trimmed.starts_with("except") || trimmed == "finally:"
}

fn stmt_end_line(stmt: &Stmt) -> u32 {
    match stmt {
        Stmt::Let { span, .. }
        | Stmt::Assign { span, .. }
        | Stmt::Expr { span, .. }
        | Stmt::If { span, .. }
        | Stmt::While { span, .. }
        | Stmt::ForEach { span, .. }
        | Stmt::Return { span, .. }
        | Stmt::Throw { span, .. }
        | Stmt::Try { span, .. } => span.end_line,
    }
}

fn build_py_block(builder: &mut ModuleBuilder, stmts: Vec<Stmt>, start_line: u32, end_line: u32) -> Block {
    Block {
        id: builder.alloc_block_id(),
        stmts,
        span: span_from_line_range(builder.file_id(), start_line, end_line.max(start_line)),
    }
}

fn lambda_function_name(enclosing_function: &str, id: ExprId, line_no: u32) -> String {
    format!("{enclosing_function}.__lambda_{}_{}", line_no, id.0)
}

fn lambda_capture_field_name(name: &str) -> String {
    format!("__capture__{name}")
}

fn collect_free_lambda_symbols(
    expr: &Expr,
    locals: &HashSet<SymbolId>,
    outer_symbols: &HashMap<SymbolId, String>,
    seen: &mut HashSet<SymbolId>,
    out: &mut Vec<(SymbolId, String)>,
) {
    match expr {
        Expr::VarRef { symbol, .. } => {
            if !locals.contains(symbol) {
                if let Some(name) = outer_symbols.get(symbol) {
                    if seen.insert(*symbol) {
                        out.push((*symbol, name.clone()));
                    }
                }
            }
        }
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => {
            collect_free_lambda_symbols(expr, locals, outer_symbols, seen, out);
        }
        Expr::Binary { lhs, rhs, .. } => {
            collect_free_lambda_symbols(lhs, locals, outer_symbols, seen, out);
            collect_free_lambda_symbols(rhs, locals, outer_symbols, seen, out);
        }
        Expr::FieldRead { base, .. } => {
            collect_free_lambda_symbols(base, locals, outer_symbols, seen, out);
        }
        Expr::IndexRead { base, index, .. } => {
            collect_free_lambda_symbols(base, locals, outer_symbols, seen, out);
            collect_free_lambda_symbols(index, locals, outer_symbols, seen, out);
        }
        Expr::Call(call) => {
            if let CallTarget::Dynamic(callee) = &call.target {
                collect_free_lambda_symbols(callee, locals, outer_symbols, seen, out);
            }
            if let Some(receiver) = &call.receiver {
                collect_free_lambda_symbols(receiver, locals, outer_symbols, seen, out);
            }
            for arg in &call.args {
                collect_free_lambda_symbols(arg, locals, outer_symbols, seen, out);
            }
        }
        Expr::Lambda { captures, .. } => {
            for capture in captures {
                if !locals.contains(&capture.source_symbol) {
                    if let Some(name) = outer_symbols.get(&capture.source_symbol) {
                        if seen.insert(capture.source_symbol) {
                            out.push((capture.source_symbol, name.clone()));
                        }
                    }
                }
            }
        }
        Expr::New { args, .. } => {
            for arg in args {
                collect_free_lambda_symbols(arg, locals, outer_symbols, seen, out);
            }
        }
        Expr::Literal { .. } | Expr::Unknown { .. } => {}
    }
}

fn rewrite_lambda_capture_symbols(expr: Expr, capture_map: &HashMap<SymbolId, SymbolId>) -> Expr {
    match expr {
        Expr::VarRef { id, symbol, span } => Expr::VarRef {
            id,
            symbol: capture_map.get(&symbol).copied().unwrap_or(symbol),
            span,
        },
        Expr::Unary { id, op, expr, span } => Expr::Unary {
            id,
            op,
            expr: Box::new(rewrite_lambda_capture_symbols(*expr, capture_map)),
            span,
        },
        Expr::Binary { id, op, lhs, rhs, span } => Expr::Binary {
            id,
            op,
            lhs: Box::new(rewrite_lambda_capture_symbols(*lhs, capture_map)),
            rhs: Box::new(rewrite_lambda_capture_symbols(*rhs, capture_map)),
            span,
        },
        Expr::FieldRead { id, base, field, span } => Expr::FieldRead {
            id,
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            field,
            span,
        },
        Expr::IndexRead { id, base, index, span } => Expr::IndexRead {
            id,
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            index: Box::new(rewrite_lambda_capture_symbols(*index, capture_map)),
            span,
        },
        Expr::Call(mut call) => {
            if let CallTarget::Dynamic(callee) = call.target {
                call.target = CallTarget::Dynamic(Box::new(rewrite_lambda_capture_symbols(*callee, capture_map)));
            }
            if let Some(receiver) = call.receiver.take() {
                call.receiver = Some(Box::new(rewrite_lambda_capture_symbols(*receiver, capture_map)));
            }
            call.args = call.args.into_iter().map(|arg| rewrite_lambda_capture_symbols(arg, capture_map)).collect();
            Expr::Call(call)
        }
        Expr::Lambda { id, params, mut captures, body, span } => {
            for capture in &mut captures {
                if let Some(mapped) = capture_map.get(&capture.source_symbol).copied() {
                    capture.source_symbol = mapped;
                }
            }
            Expr::Lambda { id, params, captures, body, span }
        }
        Expr::New { id, type_name, args, span } => Expr::New {
            id,
            type_name,
            args: args.into_iter().map(|arg| rewrite_lambda_capture_symbols(arg, capture_map)).collect(),
            span,
        },
        Expr::Cast { id, ty, expr, span } => Expr::Cast {
            id,
            ty,
            expr: Box::new(rewrite_lambda_capture_symbols(*expr, capture_map)),
            span,
        },
        other @ Expr::Literal { .. } | other @ Expr::Unknown { .. } => other,
    }
}

fn infer_lambda_capture_type(
    builder: &mut ModuleBuilder,
    env: &PyEnv,
    name: &str,
) -> Option<uniflow_hir::TypeId> {
    env.callable_aliases
        .get(name)
        .or_else(|| env.types.get(name))
        .map(|ty| builder.ensure_type(ty))
}

fn collect_expr_lambda_functions(
    builder: &mut ModuleBuilder,
    expr: &Expr,
    enclosing_function: &str,
    out: &mut Vec<uniflow_hir::Function>,
) {
    match expr {
        Expr::Unary { expr, .. } => collect_expr_lambda_functions(builder, expr, enclosing_function, out),
        Expr::Binary { lhs, rhs, .. } => {
            collect_expr_lambda_functions(builder, lhs, enclosing_function, out);
            collect_expr_lambda_functions(builder, rhs, enclosing_function, out);
        }
        Expr::FieldRead { base, .. } => collect_expr_lambda_functions(builder, base, enclosing_function, out),
        Expr::IndexRead { base, index, .. } => {
            collect_expr_lambda_functions(builder, base, enclosing_function, out);
            collect_expr_lambda_functions(builder, index, enclosing_function, out);
        }
        Expr::Call(call) => {
            if let CallTarget::Dynamic(callee) = &call.target {
                collect_expr_lambda_functions(builder, callee, enclosing_function, out);
            }
            if let Some(receiver) = &call.receiver {
                collect_expr_lambda_functions(builder, receiver, enclosing_function, out);
            }
            for arg in &call.args {
                collect_expr_lambda_functions(builder, arg, enclosing_function, out);
            }
        }
        Expr::Lambda { id, params, captures, body, span } => {
            out.push(uniflow_hir::Function {
                id: builder.alloc_function_id(),
                name: lambda_function_name(enclosing_function, *id, span.start_line.max(1)),
                symbol: Some(builder.add_symbol("<lambda>", SymbolKind::Function)),
                params: params.clone(),
                captures: captures.iter().map(|capture| uniflow_hir::Param {
                    name: capture.name.clone(),
                    symbol: capture.symbol,
                    ty: capture.ty,
                    kind: ParamKind::Positional,
                    has_default: false,
                    keyword_only: false,
                    span: capture.span,
                }).collect(),
                return_type: None,
                body: body.clone(),
                is_method: false,
                receiver: None,
                span: *span,
            });
            collect_block_lambda_functions(builder, body, enclosing_function, out);
        }
        Expr::New { args, .. } => {
            for arg in args {
                collect_expr_lambda_functions(builder, arg, enclosing_function, out);
            }
        }
        Expr::Cast { expr, .. } => collect_expr_lambda_functions(builder, expr, enclosing_function, out),
        Expr::VarRef { .. } | Expr::Literal { .. } | Expr::Unknown { .. } => {}
    }
}

fn collect_stmt_lambda_functions(
    builder: &mut ModuleBuilder,
    stmt: &Stmt,
    enclosing_function: &str,
    out: &mut Vec<uniflow_hir::Function>,
) {
    match stmt {
        Stmt::Let { init, .. } => {
            if let Some(expr) = init {
                collect_expr_lambda_functions(builder, expr, enclosing_function, out);
            }
        }
        Stmt::Assign { lhs, rhs, .. } => {
            match lhs {
                LValue::Field { base, .. } => collect_expr_lambda_functions(builder, base, enclosing_function, out),
                LValue::Index { base, index } => {
                    collect_expr_lambda_functions(builder, base, enclosing_function, out);
                    collect_expr_lambda_functions(builder, index, enclosing_function, out);
                }
                LValue::Var(_) => {}
            }
            collect_expr_lambda_functions(builder, rhs, enclosing_function, out);
        }
        Stmt::Expr { expr, .. } => collect_expr_lambda_functions(builder, expr, enclosing_function, out),
        Stmt::If { cond, then_block, else_block, .. } => {
            collect_expr_lambda_functions(builder, cond, enclosing_function, out);
            collect_block_lambda_functions(builder, then_block, enclosing_function, out);
            if let Some(block) = else_block {
                collect_block_lambda_functions(builder, block, enclosing_function, out);
            }
        }
        Stmt::While { cond, body, .. } => {
            collect_expr_lambda_functions(builder, cond, enclosing_function, out);
            collect_block_lambda_functions(builder, body, enclosing_function, out);
        }
        Stmt::ForEach { iterable, body, .. } => {
            collect_expr_lambda_functions(builder, iterable, enclosing_function, out);
            collect_block_lambda_functions(builder, body, enclosing_function, out);
        }
        Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
            if let Some(expr) = value {
                collect_expr_lambda_functions(builder, expr, enclosing_function, out);
            }
        }
        Stmt::Try { try_block, catches, finally_block, .. } => {
            collect_block_lambda_functions(builder, try_block, enclosing_function, out);
            for catch in catches {
                collect_block_lambda_functions(builder, &catch.body, enclosing_function, out);
            }
            if let Some(block) = finally_block {
                collect_block_lambda_functions(builder, block, enclosing_function, out);
            }
        }
    }
}

fn collect_block_lambda_functions(
    builder: &mut ModuleBuilder,
    block: &Block,
    enclosing_function: &str,
    out: &mut Vec<uniflow_hir::Function>,
) {
    for stmt in &block.stmts {
        collect_stmt_lambda_functions(builder, stmt, enclosing_function, out);
    }
}

fn collect_stmt_local_symbols(stmt: &Stmt, locals: &mut HashSet<SymbolId>) {
    match stmt {
        Stmt::Let { symbol, .. } => {
            locals.insert(*symbol);
        }
        Stmt::ForEach { item_symbol, body, .. } => {
            locals.insert(*item_symbol);
            collect_block_local_symbols(body, locals);
        }
        Stmt::If { then_block, else_block, .. } => {
            collect_block_local_symbols(then_block, locals);
            if let Some(block) = else_block {
                collect_block_local_symbols(block, locals);
            }
        }
        Stmt::While { body, .. } => collect_block_local_symbols(body, locals),
        Stmt::Try { try_block, catches, finally_block, .. } => {
            collect_block_local_symbols(try_block, locals);
            for catch in catches {
                if let Some(symbol) = catch.symbol {
                    locals.insert(symbol);
                }
                collect_block_local_symbols(&catch.body, locals);
            }
            if let Some(block) = finally_block {
                collect_block_local_symbols(block, locals);
            }
        }
        Stmt::Assign { .. } | Stmt::Expr { .. } | Stmt::Return { .. } | Stmt::Throw { .. } => {}
    }
}

fn collect_block_local_symbols(block: &Block, locals: &mut HashSet<SymbolId>) {
    for stmt in &block.stmts {
        collect_stmt_local_symbols(stmt, locals);
    }
}

fn collect_stmt_free_symbols(
    stmt: &Stmt,
    locals: &HashSet<SymbolId>,
    outer_symbols: &HashMap<SymbolId, String>,
    seen: &mut HashSet<SymbolId>,
    out: &mut Vec<(SymbolId, String)>,
) {
    match stmt {
        Stmt::Let { init, .. } => {
            if let Some(expr) = init {
                collect_free_lambda_symbols(expr, locals, outer_symbols, seen, out);
            }
        }
        Stmt::Assign { lhs, rhs, .. } => {
            match lhs {
                LValue::Field { base, .. } => collect_free_lambda_symbols(base, locals, outer_symbols, seen, out),
                LValue::Index { base, index } => {
                    collect_free_lambda_symbols(base, locals, outer_symbols, seen, out);
                    collect_free_lambda_symbols(index, locals, outer_symbols, seen, out);
                }
                LValue::Var(_) => {}
            }
            collect_free_lambda_symbols(rhs, locals, outer_symbols, seen, out);
        }
        Stmt::Expr { expr, .. } => collect_free_lambda_symbols(expr, locals, outer_symbols, seen, out),
        Stmt::If { cond, then_block, else_block, .. } => {
            collect_free_lambda_symbols(cond, locals, outer_symbols, seen, out);
            collect_block_free_symbols(then_block, locals, outer_symbols, seen, out);
            if let Some(block) = else_block {
                collect_block_free_symbols(block, locals, outer_symbols, seen, out);
            }
        }
        Stmt::While { cond, body, .. } => {
            collect_free_lambda_symbols(cond, locals, outer_symbols, seen, out);
            collect_block_free_symbols(body, locals, outer_symbols, seen, out);
        }
        Stmt::ForEach { iterable, body, .. } => {
            collect_free_lambda_symbols(iterable, locals, outer_symbols, seen, out);
            collect_block_free_symbols(body, locals, outer_symbols, seen, out);
        }
        Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
            if let Some(expr) = value {
                collect_free_lambda_symbols(expr, locals, outer_symbols, seen, out);
            }
        }
        Stmt::Try { try_block, catches, finally_block, .. } => {
            collect_block_free_symbols(try_block, locals, outer_symbols, seen, out);
            for catch in catches {
                collect_block_free_symbols(&catch.body, locals, outer_symbols, seen, out);
            }
            if let Some(block) = finally_block {
                collect_block_free_symbols(block, locals, outer_symbols, seen, out);
            }
        }
    }
}

fn collect_block_free_symbols(
    block: &Block,
    locals: &HashSet<SymbolId>,
    outer_symbols: &HashMap<SymbolId, String>,
    seen: &mut HashSet<SymbolId>,
    out: &mut Vec<(SymbolId, String)>,
) {
    for stmt in &block.stmts {
        collect_stmt_free_symbols(stmt, locals, outer_symbols, seen, out);
    }
}

fn rewrite_lvalue_capture_symbols(lhs: LValue, capture_map: &HashMap<SymbolId, SymbolId>) -> LValue {
    match lhs {
        LValue::Var(symbol) => LValue::Var(capture_map.get(&symbol).copied().unwrap_or(symbol)),
        LValue::Field { base, field } => LValue::Field {
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            field,
        },
        LValue::Index { base, index } => LValue::Index {
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            index: Box::new(rewrite_lambda_capture_symbols(*index, capture_map)),
        },
    }
}

fn rewrite_stmt_capture_symbols(stmt: Stmt, capture_map: &HashMap<SymbolId, SymbolId>) -> Stmt {
    match stmt {
        Stmt::Let { id, symbol, ty, init, span } => Stmt::Let {
            id,
            symbol,
            ty,
            init: init.map(|expr| rewrite_lambda_capture_symbols(expr, capture_map)),
            span,
        },
        Stmt::Assign { id, lhs, rhs, span } => Stmt::Assign {
            id,
            lhs: rewrite_lvalue_capture_symbols(lhs, capture_map),
            rhs: rewrite_lambda_capture_symbols(rhs, capture_map),
            span,
        },
        Stmt::Expr { id, expr, span } => Stmt::Expr {
            id,
            expr: rewrite_lambda_capture_symbols(expr, capture_map),
            span,
        },
        Stmt::If { id, cond, then_block, else_block, span } => Stmt::If {
            id,
            cond: rewrite_lambda_capture_symbols(cond, capture_map),
            then_block: rewrite_block_capture_symbols(then_block, capture_map),
            else_block: else_block.map(|block| rewrite_block_capture_symbols(block, capture_map)),
            span,
        },
        Stmt::While { id, cond, body, span } => Stmt::While {
            id,
            cond: rewrite_lambda_capture_symbols(cond, capture_map),
            body: rewrite_block_capture_symbols(body, capture_map),
            span,
        },
        Stmt::ForEach { id, item_symbol, iterable, body, span } => Stmt::ForEach {
            id,
            item_symbol,
            iterable: rewrite_lambda_capture_symbols(iterable, capture_map),
            body: rewrite_block_capture_symbols(body, capture_map),
            span,
        },
        Stmt::Return { id, value, span } => Stmt::Return {
            id,
            value: value.map(|expr| rewrite_lambda_capture_symbols(expr, capture_map)),
            span,
        },
        Stmt::Throw { id, value, span } => Stmt::Throw {
            id,
            value: value.map(|expr| rewrite_lambda_capture_symbols(expr, capture_map)),
            span,
        },
        Stmt::Try { id, try_block, catches, finally_block, span } => Stmt::Try {
            id,
            try_block: rewrite_block_capture_symbols(try_block, capture_map),
            catches: catches.into_iter().map(|catch| CatchClause {
                symbol: catch.symbol,
                ty: catch.ty,
                body: rewrite_block_capture_symbols(catch.body, capture_map),
                span: catch.span,
            }).collect(),
            finally_block: finally_block.map(|block| rewrite_block_capture_symbols(block, capture_map)),
            span,
        },
    }
}

fn rewrite_block_capture_symbols(block: Block, capture_map: &HashMap<SymbolId, SymbolId>) -> Block {
    Block {
        id: block.id,
        stmts: block.stmts.into_iter().map(|stmt| rewrite_stmt_capture_symbols(stmt, capture_map)).collect(),
        span: block.span,
    }
}

fn finalize_nested_function_captures(
    builder: &mut ModuleBuilder,
    function: &mut uniflow_hir::Function,
    outer_env: &PyEnv,
) {
    let mut locals = HashSet::new();
    if let Some(receiver) = &function.receiver {
        locals.insert(receiver.symbol);
    }
    for param in &function.params {
        locals.insert(param.symbol);
    }
    collect_block_local_symbols(&function.body, &mut locals);
    let outer_symbols = outer_env
        .vars
        .iter()
        .map(|(name, symbol)| (*symbol, name.clone()))
        .collect::<HashMap<_, _>>();
    let mut captures = Vec::new();
    let mut seen = HashSet::new();
    collect_block_free_symbols(&function.body, &locals, &outer_symbols, &mut seen, &mut captures);
    if captures.is_empty() {
        return;
    }
    let mut capture_map = HashMap::new();
    let mut capture_params = Vec::new();
    for (source_symbol, name) in captures {
        let symbol = builder.add_symbol(&lambda_capture_field_name(&name), SymbolKind::Local);
        capture_map.insert(source_symbol, symbol);
        capture_params.push(uniflow_hir::Param {
            name,
            symbol,
            ty: infer_lambda_capture_type(builder, outer_env, &outer_symbols[&source_symbol]),
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            span: function.span,
        });
    }
    function.body = rewrite_block_capture_symbols(function.body.clone(), &capture_map);
    function.captures = capture_params;
}

fn parse_nested_function_definition(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) {
    let line = &lines[*idx];
    let def_re = Regex::new(r"^\s*(?:async\s+def|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*:").expect("valid regex");
    let Some(caps) = def_re.captures(&line.text) else {
        *idx += 1;
        return;
    };
    let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default().to_string();
    let params = caps.get(2).map(|m| m.as_str()).unwrap_or_default().to_string();
    let start = *idx;
    let mut end = start + 1;
    while end < lines.len() {
        let trimmed = lines[end].text.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') && lines[end].indent <= current_indent {
            break;
        }
        end += 1;
    }
    let body = lines[start + 1..end]
        .iter()
        .map(|entry| entry.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let nested = PyFunctionText {
        name: name.clone(),
        params,
        body,
        start_line: line.line_no,
        end_line: lines[end.saturating_sub(1)].line_no.max(line.line_no),
        decorators: Vec::new(),
    };
    let qualified_name = format!("{}.{}", env.current_function, name);
    let current_module = env.current_module.clone();
    let project_index = env.project_index.clone();
    let parsed = parse_function(
        builder,
        &nested,
        imports,
        known_classes,
        None,
        &[],
        &HashMap::new(),
        &HashMap::new(),
        &current_module,
        Some(&project_index),
        Some(&qualified_name),
        Some(env),
    );
    env.callable_aliases.insert(name.clone(), qualified_name.clone());
    env.types.insert(name.clone(), qualified_name.clone());
    env.synthetic_functions.push(parsed.function);
    env.synthetic_functions.extend(parsed.synthetic_functions);
    *idx = end;
}

fn parse_body(
    builder: &mut ModuleBuilder,
    body: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    first_line: u32,
) -> Vec<Stmt> {
    let lines = collect_py_body_lines(body, first_line);
    let mut idx = 0usize;
    parse_stmt_sequence(
        builder,
        &lines,
        &mut idx,
        current_body_indent(&lines),
        imports,
        known_classes,
        env,
    )
}

fn parse_stmt_sequence(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    while *idx < lines.len() {
        let Some(code_idx) = next_code_line(lines, *idx) else {
            *idx = lines.len();
            break;
        };
        *idx = code_idx;
        let line = &lines[*idx];
        let trimmed = line.text.trim();
        if line.indent < current_indent {
            break;
        }
        if line.indent > current_indent {
            *idx += 1;
            continue;
        }
        if is_clause_continuation_header(trimmed) {
            break;
        }
        if trimmed.starts_with("def ") || trimmed.starts_with("async def ") {
            parse_nested_function_definition(builder, lines, idx, current_indent, imports, known_classes, env);
            continue;
        }
        if trimmed.starts_with("class ") {
            *idx += 1;
            continue;
        }

        if trimmed.starts_with("if ") {
            out.push(parse_if_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }
        if trimmed.starts_with("while ") {
            out.push(parse_while_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }
        if trimmed.starts_with("for ") || trimmed.starts_with("async for ") {
            out.push(parse_for_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }
        if trimmed == "try:" {
            out.push(parse_try_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }
        if trimmed.starts_with("with ") || trimmed.starts_with("async with ") {
            out.extend(parse_with_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }

        out.extend(parse_simple_stmt(builder, trimmed, imports, known_classes, env, line.line_no));
        *idx += 1;
    }
    out
}

fn parse_nested_block(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    parent_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    fallback_line: u32,
) -> Block {
    let Some(start_idx) = next_code_line(lines, *idx) else {
        return build_py_block(builder, Vec::new(), fallback_line, fallback_line);
    };
    if lines[start_idx].indent <= parent_indent {
        return build_py_block(builder, Vec::new(), fallback_line, fallback_line);
    }
    *idx = start_idx;
    let start_line = lines[start_idx].line_no;
    let nested_indent = lines[start_idx].indent;
    let stmts = parse_stmt_sequence(builder, lines, idx, nested_indent, imports, known_classes, env);
    let end_line = stmts.last().map(stmt_end_line).unwrap_or(start_line);
    build_py_block(builder, stmts, start_line, end_line)
}

fn parse_if_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Stmt {
    let line = &lines[*idx];
    let trimmed = line.text.trim();
    let cond_text = trimmed
        .strip_prefix("if ")
        .or_else(|| trimmed.strip_prefix("elif ") )
        .and_then(|rest| rest.strip_suffix(':'))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_else(|| "True".to_string());
    let cond = parse_expr(builder, &cond_text, imports, known_classes, env, line.line_no);
    let start_line = line.line_no;
    let base_env = env.clone();
    *idx += 1;
    let mut then_env = base_env.clone();
    apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut then_env);
    let then_block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut then_env, start_line);

    let mut else_block = None;
    let mut end_line = then_block.span.end_line.max(start_line);
    let mut else_env_out = None;
    if let Some(next_idx) = next_code_line(lines, *idx) {
        if lines[next_idx].indent == current_indent {
            let header = lines[next_idx].text.trim();
            if header.starts_with("elif ") {
                *idx = next_idx;
                let mut elif_env = base_env.clone();
                apply_runtime_condition_refinements(&cond_text, false, imports, known_classes, &mut elif_env);
                let elif_stmt = parse_if_stmt(builder, lines, idx, current_indent, imports, known_classes, &mut elif_env);
                end_line = stmt_end_line(&elif_stmt).max(end_line);
                else_env_out = Some(elif_env);
                else_block = Some(build_py_block(builder, vec![elif_stmt], lines[next_idx].line_no, end_line));
            } else if header == "else:" {
                let else_line = lines[next_idx].line_no;
                *idx = next_idx + 1;
                let mut else_env = base_env.clone();
                apply_runtime_condition_refinements(&cond_text, false, imports, known_classes, &mut else_env);
                let block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut else_env, else_line);
                end_line = block.span.end_line.max(end_line);
                else_env_out = Some(else_env);
                else_block = Some(block);
            }
        }
    }

    *env = merge_py_envs(&base_env, &then_env, else_env_out.as_ref());

    Stmt::If {
        id: builder.alloc_stmt_id(),
        cond,
        then_block,
        else_block,
        span: span_from_line_range(builder.file_id(), start_line, end_line),
    }
}

fn parse_while_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Stmt {
    let line = &lines[*idx];
    let trimmed = line.text.trim();
    let cond_text = trimmed
        .strip_prefix("while ")
        .and_then(|rest| rest.strip_suffix(':'))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_else(|| "True".to_string());
    let cond = parse_expr(builder, &cond_text, imports, known_classes, env, line.line_no);
    let start_line = line.line_no;
    let base_env = env.clone();
    *idx += 1;
    let mut loop_env = base_env.clone();
    apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut loop_env);
    let body = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut loop_env, start_line);
    *env = merge_py_envs(&base_env, &loop_env, Some(&base_env));
    let end_line = body.span.end_line.max(start_line);
    Stmt::While {
        id: builder.alloc_stmt_id(),
        cond,
        body,
        span: span_from_line_range(builder.file_id(), start_line, end_line),
    }
}

fn infer_iterable_item_type(iterable_text: &str, imports: &PyImports, env: &PyEnv, known_classes: &HashSet<String>) -> Option<String> {
    let trimmed = iterable_text.trim();
    if trimmed.starts_with("range(") {
        return Some("int".to_string());
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        if callee_text == "enumerate" {
            let first_arg = args.iter().find(|arg| !arg.trim().is_empty())?;
            let item_ty = infer_iterable_item_type(first_arg, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
            return Some(format!("tuple<int|{}>", item_ty));
        }
        if callee_text == "zip" {
            let item_types = args
                .iter()
                .filter(|arg| !arg.trim().is_empty())
                .filter_map(|arg| infer_iterable_item_type(arg, imports, env, known_classes))
                .collect::<Vec<_>>();
            if !item_types.is_empty() {
                return Some(format!("tuple<{}>", item_types.join("|")));
            }
        }
        if callee_text == "map" {
            let iterables = args.iter().skip(1).filter(|arg| !arg.trim().is_empty()).collect::<Vec<_>>();
            if !iterables.is_empty() {
                if let Some(ret) = infer_simple_callable_result_type_from_expr(&args[0], iterables.len(), imports, env, known_classes) {
                    return Some(ret);
                }
                return infer_iterable_item_type(iterables[0], imports, env, known_classes);
            }
        }
        if callee_text == "filter" {
            let first_iterable = args.iter().skip(1).find(|arg| !arg.trim().is_empty())?;
            return infer_iterable_item_type(first_iterable, imports, env, known_classes);
        }
        if callee_text == "sorted" {
            let first_arg = args.iter().find(|arg| !arg.trim().is_empty())?;
            return infer_iterable_item_type(first_arg, imports, env, known_classes);
        }
    }
    let iterable_ty = infer_simple_python_type(iterable_text, imports, env, known_classes)?;
    if let Some((base, method)) = split_last_top_level_dot(trimmed) {
        if let Some(base_ty) = infer_simple_python_type(&base, imports, env, known_classes) {
            if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                if let Some((key, value)) = split_once_top_level(inner, ',') {
                    let key = key.trim();
                    let value = value.trim();
                    if method == "items" {
                        return Some(format!("tuple<{}|{}>", key, value));
                    }
                    if method == "values" {
                        return Some(value.to_string());
                    }
                    if method == "keys" {
                        return Some(key.to_string());
                    }
                }
            }
        }
    }
    if let Some(inner) = iterable_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = iterable_ty.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = iterable_ty.strip_prefix("generator<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = iterable_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some((key, _)) = split_once_top_level(inner, ',') {
            return Some(key.trim().to_string());
        }
    }
    if let Some(items) = parse_tuple_type_elements(&iterable_ty) {
        if items.len() == 1 {
            return items.first().cloned();
        }
    }
    iterable_item_type_from_project_type(&env.project_index, &iterable_ty, &mut HashSet::new())
}

fn parse_for_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Stmt {
    let line = &lines[*idx];
    let trimmed = line.text.trim();
    let header = trimmed.strip_prefix("async ").unwrap_or(trimmed);
    let rest = header
        .strip_prefix("for ")
        .and_then(|value| value.strip_suffix(':'))
        .map(|value| value.trim().to_string())
        .unwrap_or_default();
    let (item_name, iterable_text) = split_once_top_level_str(&rest, " in ", false)
        .unwrap_or_else(|| ("item".to_string(), rest));
    let base_env = env.clone();
    let iterable = parse_expr(builder, &iterable_text, imports, known_classes, env, line.line_no);
    let mut loop_env = base_env.clone();
    let destructured_targets = parse_destructuring_targets(item_name.trim());
    let symbol = if destructured_targets.is_empty() {
        ensure_known_symbol(builder, &mut loop_env.vars, item_name.trim(), SymbolKind::Local)
    } else {
        new_unpack_symbol(builder, "iter_item", line.line_no, 0)
    };
    let item_ty = infer_iterable_item_type(&iterable_text, imports, &base_env, known_classes);
    if destructured_targets.is_empty() {
        let item_name = item_name.trim().to_string();
        if let Some(ty) = item_ty.clone() {
            if let Some(path) = callable_path_from_type(&loop_env.project_index, &ty) {
                loop_env.callable_aliases.insert(item_name.clone(), path);
            } else {
                loop_env.callable_aliases.remove(&item_name);
            }
            loop_env.types.insert(item_name, ty);
        }
    } else if let Some(target_types) = item_ty.as_deref().and_then(destructure_type_elements) {
        for (target, ty) in destructured_targets.iter().zip(target_types.into_iter()) {
            loop_env.types.insert(target.clone(), ty);
        }
    }
    let start_line = line.line_no;
    *idx += 1;
    let mut body = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut loop_env, start_line);
    if !destructured_targets.is_empty() {
        let inferred_targets = item_ty
            .as_deref()
            .and_then(destructure_type_elements)
            .unwrap_or_default()
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
        let mut prefix = Vec::new();
        extend_destructuring_bindings(builder, &mut prefix, &destructured_targets, symbol, &inferred_targets, &mut loop_env, line.line_no);
        if !prefix.is_empty() {
            let mut combined = prefix;
            combined.extend(body.stmts);
            body.stmts = combined;
        }
    }
    *env = merge_py_envs(&base_env, &loop_env, Some(&base_env));
    let end_line = body.span.end_line.max(start_line);
    Stmt::ForEach {
        id: builder.alloc_stmt_id(),
        item_symbol: symbol,
        iterable,
        body,
        span: span_from_line_range(builder.file_id(), start_line, end_line),
    }
}

fn parse_try_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Stmt {
    let line = &lines[*idx];
    let start_line = line.line_no;
    let base_env = env.clone();
    *idx += 1;

    let mut try_env = base_env.clone();
    let mut try_block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut try_env, start_line);
    let mut catches = Vec::new();
    let mut catch_envs = Vec::new();
    let mut finally_block = None;
    let mut end_line = try_block.span.end_line.max(start_line);
    let mut success_env = try_env.clone();

    loop {
        let Some(next_idx) = next_code_line(lines, *idx) else {
            break;
        };
        if lines[next_idx].indent != current_indent {
            break;
        }
        let header = lines[next_idx].text.trim();
        if header.starts_with("except") {
            let catch_line = lines[next_idx].line_no;
            let spec = header
                .strip_prefix("except")
                .and_then(|rest| rest.strip_suffix(':'))
                .map(|rest| rest.trim().to_string())
                .unwrap_or_default();
            let (ty_text, sym_text) = if let Some((lhs, rhs)) = split_once_top_level_str(&spec, " as ", false) {
                (Some(lhs), Some(rhs))
            } else if spec.is_empty() {
                (None, None)
            } else {
                (Some(spec), None)
            };
            let mut catch_env = base_env.clone();
            let symbol = sym_text.as_deref().filter(|name| is_simple_ident(name)).map(|name| {
                ensure_known_symbol(builder, &mut catch_env.vars, name, SymbolKind::Local)
            });
            let ty_name = ty_text
                .as_deref()
                .and_then(|name| qualify_type_name(&env.current_module, name, imports, Some(&env.project_index)).or_else(|| qualify_type_name(&env.current_module, name, imports, None)));
            if let (Some(name), Some(ty_name)) = (sym_text.as_deref().filter(|name| is_simple_ident(name)), ty_name.clone()) {
                catch_env.types.insert(name.to_string(), canonicalize_project_path(&env.project_index, &ty_name));
            }
            let ty = ty_name.map(|name| builder.ensure_type(&name));
            *idx = next_idx + 1;
            let body = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut catch_env, catch_line);
            end_line = body.span.end_line.max(end_line);
            catches.push(CatchClause {
                symbol,
                ty,
                body,
                span: span_from_line_range(builder.file_id(), catch_line, end_line),
            });
            catch_envs.push(catch_env);
            continue;
        }
        if header == "else:" {
            let else_line = lines[next_idx].line_no;
            *idx = next_idx + 1;
            let mut else_env = try_env.clone();
            let else_block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut else_env, else_line);
            end_line = else_block.span.end_line.max(end_line);
            let block_start = try_block.span.start_line;
            let mut combined = try_block.stmts;
            combined.extend(else_block.stmts);
            try_block = build_py_block(builder, combined, block_start, end_line);
            success_env = else_env;
            continue;
        }
        if header == "finally:" {
            let finally_line = lines[next_idx].line_no;
            *idx = next_idx + 1;
            let mut merged_before_finally_paths = vec![success_env.clone()];
            merged_before_finally_paths.extend(catch_envs.iter().cloned());
            let mut merged_before_finally = merge_py_env_paths(&base_env, &merged_before_finally_paths);
            let block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut merged_before_finally, finally_line);
            end_line = block.span.end_line.max(end_line);
            finally_block = Some(block);
            *env = merged_before_finally;
        }
        break;
    }

    if finally_block.is_none() {
        let mut merged_paths = vec![success_env];
        merged_paths.extend(catch_envs);
        *env = merge_py_env_paths(&base_env, &merged_paths);
    }

    Stmt::Try {
        id: builder.alloc_stmt_id(),
        try_block,
        catches,
        finally_block,
        span: span_from_line_range(builder.file_id(), start_line, end_line),
    }
}

fn parse_with_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Vec<Stmt> {
    let line = &lines[*idx];
    let header = line.text.trim();
    let inner = header
        .strip_prefix("async with ")
        .or_else(|| header.strip_prefix("with ") )
        .and_then(|rest| rest.strip_suffix(':'))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_default();
    let mut out = Vec::new();
    for item in split_top_level_commas(&inner).into_iter().filter(|part| !part.trim().is_empty()) {
        if let Some((expr_text, alias_text)) = split_once_top_level_str(&item, " as ", false) {
            let alias = alias_text.trim();
            let span = span_from_line_range(builder.file_id(), line.line_no, line.line_no);
            let rhs = parse_expr(builder, &expr_text, imports, known_classes, env, line.line_no);
            let inferred_ty = context_manager_alias_type(&expr_text, imports, env, known_classes)
                .or_else(|| infer_simple_python_type(&expr_text, imports, env, known_classes));
            let existed = env.vars.contains_key(alias);
            let symbol = ensure_known_symbol(builder, &mut env.vars, alias, SymbolKind::Local);
            if let Some(ty) = inferred_ty.clone() {
                env.types.insert(alias.to_string(), ty);
            }
            if let Some(path) = infer_project_callable_value_type(&expr_text, imports, env, known_classes) {
                env.callable_aliases.insert(alias.to_string(), path);
            } else {
                env.callable_aliases.remove(alias);
            }
            env.local_object_aliases.remove(alias);
            env.local_field_types.remove(alias);
            populate_precise_container_slots_from_expr(env, alias, &expr_text, imports, known_classes);
            if existed {
                out.push(Stmt::Assign {
                    id: builder.alloc_stmt_id(),
                    lhs: LValue::Var(symbol),
                    rhs,
                    span,
                });
            } else {
                out.push(Stmt::Let {
                    id: builder.alloc_stmt_id(),
                    symbol,
                    ty: inferred_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                    init: Some(rhs),
                    span,
                });
            }
        } else {
            let span = span_from_line_range(builder.file_id(), line.line_no, line.line_no);
            out.push(Stmt::Expr {
                id: builder.alloc_stmt_id(),
                expr: parse_expr(builder, &item, imports, known_classes, env, line.line_no),
                span,
            });
        }
    }
    *idx += 1;
    let body = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, env, line.line_no);
    out.extend(body.stmts);
    out
}

fn local_object_alias_root(env: &PyEnv, name: &str) -> Option<String> {
    if !is_simple_ident(name) {
        return None;
    }
    let mut cur = name.trim().to_string();
    let mut seen = HashSet::new();
    while let Some(next) = env.local_object_aliases.get(&cur) {
        if !seen.insert(cur.clone()) || next == &cur {
            break;
        }
        cur = next.clone();
    }
    Some(cur)
}

fn propagate_local_object_alias(env: &mut PyEnv, target: &str, source_expr: &str) {
    let source = source_expr.trim();
    if !is_simple_ident(target) {
        return;
    }
    let source_root = if env.self_name.as_deref() == Some(source) {
        Some(source.to_string())
    } else {
        local_object_alias_root(env, source)
    };
    let Some(root) = source_root else {
        env.local_object_aliases.remove(target);
        env.local_field_types.remove(target);
        return;
    };
    env.local_object_aliases.insert(target.to_string(), root.clone());
    let field_map = env
        .local_field_types
        .get(source)
        .cloned()
        .or_else(|| env.local_field_types.get(&root).cloned())
        .or_else(|| {
            if env.self_name.as_deref() == Some(root.as_str()) {
                Some(env.field_types.clone())
            } else {
                None
            }
        });
    if let Some(fields) = field_map {
        env.local_field_types.insert(target.to_string(), fields);
    }
}

fn update_local_object_field_type(env: &mut PyEnv, base_name: &str, field: &str, ty: &str) {
    let base = base_name.trim();
    if base.is_empty() {
        return;
    }
    if !is_simple_ident(base) {
        if let Some(canonical) = canonical_container_path(env, base) {
            env.local_field_types
                .entry(canonical)
                .or_default()
                .insert(field.to_string(), ty.to_string());
        }
        return;
    }
    let root = local_object_alias_root(env, base).unwrap_or_else(|| base.to_string());
    let mut names = vec![base.to_string()];
    if root != base {
        names.push(root.clone());
    }
    for (alias, alias_root) in env.local_object_aliases.clone() {
        if alias_root == root && !names.iter().any(|name| name == &alias) {
            names.push(alias);
        }
    }
    for name in names {
        env.local_field_types
            .entry(name)
            .or_default()
            .insert(field.to_string(), ty.to_string());
    }
}


fn clear_local_object_field_type(env: &mut PyEnv, base_name: &str, field: &str) {
    let base = base_name.trim();
    if base.is_empty() {
        return;
    }
    if !is_simple_ident(base) {
        if let Some(canonical) = canonical_container_path(env, base) {
            let mut should_remove = false;
            if let Some(fields) = env.local_field_types.get_mut(&canonical) {
                fields.remove(field);
                should_remove = fields.is_empty();
            }
            if should_remove {
                env.local_field_types.remove(&canonical);
            }
        }
        return;
    }
    let root = local_object_alias_root(env, base).unwrap_or_else(|| base.to_string());
    let mut names = vec![base.to_string()];
    if root != base {
        names.push(root.clone());
    }
    for (alias, alias_root) in env.local_object_aliases.clone() {
        if alias_root == root && !names.iter().any(|name| name == &alias) {
            names.push(alias);
        }
    }
    for name in names {
        let mut should_remove = false;
        if let Some(fields) = env.local_field_types.get_mut(&name) {
            fields.remove(field);
            should_remove = fields.is_empty();
        }
        if should_remove {
            env.local_field_types.remove(&name);
        }
    }
}

fn strip_python_string_literal(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let quote = trimmed.chars().next()?;
    if (quote == '\'' || quote == '"') && trimmed.ends_with(quote) {
        return Some(trimmed[1..trimmed.len() - 1].to_string());
    }
    None
}

fn decode_python_string_literal(text: &str) -> Option<String> {
    let raw = strip_python_string_literal(text)?;
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('\'') => out.push('\''),
            Some('"') => out.push('"'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    Some(out)
}
fn parse_static_eval_expr_text(text: &str) -> Option<String> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee = callee_text.trim();
    if callee != "eval" && callee != "builtins.eval" {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let decoded = decode_python_string_literal(args.get(0)?)?;
    let expr = decoded.trim();
    (!expr.is_empty()).then(|| expr.to_string())
}

fn parse_static_exec_body(text: &str) -> Option<Vec<String>> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee = callee_text.trim();
    if callee != "exec" && callee != "builtins.exec" {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let decoded = decode_python_string_literal(args.get(0)?)?;
    let lines = decoded
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    (!lines.is_empty()).then_some(lines)
}

fn parse_static_index_slot_key(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if let Some(value) = strip_python_string_literal(trimmed) {
        return Some(value);
    }
    if let Ok(value) = trimmed.parse::<i64>() {
        return Some(value.to_string());
    }
    None
}


fn parse_builtin_static_attr_call(text: &str, builtin_name: &str) -> Option<(String, String, Vec<String>)> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    if callee_text.trim() != builtin_name {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let base = args.get(0)?.trim().to_string();
    let field = args.get(1).and_then(|value| strip_python_string_literal(&value))?;
    Some((base, field, args))
}

fn synthetic_attr_expr_text(base: &str, field: &str) -> String {
    format!("{}.{}", base.trim(), field.trim())
}

fn synthetic_static_namespace_access_text(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let (base_text, index_text) = split_last_top_level_index(trimmed)?;
    let slot_key = parse_static_index_slot_key(&index_text)?;
    let base_trimmed = base_text.trim();
    if base_trimmed == "globals()" || base_trimmed == "locals()" {
        return Some(slot_key);
    }
    if let Some(owner) = base_trimmed.strip_suffix(".__dict__") {
        return Some(synthetic_attr_expr_text(owner, &slot_key));
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(base_trimmed) {
        if callee_text.trim() == "vars" {
            let args = split_python_call_args(&arg_text);
            if args.len() == 1 {
                return Some(synthetic_attr_expr_text(args[0].trim(), &slot_key));
            }
        }
    }
    None
}
 
fn static_namespace_update_target(base_text: &str, key: &str) -> Option<String> {
    let base_trimmed = base_text.trim();
    if base_trimmed == "globals()" || base_trimmed == "locals()" {
        return Some(key.to_string());
    }
    if let Some(owner) = base_trimmed.strip_suffix(".__dict__") {
        return Some(synthetic_attr_expr_text(owner, key));
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(base_trimmed) {
        if callee_text.trim() == "vars" {
            let args = split_python_call_args(&arg_text);
            if args.len() == 1 {
                return Some(synthetic_attr_expr_text(args[0].trim(), key));
            }
        }
    }
    None
}

fn parse_static_namespace_method_call(text: &str) -> Option<(String, StaticNamespaceMethodKind, Option<String>)> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let (receiver_text, method) = split_last_top_level_dot(callee_text.trim())?;
    let kind = match method.as_str() {
        "get" => StaticNamespaceMethodKind::Get,
        "pop" => StaticNamespaceMethodKind::Pop,
        "setdefault" => StaticNamespaceMethodKind::SetDefault,
        _ => return None,
    };
    let args = split_python_call_args(&arg_text);
    let key = args.get(0).and_then(|arg| strip_python_string_literal(arg))?;
    let target = static_namespace_update_target(&receiver_text, &key)?;
    let default_value = args.get(1).map(|value| value.trim().to_string());
    Some((target, kind, default_value))
}

fn parse_static_namespace_update_call(text: &str) -> Option<Vec<(String, String)>> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let (receiver_text, method) = split_last_top_level_dot(callee_text.trim())?;
    if method != "update" {
        return None;
    }
    let mut out = Vec::new();
    let mut push_entry = |key: String, value_text: String| {
        if let Some(target) = static_namespace_update_target(&receiver_text, &key) {
            out.push((target, value_text));
        }
    };
    for arg in split_python_call_args(&arg_text) {
        let item = arg.trim();
        if item.is_empty() {
            continue;
        }
        if let Some((name, value)) = split_once_top_level(item, '=') {
            let key = name.trim();
            if is_simple_ident(key) {
                push_entry(key.to_string(), value.trim().to_string());
                continue;
            }
        }
        if let Some(entries) = parse_static_mapping_entries(item) {
            for (key, value_text) in entries {
                push_entry(key, value_text);
            }
            continue;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn context_manager_alias_type(
    expr_text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let manager_ty = infer_simple_python_type(expr_text, imports, env, known_classes)?;
    env.project_index
        .method_return(&manager_ty, "__aenter__", 0)
        .or_else(|| env.project_index.method_return(&manager_ty, "__enter__", 0))
        .or(Some(manager_ty))
}

fn parse_builtin_setattr_call(text: &str) -> Option<(String, String, String)> {
    let (base, field, args) = parse_builtin_static_attr_call(text, "setattr")?;
    let value = args.get(2)?.trim().to_string();
    Some((base, field, value))
}

fn parse_builtin_delattr_call(text: &str) -> Option<(String, String)> {
    let (base, field, _args) = parse_builtin_static_attr_call(text, "delattr")?;
    Some((base, field))
}


fn parse_builtin_type_guard_call(text: &str, builtin_name: &str) -> Option<(String, String)> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee = callee_text.trim();
    if callee != builtin_name && !callee.ends_with(&format!(".{builtin_name}")) {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let target = args.get(0)?.trim().to_string();
    let ty_text = args.get(1)?.trim();
    if ty_text.starts_with('(') && ty_text.ends_with(')') {
        return None;
    }
    let ty = strip_python_string_literal(ty_text).unwrap_or_else(|| ty_text.to_string());
    Some((target, ty))
}

fn normalize_runtime_type_name(
    type_text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = type_text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(class_name) = resolve_known_class_name(trimmed, imports, env, known_classes) {
        return Some(class_name);
    }
    if let Some(resolved) = resolve_dotted_type(trimmed, imports, env, known_classes) {
        return Some(resolved);
    }
    qualify_type_name(&env.current_module, trimmed, imports, Some(&env.project_index))
}

fn apply_refined_target_type(env: &mut PyEnv, target_text: &str, ty: &str) {
    let target = target_text.trim();
    if target.is_empty() {
        return;
    }
    if is_simple_ident(target) {
        env.types.insert(target.to_string(), ty.to_string());
        return;
    }
    if let Some((base_text, field)) = split_last_top_level_dot(target) {
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            env.field_types.insert(field.clone(), ty.to_string());
            if let Some(current_class) = env.current_class.clone() {
                env.class_field_index
                    .entry(current_class)
                    .or_default()
                    .insert(field, ty.to_string());
            }
            return;
        }
        if is_simple_ident(&base_text) {
            update_local_object_field_type(env, &base_text, &field, ty);
        }
    }
}

fn parse_runtime_type_identity_guard(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    for op in [" is ", " == "] {
        if let Some((left, right)) = split_once_top_level_str(trimmed, op, false) {
            if let Some(target) = left.trim().strip_prefix("type(").and_then(|rest| rest.strip_suffix(')')) {
                return Some((target.trim().to_string(), right.trim().to_string()));
            }
            if let Some(target) = right.trim().strip_prefix("type(").and_then(|rest| rest.strip_suffix(')')) {
                return Some((target.trim().to_string(), left.trim().to_string()));
            }
        }
    }
    None
}

fn apply_runtime_condition_refinements(
    cond_text: &str,
    positive: bool,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) {
    let trimmed = cond_text.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Some(inner) = trimmed.strip_prefix("not ") {
        apply_runtime_condition_refinements(inner, !positive, imports, known_classes, env);
        return;
    }
    if positive {
        if let Some((left, right)) = split_once_top_level_str(trimmed, " and ", false) {
            apply_runtime_condition_refinements(&left, true, imports, known_classes, env);
            apply_runtime_condition_refinements(&right, true, imports, known_classes, env);
            return;
        }
    } else if let Some((left, right)) = split_once_top_level_str(trimmed, " or ", false) {
        apply_runtime_condition_refinements(&left, false, imports, known_classes, env);
        apply_runtime_condition_refinements(&right, false, imports, known_classes, env);
        return;
    }

    if positive {
        if let Some((target, ty_text)) = parse_runtime_type_identity_guard(trimmed) {
            if let Some(ty) = normalize_runtime_type_name(&ty_text, imports, env, known_classes) {
                apply_refined_target_type(env, &target, &ty);
            }
            return;
        }
        if let Some((target, ty_text)) = parse_builtin_type_guard_call(trimmed, "isinstance") {
            if let Some(ty) = normalize_runtime_type_name(&ty_text, imports, env, known_classes) {
                apply_refined_target_type(env, &target, &ty);
            }
            return;
        }
        if let Some((target, ty_text)) = parse_builtin_type_guard_call(trimmed, "issubclass") {
            if let Some(ty) = normalize_runtime_type_name(&ty_text, imports, env, known_classes) {
                apply_refined_target_type(env, &target, &ty);
            }
            return;
        }
        if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "hasattr") {
            let synthetic = synthetic_attr_expr_text(&base, &field);
            if let Some(ty) = resolve_dotted_type(&synthetic, imports, env, known_classes) {
                apply_refined_target_type(env, &synthetic, &ty);
            } else if let Some(base_ty) = resolve_dotted_type(&base, imports, env, known_classes) {
                if let Some(field_ty) = env.project_index.field_type(&base_ty, &field) {
                    apply_refined_target_type(env, &synthetic, &field_ty);
                }
            }
        }
    }
}

fn apply_python_env_assignment_effects(
    target_text: &str,
    value_text: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let target = target_text.trim();
    let value = value_text.trim();
    if target.is_empty() {
        apply_python_expr_side_effects(value, imports, env, known_classes);
        return;
    }

    if is_simple_ident(target) {
        clear_precise_container_slots(env, target);
        if let Some(path) = infer_project_callable_value_type(value, imports, env, known_classes) {
            env.callable_aliases.insert(target.to_string(), path);
        } else {
            env.callable_aliases.remove(target);
        }
        if is_simple_ident(value) {
            propagate_local_object_alias(env, target, value);
        } else {
            env.local_object_aliases.remove(target);
            env.local_field_types.remove(target);
        }
        let inferred_ty = infer_simple_python_type(value, imports, env, known_classes);
        if let Some(ty) = inferred_ty.clone() {
            env.types.insert(target.to_string(), ty.clone());
            if let Some((callee_text, _)) = parse_call_parts(value) {
                if let Some(callee_ty) = resolve_dotted_type(callee_text.trim(), imports, env, known_classes) {
                    let canonical_callee = canonicalize_project_path(&env.project_index, &callee_ty);
                    let canonical_ty = canonicalize_project_path(&env.project_index, &ty);
                    if canonical_callee == canonical_ty && env.project_index.class_exists(&canonical_ty) {
                        replay_constructor_summary_effects(target, &canonical_ty, &env.current_module.clone(), imports, env, known_classes);
                    }
                }
            }
        } else {
            env.types.remove(target);
        }
        populate_precise_container_slots_from_expr(env, target, value, imports, known_classes);
        apply_python_expr_side_effects(value, imports, env, known_classes);
        return;
    }

    if let Some((base_text, field)) = split_last_top_level_dot(target) {
        clear_precise_container_slots(env, target);
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            if let Some(inferred) = infer_simple_python_type(value, imports, env, known_classes) {
                env.field_types.insert(field.clone(), inferred.clone());
                if let Some(current_class) = env.current_class.clone() {
                    env.class_field_index.entry(current_class).or_default().insert(field, inferred);
                }
            } else {
                env.field_types.remove(&field);
            }
        } else if is_simple_ident(&base_text) {
            if let Some(inferred) = infer_simple_python_type(value, imports, env, known_classes) {
                update_local_object_field_type(env, &base_text, &field, &inferred);
                if let Some(base_ty) = env.types.get(&base_text).cloned() {
                    let canonical = canonicalize_project_path(&env.project_index, &base_ty);
                    if env.project_index.class_exists(&canonical) {
                        env.class_field_index.entry(canonical).or_default().insert(field.clone(), inferred);
                    }
                }
            } else {
                clear_local_object_field_type(env, &base_text, &field);
            }
        }
        populate_precise_container_slots_from_expr(env, target, value, imports, known_classes);
        apply_python_expr_side_effects(value, imports, env, known_classes);
        return;
    }

    if let Some((base_text, index_text)) = split_last_top_level_index(target) {
        let slot_key = parse_static_index_slot_key(&index_text).unwrap_or_else(|| "*".to_string());
        if let Some(inferred) = infer_simple_python_type(value, imports, env, known_classes) {
            update_precise_container_slot_type(env, &base_text, &slot_key, &inferred);
            if let Some(base_ty) = env.types.get(base_text.trim()).cloned() {
                let merged = merge_container_type(Some(base_ty.as_str()), &inferred);
                env.types.insert(base_text.trim().to_string(), merged);
            }
        }
        let callable = infer_project_callable_value_type(value, imports, env, known_classes);
        update_precise_container_slot_callable(env, &base_text, &slot_key, callable.as_deref());
        apply_python_expr_side_effects(value, imports, env, known_classes);
        return;
    }

    apply_python_expr_side_effects(value, imports, env, known_classes);
}

fn clear_python_env_target_effects(target_text: &str, env: &mut PyEnv) {
    let target = target_text.trim();
    if target.is_empty() {
        return;
    }
    if is_simple_ident(target) {
        env.types.remove(target);
        env.callable_aliases.remove(target);
        env.local_object_aliases.remove(target);
        env.local_field_types.remove(target);
        clear_precise_container_slots(env, target);
        return;
    }
    if let Some((base_text, field)) = split_last_top_level_dot(target) {
        clear_precise_container_slots(env, target);
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            env.field_types.remove(&field);
            if let Some(current_class) = env.current_class.clone() {
                if let Some(fields) = env.class_field_index.get_mut(&current_class) {
                    fields.remove(&field);
                }
            }
        } else if is_simple_ident(&base_text) {
            clear_local_object_field_type(env, &base_text, &field);
        }
        return;
    }
    if let Some((base_text, index_text)) = split_last_top_level_index(target) {
        if let Some(slot_key) = parse_static_index_slot_key(&index_text) {
            let base = canonical_container_path(env, &base_text).unwrap_or_else(|| base_text.trim().to_string());
            if let Some(slots) = env.precise_index_types.get_mut(&base) {
                slots.remove(&slot_key);
                if slots.is_empty() {
                    env.precise_index_types.remove(&base);
                }
            }
            if let Some(slots) = env.precise_index_callables.get_mut(&base) {
                slots.remove(&slot_key);
                if slots.is_empty() {
                    env.precise_index_callables.remove(&base);
                }
            }
        }
    }
}

fn apply_python_expr_side_effects(
    expr_text: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let trimmed = expr_text.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
        let module_name = env.current_module.clone();
        let index = env.project_index.clone();
        apply_project_module_import_line_effects(trimmed, &module_name, &index, env);
        return;
    }
    if let Some(lines) = parse_static_exec_body(trimmed) {
        for line in lines {
            apply_project_summary_line_effects(&line, imports, env, known_classes);
        }
        return;
    }
    if let Some(entries) = parse_static_namespace_update_call(trimmed) {
        for (target, value_text) in entries {
            apply_python_env_assignment_effects(&target, &value_text, imports, env, known_classes);
        }
        return;
    }
    if let Some((base_text, field, value_text)) = parse_builtin_setattr_call(trimmed) {
        apply_python_env_assignment_effects(&synthetic_attr_expr_text(&base_text, &field), &value_text, imports, env, known_classes);
        return;
    }
    if let Some((base_text, field)) = parse_builtin_delattr_call(trimmed) {
        clear_python_env_target_effects(&synthetic_attr_expr_text(&base_text, &field), env);
        return;
    }
    if let Some((target, kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        match kind {
            StaticNamespaceMethodKind::Get => {}
            StaticNamespaceMethodKind::Pop => clear_python_env_target_effects(&target, env),
            StaticNamespaceMethodKind::SetDefault => {
                if !env.types.contains_key(&target) && !env.callable_aliases.contains_key(&target) {
                    if let Some(default_value) = default_value.as_deref() {
                        apply_python_env_assignment_effects(&target, default_value, imports, env, known_classes);
                    }
                }
            }
        }
        return;
    }

    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        if let Some((receiver_text, method)) = split_last_top_level_dot(callee_text.trim()) {
            let args = split_python_call_args(&arg_text);
            match method.as_str() {
                "append" => {
                    if let Some(arg_text) = args.get(0) {
                        if let Some(inferred) = infer_simple_python_type(arg_text, imports, env, known_classes) {
                            let merged = merge_container_type(env.types.get(receiver_text.trim()).map(|v| v.as_str()), &format!("list<{}>", inferred));
                            env.types.insert(receiver_text.trim().to_string(), merged);
                            let slot_key = next_precise_list_slot(env, receiver_text.trim()).to_string();
                            update_precise_container_slot_type(env, receiver_text.trim(), &slot_key, &inferred);
                        }
                        let callable = infer_project_callable_value_type(arg_text, imports, env, known_classes);
                        let slot_key = next_precise_list_slot(env, receiver_text.trim()).to_string();
                        update_precise_container_slot_callable(env, receiver_text.trim(), &slot_key, callable.as_deref());
                    }
                }
                "insert" => {
                    if let (Some(index_text), Some(arg_text)) = (args.get(0), args.get(1)) {
                        let slot_key = parse_static_index_slot_key(index_text).unwrap_or_else(|| next_precise_list_slot(env, receiver_text.trim()).to_string());
                        if let Some(inferred) = infer_simple_python_type(arg_text, imports, env, known_classes) {
                            update_precise_container_slot_type(env, receiver_text.trim(), &slot_key, &inferred);
                        }
                        let callable = infer_project_callable_value_type(arg_text, imports, env, known_classes);
                        update_precise_container_slot_callable(env, receiver_text.trim(), &slot_key, callable.as_deref());
                    }
                }
                "extend" => {
                    if let Some(arg_text) = args.get(0) {
                        for (slot_key, ty, callable) in collect_precise_container_slots_from_expr(arg_text, imports, env, known_classes) {
                            if let Some(ty) = ty.as_deref() {
                                let next_key = if slot_key == "*" { next_precise_list_slot(env, receiver_text.trim()).to_string() } else { slot_key.clone() };
                                update_precise_container_slot_type(env, receiver_text.trim(), &next_key, ty);
                                update_precise_container_slot_callable(env, receiver_text.trim(), &next_key, callable.as_deref());
                            }
                        }
                        if let Some(item_ty) = infer_iterable_item_type(arg_text, imports, env, known_classes)
                            .or_else(|| infer_iterable_item_type(arg_text, imports, env, known_classes)) {
                            let merged = merge_container_type(env.types.get(receiver_text.trim()).map(|v| v.as_str()), &format!("list<{}>", item_ty));
                            env.types.insert(receiver_text.trim().to_string(), merged);
                        }
                    }
                }
                "update" => {
                    if let Some(arg_text) = args.get(0) {
                        for (slot_key, ty, callable) in collect_precise_container_slots_from_expr(arg_text, imports, env, known_classes) {
                            if let Some(ty) = ty.as_deref() {
                                update_precise_container_slot_type(env, receiver_text.trim(), &slot_key, ty);
                            }
                            update_precise_container_slot_callable(env, receiver_text.trim(), &slot_key, callable.as_deref());
                        }
                    }
                }
                "setdefault" => {
                    if let Some(key_text) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                        if precise_container_slot_type(env, receiver_text.trim(), &key_text).is_none()
                            && precise_container_slot_callable(env, receiver_text.trim(), &key_text).is_none() {
                            if let Some(default_text) = args.get(1) {
                                if let Some(ty) = infer_simple_python_type(default_text, imports, env, known_classes) {
                                    update_precise_container_slot_type(env, receiver_text.trim(), &key_text, &ty);
                                }
                                let callable = infer_project_callable_value_type(default_text, imports, env, known_classes);
                                update_precise_container_slot_callable(env, receiver_text.trim(), &key_text, callable.as_deref());
                            }
                        }
                    }
                }
                "pop" => {
                    if let Some(key_text) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                        clear_python_env_target_effects(&format!("{}[{}]", receiver_text.trim(), key_text), env);
                    } else if let Some(last) = last_precise_list_slot(env, receiver_text.trim()) {
                        clear_python_env_target_effects(&format!("{}[{}]", receiver_text.trim(), last), env);
                    }
                }
                _ => {}
            }
        }
    }
}

fn apply_project_summary_line_effects(
    line: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
        let module_name = env.current_module.clone();
        let index = env.project_index.clone();
        apply_project_module_import_line_effects(trimmed, &module_name, &index, env);
        return;
    }
    if parse_python_name_declaration(trimmed, "global ").is_some() || parse_python_name_declaration(trimmed, "nonlocal ").is_some() {
        return;
    }
    if let Some(lines) = parse_static_exec_body(trimmed) {
        for line in lines {
            apply_project_summary_line_effects(&line, imports, env, known_classes);
        }
        return;
    }
    if let Some(entries) = parse_static_namespace_update_call(trimmed) {
        for (target, value_text) in entries {
            apply_python_env_assignment_effects(&target, &value_text, imports, env, known_classes);
        }
        return;
    }
    if let Some(rest) = trimmed.strip_prefix("del ") {
        for raw_target in split_top_level_commas(rest) {
            let target = synthetic_static_namespace_access_text(raw_target.trim()).unwrap_or_else(|| raw_target.trim().to_string());
            clear_python_env_target_effects(&target, env);
        }
        return;
    }
    if let Some((base_text, field, value_text)) = parse_builtin_setattr_call(trimmed) {
        apply_python_env_assignment_effects(&synthetic_attr_expr_text(&base_text, &field), &value_text, imports, env, known_classes);
        return;
    }
    if let Some((base_text, field)) = parse_builtin_delattr_call(trimmed) {
        clear_python_env_target_effects(&synthetic_attr_expr_text(&base_text, &field), env);
        return;
    }
    if let Some((left, right)) = split_once_top_level(trimmed, '=') {
        if !left.contains("==") && !left.contains("!=") && !left.contains(">=") && !left.contains("<=") {
            let destructured = parse_destructuring_targets(&left);
            if !destructured.is_empty() {
                let values_inner = right.trim()
                    .strip_prefix('(').and_then(|rest| rest.strip_suffix(')'))
                    .or_else(|| right.trim().strip_prefix('[').and_then(|rest| rest.strip_suffix(']')));
                if let Some(inner) = values_inner {
                    let values = split_top_level_commas(inner)
                        .into_iter()
                        .filter(|item| !item.trim().is_empty())
                        .collect::<Vec<_>>();
                    if values.len() == destructured.len() {
                        for (target, value_text) in destructured.into_iter().zip(values.into_iter()) {
                            apply_python_env_assignment_effects(&target, &value_text, imports, env, known_classes);
                        }
                        return;
                    }
                }
                for target in destructured {
                    clear_python_env_target_effects(&target, env);
                }
                apply_python_expr_side_effects(right.trim(), imports, env, known_classes);
                return;
            }
            let normalized_left = synthetic_static_namespace_access_text(left.trim()).unwrap_or_else(|| left.trim().to_string());
            apply_python_env_assignment_effects(&normalized_left, right.trim(), imports, env, known_classes);
            return;
        }
    }
    apply_python_expr_side_effects(trimmed, imports, env, known_classes);
}

fn merge_project_summary_writebacks_into_env(summary: &ProjectFunctionSummary, env: &mut PyEnv) {
    for (name, ty) in &summary.writeback_types {
        env.types.insert(name.clone(), ty.clone());
    }
    for (name, path) in &summary.writeback_callables {
        env.callable_aliases.insert(name.clone(), path.clone());
    }
}

fn merge_project_summary_effects_into_env(summary: &ProjectFunctionSummary, env: &mut PyEnv) {
    merge_project_summary_writebacks_into_env(summary, env);
    for (root, fields) in &summary.local_field_writes {
        for (field, ty) in fields {
            if root == "self" || env.self_name.as_deref() == Some(root.as_str()) {
                env.field_types.insert(field.clone(), ty.clone());
                if let Some(current_class) = env.current_class.clone() {
                    env.class_field_index.entry(current_class).or_default().insert(field.clone(), ty.clone());
                }
                continue;
            }
            update_local_object_field_type(env, root, field, ty);
            if let Some(base_ty) = env.types.get(root).cloned() {
                let canonical = canonicalize_project_path(&env.project_index, &base_ty);
                if env.project_index.class_exists(&canonical) {
                    env.class_field_index.entry(canonical).or_default().insert(field.clone(), ty.clone());
                }
            }
        }
    }
    for (root, slots) in &summary.precise_index_type_writes {
        for (slot_key, ty) in slots {
            update_precise_container_slot_type(env, root, slot_key, ty);
        }
    }
    for (root, slots) in &summary.precise_index_callable_writes {
        for (slot_key, path) in slots {
            update_precise_container_slot_callable(env, root, slot_key, Some(path));
        }
    }
}

fn project_method_receiver_param_name(func: &PyFunctionText, owner_class: &str) -> Option<String> {
    if function_has_decorator(func, "staticmethod") {
        return None;
    }
    let specs = parse_python_param_specs(&func.params);
    let first = specs.first()?;
    if first.name == "self" || first.name == "cls" || function_has_decorator(func, "classmethod") {
        return Some(first.name.clone());
    }
    if owner_class.is_empty() {
        None
    } else {
        Some(first.name.clone())
    }
}

fn apply_receiver_summary_effects(
    receiver_text: &str,
    receiver_ty: &str,
    receiver_param: &str,
    summary: &ProjectFunctionSummary,
    env: &mut PyEnv,
) {
    let receiver = receiver_text.trim();
    if receiver.is_empty() {
        return;
    }
    for (root, fields) in &summary.local_field_writes {
        if root != receiver_param {
            continue;
        }
        for (field, ty) in fields {
            if is_simple_ident(receiver) {
                update_local_object_field_type(env, receiver, field, ty);
                let canonical = canonicalize_project_path(&env.project_index, receiver_ty);
                if env.project_index.class_exists(&canonical) {
                    env.class_field_index.entry(canonical).or_default().insert(field.clone(), ty.clone());
                }
            }
        }
    }
    for (root, slots) in &summary.precise_index_type_writes {
        if root != receiver_param {
            continue;
        }
        for (slot_key, ty) in slots {
            update_precise_container_slot_type(env, receiver, slot_key, ty);
        }
    }
    for (root, slots) in &summary.precise_index_callable_writes {
        if root != receiver_param {
            continue;
        }
        for (slot_key, path) in slots {
            update_precise_container_slot_callable(env, receiver, slot_key, Some(path));
        }
    }
}

fn bind_python_call_arguments(
    func: &PyFunctionText,
    bound_leading: Option<(&str, &str)>,
    arg_text: &str,
) -> HashMap<String, String> {
    let specs = parse_python_param_specs(&func.params);
    let mut bindings = HashMap::new();
    let mut positional_specs: Vec<&PyParamSpec> = Vec::new();
    let mut keyword_specs: HashMap<String, &PyParamSpec> = HashMap::new();
    let mut varargs_name: Option<String> = None;
    let mut kwargs_name: Option<String> = None;
    let mut skip_first = false;
    if let Some((formal, actual)) = bound_leading {
        if let Some(first) = specs.first() {
            if first.name == formal {
                bindings.insert(formal.to_string(), actual.trim().to_string());
                skip_first = true;
            }
        }
    }
    for (idx, spec) in specs.iter().enumerate() {
        if skip_first && idx == 0 {
            continue;
        }
        match spec.kind {
            PyParamKind::Positional => {
                if !spec.keyword_only {
                    positional_specs.push(spec);
                }
                keyword_specs.insert(spec.name.clone(), spec);
            }
            PyParamKind::VarArgs => {
                varargs_name = Some(spec.name.clone());
                keyword_specs.insert(spec.name.clone(), spec);
            }
            PyParamKind::KwArgs => {
                kwargs_name = Some(spec.name.clone());
                keyword_specs.insert(spec.name.clone(), spec);
            }
        }
    }
    let mut positional_idx = 0usize;
    let mut pending_varargs = Vec::new();
    let mut pending_kwargs: Vec<(String, String)> = Vec::new();
    for arg in parse_python_call_args_detailed(arg_text) {
        if let Some(name) = arg.name {
            if let Some(spec) = keyword_specs.get(&name) {
                bindings.entry(spec.name.clone()).or_insert(arg.expr.trim().to_string());
            } else if kwargs_name.is_some() {
                pending_kwargs.push((name, arg.expr.trim().to_string()));
            }
            continue;
        }
        match arg.spread {
            PyCallArgSpread::Star => {
                if let Some(items) = parse_static_sequence_items(&arg.expr) {
                    for item in items {
                        while positional_idx < positional_specs.len() {
                            let spec = positional_specs[positional_idx];
                            positional_idx += 1;
                            if spec.kind == PyParamKind::Positional {
                                bindings.entry(spec.name.clone()).or_insert(item.trim().to_string());
                                break;
                            }
                        }
                    }
                } else if varargs_name.is_some() {
                    pending_varargs.push(arg.expr.trim().to_string());
                }
            }
            PyCallArgSpread::StarStar => {
                if let Some(entries) = parse_static_mapping_entries(&arg.expr) {
                    for (name, value) in entries {
                        if let Some(spec) = keyword_specs.get(&name) {
                            bindings.entry(spec.name.clone()).or_insert(value.trim().to_string());
                        } else if kwargs_name.is_some() {
                            pending_kwargs.push((name, value.trim().to_string()));
                        }
                    }
                } else if let Some(kwargs_name) = kwargs_name.as_ref() {
                    bindings.entry(kwargs_name.clone()).or_insert(arg.expr.trim().to_string());
                }
            }
            PyCallArgSpread::None => {
                while positional_idx < positional_specs.len() {
                    let spec = positional_specs[positional_idx];
                    positional_idx += 1;
                    if spec.kind == PyParamKind::Positional {
                        bindings.entry(spec.name.clone()).or_insert(arg.expr.trim().to_string());
                        break;
                    }
                }
            }
        }
    }
    if let Some(varargs_name) = varargs_name {
        if !pending_varargs.is_empty() {
            bindings
                .entry(varargs_name)
                .or_insert(format!("tuple<{}>", pending_varargs.join("|")));
        }
    }
    if let Some(kwargs_name) = kwargs_name {
        if !pending_kwargs.is_empty() {
            let mut entries = Vec::new();
            for (name, value) in pending_kwargs {
                entries.push(format!("{name}:{value}"));
            }
            bindings
                .entry(kwargs_name)
                .or_insert(format!("dict<{}>", entries.join("|")));
        }
    }
    bindings
}

fn apply_bound_summary_effects(
    bindings: &HashMap<String, String>,
    summary: &ProjectFunctionSummary,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    for (formal, actual_expr) in bindings {
        let actual = synthetic_static_namespace_access_text(actual_expr)
            .unwrap_or_else(|| actual_expr.trim().to_string());
        if actual.is_empty() {
            continue;
        }
        let actual_ty = infer_simple_python_type(&actual, imports, env, known_classes)
            .or_else(|| infer_project_expr_type(&actual, module_name, imports, index, &env.field_types, env.current_class.as_deref()));
        for (root, fields) in &summary.local_field_writes {
            if root != formal {
                continue;
            }
            for (field, ty) in fields {
                update_local_object_field_type(env, &actual, field, ty);
                if let Some(actual_ty) = actual_ty.as_deref() {
                    let canonical = canonicalize_project_path(index, actual_ty);
                    if index.class_exists(&canonical) {
                        env.class_field_index.entry(canonical).or_default().insert(field.clone(), ty.clone());
                    }
                }
            }
        }
        for (root, slots) in &summary.precise_index_type_writes {
            if root != formal {
                continue;
            }
            for (slot_key, ty) in slots {
                update_precise_container_slot_type(env, &actual, slot_key, ty);
            }
        }
        for (root, slots) in &summary.precise_index_callable_writes {
            if root != formal {
                continue;
            }
            for (slot_key, path) in slots {
                update_precise_container_slot_callable(env, &actual, slot_key, Some(path));
            }
        }
    }
}

fn decorated_summary_target_path_for_callable(
    func: &PyFunctionText,
    owner_module: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    base_path: &str,
) -> Option<String> {
    let base_canonical = canonicalize_project_path(index, base_path);
    let decorated_ty = decorate_project_callable_type(func, owner_module, imports, index, &base_canonical);
    let decorated_canonical = canonicalize_project_path(index, &decorated_ty);
    if decorated_canonical == base_canonical {
        return None;
    }
    if index.function_path_exists(&decorated_canonical)
        || index.method_text(&decorated_canonical).is_some()
        || index.top_level_function_text(&decorated_canonical).is_some()
        || infer_project_summary_by_callable_path(&decorated_canonical, index).is_some()
    {
        return Some(decorated_canonical);
    }
    if let Some(callable_path) = callable_path_from_type(index, &decorated_canonical) {
        let callable_canonical = canonicalize_project_path(index, &callable_path);
        if callable_canonical != base_canonical {
            return Some(callable_canonical);
        }
    }
    if index.class_exists(&decorated_canonical) {
        if let Some(call_path) = index.method_path(&decorated_canonical, "__call__") {
            return Some(call_path);
        }
    }
    None
}

fn replay_plain_project_method_summary_effects(
    method_path: &str,
    receiver_text: &str,
    arg_text: &str,
    caller_module_name: &str,
    caller_imports: &PyImports,
    caller_known_classes: &HashSet<String>,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) -> Option<(PyFunctionText, String, PyImports)> {
    let func = index.method_text(method_path)?.clone();
    let (owner_class, _) = method_path.rsplit_once('.')?;
    let (owner_module, _) = owner_class.rsplit_once('.')?;
    let func_imports = index.module_imports_for(owner_module)?.clone();
    let current_fields = index.field_types.get(owner_class).cloned().unwrap_or_default();
    let class_bases = index.class_bases.get(owner_class).cloned().unwrap_or_default();
    let summary = infer_project_function_summary_with_locals(
        &func,
        owner_module,
        &func_imports,
        index,
        Some(owner_class),
        &class_bases,
        &current_fields,
        None,
    );
    merge_project_summary_writebacks_into_env(&summary, env);
    let receiver_param = project_method_receiver_param_name(&func, owner_class);
    if let Some(receiver_param) = receiver_param.as_deref() {
        let receiver_ty = infer_simple_python_type(receiver_text.trim(), caller_imports, env, caller_known_classes)
            .unwrap_or_else(|| env.types.get(receiver_text.trim()).cloned().unwrap_or_else(|| owner_class.to_string()));
        apply_receiver_summary_effects(receiver_text, &receiver_ty, receiver_param, &summary, env);
    }
    let bindings = bind_python_call_arguments(
        &func,
        receiver_param.as_deref().map(|formal| (formal, receiver_text)),
        arg_text,
    );
    apply_bound_summary_effects(
        &bindings,
        &summary,
        caller_module_name,
        caller_imports,
        index,
        env,
        caller_known_classes,
    );
    Some((func, owner_module.to_string(), func_imports))
}

fn replay_plain_top_level_function_summary_effects(
    function_path: &str,
    bound_leading: Option<(&str, &str)>,
    arg_text: &str,
    caller_module_name: &str,
    caller_imports: &PyImports,
    caller_known_classes: &HashSet<String>,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) -> Option<(PyFunctionText, String, PyImports)> {
    let (func, owner_module, _owner_class) = infer_project_function_text_context_by_callable_path(function_path, index)?;
    let func_imports = index.module_imports_for(&owner_module)?.clone();
    let summary = infer_project_summary_by_callable_path(function_path, index)?;
    merge_project_summary_writebacks_into_env(&summary, env);
    let bindings = bind_python_call_arguments(&func, bound_leading, arg_text);
    apply_bound_summary_effects(
        &bindings,
        &summary,
        caller_module_name,
        caller_imports,
        index,
        env,
        caller_known_classes,
    );
    Some((func, owner_module.to_string(), func_imports))
}

fn replay_project_method_summary_effects(
    method_path: &str,
    receiver_text: &str,
    arg_text: &str,
    caller_module_name: &str,
    caller_imports: &PyImports,
    caller_known_classes: &HashSet<String>,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) -> bool {
    let Some((func, owner_module, func_imports)) = replay_plain_project_method_summary_effects(
        method_path,
        receiver_text,
        arg_text,
        caller_module_name,
        caller_imports,
        caller_known_classes,
        index,
        env,
    ) else {
        return false;
    };
    if let Some(wrapper_path) = decorated_summary_target_path_for_callable(&func, &owner_module, &func_imports, index, method_path) {
        if wrapper_path != canonicalize_project_path(index, method_path) {
            if index.method_text(&wrapper_path).is_some() {
                let _ = replay_plain_project_method_summary_effects(
                    &wrapper_path,
                    receiver_text,
                    arg_text,
                    caller_module_name,
                    caller_imports,
                    caller_known_classes,
                    index,
                    env,
                );
            } else {
                let wrapper_bound_leading = index
                    .top_level_function_text(&wrapper_path)
                    .and_then(|wrapper| parse_python_param_specs(&wrapper.params).first().cloned())
                    .and_then(|spec| (spec.name == "self" || spec.name == "cls").then(|| (spec.name.clone(), receiver_text.to_string())));
                let _ = replay_plain_top_level_function_summary_effects(
                    &wrapper_path,
                    wrapper_bound_leading.as_ref().map(|(formal, actual)| (formal.as_str(), actual.as_str())),
                    arg_text,
                    caller_module_name,
                    caller_imports,
                    caller_known_classes,
                    index,
                    env,
                );
            }
        }
    }
    true
}

fn replay_top_level_function_summary_effects(
    function_path: &str,
    arg_text: &str,
    caller_module_name: &str,
    caller_imports: &PyImports,
    caller_known_classes: &HashSet<String>,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) -> bool {
    let Some((func, owner_module, func_imports)) = replay_plain_top_level_function_summary_effects(
        function_path,
        None,
        arg_text,
        caller_module_name,
        caller_imports,
        caller_known_classes,
        index,
        env,
    ) else {
        return false;
    };
    if let Some(wrapper_path) = decorated_summary_target_path_for_callable(&func, &owner_module, &func_imports, index, function_path) {
        if wrapper_path != canonicalize_project_path(index, function_path) {
            if index.method_text(&wrapper_path).is_none() {
                let _ = replay_plain_top_level_function_summary_effects(
                &wrapper_path,
                None,
                arg_text,
                caller_module_name,
                caller_imports,
                caller_known_classes,
                index,
                env,
            );
            }
        }
    }
    true
}

fn replay_constructor_summary_effects(
    target_text: &str,
    constructed_type: &str,
    module_name: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let target = target_text.trim();
    if target.is_empty() || !is_simple_ident(target) {
        return;
    }
    let canonical_ty = canonicalize_project_path(&env.project_index, constructed_type);
    let Some(init_path) = env.project_index.method_path(&canonical_ty, "__init__") else {
        return;
    };
    let _ = replay_project_method_summary_effects(
        &init_path,
        target,
        "",
        module_name,
        imports,
        known_classes,
        &env.project_index.clone(),
        env,
    );
}

fn apply_direct_call_summary_effects(
    line: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
    nested_summaries: Option<&HashMap<String, ProjectFunctionSummary>>,
) {
    let Some((callee_text, _arg_text)) = parse_call_parts(line.trim()) else {
        return;
    };
    let callee = callee_text.trim();
    if callee.is_empty() {
        return;
    }

    let mut candidate = env
        .callable_aliases
        .get(callee)
        .cloned()
        .or_else(|| env.types.get(callee).and_then(|ty| callable_path_from_type(index, ty)));

    if candidate.is_none() {
        if let Some(nested) = nested_summaries {
            let direct_nested = format!("{}.{}", env.current_function, callee);
            if nested.contains_key(&direct_nested) {
                candidate = Some(direct_nested);
            }
        }
    }

    if candidate.is_none() {
        candidate = infer_project_symbol_path_in_env(callee, module_name, imports, index, env, known_classes);
    }

    let Some(path) = candidate else {
        return;
    };
    let canonical = canonicalize_project_path(index, &path);
    if canonical == env.current_function {
        return;
    }

    if let Some(nested) = nested_summaries.and_then(|items| items.get(&canonical).or_else(|| items.get(&path))) {
        merge_project_summary_effects_into_env(nested, env);
        return;
    }

    if let Some((receiver_text, _)) = split_last_top_level_dot(callee) {
        if replay_project_method_summary_effects(&canonical, &receiver_text, &_arg_text, module_name, imports, known_classes, index, env) {
            return;
        }
    }

    let _ = replay_top_level_function_summary_effects(
        &canonical,
        &_arg_text,
        module_name,
        imports,
        known_classes,
        index,
        env,
    );
}

fn merge_py_envs(base: &PyEnv, then_env: &PyEnv, else_env: Option<&PyEnv>) -> PyEnv {
    let mut out = base.clone();
    out.synthetic_functions = base.synthetic_functions.clone();
    for func in then_env.synthetic_functions.iter().chain(else_env.into_iter().flat_map(|env| env.synthetic_functions.iter())) {
        if !out.synthetic_functions.iter().any(|existing| existing.name == func.name) {
            out.synthetic_functions.push(func.clone());
        }
    }
    out.discovered_fields.extend(then_env.discovered_fields.clone());
    if let Some(other) = else_env {
        out.discovered_fields.extend(other.discovered_fields.clone());
    }

    if let Some(other) = else_env {
        let mut merged_vars = base.vars.clone();
        for (name, symbol) in then_env.vars.iter().chain(other.vars.iter()) {
            merged_vars.entry(name.clone()).or_insert(*symbol);
        }
        out.vars = merged_vars;
        let mut merged_caps = base.capturable_vars.clone();
        for (name, symbol) in then_env.capturable_vars.iter().chain(other.capturable_vars.iter()) {
            merged_caps.entry(name.clone()).or_insert(*symbol);
        }
        out.capturable_vars = merged_caps;

        let all_type_keys = then_env
            .types
            .keys()
            .chain(other.types.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for key in all_type_keys {
            match (then_env.types.get(&key), other.types.get(&key)) {
                (Some(left), Some(right)) => {
                    out.types.insert(key.clone(), merge_container_type(Some(left.as_str()), right));
                }
                _ => {
                    out.types.remove(&key);
                }
            }
        }

        let all_callable_keys = then_env
            .callable_aliases
            .keys()
            .chain(other.callable_aliases.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for key in all_callable_keys {
            match (then_env.callable_aliases.get(&key), other.callable_aliases.get(&key)) {
                (Some(left), Some(right)) if left == right => {
                    out.callable_aliases.insert(key.clone(), left.clone());
                }
                _ => {
                    out.callable_aliases.remove(&key);
                }
            }
        }

        let all_field_keys = then_env
            .field_types
            .keys()
            .chain(other.field_types.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for key in all_field_keys {
            match (then_env.field_types.get(&key), other.field_types.get(&key)) {
                (Some(left), Some(right)) => {
                    out.field_types.insert(key.clone(), merge_container_type(Some(left.as_str()), right));
                }
                _ => {
                    out.field_types.remove(&key);
                }
            }
        }

        let local_roots = then_env
            .local_field_types
            .keys()
            .chain(other.local_field_types.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for root in local_roots {
            let left = then_env.local_field_types.get(&root);
            let right = other.local_field_types.get(&root);
            match (left, right) {
                (Some(left_fields), Some(right_fields)) => {
                    let mut merged = HashMap::new();
                    let field_names = left_fields
                        .keys()
                        .chain(right_fields.keys())
                        .cloned()
                        .collect::<HashSet<_>>();
                    for field in field_names {
                        if let (Some(left_ty), Some(right_ty)) = (left_fields.get(&field), right_fields.get(&field)) {
                            merged.insert(field.clone(), merge_container_type(Some(left_ty.as_str()), right_ty));
                        }
                    }
                    if merged.is_empty() {
                        out.local_field_types.remove(&root);
                    } else {
                        out.local_field_types.insert(root.clone(), merged);
                    }
                }
                _ => {
                    out.local_field_types.remove(&root);
                }
            }
        }

        let alias_names = then_env
            .local_object_aliases
            .keys()
            .chain(other.local_object_aliases.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for name in alias_names {
            match (then_env.local_object_aliases.get(&name), other.local_object_aliases.get(&name)) {
                (Some(left), Some(right)) if left == right => {
                    out.local_object_aliases.insert(name.clone(), left.clone());
                }
                _ => {
                    out.local_object_aliases.remove(&name);
                }
            }
        }

        let precise_roots = then_env
            .precise_index_types
            .keys()
            .chain(other.precise_index_types.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for root in precise_roots {
            let left = then_env.precise_index_types.get(&root);
            let right = other.precise_index_types.get(&root);
            match (left, right) {
                (Some(left_slots), Some(right_slots)) => {
                    let mut merged = HashMap::new();
                    let slot_names = left_slots
                        .keys()
                        .chain(right_slots.keys())
                        .cloned()
                        .collect::<HashSet<_>>();
                    for slot in slot_names {
                        if let (Some(left_ty), Some(right_ty)) = (left_slots.get(&slot), right_slots.get(&slot)) {
                            merged.insert(slot.clone(), merge_container_type(Some(left_ty.as_str()), right_ty));
                        }
                    }
                    if merged.is_empty() {
                        out.precise_index_types.remove(&root);
                    } else {
                        out.precise_index_types.insert(root.clone(), merged);
                    }
                }
                _ => {
                    out.precise_index_types.remove(&root);
                }
            }
        }

        let precise_callable_roots = then_env
            .precise_index_callables
            .keys()
            .chain(other.precise_index_callables.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for root in precise_callable_roots {
            let left = then_env.precise_index_callables.get(&root);
            let right = other.precise_index_callables.get(&root);
            match (left, right) {
                (Some(left_slots), Some(right_slots)) => {
                    let mut merged = HashMap::new();
                    let slot_names = left_slots
                        .keys()
                        .chain(right_slots.keys())
                        .cloned()
                        .collect::<HashSet<_>>();
                    for slot in slot_names {
                        if let (Some(left_path), Some(right_path)) = (left_slots.get(&slot), right_slots.get(&slot)) {
                            if left_path == right_path {
                                merged.insert(slot.clone(), left_path.clone());
                            }
                        }
                    }
                    if merged.is_empty() {
                        out.precise_index_callables.remove(&root);
                    } else {
                        out.precise_index_callables.insert(root.clone(), merged);
                    }
                }
                _ => {
                    out.precise_index_callables.remove(&root);
                }
            }
        }
    }
    out
}

fn merge_py_env_paths(base: &PyEnv, paths: &[PyEnv]) -> PyEnv {
    let mut iter = paths.iter();
    let Some(first) = iter.next() else {
        return base.clone();
    };
    let mut merged = first.clone();
    for path in iter {
        merged = merge_py_envs(base, &merged, Some(path));
    }
    merged
}

fn canonical_container_path(env: &PyEnv, receiver_text: &str) -> Option<String> {
    let receiver = receiver_text.trim();
    if receiver.is_empty() {
        return None;
    }
    if is_simple_ident(receiver) {
        return Some(env.local_object_aliases.get(receiver).cloned().unwrap_or_else(|| receiver.to_string()));
    }
    if let Some((base, field)) = split_last_top_level_dot(receiver) {
        let base_path = canonical_container_path(env, &base)?;
        return Some(format!("{base_path}.{field}"));
    }
    None
}

fn clear_precise_container_slots(env: &mut PyEnv, receiver_text: &str) {
    let receiver = receiver_text.trim();
    if receiver.is_empty() {
        return;
    }
    env.precise_index_types.remove(receiver);
    env.precise_index_callables.remove(receiver);
    if let Some(canonical) = canonical_container_path(env, receiver) {
        if canonical == receiver || receiver.contains('.') {
            env.precise_index_types.remove(&canonical);
            env.precise_index_callables.remove(&canonical);
        }
    }
}

fn update_precise_container_slot_type(env: &mut PyEnv, receiver_text: &str, slot_key: &str, ty: &str) {
    if ty.trim().is_empty() {
        return;
    }
    let Some(base) = canonical_container_path(env, receiver_text) else {
        return;
    };
    let merged = merge_container_type(
        env.precise_index_types
            .get(&base)
            .and_then(|slots| slots.get(slot_key))
            .map(|value| value.as_str()),
        ty,
    );
    env.precise_index_types
        .entry(base)
        .or_default()
        .insert(slot_key.to_string(), merged);
}

fn update_precise_container_slot_callable(env: &mut PyEnv, receiver_text: &str, slot_key: &str, callable: Option<&str>) {
    let Some(base) = canonical_container_path(env, receiver_text) else {
        return;
    };
    let slots = env.precise_index_callables.entry(base.clone()).or_default();
    if let Some(callable) = callable.filter(|value| !value.trim().is_empty()) {
        slots.insert(slot_key.to_string(), callable.to_string());
    } else {
        slots.remove(slot_key);
        if slots.is_empty() {
            env.precise_index_callables.remove(&base);
        }
    }
}

fn precise_container_slot_type(env: &PyEnv, receiver_text: &str, slot_key: &str) -> Option<String> {
    let base = canonical_container_path(env, receiver_text)?;
    env.precise_index_types
        .get(&base)
        .and_then(|slots| slots.get(slot_key))
        .cloned()
}

fn precise_container_slot_callable(env: &PyEnv, receiver_text: &str, slot_key: &str) -> Option<String> {
    let base = canonical_container_path(env, receiver_text)?;
    env.precise_index_callables
        .get(&base)
        .and_then(|slots| slots.get(slot_key))
        .cloned()
}

fn next_precise_list_slot(env: &PyEnv, receiver_text: &str) -> usize {
    let Some(base) = canonical_container_path(env, receiver_text) else {
        return 0;
    };
    let mut next = 0usize;
    if let Some(slots) = env.precise_index_types.get(&base) {
        for key in slots.keys() {
            if let Ok(value) = key.parse::<usize>() {
                next = next.max(value.saturating_add(1));
            }
        }
    }
    if let Some(slots) = env.precise_index_callables.get(&base) {
        for key in slots.keys() {
            if let Ok(value) = key.parse::<usize>() {
                next = next.max(value.saturating_add(1));
            }
        }
    }
    next
}

fn last_precise_list_slot(env: &PyEnv, receiver_text: &str) -> Option<String> {
    let base = canonical_container_path(env, receiver_text)?;
    let mut best: Option<usize> = None;
    if let Some(slots) = env.precise_index_types.get(&base) {
        for key in slots.keys() {
            if let Ok(value) = key.parse::<usize>() {
                best = Some(best.map(|current| current.max(value)).unwrap_or(value));
            }
        }
    }
    if let Some(slots) = env.precise_index_callables.get(&base) {
        for key in slots.keys() {
            if let Ok(value) = key.parse::<usize>() {
                best = Some(best.map(|current| current.max(value)).unwrap_or(value));
            }
        }
    }
    best.map(|value| value.to_string())
}

fn collect_precise_container_slots_from_expr(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Vec<(String, Option<String>, Option<String>)> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        return split_top_level_commas(&trimmed[1..trimmed.len().saturating_sub(1)])
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .enumerate()
            .map(|(idx, item)| {
                let ty = infer_simple_python_type(&item, imports, env, known_classes);
                let callable = infer_project_callable_value_type(&item, imports, env, known_classes);
                (idx.to_string(), ty, callable)
            })
            .collect();
    }

    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        let items = split_top_level_commas(&trimmed[1..trimmed.len().saturating_sub(1)])
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .collect::<Vec<_>>();
        if items.len() >= 2 {
            return items
                .into_iter()
                .enumerate()
                .map(|(idx, item)| {
                    let ty = infer_simple_python_type(&item, imports, env, known_classes);
                    let callable = infer_project_callable_value_type(&item, imports, env, known_classes);
                    (idx.to_string(), ty, callable)
                })
                .collect();
        }
    }

    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.contains(':') {
        let mut out = Vec::new();
        for entry in split_top_level_commas(&trimmed[1..trimmed.len().saturating_sub(1)])
            .into_iter()
            .filter(|item| !item.trim().is_empty())
        {
            if let Some((key_text, value_text)) = split_once_top_level(&entry, ':') {
                if let Some(slot_key) = parse_static_index_slot_key(&key_text) {
                    let ty = infer_simple_python_type(&value_text, imports, env, known_classes);
                    let callable = infer_project_callable_value_type(&value_text, imports, env, known_classes);
                    out.push((slot_key, ty, callable));
                }
            }
        }
        return out;
    }

    if let Some(base) = canonical_container_path(env, trimmed) {
        let mut out = Vec::new();
        let mut keys = Vec::new();
        if let Some(slots) = env.precise_index_types.get(&base) {
            keys.extend(slots.keys().cloned());
        }
        if let Some(slots) = env.precise_index_callables.get(&base) {
            for key in slots.keys() {
                if !keys.iter().any(|existing| existing == key) {
                    keys.push(key.clone());
                }
            }
        }
        keys.sort();
        for key in keys {
            out.push((
                key.clone(),
                env.precise_index_types.get(&base).and_then(|slots| slots.get(&key)).cloned(),
                env.precise_index_callables.get(&base).and_then(|slots| slots.get(&key)).cloned(),
            ));
        }
        return out;
    }

    Vec::new()
}

fn populate_precise_container_slots_from_expr(
    env: &mut PyEnv,
    receiver_text: &str,
    text: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
) {
    clear_precise_container_slots(env, receiver_text);
    for (slot_key, ty, callable) in collect_precise_container_slots_from_expr(text, imports, env, known_classes) {
        if let Some(ty) = ty.as_deref() {
            update_precise_container_slot_type(env, receiver_text, &slot_key, ty);
        }
        update_precise_container_slot_callable(env, receiver_text, &slot_key, callable.as_deref());
    }
}

fn merge_container_type(existing: Option<&str>, incoming: &str) -> String {
    let incoming = incoming.trim();
    if incoming.is_empty() {
        return existing.unwrap_or("unknown").to_string();
    }
    let Some(current) = existing.map(|value| value.trim()).filter(|value| !value.is_empty()) else {
        return incoming.to_string();
    };
    if current == incoming {
        return current.to_string();
    }

    fn parse_unary_container<'a>(ty: &'a str, prefix: &str) -> Option<&'a str> {
        ty.strip_prefix(prefix).and_then(|rest| rest.strip_suffix('>'))
    }

    fn merge_atoms(left: &str, right: &str) -> String {
        let mut parts = left
            .split('|')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(|part| part.to_string())
            .collect::<Vec<_>>();
        for part in right.split('|').map(|part| part.trim()).filter(|part| !part.is_empty()) {
            if !parts.iter().any(|existing| existing == part) {
                parts.push(part.to_string());
            }
        }
        if parts.is_empty() {
            "unknown".to_string()
        } else if parts.len() == 1 {
            parts.remove(0)
        } else {
            parts.join("|")
        }
    }

    if let (Some(cur_inner), Some(new_inner)) = (
        parse_unary_container(current, "list<"),
        parse_unary_container(incoming, "list<"),
    ) {
        return format!("list<{}>", merge_atoms(cur_inner, new_inner));
    }
    if let (Some(cur_inner), Some(new_inner)) = (
        parse_unary_container(current, "set<"),
        parse_unary_container(incoming, "set<"),
    ) {
        return format!("set<{}>", merge_atoms(cur_inner, new_inner));
    }
    if let (Some(cur_inner), Some(new_inner)) = (
        parse_unary_container(current, "generator<"),
        parse_unary_container(incoming, "generator<"),
    ) {
        return format!("generator<{}>", merge_atoms(cur_inner, new_inner));
    }
    if let (Some(cur_inner), Some(new_inner)) = (
        current.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')),
        incoming.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')),
    ) {
        if let (Some((cur_key, cur_value)), Some((new_key, new_value))) = (
            split_once_top_level(cur_inner, ','),
            split_once_top_level(new_inner, ','),
        ) {
            return format!(
                "dict<{},{}>",
                merge_atoms(cur_key.trim(), new_key.trim()),
                merge_atoms(cur_value.trim(), new_value.trim())
            );
        }
    }
    merge_atoms(current, incoming)
}

fn update_container_receiver_type(
    env: &mut PyEnv,
    receiver_text: &str,
    ty: &str,
) {
    let receiver = receiver_text.trim();
    if receiver.is_empty() || ty.trim().is_empty() {
        return;
    }
    if is_simple_ident(receiver) {
        let merged = merge_container_type(env.types.get(receiver).map(|value| value.as_str()), ty);
        env.types.insert(receiver.to_string(), merged);
        return;
    }
    if let Some((base, field)) = split_last_top_level_dot(receiver) {
        if env.self_name.as_deref() == Some(base.as_str()) {
            let merged = merge_container_type(env.field_types.get(&field).map(|value| value.as_str()), ty);
            env.field_types.insert(field.clone(), merged.clone());
            if let Some(current_class) = env.current_class.clone() {
                env.class_field_index.entry(current_class).or_default().insert(field.clone(), merged.clone());
            }
            update_local_object_field_type(env, &base, &field, &merged);
        } else if is_simple_ident(&base) {
            let existing = env
                .local_field_types
                .get(&base)
                .and_then(|fields| fields.get(&field))
                .map(|value| value.as_str());
            let merged = merge_container_type(existing, ty);
            update_local_object_field_type(env, &base, &field, &merged);
        }
    }
}

fn apply_container_method_type_effects(
    line: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let Some((callee_text, arg_text)) = parse_call_parts(line.trim()) else {
        return;
    };
    let Some((receiver_text, method)) = split_last_top_level_dot(&callee_text) else {
        return;
    };
    let args = split_python_call_args(&arg_text);
    let receiver_existing = resolve_dotted_type(&receiver_text, imports, env, known_classes);
    match method.as_str() {
        "append" => {
            let Some(arg_text) = args.get(0) else {
                return;
            };
            let Some(arg_ty) = infer_simple_python_type(arg_text, imports, env, known_classes) else {
                return;
            };
            update_container_receiver_type(env, &receiver_text, &format!("list<{arg_ty}>"));
            let slot_key = next_precise_list_slot(env, &receiver_text).to_string();
            update_precise_container_slot_type(env, &receiver_text, &slot_key, &arg_ty);
            let callable = infer_project_callable_value_type(arg_text, imports, env, known_classes);
            update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
        }
        "insert" => {
            let Some(arg_text) = args.get(1) else {
                return;
            };
            let Some(arg_ty) = infer_simple_python_type(arg_text, imports, env, known_classes) else {
                return;
            };
            update_container_receiver_type(env, &receiver_text, &format!("list<{arg_ty}>"));
            if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                update_precise_container_slot_type(env, &receiver_text, &slot_key, &arg_ty);
                let callable = infer_project_callable_value_type(arg_text, imports, env, known_classes);
                update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
            }
        }
        "extend" => {
            let Some(arg_text) = args.get(0) else {
                return;
            };
            let Some(arg_ty) = infer_simple_python_type(arg_text, imports, env, known_classes) else {
                return;
            };
            if let Some(inner) = arg_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                update_container_receiver_type(env, &receiver_text, &format!("list<{}>", inner.trim()));
                let base = next_precise_list_slot(env, &receiver_text);
                let mut slots = collect_precise_container_slots_from_expr(arg_text, imports, env, known_classes);
                slots.sort_by_key(|(key, _, _)| key.parse::<usize>().unwrap_or(usize::MAX));
                for (offset, (_, ty, callable)) in slots.into_iter().enumerate() {
                    let slot_key = (base + offset).to_string();
                    if let Some(ty) = ty.as_deref() {
                        update_precise_container_slot_type(env, &receiver_text, &slot_key, ty);
                    }
                    update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
                }
            } else if let Some(inner) = arg_ty.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
                update_container_receiver_type(env, &receiver_text, &format!("set<{}>", inner.trim()));
            } else if let Some(inner) = arg_ty.strip_prefix("generator<").and_then(|rest| rest.strip_suffix('>')) {
                update_container_receiver_type(env, &receiver_text, &format!("list<{}>", inner.trim()));
            }
        }
        "update" => {
            let Some(arg_text) = args.get(0) else {
                return;
            };
            let Some(arg_ty) = infer_simple_python_type(arg_text, imports, env, known_classes) else {
                return;
            };
            if arg_ty.starts_with("dict<") {
                update_container_receiver_type(env, &receiver_text, &arg_ty);
                for (slot_key, ty, callable) in collect_precise_container_slots_from_expr(arg_text, imports, env, known_classes) {
                    if let Some(ty) = ty.as_deref() {
                        update_precise_container_slot_type(env, &receiver_text, &slot_key, ty);
                    }
                    update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
                }
            } else if let Some(inner) = arg_ty.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
                update_container_receiver_type(env, &receiver_text, &format!("set<{}>", inner.trim()));
            }
        }
        "setdefault" => {
            let key_ty = args
                .get(0)
                .and_then(|arg| infer_simple_python_type(arg, imports, env, known_classes))
                .unwrap_or_else(|| "unknown".to_string());
            let value_ty = args
                .get(1)
                .and_then(|arg| infer_simple_python_type(arg, imports, env, known_classes))
                .unwrap_or_else(|| receiver_existing
                    .as_deref()
                    .and_then(|ty| ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')))
                    .and_then(|inner| split_once_top_level(inner, ',').map(|(_, value)| value.trim().to_string()))
                    .unwrap_or_else(|| "unknown".to_string()));
            update_container_receiver_type(env, &receiver_text, &format!("dict<{},{}>", key_ty.trim(), value_ty.trim()));
            if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                if precise_container_slot_type(env, &receiver_text, &slot_key).is_none() {
                    update_precise_container_slot_type(env, &receiver_text, &slot_key, &value_ty);
                    let callable = args
                        .get(1)
                        .and_then(|arg| infer_project_callable_value_type(arg, imports, env, known_classes));
                    update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
                }
            }
        }
        _ => {}
    }
}


fn parse_simple_stmt(
    builder: &mut ModuleBuilder,
    line: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    line_no: u32,
) -> Vec<Stmt> {
    let span = span_from_line_range(builder.file_id(), line_no, line_no);
    let mut out = Vec::new();

    if let Some(rest) = line.strip_prefix("return ") {
        out.push(Stmt::Return {
            id: builder.alloc_stmt_id(),
            value: Some(parse_expr(builder, rest, imports, known_classes, env, line_no)),
            span,
        });
        return out;
    }
    if line == "return" {
        out.push(Stmt::Return {
            id: builder.alloc_stmt_id(),
            value: None,
            span,
        });
        return out;
    }
    if let Some(rest) = line.strip_prefix("raise ") {
        out.push(Stmt::Throw {
            id: builder.alloc_stmt_id(),
            value: Some(parse_expr(builder, rest, imports, known_classes, env, line_no)),
            span,
        });
        return out;
    }
    if line == "raise" {
        out.push(Stmt::Throw {
            id: builder.alloc_stmt_id(),
            value: None,
            span,
        });
        return out;
    }
    if line == "pass" || line == "break" || line == "continue" {
        return out;
    }
    if let Some(names) = parse_python_name_declaration(line, "global ") {
        for name in names {
            seed_declared_global_name(Some(builder), env, &name);
        }
        return out;
    }
    if let Some(names) = parse_python_name_declaration(line, "nonlocal ") {
        for name in names {
            if let Some(symbol) = env.capturable_vars.get(&name).copied() {
                env.vars.insert(name.clone(), symbol);
            } else {
                let created = ensure_known_symbol(builder, &mut env.vars, &name, SymbolKind::Local);
                env.capturable_vars.insert(name.clone(), created);
            }
        }
        return out;
    }
    if let Some(rest) = line.strip_prefix("yield from ") {
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, rest, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }
    if let Some(rest) = line.strip_prefix("yield ") {
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, rest, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }
    if line == "yield" {
        return out;
    }
    if let Some(rest) = line.strip_prefix("assert ") {
        apply_runtime_condition_refinements(rest, true, imports, known_classes, env);
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, rest, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }

    if let Some(lines) = parse_static_exec_body(line) {
        for exec_line in lines {
            out.extend(parse_simple_stmt(builder, &exec_line, imports, known_classes, env, line_no));
        }
        return out;
    }

    if let Some(entries) = parse_static_namespace_update_call(line) {
        for (target, value_text) in entries {
            apply_python_env_assignment_effects(&target, &value_text, imports, env, known_classes);
        }
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, line, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }

    if let Some(rest) = line.strip_prefix("del ") {
        for raw_target in split_top_level_commas(rest).into_iter().filter(|part| !part.trim().is_empty()) {
            let target_buf = synthetic_static_namespace_access_text(raw_target.trim());
            let target = target_buf.as_deref().unwrap_or_else(|| raw_target.trim());
            if let Some((base_text, field)) = split_last_top_level_dot(target) {
                clear_python_env_target_effects(target, env);
                if let Some(base_ty) = resolve_dotted_type(&base_text, imports, env, known_classes) {
                    if env.project_index.class_has_property_deleter(&base_ty, &field) {
                        if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, &field) {
                            let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                            out.push(Stmt::Expr {
                                id: builder.alloc_stmt_id(),
                                expr: with_line_span(new_call(builder, &method_path, Some(receiver), Vec::new()), builder.file_id(), line_no),
                                span,
                            });
                            continue;
                        }
                    }
                }
                out.push(Stmt::Expr {
                    id: builder.alloc_stmt_id(),
                    expr: parse_expr(builder, target, imports, known_classes, env, line_no),
                    span,
                });
                continue;
            }
            if let Some((base_text, index_text)) = split_last_top_level_index(target) {
                if let Some(base_ty) = resolve_dotted_type(&base_text, imports, env, known_classes) {
                    if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, "__delitem__") {
                        let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                        let index_expr = parse_expr(builder, &index_text, imports, known_classes, env, line_no);
                        out.push(Stmt::Expr {
                            id: builder.alloc_stmt_id(),
                            expr: with_line_span(new_call(builder, &method_path, Some(receiver), vec![index_expr]), builder.file_id(), line_no),
                            span,
                        });
                    } else {
                        out.push(Stmt::Expr {
                            id: builder.alloc_stmt_id(),
                            expr: parse_expr(builder, target, imports, known_classes, env, line_no),
                            span,
                        });
                    }
                }
                clear_python_env_target_effects(target, env);
                continue;
            }
            clear_python_env_target_effects(target, env);
        }
        return out;
    }

    if parse_static_namespace_method_call(line).is_some() {
        apply_python_expr_side_effects(line, imports, env, known_classes);
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, line, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }

    if let Some((base_text, field, value_text)) = parse_builtin_setattr_call(line) {
        let lhs = LValue::Field {
            base: Box::new(parse_expr(builder, &base_text, imports, known_classes, env, line_no)),
            field: field.clone(),
        };
        let rhs = parse_expr(builder, &value_text, imports, known_classes, env, line_no);
        let inferred_ty = infer_simple_python_type(&value_text, imports, env, known_classes);
        apply_python_env_assignment_effects(&synthetic_attr_expr_text(&base_text, &field), &value_text, imports, env, known_classes);
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            let ty = inferred_ty.as_ref().map(|ty| builder.ensure_type(ty));
            env.discovered_fields.entry(field.clone()).or_insert(Field {
                name: field.clone(),
                symbol: Some(builder.add_symbol(&field, SymbolKind::Field)),
                ty,
                span,
            });
        }
        if let Some(base_ty) = resolve_dotted_type(&base_text, imports, env, known_classes) {
            if env.project_index.class_has_property_setter(&base_ty, &field) {
                if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, &field) {
                    let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                    let value_expr = parse_expr(builder, &value_text, imports, known_classes, env, line_no);
                    out.push(Stmt::Expr {
                        id: builder.alloc_stmt_id(),
                        expr: with_line_span(new_call(builder, &method_path, Some(receiver), vec![value_expr]), builder.file_id(), line_no),
                        span,
                    });
                    return out;
                }
            }
        }
        out.push(Stmt::Assign {
            id: builder.alloc_stmt_id(),
            lhs,
            rhs,
            span,
        });
        return out;
    }

    if let Some((base_text, field)) = parse_builtin_delattr_call(line) {
        let target_text = synthetic_attr_expr_text(&base_text, &field);
        clear_precise_container_slots(env, &target_text);
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            env.field_types.remove(&field);
        } else if is_simple_ident(&base_text) {
            clear_local_object_field_type(env, &base_text, &field);
        }
        if let Some(base_ty) = resolve_dotted_type(&base_text, imports, env, known_classes) {
            if env.project_index.class_has_property_deleter(&base_ty, &field) {
                if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, &field) {
                    let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                    out.push(Stmt::Expr {
                        id: builder.alloc_stmt_id(),
                        expr: with_line_span(new_call(builder, &method_path, Some(receiver), Vec::new()), builder.file_id(), line_no),
                        span,
                    });
                    return out;
                }
            }
        }
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, line, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }

    if let Some((left, right)) = split_once_top_level(line, '=') {
        if !left.contains("==") && !left.contains("!=") && !left.contains(">=") && !left.contains("<=") {
            let destructured = parse_destructuring_targets(&left);
            if !destructured.is_empty() {
                let values_inner = right.trim()
                    .strip_prefix('(').and_then(|rest| rest.strip_suffix(')'))
                    .or_else(|| right.trim().strip_prefix('[').and_then(|rest| rest.strip_suffix(']')));
                if let Some(inner) = values_inner {
                    let values = split_top_level_commas(inner)
                        .into_iter()
                        .filter(|item| !item.trim().is_empty())
                        .collect::<Vec<_>>();
                    let inferred = infer_simple_destructured_types(&right, imports, env, known_classes);
                    if values.len() == destructured.len() && inferred.len() == destructured.len() {
                        for ((target, value_text), inferred_ty) in destructured.into_iter().zip(values.into_iter()).zip(inferred.into_iter()) {
                            let symbol = ensure_known_symbol(builder, &mut env.vars, &target, SymbolKind::Local);
                            let value = parse_expr(builder, &value_text, imports, known_classes, env, line_no);
                            if let Some(ty) = inferred_ty.clone() {
                                env.types.insert(target.clone(), ty.clone());
                            }
                            if let Some(path) = infer_project_callable_value_type(&value_text, imports, env, known_classes) {
                                env.callable_aliases.insert(target.clone(), path);
                            } else {
                                env.callable_aliases.remove(&target);
                            }
                            env.local_object_aliases.remove(&target);
                            env.local_field_types.remove(&target);
                            out.push(Stmt::Let {
                                id: builder.alloc_stmt_id(),
                                symbol,
                                ty: inferred_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                                init: Some(value),
                                span,
                            });
                        }
                        return out;
                    }
                }
                let inferred = infer_simple_destructured_types(&right, imports, env, known_classes);
                let temp_symbol = new_unpack_symbol(builder, "unpack", line_no, out.len());
                let temp_ty = infer_simple_python_type(&right, imports, env, known_classes);
                out.push(Stmt::Let {
                    id: builder.alloc_stmt_id(),
                    symbol: temp_symbol,
                    ty: temp_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                    init: Some(parse_expr(builder, &right, imports, known_classes, env, line_no)),
                    span,
                });
                extend_destructuring_bindings(builder, &mut out, &destructured, temp_symbol, &inferred, env, line_no);
                return out;
            }

            let normalized_left = synthetic_static_namespace_access_text(left.trim()).unwrap_or_else(|| left.trim().to_string());
            let lhs = parse_lvalue(builder, &normalized_left, imports, known_classes, env, line_no);
            let rhs = parse_expr(builder, &right, imports, known_classes, env, line_no);
            let inferred_ty = infer_simple_python_type(&right, imports, env, known_classes);
            match &lhs {
                LValue::Var(symbol) => {
                    let name = normalized_left.trim();
                    clear_precise_container_slots(env, name);
                    if let Some(path) = infer_project_callable_value_type(&right, imports, env, known_classes) {
                        env.callable_aliases.insert(name.to_string(), path);
                    } else {
                        env.callable_aliases.remove(name);
                    }
                    if is_simple_ident(right.trim()) {
                        propagate_local_object_alias(env, name, &right);
                    } else {
                        env.local_object_aliases.remove(name);
                        env.local_field_types.remove(name);
                    }
                    if let Some(ty) = inferred_ty.clone() {
                        env.types.insert(name.to_string(), ty);
                    } else {
                        env.types.remove(name);
                    }
                    populate_precise_container_slots_from_expr(env, name, &right, imports, known_classes);
                    apply_python_expr_side_effects(&right, imports, env, known_classes);
                    if !env.vars.contains_key(name) {
                        env.vars.insert(name.to_string(), *symbol);
                        out.push(Stmt::Let {
                            id: builder.alloc_stmt_id(),
                            symbol: *symbol,
                            ty: inferred_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                            init: Some(rhs),
                            span,
                        });
                    } else {
                        out.push(Stmt::Assign {
                            id: builder.alloc_stmt_id(),
                            lhs,
                            rhs,
                            span,
                        });
                    }
                }
                LValue::Field { base, field } => {
                    let target_text = normalized_left.trim();
                    clear_precise_container_slots(env, target_text);
                    if base_is_self(base, env) {
                        let ty = inferred_ty.as_ref().map(|ty| builder.ensure_type(ty));
                        if let Some(inferred) = inferred_ty.clone() {
                            env.field_types.insert(field.clone(), inferred.clone());
                            if let Some(current_class) = env.current_class.clone() {
                                env.class_field_index.entry(current_class).or_default().insert(field.clone(), inferred);
                            }
                        } else {
                            env.field_types.remove(field);
                        }
                        env.discovered_fields.entry(field.clone()).or_insert(Field {
                            name: field.clone(),
                            symbol: Some(builder.add_symbol(field, SymbolKind::Field)),
                            ty,
                            span,
                        });
                    } else if let Some((base_name, _)) = split_last_top_level_dot(normalized_left.trim()) {
                        if is_simple_ident(&base_name) {
                            if let Some(inferred) = inferred_ty.clone() {
                                update_local_object_field_type(env, &base_name, field, &inferred);
                            }
                        }
                    }
                    populate_precise_container_slots_from_expr(env, target_text, &right, imports, known_classes);
                    apply_python_expr_side_effects(&right, imports, env, known_classes);
                    if let Some((base_text, _)) = split_last_top_level_dot(normalized_left.trim()) {
                        if let Some(base_ty) = resolve_dotted_type(&base_text, imports, env, known_classes) {
                            if env.project_index.class_has_property_setter(&base_ty, field) {
                                if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, field) {
                                    let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                                    let value_expr = parse_expr(builder, &right, imports, known_classes, env, line_no);
                                    out.push(Stmt::Expr {
                                        id: builder.alloc_stmt_id(),
                                        expr: with_line_span(new_call(builder, &method_path, Some(receiver), vec![value_expr]), builder.file_id(), line_no),
                                        span,
                                    });
                                    return out;
                                }
                            }
                        }
                    }
                    out.push(Stmt::Assign {
                        id: builder.alloc_stmt_id(),
                        lhs,
                        rhs,
                        span,
                    });
                }
                LValue::Index { .. } => {
                    if let Some((base_text, index_text)) = split_last_top_level_index(normalized_left.trim()) {
                        if let Some(base_ty) = resolve_dotted_type(&base_text, imports, env, known_classes) {
                            if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, "__setitem__") {
                                let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                                let index_expr = parse_expr(builder, &index_text, imports, known_classes, env, line_no);
                                let value_expr = parse_expr(builder, &right, imports, known_classes, env, line_no);
                                out.push(Stmt::Expr {
                                    id: builder.alloc_stmt_id(),
                                    expr: with_line_span(new_call(builder, &method_path, Some(receiver), vec![index_expr, value_expr]), builder.file_id(), line_no),
                                    span,
                                });
                                return out;
                            }
                        }
                        if let Some(slot_key) = parse_static_index_slot_key(&index_text) {
                            if let Some(inferred) = inferred_ty.clone() {
                                update_precise_container_slot_type(env, &base_text, &slot_key, &inferred);
                                if slot_key.parse::<i64>().is_ok() {
                                    update_container_receiver_type(env, &base_text, &format!("list<{}>", inferred));
                                } else {
                                    update_container_receiver_type(env, &base_text, &format!("dict<str,{}>", inferred));
                                }
                            }
                            let callable = infer_project_callable_value_type(&right, imports, env, known_classes);
                            update_precise_container_slot_callable(env, &base_text, &slot_key, callable.as_deref());
                        }
                    }
                    apply_python_expr_side_effects(&right, imports, env, known_classes);
                    out.push(Stmt::Assign {
                        id: builder.alloc_stmt_id(),
                        lhs,
                        rhs,
                        span,
                    });
                }
            }
            return out;
        }
    }

    apply_container_method_type_effects(line, imports, env, known_classes);
    out.push(Stmt::Expr {
        id: builder.alloc_stmt_id(),
        expr: parse_expr(builder, line, imports, known_classes, env, line_no),
        span,
    });
    out
}

fn infer_simple_python_type(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = text.trim();
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return infer_simple_python_type(&inner, imports, env, known_classes);
    }
    if let Some(synthetic) = synthetic_static_namespace_access_text(trimmed) {
        return infer_simple_python_type(&synthetic, imports, env, known_classes);
    }
    if let Some((synthetic, _kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        if let Some(ty) = infer_simple_python_type(&synthetic, imports, env, known_classes) {
            return Some(ty);
        }
        if let Some(default_expr) = default_value {
            return infer_simple_python_type(&default_expr, imports, env, known_classes);
        }
    }
    if let Some(inner) = trimmed.strip_prefix("await ") {
        return infer_simple_python_type(inner, imports, env, known_classes);
    }
    if trimmed == "super()" {
        return current_super_type(env);
    }
    if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
        return Some(path);
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '[', ']') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_types_only(&mut comp_env, &target_text, item_ty.as_deref());
        let result_ty = infer_simple_python_type(&result_expr, imports, &comp_env, known_classes)
            .or_else(|| item_ty.clone())
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("list<{}>", result_ty));
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '{', '}') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_types_only(&mut comp_env, &target_text, item_ty.as_deref());
        if let Some((key_text, value_text)) = split_once_top_level(&result_expr, ':') {
            let key_ty = infer_simple_python_type(&key_text, imports, &comp_env, known_classes)
                .unwrap_or_else(|| "unknown".to_string());
            let value_ty = infer_simple_python_type(&value_text, imports, &comp_env, known_classes)
                .or_else(|| item_ty.clone())
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("dict<{},{}>", key_ty, value_ty));
        }
        let result_ty = infer_simple_python_type(&result_expr, imports, &comp_env, known_classes)
            .or_else(|| item_ty.clone())
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("set<{}>", result_ty));
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '(', ')') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_types_only(&mut comp_env, &target_text, item_ty.as_deref());
        let result_ty = infer_simple_python_type(&result_expr, imports, &comp_env, known_classes)
            .or_else(|| item_ty.clone())
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("generator<{}>", result_ty));
    }
    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner)
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .collect::<Vec<_>>();
        if items.len() >= 2 {
            let parts = items
                .into_iter()
                .map(|item| infer_simple_python_type(&item, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string()))
                .collect::<Vec<_>>();
            return Some(format!("tuple<{}>", parts.join("|")));
        }
    }
    if is_string_literal(trimmed) {
        return Some("str".to_string());
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '[', ']') {
        let result_ty = infer_simple_python_type(&result_expr, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes).unwrap_or_else(|| result_ty.clone());
        return Some(format!("list<{}>", if result_ty == "unknown" { item_ty } else { result_ty }));
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '{', '}') {
        if let Some((key_text, value_text)) = split_once_top_level(&result_expr, ':') {
            let key_ty = infer_simple_python_type(&key_text, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
            let value_ty = infer_simple_python_type(&value_text, imports, env, known_classes).unwrap_or_else(|| infer_iterable_item_type(&iterable_text, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string()));
            return Some(format!("dict<{},{}>", key_ty, value_ty));
        }
        let result_ty = infer_simple_python_type(&result_expr, imports, env, known_classes)
            .or_else(|| infer_iterable_item_type(&iterable_text, imports, env, known_classes))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("set<{}>", result_ty));
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '(', ')') {
        let result_ty = infer_simple_python_type(&result_expr, imports, env, known_classes)
            .or_else(|| infer_iterable_item_type(&iterable_text, imports, env, known_classes))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("generator<{}>", result_ty));
    }
    if is_int_literal(trimmed) {
        return Some("int".to_string());
    }
    if trimmed == "True" || trimmed == "False" {
        return Some("bool".to_string());
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let first = split_top_level_commas(inner).into_iter().find(|item| !item.trim().is_empty());
        if let Some(item) = first.and_then(|item| infer_simple_python_type(&item, imports, env, known_classes)) {
            return Some(format!("list<{}>", item));
        }
        return Some("list".to_string());
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.contains(':') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let first = split_top_level_commas(inner).into_iter().find(|item| !item.trim().is_empty());
        if let Some(entry) = first {
            if let Some((key, value)) = split_once_top_level(&entry, ':') {
                let key_ty = infer_simple_python_type(&key, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
                let value_ty = infer_simple_python_type(&value, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
                return Some(format!("dict<{},{}>", key_ty, value_ty));
            }
        }
        return Some("dict".to_string());
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let first = split_top_level_commas(inner).into_iter().find(|item| !item.trim().is_empty());
        if let Some(item) = first.and_then(|item| infer_simple_python_type(&item, imports, env, known_classes)) {
            return Some(format!("set<{}>", item));
        }
        return Some("set".to_string());
    }
    if let Some((base, index_expr)) = split_last_top_level_index(trimmed) {
        if let Some(slot_key) = parse_static_index_slot_key(&index_expr) {
            if let Some(slot_ty) = precise_container_slot_type(env, &base, &slot_key) {
                return Some(slot_ty);
            }
        }
        if let Some(base_ty) = resolve_dotted_type(&base, imports, env, known_classes) {
            if let Some(key) = parse_python_string_literal_content(&index_expr) {
                if let Some(field_ty) = env.project_index.typed_dict_key_type(&base_ty, &key) {
                    return Some(field_ty);
                }
            }
            if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                return Some(inner.to_string());
            }
            if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                if let Some((_, value)) = split_once_top_level(inner, ',') {
                    return Some(value.trim().to_string());
                }
            }
            if let Some(elems) = parse_tuple_type_elements(&base_ty) {
                if let Ok(idx) = index_expr.trim().parse::<usize>() {
                    if idx < elems.len() {
                        return Some(elems[idx].clone());
                    }
                }
            }
            if let Some(ret_ty) = env.project_index.method_return(&base_ty, "__getitem__", 1) {
                return Some(ret_ty);
            }
            if base_ty.ends_with("request.args") || base_ty.ends_with("request.form") || base_ty.ends_with("request.headers") || base_ty.ends_with("request.values") || base_ty.ends_with("request.GET") || base_ty.ends_with("request.POST") || base_ty.ends_with("request.query_params") || base_ty.ends_with("request.cookies") || base_ty.ends_with("request.json") {
                return Some("str".to_string());
            }
        }
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        let arg_types = args
            .iter()
            .map(|arg| infer_simple_python_type(arg, imports, env, known_classes))
            .collect::<Vec<_>>();
        if callee_text == "getattr" {
            if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
                return infer_simple_python_type(&synthetic_attr_expr_text(&base, &field), imports, env, known_classes)
                    .or_else(|| resolve_dotted_type(&synthetic_attr_expr_text(&base, &field), imports, env, known_classes));
            }
        }
        if matches!(callee_text.as_str(), "field" | "dataclasses.field" | "Field" | "pydantic.Field" | "sqlmodel.Field" | "attr.ib" | "attr.field" | "attrs.field") {
            let default_factory = args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                if name == "default_factory" || name == "factory" {
                    Some(value)
                } else {
                    None
                }
            });
            if let Some(factory) = default_factory {
                let factory = factory.trim();
                match factory {
                    "list" => return Some("list".to_string()),
                    "dict" => return Some("dict".to_string()),
                    "set" => return Some("set".to_string()),
                    "tuple" => return Some("tuple".to_string()),
                    _ => {}
                }
                if let Some(class_name) = resolve_known_class_name(factory, imports, env, known_classes) {
                    return Some(class_name);
                }
                if let Some(factory_ty) = resolve_dotted_type(factory, imports, env, known_classes) {
                    if env.project_index.class_exists(&factory_ty) {
                        return Some(factory_ty);
                    }
                }
            }
            if let Some(default_expr) = args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "default").then_some(value)
            }) {
                if default_expr.trim() != "None" {
                    if let Some(default_ty) = infer_simple_python_type(&default_expr, imports, env, known_classes) {
                        return Some(default_ty);
                    }
                }
            }
        }
        let resolved_callee = resolve_imported_name(&callee_text, imports, env);
        if matches!(callee_text.as_str(), "Factory" | "attr.Factory" | "attrs.Factory") {
            if let Some(first) = args.get(0) {
                if let Some(ret) = infer_simple_python_type(first, imports, env, known_classes) {
                    return Some(ret);
                }
                if let Some(class_name) = resolve_known_class_name(first, imports, env, known_classes) {
                    return Some(class_name);
                }
            }
        }
        if matches!(callee_text.as_str(), "TypeVar" | "typing.TypeVar") {
            if let Some(bound_expr) = args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "bound").then_some(value)
            }) {
                if let Some(bound_ty) = infer_simple_python_type(&bound_expr, imports, env, known_classes)
                    .or_else(|| resolve_dotted_type(&bound_expr, imports, env, known_classes))
                {
                    return Some(bound_ty);
                }
            }
            for arg in args.iter().skip(1) {
                if split_python_keyword_arg(arg).is_some() {
                    continue;
                }
                if let Some(ty) = infer_simple_python_type(arg, imports, env, known_classes)
                    .or_else(|| resolve_dotted_type(arg, imports, env, known_classes))
                {
                    return Some(ty);
                }
            }
        }
        if matches!(callee_text.as_str(), "NewType" | "typing.NewType") {
            if let Some(base_expr) = args.get(1) {
                if let Some(base_ty) = infer_simple_python_type(base_expr, imports, env, known_classes)
                    .or_else(|| resolve_dotted_type(base_expr, imports, env, known_classes))
                {
                    return Some(base_ty);
                }
            }
        }
        let is_dependency_wrapper = matches!(callee_text.as_str(), "Depends" | "Security" | "Query" | "Path" | "Header" | "Cookie" | "Body" | "Form" | "File")
            || matches!(resolved_callee.as_deref(), Some("fastapi.Depends" | "fastapi.Security" | "fastapi.params.Depends" | "fastapi.params.Security" | "fastapi.Query" | "fastapi.Path" | "fastapi.Header" | "fastapi.Cookie" | "fastapi.Body" | "fastapi.Form" | "fastapi.File" | "fastapi.params.Query" | "fastapi.params.Path" | "fastapi.params.Header" | "fastapi.params.Cookie" | "fastapi.params.Body" | "fastapi.params.Form" | "fastapi.params.File"));
        if is_dependency_wrapper {
            if let Some(first) = args.get(0) {
                if let Some(callable_path) = infer_project_callable_value_type(first, imports, env, known_classes) {
                    if let Some(ret) = project_callable_return_from_type(&env.project_index, &callable_path, 0) {
                        return Some(ret);
                    }
                    if let Some(ty) = env.project_index.module_value_type_by_path(&callable_path) {
                        return Some(ty);
                    }
                    return Some(callable_path);
                }
                if first.trim() != "..." && first.trim() != "None" {
                    if let Some(default_ty) = infer_simple_python_type(first, imports, env, known_classes)
                        .or_else(|| resolve_dotted_type(first, imports, env, known_classes))
                    {
                        return Some(default_ty);
                    }
                }
            }
        }
        if matches!(callee_text.as_str(), "next" | "anext") {
            if let Some(first) = args.get(0) {
                return infer_iterable_item_type(first, imports, env, known_classes);
            }
        }
        if matches!(callee_text.as_str(), "iter" | "aiter" | "reversed") {
            if let Some(first) = args.get(0) {
                if let Some(base_ty) = infer_simple_python_type(first, imports, env, known_classes) {
                    let method = if callee_text == "aiter" { "__aiter__" } else { "__iter__" };
                    if let Some(ret) = env.project_index.method_return(&base_ty, method, 0) {
                        return Some(ret);
                    }
                }
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("generator<{}>", item));
            }
        }
        if matches!(callee_text.as_str(), "enumerate" | "zip" | "map" | "filter") {
            let item = infer_iterable_item_type(trimmed, imports, env, known_classes)
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("generator<{}>", item));
        }
        if callee_text == "sorted" {
            if let Some(first) = args.get(0) {
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .or_else(|| infer_simple_python_type(first, imports, env, known_classes))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{}>", item));
            }
            return Some("list".to_string());
        }
        if callee_text == "any" || callee_text == "all" {
            return Some("bool".to_string());
        }
        if let Some(module_path) = static_python_imported_module_path(trimmed, &env.current_module, imports, &env.project_index, Some(env)) {
            return Some(module_path);
        }
        if callee_text == "super" && args.is_empty() {
            return current_super_type(env);
        }
        if callee_text == "hasattr" || callee_text == "isinstance" || callee_text == "issubclass" || callee_text == "callable" {
            return Some("bool".to_string());
        }
        if (callee_text == "cast" || callee_text.ends_with(".cast")) && args.len() >= 2 {
            if let Some(ty) = normalize_runtime_type_name(args[0].trim(), imports, env, known_classes) {
                return Some(ty);
            }
        }
        if callee_text == "list" {
            if let Some(first) = args.get(0) {
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .or_else(|| infer_simple_python_type(first, imports, env, known_classes))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{}>", item));
            }
            return Some("list".to_string());
        }
        if callee_text == "set" {
            if let Some(first) = args.get(0) {
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .or_else(|| infer_simple_python_type(first, imports, env, known_classes))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("set<{}>", item));
            }
            return Some("set".to_string());
        }
        if callee_text == "tuple" {
            if let Some(first) = args.get(0) {
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .or_else(|| infer_simple_python_type(first, imports, env, known_classes))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("tuple<{}>", item));
            }
            return Some("tuple".to_string());
        }
        if callee_text == "dict" {
            return Some("dict".to_string());
        }
        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            let receiver_ty = resolve_dotted_type(&prefix, imports, env, known_classes);
            if method == "cursor" {
                if let Some(base_ty) = receiver_ty.clone() {
                    return Some(format!("{base_ty}.cursor"));
                }
            }
            if let Some(base_ty) = receiver_ty.clone() {
                if let Some(ret) = env.project_index.method_return(&base_ty, &method, arg_types.len()) {
                    return Some(ret);
                }
                if env.project_index.module_exists(&base_ty) {
                    if let Some(member) = env.project_index.resolve_module_member(&base_ty, &method) {
                        if let Some(ret) = env.project_index.top_level_return(&member, arg_types.len()) {
                            return Some(ret);
                        }
                        if let Some(ty) = env.project_index.module_value_type_by_path(&member) {
                            return Some(ty);
                        }
                        return Some(member);
                    }
                }
                if method == "get" || method == "pop" || method == "setdefault" {
                    if base_ty.ends_with("request.args") || base_ty.ends_with("request.form") || base_ty.ends_with("request.headers") || base_ty.ends_with("request.values") || base_ty.ends_with("request.GET") || base_ty.ends_with("request.POST") || base_ty.ends_with("request.query_params") || base_ty.ends_with("request.cookies") || base_ty.ends_with("request.json") {
                        return Some("str".to_string());
                    }
                    if method == "get" || method == "setdefault" || (method == "pop" && !base_ty.starts_with("list<")) {
                        if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                            if let Some(slot_ty) = precise_container_slot_type(env, &prefix, &slot_key) {
                                return Some(slot_ty);
                            }
                        }
                    }
                    if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                        if let Some((_, value)) = split_once_top_level(inner, ',') {
                            return Some(value.trim().to_string());
                        }
                    }
                }
                if method == "pop" {
                    if args.is_empty() {
                        if let Some(slot_key) = last_precise_list_slot(env, &prefix) {
                            if let Some(slot_ty) = precise_container_slot_type(env, &prefix, &slot_key) {
                                return Some(slot_ty);
                            }
                        }
                    } else if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                        if let Some(slot_ty) = precise_container_slot_type(env, &prefix, &slot_key) {
                            return Some(slot_ty);
                        }
                    }
                    if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                        return Some(inner.to_string());
                    }
                }
                if method == "append" {
                    return Some(base_ty);
                }
                if method == "copy" {
                    return Some(base_ty);
                }
                if method == "read" || method == "readline" {
                    return Some("str".to_string());
                }
                if method == "cursor" {
                    return Some(format!("{base_ty}.cursor"));
                }
                if method == "dumps" && base_ty == "json" {
                    return Some("str".to_string());
                }
            }
            if method == "connect" {
                if let Some(base_ty) = receiver_ty {
                    return Some(format!("{base_ty}.connection"));
                }
            }
        }
        if let Some(callee_ty) = resolve_dotted_type(&callee_text, imports, env, known_classes) {
            if env.project_index.class_exists(&callee_ty) {
                return Some(callee_ty);
            }
        }
        if let Some(mapped) = env.callable_aliases.get(&callee_text).cloned() {
            if let Some(ret) = env.project_index.top_level_return(&mapped, arg_types.len()) {
                return Some(ret);
            }
            if let Some(ty) = env.project_index.module_value_type_by_path(&mapped) {
                return Some(ty);
            }
            return Some(mapped);
        }
        if let Some(mapped) = resolve_imported_name(&callee_text, imports, env) {
            if let Some(ret) = env.project_index.top_level_return(&mapped, arg_types.len()) {
                return Some(ret);
            }
            if let Some(ty) = env.project_index.module_value_type_by_path(&mapped) {
                return Some(ty);
            }
            return Some(mapped);
        }
        if let Some(class_name) = resolve_known_class_name(&callee_text, imports, env, known_classes) {
            return Some(class_name);
        }
        if let Some(class_name) = env.current_class.as_ref() {
            if !is_builtin_python_name(&callee_text) {
                if let Some(ret) = env.project_index.method_return(class_name, &callee_text, arg_types.len()) {
                    return Some(ret);
                }
                return Some(format!("{class_name}.{}#ret", callee_text));
            }
        }
        let current_function = format!("{}.{}", env.current_module, callee_text);
        if let Some(ret) = env.project_index.top_level_return(&current_function, arg_types.len()) {
            return Some(ret);
        }
        if callee_text == "str" {
            return Some("str".to_string());
        }
        if callee_text == "int" {
            return Some("int".to_string());
        }
        if callee_text == "bool" {
            return Some("bool".to_string());
        }
    }
    resolve_dotted_type(trimmed, imports, env, known_classes)
}

fn split_last_top_level_index(input: &str) -> Option<(String, String)> {
    let trimmed = input.trim();
    if !trimmed.ends_with(']') {
        return None;
    }
    let mut depth_paren = 0isize;
    let mut depth_brace = 0isize;
    let mut depth_bracket = 0isize;
    let mut in_string = false;
    let mut quote = '\0';
    for (idx, ch) in trimmed.char_indices().rev() {
        if in_string {
            if ch == quote {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' | '\'' => { in_string = true; quote = ch; }
            ']' => depth_bracket += 1,
            '[' => {
                depth_bracket -= 1;
                if depth_bracket == 0 {
                    let base = trimmed[..idx].trim();
                    let index = trimmed[idx + 1..trimmed.len() - 1].trim();
                    if !base.is_empty() && !index.is_empty() {
                        return Some((base.to_string(), index.to_string()));
                    }
                    return None;
                }
            }
            ')' => depth_paren += 1,
            '(' => depth_paren -= 1,
            '}' => depth_brace += 1,
            '{' => depth_brace -= 1,
            _ => {}
        }
        if depth_paren < 0 || depth_brace < 0 || depth_bracket < 0 {
            return None;
        }
    }
    None
}

fn split_once_top_level_str(input: &str, needle: &str, prefer_rightmost: bool) -> Option<(String, String)> {
    if needle.is_empty() {
        return None;
    }
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;
    let mut found = None;

    for (idx, ch) in input.char_indices() {
        if !in_string && paren == 0 && bracket == 0 && brace == 0 && input[idx..].starts_with(needle) {
            if !prefer_rightmost {
                let left = input[..idx].trim();
                let right = input[idx + needle.len()..].trim();
                return if left.is_empty() || right.is_empty() {
                    None
                } else {
                    Some((left.to_string(), right.to_string()))
                };
            }
            found = Some(idx);
        }
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
            }
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            _ => {}
        }
    }

    let idx = found?;
    let left = input[..idx].trim();
    let right = input[idx + needle.len()..].trim();
    if left.is_empty() || right.is_empty() {
        None
    } else {
        Some((left.to_string(), right.to_string()))
    }
}

fn parse_python_binary_expr(
    builder: &mut ModuleBuilder,
    text: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    line_no: u32,
) -> Option<Expr> {
    let trimmed = text.trim();
    if let Some(inner) = trimmed.strip_prefix("not ") {
        return Some(with_line_span(
            Expr::Unary {
                id: builder.alloc_expr_id(),
                op: UnaryOp::Not,
                expr: Box::new(parse_expr(builder, inner, imports, known_classes, env, line_no)),
                span: default_span(),
            },
            builder.file_id(),
            line_no,
        ));
    }
    for (needle, op) in [
        (" or ", BinaryOp::Or),
        (" and ", BinaryOp::And),
        ("==", BinaryOp::Eq),
        ("!=", BinaryOp::Ne),
        (">=", BinaryOp::Ge),
        ("<=", BinaryOp::Le),
        (" in ", BinaryOp::In),
        (">", BinaryOp::Gt),
        ("<", BinaryOp::Lt),
        (" + ", BinaryOp::Add),
        (" - ", BinaryOp::Sub),
        (" * ", BinaryOp::Mul),
        (" / ", BinaryOp::Div),
        (" % ", BinaryOp::Mod),
    ] {
        if let Some((lhs, rhs)) = split_once_top_level_str(trimmed, needle, true) {
            return Some(with_line_span(
                Expr::Binary {
                    id: builder.alloc_expr_id(),
                    op,
                    lhs: Box::new(parse_expr(builder, &lhs, imports, known_classes, env, line_no)),
                    rhs: Box::new(parse_expr(builder, &rhs, imports, known_classes, env, line_no)),
                    span: default_span(),
                },
                builder.file_id(),
                line_no,
            ));
        }
    }
    None
}

fn parse_lvalue(
    builder: &mut ModuleBuilder,
    text: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    line_no: u32,
) -> LValue {
    let trimmed = text.trim();
    if let Some((base, index)) = split_last_top_level_index(trimmed) {
        return LValue::Index {
            base: Box::new(parse_expr(builder, &base, imports, known_classes, env, line_no)),
            index: Box::new(parse_expr(builder, &index, imports, known_classes, env, line_no)),
        };
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        LValue::Field {
            base: Box::new(parse_expr(builder, &base, imports, known_classes, env, line_no)),
            field,
        }
    } else {
        let symbol = ensure_known_symbol(builder, &mut env.vars, trimmed, SymbolKind::Local);
        LValue::Var(symbol)
    }
}

fn parse_expr(
    builder: &mut ModuleBuilder,
    text: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    line_no: u32,
) -> Expr {
    let trimmed = text.trim();
    if let Some(synthetic) = synthetic_static_namespace_access_text(trimmed) {
        return parse_expr(builder, &synthetic, imports, known_classes, env, line_no);
    }
    if let Some((synthetic, _kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            let expr = parse_expr(builder, &synthetic, imports, known_classes, env, line_no);
            return with_line_span(wrap_expr_with_explicit_type(builder, expr, &path), builder.file_id(), line_no);
        }
        if resolve_dotted_type(&synthetic, imports, env, known_classes).is_some() {
            return parse_expr(builder, &synthetic, imports, known_classes, env, line_no);
        }
        if let Some(default_expr) = default_value {
            return parse_expr(builder, &default_expr, imports, known_classes, env, line_no);
        }
    }

    if let Some(inner) = trimmed.strip_prefix("await ") {
        return with_line_span(parse_expr(builder, inner, imports, known_classes, env, line_no), builder.file_id(), line_no);
    }
    if let Some(rest) = trimmed.strip_prefix("lambda") {
        let lambda_tail = rest.trim_start();
        let lambda_parts = split_once_top_level_str(lambda_tail, ":", false)
            .or_else(|| lambda_tail.strip_prefix(':').map(|body| (String::new(), body.trim().to_string())));
        if let Some((params_text, body_text)) = lambda_parts {
            let lambda_specs = parse_python_param_specs(&params_text);
            let mut lambda_env = env.clone();
            let outer_symbols = env
                .vars
                .iter()
                .map(|(name, symbol)| (*symbol, name.clone()))
                .collect::<HashMap<_, _>>();
            let mut params = Vec::new();
            let mut local_symbols = HashSet::new();
            for spec in lambda_specs {
                let symbol = builder.add_symbol(&spec.name, SymbolKind::Param);
                lambda_env.vars.insert(spec.name.clone(), symbol);
                local_symbols.insert(symbol);
                params.push(Param {
                    name: spec.name.clone(),
                    symbol,
                    ty: None,
                    kind: match spec.kind {
                        PyParamKind::Positional => ParamKind::Positional,
                        PyParamKind::VarArgs => ParamKind::VarArgs,
                        PyParamKind::KwArgs => ParamKind::KwArgs,
                    },
                    has_default: spec.has_default,
                    keyword_only: spec.keyword_only,
                    span: span_from_line_range(builder.file_id(), line_no, line_no),
                });
            }
            let body_expr = parse_expr(builder, &body_text, imports, known_classes, &mut lambda_env, line_no);
            let mut seen = HashSet::new();
            let mut free_symbols = Vec::new();
            collect_free_lambda_symbols(&body_expr, &local_symbols, &outer_symbols, &mut seen, &mut free_symbols);
            let mut capture_map = HashMap::new();
            let mut captures = Vec::new();
            for (source_symbol, name) in free_symbols {
                let capture_symbol = builder.add_symbol(&name, SymbolKind::Param);
                capture_map.insert(source_symbol, capture_symbol);
                captures.push(LambdaCapture {
                    name: name.clone(),
                    source_symbol,
                    symbol: capture_symbol,
                    ty: infer_lambda_capture_type(builder, env, &name),
                    span: span_from_line_range(builder.file_id(), line_no, line_no),
                });
            }
            let body_expr = rewrite_lambda_capture_symbols(body_expr, &capture_map);
            let return_stmt_id = builder.alloc_stmt_id();
            let return_span = span_from_line_range(builder.file_id(), line_no, line_no);
            let body_block = build_py_block(
                builder,
                vec![Stmt::Return {
                    id: return_stmt_id,
                    value: Some(body_expr),
                    span: return_span,
                }],
                line_no,
                line_no,
            );
            return with_line_span(
                Expr::Lambda {
                    id: builder.alloc_expr_id(),
                    params,
                    captures,
                    body: body_block,
                    span: default_span(),
                },
                builder.file_id(),
                line_no,
            );
        }
    }
    if let Some(expr) = parse_python_binary_expr(builder, trimmed, imports, known_classes, env, line_no) {
        return expr;
    }
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return parse_expr(builder, &inner, imports, known_classes, env, line_no);
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '[', ']') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_env(builder, &mut comp_env, &target_text, item_ty.as_deref(), line_no, 0);
        let iterable = parse_expr(builder, &iterable_text, imports, known_classes, env, line_no);
        let result = parse_expr(builder, &result_expr, imports, known_classes, &mut comp_env, line_no);
        return with_line_span(new_call(builder, "builtins.list_comp", None, vec![iterable, result]), builder.file_id(), line_no);
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '{', '}') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_env(builder, &mut comp_env, &target_text, item_ty.as_deref(), line_no, 1);
        let iterable = parse_expr(builder, &iterable_text, imports, known_classes, env, line_no);
        if let Some((key_text, value_text)) = split_once_top_level(&result_expr, ':') {
            let key = parse_expr(builder, &key_text, imports, known_classes, &mut comp_env, line_no);
            let value = parse_expr(builder, &value_text, imports, known_classes, &mut comp_env, line_no);
            return with_line_span(new_call(builder, "builtins.dict_comp", None, vec![iterable, key, value]), builder.file_id(), line_no);
        }
        let result = parse_expr(builder, &result_expr, imports, known_classes, &mut comp_env, line_no);
        return with_line_span(new_call(builder, "builtins.set_comp", None, vec![iterable, result]), builder.file_id(), line_no);
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '(', ')') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_env(builder, &mut comp_env, &target_text, item_ty.as_deref(), line_no, 3);
        let iterable = parse_expr(builder, &iterable_text, imports, known_classes, env, line_no);
        let result = parse_expr(builder, &result_expr, imports, known_classes, &mut comp_env, line_no);
        return with_line_span(new_call(builder, "builtins.gen_expr", None, vec![iterable, result]), builder.file_id(), line_no);
    }

    if is_string_literal(trimmed) {
        return new_string(builder, &trimmed[1..trimmed.len() - 1]);
    }
    if is_int_literal(trimmed) {
        return new_int(builder, trimmed.parse::<i64>().unwrap_or_default());
    }
    if trimmed == "True" {
        return Expr::Literal {
            id: builder.alloc_expr_id(),
            kind: uniflow_hir::LiteralKind::Bool(true),
            span: default_span(),
        };
    }
    if trimmed == "False" {
        return Expr::Literal {
            id: builder.alloc_expr_id(),
            kind: uniflow_hir::LiteralKind::Bool(false),
            span: default_span(),
        };
    }
    if trimmed == "None" {
        return Expr::Literal {
            id: builder.alloc_expr_id(),
            kind: uniflow_hir::LiteralKind::Null,
            span: default_span(),
        };
    }

    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner)
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .collect::<Vec<_>>();
        if items.len() >= 2 {
            let args = items
                .into_iter()
                .map(|arg| parse_expr(builder, &arg, imports, known_classes, env, line_no))
                .collect::<Vec<_>>();
            return with_line_span(new_call(builder, "builtins.tuple", None, args), builder.file_id(), line_no);
        }
    }

    if let Some(inner) = trimmed.strip_prefix('*') {
        return with_line_span(
            Expr::Unary {
                id: builder.alloc_expr_id(),
                op: UnaryOp::Deref,
                expr: Box::new(parse_expr(builder, inner, imports, known_classes, env, line_no)),
                span: default_span(),
            },
            builder.file_id(),
            line_no,
        );
    }

    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let arg_entries = parse_python_call_args_detailed(&arg_text);
        let arg_names = arg_entries.iter().map(|arg| arg.name.clone()).collect::<Vec<_>>();
        let args = arg_entries
            .iter()
            .map(|arg| parse_expr(builder, &arg.expr, imports, known_classes, env, line_no))
            .collect::<Vec<_>>();

        if callee_text == "getattr" {
            if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
                let base_expr = parse_expr(builder, &base, imports, known_classes, env, line_no);
                let expr = with_line_span(new_field_read(builder, base_expr, &field), builder.file_id(), line_no);
                if let Some(path) = infer_project_callable_value_type(&synthetic_attr_expr_text(&base, &field), imports, env, known_classes) {
                    let expr = wrap_expr_with_explicit_type(builder, expr, &path);
                    return with_line_span(expr, builder.file_id(), line_no);
                }
                return expr;
            }
        }
        if (callee_text == "cast" || callee_text.ends_with(".cast")) && arg_entries.len() >= 2 {
            let value_expr = parse_expr(builder, &arg_entries[1].expr, imports, known_classes, env, line_no);
            if let Some(ty) = normalize_runtime_type_name(arg_entries[0].expr.trim(), imports, env, known_classes) {
                let expr = wrap_expr_with_explicit_type(builder, value_expr, &ty);
                return with_line_span(expr, builder.file_id(), line_no);
            }
            return value_expr;
        }
        if callee_text == "super" && arg_entries.is_empty() {
            if let (Some(base_name), Some(self_symbol)) = (current_super_type(env), env.self_symbol) {
                let self_expr = new_var_ref(builder, self_symbol);
                let expr = wrap_expr_with_explicit_type(builder, self_expr, &base_name);
                return with_line_span(expr, builder.file_id(), line_no);
            }
        }

        match callee_text.as_str() {
            "list" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.list", None, args, arg_names), builder.file_id(), line_no);
            }
            "tuple" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.tuple", None, args, arg_names), builder.file_id(), line_no);
            }
            "set" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.set", None, args, arg_names), builder.file_id(), line_no);
            }
            "dict" => {
                let mut dict_args = Vec::new();
                for (entry, value_expr) in arg_entries.iter().zip(args.into_iter()) {
                    if let Some(name) = entry.name.as_ref() {
                        dict_args.push(new_string(builder, name));
                        dict_args.push(value_expr);
                    } else {
                        dict_args.push(value_expr);
                    }
                }
                return with_line_span(new_call(builder, "builtins.dict", None, dict_args), builder.file_id(), line_no);
            }
            "iter" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.iter", None, args, arg_names), builder.file_id(), line_no);
            }
            "aiter" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.aiter", None, args, arg_names), builder.file_id(), line_no);
            }
            "next" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.next", None, args, arg_names), builder.file_id(), line_no);
            }
            "anext" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.anext", None, args, arg_names), builder.file_id(), line_no);
            }
            "reversed" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.reversed", None, args, arg_names), builder.file_id(), line_no);
            }
            _ => {}
        }

        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if prefix == "super()" {
                let base_name = env.current_class_bases.first().cloned().unwrap_or_else(|| {
                    env.current_class.clone().unwrap_or_else(|| "super".to_string())
                });
                let receiver = env
                    .self_symbol
                    .map(|symbol| with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no));
                return with_line_span(
                    new_call_with_arg_names(builder, &format!("{base_name}.{method}"), receiver, args, arg_names),
                    builder.file_id(),
                    line_no,
                );
            }
            let receiver = parse_expr(builder, &prefix, imports, known_classes, env, line_no);
            let method_callee = if env.self_name.as_deref() == Some(prefix.as_str()) {
                if let Some(class_name) = env.current_class.as_ref() {
                    format!("{class_name}.{method}")
                } else {
                    format!("{prefix}.{method}")
                }
            } else if let Some(base_ty) = resolve_dotted_type(&prefix, imports, env, known_classes) {
                format!("{base_ty}.{method}")
            } else {
                format!("{prefix}.{method}")
            };
            if let Some(callable_value) = infer_project_callable_value_type(&callee_text, imports, env, known_classes) {
                if callable_value != method_callee {
                    return with_line_span(
                        new_call_with_arg_names(builder, &callable_value, None, args, arg_names),
                        builder.file_id(),
                        line_no,
                    );
                }
            }
            return with_line_span(new_call_with_arg_names(builder, &method_callee, Some(receiver), args, arg_names), builder.file_id(), line_no);
        }

        if let Some(mapped) = infer_project_callable_value_type(&callee_text, imports, env, known_classes) {
            return with_line_span(new_call_with_arg_names(builder, &mapped, None, args, arg_names), builder.file_id(), line_no);
        }

        if let Some(mapped) = env.callable_aliases.get(&callee_text).cloned() {
            return with_line_span(new_call_with_arg_names(builder, &mapped, None, args, arg_names), builder.file_id(), line_no);
        }

        if let Some(mapped) = resolve_imported_name(&callee_text, imports, env) {
            if known_classes.contains(callee_text.as_str()) || mapped.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()) {
                return with_line_span(
                    Expr::New {
                        id: builder.alloc_expr_id(),
                        type_name: mapped.clone(),
                        args,
                        span: default_span(),
                    },
                    builder.file_id(),
                    line_no,
                );
            }
            return with_line_span(new_call_with_arg_names(builder, &mapped, None, args, arg_names), builder.file_id(), line_no);
        }

        if let Some(class_name) = resolve_known_class_name(&callee_text, imports, env, known_classes) {
            return with_line_span(
                Expr::New {
                    id: builder.alloc_expr_id(),
                    type_name: class_name,
                    args,
                    span: default_span(),
                },
                builder.file_id(),
                line_no,
            );
        }

        if let Some(class_name) = env.current_class.as_ref() {
            if !is_builtin_python_name(&callee_text) {
                let receiver = env
                    .self_symbol
                    .map(|symbol| with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no));
                return with_line_span(
                    new_call_with_arg_names(builder, &format!("{class_name}.{callee_text}"), receiver, args, arg_names),
                    builder.file_id(),
                    line_no,
                );
            }
        }

        if let Some(callee_ty) = resolve_dotted_type(&callee_text, imports, env, known_classes) {
            if env.project_index.class_exists(&callee_ty) {
                return with_line_span(
                    Expr::New {
                        id: builder.alloc_expr_id(),
                        type_name: callee_ty,
                        args,
                        span: default_span(),
                    },
                    builder.file_id(),
                    line_no,
                );
            }
        }

        if let Some(symbol) = env.vars.get(&callee_text).copied() {
            let callee_expr = if let Some(path) = infer_project_callable_value_type(&callee_text, imports, env, known_classes) {
                let callee_ref = new_var_ref(builder, symbol);
                with_line_span(wrap_expr_with_explicit_type(builder, callee_ref, &path), builder.file_id(), line_no)
            } else {
                with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no)
            };
            return with_line_span(
                new_dynamic_call_with_arg_names(builder, callee_expr, None, args, arg_names),
                builder.file_id(),
                line_no,
            );
        }

        if let Some(mapped) = infer_project_callable_value_type(&callee_text, imports, env, known_classes) {
            return with_line_span(new_call_with_arg_names(builder, &mapped, None, args, arg_names), builder.file_id(), line_no);
        }

        if !is_simple_ident(&callee_text) {
            let callee_expr = parse_expr(builder, &callee_text, imports, known_classes, env, line_no);
            return with_line_span(
                new_dynamic_call_with_arg_names(builder, callee_expr, None, args, arg_names),
                builder.file_id(),
                line_no,
            );
        }

        return with_line_span(new_call_with_arg_names(builder, &callee_text, None, args, arg_names), builder.file_id(), line_no);
    }

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let args = split_top_level_commas(inner)
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .map(|arg| parse_expr(builder, &arg, imports, known_classes, env, line_no))
            .collect::<Vec<_>>();
        return with_line_span(new_call(builder, "builtins.list", None, args), builder.file_id(), line_no);
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.contains(':') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let mut args = Vec::new();
        for entry in split_top_level_commas(inner).into_iter().filter(|arg| !arg.trim().is_empty()) {
            if let Some((key, value)) = split_once_top_level(&entry, ':') {
                args.push(parse_expr(builder, &key, imports, known_classes, env, line_no));
                args.push(parse_expr(builder, &value, imports, known_classes, env, line_no));
            }
        }
        return with_line_span(new_call(builder, "builtins.dict", None, args), builder.file_id(), line_no);
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let args = split_top_level_commas(inner)
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .map(|arg| parse_expr(builder, &arg, imports, known_classes, env, line_no))
            .collect::<Vec<_>>();
        return with_line_span(new_call(builder, "builtins.set", None, args), builder.file_id(), line_no);
    }
    if let Some((base, index_expr)) = split_last_top_level_index(trimmed) {
        if let Some(base_ty) = resolve_dotted_type(&base, imports, env, known_classes) {
            if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, "__getitem__") {
                let receiver = parse_expr(builder, &base, imports, known_classes, env, line_no);
                let index = parse_expr(builder, &index_expr, imports, known_classes, env, line_no);
                let expr = with_line_span(
                    new_call(builder, &method_path, Some(receiver), vec![index]),
                    builder.file_id(),
                    line_no,
                );
                if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
                    let expr = wrap_expr_with_explicit_type(builder, expr, &path);
                    return with_line_span(expr, builder.file_id(), line_no);
                }
                return expr;
            }
        }
        let expr = with_line_span(
            Expr::IndexRead {
                id: builder.alloc_expr_id(),
                base: Box::new(parse_expr(builder, &base, imports, known_classes, env, line_no)),
                index: Box::new(parse_expr(builder, &index_expr, imports, known_classes, env, line_no)),
                span: default_span(),
            },
            builder.file_id(),
            line_no,
        );
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            let expr = wrap_expr_with_explicit_type(builder, expr, &path);
            return with_line_span(expr, builder.file_id(), line_no);
        }
        return expr;
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        let base_expr = parse_expr(builder, &base, imports, known_classes, env, line_no);
        let expr = with_line_span(new_field_read(builder, base_expr, &field), builder.file_id(), line_no);
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            let expr = wrap_expr_with_explicit_type(builder, expr, &path);
            return with_line_span(expr, builder.file_id(), line_no);
        }
        return expr;
    }

    if let Some(symbol) = env.capturable_vars.get(trimmed).copied() {
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            let expr = new_var_ref(builder, symbol);
            let expr = wrap_expr_with_explicit_type(builder, expr, &path);
            return with_line_span(expr, builder.file_id(), line_no);
        }
        return with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no);
    }

    if let Some(symbol) = env.vars.get(trimmed).copied() {
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            let expr = new_var_ref(builder, symbol);
            let expr = wrap_expr_with_explicit_type(builder, expr, &path);
            return with_line_span(expr, builder.file_id(), line_no);
        }
        return with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no);
    }

    let symbol = ensure_known_symbol(builder, &mut env.vars, trimmed, SymbolKind::Local);
    if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
        env.types.insert(trimmed.to_string(), path.clone());
        let expr = new_var_ref(builder, symbol);
        let expr = wrap_expr_with_explicit_type(builder, expr, &path);
        return with_line_span(expr, builder.file_id(), line_no);
    }
    with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no)
}

fn parse_python_comprehension(text: &str, open: char, close: char) -> Option<(String, String, String)> {
    let trimmed = text.trim();
    if !trimmed.starts_with(open) || !trimmed.ends_with(close) {
        return None;
    }
    let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
    let (result_expr, tail) = split_once_top_level_str(inner, " for ", false)?;
    let (target_text, iterable_text) = split_once_top_level_str(&tail, " in ", false)?;
    if result_expr.trim().is_empty() || target_text.trim().is_empty() || iterable_text.trim().is_empty() {
        None
    } else {
        Some((result_expr, target_text, iterable_text))
    }
}


fn resolve_known_class_name(
    name: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    if let Some(mapped) = resolve_imported_name(name, imports, env) {
        return Some(mapped);
    }
    if let Some(unique) = env.project_index.resolve_simple_class(name) {
        return Some(unique);
    }
    if known_classes.contains(name) || name.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()) {
        if let Some(in_module) = env.project_index.resolve_module_member(&env.current_module, name) {
            return Some(in_module);
        }
        return Some(name.to_string());
    }
    None
}

fn resolve_dotted_type(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = text.trim();
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return resolve_dotted_type(&inner, imports, env, known_classes);
    }
    if let Some(synthetic) = synthetic_static_namespace_access_text(trimmed) {
        return resolve_dotted_type(&synthetic, imports, env, known_classes);
    }
    if let Some((synthetic, _kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        if let Some(ty) = resolve_dotted_type(&synthetic, imports, env, known_classes) {
            return Some(ty);
        }
        if let Some(default_expr) = default_value {
            return resolve_dotted_type(&default_expr, imports, env, known_classes);
        }
    }
    if let Some(inner) = trimmed.strip_prefix("await ") {
        return infer_simple_python_type(inner, imports, env, known_classes);
    }
    if trimmed == "super()" {
        return current_super_type(env);
    }
    if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
        return resolve_dotted_type(&synthetic_attr_expr_text(&base, &field), imports, env, known_classes);
    }
    if let Some(ty) = env.types.get(trimmed) {
        return Some(ty.clone());
    }
    if let Some(mapped) = resolve_imported_name(trimmed, imports, env) {
        if let Some(ty) = env.project_index.module_value_type_by_path(&mapped) {
            return Some(ty);
        }
        return Some(mapped);
    }
    if let Some(prefixed) = resolve_prefixed_imported_name(trimmed, imports, env) {
        if let Some(ty) = env.project_index.module_value_type_by_path(&prefixed) {
            return Some(ty);
        }
        return Some(prefixed);
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        if (callee_text == "cast" || callee_text.ends_with(".cast")) && args.len() >= 2 {
            if let Some(ty) = normalize_runtime_type_name(args[0].trim(), imports, env, known_classes) {
                return Some(ty);
            }
        }
    }
    if let Some((base, _index)) = split_last_top_level_index(trimmed) {
        if let Some(base_ty) = resolve_dotted_type(&base, imports, env, known_classes) {
            if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                return Some(inner.to_string());
            }
            if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                if let Some((_, value)) = split_once_top_level(inner, ',') {
                    return Some(value.trim().to_string());
                }
            }
            if base_ty.ends_with("request.args") || base_ty.ends_with("request.form") || base_ty.ends_with("request.headers") || base_ty.ends_with("request.values") || base_ty.ends_with("request.GET") || base_ty.ends_with("request.POST") || base_ty.ends_with("request.query_params") || base_ty.ends_with("request.cookies") || base_ty.ends_with("request.json") {
                return Some("str".to_string());
            }
        }
    }
    if let Some(class_name) = resolve_known_class_name(trimmed, imports, env, known_classes) {
        return Some(class_name);
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        if env.self_name.as_deref() == Some(base.as_str()) {
            if let Some(ty) = direct_env_field_access_type(env, &field) {
                return Some(ty);
            }
        }
        if let Some(ty) = direct_local_field_access_type(env, &base, &field) {
            return Some(ty);
        }
        if is_simple_ident(&base) {
            if let Some(root) = local_object_alias_root(env, &base) {
                if let Some(ty) = direct_local_field_access_type(env, &root, &field) {
                    return Some(ty);
                }
            }
        } else if let Some(canonical) = canonical_container_path(env, &base) {
            if let Some(ty) = direct_local_field_access_type(env, &canonical, &field) {
                return Some(ty);
            }
        }
        let base_ty = resolve_dotted_type(&base, imports, env, known_classes)?;
        if let Some(class_fields) = env.class_field_index.get(&base_ty) {
            if let Some(raw_ty) = class_fields.get(&field).cloned() {
                return descriptor_access_type(&env.project_index, &raw_ty).or(Some(raw_ty));
            }
        }
        if let Some(ty) = direct_field_access_type(&env.project_index, &base_ty, &field) {
            return Some(ty);
        }
        if env.project_index.module_exists(&base_ty) {
            if let Some(member) = env.project_index.resolve_module_member(&base_ty, &field) {
                if let Some(ty) = env.project_index.module_value_type_by_path(&member) {
                    return Some(ty);
                }
                return Some(member);
            }
        }
        return Some(format!("{base_ty}.{field}"));
    }
    None
}

fn base_is_self(base: &Expr, env: &PyEnv) -> bool {
    match base {
        Expr::VarRef { symbol, .. } => env.self_symbol == Some(*symbol),
        _ => false,
    }
}

fn is_simple_ident(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_builtin_python_name(name: &str) -> bool {
    matches!(
        name,
        "str" | "int" | "bool" | "float" | "list" | "dict" | "set" | "tuple" | "len" | "print" | "range" | "enumerate"
    )
}

fn with_line_span(expr: Expr, file_id: uniflow_hir::FileId, line_no: u32) -> Expr {
    let span = span_from_line_range(file_id, line_no, line_no);
    set_span(expr, span)
}

fn set_span(expr: Expr, span: Span) -> Expr {
    match expr {
        Expr::VarRef { id, symbol, .. } => Expr::VarRef { id, symbol, span },
        Expr::Literal { id, kind, .. } => Expr::Literal { id, kind, span },
        Expr::Unary { id, op, expr, .. } => Expr::Unary { id, op, expr, span },
        Expr::Binary { id, op, lhs, rhs, .. } => Expr::Binary { id, op, lhs, rhs, span },
        Expr::FieldRead { id, base, field, .. } => Expr::FieldRead { id, base, field, span },
        Expr::IndexRead { id, base, index, .. } => Expr::IndexRead { id, base, index, span },
        Expr::Call(mut call) => {
            call.span = span;
            Expr::Call(call)
        }
        Expr::Lambda { id, params, captures, body, .. } => Expr::Lambda { id, params, captures, body, span },
        Expr::New { id, type_name, args, .. } => Expr::New { id, type_name, args, span },
        Expr::Cast { id, ty, expr, .. } => Expr::Cast { id, ty, expr, span },
        Expr::Unknown { id, .. } => Expr::Unknown { id, span },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_hir::CallTarget;
    use uniflow_parser_core::SourceParser;

    #[test]
    fn parses_python_class_methods_and_fields() {
        let src = r#"
from flask import request

class Controller:
    def __init__(self):
        self.name = "x"

    def handle(self):
        return request.args.get("q")
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let class = module
            .items
            .iter()
            .find_map(|item| match item { Item::Class(class) => Some(class), _ => None })
            .expect("class present");
        assert_eq!(class.name, "Controller");
        assert!(class.fields.iter().any(|field| field.name == "name"));
        assert!(class.methods.iter().any(|method| method.name.ends_with("handle")));
    }

    #[test]
    fn propagates_self_field_types_across_methods() {
        let src = r#"
class Repo:
    def run(self, value):
        return value

class Controller:
    def __init__(self):
        self.repo = Repo()

    def handle(self, value):
        return self.repo.run(value)
"#;
        let program = PythonParser.parse_file("service.py", src).expect("parse ok");
        let module = &program.modules[0];
        let class = module
            .items
            .iter()
            .find_map(|item| match item { Item::Class(class) if class.name == "Controller" => Some(class), _ => None })
            .expect("class present");
        assert!(class.fields.iter().any(|field| field.name == "repo"));
        assert!(class.methods.iter().any(|method| method.name.ends_with("handle")));
    }

    #[test]
    fn parses_project_sources_with_cross_file_imports() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "from db import DB\n\nclass Repo:\n    def __init__(self):\n        self.db = DB()\n".to_string(),
            ),
            (
                "db.py".to_string(),
                "class DB:\n    def execute(self, sql):\n        return sql\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\nfrom flask import *\n\nclass Controller:\n    def __init__(self):\n        self.repo = Repo()\n\n    def handle(self):\n        return self.repo.db.execute(request.args.get(\"q\"))\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("project parse ok");
        assert!(program.modules.iter().any(|module| module.name == "repo"));
        assert!(program.modules.iter().any(|module| module.name == "app"));
    }

    #[test]
    fn resolves_wildcard_imports_and_nested_self_fields() {
        let src = r#"
from flask import *

class Repo:
    def __init__(self):
        self.conn = request.args

class Controller:
    def __init__(self):
        self.repo = Repo()

    def handle(self):
        return self.repo.conn.get("q")
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Class(class) if class.name == "Repo")));
        assert!(module.items.iter().any(|item| matches!(item, Item::Class(class) if class.name == "Controller")));
    }

    #[test]
    fn propagates_cross_file_nested_field_types() {
        let entries = vec![
            (
                "db.py".to_string(),
                "class DB:
    def execute(self, sql):
        return sql
".to_string(),
            ),
            (
                "repo.py".to_string(),
                "from db import DB

class Repo:
    def __init__(self):
        self.db = DB()
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

class Controller:
    def __init__(self):
        self.repo = Repo()

    def handle(self, sql):
        return self.repo.db.execute(sql)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("project parse ok");
        assert!(program.modules.iter().any(|module| module.name == "app"));
    }

    #[test]
    fn infers_cross_file_method_return_types() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "from db import DB

class Repo:
    def current(self):
        return DB()
".to_string(),
            ),
            (
                "db.py".to_string(),
                "class DB:
    def execute(self, sql):
        return sql
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

class App:
    def __init__(self):
        self.repo = Repo()

    def run(self, sql):
        return self.repo.current().execute(sql)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("project parse ok");
        assert!(program.modules.iter().any(|module| module.name == "app"));
    }

    #[test]
    fn parses_python_package_project_with_top_level_return() {
        let entries = vec![
            (
                "examples/python_pkg/service/__init__.py".to_string(),
                "from service.repo import make_repo
".to_string(),
            ),
            (
                "examples/python_pkg/service/repo.py".to_string(),
                "from service.db import DB

class Repo:
    def __init__(self):
        self.db = DB()

def make_repo():
    return Repo()
".to_string(),
            ),
            (
                "examples/python_pkg/service/db.py".to_string(),
                "class DB:
    def execute(self, sql):
        return sql
".to_string(),
            ),
            (
                "examples/python_pkg/app.py".to_string(),
                "from service.repo import make_repo
from flask import request

class Controller:
    def handle(self):
        repo = make_repo()
        return repo.db.execute(request.args.get("q"))
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse ok");
        assert!(!program.modules.is_empty());
    }

    #[test]
    fn resolves_package_reexports_from_init() {
        let entries = vec![
            (
                "examples/python_pkg_reexport/pkg/__init__.py".to_string(),
                "from .repo import Repo, make_repo
".to_string(),
            ),
            (
                "examples/python_pkg_reexport/pkg/repo.py".to_string(),
                "from .db import DB

class Repo:
    def __init__(self):
        self.db = DB()

def make_repo():
    return Repo()
".to_string(),
            ),
            (
                "examples/python_pkg_reexport/pkg/db.py".to_string(),
                "class DB:
    def execute(self, sql):
        return sql
".to_string(),
            ),
            (
                "examples/python_pkg_reexport/app.py".to_string(),
                "from pkg import make_repo

class App:
    def run(self, sql):
        return make_repo().db.execute(sql)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse ok");
        assert!(program.modules.iter().any(|module| module.name == "pkg"));
    }

    #[test]
    fn resolves_package_reexported_function_returns() {
        let entries = vec![
            (
                "examples/python_pkg_reexport_return/app.py".to_string(),
                "from pkg import make_repo\nvalue = make_repo()\n".to_string(),
            ),
            (
                "examples/python_pkg_reexport_return/pkg/__init__.py".to_string(),
                "from .repo import make_repo\n".to_string(),
            ),
            (
                "examples/python_pkg_reexport_return/pkg/repo.py".to_string(),
                "from .db import DB\n\ndef make_repo():\n    return DB()\n".to_string(),
            ),
            (
                "examples/python_pkg_reexport_return/pkg/db.py".to_string(),
                "class DB:\n    pass\n".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("pkg.make_repo", 0).as_deref(), Some("pkg.db.DB"));
    }

    #[test]
    fn resolves_package_submodule_member_from_parent_import() {
        let entries = vec![
            (
                "examples/python_pkg_submodule/app.py".to_string(),
                "from pkg import repo\n\nclass App:\n    def handle(self, request):\n        db = repo.make_db()\n        db.execute(request.args.get(\"q\"))\n".to_string(),
            ),
            (
                "examples/python_pkg_submodule/pkg/repo.py".to_string(),
                "from .db import DB\n\ndef make_db():\n    return DB()\n".to_string(),
            ),
            (
                "examples/python_pkg_submodule/pkg/db.py".to_string(),
                "class DB:\n    def execute(self, sql):\n        return sql\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("pkg.repo.make_db") || rendered.contains("pkg.repo"));
    }


    #[test]
    fn resolves_wildcard_package_submodule_member() {
        let entries = vec![
            (
                "examples/python_pkg_wildcard_submodule/app.py".to_string(),
                "from pkg import *
value = repo.make_db()
".to_string(),
            ),
            (
                "examples/python_pkg_wildcard_submodule/pkg/repo.py".to_string(),
                "from .db import DB

def make_db():
    return DB()
".to_string(),
            ),
            (
                "examples/python_pkg_wildcard_submodule/pkg/db.py".to_string(),
                r#"class DB:
    pass
"#.to_string(),
            ),
            (
                "examples/python_pkg_wildcard_submodule/pkg/__init__.py".to_string(),
                "from . import repo
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        let imports = parse_imports_shallow_for_module("from pkg import *
", "app");
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index.clone(),
            ..Default::default()
        };
        assert_eq!(resolve_imported_name("repo", &imports, &env).as_deref(), Some("pkg.repo"));
    }

    #[test]
    fn canonicalizes_imported_module_alias_targets() {
        let entries = vec![
            (
                "examples/python_pkg_alias/pkg/__init__.py".to_string(),
                "from . import repo
".to_string(),
            ),
            (
                "examples/python_pkg_alias/pkg/repo.py".to_string(),
                "def make_db():
    return 1
".to_string(),
            ),
            (
                "examples/python_pkg_alias/app.py".to_string(),
                "import pkg.repo as repo_mod
value = repo_mod.make_db()
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        let imports = parse_imports_shallow_for_module("import pkg.repo as repo_mod
", "app");
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index,
            ..Default::default()
        };
        assert_eq!(resolve_imported_name("repo_mod", &imports, &env).as_deref(), Some("pkg.repo"));
    }


    #[test]
    fn import_pkg_repo_binds_pkg_root_name() {
        let imports = parse_imports_shallow_for_module("import pkg.repo\n", "app");
        assert_eq!(imports.aliases.get("pkg"), Some(&"pkg.repo".to_string()));
        assert!(!imports.aliases.contains_key("repo"));
    }

    #[test]
    fn canonicalizes_root_package_alias_prefix_chains() {
        let entries = vec![
            (
                "examples/python_pkg_root_alias/pkg/repo.py".to_string(),
                "def make_db():
    return 1
".to_string(),
            ),
            (
                "examples/python_pkg_root_alias/app.py".to_string(),
                "import pkg as root_pkg
value = root_pkg.repo.make_db()
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        let imports = parse_imports_shallow_for_module("import pkg as root_pkg
", "app");
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index,
            ..Default::default()
        };
        assert_eq!(resolve_prefixed_imported_name("root_pkg.repo", &imports, &env).as_deref(), Some("pkg.repo"));
    }

    #[test]
    fn resolves_unique_top_level_function_across_modules() {
        let entries = vec![
            (
                "examples/python_unique_func/pkg/repo.py".to_string(),
                "def make_db():
    return 1
".to_string(),
            ),
            (
                "examples/python_unique_func/app.py".to_string(),
                "value = make_db()
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.resolve_simple_function("make_db").as_deref(), Some("pkg.repo.make_db"));
    }

    #[test]
    fn infers_module_level_value_types_and_cross_module_object_flow() {
        let entries = vec![
            (
                "examples/python_module_values/service.py".to_string(),
                r#"from db import DB

db = DB()

def get_db():
    return db
"#
                .to_string(),
            ),
            (
                "examples/python_module_values/db.py".to_string(),
                r#"class DB:
    def execute(self, sql):
        return sql
"#
                .to_string(),
            ),
            (
                "examples/python_module_values/app.py".to_string(),
                r#"from service import get_db

class App:
    def handle(self, request):
        get_db().execute(request.args.get("q"))
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type("service", "db").as_deref(), Some("db.DB"));
        assert_eq!(index.top_level_return("service.get_db", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn inherited_fields_and_method_returns_resolve_through_base_classes() {
        let entries = vec![
            (
                "examples/python_inheritance_chain/base.py".to_string(),
                r#"from db import DB

class BaseRepo:
    def __init__(self):
        self.db = DB()

    def current(self):
        return self.db
"#
                .to_string(),
            ),
            (
                "examples/python_inheritance_chain/repo.py".to_string(),
                r#"from base import BaseRepo

class Repo(BaseRepo):
    pass
"#
                .to_string(),
            ),
            (
                "examples/python_inheritance_chain/db.py".to_string(),
                r#"class DB:
    def execute(self, sql):
        return sql
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("repo.Repo", "db").as_deref(), Some("db.DB"));
        assert_eq!(index.method_return("repo.Repo", "current", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn resolves_module_value_members_through_import_aliases() {
        let entries = vec![
            (
                "examples/python_module_alias_values/service.py".to_string(),
                r#"from db import DB

db = DB()
"#
                .to_string(),
            ),
            (
                "examples/python_module_alias_values/db.py".to_string(),
                r#"class DB:
    pass
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        let imports = parse_imports_shallow_for_module("import service as svc
", "app");
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index,
            ..Default::default()
        };
        assert_eq!(resolve_dotted_type("svc.db", &imports, &env, &HashSet::new()).as_deref(), Some("db.DB"));
    }


    #[test]
    fn parses_all_exports_and_module_aliases() {
        let entries = vec![
            (
                "examples/python_pkg_all/pkg/__init__.py".to_string(),
                r#"from .repo import make_repo
__all__ = ["make_repo"]
"#
                .to_string(),
            ),
            (
                "examples/python_pkg_all/pkg/repo.py".to_string(),
                r#"class Repo:
    pass

def make_repo():
    return Repo()
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.resolve_module_member("pkg", "make_repo").as_deref(), Some("pkg.repo.make_repo"));
        assert_eq!(index.top_level_return("pkg.make_repo", 0).as_deref(), Some("pkg.repo.Repo"));
    }

    #[test]
    fn resolves_module_symbol_aliases_and_index_types() {
        let entries = vec![
            (
                "examples/python_alias_mod/db.py".to_string(),
                r#"class DB:
    pass

conn = DB()
"#
                .to_string(),
            ),
            (
                "examples/python_alias_mod/service.py".to_string(),
                r#"from db import conn
get_conn = conn
items = [conn]
vals = {"x": conn}
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_symbol_alias("service", "get_conn").as_deref(), Some("db.conn"));
        let imports = parse_imports_shallow_for_module(
            r#"from service import get_conn
from service import items
from service import vals
"#,
            "app",
        );
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index,
            ..Default::default()
        };
        assert_eq!(resolve_dotted_type("get_conn", &imports, &env, &HashSet::new()).as_deref(), Some("db.DB"));
        assert_eq!(infer_simple_python_type("items[0]", &imports, &env, &HashSet::new()).as_deref(), Some("db.DB"));
        assert_eq!(infer_simple_python_type("vals['x']", &imports, &env, &HashSet::new()).as_deref(), Some("db.DB"));
    }



    #[test]
    fn infers_tuple_destructuring_and_tuple_indices() {
        let imports = PyImports::default();
        let mut env = PyEnv::default();
        env.current_module = "app".to_string();
        let known = HashSet::new();
        assert_eq!(infer_simple_python_type("(1, 'x')", &imports, &env, &known).as_deref(), Some("tuple<int|str>"));
        env.types.insert("pair".to_string(), "tuple<db.DB|repo.Repo>".to_string());
        assert_eq!(infer_simple_python_type("pair[0]", &imports, &env, &known).as_deref(), Some("db.DB"));
        assert_eq!(infer_simple_python_type("pair[1]", &imports, &env, &known).as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn infers_module_value_types_from_destructuring() {
        let entries = vec![
            (
                "examples/python_module_destructure/db.py".to_string(),
                r#"class DB:
    pass

class Repo:
    pass

conn, repo = (DB(), Repo())
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type("db", "conn").as_deref(), Some("db.DB"));
        assert_eq!(index.module_value_type("db", "repo").as_deref(), Some("db.Repo"));
    }

    #[test]
    fn local_destructuring_keeps_index_value_types() {
        let program = parse_python_file(
            "examples/python_destructure_locals/app.py",
            r#"from db import DB

def run():
    conn, alias = (DB(), DB())
    items = [conn]
    return items[0]
"#,
            None,
        )
        .expect("parse");
        assert!(!program.modules[0].items.is_empty());
    }


    #[test]
    fn parses_general_destructuring_via_index_reads() {
        let src = r#"
def load_pair():
    return source()

def handle():
    left, right = load_pair()
    return right
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("function present");
        assert!(matches!(function.body.stmts.first(), Some(Stmt::Let { .. })));
        assert!(function.body.stmts.iter().filter(|stmt| matches!(stmt, Stmt::Let { .. } | Stmt::Assign { .. })).count() >= 3);
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt,
            Stmt::Let { init: Some(Expr::IndexRead { .. }), .. } | Stmt::Assign { rhs: Expr::IndexRead { .. }, .. }
        )));
    }

    #[test]
    fn parses_for_each_destructuring_items_into_body_bindings() {
        let src = r#"
def handle(payload):
    for key, value in payload.items():
        result = value
    return result
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("function present");
        let loop_stmt = function.body.stmts.iter().find_map(|stmt| match stmt {
            Stmt::ForEach { body, .. } => Some(body),
            _ => None,
        }).expect("for loop present");
        assert!(loop_stmt.stmts.iter().take(2).all(|stmt| matches!(stmt, Stmt::Let { .. } | Stmt::Assign { .. })));
    }

    #[test]
    fn infers_python_comprehension_types() {
        let imports = parse_imports_shallow_for_module("", "app");
        let mut env = PyEnv::default();
        env.current_module = "app".to_string();
        env.types.insert("items".to_string(), "list<db.DB>".to_string());
        env.types.insert("payload".to_string(), "dict<str,repo.Repo>".to_string());
        let known = HashSet::new();
        assert_eq!(infer_simple_python_type("[item for item in items]", &imports, &env, &known).as_deref(), Some("list<db.DB>"));
        assert_eq!(infer_simple_python_type("{key: value for key, value in payload.items()}", &imports, &env, &known).as_deref(), Some("dict<str,repo.Repo>"));
    }

    #[test]
    fn parses_python_control_flow_statements() {
        let src = r#"
from flask import request

def handle(items):
    cmd = request.args.get("cmd")
    if cmd:
        value = cmd
    else:
        value = "safe"
    while cmd:
        cmd = value
    for item in items:
        value = item
    try:
        result = value
    except ValueError as err:
        result = err
    finally:
        value = result
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("function present");
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::If { .. })));
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::While { .. })));
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::ForEach { .. })));
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::Try { .. })));
    }

    #[test]
    fn parses_python_with_statement_as_flow_setup() {
        let src = r#"
def handle(path):
    with open(path) as handle:
        return handle.read()
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("function present");
        assert!(matches!(function.body.stmts.first(), Some(Stmt::Let { .. })));
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::Return { .. })));
    }

    #[test]
    fn parses_async_functions_and_await_calls() {
        let src = r#"
import subprocess

async def run(cmd):
    return await subprocess.run(args=cmd, shell=True)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("function present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else {
            panic!("expected return call");
        };
        assert!(matches!(call.args.first(), Some(Expr::VarRef { symbol, .. }) if *symbol == function.params[0].symbol));
        assert!(matches!(call.args.get(1), Some(Expr::Literal { kind: uniflow_hir::LiteralKind::Bool(true), .. })));
    }

    #[test]
    fn infers_async_and_keyword_argument_types() {
        let imports = parse_imports_shallow_for_module("import json\n", "app");
        let mut env = PyEnv::default();
        env.current_module = "app".to_string();
        env.types.insert("items".to_string(), "list<db.DB>".to_string());
        env.types.insert("payload".to_string(), "dict<str,repo.Repo>".to_string());
        let known = HashSet::new();
        assert_eq!(infer_simple_python_type("await items.pop()", &imports, &env, &known).as_deref(), Some("db.DB"));
        assert_eq!(infer_simple_python_type("payload.get(key='x')", &imports, &env, &known).as_deref(), Some("repo.Repo"));
        assert_eq!(infer_simple_python_type("json.dumps(obj=payload)", &imports, &env, &known).as_deref(), Some("str"));
    }


    #[test]
    fn parses_python_parameter_shapes_for_binding() {
        let specs = parse_python_param_specs("self, x, y=1, *args, z, flag=False, **kwargs");
        assert_eq!(specs.len(), 7);
        assert_eq!(specs[0].name, "self");
        assert_eq!(specs[1].name, "x");
        assert_eq!(specs[2].name, "y");
        assert!(specs[2].has_default);
        assert_eq!(specs[3].kind, PyParamKind::VarArgs);
        assert!(specs[4].keyword_only);
        assert!(specs[5].has_default);
        assert_eq!(specs[6].kind, PyParamKind::KwArgs);
    }

    #[test]
    fn call_parser_keeps_keyword_argument_names() {
        let src = r#"
def run(cmd, payload=None):
    return target(y=payload, x=cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("function present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else {
            panic!("expected return call");
        };
        assert_eq!(call.arg_names, vec![Some("y".to_string()), Some("x".to_string())]);
    }

    #[test]
    fn project_index_registers_default_argument_arities() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class DB:
    pass

def load(x, y=1):
    return DB()
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("repo.load", 1).as_deref(), Some("repo.DB"));
        assert_eq!(index.top_level_return("repo.load", 2).as_deref(), Some("repo.DB"));
    }

    #[test]
    fn resolves_local_callable_aliases_to_project_functions() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    runner = load
    return runner(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { .. } = &function.body.stmts[0] else {
            panic!("expected alias binding");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[1] else {
            panic!("expected return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn clears_local_callable_alias_after_non_callable_reassignment() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    runner = load
    runner = cmd
    return runner(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[2] else {
            panic!("expected return call");
        };
        assert!(matches!(&call.target, CallTarget::Dynamic(_)));
    }



    #[test]
    fn parses_local_callback_parameters_as_dynamic_calls() {
        let src = r#"
def wrap(cb, cmd):
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "wrap" => Some(function),
                _ => None,
            })
            .expect("wrap function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else {
            panic!("expected callback call");
        };
        assert!(matches!(&call.target, CallTarget::Dynamic(_)));
    }

    #[test]
    fn resolves_bound_method_aliases_to_project_methods() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Service:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service

def handle(cmd):
    svc = Service()
    runner = svc.run
    return runner(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[2] else {
            panic!("expected bound method call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.Service.run"));
    }

    #[test]
    fn parses_indexed_callable_invocations_as_dynamic_calls() {
        let src = r#"
def handle(handler_list, cmd):
    return handler_list[0](cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else {
            panic!("expected indexed callback call");
        };
        assert!(matches!(&call.target, CallTarget::Dynamic(_)));
    }

    #[test]
    fn async_project_returns_are_indexed() {
        let entries = vec![
            (
                "db.py".to_string(),
                "class DB:\n    pass\n".to_string(),
            ),
            (
                "repo.py".to_string(),
                "from db import DB\n\nasync def current():\n    return DB()\n".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("repo.current", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn resolves_callable_field_values_to_project_functions() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

class Service:
    def handle(self, cmd):
        self.cb = load
        return self.cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) => class.methods.iter().find(|method| method.name == "handle"),
                _ => None,
            })
            .expect("handle method");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[1] else {
            panic!("expected callable field return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn resolves_indexed_callable_values_to_project_functions() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    handlers = [load]
    return handlers[0](cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[1] else {
            panic!("expected indexed callable return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn resolves_local_object_callable_fields_inside_a_function() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, load

def handle(cmd):
    svc = Service()
    svc.cb = load
    return svc.cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[2] else {
            panic!("expected callable object-field return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn resolves_callable_fields_across_local_object_aliases() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, load

def handle(cmd):
    svc = Service()
    alias = svc
    alias.cb = load
    return svc.cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[3] else {
            panic!("expected alias-backed callable field return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }


    #[test]
    fn parses_lambda_capture_metadata() {
        let src = r#"
def handle(cmd):
    cb = lambda x: cmd
    return cb("safe")
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(func) if func.name == "handle" => Some(func),
                _ => None,
            })
            .expect("handle function");
        let outer_cmd = function.params[0].symbol;
        let Stmt::Let { init: Some(Expr::Lambda { captures, body, .. }), .. } = &function.body.stmts[0] else {
            panic!("expected lambda assignment");
        };
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].name, "cmd");
        assert_eq!(captures[0].source_symbol, outer_cmd);
        let Stmt::Return { value: Some(Expr::VarRef { symbol, .. }), .. } = &body.stmts[0] else {
            panic!("expected rewritten lambda return");
        };
        assert_eq!(*symbol, captures[0].symbol);
    }

    #[test]
    fn parses_lambda_callback_as_hir_lambda() {
        let src = r#"
def handle(cmd):
    cb = lambda x: x
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let function = program
            .modules
            .first()
            .and_then(|module| module.items.iter().find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            }))
            .expect("function");
        let has_lambda = function.body.stmts.iter().any(|stmt| match stmt {
            Stmt::Let { init: Some(Expr::Lambda { .. }), .. } => true,
            _ => false,
        });
        assert!(has_lambda);
    }

    #[test]
    fn resolves_nested_function_callbacks_to_project_internal_targets() {
        let src = r#"
def handle(cmd):
    def inner(x):
        return cmd
    return inner("safe")
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[0] else {
            panic!("expected nested callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.handle.inner"));
        let inner = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle.inner" => Some(function),
                _ => None,
            })
            .expect("nested function");
        assert_eq!(inner.captures.len(), 1);
        assert_eq!(inner.captures[0].name, "cmd");
    }

    #[test]
    fn parses_nested_function_values_returned_from_functions() {
        let src = r#"
def choose(cmd):
    def inner(x):
        return cmd
    return inner
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let choose = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "choose" => Some(function),
                _ => None,
            })
            .expect("choose function");
        let Stmt::Return { value: Some(Expr::VarRef { .. }), .. } = &choose.body.stmts[0] else {
            panic!("expected nested function return");
        };
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(function) if function.name == "app.choose.inner")));
    }

    #[test]
    fn project_index_recovers_nested_function_values_and_nonlocal_writebacks() {
        let entries = vec![
            (
                "app.py".to_string(),
                "class A:
    pass

class B:
    pass

def load(cmd):
    return A()

def alt(cmd):
    return B()

def choose(flag):
    cb = load
    def patch():
        nonlocal cb
        cb = alt
    return cb if flag else patch

def outer(cmd):
    cb = load
    def patch():
        nonlocal cb
        cb = alt
    patch()
    return cb(cmd)
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.choose", 1).as_deref(), Some("app.choose.patch"));
        assert_eq!(index.top_level_return("app.outer", 1).as_deref(), Some("app.B"));
    }

    #[test]
    fn project_index_applies_simple_decorator_wrapper_chains() {
        let entries = vec![
            (
                "app.py".to_string(),
                "class Repo:
    pass

def build(cmd):
    return Repo()

def deco(fn):
    def wrapper(cmd):
        return fn(cmd)
    return wrapper

@deco
def handle(cmd):
    return build(cmd)
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.deco", 1).as_deref(), Some("app.deco.wrapper"));
        assert_eq!(index.top_level_return("app.handle", 1).as_deref(), Some("app.Repo"));
        assert_eq!(index.module_value_type_by_path("app.handle").as_deref(), Some("app.deco.wrapper"));
    }

    #[test]
    fn resolves_callable_aliases_through_setdefault_and_get() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    mapping = {}
    mapping.setdefault("cb", load)
    cb = mapping.get("cb")
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Expr { .. } = &handle.body.stmts[1] else {
            panic!("expected setdefault expression statement");
        };
        let Stmt::Let { init: Some(Expr::Call(_)), .. } = &handle.body.stmts[2] else {
            panic!("expected get binding");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn resolves_callable_aliases_through_append_and_index_reads() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    handlers = []
    handlers.append(load)
    cb = handlers[0]
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Expr { .. } = &handle.body.stmts[1] else {
            panic!("expected append expression statement");
        };
        let Stmt::Let { init: Some(Expr::IndexRead { .. }), .. } = &handle.body.stmts[2] else {
            panic!("expected indexed callback binding");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn resolves_callable_aliases_through_precise_list_literal_slots() {
        let src = r#"
def load(cmd):
    return cmd

def noop(cmd):
    return "safe"

def handle(cmd):
    handlers = [noop, load]
    alias = handlers
    cb = alias[1]
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { init: Some(Expr::IndexRead { .. }), .. } = &handle.body.stmts[2] else {
            panic!("expected precise indexed callback binding");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected precise callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn resolves_callable_aliases_through_precise_dict_index_updates() {
        let src = r#"
def load(cmd):
    return cmd

def noop(cmd):
    return "safe"

def handle(cmd):
    mapping = {"safe": noop}
    alias = mapping
    alias["cb"] = load
    return mapping["cb"](cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Assign { .. } = &handle.body.stmts[2] else {
            panic!("expected indexed dict assignment");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected dict callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn parses_staticmethod_classmethod_and_property_decorators() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, value):
        return value

class Factory:
    @staticmethod
    def make_repo():
        return Repo()

    @classmethod
    def current(cls):
        return cls.make_repo()

    @property
    def repo(self):
        return self.make_repo()
"#
                .to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Factory

class App:
    def handle(self, value):
        factory = Factory()
        return factory.repo.run(value)
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.method_return("repo.Factory", "make_repo", 0).as_deref(), Some("repo.Repo"));
        assert_eq!(index.method_return("repo.Factory", "current", 0).as_deref(), Some("repo.Repo"));
        assert_eq!(index.field_type("repo.Factory", "repo").as_deref(), Some("repo.Repo"));
        let program = parse_project_sources(&entries).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("repo.Repo.run"));
    }

    #[test]
    fn infers_callable_object_values_via_dunder_call() {
        let src = r#"
class Loader:
    def __call__(self, cmd):
        return cmd

def handle(cmd):
    loader = Loader()
    return loader(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected callable-object return call");
        };
        assert!(matches!(&call.target, CallTarget::Dynamic(_)));
    }

    #[test]
    fn lowers_setattr_getattr_receiver_calls() {
        let src = r#"
import os

class Repo:
    def run(self, cmd):
        return os.system(cmd)

class Service:
    pass

def handle(cmd):
    svc = Service()
    setattr(svc, "repo", Repo())
    return getattr(svc, "repo").run(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Assign { lhs: LValue::Field { field, .. }, .. } = &handle.body.stmts[1] else {
            panic!("expected setattr lowering to field assignment");
        };
        assert_eq!(field, "repo");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[2] else {
            panic!("expected getattr based receiver call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.Repo.run" || name.ends_with("Repo.run")));
    }

    #[test]
    fn resolves_callable_aliases_through_getattr_fields() {
        let src = r#"
def load(cmd):
    return cmd

class Holder:
    pass

def handle(cmd):
    holder = Holder()
    setattr(holder, "cb", load)
    cb = getattr(holder, "cb")
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Assign { lhs: LValue::Field { field, .. }, .. } = &handle.body.stmts[1] else {
            panic!("expected setattr lowering");
        };
        assert_eq!(field, "cb");
        let Stmt::Let { .. } = &handle.body.stmts[2] else {
            panic!("expected getattr binding");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn maps_direct_builtin_constructor_calls() {
        let src = r#"
def load(cmd):
    return cmd

def handle():
    handlers = list([load])
    mapping = dict(cb=load)
    return handlers[0], mapping["cb"]
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { init: Some(Expr::Call(list_call)), .. } = &handle.body.stmts[0] else {
            panic!("expected list constructor binding");
        };
        assert!(matches!(&list_call.target, CallTarget::Named(name) if name == "builtins.list"));
        let Stmt::Let { init: Some(Expr::Call(dict_call)), .. } = &handle.body.stmts[1] else {
            panic!("expected dict constructor binding");
        };
        assert!(matches!(&dict_call.target, CallTarget::Named(name) if name == "builtins.dict"));
    }

    #[test]
    fn lowers_custom_getitem_to_method_call() {
        let src = r#"
class Box:
    def __init__(self):
        self.cb = run

    def __getitem__(self, key):
        return self.cb

def run(cmd):
    return cmd

def handle(box, cmd):
    cb = box["cb"]
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("handle") => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Let { init: Some(Expr::Call(call)), .. } = &handle.body.stmts[0] else {
            panic!("expected getitem lowering call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named __getitem__ call");
        };
        assert!(name.ends_with("Box.__getitem__"));
    }

    #[test]
    fn lowers_custom_setitem_to_method_call_stmt() {
        let src = r#"
class Box:
    def __setitem__(self, key, value):
        self.cb = value

def run(cmd):
    return cmd

def configure(box):
    box["cb"] = run
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let configure = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("configure") => Some(func), _ => None })
            .expect("configure present");
        let Stmt::Expr { expr: Expr::Call(call), .. } = &configure.body.stmts[0] else {
            panic!("expected __setitem__ expr call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named __setitem__ call");
        };
        assert!(name.ends_with("Box.__setitem__"));
    }

    #[test]
    fn resolves_callable_loop_items_from_custom_iter() {
        let src = r#"
def run(cmd):
    return cmd

class Registry:
    def __init__(self):
        self.handlers = [run]

    def __iter__(self):
        return self.handlers

def handle(registry, cmd):
    for cb in registry:
        return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("handle") => Some(func), _ => None })
            .expect("handle present");
        let Some(Stmt::ForEach { body, .. }) = handle.body.stmts.first() else {
            panic!("expected foreach");
        };
        let Some(Stmt::Return { value: Some(Expr::Call(call)), .. }) = body.stmts.first() else {
            panic!("expected return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected resolved callable loop item");
        };
        assert!(name.ends_with("run"));
    }



    #[test]
    fn resolves_super_property_receiver_calls() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Base:
    @property
    def repo(self):
        return Repo()

class Service(Base):
    def handle(self, cmd):
        return super().repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program
            .modules
            .iter()
            .find(|module| module.name == "repo")
            .expect("repo module");
        let service = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name == "repo.Service" => Some(class),
                _ => None,
            })
            .expect("service class");
        let handle = service
            .methods
            .iter()
            .find(|method| method.name == "repo.Service.handle")
            .expect("handle method");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[0] else {
            panic!("expected return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named call");
        };
        assert!(name.ends_with("Repo.run"));
    }

    #[test]
    fn unwraps_descriptor_field_reads_to_descriptor_get_return() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"def load(cmd):
    return cmd

class LoaderDescriptor:
    def __get__(self, obj, owner):
        return load

class Service:
    handler = LoaderDescriptor()

    def handle(self, cmd):
        cb = self.handler
        return cb(cmd)
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Service", "handler").as_deref(), Some("app.LoaderDescriptor"));
        assert_eq!(descriptor_access_type(&index, "app.LoaderDescriptor").as_deref(), Some("app.load"));
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let service = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name == "app.Service" => Some(class),
                _ => None,
            })
            .expect("service class");
        let handle = service.methods.iter().find(|method| method.name == "app.Service.handle").expect("handle method");
        let Stmt::Let { init: Some(expr), .. } = &handle.body.stmts[0] else {
            panic!("expected cb binding");
        };
        let expr_text = format!("{:?}", expr);
        assert!(expr_text.contains("app.load") || expr_text.contains("load"));
    }

    #[test]
    fn lowers_direct_delitem_to_magic_method_call() {
        let src = r#"
class Box:
    def __delitem__(self, key):
        pass

def clear(box):
    del box["cb"]
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let clear = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("clear") => Some(func), _ => None })
            .expect("clear present");
        let Stmt::Expr { expr: Expr::Call(call), .. } = &clear.body.stmts[0] else {
            panic!("expected __delitem__ expr call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named __delitem__ call");
        };
        assert!(name.ends_with("Box.__delitem__"));
    }

    #[test]
    fn tracks_property_setter_and_deleter_metadata() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"class Repo:
    pass

class Service:
    @property
    def repo(self):
        return Repo()

    @repo.setter
    def repo(self, value):
        self._repo = value

    @repo.deleter
    def repo(self):
        self._repo = None
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert!(index.class_has_property_setter("app.Service", "repo"));
        assert!(index.class_has_property_deleter("app.Service", "repo"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("app.Repo"));
    }

    #[test]
    fn parses_direct_del_field_statements() {
        let src = r#"
class Service:
    def handle(self):
        del self.repo
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let service = module
            .items
            .iter()
            .find_map(|item| match item { Item::Class(class) if class.name == "Service" => Some(class), _ => None })
            .expect("service class");
        let handle = service.methods.iter().find(|method| method.name == "Service.handle").expect("handle method");
        let Stmt::Expr { .. } = &handle.body.stmts[0] else {
            panic!("expected direct del lowering to expr");
        };
    }

    #[test]
    fn infers_top_level_return_through_local_alias() {
        let entries = vec![
            (
                "db.py".to_string(),
                r#"class DB:
    pass
"#.to_string(),
            ),
            (
                "service.py".to_string(),
                r#"from db import DB

def make_db():
    conn = DB()
    return conn
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("service.make_db", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn infers_method_return_through_local_alias() {
        let entries = vec![
            (
                "db.py".to_string(),
                r#"class DB:
    pass
"#.to_string(),
            ),
            (
                "service.py".to_string(),
                r#"from db import DB

class Repo:
    def __init__(self):
        self.db = DB()

    def current_db(self):
        conn = self.db
        return conn
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.method_return("service.Repo", "current_db", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn infers_class_field_types_through_setattr_local_alias() {
        let entries = vec![
            (
                "service.py".to_string(),
                r#"class Repo:
    pass

class Service:
    def __init__(self):
        repo = Repo()
        setattr(self, "repo", repo)
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("service.Service", "repo").as_deref(), Some("service.Repo"));
    }


    #[test]
    fn infers_class_body_descriptor_field_types() {
        let entries = vec![(
            "app.py".to_string(),
            r#"def load(cmd):
    return cmd

class LoaderDescriptor:
    def __get__(self, obj, owner):
        return load

class Service:
    handler = LoaderDescriptor()
"#.to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Service", "handler").as_deref(), Some("app.LoaderDescriptor"));
    }

    #[test]
    fn infers_module_aliases_through_local_bindings_and_dynamic_imports() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"def load(cmd):
    return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from importlib import import_module

mod = import_module("repo")
cb = mod.load
exported = cb
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_symbol_alias("app", "mod").as_deref(), Some("repo"));
        assert_eq!(index.module_symbol_alias("app", "cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_symbol_alias("app", "exported").as_deref(), Some("repo.load"));
    }

    #[test]
    fn resolves_importlib_module_types_and_partial_targets() {
        let src = r#"
import importlib
from functools import partial

def load(cmd):
    return cmd

def handle(cmd):
    mod = importlib.import_module("app")
    cb = partial(mod.load)
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("handle") => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[2] else {
            panic!("expected callback return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected resolved partial callback call");
        };
        assert!(name.ends_with("load"));
    }

    #[test]
    fn lowers_property_setter_and_deleter_writes_to_calls() {
        let entries = vec![(
            "app.py".to_string(),
            r#"class Repo:
    pass

class Service:
    @property
    def repo(self):
        return Repo()

    @repo.setter
    def repo(self, value):
        self._repo = value

    @repo.deleter
    def repo(self):
        self._repo = None

def configure(svc):
    svc.repo = Repo()
    del svc.repo
"#.to_string(),
        )];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let configure = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.configure" => Some(func), _ => None })
            .expect("configure present");
        let Stmt::Expr { expr: Expr::Call(first), .. } = &configure.body.stmts[0] else {
            panic!("expected property setter call");
        };
        let CallTarget::Named(first_name) = &first.target else {
            panic!("expected named property setter call");
        };
        assert!(first_name.ends_with("Service.repo"));
        let Stmt::Expr { expr: Expr::Call(second), .. } = &configure.body.stmts[1] else {
            panic!("expected property deleter call");
        };
        let CallTarget::Named(second_name) = &second.target else {
            panic!("expected named property deleter call");
        };
        assert!(second_name.ends_with("Service.repo"));
    }

    #[test]
    fn narrows_isinstance_receiver_in_if_branch() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\n\ndef handle(obj, cmd):\n    if isinstance(obj, Repo):\n        return obj.run(cmd)\n    return cmd\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle" => Some(func), _ => None })
            .expect("handle present");
        let Stmt::If { then_block, .. } = &handle.body.stmts[0] else {
            panic!("expected if statement");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &then_block.stmts[0] else {
            panic!("expected narrowed return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named narrowed target");
        };
        assert!(name.ends_with("Repo.run"));
    }

    #[test]
    fn merges_branch_locals_after_if_else() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\n\ndef handle(flag, cmd):\n    if flag:\n        repo = Repo()\n    else:\n        repo = Repo()\n    return repo.run(cmd)\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle" => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected merged return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named merged target");
        };
        assert!(name.ends_with("Repo.run"));
    }

    #[test]
    fn resolves_typing_cast_and_assert_isinstance() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from typing import cast\nfrom repo import Repo\n\ndef handle(obj, cmd):\n    repo = cast(Repo, obj)\n    assert isinstance(repo, Repo)\n    return repo.run(cmd)\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle" => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Let { ty: Some(ty), .. } = &handle.body.stmts[0] else {
            panic!("expected cast let with explicit type");
        };
        assert!(module.types[*ty].name.ends_with("Repo"));
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[2] else {
            panic!("expected asserted return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named asserted target");
        };
        assert!(name.ends_with("Repo.run"));
    }

    #[test]
    fn tracks_module_and_class_monkey_patches_and_class_alias_calls() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"def old(cmd):
    return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"import repo

def load(cmd):
    return cmd

class Service:
    pass

repo.run = load
Service.run = load

def handle_module(cmd):
    return repo.run(cmd)

def handle_service(cmd):
    factory = Service
    svc = factory()
    return svc.run(cmd)
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("repo.run").as_deref(), Some("app.load"));
        assert_eq!(index.field_type("app.Service", "run").as_deref(), Some("app.load"));

        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle_module = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle_module" => Some(func), _ => None })
            .expect("handle_module present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle_module.body.stmts[0] else {
            panic!("expected module patch call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named module patch target");
        };
        assert_eq!(name, "app.load");

        let handle_service = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle_service" => Some(func), _ => None })
            .expect("handle_service present");
        let Stmt::Let { init: Some(Expr::New { type_name, .. }), .. } = &handle_service.body.stmts[1] else {
            panic!("expected class alias constructor new");
        };
        assert_eq!(type_name, "app.Service");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle_service.body.stmts[2] else {
            panic!("expected service patch call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named service patch target");
        };
        assert_eq!(name, "app.load");
    }

    #[test]
    fn resolves_static_globals_and_vars_namespace_accesses() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

def load(cmd):
    return cmd

globals()["load_alias"] = load

class Service:
    def __init__(self):
        self.__dict__["repo"] = Repo()

    def handle(self, cmd):
        cb = globals()["load_alias"]
        return cb(vars(self)["repo"].run(cmd))
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("app.load_alias").as_deref(), Some("app.load"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("repo.Repo"));

        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let service = module
            .items
            .iter()
            .find_map(|item| match item { Item::Class(class) if class.name == "app.Service" => Some(class), _ => None })
            .expect("service class");
        let handle = service.methods.iter().find(|method| method.name == "app.Service.handle").expect("handle method");
        let Stmt::Let { ty: Some(ty), .. } = &handle.body.stmts[0] else {
            panic!("expected globals alias let");
        };
        assert!(module.types[*ty].name.ends_with("load"));
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected namespace return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named namespace callback target");
        };
        assert_eq!(name, "app.load");
    }

    #[test]
    fn uses_context_manager_enter_return_types_for_with_aliases() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

class RepoManager:
    def __enter__(self):
        return Repo()

    def __exit__(self, exc_type, exc, tb):
        return None

def handle(cmd):
    with RepoManager() as repo:
        return repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle" => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Let { ty: Some(ty), .. } = &handle.body.stmts[0] else {
            panic!("expected with alias let");
        };
        assert_eq!(module.types[*ty].name, "repo.Repo");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected with return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named with target");
        };
        assert_eq!(name, "repo.Repo.run");
    }

    #[test]
    fn resolves_static_namespace_get_pop_and_setdefault_helpers() {
        let entries = vec![
            (
                "examples/python_namespace_method_helpers/repo.py".to_string(),
                "def load(cmd):\n    return cmd\n\nclass Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "examples/python_namespace_method_helpers/app.py".to_string(),
                "from repo import Repo, load\n\nglobals()[\"cb\"] = load\nglobals()[\"factory\"] = Repo\n\ndef handle_get(cmd):\n    cb = globals().get(\"cb\")\n    return cb(cmd)\n\ndef handle_pop(cmd):\n    cb = globals().pop(\"cb\")\n    return cb(cmd)\n\ndef handle_setdefault(cmd):\n    cb = globals().setdefault(\"cb2\", load)\n    return cb(cmd)\n\ndef handle_factory(cmd):\n    factory = globals().get(\"factory\")\n    repo = factory()\n    return repo.run(cmd)\n".to_string(),
            ),
        ];
        let parser = PythonParser::default();
        let project = parser.parse_project(&entries).expect("parse project");
        let app_module = project.modules.iter().find(|m| m.name == "app").expect("app module");
        let handle_get = app_module.functions.iter().find(|f| f.name == "handle_get").expect("handle_get");
        let handle_pop = app_module.functions.iter().find(|f| f.name == "handle_pop").expect("handle_pop");
        let handle_setdefault = app_module.functions.iter().find(|f| f.name == "handle_setdefault").expect("handle_setdefault");
        let handle_factory = app_module.functions.iter().find(|f| f.name == "handle_factory").expect("handle_factory");
        let saw_get_alias = handle_get.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::Let { init: Some(Expr::Cast { ty: Some(ty), .. }), .. } if app_module.types.resolve(*ty).is_some_and(|name| name == "repo.load")));
        let saw_pop_alias = handle_pop.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::Let { init: Some(Expr::Cast { ty: Some(ty), .. }), .. } if app_module.types.resolve(*ty).is_some_and(|name| name == "repo.load")));
        let saw_setdefault_alias = handle_setdefault.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::Let { init: Some(Expr::Cast { ty: Some(ty), .. }), .. } if app_module.types.resolve(*ty).is_some_and(|name| name == "repo.load")));
        let saw_factory_ctor = handle_factory.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::Let { init: Some(Expr::New { type_name, .. }), .. } if type_name == "repo.Repo"));
        assert!(saw_get_alias);
        assert!(saw_pop_alias);
        assert!(saw_setdefault_alias);
        assert!(saw_factory_ctor);
    }

    #[test]
    fn resolves_static_eval_callable_aliases() {
        let entries = vec![
            (
                "examples/python_eval_exec_dynamic/repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "examples/python_eval_exec_dynamic/app.py".to_string(),
                "from repo import load

def handle(cmd):
    cb = eval("load")
    return cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { .. } = &handle.body.stmts[0] else {
            panic!("expected eval alias let");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name.ends_with("repo.load")));
    }

    #[test]
    fn lowers_static_exec_assignments_into_real_statements() {
        let entries = vec![
            (
                "examples/python_eval_exec_dynamic/repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "examples/python_eval_exec_dynamic/app.py".to_string(),
                r#"from repo import Repo

def handle(cmd):
    exec("repo = Repo()\ncb = repo.run")
    return cb(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { .. } = &handle.body.stmts[0] else {
            panic!("expected exec-defined repo let");
        };
        let Stmt::Let { .. } = &handle.body.stmts[1] else {
            panic!("expected exec-defined callback let");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[2] else {
            panic!("expected callback return call after exec");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name.ends_with("Repo.run")));
    }

    #[test]
    fn narrows_type_identity_guards() {
        let entries = vec![
            (
                "examples/python_type_identity_guard/repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "examples/python_type_identity_guard/app.py".to_string(),
                "from repo import Repo

def handle(obj, cmd):
    if type(obj) is Repo:
        return obj.run(cmd)
    return cmd
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::If { then_block, .. } = &handle.body.stmts[0] else {
            panic!("expected if statement");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &then_block.stmts[0] else {
            panic!("expected narrowed return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name.ends_with("Repo.run")));
    }

    #[test]
    fn resolves_async_with_aenter_and_async_for_anext() {
        let entries = vec![
            (
                "examples/python_async_magic/repo.py".to_string(),
                "def load(cmd):
    return cmd

class Repo:
    def run(self, cmd):
        return cmd

class AsyncManager:
    async def __aenter__(self):
        return Repo()

    async def __aexit__(self, exc_type, exc, tb):
        return None

class AsyncRegistry:
    def __aiter__(self):
        return self

    async def __anext__(self):
        return load
".to_string(),
            ),
            (
                "examples/python_async_magic/app.py".to_string(),
                "from repo import AsyncManager, AsyncRegistry

async def handle(cmd):
    async with AsyncManager() as repo:
        first = repo.run(cmd)
    async for cb in AsyncRegistry():
        return cb(first)
    return first
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { ty: Some(ty), .. } = &handle.body.stmts[0] else {
            panic!("expected async with alias let");
        };
        assert_eq!(module.types[*ty].name, "repo.Repo");
        let Stmt::ForEach { body, .. } = &handle.body.stmts[2] else {
            panic!("expected async for lowered as foreach");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &body.stmts[0] else {
            panic!("expected callback return inside async for");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn tracks_static_namespace_update_calls() {
        let entries = vec![
            (
                "examples/python_namespace_update_calls/repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd

def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "examples/python_namespace_update_calls/app.py".to_string(),
                r#"from repo import Repo, load

globals().update({"load_alias": load})

class Service:
    pass

vars(Service).update(repo=Repo())

def handle(cmd):
    cb = globals()["load_alias"]
    return cb(Service.repo.run(cmd))
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("app.load_alias").as_deref(), Some("repo.load"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn resolves_next_callable_aliases_from_iterables() {
        let entries = vec![
            (
                "examples/python_next_callable/repo.py".to_string(),
                "def load(cmd):
    return cmd

class Registry:
    def __iter__(self):
        return self

    def __next__(self):
        return load
".to_string(),
            ),
            (
                "examples/python_next_callable/app.py".to_string(),
                "from repo import Registry

def handle(cmd):
    cb = next(Registry())
    return cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn merges_try_except_finally_callback_envs() {
        let entries = vec![
            (
                "examples/python_try_except_finally_callbacks/repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "examples/python_try_except_finally_callbacks/app.py".to_string(),
                "from repo import load

def handle(cmd):
    try:
        cb = load
    except Exception as exc:
        cb = load
    finally:
        final_cb = cb
    return final_cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[2] else {
            panic!("expected callback return after try/finally merge");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn resolves_generator_yield_callbacks_through_next() {
        let entries = vec![
            (
                "examples/python_generator_yield_callbacks/repo.py".to_string(),
                "def load(cmd):
    return cmd

def callbacks():
    yield load
".to_string(),
            ),
            (
                "examples/python_generator_yield_callbacks/app.py".to_string(),
                "from repo import callbacks

def handle(cmd):
    cb = next(callbacks())
    return cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected generator-backed callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }


    #[test]
    fn project_index_keeps_loop_only_assignments_conservative() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

def maybe_repo(items):
    repo = None
    for item in items:
        repo = Repo()
    return repo
".to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.top_level_return("app.maybe_repo", 1), None);
    }

    #[test]
    fn project_index_models_map_and_sorted_iterable_helpers() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

def build(x):
    return Repo()

def via_map():
    return next(map(build, [1]))

def via_sorted():
    repo = sorted([Repo()])[0]
    return repo
".to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.top_level_return("app.via_map", 0).as_deref(), Some("repo.Repo"));
        assert_eq!(index.top_level_return("app.via_sorted", 0).as_deref(), Some("repo.Repo"));
    }



    #[test]
    fn project_index_models_structured_if_branch_merges() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    pass\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\n\ndef choose(flag):\n    if flag:\n        repo = Repo()\n    else:\n        repo = Repo()\n    return repo\n".to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.top_level_return("app.choose", 1).as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn project_index_models_structured_try_except_merges() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    pass\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\n\ndef choose():\n    try:\n        repo = Repo()\n    except Exception as exc:\n        repo = Repo()\n    return repo\n".to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.top_level_return("app.choose", 0).as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn project_index_stops_after_unconditional_return_in_summary() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):\n    return cmd\n\ndef other(cmd):\n    return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, other\n\ndef choose():\n    cb = load\n    return cb\n    cb = other\n".to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.top_level_return("app.choose", 0).as_deref(), Some("repo.load"));
    }


    #[test]
    fn project_index_models_structured_module_level_branches() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):\n    return cmd\n\nclass Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo, load\n\nclass Service:\n    pass\n\nif flag:\n    cb = load\n    Service.repo = Repo()\nelse:\n    cb = load\n    Service.repo = Repo()\n".to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.module_value_type_by_path("app.cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_symbol_alias("app", "cb").as_deref(), Some("repo.load"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn project_index_models_structured_module_try_imports() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):\n    return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "try:\n    from repo import load as cb\nexcept ImportError:\n    from repo import load as cb\n".to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.module_value_type_by_path("app.cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_symbol_alias("app", "cb").as_deref(), Some("repo.load"));
    }




    #[test]
    fn project_index_delays_nested_writebacks_until_call_time() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class A:
    pass

class B:
    pass

def load(cmd):
    return A()

def alt(cmd):
    return B()
".to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import load, alt

def outer(cmd):
    cb = load

    def patch():
        nonlocal cb
        cb = alt

    return cb(cmd)
"#.to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.top_level_return("app.outer", 1).as_deref(), Some("repo.A"));
    }

    #[test]
    fn project_index_replays_module_helper_writebacks_on_call() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class A:
    pass

class B:
    pass

class Repo:
    def execute(self, value):
        return value

def load(cmd):
    return A()

def alt(cmd):
    return B()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import load, alt, Repo

cb = load

class Service:
    pass

def patch():
    global cb
    cb = alt

def install():
    Service.repo = Repo

patch()
install()
"#.to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.module_value_type_by_path("app.cb").as_deref(), Some("repo.alt"));
        assert_eq!(index.module_symbol_alias("app", "cb").as_deref(), Some("repo.alt"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn project_index_respects_cross_module_import_execution_order() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class A:
    pass

class B:
    pass

def load(cmd):
    return A()

def alt(cmd):
    return B()

cb = load
".to_string(),
            ),
            (
                "patcher.py".to_string(),
                "import repo
from repo import alt

repo.cb = alt
".to_string(),
            ),
            (
                "before.py".to_string(),
                "from repo import cb
import patcher
".to_string(),
            ),
            (
                "after.py".to_string(),
                "import patcher
from repo import cb
".to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.module_value_type_by_path("before.cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_symbol_alias("before", "cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_value_type_by_path("after.cb").as_deref(), Some("repo.alt"));
        assert_eq!(index.module_symbol_alias("after", "cb").as_deref(), Some("repo.alt"));
    }

    #[test]
    fn project_index_replays_nested_outer_heap_writebacks_on_call() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class A:
    pass

class B:
    pass

def load(cmd):
    return A()

def alt(cmd):
    return B()

class Box:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Box, load, alt

def outer(cmd):
    holder = Box()
    holder.inner = Box()
    holder.inner.cb = load

    def patch():
        holder.inner.cb = alt

    patch()
    return holder.inner.cb(cmd)
".to_string(),
            ),
        ];
        let index = build_python_project_index(&entries).expect("python index");
        assert_eq!(index.top_level_return("app.outer", 1).as_deref(), Some("repo.B"));
    }

    #[test]
    fn replays_decorator_wrapper_side_effects_at_call_time() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

class Service:
    pass

def deco(fn):
    def wrapper(svc, cmd):
        svc.repo = Repo()
        return fn(svc, cmd)
    return wrapper

@deco
def handle(svc, cmd):
    return cmd

def call(cmd):
    svc = Service()
    handle(svc, cmd)
    return svc.repo.run(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let call = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.call" => Some(function),
                _ => None,
            })
            .expect("call function");
        let Stmt::Return { value: Some(Expr::Call(call_expr)), .. } = &call.body.stmts[2] else {
            panic!("expected decorated wrapper side-effect replayed call");
        };
        assert!(matches!(&call_expr.target, CallTarget::Named(name) if name == "repo.Repo.run"));
    }

    #[test]
    fn project_index_replays_constructor_init_side_effects_into_receiver_objects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    def __init__(self):
        self.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service

def handle(cmd):
    svc = Service()
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_instance_method_side_effects_into_receivers() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    def install(self):
        self.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service

def handle(cmd):
    svc = Service()
    svc.install()
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_free_function_parameter_side_effects_into_arguments() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    pass

def install(service):
    service.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service, install

def handle(cmd):
    svc = Service()
    install(svc)
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_dotted_receiver_method_side_effects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Runner:
    def run(self, cmd):
        return cmd

class Holder:
    def install(self):
        self.runner = Runner()

class Service:
    def __init__(self):
        self.repo = Holder()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service

def handle(cmd):
    svc = Service()
    svc.repo.install()
    return svc.repo.runner.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Runner.run");
    }

    #[test]
    fn project_index_replays_classmethod_side_effects_into_class_receivers() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

class Service:
    @classmethod
    def install(cls):
        cls.repo = Repo()

def handle(cmd):
    Service.install()
    return Service.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_applies_recursive_import_side_effects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    pass
"#.to_string(),
            ),
            (
                "patch_inner.py".to_string(),
                r#"from repo import Repo, Service

Service.repo = Repo()
"#.to_string(),
            ),
            (
                "patch_outer.py".to_string(),
                r#"import patch_inner
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"import patch_outer
from repo import Service

def handle(cmd):
    return Service.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_decorated_method_wrapper_with_bound_self() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

def deco(fn):
    def wrapper(self):
        self.repo = Repo()
        return fn(self)
    return wrapper

class Service:
    @deco
    def install(self):
        return None

def handle(cmd):
    svc = Service()
    svc.install()
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_star_spread_argument_side_effects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    pass

def install(service):
    service.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service, install

def handle(cmd):
    svc = Service()
    args = (svc,)
    install(*args)
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_starstar_keyword_side_effects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    pass

def install(*, service):
    service.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service, install

def handle(cmd):
    svc = Service()
    kwargs = {"service": svc}
    install(**kwargs)
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }


    #[test]
    fn parses_annotated_class_body_fields() {
        let src = r#"
class Repo:
    pass

class Payload:
    repo: Repo
    items: list[Repo]
    payload: dict[str, Repo]
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let payload = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name.ends_with("Payload") => Some(class),
                _ => None,
            })
            .expect("payload class");
        let field_type = |name: &str| -> String {
            let field = payload.fields.iter().find(|field| field.name == name).expect("field present");
            let ty = field.ty.expect("typed field");
            program.types[ty.0 as usize].name.clone()
        };
        assert_eq!(field_type("repo"), "app.Repo");
        assert_eq!(field_type("items"), "list<app.Repo>");
        assert_eq!(field_type("payload"), "dict<str,app.Repo>");
    }

    #[test]
    fn project_index_recovers_annotated_framework_style_fields() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

class Payload:
    repo: Repo
    items: list[Repo]
    payload: dict[str, Repo]
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Payload", "repo").as_deref(), Some("repo.Repo"));
        assert_eq!(index.field_type("app.Payload", "items").as_deref(), Some("list<repo.Repo>"));
        assert_eq!(index.field_type("app.Payload", "payload").as_deref(), Some("dict<str,repo.Repo>"));
    }

    #[test]
    fn infers_fastapi_depends_parameter_type_from_provider_return() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from fastapi import Depends
from repo import Repo

def get_repo() -> Repo:
    return Repo()

def handle(repo = Depends(get_repo)):
    return repo
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.handle", 0).as_deref(), Some("repo.Repo"));
    }


    #[test]
    fn resolves_typevar_and_newtype_annotations_in_project_index() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"from typing import NewType, TypeVar

class Repo:
    pass

RepoId = NewType("RepoId", str)
TRepo = TypeVar("TRepo", bound=Repo)

class Payload:
    repo: TRepo
    rid: RepoId
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("repo.Payload", "repo").as_deref(), Some("repo.Repo"));
        assert_eq!(index.field_type("repo.Payload", "rid").as_deref(), Some("str"));
    }

    #[test]
    fn parses_typing_extensions_and_attrs_field_factories() {
        let src = r#"
from typing_extensions import Annotated, Literal, NotRequired, Required
import attrs

class Repo:
    pass

class Payload:
    repo: Required[Annotated[Repo, "payload"]]
    rid: Literal[1]
    maybe: NotRequired[Repo]
    created = attrs.field(factory=Repo)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let payload = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name.ends_with("Payload") => Some(class),
                _ => None,
            })
            .expect("payload class");
        let field_type = |name: &str| -> String {
            let field = payload.fields.iter().find(|field| field.name == name).expect("field present");
            let ty = field.ty.expect("typed field");
            program.types[ty.0 as usize].name.clone()
        };
        assert_eq!(field_type("repo"), "app.Repo");
        assert_eq!(field_type("rid"), "int");
        assert_eq!(field_type("maybe"), "app.Repo");
        assert_eq!(field_type("created"), "app.Repo");
    }

    #[test]
    fn infers_fastapi_query_default_type() {
        let entries = vec![
            (
                "app.py".to_string(),
                "from fastapi import Query

def handle(limit = Query(10)):
    return limit
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.handle", 0).as_deref(), Some("int"));
    }


    #[test]
    fn parses_extended_annotation_aliases_and_field_factories() {
        let src = r#"
from dataclasses import field
from typing import Annotated, Mapping, Optional, Sequence

class Repo:
    pass

class Payload:
    repo: Optional[Repo]
    seq: Sequence[Repo]
    mapping: Mapping[str, Repo]
    annotated: Annotated[Repo, "payload"]
    created = field(default_factory=Repo)
    items = field(default_factory=list)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let payload = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name.ends_with("Payload") => Some(class),
                _ => None,
            })
            .expect("payload class");
        let field_type = |name: &str| -> String {
            let field = payload.fields.iter().find(|field| field.name == name).expect("field present");
            let ty = field.ty.expect("typed field");
            program.types[ty.0 as usize].name.clone()
        };
        assert_eq!(field_type("repo"), "app.Repo");
        assert_eq!(field_type("seq"), "list<app.Repo>");
        assert_eq!(field_type("mapping"), "dict<str,app.Repo>");
        assert_eq!(field_type("annotated"), "app.Repo");
        assert_eq!(field_type("created"), "app.Repo");
        assert_eq!(field_type("items"), "list");
    }

    #[test]
    fn project_index_substitutes_generic_base_field_types() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"from typing import Generic, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    item: T

class Repo:
    pass

class RepoBox(Box[Repo]):
    pass
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.RepoBox", "item").as_deref(), Some("app.Repo"));
    }

    #[test]
    fn project_index_substitutes_generic_base_method_returns() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"from typing import Generic, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    item: T

    def current(self) -> T:
        return self.item

class Repo:
    pass

class RepoBox(Box[Repo]):
    pass
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.method_return("app.RepoBox", "current", 0).as_deref(), Some("app.Repo"));
    }

    #[test]
    fn functional_typed_dict_declarations_are_indexed_and_key_sensitive() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"from typing import TypedDict

UserPayload = TypedDict("UserPayload", {"id": int, "name": str})

def handle(payload: UserPayload):
    return payload["id"]
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert!(index.is_typed_dict_class("app.UserPayload"));
        assert_eq!(index.field_type("app.UserPayload", "id").as_deref(), Some("int"));
        assert_eq!(index.typed_dict_key_type("app.UserPayload", "name").as_deref(), Some("str"));
    }

    #[test]
    fn functional_named_tuple_declarations_expose_fields() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"from typing import NamedTuple

Point = NamedTuple("Point", [("x", int), ("y", int)])

def handle(point: Point):
    return point.x
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert!(index.is_named_tuple_class("app.Point"));
        assert_eq!(index.field_type("app.Point", "x").as_deref(), Some("int"));
        assert_eq!(index.field_type("app.Point", "y").as_deref(), Some("int"));
    }


    #[test]
    fn infers_protocol_base_with_type_args() {
        let index = PyProjectIndex::build(&[(
            "repo.py".to_string(),
            r#"from typing import Protocol, TypeVar
T = TypeVar("T")
class Reader(Protocol[T]):
    def get(self) -> T:
        return None
"#
            .to_string(),
        )]);
        assert!(index.is_protocol_class("repo.Reader"));
    }

    #[test]
    fn infers_orm_relationship_field_shapes() {
        let index = PyProjectIndex::build(&[(
            "models.py".to_string(),
            r#"from sqlalchemy.orm import Mapped, relationship

class User:
    pass

class Team:
    owner: Mapped[User]
    members = relationship("User")
"#
            .to_string(),
        )]);
        assert_eq!(index.field_type("models.Team", "owner").as_deref(), Some("models.User"));
        assert_eq!(index.field_type("models.Team", "members").as_deref(), Some("models.User"));
    }

    #[test]
    fn typed_dict_get_is_key_sensitive() {
        let index = PyProjectIndex::build(&[(
            "app.py".to_string(),
            r#"from typing import TypedDict

class Payload(TypedDict):
    id: int
    name: str

def read(payload: Payload):
    return payload.get("id")
"#
            .to_string(),
        )]);
        assert_eq!(index.top_level_return("app.read", 1).as_deref(), Some("int"));
    }

    #[test]
    fn typed_dict_items_return_is_iterable_and_key_sensitive() {
        let index = PyProjectIndex::build(&[(
            "app.py".to_string(),
            r#"from typing import TypedDict

class Payload(TypedDict):
    id: int
    name: str

def read(payload: Payload):
    return payload.items()
"#
            .to_string(),
        )]);
        let ret = index.top_level_return("app.read", 1).expect("typed dict items return");
        assert!(ret.starts_with("generator<tuple<str|"));
    }

    #[test]
    fn dict_keys_and_values_returns_are_typed() {
        let index = PyProjectIndex::build(&[(
            "app.py".to_string(),
            r#"def keys(payload: dict[str, int]):
    return payload.keys()

def values(payload: dict[str, int]):
    return payload.values()
"#
            .to_string(),
        )]);
        assert_eq!(index.top_level_return("app.keys", 1).as_deref(), Some("generator<str>"));
        assert_eq!(index.top_level_return("app.values", 1).as_deref(), Some("generator<int>"));
    }

    #[test]
    fn self_return_types_are_specialized_to_concrete_class() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Self

class Repo:
    def clone(self) -> Self:
        return self
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.method_return("app.Repo", "clone", 0).as_deref(), Some("app.Repo"));
    }

    #[test]
    fn callable_and_awaitable_annotations_are_recovered() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Awaitable, Callable

class Repo:
    pass

Handler = Callable[[str], Repo]

class Service:
    callback: Handler
    pending: Awaitable[Repo]
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Service", "callback").as_deref(), Some("callable<app.Repo>"));
        assert_eq!(index.field_type("app.Service", "pending").as_deref(), Some("app.Repo"));
    }

    #[test]
    fn relationship_uselist_and_self_targets_are_recovered() {
        let entries = vec![(
            "models.py".to_string(),
            r#"from sqlalchemy.orm import relationship

class Node:
    children = relationship("self", uselist=True)
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("models.Node", "children").as_deref(), Some("list<models.Node>"));
    }


    #[test]
    fn normalizes_project_generic_annotations_with_type_args() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Generic, Protocol, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    item: T

class Reader(Protocol[T]):
    def get(self) -> T:
        return None

class Repo:
    pass

class Service:
    box: Box[Repo]
    reader: Reader[Repo]
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Service", "box").as_deref(), Some("app.Box<app.Repo>"));
        assert_eq!(index.field_type("app.Service", "reader").as_deref(), Some("app.Reader<app.Repo>"));
    }

    #[test]
    fn substitutes_instantiated_generic_field_and_method_types() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Generic, Protocol, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    item: T

    def current(self) -> T:
        return self.item

class Reader(Protocol[T]):
    def get(self) -> T:
        return None

class Repo:
    pass
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Box<app.Repo>", "item").as_deref(), Some("app.Repo"));
        assert_eq!(index.method_return("app.Box<app.Repo>", "current", 0).as_deref(), Some("app.Repo"));
        assert_eq!(index.method_return("app.Reader<app.Repo>", "get", 0).as_deref(), Some("app.Repo"));
    }


    #[test]
    fn infers_member_access_and_method_calls_on_instantiated_generic_types() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Generic, TypeVar

T = TypeVar("T")

class Repo:
    pass

class Box(Generic[T]):
    item: T

    def current(self) -> T:
        return self.item

def read(box: Box[Repo]):
    item = box.item
    current = box.current()
    return current
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.read", 1).as_deref(), Some("app.Repo"));
    }

    #[test]
    fn normalizes_pep604_union_annotations_and_typeddict_value_unions() {
        let imports = PyImports::default();
        let env = PyInferenceEnv::default();
        let known = collect_known_classes_from_env(&env);
        assert_eq!(infer_simple_python_type("dict[str, int] | None", &imports, &env, &known).as_deref(), Some("dict<str,int>"));
        assert_eq!(infer_simple_python_type("int | None", &imports, &env, &known).as_deref(), Some("int"));

        let index = PyProjectIndex::build(&[(
            "app.py".to_string(),
            r#"from typing import TypedDict

class Payload(TypedDict):
    title: str
    count: int
"#.to_string(),
        )]);
        assert_eq!(index.typed_dict_value_type("app.Payload").as_deref(), Some("int|str"));
    }

    #[test]
    fn normalizes_typeis_never_unpack_and_concatenate_annotations() {
        let imports = PyImports::default();
        let env = PyInferenceEnv::default();
        let known = collect_known_classes_from_env(&env);
        assert_eq!(infer_simple_python_type("TypeIs[int]", &imports, &env, &known).as_deref(), Some("bool"));
        assert_eq!(infer_simple_python_type("Never", &imports, &env, &known).as_deref(), Some("none"));
        assert_eq!(infer_simple_python_type("Unpack[list[int]]", &imports, &env, &known).as_deref(), Some("list<int>"));
        assert_eq!(infer_simple_python_type("Concatenate[str, int]", &imports, &env, &known).as_deref(), Some("int"));
    }

}
