use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use uniflow_hir::{
    Block, CallTarget, Class, Expr, Field, Item, Language, LValue, Param, ParamKind, Program, Stmt, SymbolId, SymbolKind,
};
use uniflow_parser_core::{
    default_span, ensure_known_symbol, find_matching_brace, find_substring_span, is_int_literal,
    is_probable_type_name, is_string_literal, module_name_from_path, new_call, new_field_read,
    new_int, new_string, new_var_ref, parse_call_parts, span_from_offsets,
    split_last_top_level_dot, split_once_top_level, split_top_level_commas,
    split_top_level_statements_c_like_with_offsets, strip_c_like_comments, ModuleBuilder,
    SourceParser,
};

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

        let snapshot = index.clone();
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
                    Some(snapshot.clone()),
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
    let index = JavaProjectIndex::from_sources(entries);
    let parser = JavaParser::default();
    let mut project = Program::empty(Language::Java);
    for (path, source) in entries {
        let parsed = parser.parse_file_with_index(path, source, Some(&index))?;
        project.merge(parsed);
    }
    Ok(project)
}

impl JavaParser {
    fn parse_file_with_index(
        &self,
        path: &str,
        source: &str,
        project_index: Option<&JavaProjectIndex>,
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
                project_index.cloned(),
            ),
        );

        let class_symbol = builder.add_symbol(&class_name, SymbolKind::Class);
        let class_body = extract_class_body(&source).unwrap_or(source.as_str());
        let parsed_fields = extract_fields(&mut builder, class_body, &resolver);
        let fields = parsed_fields
            .iter()
            .map(|field| field.field.clone())
            .collect::<Vec<_>>();

        let mut methods = Vec::new();
        for method_text in extract_methods(class_body) {
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

#[derive(Clone, Debug)]
struct JavaResolver {
    package_name: Option<String>,
    simple_class_name: String,
    class_name: String,
    exact_imports: HashMap<String, Vec<String>>,
    wildcard_imports: Vec<String>,
    static_exact_imports: HashMap<String, Vec<String>>,
    static_wildcard_imports: Vec<String>,
    project_index: Option<JavaProjectIndex>,
}

impl JavaResolver {
    fn new(
        package_name: Option<String>,
        simple_class_name: String,
        class_name: String,
        project_index: Option<JavaProjectIndex>,
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
        self.project_index.as_ref().and_then(|index| {
            index.method_return_type(
                &self.qualify_type_name(owner_type),
                method_name,
                arg_count,
                arg_types,
            )
        })
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

#[derive(Clone, Debug)]
struct JavaClassDecl {
    simple_name: String,
    bases: Vec<String>,
    span: uniflow_hir::Span,
}

#[derive(Clone, Debug)]
struct JavaMethodText {
    signature: String,
    body: String,
    span: uniflow_hir::Span,
    body_start_byte: usize,
}

#[derive(Clone, Debug)]
struct ParsedMethodSignature {
    method_name: String,
    return_type: Option<String>,
    params_text: String,
    param_types: Vec<String>,
    is_static: bool,
    is_constructor: bool,
    param_count: usize,
}

#[derive(Clone, Debug)]
struct ParsedField {
    field: Field,
    qualified_ty: String,
}

#[derive(Clone, Debug)]
struct IndexedMethodReturnEntry {
    name: String,
    param_types: Vec<String>,
    return_type: String,
}

#[derive(Default)]
struct JavaEnv {
    vars: HashMap<String, SymbolId>,
    types: HashMap<String, String>,
    field_types: HashMap<String, String>,
    this_symbol: Option<SymbolId>,
    current_class: String,
}

fn parse_package(source: &str) -> Option<String> {
    let re = Regex::new(r"(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*;").expect("valid regex");
    re.captures(source)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn qualify_local_class_name(package_name: Option<&str>, simple_class_name: &str) -> String {
    match package_name {
        Some(pkg) if !pkg.is_empty() => format!("{pkg}.{simple_class_name}"),
        _ => simple_class_name.to_string(),
    }
}

fn detect_class_decl(source: &str) -> Option<JavaClassDecl> {
    let re = Regex::new(
        r"(?x)
        \b(?:class|interface|record)\s+([A-Za-z_][A-Za-z0-9_]*)
        (?:\s+extends\s+([A-Za-z0-9_.$]+))?
        (?:\s+implements\s+([A-Za-z0-9_.$,\s]+))?
        "
    )
    .expect("valid regex");
    let caps = re.captures(source)?;
    let whole = caps.get(0)?;
    let simple_name = caps.get(1).map(|m| m.as_str()).unwrap_or("Main").to_string();
    let mut bases = Vec::new();
    if let Some(ext) = caps.get(2) {
        bases.push(ext.as_str().trim().to_string());
    }
    if let Some(impls) = caps.get(3) {
        for part in impls.as_str().split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                bases.push(trimmed.to_string());
            }
        }
    }
    Some(JavaClassDecl {
        simple_name,
        bases,
        span: span_from_offsets(uniflow_hir::FileId(0), source, whole.start(), whole.end()),
    })
}

fn parse_imports(source: &str, builder: &mut ModuleBuilder, mut resolver: JavaResolver) -> JavaResolver {
    let re = Regex::new(r"(?m)^\s*import\s+(static\s+)?([A-Za-z0-9_.*]+)\s*;").expect("valid regex");
    for caps in re.captures_iter(source) {
        let is_static = caps.get(1).is_some();
        let path = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let alias = path.rsplit('.').next().unwrap_or(path).to_string();
        builder.add_import(path, Some(alias.clone()));
        if is_static {
            if path.ends_with(".*") {
                resolver
                    .static_wildcard_imports
                    .push(path.trim_end_matches(".*").to_string());
            } else {
                resolver.static_exact_imports.entry(alias).or_default().push(path.to_string());
            }
            continue;
        }
        if path.ends_with(".*") {
            resolver
                .wildcard_imports
                .push(path.trim_end_matches(".*").to_string());
        } else {
            resolver.exact_imports.entry(alias).or_default().push(path.to_string());
        }
    }
    resolver
}

fn extract_class_body(source: &str) -> Option<&str> {
    let decl_re = Regex::new(r"\b(?:class|interface|record)\b").expect("valid regex");
    let decl = decl_re.find(source)?;
    let open = source[decl.start()..].find('{')? + decl.start();
    let close = find_matching_brace(source, open)?;
    Some(&source[open + 1..close])
}

fn extract_methods(body: &str) -> Vec<JavaMethodText> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < body.len() {
        let Some(open_rel) = body[idx..].find('{') else {
            break;
        };
        let open = idx + open_rel;
        let line_start = body[..open].rfind('\n').map(|n| n + 1).unwrap_or(0);
        let signature = body[line_start..open].trim();
        if is_method_signature(signature) {
            if let Some(close) = find_matching_brace(body, open) {
                let inner = body[open + 1..close].to_string();
                out.push(JavaMethodText {
                    signature: signature.to_string(),
                    body: inner,
                    span: span_from_offsets(uniflow_hir::FileId(0), body, line_start, close + 1),
                    body_start_byte: open + 1,
                });
                idx = close + 1;
                continue;
            }
        }
        idx = open + 1;
    }
    out
}

fn extract_fields(builder: &mut ModuleBuilder, body: &str, resolver: &JavaResolver) -> Vec<ParsedField> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut idx = 0usize;
    let bytes = body.as_bytes();

    while idx < bytes.len() {
        match bytes[idx] as char {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ';' if depth == 0 => {
                let stmt = body[start..=idx].trim();
                if let Some(field) = parse_field_decl(builder, stmt, resolver, start, idx + 1, body) {
                    out.push(field);
                }
                start = idx + 1;
            }
            _ => {}
        }
        idx += 1;
    }

    out
}

fn parse_field_decl(
    builder: &mut ModuleBuilder,
    stmt: &str,
    resolver: &JavaResolver,
    start: usize,
    end: usize,
    body: &str,
) -> Option<ParsedField> {
    let trimmed = stmt.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() || trimmed.contains('(') {
        return None;
    }
    if ["class ", "interface ", "enum ", "@", "return ", "package ", "import "]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
    {
        return None;
    }

    let decl = split_once_top_level(trimmed, '=')
        .map(|(left, _)| left)
        .unwrap_or_else(|| trimmed.to_string());
    let mut pieces = decl
        .split_whitespace()
        .filter(|piece| {
            !matches!(
                *piece,
                "public" | "private" | "protected" | "static" | "final" | "volatile" | "transient"
            )
        })
        .collect::<Vec<_>>();
    if pieces.len() < 2 {
        return None;
    }
    let name = pieces.pop()?.trim().trim_end_matches(';').to_string();
    if name.is_empty() {
        return None;
    }
    let ty_name = pieces.join(" ");
    let qualified_ty = resolver.qualify_type_name(&ty_name);
    let symbol = builder.add_symbol(&name, SymbolKind::Field);
    Some(ParsedField {
        field: Field {
            name,
            symbol: Some(symbol),
            ty: Some(builder.ensure_type(&qualified_ty)),
            span: span_from_offsets(builder.file_id(), body, start, end),
        },
        qualified_ty,
    })
}

fn is_method_signature(signature: &str) -> bool {
    let trimmed = signature.trim();
    trimmed.contains('(')
        && trimmed.contains(')')
        && !trimmed.contains('=')
        && !["if", "for", "while", "switch", "catch", "try", "else"]
            .iter()
            .any(|kw| trimmed.starts_with(kw))
}

fn parse_method_signature(signature: &str, simple_class_name: &str) -> Option<ParsedMethodSignature> {
    let open = signature.find('(')?;
    let close = signature.rfind(')')?;
    if close <= open {
        return None;
    }
    let prefix = signature[..open].trim();
    let params_text = signature[open + 1..close].trim().to_string();
    let raw_params = split_top_level_commas(&params_text)
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>();
    let param_count = raw_params.len();
    let param_types = raw_params
        .iter()
        .map(|part| {
            let pieces = part.split_whitespace().collect::<Vec<_>>();
            if pieces.len() >= 2 {
                pieces[..pieces.len() - 1].join(" ")
            } else {
                "Object".to_string()
            }
        })
        .collect::<Vec<_>>();

    let mut filtered = prefix
        .split_whitespace()
        .filter(|tok| !tok.starts_with('@'))
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return None;
    }

    let is_static = filtered.iter().any(|tok| *tok == "static");
    filtered.retain(|tok| {
        !matches!(
            *tok,
            "public"
                | "private"
                | "protected"
                | "static"
                | "final"
                | "synchronized"
                | "abstract"
                | "native"
                | "default"
                | "strictfp"
        )
    });

    if filtered.is_empty() {
        return None;
    }

    if filtered.len() == 1 {
        let method_name = filtered[0].to_string();
        return Some(ParsedMethodSignature {
            is_constructor: method_name == simple_class_name,
            method_name,
            return_type: None,
            params_text,
            param_types,
            is_static,
            param_count,
        });
    }

    let method_name = filtered.pop()?.to_string();
    let return_type = filtered.join(" ");
    Some(ParsedMethodSignature {
        is_constructor: method_name == simple_class_name,
        method_name,
        return_type: Some(return_type),
        params_text,
        param_types,
        is_static,
        param_count,
    })
}

fn parse_method(
    builder: &mut ModuleBuilder,
    class_name: &str,
    simple_class_name: &str,
    method_text: &JavaMethodText,
    resolver: &JavaResolver,
    class_fields: &[ParsedField],
) -> Option<uniflow_hir::Function> {
    let sig = parse_method_signature(method_text.signature.trim(), simple_class_name)?;
    let mut env = JavaEnv {
        current_class: class_name.to_string(),
        ..Default::default()
    };

    let receiver = if sig.is_static {
        None
    } else {
        let this_symbol = builder.add_symbol("this", SymbolKind::Param);
        env.this_symbol = Some(this_symbol);
        env.vars.insert("this".to_string(), this_symbol);
        env.types.insert("this".to_string(), class_name.to_string());
        Some(Param {
            name: "this".to_string(),
            symbol: this_symbol,
            ty: Some(builder.ensure_type(class_name)),
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            span: method_text.span,
        })
    };

    for field in class_fields {
        env.field_types
            .insert(field.field.name.clone(), field.qualified_ty.clone());
    }

    let mut params = Vec::new();
    for param in split_top_level_commas(&sig.params_text) {
        let part = param.trim();
        if part.is_empty() {
            continue;
        }
        let pieces: Vec<&str> = part.split_whitespace().collect();
        if pieces.is_empty() {
            continue;
        }
        let name = pieces[pieces.len() - 1].to_string();
        let ty_name = if pieces.len() >= 2 {
            pieces[..pieces.len() - 1].join(" ")
        } else {
            "Object".to_string()
        };
        let qualified_ty = resolver.qualify_type_name(&ty_name);
        let symbol = builder.add_symbol(&name, SymbolKind::Param);
        env.vars.insert(name.clone(), symbol);
        env.types.insert(name.clone(), qualified_ty.clone());
        params.push(Param {
            name,
            symbol,
            ty: Some(builder.ensure_type(&qualified_ty)),
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            span: find_substring_span(builder.file_id(), &method_text.body, part, 0),
        });
    }

    let stmts =
        parse_block_statements(builder, &method_text.body, method_text.body_start_byte, resolver, &mut env);
    let body = Block {
        id: builder.alloc_block_id(),
        stmts,
        span: method_text.span,
    };

    let return_type = sig
        .return_type
        .as_ref()
        .map(|ty| builder.ensure_type(&resolver.qualify_type_name(ty)));

    Some(uniflow_hir::Function {
        id: builder.alloc_function_id(),
        name: if sig.is_constructor {
            format!("{class_name}.<init>")
        } else {
            format!("{class_name}.{}", sig.method_name)
        },
        symbol: Some(builder.add_symbol(
            if sig.is_constructor {
                "<init>"
            } else {
                &sig.method_name
            },
            SymbolKind::Method,
        )),
        params,
        captures: Vec::new(),
        return_type,
        body,
        is_method: true,
        receiver,
        span: method_text.span,
    })
}

fn parse_block_statements(
    builder: &mut ModuleBuilder,
    body_text: &str,
    _body_start_byte: usize,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    for (start, end, raw_stmt) in split_top_level_statements_c_like_with_offsets(body_text) {
        let stmt = raw_stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        let span = span_from_offsets(builder.file_id(), body_text, start, end);

        if let Some(rest) = stmt.strip_prefix("return ") {
            let value = parse_expr(builder, rest, resolver, env, span);
            out.push(Stmt::Return {
                id: builder.alloc_stmt_id(),
                value: Some(value),
                span,
            });
            continue;
        }

        if stmt == "return" {
            out.push(Stmt::Return {
                id: builder.alloc_stmt_id(),
                value: None,
                span,
            });
            continue;
        }

        if let Some((left, right)) = split_once_top_level(stmt, '=') {
            if is_declaration(left.as_str(), env) {
                let pieces: Vec<&str> = left.split_whitespace().collect();
                if pieces.len() < 2 {
                    continue;
                }
                let name = pieces[pieces.len() - 1].to_string();
                let raw_ty_name = pieces[..pieces.len() - 1]
                    .iter()
                    .copied()
                    .filter(|piece| !matches!(*piece, "final"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let init = parse_expr(builder, &right, resolver, env, span);
                let qualified_ty = if raw_ty_name.trim() == "var" {
                    infer_expr_type_from_expr(&init, resolver, env)
                        .unwrap_or_else(|| "Object".to_string())
                } else {
                    resolver.qualify_type_name(&raw_ty_name)
                };
                let symbol = builder.add_symbol(&name, SymbolKind::Local);
                env.vars.insert(name.clone(), symbol);
                env.types.insert(name.clone(), qualified_ty.clone());
                out.push(Stmt::Let {
                    id: builder.alloc_stmt_id(),
                    symbol,
                    ty: Some(builder.ensure_type(&qualified_ty)),
                    init: Some(init),
                    span,
                });
            } else {
                let lhs = parse_lvalue(builder, &left, resolver, env, span);
                let rhs = parse_expr(builder, &right, resolver, env, span);
                out.push(Stmt::Assign {
                    id: builder.alloc_stmt_id(),
                    lhs,
                    rhs,
                    span,
                });
            }
            continue;
        }

        let expr = parse_expr(builder, stmt, resolver, env, span);
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr,
            span,
        });
    }
    out
}

fn is_declaration(left: &str, env: &JavaEnv) -> bool {
    let pieces: Vec<&str> = left.split_whitespace().collect();
    if pieces.len() < 2 {
        return false;
    }
    let name = pieces[pieces.len() - 1];
    !env.vars.contains_key(name)
}

fn parse_lvalue(
    builder: &mut ModuleBuilder,
    text: &str,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> LValue {
    let trimmed = text.trim();
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        LValue::Field {
            base: Box::new(parse_expr(builder, &base, resolver, env, span)),
            field,
        }
    } else if env.field_types.contains_key(trimmed) {
        LValue::Field {
            base: Box::new(this_expr(builder, env, span)),
            field: trimmed.to_string(),
        }
    } else {
        let symbol = ensure_known_symbol(builder, &mut env.vars, trimmed, SymbolKind::Local);
        LValue::Var(symbol)
    }
}

fn parse_expr(
    builder: &mut ModuleBuilder,
    text: &str,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> Expr {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        let unknown = ensure_known_symbol(builder, &mut env.vars, "_", SymbolKind::Local);
        return with_span(new_var_ref(builder, unknown), span);
    }

    if let Some(rest) = trimmed.strip_prefix("new ") {
        if let Some((type_name, arg_text)) = parse_call_parts(rest) {
            let args = split_top_level_commas(&arg_text)
                .into_iter()
                .map(|arg| parse_expr(builder, &arg, resolver, env, span))
                .collect::<Vec<_>>();
            return Expr::New {
                id: builder.alloc_expr_id(),
                type_name: resolver.qualify_type_name(&type_name),
                args,
                span,
            };
        }
    }

    if is_string_literal(trimmed) {
        return with_span(new_string(builder, &trimmed[1..trimmed.len() - 1]), span);
    }

    if is_int_literal(trimmed) {
        let value = trimmed.parse::<i64>().unwrap_or_default();
        return with_span(new_int(builder, value), span);
    }

    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_top_level_commas(&arg_text)
            .into_iter()
            .map(|arg| parse_expr(builder, &arg, resolver, env, span))
            .collect::<Vec<_>>();

        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if is_static_receiver(&prefix, env) {
                let qual = resolver.qualify_type_name(prefix.as_str());
                return with_span(new_call(builder, &format!("{qual}.{method}"), None, args), span);
            }

            let receiver_type = infer_expr_type_text(&prefix, resolver, env);
            let receiver = parse_expr(builder, &prefix, resolver, env, span);
            let target = receiver_type
                .as_deref()
                .map(|ty| resolver.qualify_method_target(ty, &method))
                .unwrap_or_else(|| resolve_receiver_method_name(&prefix, &method, resolver, env));
            return with_span(new_call(builder, &target, Some(receiver), args), span);
        }

        if let Some(target) = resolver.resolve_static_member_call(&callee_text) {
            return with_span(new_call(builder, &target, None, args), span);
        }

        if !env.current_class.is_empty() {
            let receiver = env
                .this_symbol
                .map(|_| this_expr(builder, env, span));
            let target = format!("{}.{}", env.current_class, callee_text);
            return with_span(new_call(builder, &target, receiver, args), span);
        }

        let target = resolver.qualify_type_name(&callee_text);
        return with_span(new_call(builder, &target, None, args), span);
    }

    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        let base_expr = parse_expr(builder, &base, resolver, env, span);
        return with_span(new_field_read(builder, base_expr, &field), span);
    }

    if env.field_types.contains_key(trimmed) {
        let this_base = this_expr(builder, env, span);
        return with_span(new_field_read(builder, this_base, trimmed), span);
    }

    let symbol = ensure_known_symbol(builder, &mut env.vars, trimmed, SymbolKind::Local);
    with_span(new_var_ref(builder, symbol), span)
}

fn with_span(expr: Expr, span: uniflow_hir::Span) -> Expr {
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

fn this_expr(builder: &mut ModuleBuilder, env: &mut JavaEnv, span: uniflow_hir::Span) -> Expr {
    let this_symbol = env.this_symbol.unwrap_or_else(|| {
        let symbol = builder.add_symbol("this", SymbolKind::Param);
        env.this_symbol = Some(symbol);
        env.vars.insert("this".to_string(), symbol);
        env.types
            .entry("this".to_string())
            .or_insert_with(|| env.current_class.clone());
        symbol
    });
    with_span(new_var_ref(builder, this_symbol), span)
}

fn is_static_receiver(prefix: &str, env: &JavaEnv) -> bool {
    let first = prefix.split('.').next().unwrap_or(prefix);
    !env.vars.contains_key(first) && is_probable_type_name(first)
}

fn normalize_java_type_name(name: &str) -> &str {
    name.split('<').next().unwrap_or(name)
}

fn is_java_primitive_or_builtin(name: &str) -> bool {
    matches!(
        name,
        "void"
            | "boolean"
            | "byte"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "char"
            | "String"
            | "Object"
    )
}

fn default_java_qualifier(name: &str) -> String {
    match name {
        "HttpServletRequest" => "javax.servlet.http.HttpServletRequest".to_string(),
        "Statement" => "java.sql.Statement".to_string(),
        "Runtime" => "java.lang.Runtime".to_string(),
        "System" => "java.lang.System".to_string(),
        "StringBuilder" => "java.lang.StringBuilder".to_string(),
        _ => name.to_string(),
    }
}

fn unique_import_match(imports: &HashMap<String, Vec<String>>, simple_name: &str) -> Option<String> {
    let entries = imports.get(simple_name)?;
    if entries.len() == 1 {
        Some(entries[0].clone())
    } else {
        None
    }
}

fn resolve_unique_wildcard_type(
    index: &JavaProjectIndex,
    wildcards: &[String],
    simple_name: &str,
) -> Option<String> {
    let mut found = Vec::new();
    for wildcard in wildcards {
        if let Some(candidate) = index.resolve_wildcard(wildcard, simple_name) {
            if !found.iter().any(|existing| existing == &candidate) {
                found.push(candidate);
            }
        }
    }
    if found.len() == 1 {
        found.into_iter().next()
    } else {
        None
    }
}

fn select_best_method_return(
    candidates: &[IndexedMethodReturn],
    arg_types: Option<&[Option<String>]>,
    class_bases: &HashMap<String, Vec<String>>,
) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    let mut best_score: Option<usize> = None;
    let mut best_return: Option<String> = None;
    let mut ambiguous = false;
    for candidate in candidates {
        let Some(score) = method_signature_score(candidate, arg_types, class_bases) else {
            continue;
        };
        match best_score {
            None => {
                best_score = Some(score);
                best_return = Some(candidate.return_type.clone());
                ambiguous = false;
            }
            Some(existing) if score > existing => {
                best_score = Some(score);
                best_return = Some(candidate.return_type.clone());
                ambiguous = false;
            }
            Some(existing) if score == existing => {
                ambiguous = best_return.as_deref() != Some(candidate.return_type.as_str());
            }
            _ => {}
        }
    }
    if ambiguous {
        None
    } else {
        best_return
    }
}

fn method_signature_score(
    candidate: &IndexedMethodReturn,
    arg_types: Option<&[Option<String>]>,
    class_bases: &HashMap<String, Vec<String>>,
) -> Option<usize> {
    let Some(arg_types) = arg_types else {
        return Some(0);
    };
    if candidate.param_types.len() != arg_types.len() {
        return None;
    }
    let mut score = 0usize;
    let mut seen_known = false;
    for (expected, actual) in candidate.param_types.iter().zip(arg_types.iter()) {
        let Some(actual) = actual.as_deref() else {
            continue;
        };
        seen_known = true;
        if actual == expected {
            score += 2;
            continue;
        }
        if inherits_from(actual, expected, class_bases) {
            score += 1;
            continue;
        }
        return None;
    }
    Some(if seen_known { score } else { 0 })
}

fn inherits_from(actual: &str, expected: &str, class_bases: &HashMap<String, Vec<String>>) -> bool {
    if actual == expected {
        return true;
    }
    let mut stack = vec![actual.to_string()];
    let mut seen = Vec::<String>::new();
    while let Some(cur) = stack.pop() {
        if seen.iter().any(|item| item == &cur) {
            continue;
        }
        seen.push(cur.clone());
        if let Some(parents) = class_bases.get(&cur) {
            for parent in parents {
                if parent == expected {
                    return true;
                }
                stack.push(parent.clone());
            }
        }
    }
    false
}

fn resolve_receiver_method_name(
    prefix: &str,
    method: &str,
    resolver: &JavaResolver,
    env: &JavaEnv,
) -> String {
    let root = prefix.split('.').next().unwrap_or(prefix);
    if root == "this" {
        return format!("{}.{}", env.current_class, method);
    }
    if let Some(ty) = env.types.get(root) {
        return resolver.qualify_method_target(ty, method);
    }
    let receiver_name = resolver.qualify_type_name(root);
    format!("{receiver_name}.{method}")
}

fn infer_expr_type_from_expr(expr: &Expr, resolver: &JavaResolver, env: &JavaEnv) -> Option<String> {
    match expr {
        Expr::VarRef { symbol, .. } => env
            .vars
            .iter()
            .find(|(_, sym)| **sym == *symbol)
            .and_then(|(name, _)| env.types.get(name).cloned()),
        Expr::Literal { kind, .. } => match kind {
            uniflow_hir::LiteralKind::String(_) => Some("java.lang.String".to_string()),
            uniflow_hir::LiteralKind::Int(_) => Some("int".to_string()),
            _ => None,
        },
        Expr::FieldRead { base, field, .. } => {
            let base_ty = infer_expr_type_from_expr(base, resolver, env)?;
            resolver.lookup_field_type(&base_ty, field)
        }
        Expr::Call(call) => infer_call_return_type(call, resolver, env),
        Expr::New { type_name, .. } => Some(type_name.clone()),
        Expr::Cast { expr, .. } => infer_expr_type_from_expr(expr, resolver, env),
        _ => None,
    }
}

fn infer_call_return_type(call: &uniflow_hir::CallExpr, resolver: &JavaResolver, env: &JavaEnv) -> Option<String> {
    let arg_count = call.args.len();
    match &call.target {
        CallTarget::Named(name) => {
            let method_name = name.rsplit('.').next()?;
            let owner = name.rsplit_once('.')?.0;
            let arg_types = call_arg_type_list(call, resolver, env);
            resolver.lookup_method_return_type(owner, method_name, Some(arg_count), Some(&arg_types))
        }
        CallTarget::Dynamic(_) => None,
        CallTarget::Resolved(_) => None,
    }
}

fn call_arg_type_list(
    call: &uniflow_hir::CallExpr,
    resolver: &JavaResolver,
    env: &JavaEnv,
) -> Vec<Option<String>> {
    call.args
        .iter()
        .map(|arg| infer_expr_type_from_expr(arg, resolver, env))
        .collect()
}

fn call_arg_type_list_from_text(
    arg_text: &str,
    resolver: &JavaResolver,
    env: &JavaEnv,
) -> Vec<Option<String>> {
    split_top_level_commas(arg_text)
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .map(|part| infer_expr_type_text(&part, resolver, env))
        .collect()
}

fn infer_expr_type_text(text: &str, resolver: &JavaResolver, env: &JavaEnv) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("new ") {
        if let Some((type_name, _)) = parse_call_parts(rest) {
            return Some(resolver.qualify_type_name(&type_name));
        }
    }
    if is_string_literal(trimmed) {
        return Some("java.lang.String".to_string());
    }
    if is_int_literal(trimmed) {
        return Some("int".to_string());
    }
    if trimmed == "this" {
        return Some(env.current_class.clone());
    }
    if let Some(ty) = env.types.get(trimmed) {
        return Some(ty.clone());
    }
    if let Some(field_ty) = env.field_types.get(trimmed) {
        return Some(field_ty.clone());
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let arg_count = split_top_level_commas(&arg_text)
            .into_iter()
            .filter(|part| !part.trim().is_empty())
            .count();
        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if is_static_receiver(&prefix, env) {
                let owner = resolver.qualify_type_name(prefix.as_str());
                return resolver.lookup_method_return_type(&owner, &method, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
            }
            let owner = infer_expr_type_text(&prefix, resolver, env)?;
            return resolver.lookup_method_return_type(&owner, &method, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
        }
        if let Some(target) = resolver.resolve_static_member_call(&callee_text) {
            let method_name = target.rsplit('.').next().unwrap_or(target.as_str());
            let owner = target.rsplit_once('.').map(|(owner, _)| owner).unwrap_or(target.as_str());
            return resolver.lookup_method_return_type(owner, method_name, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
        }
        if !env.current_class.is_empty() {
            return resolver.lookup_method_return_type(&env.current_class, &callee_text, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
        }
        let owner = resolver.qualify_type_name(&callee_text);
        let method = owner.rsplit('.').next().unwrap_or(owner.as_str());
        return resolver.lookup_method_return_type(&owner, method, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        let base_ty = infer_expr_type_text(&base, resolver, env)?;
        return resolver.lookup_field_type(&base_ty, &field);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    #[test]
    fn parses_java_package_receiver_and_fields() {
        let src = r#"
            package demo.app;
            import java.sql.Statement;

            public class UserService {
                private Statement stmt;

                public void run(String q) {
                    execute(q);
                }

                void execute(String q) {
                    stmt.executeQuery(q);
                }
            }
        "#;

        let program = JavaParser::default().parse_file("UserService.java", src).unwrap();
        let class = match &program.modules[0].items[0] {
            Item::Class(class) => class,
            _ => panic!("expected class"),
        };
        assert_eq!(class.name, "demo.app.UserService");
        assert_eq!(class.fields.len(), 1);
        assert!(class.methods.iter().all(|m| m.receiver.is_some()));
        assert!(class
            .methods
            .iter()
            .any(|m| m.name == "demo.app.UserService.run"));
    }

    #[test]
    fn resolves_project_imports_and_wildcards() {
        let entries = vec![
            (
                "src/demo/app/UserService.java".to_string(),
                r#"
                    package demo.app;
                    public class UserService {
                        public String read() {
                            return "x";
                        }
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/web/Controller.java".to_string(),
                r#"
                    package demo.web;
                    import demo.app.*;
                    public class Controller {
                        public void handle() {
                            UserService svc = new UserService();
                            svc.read();
                        }
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.UserService"));
        assert!(rendered.contains("demo.web.Controller.handle"));
    }

    #[test]
    fn qualifies_same_package_new_type() {
        let src = r#"
            package demo.app;
            public class Controller {
                public void handle() {
                    UserService svc = new UserService();
                    svc.run("x");
                }
            }
        "#;

        let program = JavaParser::default().parse_file("Controller.java", src).unwrap();
        let class = match &program.modules[0].items[0] {
            Item::Class(class) => class,
            _ => panic!("expected class"),
        };
        let method = class
            .methods
            .iter()
            .find(|m| m.name.ends_with(".handle"))
            .expect("handle");
        let body_text = format!("{:?}", method.body);
        assert!(body_text.contains("demo.app.UserService"));
    }

    #[test]
    fn infers_var_type_from_project_method_return() {
        let entries = vec![
            (
                "src/demo/app/Repo.java".to_string(),
                r#"
                    package demo.app;
                    public class Repo {
                        public void query(String sql) {}
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/app/UserService.java".to_string(),
                r#"
                    package demo.app;
                    public class UserService {
                        public Repo repo() {
                            return new Repo();
                        }
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/web/Controller.java".to_string(),
                r#"
                    package demo.web;
                    import demo.app.*;
                    public class Controller {
                        public void handle(UserService svc, String sql) {
                            var repo = svc.repo();
                            repo.query(sql);
                        }
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.UserService.repo"));
        assert!(rendered.contains("demo.app.Repo.query"));
    }

    #[test]
    fn resolves_static_imported_method_calls() {
        let entries = vec![
            (
                "src/demo/util/SqlUtil.java".to_string(),
                r#"
                    package demo.util;
                    public class SqlUtil {
                        public static String escape(String sql) { return sql; }
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/web/Controller.java".to_string(),
                r#"
                    package demo.web;
                    import static demo.util.SqlUtil.escape;
                    public class Controller {
                        public String handle(String input) {
                            return escape(input);
                        }
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.util.SqlUtil.escape"));
    }

    #[test]
    fn detects_interface_declarations_in_project_index() {
        let entries = vec![
            (
                "src/demo/app/Repo.java".to_string(),
                r#"
                    package demo.app;
                    public interface Repo {}
                "#
                .to_string(),
            ),
            (
                "src/demo/app/JdbcRepo.java".to_string(),
                r#"
                    package demo.app;
                    public class JdbcRepo implements Repo {
                        public void query(String sql) {}
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.Repo"));
        assert!(rendered.contains("demo.app.JdbcRepo"));
    }

    #[test]
    fn infers_field_type_through_method_chain() {
        let entries = vec![
            (
                "src/demo/app/Repo.java".to_string(),
                r#"
                    package demo.app;
                    public class Repo {
                        public void query(String sql) {}
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/app/UserService.java".to_string(),
                r#"
                    package demo.app;
                    public class UserService {
                        private Repo repo;
                        public Repo current() { return repo; }
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/web/Controller.java".to_string(),
                r#"
                    package demo.web;
                    import demo.app.*;
                    public class Controller {
                        public void handle(UserService svc, String sql) {
                            svc.current().query(sql);
                        }
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.UserService.current"));
        assert!(rendered.contains("demo.app.Repo.query"));
    }

    #[test]
    fn project_index_tracks_overload_return_types_by_arity() {
        let entries = vec![
            (
                "src/demo/app/Repo.java".to_string(),
                r#"
                    package demo.app;
                    public class Repo {
                        public String current() { return "x"; }
                        public int current(int id) { return id; }
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/app/Controller.java".to_string(),
                r#"
                    package demo.app;
                    public class Controller {
                        public void handle() {
                            var repo = new Repo();
                            var sql = repo.current();
                            repo.current(1);
                        }
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.Repo.current"));
    }

}
