//! Per-file top-level orchestration: resolves this file's `import` bindings,
//! then does the two-pass lowering `Program`/`project_index` need — pass 1
//! collects every struct type this FILE declares (`Item::Class` skeletons,
//! fields only), pass 2 walks every function/method/global declaration,
//! attaching a method to its own file's `Class` when the struct is declared
//! in the same file, and pushing it as a standalone `Item::Function`
//! otherwise (its receiver's struct lives in a sibling file of the same
//! package — see the module-level docs on `project_index::GoProjectIndex`
//! for why cross-file method attachment isn't attempted).

use std::collections::HashMap;

use gosyn::ast as go;
use uniflow_hir::{Class, Field, Function, GlobalVar, Item, Param, ParamKind, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::GoEnv;
use crate::frontend::expr::{decode_string_literal_value, expression_qualifier, span_at, type_qualifier};
use crate::frontend::functions::{captures_to_params, lower_function_parts, lower_params};
use crate::frontend::stmt::lower_block;

/// Recursively strips wrapper expressions (pointer, generic instantiation,
/// parens) down to the bare identifier naming a type — used both to decide
/// which file-local struct a method's receiver belongs to (pass 2) and by
/// `expr::type_qualifier`'s own equivalent logic.
fn bare_type_name(expr: &go::Expression) -> Option<&str> {
    match expr {
        go::Expression::Ident(ident) => Some(&ident.name),
        // A type parsed in TYPE position (a receiver's or parameter's
        // declared type) produces `TypePointer`, not the `Star` expression
        // variant — `Star`/`Operation{op: And, ..}` are what a pointer
        // deref/address-of look like in ordinary VALUE position. Both are
        // handled here (and in `expr::type_qualifier`) since a defensive
        // caller could hand either shape to this helper.
        go::Expression::TypePointer(pointer) => bare_type_name(&pointer.typ),
        go::Expression::Star(star) => bare_type_name(&star.right),
        go::Expression::Index(index) => bare_type_name(&index.left),
        go::Expression::IndexList(index) => bare_type_name(&index.left),
        go::Expression::Paren(paren) => bare_type_name(&paren.expr),
        _ => None,
    }
}

/// Binds every `import` this file declares. `resolve_import` maps an
/// import's full path text to a project-internal package's own qualified
/// name (its declared `package` clause) when that path resolves to another
/// file in this project (see `project_index::GoProjectIndex::resolve_import`);
/// otherwise the import's raw path text itself is used as the qualifier,
/// matching what the legacy Go rule catalog's `regex`/`method_regex`
/// matchers expect for a standard-library package (`"net/http"`, `"os"`).
pub(crate) fn bind_imports(env: &mut GoEnv, file: &go::File, resolve_import: &dyn Fn(&str) -> Option<String>) {
    for import in &file.imports {
        let import_path = decode_string_literal_value(&import.path.value);
        let local_name = match &import.name {
            // A blank import (`import _ "pkg"`, for side effects only) or a
            // dot import (`import . "pkg"`, merging all exported names into
            // this file's scope) binds no single namespace identifier this
            // frontend can track; skipped rather than guessed at.
            Some(ident) if ident.name == "_" || ident.name == "." => continue,
            Some(ident) => ident.name.clone(),
            None => import_path.rsplit('/').next().unwrap_or(&import_path).to_string(),
        };
        let qualifier = resolve_import(&import_path).unwrap_or_else(|| import_path.clone());
        env.set_import_binding(local_name, qualifier);
    }
}

fn lower_struct_fields(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, fields: &[go::Field]) -> Vec<Field> {
    let mut out = Vec::with_capacity(fields.len());
    for field in fields {
        let ty = type_qualifier(env, &field.typ).map(|qualifier| builder.ensure_type(&qualifier));
        if field.name.is_empty() {
            // An embedded field (anonymous struct embedding) uses its own
            // type's name as the implicit field name.
            if let Some(bare) = bare_type_name(&field.typ) {
                let bare = bare.to_string();
                out.push(Field { name: bare.clone(), symbol: Some(builder.add_symbol(&bare, SymbolKind::Field)), ty, span: span_at(builder, source, field.typ.pos()) });
            }
            continue;
        }
        for ident in &field.name {
            out.push(Field { name: ident.name.clone(), symbol: Some(builder.add_symbol(&ident.name, SymbolKind::Field)), ty, span: span_at(builder, source, ident.pos) });
        }
    }
    out
}

/// cgo's real spec: an unindented `//export Name` comment on the line
/// immediately before a function definition marks it callable from C when
/// this package is built as a C archive/shared library (`go build
/// -buildmode=c-archive`) — the reverse direction from an ordinary Go->C
/// `C.foo(...)` call. `FuncDecl.docs` already only holds comments gosyn
/// determined were directly, contiguously attached to this declaration (see
/// the parser's `lead_comments`/`clear_lead_comments` handling), so no extra
/// blank-line/indentation check is needed here.
fn cgo_export_marker(decl: &go::FuncDecl) -> bool {
    decl.docs.iter().any(|comment| {
        comment
            .text
            .strip_prefix("//export")
            .is_some_and(|rest| rest.split_whitespace().next() == Some(decl.name.name.as_str()))
    })
}

fn lower_free_function(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, decl: &go::FuncDecl, package_qualifier: &str) -> Function {
    let name = format!("{package_qualifier}.{}", decl.name.name);
    let symbol = builder.add_symbol(&decl.name.name, SymbolKind::Function);
    if cgo_export_marker(decl) {
        // Consumed by `uniflow_system_graph::go_ffi` to mark this function as
        // an entrypoint reachable from an external C caller, mirroring how
        // `lifecycle.rs` treats a Spring `@PostConstruct`-annotated method as
        // reachable from outside without an ordinary source-level call.
        builder.set_symbol_attribute(symbol, "go.cgo.export", "true".to_string());
    }
    let (params, body, captures) = lower_function_parts(builder, env, source, &decl.typ.params, |builder, env, source| {
        decl.body.as_ref().map(|body| lower_block(builder, env, source, body)).unwrap_or_else(|| builder.empty_block())
    });
    Function {
        id: builder.alloc_function_id(),
        name,
        symbol: Some(symbol),
        params,
        captures: captures_to_params(captures),
        return_type: None,
        body,
        is_method: false,
        receiver: None,
        cpp: None,
        cpp_initializers: Vec::new(),
        span: span_at(builder, source, decl.name.pos),
    }
}

fn lower_method(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, decl: &go::FuncDecl, recv_field: &go::Field, package_qualifier: &str, bare_type: &str) -> Function {
    let class_name = format!("{package_qualifier}.{bare_type}");
    let name = format!("{class_name}.{}", decl.name.name);
    let symbol = builder.add_symbol(&decl.name.name, SymbolKind::Method);

    env.enter_function();
    let receiver_name = recv_field.name.first().map(|ident| ident.name.clone()).unwrap_or_else(|| "$receiver".to_string());
    let receiver_symbol = builder.add_symbol(&receiver_name, SymbolKind::Param);
    env.declare(&receiver_name, receiver_symbol);
    // Every method's own receiver gets `value_qualifier` set to its own
    // class's qualified name, so a call like `s.Method()` from within
    // ANOTHER method on the same receiver also resolves — not just a call
    // reached through an ordinary typed parameter.
    env.set_value_qualifier(receiver_symbol, class_name.clone());
    let params = lower_params(builder, env, source, &decl.typ.params);
    let body = decl.body.as_ref().map(|body| lower_block(builder, env, source, body)).unwrap_or_else(|| builder.empty_block());
    let captures = env.leave_function();

    let receiver_param = Param {
        name: receiver_name,
        symbol: receiver_symbol,
        ty: Some(builder.ensure_type(&class_name)),
        kind: ParamKind::Positional,
        has_default: false,
        keyword_only: false,
        cpp: Default::default(),
        span: span_at(builder, source, recv_field.typ.pos()),
    };

    Function {
        id: builder.alloc_function_id(),
        name,
        symbol: Some(symbol),
        params,
        captures: captures_to_params(captures),
        return_type: None,
        body,
        is_method: true,
        receiver: Some(receiver_param),
        cpp: None,
        cpp_initializers: Vec::new(),
        span: span_at(builder, source, decl.name.pos),
    }
}

fn lower_global_binding_group(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, names: &[go::Ident], typ: &Option<go::Expression>, values: &[go::Expression], out: &mut Vec<GlobalVar>) {
    let explicit_qualifier = typ.as_ref().and_then(|t| type_qualifier(env, t));
    let package_qualifier = env.package_qualifier().to_string();
    for (index, name) in names.iter().enumerate() {
        if name.name == "_" {
            continue;
        }
        let value = if names.len() == values.len() { values.get(index) } else { values.first() };
        let qualifier = explicit_qualifier.clone().or_else(|| value.and_then(|value_expr| expression_qualifier(env, value_expr)));
        let init = value.map(|value_expr| crate::frontend::expr::lower_expr(builder, env, source, value_expr));
        let symbol = builder.add_symbol(&name.name, SymbolKind::Global);
        env.declare(&name.name, symbol);
        if let Some(qualifier) = &qualifier {
            env.set_value_qualifier(symbol, qualifier.clone());
        }
        let ty = qualifier.map(|q| builder.ensure_type(&q));
        out.push(GlobalVar { name: format!("{package_qualifier}.{}", name.name), symbol: Some(symbol), ty, init, span: span_at(builder, source, name.pos) });
    }
}

/// Lowers one file's top-level declarations into `builder`'s module. `env`
/// must already have this file's imports bound (see [`bind_imports`]) and
/// this package's cross-file free-function/type registrations pre-loaded
/// (see `project_index`) before this runs; this also performs a redundant
/// local registration of the same file's own declarations so a standalone,
/// no-project-index parse (`GoParser::parse_file`) still resolves same-file
/// forward references correctly.
pub(crate) fn lower_file(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, file: &go::File) {
    let package_qualifier = env.package_qualifier().to_string();

    // Pass 0: register this file's own top-level free functions and type
    // names before lowering any function body, mirroring real Go's
    // whole-package visibility (a call to a function declared later in this
    // same file, or in a sibling file the project index didn't cover in
    // standalone mode, must still resolve).
    for decl in &file.decl {
        match decl {
            go::Declaration::Function(func_decl) if func_decl.recv.is_none() => {
                env.register_package_function(func_decl.name.name.clone(), format!("{package_qualifier}.{}", func_decl.name.name));
            }
            go::Declaration::Type(type_decl) => {
                for spec in &type_decl.specs {
                    env.register_package_type(spec.name.name.clone());
                }
            }
            _ => {}
        }
    }

    // Pass 1: collect this file's own struct declarations.
    struct LocalStruct<'a> {
        name: String,
        name_pos: usize,
        fields: &'a [go::Field],
    }
    let mut local_structs = Vec::new();
    for decl in &file.decl {
        if let go::Declaration::Type(type_decl) = decl {
            for spec in &type_decl.specs {
                if let go::Expression::TypeStruct(struct_type) = &spec.typ {
                    local_structs.push(LocalStruct { name: spec.name.name.clone(), name_pos: spec.name.pos, fields: &struct_type.fields });
                }
            }
        }
    }
    let mut class_index: HashMap<String, usize> = HashMap::new();
    let mut classes: Vec<Class> = Vec::with_capacity(local_structs.len());
    for local_struct in &local_structs {
        let class_name = format!("{package_qualifier}.{}", local_struct.name);
        let class_symbol = builder.add_symbol(&local_struct.name, SymbolKind::Class);
        let fields = lower_struct_fields(builder, env, source, local_struct.fields);
        class_index.insert(local_struct.name.clone(), classes.len());
        classes.push(Class { name: class_name, symbol: Some(class_symbol), bases: Vec::new(), fields, methods: Vec::new(), span: span_at(builder, source, local_struct.name_pos) });
    }

    // Pass 2: functions, methods, and package-level var/const globals.
    let mut standalone_functions: Vec<Function> = Vec::new();
    let mut global_vars: Vec<GlobalVar> = Vec::new();
    for decl in &file.decl {
        match decl {
            go::Declaration::Function(func_decl) => match &func_decl.recv {
                None => standalone_functions.push(lower_free_function(builder, env, source, func_decl, &package_qualifier)),
                Some(recv_list) => {
                    let Some(recv_field) = recv_list.list.first() else { continue };
                    let bare_type = bare_type_name(&recv_field.typ).unwrap_or_default().to_string();
                    let method = lower_method(builder, env, source, func_decl, recv_field, &package_qualifier, &bare_type);
                    match class_index.get(&bare_type) {
                        Some(&index) => classes[index].methods.push(method),
                        None => standalone_functions.push(method),
                    }
                }
            },
            go::Declaration::Variable(var_decl) => {
                for spec in &var_decl.specs {
                    lower_global_binding_group(builder, env, source, &spec.name, &spec.typ, &spec.values, &mut global_vars);
                }
            }
            go::Declaration::Const(const_decl) => {
                for spec in &const_decl.specs {
                    lower_global_binding_group(builder, env, source, &spec.name, &spec.typ, &spec.values, &mut global_vars);
                }
            }
            go::Declaration::Type(_) => {}
        }
    }

    for class in classes {
        builder.push_item(Item::Class(class));
    }
    for function in standalone_functions {
        builder.push_item(Item::Function(function));
    }
    for global in global_vars {
        builder.push_item(Item::GlobalVar(global));
    }
}
