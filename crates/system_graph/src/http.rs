//! HTTP service-stitching adapter: recognizes a statically-evident inbound
//! route registration (`router.get("/path", Service::handler)`) and a
//! statically-evident outbound call (`client.get(url)`, where `url` is
//! built from literal text plus, optionally, a resolved `getenv` value),
//! then recovers PRECISE per-field value mappings — *which* query field
//! corresponds to *which* handler parameter — rather than declaring every
//! handler parameter tainted.
//!
//! Route recognition has two layers: a small, generic HTTP-verb-shaped
//! method name convention (`get`/`post`/`put`/`delete`/`patch`/`route`/
//! `handle`, incidentally matching Express/axios/requests-shaped calls) for
//! frameworks with no dedicated recognizer yet, plus a real per-framework
//! recognizer where one has been written — Flask/FastAPI decorators
//! ([`python_decorator_routes`]) and Spring MVC annotations
//! ([`spring_annotation_routes`]) so far. A future framework (Express's own
//! router API, Rails, ...) needs its own recognizer producing the *same*
//! normalized facts; the generic convention remains the fallback in the
//! meantime, not a replacement for one.
//!
//! ## Why field-level precision is recoverable here
//!
//! Source-level string concatenation (`a + b + c`) lowers, in this
//! codebase's `lang_java` frontend, to *nested* `Phi` merges matching the
//! expression's own left-associative structure (empirically confirmed —
//! `base + "/x?id=" + id` becomes `Phi(Phi(base, "/x?id="), id)`), so
//! [`crate::ir_utils::resolve_string_sequence`] recovers the original
//! left-to-right literal/dynamic sequence, not just an unordered bag of
//! pieces. Reconstructing that sequence with a unique placeholder standing
//! in for each dynamic piece, then parsing the result as an ordinary query
//! string, recovers exact field-name-to-value correspondence — including
//! correctly leaving a field's value **unmapped** when it is a literal
//! constant, or when a placeholder is *mixed* with other text (neither
//! case has a single value worth naming). A mapped dynamic value only
//! becomes a precise [`BoundaryFlowEdge`] when it resolves (through
//! `Copy`/`Phi`) to exactly one of the caller's own formal parameters
//! ([`crate::ir_utils::parameter_index`]) — anything else is left
//! unmapped rather than guessed.

use std::collections::{HashMap, HashSet};

use anyhow::Result;

use uniflow_ir::{Callee, Function, InstKind, Program, ValueId};
use uniflow_rules::Port;

use crate::config::{getenv_name_for_result, resolve_env_literal};
use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};
use crate::ir_utils::{is_python_root_alias, parameter_index, parameter_index_by_name, resolve_callable_argument, resolve_string_sequence, FunctionIndex, StringPiece};

// `handlefunc` is Go's own convention (`http.HandleFunc`/`mux.HandleFunc`,
// stdlib `net/http`) — the same literal-path-plus-callable-argument shape
// this generic table already recognizes for every other framework, so no
// dedicated recognizer is needed for it. gin's `router.GET(...)`/`.POST(...)`
// etc. already match the existing `get`/`post`/... markers (case-insensitive
// last-segment method-name matching).
const ROUTE_REGISTRATION_METHODS: &[&str] = &["get", "post", "put", "delete", "patch", "route", "api_route", "handle", "handlefunc"];
// `getforobject`/`postforobject`/`getforentity`/`postforentity` are Spring's
// `RestTemplate` methods — unambiguous enough (unlike a generic `exchange`)
// to add unconditionally, without a receiver-type heuristic: the URL is
// always the RestTemplate call's own first argument, matching this
// module's existing model exactly.
const OUTBOUND_CALL_METHODS: &[&str] =
    &["get", "post", "put", "delete", "patch", "request", "fetch", "getforobject", "postforobject", "getforentity", "postforentity"];

/// Lowercased so a receiver-value method call (`rt.postForObject(...)`,
/// camelCase per Java convention) matches this module's all-lowercase
/// marker tables the same way a plain lowercase static call already does.
fn method_name(callee: &str) -> String {
    callee.rsplit('.').next().unwrap_or(callee).to_ascii_lowercase()
}

fn http_verb_for(marker: &str) -> String {
    match marker {
        "get" | "post" | "put" | "delete" | "patch" => marker.to_ascii_uppercase(),
        "getforobject" | "getforentity" => "GET".to_string(),
        "postforobject" | "postforentity" => "POST".to_string(),
        _ => "GET".to_string(),
    }
}

fn route_id(method: &str, path: &str) -> String {
    format!("http:route:{method}:{path}")
}

fn direct_literal(function: &uniflow_ir::Function, value: ValueId) -> Option<String> {
    match resolve_string_sequence(function, value).as_slice() {
        [StringPiece::Literal(text)] => Some(text.clone()),
        _ => None,
    }
}

/// Extracts Flask/FastAPI-style route decorators retained by the Python
/// frontend as raw attributes, for example `@app.get("/profile")` and
/// `@router.route("/profile", methods=["POST"])`.  The first decorator
/// argument must be a literal quoted path; interpolated/dynamic registrations
/// are intentionally ignored.
fn python_decorator_routes(function: &uniflow_ir::Function) -> Vec<(String, String)> {
    let Some(raw) = function.attrs.get("python.decorators.raw") else { return Vec::new() };
    raw.split('\u{1f}')
        .filter_map(|decorator| {
            let text = decorator.trim().trim_start_matches('@').trim();
            let (callee, args) = text.split_once('(')?;
            let method_marker = callee.rsplit('.').next()?.to_ascii_lowercase();
            if !ROUTE_REGISTRATION_METHODS.contains(&method_marker.as_str()) {
                return None;
            }
            let args = args.strip_suffix(')')?.trim();
            let first = args.split(',').next()?.trim();
            let quote = first.chars().next()?;
            if !matches!(quote, '\'' | '"') || !first.ends_with(quote) || first.len() < 3 {
                return None;
            }
            let path = first[1..first.len() - 1].to_string();
            if !path.starts_with('/') {
                return None;
            }
            let method = if matches!(method_marker.as_str(), "route" | "api_route") {
                if let Some((_, methods)) = args.split_once("methods") {
                    let quote = methods.chars().find(|ch| matches!(ch, '\'' | '"'))?;
                    let start = methods.find(quote)? + 1;
                    let rest = &methods[start..];
                    let end = rest.find(quote)?;
                    rest[..end].to_ascii_uppercase()
                } else {
                    "GET".to_string()
                }
            } else {
                http_verb_for(&method_marker)
            };
            Some((method, path))
        })
        .collect()
}

const SPRING_MAPPING_ANNOTATIONS: &[(&str, &str)] =
    &[("getmapping", "GET"), ("postmapping", "POST"), ("putmapping", "PUT"), ("deletemapping", "DELETE"), ("patchmapping", "PATCH")];

fn extract_quoted(text: &str) -> Option<String> {
    let quote = text.chars().find(|ch| matches!(ch, '\'' | '"'))?;
    let start = text.find(quote)? + 1;
    let rest = &text[start..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// ASP.NET Core accepts both `"api/users"` and `"/api/users"` in route
/// attributes. Normalize only a non-empty literal without route-template
/// tokens; templates need framework substitution and must remain unresolved.
fn normalize_aspnet_literal_path(path: String) -> Option<String> {
    if path.is_empty() || path.contains(['[', ']', '{', '}']) {
        return None;
    }
    Some(if path.starts_with('/') { path } else { format!("/{path}") })
}

/// A mapping annotation's route path, from either a positional
/// (`@GetMapping("/x")`) or named (`@GetMapping(value = "/x")` /
/// `@GetMapping(path = "/x")`) argument. Only one literal path candidate is
/// ever accepted — an unrecognized leading named argument (neither a bare
/// literal nor `value`/`path`) is left unresolved rather than guessed.
fn mapping_path(args: &str) -> Option<String> {
    for marker in ["value", "path"] {
        if let Some(pos) = args.find(marker) {
            let after = &args[pos + marker.len()..];
            if after.trim_start().starts_with('=') {
                if let Some(path) = extract_quoted(after) {
                    return Some(path);
                }
            }
        }
    }
    let first = args.split(',').next()?.trim();
    if first.contains('=') {
        return None;
    }
    extract_quoted(first)
}

/// Extracts Spring MVC-style route annotations retained by the Java
/// frontend as a raw attribute (`@GetMapping("/profile")`,
/// `@RequestMapping(value = "/profile", method = RequestMethod.POST)`).
fn spring_annotation_routes(function: &uniflow_ir::Function) -> Vec<(String, String)> {
    let Some(raw) = function.attrs.get("java.annotations.raw") else { return Vec::new() };
    raw.split('\u{1f}')
        .filter_map(|annotation| {
            let text = annotation.trim().trim_start_matches('@').trim();
            let (name, args) = text.split_once('(')?;
            let args = args.strip_suffix(')')?.trim();
            let name_lower = name.rsplit('.').next()?.to_ascii_lowercase();
            let method = if let Some(&(_, verb)) = SPRING_MAPPING_ANNOTATIONS.iter().find(|(marker, _)| *marker == name_lower) {
                verb.to_string()
            } else if name_lower == "requestmapping" {
                args.find("method")
                    .map(|pos| &args[pos + "method".len()..])
                    .and_then(|after| after.split_once('='))
                    .and_then(|(_, rest)| rest.trim().trim_matches(|c: char| matches!(c, ',' | ')')).rsplit('.').next())
                    .map(str::to_ascii_uppercase)
                    .unwrap_or_else(|| "GET".to_string())
            } else {
                return None;
            };
            let path = mapping_path(args)?;
            if !path.starts_with('/') {
                return None;
            }
            Some((method, path))
        })
        .collect()
}

/// A conservative Spring class-level `@RequestMapping` prefix.  A class
/// mapping with a `method = ...` constraint participates in Spring's route
/// condition intersection, so simply prepending it to a method route can
/// manufacture an invalid endpoint; leave that more complex case unresolved
/// until the full condition model exists.  An unconstrained literal prefix is
/// exact and is by far the normal controller idiom.
fn spring_class_path_prefix(function: &uniflow_ir::Function) -> Option<String> {
    let raw = function.attrs.get("java.class.annotations.raw")?;
    raw.split('\u{1f}').find_map(|annotation| {
        let text = annotation.trim().trim_start_matches('@').trim();
        let (name, args) = text.split_once('(')?;
        if name.rsplit('.').next()?.eq_ignore_ascii_case("RequestMapping") {
            let args = args.strip_suffix(')')?.trim();
            if args.contains("method") {
                return None;
            }
            let path = mapping_path(args)?;
            if path.starts_with('/') { Some(path) } else { None }
        } else {
            None
        }
    })
}

fn join_spring_paths(prefix: &str, path: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    let path = if path.starts_with('/') { path } else { return path.to_string() };
    if prefix.is_empty() || prefix == "/" {
        path.to_string()
    } else if path == "/" {
        prefix.to_string()
    } else {
        format!("{prefix}{path}")
    }
}

const RUST_ROUTE_MACRO_VERBS: &[(&str, &str)] = &[("get", "GET"), ("post", "POST"), ("put", "PUT"), ("delete", "DELETE"), ("patch", "PATCH")];

/// Extracts actix-web's and Rocket's shared attribute-macro route
/// convention (`#[get("/profile")]`, `#[route("/profile", method =
/// "GET")]`), retained by the Rust frontend as a raw attribute — same shape
/// as [`spring_annotation_routes`], just Rust's macro-attribute syntax
/// instead of an annotation. The first attribute argument must be a literal
/// quoted path; interpolated/dynamic registrations are intentionally
/// ignored, same as the Python/Spring recognizers above.
fn rust_attribute_macro_routes(function: &uniflow_ir::Function) -> Vec<(String, String)> {
    let Some(raw) = function.attrs.get("rust.attributes.raw") else { return Vec::new() };
    raw.split('\u{1f}')
        .filter_map(|attribute| {
            let text = attribute.trim().trim_start_matches('#').trim().trim_start_matches('[').trim_end_matches(']').trim();
            let (name, args) = text.split_once('(')?;
            let args = args.strip_suffix(')')?.trim();
            let name_lower = name.trim().rsplit("::").next()?.to_ascii_lowercase();
            let method = if let Some(&(_, verb)) = RUST_ROUTE_MACRO_VERBS.iter().find(|(marker, _)| *marker == name_lower) {
                verb.to_string()
            } else if name_lower == "route" {
                args.find("method")
                    .map(|pos| &args[pos + "method".len()..])
                    .and_then(|after| after.split_once('='))
                    .and_then(|(_, rest)| extract_quoted(rest))
                    .map(|verb| verb.to_ascii_uppercase())
                    .unwrap_or_else(|| "GET".to_string())
            } else {
                return None;
            };
            let first = args.split(',').next()?.trim();
            let path = extract_quoted(first)?;
            if !path.starts_with('/') {
                return None;
            }
            Some((method, path))
        })
        .collect()
}

/// Axum's own route-registration idiom, `.route("/path", get(handler))` —
/// unlike the generic `ROUTE_REGISTRATION_METHODS` convention below (which
/// expects a *direct* callable reference as the second argument), axum's
/// verb function (`get`/`post`/`put`/`delete`/`patch`) wraps the handler in
/// its own call. Recovers the handler when it resolves via
/// [`resolve_callable_argument`] — the common case of an inline closure
/// (`get(|req| { ... })`) or a hoisted-lambda-shaped forwarding reference.
/// A bare *named* function passed by reference (`get(my_handler)`) is a
/// known, deliberately unhandled gap: this frontend (like every other one
/// in this codebase today) has no general "a bare identifier value refers
/// to a real named function" concept, so recovering that case soundly
/// (without guessing at a same-named-but-unrelated function) needs a real
/// frontend/engine enhancement, not a text-matching trick here.
fn axum_wrapped_handler(program: &Program, function: &uniflow_ir::Function, arg: ValueId) -> Option<String> {
    for block in &function.blocks {
        for inst in &block.insts {
            let InstKind::Call(call) = &inst.kind else { continue };
            if call.dst != Some(arg) {
                continue;
            }
            let Callee::Static(name) = &call.callee else { continue };
            if !matches!(method_name(name).as_str(), "get" | "post" | "put" | "delete" | "patch") {
                continue;
            }
            let [only_arg] = call.args.as_slice() else { continue };
            return resolve_callable_argument(program, function, *only_arg);
        }
    }
    None
}

/// Express (and Express-shaped Koa/Connect) middleware registration —
/// `app.use(middlewareFn)` or `app.use('/prefix', middlewareFn)`. Unlike an
/// ordinary route (`app.get('/path', handler)`), middleware has no
/// required HTTP verb and commonly no path at all (global middleware runs
/// on every request), so it is modeled as a bare [`NodeKind::Entrypoint`]
/// rather than an `HttpRoute --HANDLES-->` fact — the caller only needs to
/// know the handler is externally reachable, not which specific route
/// leads to it. Accepts the handler as either the first argument (no path)
/// or the second (a literal path prefix as the first argument); a
/// non-literal path prefix is still accepted since, unlike a route, the
/// path itself carries no per-field taint-mapping value here.
fn express_middleware_handler(program: &Program, function: &uniflow_ir::Function, call: &uniflow_ir::CallInst) -> Option<String> {
    call.args.iter().find_map(|&arg| resolve_callable_argument(program, function, arg).or_else(|| axum_wrapped_handler(program, function, arg)))
}

const ASPNET_HTTP_ATTRIBUTES: &[(&str, &str)] =
    &[("httpget", "GET"), ("httppost", "POST"), ("httpput", "PUT"), ("httpdelete", "DELETE"), ("httppatch", "PATCH")];

/// Extracts ASP.NET Core attribute-routing annotations retained by the
/// descriptor engine's C# support as a raw attribute (`csharp.attributes.raw`
/// — see `crates/lang_frontends`' `add_csharp_attributes_raw`), for example
/// `[HttpGet("/profile")]` or a bare `[Route("/profile")]` (accepted as any
/// method, a documented approximation — ASP.NET itself would restrict a bare
/// `[Route]` by whatever `[AcceptVerbs]`/HTTP-verb attribute accompanies it,
/// which this does not attempt to combine). Mirrors `spring_annotation_routes`'s
/// structure exactly.
fn csharp_attribute_routes(function: &uniflow_ir::Function) -> Vec<(String, String)> {
    let Some(raw) = function.attrs.get("csharp.attributes.raw") else { return Vec::new() };
    raw.split('\u{1f}')
        .filter_map(|attribute| {
            let attribute = attribute.trim();
            let (name, args) = attribute.split_once('(').unwrap_or((attribute, ""));
            let args = args.strip_suffix(')').unwrap_or(args).trim();
            let name_lower = name.trim().to_ascii_lowercase();
            let method = if let Some(&(_, verb)) = ASPNET_HTTP_ATTRIBUTES.iter().find(|(marker, _)| *marker == name_lower) {
                verb.to_string()
            } else if name_lower == "route" {
                "GET".to_string()
            } else {
                return None;
            };
            let path = normalize_aspnet_literal_path(extract_quoted(args)?)?;
            Some((method, path))
        })
        .collect()
}

/// ASP.NET Core's common `[Route("/api")]` controller prefix.  Controller
/// token templates such as `[controller]`, route parameters, and verb-bearing
/// class attributes all need ASP.NET's route-template/constraint semantics,
/// so they are intentionally not flattened into a literal path here.
fn csharp_class_path_prefix(function: &uniflow_ir::Function) -> Option<String> {
    let raw = function.attrs.get("csharp.class.attributes.raw")?;
    raw.split('\u{1f}').find_map(|attribute| {
        let attribute = attribute.trim();
        let (name, args) = attribute.split_once('(')?;
        if !name.trim().rsplit('.').next()?.eq_ignore_ascii_case("Route") {
            return None;
        }
        normalize_aspnet_literal_path(extract_quoted(args.strip_suffix(')').unwrap_or(args))?)
    })
}

/// Every handler a route currently resolves to (a route id maps to more
/// than one handler exactly when two independent registrations collide on
/// the same literal method+path — an ambiguity this module represents
/// explicitly, see [`discover_outbound_calls_into`], rather than picking
/// one arbitrarily).
fn handlers_for_route(graph: &SystemGraph, route_id: &str) -> Vec<CodeRef> {
    graph
        .edges()
        .filter(|(from, _, edge)| edge.kind == EdgeKind::Handles && from.id == route_id)
        .filter_map(|(_, to, _)| to.code_ref.clone())
        .collect()
}

/// A Go method named exactly `ServeHTTP` with a receiver implements the
/// stdlib `http.Handler` interface — by Go convention (structural typing,
/// not a declared `impl`) this makes it reachable from any caller that
/// registers the receiver type via `http.Handle`/`http.ListenAndServe`,
/// regardless of which literal path it ends up registered under. Marked
/// directly as a real [`NodeKind::Entrypoint`] with no route path attached
/// (the same "structural recognition, no call site needed" shape
/// `crate::lifecycle` uses for a Spring `@PostConstruct` hook) rather than
/// attempting to resolve the registration call's receiver-instance type,
/// which this adapter does not track.
fn is_go_servehttp_handler(program: &Program, function: &uniflow_ir::Function) -> bool {
    program.language == uniflow_hir::Language::Go && function.name.rsplit('.').next() == Some("ServeHTTP") && function.name.contains('.')
}

/// A Rails controller action: `lang_ruby` tags every instance method of a
/// class inheriting `ApplicationController`/`ActionController::Base`/`::API`
/// with a `"ruby.rails.controller_action"` attribute (Rails' own
/// convention-over-configuration routing has no per-action
/// decorator/annotation the way Spring/Flask do) — the same "structural
/// recognition, no call site needed" shape as [`is_go_servehttp_handler`].
fn is_rails_controller_action(program: &Program, function: &uniflow_ir::Function) -> bool {
    program.language == uniflow_hir::Language::Ruby && function.attrs.contains_key("ruby.rails.controller_action")
}

/// Scans `program` for inbound route registrations, recording each as an
/// `HttpRoute --HANDLES--> Function` fact.
pub fn discover_routes_into(graph: &mut SystemGraph, program: &Program) -> Result<()> {
    let language_tag = program.language.as_str();
    let mut registered = HashSet::new();
    for function in &program.functions {
        if is_python_root_alias(program, function) {
            continue;
        }
        if is_go_servehttp_handler(program, function) || is_rails_controller_action(program, function) {
            let handler_id = format!("code:{language_tag}:{}", function.name);
            graph.upsert_node(
                SystemNode::new(NodeKind::Entrypoint, handler_id.clone(), &function.name).with_code_ref(CodeRef {
                    language: program.language.clone(),
                    qualified_name: function.name.clone(),
                }),
            );
            // A structural entrypoint (no literal route path the way an
            // annotation/decorator carries one) still needs a `Handles`
            // edge, not just a bare node — `bridge::handler_source_rules`'
            // external-ingress fallback (the mechanism that lets a handler
            // no analyzed caller reaches still be treated as attacker-
            // reachable) only ever looks at `EdgeKind::Handles` edges, so a
            // node with no edge at all would silently never get a taint
            // source, defeating the whole point of recognizing it. The
            // "route" side is synthetic — there is no real path — but still
            // a distinct node so this handler is never mistaken for
            // "internally called" by an unrelated `HTTP_CALL` edge.
            let route_node_id = format!("structural-entrypoint:{language_tag}:{}", function.name);
            graph.upsert_node(SystemNode::new(NodeKind::HttpRoute, route_node_id.clone(), format!("structural entrypoint: {}", function.name)));
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::Handles, route_node_id, handler_id, Confidence::Inferred)
                    .with_evidence(Evidence::new(format!("{} is a structurally recognized entrypoint with no literal route path", function.name))),
            )?;
        }
        // Python's decorator and Spring's annotation both register the
        // handler on itself, not via a call in another function. This
        // precedes the generic call pattern below but produces exactly the
        // same graph shape.
        let spring_prefix = spring_class_path_prefix(function);
        let csharp_prefix = csharp_class_path_prefix(function);
        for (method, path, evidence) in python_decorator_routes(function)
            .into_iter()
            .map(|(m, p)| (m, p, "declares Python HTTP route"))
            .chain(spring_annotation_routes(function).into_iter().map(|(m, p)| {
                let path = spring_prefix.as_deref().map(|prefix| join_spring_paths(prefix, &p)).unwrap_or(p);
                (m, path, "declares a Spring MVC route")
            }))
            .chain(rust_attribute_macro_routes(function).into_iter().map(|(m, p)| (m, p, "declares an actix-web/Rocket HTTP route")))
            .chain(csharp_attribute_routes(function).into_iter().map(|(m, p)| {
                let path = csharp_prefix.as_deref().map(|prefix| join_spring_paths(prefix, &p)).unwrap_or(p);
                (m, path, "declares an ASP.NET Core route attribute")
            }))
        {
            if !registered.insert((method.clone(), path.clone(), function.name.clone())) {
                continue;
            }
            let route_node_id = route_id(&method, &path);
            graph.upsert_node(SystemNode::new(NodeKind::HttpRoute, route_node_id.clone(), format!("{method} {path}")));
            let handler_node_id = format!("code:{language_tag}:{}", function.name);
            graph.upsert_node(
                SystemNode::new(NodeKind::Function, handler_node_id.clone(), &function.name).with_code_ref(CodeRef {
                    language: program.language.clone(),
                    qualified_name: function.name.clone(),
                }),
            );
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::Handles, route_node_id, handler_node_id, Confidence::Exact).with_evidence(
                    Evidence::new(format!("{} {evidence} {method} {path} via annotation", function.name)),
                ),
            )?;
        }
        for block in &function.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else { continue };
                let Callee::Static(name) = &call.callee else { continue };
                if method_name(name) == "use" {
                    if let Some(handler_name) = express_middleware_handler(program, function, call) {
                        let handler_id = format!("code:{language_tag}:{handler_name}");
                        graph.upsert_node(
                            SystemNode::new(NodeKind::Entrypoint, handler_id, &handler_name)
                                .with_code_ref(CodeRef { language: program.language.clone(), qualified_name: handler_name.clone() }),
                        );
                    }
                    continue;
                }
                if !ROUTE_REGISTRATION_METHODS.contains(&method_name(name).as_str()) {
                    continue;
                }
                let Some(&path_arg) = call.args.first() else { continue };
                let Some(path_literal) = direct_literal(function, path_arg) else { continue };
                if !path_literal.starts_with('/') {
                    continue;
                }
                let Some(handler_name) = call
                    .args
                    .iter()
                    .skip(1)
                    .find_map(|&arg| resolve_callable_argument(program, function, arg).or_else(|| axum_wrapped_handler(program, function, arg)))
                else {
                    continue;
                };

                let method = http_verb_for(&method_name(name));
                if !registered.insert((method.clone(), path_literal.clone(), handler_name.clone())) {
                    continue;
                }
                let route_node_id = route_id(&method, &path_literal);
                graph.upsert_node(SystemNode::new(NodeKind::HttpRoute, route_node_id.clone(), format!("{method} {path_literal}")));
                let handler_node_id = format!("code:{language_tag}:{handler_name}");
                graph.upsert_node(
                    SystemNode::new(NodeKind::Function, handler_node_id.clone(), &handler_name).with_code_ref(CodeRef {
                        language: program.language.clone(),
                        qualified_name: handler_name.clone(),
                    }),
                );
                graph.apply_boundary(
                    BoundarySummary::new(EdgeKind::Handles, route_node_id, handler_node_id, Confidence::Exact).with_evidence(
                        Evidence::new(format!("{} registers route {method} {path_literal} -> {handler_name}", function.name)),
                    ),
                )?;
            }
        }
    }
    Ok(())
}

enum FieldValue {
    /// A hardcoded constant — nothing to track; a literal cannot be a
    /// taint source, so this field intentionally gets no mapping at all
    /// (see the negative tests in `crates/cli/tests/system_graph_analysis.rs`).
    Literal,
    /// Exactly one dynamic piece, cleanly attributable.
    Dynamic(ValueId),
    /// A dynamic piece combined with other text (or more than one dynamic
    /// piece) inside the same field's value — the individual contribution
    /// can't be named precisely, so this is left unmapped rather than
    /// guessed.
    Mixed,
}

fn reconstruct_with_placeholders(sequence: &[StringPiece]) -> (String, HashMap<String, ValueId>) {
    let mut text = String::new();
    let mut placeholders = HashMap::new();
    for (index, piece) in sequence.iter().enumerate() {
        match piece {
            StringPiece::Literal(literal) => text.push_str(literal),
            StringPiece::Dynamic(value) => {
                let token = format!("\u{1}D{index}\u{1}");
                placeholders.insert(token.clone(), *value);
                text.push_str(&token);
            }
        }
    }
    (text, placeholders)
}

fn split_path_and_query(text: &str) -> (String, Vec<(String, String)>) {
    let after_scheme = text.find("://").map(|index| &text[index + 3..]).unwrap_or(text);
    let slash = after_scheme.find('/').unwrap_or(0);
    let rest = &after_scheme[slash..];
    match rest.split_once('?') {
        Some((path, query)) => {
            let fields =
                query.split('&').filter_map(|pair| pair.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
            (path.to_string(), fields)
        }
        None => (rest.to_string(), Vec::new()),
    }
}

fn resolve_field_value(value_text: &str, placeholders: &HashMap<String, ValueId>) -> FieldValue {
    if let Some(&value_id) = placeholders.get(value_text) {
        return FieldValue::Dynamic(value_id);
    }
    if placeholders.keys().any(|token| value_text.contains(token.as_str())) {
        return FieldValue::Mixed;
    }
    FieldValue::Literal
}

/// Recovers the literal key -> value correspondence of a JavaScript/Ruby map
/// literal that lowering has explicitly marked with
/// `__uniflow.compose.map`.  A bare `Phi` is deliberately not accepted: the
/// IR also uses it for control-flow joins, where input position does not mean
/// key/value position.  This makes the body model conservative by
/// construction and avoids treating arbitrary POST payloads as JSON.
fn literal_map_fields(function: &Function, value: ValueId) -> Vec<(String, ValueId)> {
    let mut definitions = HashMap::new();
    for block in &function.blocks {
        for inst in &block.insts {
            match &inst.kind {
                InstKind::Copy { dst, src } => {
                    definitions.insert(*dst, (Some(*src), None));
                }
                InstKind::Phi { dst, inputs } => {
                    definitions.insert(*dst, (None, Some(inputs.as_slice())));
                }
                InstKind::Call(call) if call.dst.is_some() => {
                    let source = matches!(&call.callee, Callee::Static(name) if name == "__uniflow.compose.map")
                        .then(|| call.args.first().copied())
                        .flatten();
                    definitions.insert(call.dst.expect("checked"), (source, None));
                }
                _ => {}
            }
        }
    }

    let mut current = value;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current) {
            return Vec::new();
        }
        let Some((copy_source, phi_inputs)) = definitions.get(&current) else { return Vec::new() };
        if let Some(source) = copy_source {
            current = *source;
            continue;
        }
        let Some(inputs) = phi_inputs else { return Vec::new() };
        return inputs
            .chunks_exact(2)
            .filter_map(|pair| direct_literal(function, pair[0]).map(|key| (key, pair[1])))
            .collect();
    }
}

/// Direct map payloads for the conventional `(url, body, ...)` forms. A
/// `request(...)`/`fetch(...)` options object has framework-specific method
/// and nested-body semantics, so it is intentionally left for a dedicated
/// framework model rather than guessed here.
fn direct_body_values(method: &str, args: &[ValueId]) -> impl Iterator<Item = ValueId> {
    matches!(method, "post" | "put" | "patch" | "postforobject" | "postforentity")
        .then(|| args.get(1).copied())
        .flatten()
        .into_iter()
}

/// Replaces any dynamic piece that is itself a resolvable `getenv(...)`
/// result with its known literal value, so a base URL built from
/// configuration (`Http.get(getenv("URL") + "/path?id=" + x)`) still
/// resolves to a concrete host — without that substitution, the whole
/// sequence would otherwise be indistinguishable from a call with no
/// determinable target at all. Returns whether any substitution happened
/// (used to grade confidence `Inferred` rather than `Exact`).
fn substitute_resolved_env_pieces(
    sequence: &[StringPiece],
    function: &uniflow_ir::Function,
    graph: &SystemGraph,
) -> (Vec<StringPiece>, bool) {
    let mut resolved_any = false;
    let mut out = Vec::with_capacity(sequence.len());
    for piece in sequence {
        if let StringPiece::Dynamic(value) = piece {
            if let Some(env_name) = getenv_name_for_result(function, *value) {
                if let Some(literal) = resolve_env_literal(graph, &env_name) {
                    out.push(StringPiece::Literal(literal));
                    resolved_any = true;
                    continue;
                }
            }
        }
        out.push(piece.clone());
    }
    (out, resolved_any)
}

/// One resolved outbound HTTP call, kept for the (topology-only, coarse)
/// `HTTP_CALL` graph edge and diagnostics; the precise per-field
/// consequences are already folded into that edge's own `value_mappings`
/// by the time this is returned.
#[derive(Clone, Debug)]
pub struct OutboundHttpCall {
    pub caller_function: String,
    pub callee_name: String,
    pub route_ids: Vec<String>,
    pub confidence: Confidence,
}

/// Scans `program` for outbound HTTP-shaped calls and, for each whose
/// target route is already known (via a prior [`discover_routes_into`]
/// pass over *every* group — this must run after all groups' routes are
/// registered), recovers precise per-field [`BoundaryFlowEdge`]s using
/// `function_index` to look up the target handler's own parameter names
/// across whichever language/group it lives in.
pub fn discover_outbound_calls_into(
    graph: &mut SystemGraph,
    program: &Program,
    function_index: &FunctionIndex<'_>,
) -> Result<Vec<OutboundHttpCall>> {
    let language_tag = program.language.as_str();
    let mut calls = Vec::new();
    for function in &program.functions {
        if is_python_root_alias(program, function) {
            continue;
        }
        for block in &function.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else { continue };
                let Callee::Static(name) = &call.callee else { continue };
                if !OUTBOUND_CALL_METHODS.contains(&method_name(name).as_str()) {
                    continue;
                }
                let Some(&url_arg) = call.args.first() else { continue };
                let raw_sequence = resolve_string_sequence(function, url_arg);
                let (sequence, host_resolved_via_env) = substitute_resolved_env_pieces(&raw_sequence, function, graph);
                let (reconstructed, placeholders) = reconstruct_with_placeholders(&sequence);
                let (bare_path, query_fields) = split_path_and_query(&reconstructed);
                if !bare_path.starts_with('/') {
                    continue;
                }

                let method = http_verb_for(&method_name(name));
                let expected_route_id = route_id(&method, &bare_path);
                if !graph.contains(&expected_route_id) {
                    continue;
                }

                let handlers = handlers_for_route(graph, &expected_route_id);
                let route_is_ambiguous = handlers.len() > 1;
                let base_confidence = if host_resolved_via_env { Confidence::Inferred } else { Confidence::Exact };

                let call_site_id = format!("code:{language_tag}:{}#{}", function.name, inst.id.0);
                graph.upsert_node(SystemNode::new(NodeKind::CallSite, call_site_id.clone(), name.clone()).with_code_ref(CodeRef {
                    language: program.language.clone(),
                    qualified_name: function.name.clone(),
                }));

                let mut summary = BoundarySummary::new(EdgeKind::HttpCall, call_site_id, expected_route_id.clone(), base_confidence)
                    .with_evidence(Evidence::new(format!("{} calls {name}(...) matching route {method} {bare_path}", function.name)));

                for (field_name, value_text) in &query_fields {
                    let FieldValue::Dynamic(value_id) = resolve_field_value(value_text, &placeholders) else {
                        // Literal (a hardcoded constant — nothing to map) or
                        // Mixed (can't be attributed to one value) — both
                        // intentionally produce no mapping.
                        continue;
                    };
                    let Some(caller_param_index) = parameter_index(function, value_id) else {
                        // Not (through Copy/Phi) one of the caller's own
                        // parameters — e.g. a separate call's result. Not
                        // yet supported; see this crate's docs for why.
                        continue;
                    };
                    for handler in &handlers {
                        let Some((handler_language, handler_function)) = function_index.get(&handler.qualified_name) else {
                            continue;
                        };
                        let Some(handler_param_index) = parameter_index_by_name(handler_function, field_name) else {
                            continue;
                        };
                        let mapping_confidence = if route_is_ambiguous { Confidence::Conservative } else { base_confidence };
                        let from = FlowNodeRef::function_port(program.language.clone(), function.name.clone(), Port::Arg(caller_param_index));
                        let to = FlowNodeRef::function_port(handler_language.clone(), handler.qualified_name.clone(), Port::Arg(handler_param_index));
                        summary = summary.with_value_mapping(
                            BoundaryFlowEdge::new(ValueMappingKind::ArgumentToParameter, from, to, mapping_confidence).with_evidence(
                                Evidence::new(format!("query field {field_name:?} bound to parameter {field_name:?} of {}", handler.qualified_name)),
                            ),
                        );
                    }
                }

                // A direct object/map literal supplied as the conventional
                // second argument to POST/PUT/PATCH carries the same kind of
                // field-level contract as a query string. Only lowering's
                // explicit map-composition marker is accepted here; dynamic
                // serializers and generic options objects remain unresolved
                // until their framework model can prove a correspondence.
                for body in direct_body_values(&method_name(name), &call.args) {
                    for (field_name, value) in literal_map_fields(function, body) {
                        let Some(caller_param_index) = parameter_index(function, value) else {
                            continue;
                        };
                        for handler in &handlers {
                            let Some((handler_language, handler_function)) = function_index.get(&handler.qualified_name) else {
                                continue;
                            };
                            let Some(handler_param_index) = parameter_index_by_name(handler_function, &field_name) else {
                                continue;
                            };
                            let mapping_confidence = if route_is_ambiguous { Confidence::Conservative } else { base_confidence };
                            summary = summary.with_value_mapping(
                                BoundaryFlowEdge::new(
                                    ValueMappingKind::ArgumentToParameter,
                                    FlowNodeRef::function_port(program.language.clone(), function.name.clone(), Port::Arg(caller_param_index)),
                                    FlowNodeRef::function_port(handler_language.clone(), handler.qualified_name.clone(), Port::Arg(handler_param_index)),
                                    mapping_confidence,
                                )
                                .with_evidence(Evidence::new(format!(
                                    "literal request-body field {field_name:?} binds to parameter {field_name:?} of {}",
                                    handler.qualified_name
                                ))),
                            );
                        }
                    }
                }

                graph.apply_boundary(summary)?;
                calls.push(OutboundHttpCall {
                    caller_function: function.name.clone(),
                    callee_name: name.clone(),
                    route_ids: vec![expected_route_id],
                    confidence: base_confidence,
                });
            }
        }
    }
    Ok(calls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    fn lower_java(source: &str) -> Program {
        let hir = uniflow_lang_java::JavaParser::default().parse_file("Probe.java", source).expect("parse java");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_js(source: &str) -> Program {
        let hir = uniflow_lang_javascript::JavaScriptParser::default()
            .parse_file("client.js", source)
            .expect("parse javascript");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_go(source: &str) -> Program {
        let hir = uniflow_lang_go::GoParser::default().parse_file("main.go", source).expect("parse go");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_ruby(source: &str) -> Program {
        let hir = uniflow_lang_ruby::RubyParser::default().parse_file("app.rb", source).expect("parse ruby");
        uniflow_lowering::lower_program(&hir)
    }

    // NOTE on the two tests below: they pass an inline closure
    // (`func(...) { ... }`), not a bare top-level function name
    // (`http.HandleFunc("/profile", handler)`), as the handler argument.
    // That's a deliberate, known gap this work surfaced rather than fixed:
    // `resolve_callable_argument` (`crate::ir_utils`) only resolves an
    // argument value through `Function::value_types`, which
    // `uniflow_lowering` only populates for a *synthesized* lambda
    // (an inline closure, or a Java-style `Type::method` reference
    // desugared into one) — a bare identifier naming an ordinary top-level
    // function is never given a `value_types` entry by any frontend today,
    // Go included. Fixing that is a shared-`uniflow_lowering` change
    // affecting every language, not a Go-specific one, so it's out of scope
    // here; flagged for the coordinating session instead of silently
    // routing around it with a same-arity closure that resolves for a
    // different reason.
    #[test]
    fn recovers_a_net_http_handlefunc_route_registered_via_an_inline_closure() {
        let program = lower_go(
            r#"
package main

import "net/http"

func registerRoutes() {
	http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	})
}

func handler(w http.ResponseWriter, r *http.Request) {}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        assert!(graph.contains("http:route:GET:/profile"));
        let handles: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Handles).collect();
        assert_eq!(handles.len(), 1, "{handles:?}");
        assert_eq!(handles[0].1.name, "main.handler");
    }

    #[test]
    fn recovers_a_gin_style_get_route_registered_via_an_inline_closure() {
        let program = lower_go(
            r#"
package main

func registerRoutes(router *gin.Engine) {
	router.GET("/profile", func(c *gin.Context) {
		handler(c)
	})
}

func handler(c *gin.Context) {}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        assert!(graph.contains("http:route:GET:/profile"));
        let handles: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Handles).collect();
        assert_eq!(handles.len(), 1, "{handles:?}");
        assert_eq!(handles[0].1.name, "main.handler");
    }

    #[test]
    fn a_servehttp_method_is_a_structural_entrypoint_with_no_route() {
        let program = lower_go(
            r#"
package main

type MyHandler struct{}

func (h *MyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        assert!(graph.contains("code:go:main.MyHandler.ServeHTTP"));
    }

    #[test]
    fn a_rails_controller_action_is_a_structural_entrypoint_with_no_route() {
        let program = lower_ruby(
            r#"
class UsersController < ApplicationController
  def show
    render json: params[:id]
  end
end
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        assert!(graph.contains("code:ruby:app.UsersController.show"));
    }

    #[test]
    fn a_plain_ruby_class_method_is_not_treated_as_an_entrypoint() {
        let program = lower_ruby(
            r#"
class Widget
  def show
  end
end
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        assert!(!graph.contains("code:ruby:app.Widget.show"));
    }

    #[test]
    fn recovers_a_route_registered_via_method_reference() {
        let program = lower_java(
            r#"
class ServiceB {
    static void registerRoutes() {
        route("/profile", ServiceB::handler);
    }

    static void handler(String id) {}
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        assert!(graph.contains("http:route:GET:/profile"));
        let handles: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Handles).collect();
        assert_eq!(handles.len(), 1, "{handles:?}");
        assert_eq!(handles[0].1.name, "ServiceB.handler");
    }

    #[test]
    fn recovers_a_fastapi_style_python_decorator_route() {
        let hir = uniflow_lang_python::PythonParser::default()
            .parse_file(
                "src/api.py",
                r#"
@app.post("/profile")
def handler(id):
    pass
"#,
            )
            .expect("parse python");
        let program = uniflow_lowering::lower_program(&hir);
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        let routes: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Handles).collect();
        assert_eq!(routes.len(), 1, "{routes:?}");
        assert_eq!(routes[0].0.id, "http:route:POST:/profile");
        assert_eq!(routes[0].1.code_ref.as_ref().map(|code| code.qualified_name.as_str()), Some("handler"));
    }

    #[test]
    fn recovers_a_spring_mvc_get_mapping_route() {
        let program = lower_java(
            r#"
class ProfileController {
    @GetMapping("/profile")
    String handler(String id) { return id; }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        let routes: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Handles).collect();
        assert_eq!(routes.len(), 1, "{routes:?}");
        assert_eq!(routes[0].0.id, "http:route:GET:/profile");
        assert_eq!(routes[0].1.code_ref.as_ref().map(|code| code.qualified_name.as_str()), Some("ProfileController.handler"));
    }

    #[test]
    fn combines_an_unconstrained_spring_class_prefix_with_a_method_mapping() {
        let route_program = lower_java(
            r#"
@RequestMapping("/api/v1")
class ProfileController {
    @GetMapping("/profile")
    String handler(String id) { return id; }
}
"#,
        );
        let caller_program = lower_java(
            r#"
class Gateway {
    static void forward(String userInput) {
        Http.get("/api/v1/profile?id=" + userInput);
    }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &route_program).expect("discover routes");
        assert!(graph.contains("http:route:GET:/api/v1/profile"));
        assert!(!graph.contains("http:route:GET:/profile"));
        let programs = vec![
            (uniflow_hir::Language::Java, route_program),
            (uniflow_hir::Language::Java, caller_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        discover_outbound_calls_into(&mut graph, &caller_program, &index).expect("discover outbound call");
        let call = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).expect("HTTP call");
        assert_eq!(call.2.value_mappings.len(), 1, "{:#?}", call.2.value_mappings);
        assert_eq!(call.2.value_mappings[0].from.function, "Gateway.forward");
        assert_eq!(call.2.value_mappings[0].to.function, "ProfileController.handler");
    }

    #[test]
    fn does_not_guess_through_a_verb_constrained_spring_class_mapping() {
        let program = lower_java(
            r#"
@RequestMapping(value = "/api", method = RequestMethod.POST)
class ProfileController {
    @GetMapping("/profile")
    String handler(String id) { return id; }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        // Spring would reject the GET/POST condition intersection. The
        // adapter must not fabricate `/api/profile`; its method-level fact is
        // intentionally retained as the existing conservative fallback.
        assert!(!graph.contains("http:route:GET:/api/profile"));
        assert!(graph.contains("http:route:GET:/profile"));
    }

    #[test]
    fn recovers_an_aspnet_core_http_get_attribute_route() {
        let hir = uniflow_lang_frontends::parse_file(
            uniflow_hir::Language::CSharp,
            "ProfileController.cs",
            r#"
class ProfileController {
    [HttpGet("/profile")]
    public string Handler(string id) { return id; }
}
"#,
        )
        .expect("parse csharp");
        let program = uniflow_lowering::lower_program(&hir);
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        let routes: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Handles).collect();
        assert_eq!(routes.len(), 1, "{routes:?}");
        assert_eq!(routes[0].0.id, "http:route:GET:/profile");
        assert_eq!(routes[0].1.code_ref.as_ref().map(|code| code.qualified_name.as_str()), Some("ProfileController.Handler"));
    }

    #[test]
    fn combines_a_literal_aspnet_controller_prefix_and_stitches_a_caller_field() {
        let route_program = uniflow_lowering::lower_program(
            &uniflow_lang_frontends::parse_file(
                uniflow_hir::Language::CSharp,
                "ProfileController.cs",
                r#"
[Route("api")]
class ProfileController {
    [HttpGet("profile")]
    public string Handler(string id) { return id; }
}
"#,
            )
            .expect("parse csharp"),
        );
        let caller_program = uniflow_lowering::lower_program(
            &uniflow_lang_frontends::parse_file(
                uniflow_hir::Language::CSharp,
                "Gateway.cs",
                r#"
class Gateway {
    public void Forward(string userInput) {
        Http.get("/api/profile?id=" + userInput);
    }
}
"#,
            )
            .expect("parse csharp"),
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &route_program).expect("discover routes");
        assert!(graph.contains("http:route:GET:/api/profile"));
        let programs = vec![
            (uniflow_hir::Language::CSharp, route_program),
            (uniflow_hir::Language::CSharp, caller_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        discover_outbound_calls_into(&mut graph, &caller_program, &index).expect("discover outbound call");
        let call = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).expect("HTTP call");
        assert_eq!(call.2.value_mappings.len(), 1, "{:#?}", call.2.value_mappings);
        assert_eq!(call.2.value_mappings[0].from.function, "Gateway.Forward");
        assert_eq!(call.2.value_mappings[0].to.function, "ProfileController.Handler");
    }

    #[test]
    fn does_not_flatten_an_aspnet_controller_token_template() {
        let program = uniflow_lowering::lower_program(
            &uniflow_lang_frontends::parse_file(
                uniflow_hir::Language::CSharp,
                "ProfileController.cs",
                r#"
[Route("/api/[controller]")]
class ProfileController {
    [HttpGet("/profile")]
    public string Handler(string id) { return id; }
}
"#,
            )
            .expect("parse csharp"),
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        assert!(!graph.contains("http:route:GET:/api/[controller]/profile"));
        assert!(graph.contains("http:route:GET:/profile"));
    }

    #[test]
    fn recovers_a_spring_mvc_request_mapping_with_explicit_method_and_named_value() {
        let program = lower_java(
            r#"
class ProfileController {
    @RequestMapping(value = "/profile", method = RequestMethod.POST)
    String handler(String id) { return id; }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        let routes: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Handles).collect();
        assert_eq!(routes.len(), 1, "{routes:?}");
        assert_eq!(routes[0].0.id, "http:route:POST:/profile");
    }

    #[test]
    fn a_bare_request_mapping_with_no_arguments_registers_no_route() {
        // No literal path is recoverable from `@RequestMapping` alone (it
        // would only be meaningful combined with a class-level prefix,
        // which this adapter does not yet recover) — must not be guessed.
        let program = lower_java(
            r#"
class ProfileController {
    @RequestMapping
    String handler(String id) { return id; }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &program).expect("discover routes");
        assert_eq!(graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Handles).count(), 0);
    }

    #[test]
    fn a_spring_handler_gets_a_precise_field_mapping_from_an_outbound_caller() {
        let route_program = lower_java(
            r#"
class ProfileController {
    @GetMapping("/profile")
    String handler(String id) { return id; }
}
"#,
        );
        let call_program = lower_java(
            r#"
class ServiceA {
    static void run(String userInput) {
        Http.get("/profile?id=" + userInput);
    }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &route_program).expect("discover routes");
        let programs = vec![(uniflow_hir::Language::Java, route_program), (uniflow_hir::Language::Java, call_program.clone())];
        let index = FunctionIndex::build(&programs);
        discover_outbound_calls_into(&mut graph, &call_program, &index).expect("discover outbound calls");

        let http_calls: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).collect();
        assert_eq!(http_calls.len(), 1, "{http_calls:?}");
        let mappings = &http_calls[0].2.value_mappings;
        assert_eq!(mappings.len(), 1, "{mappings:?}");
        assert_eq!(mappings[0].to.function, "ProfileController.handler");
        assert_eq!(mappings[0].to.port, Port::Arg(0));
    }

    #[test]
    fn maps_a_literal_javascript_post_body_field_to_the_matching_handler_parameter() {
        let route_program = lower_java(
            r#"
class ProfileController {
    @PostMapping("/profile")
    String handler(String id) { return id; }
}
"#,
        );
        let call_program = lower_js(
            r#"
function run(userInput) {
    Http.post("http://user/profile", { id: userInput, fixed: "constant" });
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &route_program).expect("discover routes");
        let programs = vec![
            (uniflow_hir::Language::Java, route_program),
            (uniflow_hir::Language::JavaScript, call_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        discover_outbound_calls_into(&mut graph, &call_program, &index).expect("discover outbound calls");
        let http_calls: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).collect();
        assert_eq!(http_calls.len(), 1, "{http_calls:?}");
        let mappings = &http_calls[0].2.value_mappings;
        assert_eq!(mappings.len(), 1, "{mappings:?}");
        assert_eq!(mappings[0].from.function, "client.run");
        assert_eq!(mappings[0].from.port, Port::Arg(0));
        assert_eq!(mappings[0].to.function, "ProfileController.handler");
        assert_eq!(mappings[0].to.port, Port::Arg(0));
        assert!(mappings[0]
            .evidence
            .iter()
            .any(|evidence| evidence.description.contains("request-body field \"id\"")));
    }

    #[test]
    fn recognizes_a_resttemplate_postforobject_call_as_a_post() {
        let route_program = lower_java(
            r#"
class ServiceB {
    @PostMapping("/profile")
    String handler(String id) { return id; }
}
"#,
        );
        let call_program = lower_java(
            r#"
class ServiceA {
    static void run(RestTemplate rt, String userInput, Object body, Class responseType) {
        rt.postForObject("/profile?id=" + userInput, body, responseType);
    }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &route_program).expect("discover routes");
        let programs = vec![(uniflow_hir::Language::Java, route_program), (uniflow_hir::Language::Java, call_program.clone())];
        let index = FunctionIndex::build(&programs);
        let calls = discover_outbound_calls_into(&mut graph, &call_program, &index).expect("discover outbound calls");
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].route_ids, vec!["http:route:POST:/profile".to_string()]);
        let http_calls: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).collect();
        assert_eq!(http_calls[0].2.value_mappings.len(), 1);
    }

    #[test]
    fn stitches_an_outbound_call_to_its_registered_route_with_a_precise_field_mapping() {
        let route_program = lower_java(
            r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id) {}
}
"#,
        );
        let call_program = lower_java(
            r#"
class ServiceA {
    static void run(String userInput) {
        String base = System.getenv("USER_SERVICE_URL");
        String url = base + "/profile?id=" + userInput;
        Http.get(url);
    }
}
"#,
        );

        let mut graph = SystemGraph::new();
        graph.upsert_node(
            SystemNode::new(NodeKind::EnvironmentVariable, "compose:env:api:USER_SERVICE_URL", "USER_SERVICE_URL")
                .with_attr("value", "http://user:8080"),
        );
        discover_routes_into(&mut graph, &route_program).expect("discover routes");
        let programs = vec![
            (uniflow_hir::Language::Java, route_program),
            (uniflow_hir::Language::Java, call_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        let calls = discover_outbound_calls_into(&mut graph, &call_program, &index).expect("discover outbound calls");

        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].route_ids, vec!["http:route:GET:/profile".to_string()]);
        assert_eq!(calls[0].confidence, Confidence::Inferred);

        let http_calls: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).collect();
        assert_eq!(http_calls.len(), 1, "{http_calls:?}");
        let mappings = &http_calls[0].2.value_mappings;
        assert_eq!(mappings.len(), 1, "{mappings:?}");
        assert_eq!(mappings[0].from.function, "ServiceA.run");
        assert_eq!(mappings[0].from.port, Port::Arg(0));
        assert_eq!(mappings[0].to.function, "ServiceB.handler");
        assert_eq!(mappings[0].to.port, Port::Arg(0));
    }

    #[test]
    fn a_literal_query_field_produces_no_value_mapping() {
        let route_program = lower_java(
            r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id) {}
}
"#,
        );
        let call_program = lower_java(
            r#"
class ServiceA {
    static void run() {
        Http.get("/profile?id=constant");
    }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &route_program).expect("discover routes");
        let programs = vec![(uniflow_hir::Language::Java, route_program), (uniflow_hir::Language::Java, call_program.clone())];
        let index = FunctionIndex::build(&programs);
        discover_outbound_calls_into(&mut graph, &call_program, &index).expect("discover outbound calls");

        let http_calls: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).collect();
        assert_eq!(http_calls.len(), 1, "{http_calls:?}");
        assert!(http_calls[0].2.value_mappings.is_empty(), "{:?}", http_calls[0].2.value_mappings);
    }

    #[test]
    fn only_the_dynamic_field_among_several_gets_a_mapping() {
        let route_program = lower_java(
            r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id, String lang) {}
}
"#,
        );
        let call_program = lower_java(
            r#"
class ServiceA {
    static void run(String langValue) {
        Http.get("/profile?id=constant&lang=" + langValue);
    }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &route_program).expect("discover routes");
        let programs = vec![(uniflow_hir::Language::Java, route_program), (uniflow_hir::Language::Java, call_program.clone())];
        let index = FunctionIndex::build(&programs);
        discover_outbound_calls_into(&mut graph, &call_program, &index).expect("discover outbound calls");

        let http_calls: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).collect();
        let mappings = &http_calls[0].2.value_mappings;
        assert_eq!(mappings.len(), 1, "{mappings:?}");
        assert_eq!(mappings[0].to.port, Port::Arg(1)); // "lang" is handler's 2nd parameter
    }

    #[test]
    fn an_ambiguous_route_maps_to_every_candidate_handler_conservatively() {
        // Two independent top-level classes must live in separate files:
        // `uniflow_lang_java::JavaParser::parse_file` only lowers the first
        // top-level class declaration it finds in one source text.
        let entries = vec![
            (
                "ServiceB.java".to_string(),
                r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id) {}
}
"#
                .to_string(),
            ),
            (
                "ServiceC.java".to_string(),
                r#"
class ServiceC {
    static void registerRoutes() { route("/profile", ServiceC::handler); }
    static void handler(String id) {}
}
"#
                .to_string(),
            ),
        ];
        let hir = uniflow_lang_java::parse_project_sources(&entries).expect("parse java project");
        let route_program = uniflow_lowering::lower_program(&hir);
        let call_program = lower_java(
            r#"
class ServiceA {
    static void run(String userInput) {
        Http.get("/profile?id=" + userInput);
    }
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_routes_into(&mut graph, &route_program).expect("discover routes");
        let programs = vec![(uniflow_hir::Language::Java, route_program), (uniflow_hir::Language::Java, call_program.clone())];
        let index = FunctionIndex::build(&programs);
        discover_outbound_calls_into(&mut graph, &call_program, &index).expect("discover outbound calls");

        let http_calls: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).collect();
        let mappings = &http_calls[0].2.value_mappings;
        assert_eq!(mappings.len(), 2, "{mappings:?}");
        assert!(mappings.iter().all(|mapping| mapping.confidence == Confidence::Conservative));
        let mut targets: Vec<&str> = mappings.iter().map(|mapping| mapping.to.function.as_str()).collect();
        targets.sort_unstable();
        assert_eq!(targets, vec!["ServiceB.handler", "ServiceC.handler"]);
    }
}
