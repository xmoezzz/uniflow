//! gRPC service-boundary adapter.
//!
//! A `.proto` file's `service`/`rpc` declarations are the shared contract
//! every language's generated bindings implement independently — this
//! module parses that contract, then connects each language's own binding
//! shape on both ends: a structural server-side implementation (a method
//! whose name matches an RPC and whose enclosing type relates to the
//! service name — the same "structural recognition, no call site needed"
//! shape `crate::http::is_go_servehttp_handler` uses for Go's `ServeHTTP`)
//! and a client-side call to a generated stub method. This is the same
//! producer/consumer stitching pattern `crate::message` uses for
//! Kafka/RabbitMQ (a literal channel name connecting an independently
//! discovered producer to an independently discovered consumer), adapted
//! for gRPC's service-contract-first design in place of a literal topic
//! string.
//!
//! Deliberately conservative, matching every other adapter in this crate:
//! recognition is *(service name, method name)* literal-text matching
//! against the parsed `.proto` contract, not real interface/trait
//! conformance checking — this codebase's IR has no uniform way to verify
//! "this type actually implements this generated interface" across every
//! language. A same-named, same-service-shaped method that is not actually
//! a generated binding is a possible (rare, given the naming convention
//! required) false positive — the same tradeoff `message.rs` already
//! accepts for its own literal-marker-based client/topic detection.
//!
//! Go, Java, and C# are covered by the server/client recognizers below;
//! the `.proto` parser itself is language-agnostic and a future recognizer
//! for another language only needs its own
//! [`request_param_index`] entry plus (if its generated binding's naming
//! convention differs) its own match against [`matches_service_type`].

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use uniflow_ir::{Callee, InstKind, Program};
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};
use crate::ir_utils::{is_python_root_alias, FunctionIndex};

fn is_proto_file(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("proto"))
}

/// Finds every `.proto` file under `roots` — mirrors
/// `crate::docker_compose::find_compose_files`/`crate::kubernetes::find_manifest_files`.
pub fn find_proto_files(roots: &[PathBuf]) -> Vec<PathBuf> {
    crate::discovery::find_files(roots, is_proto_file)
}

/// Reads and parses every `.proto` file in `proto_files` into one combined
/// service list — a file that fails to read is skipped with an error
/// context rather than aborting the whole scan (mirrors how a single
/// malformed Docker Compose/Kubernetes manifest is handled).
pub fn load_proto_services(proto_files: &[PathBuf]) -> Result<Vec<ProtoService>> {
    let mut services = Vec::new();
    for path in proto_files {
        let source = std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
        services.extend(parse_proto_services(&source));
    }
    Ok(services)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoMethod {
    pub name: String,
    pub request_type: String,
    pub response_type: String,
    /// A streaming request is represented by a reader/writer/callback whose
    /// ownership and per-message element flow differs between generated
    /// bindings.  It must not be treated as a unary request argument.
    pub client_streaming: bool,
    /// See [`Self::client_streaming`].  A streaming response does not make
    /// the incoming request mapping unsafe, but retaining the contract fact
    /// lets consumers distinguish unary RPCs from server-streaming ones.
    pub server_streaming: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoService {
    pub name: String,
    pub methods: Vec<ProtoMethod>,
}

/// Strips `//` line comments and `/* */` block comments — naively (no
/// awareness of a `//`/`/*` occurring inside a string literal), which is
/// good enough for real-world `.proto` files: string literals appear only
/// in field default values/options, essentially never containing comment
/// delimiters.
fn strip_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Byte offset (within `text`, which must start with the opening `{`) of
/// the matching closing brace, depth-aware so a nested `message`/`option`
/// block doesn't terminate the scan early.
fn matching_brace(text: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (idx, ch) in text.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_rpc_methods(block: &str) -> Vec<ProtoMethod> {
    let mut methods = Vec::new();
    let mut rest = block;
    while let Some(rpc_kw) = rest.find("rpc ") {
        let after = &rest[rpc_kw + "rpc ".len()..];
        let Some(paren_start) = after.find('(') else { break };
        let name = after[..paren_start].trim().to_string();
        let Some(paren_len) = after[paren_start..].find(')') else { break };
        let request_raw = after[paren_start + 1..paren_start + paren_len].trim();
        let client_streaming = request_raw.split_whitespace().next() == Some("stream");
        let request_type = request_raw.trim_start_matches("stream").trim().to_string();
        let after_request = &after[paren_start + paren_len + 1..];
        let Some(returns_pos) = after_request.find("returns") else { break };
        let after_returns = &after_request[returns_pos + "returns".len()..];
        let Some(ret_paren_start) = after_returns.find('(') else { break };
        let Some(ret_paren_len) = after_returns[ret_paren_start..].find(')') else { break };
        let response_raw = after_returns[ret_paren_start + 1..ret_paren_start + ret_paren_len].trim();
        let server_streaming = response_raw.split_whitespace().next() == Some("stream");
        let response_type = response_raw.trim_start_matches("stream").trim().to_string();
        if !name.is_empty() {
            methods.push(ProtoMethod {
                name,
                request_type,
                response_type,
                client_streaming,
                server_streaming,
            });
        }
        let tail = &after_returns[ret_paren_start + ret_paren_len + 1..];
        // Whichever of `;` (a bare `rpc ... );`) or `{` (a `{ ... }`
        // method-options block) comes FIRST terminates *this* rpc — a
        // later rpc's own `{}` block must not be mistaken for this one's
        // terminator just because it also contains a brace.
        let brace_pos = tail.find('{');
        let semi_pos = tail.find(';');
        let advance = match (brace_pos, semi_pos) {
            (Some(brace_pos), Some(semi_pos)) if brace_pos < semi_pos => {
                matching_brace(&tail[brace_pos..]).map(|end| brace_pos + end + 1).unwrap_or(tail.len())
            }
            (_, Some(semi_pos)) => semi_pos + 1,
            (Some(brace_pos), None) => matching_brace(&tail[brace_pos..]).map(|end| brace_pos + end + 1).unwrap_or(tail.len()),
            (None, None) => tail.len(),
        };
        rest = &tail[advance.min(tail.len())..];
    }
    methods
}

/// Finds every top-level `service NAME { ... }` block and parses its
/// `rpc NAME(REQ) returns (RESP);` (or `(stream REQ)`/`(stream RESP)`,
/// optionally followed by a `{ ... }` method-options block instead of a
/// bare `;`) declarations. Not a full protobuf grammar — a lightweight
/// structural scan, which is all the recognizers below need.
pub fn parse_proto_services(source: &str) -> Vec<ProtoService> {
    let text = strip_comments(source);
    let mut services = Vec::new();
    let mut rest = text.as_str();
    while let Some(service_kw) = rest.find("service ") {
        let after_kw = &rest[service_kw + "service ".len()..];
        let Some(name_end) = after_kw.find(|c: char| c == '{' || c.is_whitespace()) else { break };
        let name = after_kw[..name_end].trim().to_string();
        let Some(brace_start) = after_kw.find('{') else { break };
        let Some(block_len) = matching_brace(&after_kw[brace_start..]) else { break };
        let block = &after_kw[brace_start + 1..brace_start + block_len];
        let methods = parse_rpc_methods(block);
        if !name.is_empty() && !methods.is_empty() {
            services.push(ProtoService { name, methods });
        }
        rest = &after_kw[brace_start + block_len + 1..];
    }
    services
}

fn channel_id(service: &str, method: &str) -> String {
    format!("grpc:method:{service}.{method}")
}

fn function_node_id(language: &uniflow_hir::Language, function: &str) -> String {
    format!("code:{}:{function}", language.as_str())
}

fn ensure_channel(graph: &mut SystemGraph, service: &str, method: &ProtoMethod) -> String {
    let id = channel_id(service, &method.name);
    graph.upsert_node(
        SystemNode::new(NodeKind::RpcMethod, id.clone(), format!("{service}.{}", method.name))
            .with_attr("request_type", method.request_type.clone())
            .with_attr("response_type", method.response_type.clone())
            .with_attr("client_streaming", method.client_streaming.to_string())
            .with_attr("server_streaming", method.server_streaming.to_string()),
    );
    id
}

/// A function's enclosing type (its qualified name's owner segment, e.g.
/// `pkg.fooServerImpl` for `pkg.fooServerImpl.Bar`) is treated as this
/// service's real implementation when its simple (unqualified) name
/// contains the service name, case-insensitively — generated server
/// implementations commonly lowercase and/or suffix the service name
/// (`fooServerImpl`, `FooServiceImpl`, `FooGrpc$FooImplBase`).
fn matches_service_type(qualified_name: &str, service: &str) -> bool {
    let Some((owner, _method)) = qualified_name.rsplit_once('.') else { return false };
    let owner_simple = owner.rsplit(['.', '$']).next().unwrap_or(owner);
    owner_simple.to_ascii_lowercase().contains(&service.to_ascii_lowercase())
}

/// Request-parameter positional convention. This IR carries no reliable
/// cross-language parameter *type* information to match directly against
/// the `.proto` request message name, so position is used instead: Go's
/// generated server methods always take `context.Context` as their first
/// parameter (`func (s *impl) Bar(ctx context.Context, req *pb.BarRequest)
/// (*pb.BarResponse, error)`), so the request is the second parameter
/// (index 1); Java's generated methods (`bar(BarRequest req,
/// StreamObserver<BarResponse> obs)`) and every other currently-supported
/// language put the request message first (index 0).
fn request_param_index(language: &uniflow_hir::Language) -> usize {
    match language {
        uniflow_hir::Language::Go => 1,
        _ => 0,
    }
}

#[derive(Clone, Debug)]
pub struct RpcServerMethod {
    pub service: String,
    pub method: String,
    pub function: String,
}

/// Scans `program` for a structural server-side RPC implementation (see
/// module docs) for each `rpc` declared by `services`, marking each match
/// as a real [`NodeKind::Entrypoint`] and linking it to the RPC's channel
/// node via [`EdgeKind::Handles`] — the same node/edge shape
/// `crate::http::discover_routes_into` uses for an HTTP route's handler.
pub fn discover_server_methods_into(graph: &mut SystemGraph, services: &[ProtoService], program: &Program) -> Result<Vec<RpcServerMethod>> {
    let mut servers = Vec::new();
    if !matches!(
        program.language,
        uniflow_hir::Language::Go | uniflow_hir::Language::Java | uniflow_hir::Language::CSharp
    ) {
        return Ok(servers);
    }
    for function in &program.functions {
        if is_python_root_alias(program, function) {
            continue;
        }
        let Some(simple_name) = function.name.rsplit('.').next() else { continue };
        for service in services {
            // Case-insensitive: a `.proto` RPC name is PascalCase by
            // convention (`PlaceOrder`), which generated Go bindings keep
            // as-is (exported method names are always PascalCase) but
            // generated Java bindings lower-case to match Java's own
            // method-naming convention (`placeOrder`).
            let Some(rpc) = service.methods.iter().find(|method| method.name.eq_ignore_ascii_case(simple_name)) else { continue };
            if !matches_service_type(&function.name, &service.name) {
                continue;
            }
            let param_index = request_param_index(&program.language);
            if function.params.get(param_index).is_none() {
                continue;
            }
            let channel_id = ensure_channel(graph, &service.name, rpc);
            let handler_id = function_node_id(&program.language, &function.name);
            graph.upsert_node(
                SystemNode::new(NodeKind::Entrypoint, handler_id.clone(), &function.name).with_code_ref(CodeRef {
                    language: program.language.clone(),
                    qualified_name: function.name.clone(),
                }),
            );
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::Handles, channel_id, handler_id, Confidence::Inferred).with_evidence(Evidence::new(format!(
                    "{} implements {}.{} (matched by RPC method name and enclosing-type name)",
                    function.name, service.name, rpc.name
                ))),
            )?;
            servers.push(RpcServerMethod { service: service.name.clone(), method: rpc.name.clone(), function: function.name.clone() });
        }
    }
    Ok(servers)
}

/// Scans `program` for a client-side call to a generated stub method (the
/// call's own callee name, last-dotted-segment, matching an RPC name),
/// linking each to the RPC's channel node via [`EdgeKind::RpcCall`] and, for
/// every server implementation already discovered for that same
/// `(service, method)` pair (via a prior [`discover_server_methods_into`]
/// pass over every group), a precise request-argument-to-request-parameter
/// [`BoundaryFlowEdge`] — the same "topic connects an independently
/// discovered producer to an independently discovered consumer" shape
/// `crate::message::discover_publications_into` uses.
pub fn discover_client_calls_into(
    graph: &mut SystemGraph,
    services: &[ProtoService],
    program: &Program,
    servers: &[RpcServerMethod],
    function_index: &FunctionIndex<'_>,
) -> Result<()> {
    for function in &program.functions {
        if is_python_root_alias(program, function) {
            continue;
        }
        for block in &function.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else { continue };
                let Callee::Static(name) = &call.callee else { continue };
                let method_simple = name.rsplit('.').next().unwrap_or(name);
                for service in services {
                    let Some(rpc) = service.methods.iter().find(|method| method.name.eq_ignore_ascii_case(method_simple)) else { continue };
                    // A server implementation's own body may itself contain a
                    // call whose name happens to match (e.g. delegating to
                    // another RPC's generated client) — only exclude the
                    // exact case of a server method's call to *itself*.
                    if servers.iter().any(|server| server.function == function.name && server.method == rpc.name && server.service == service.name) {
                        continue;
                    }
                    let channel_id = ensure_channel(graph, &service.name, rpc);
                    let call_site_id = format!("code:{}:{}#{}", program.language.as_str(), function.name, inst.id.0);
                    graph.upsert_node(SystemNode::new(NodeKind::CallSite, call_site_id.clone(), name.clone()).with_code_ref(CodeRef {
                        language: program.language.clone(),
                        qualified_name: function.name.clone(),
                    }));

                    let matches: Vec<_> = servers.iter().filter(|server| server.service == service.name && server.method == rpc.name).collect();
                    let ambiguous = matches.len() > 1;
                    let mut summary = BoundarySummary::new(
                        EdgeKind::RpcCall,
                        call_site_id,
                        channel_id,
                        if matches.is_empty() { Confidence::Conservative } else { Confidence::Inferred },
                    )
                    .with_evidence(Evidence::new(format!("{} calls gRPC method {}.{} via {name}", function.name, service.name, rpc.name)));

                    // Generated APIs model client-streaming as a stream
                    // writer/iterator/callback rather than the unary request
                    // message.  Mapping its last call argument to a server
                    // parameter would create a fabricated taint path. Keep
                    // the RPC topology edge, but wait for a binding-specific
                    // element-flow adapter before emitting a data mapping.
                    if !rpc.client_streaming {
                        if let Some(request_arg_index) = call.args.len().checked_sub(1) {
                        for server in &matches {
                            let Some((server_language, server_function)) = function_index.get(&server.function) else { continue };
                            let param_index = request_param_index(server_language);
                            if server_function.params.get(param_index).is_none() {
                                continue;
                            }
                            let confidence = if ambiguous { Confidence::Conservative } else { Confidence::Inferred };
                            summary = summary.with_value_mapping(
                                BoundaryFlowEdge::new(
                                    ValueMappingKind::ArgumentToParameter,
                                    FlowNodeRef::call_site_port(program.language.clone(), function.name.clone(), inst.id.0, Port::Arg(request_arg_index)),
                                    FlowNodeRef::function_port(server_language.clone(), server.function.clone(), Port::Arg(param_index)),
                                    confidence,
                                )
                                .with_evidence(Evidence::new(format!(
                                    "gRPC method {}.{} maps client request argument to server handler's request parameter",
                                    service.name, rpc.name
                                ))),
                            );
                        }
                    }
                    }
                    graph.apply_boundary(summary)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    const ORDER_PROTO: &str = r#"
        syntax = "proto3";
        package demo;

        service OrderService {
          // Places an order.
          rpc PlaceOrder (PlaceOrderRequest) returns (PlaceOrderResponse);
          rpc StreamOrders (stream OrderUpdate) returns (stream OrderStatus) {}
        }

        message PlaceOrderRequest { string item = 1; }
        message PlaceOrderResponse { string id = 1; }
    "#;

    #[test]
    fn parses_service_and_rpc_declarations_including_streaming() {
        let services = parse_proto_services(ORDER_PROTO);
        assert_eq!(services.len(), 1);
        let service = &services[0];
        assert_eq!(service.name, "OrderService");
        assert_eq!(service.methods.len(), 2);
        assert_eq!(service.methods[0].name, "PlaceOrder");
        assert_eq!(service.methods[0].request_type, "PlaceOrderRequest");
        assert_eq!(service.methods[0].response_type, "PlaceOrderResponse");
        assert_eq!(service.methods[1].name, "StreamOrders");
        assert_eq!(service.methods[1].request_type, "OrderUpdate");
        assert_eq!(service.methods[1].response_type, "OrderStatus");
        assert!(service.methods[1].client_streaming);
        assert!(service.methods[1].server_streaming);
    }

    fn lower_java(source: &str) -> Program {
        let hir = uniflow_lang_java::JavaParser::default().parse_file("Probe.java", source).expect("parse java");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_go(source: &str) -> Program {
        let hir = uniflow_lang_go::GoParser::default().parse_file("probe.go", source).expect("parse go");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_csharp(source: &str) -> Program {
        let hir = uniflow_lang_frontends::parse_file(uniflow_hir::Language::CSharp, "Probe.cs", source)
            .expect("parse csharp");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn java_server_implementation_is_recognized_as_a_real_entrypoint() {
        let services = parse_proto_services(ORDER_PROTO);
        let server_program = lower_java(
            r#"
class OrderServiceImpl {
    void placeOrder(PlaceOrderRequest req) { sink(req); }
}
"#,
        );
        let mut graph = SystemGraph::new();
        let servers = discover_server_methods_into(&mut graph, &services, &server_program).expect("discover servers");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].service, "OrderService");
        assert_eq!(servers[0].method, "PlaceOrder");
        assert!(graph.node("code:java:OrderServiceImpl.placeOrder").is_some_and(|node| node.kind == NodeKind::Entrypoint));
        let handled: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Handles).collect();
        assert_eq!(handled.len(), 1, "{handled:?}");
    }

    #[test]
    fn go_client_call_maps_request_argument_to_java_server_parameter() {
        let services = parse_proto_services(ORDER_PROTO);
        let server_program = lower_java(
            r#"
class OrderServiceImpl {
    void placeOrder(PlaceOrderRequest req) { sink(req); }
}
"#,
        );
        let client_program = lower_go(
            r#"
package client

func run(ctx Context, stub OrderServiceClient, req PlaceOrderRequest) {
    stub.PlaceOrder(ctx, req)
}
"#,
        );
        let programs = vec![(uniflow_hir::Language::Java, server_program.clone()), (uniflow_hir::Language::Go, client_program.clone())];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let servers = discover_server_methods_into(&mut graph, &services, &server_program).expect("discover servers");
        discover_client_calls_into(&mut graph, &services, &client_program, &servers, &index).expect("discover client calls");

        let calls: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::RpcCall).collect();
        assert_eq!(calls.len(), 1, "{calls:?}");
        let mappings = &calls[0].2.value_mappings;
        assert_eq!(mappings.len(), 1, "{mappings:?}");
        assert_eq!(mappings[0].from.function, "client.run");
        assert_eq!(mappings[0].from.port, Port::Arg(1));
        assert_eq!(mappings[0].to.function, "OrderServiceImpl.placeOrder");
        assert_eq!(mappings[0].to.port, Port::Arg(0));
        assert_eq!(calls[0].2.confidence, Confidence::Inferred);
    }

    #[test]
    fn a_same_named_method_on_an_unrelated_type_is_not_recognized() {
        let services = parse_proto_services(ORDER_PROTO);
        let program = lower_java(r#"class InventoryManager { void placeOrder(PlaceOrderRequest req) {} }"#);
        let mut graph = SystemGraph::new();
        let servers = discover_server_methods_into(&mut graph, &services, &program).expect("discover servers");
        assert!(servers.is_empty(), "{servers:?}");
    }

    #[test]
    fn csharp_client_request_maps_to_a_csharp_service_implementation() {
        let services = parse_proto_services(ORDER_PROTO);
        let server_program = lower_csharp(
            r#"
class OrderServiceImpl {
    public void PlaceOrder(PlaceOrderRequest request) { Sink(request); }
}
"#,
        );
        let client_program = lower_csharp(
            r#"
class Client {
    public void Run(OrderServiceClient stub, PlaceOrderRequest request) {
        stub.PlaceOrder(request);
    }
}
"#,
        );
        let programs = vec![
            (uniflow_hir::Language::CSharp, server_program.clone()),
            (uniflow_hir::Language::CSharp, client_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let servers = discover_server_methods_into(&mut graph, &services, &server_program).expect("discover C# server");
        discover_client_calls_into(&mut graph, &services, &client_program, &servers, &index).expect("discover C# client");

        let call = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::RpcCall).expect("RPC call");
        assert_eq!(call.2.value_mappings.len(), 1, "{:?}", call.2.value_mappings);
        assert_eq!(call.2.value_mappings[0].from.function, "Client.Run");
        assert_eq!(call.2.value_mappings[0].to.function, "OrderServiceImpl.PlaceOrder");
        assert_eq!(call.2.value_mappings[0].to.port, Port::Arg(0));
    }

    #[test]
    fn client_streaming_rpc_keeps_topology_without_inventing_a_unary_value_mapping() {
        let services = parse_proto_services(ORDER_PROTO);
        let server_program = lower_java(
            r#"
class OrderServiceImpl {
    void streamOrders(OrderUpdate updates) { sink(updates); }
}
"#,
        );
        let client_program = lower_java(
            r#"
class Client {
    void run(OrderServiceStub stub, Object writer) { stub.streamOrders(writer); }
}
"#,
        );
        let programs = vec![
            (uniflow_hir::Language::Java, server_program.clone()),
            (uniflow_hir::Language::Java, client_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let servers = discover_server_methods_into(&mut graph, &services, &server_program).expect("discover server");
        discover_client_calls_into(&mut graph, &services, &client_program, &servers, &index).expect("discover client");

        let call = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::RpcCall).expect("RPC topology edge");
        assert!(call.2.value_mappings.is_empty(), "{:#?}", call.2.value_mappings);
        let channel = graph.node("grpc:method:OrderService.StreamOrders").expect("RPC channel");
        assert_eq!(channel.attrs.get("client_streaming").map(String::as_str), Some("true"));
        assert_eq!(channel.attrs.get("server_streaming").map(String::as_str), Some("true"));
    }
}
