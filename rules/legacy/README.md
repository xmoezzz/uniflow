# Migrated commercial rule catalogs

These native UniFlow rule packs are generated from the supplied legacy product
assets by the pure-Rust `decrypt-legacy-rules` and
`compile-legacy-jvm-rules` commands. The runtime never loads or executes a
legacy binary or JVM checker.

Python Pysa function, field, model-query, sanitizer, and taint-in-taint-out
models are compiled by `compile-legacy-pysa-rules`. The generated catalog is
embedded with `include_str!` just like the JVM and native catalogs.

The Go source/sink pack, including variadic ports, nested sign conditions and
argument type gates, is compiled by `compile-legacy-go-rules` and embedded in
the same way.

The C# catalog is compiled from the SecurityCodeScan configuration and its
message/vulnerability catalogs by `compile-legacy-csharp-rules`. The original
inputs are retained under `source/csharp/`; the generated bundle preserves
typed property models, named .NET parameter ports, MVC entry points,
sanitizers, transfers, severities, CWE metadata, and localized rule text.

`manifest.json` pins the generated file hashes, executable model counts, and
the number of deferred legacy features. Java models are also retargeted to
Kotlin and JSP because those frontends share JVM API semantics. The native
C/C++ pack targets both C and C++; the Objective-C pack targets Objective-C
and Objective-C++. JavaScript models retain JavaScript language targeting.

Do not edit the generated YAML manually. Change the parser/compiler and its
focused testcase, regenerate the catalog, and update the manifest hash and
counts together.

## Bundled source archive

`source/` is the repository-owned provenance archive; runtime correctness no
longer depends on the original download or a temporary decryption directory.
It currently contains 1,858 assets: 760 AST rules, 616 Semgrep rules and their
test fixtures, 297 Clang checker sources/registries, 103 Pysa assets, 54 SQL
rule documents, 20 decrypted JVM/JavaScript/native dataflow catalogs, the Go
catalog, SecurityCodeScan inputs, and the original Swift rules.

`uniflow-baseline/build.rs` recursively generates a Rust `include_bytes!`
table for every asset, so the archive is linked into the `uniflow` executable.
`uniflow list-bundled-legacy-assets [--prefix PREFIX]` exposes the immutable
embedded inventory and byte sizes for commercial audit and reproducible-build
verification. Executable native packs remain separate from this provenance
archive; merely archiving a legacy asset never marks its migration verified.

The Java AST migration inventory is generated from all 130 source YAML files
at build time. Each executable migration must resolve back to one unique
legacy id, retain its legacy message id and name a focused testcase. The
native pack contains all 130 executable Java AST rules with focused tests; the
manifest records zero remaining Java AST migrations so archived rules cannot
be mistaken for implemented rules.

The Java statement index is shared between frontend-only checks and HIR
statement boundaries. Structural regressions cover empty bodies, conditions,
switch labels, dangling else, comments, text literals, multiple/nested types,
anonymous methods and constructors. The ordinary empty-infinite-loop rule and
its YDT variant retain different body predicates. These checks run in both
text-only and HIR scans. HIR/taint regressions separately cover unbraced branches,
do/while, enhanced for, condition assignments and break/continue. Three-clause
for loops now have distinct HIR initialization, condition, update and body
regions; CFG tests verify continue-to-update, loop-header phi inputs and
break-to-exit. Taint tests cover update-to-next-iteration flow, multiple
declarators, loop-local scope, and jumps that execute finally before proceeding.
The ordinary and YDT floating-loop-variable checks use resolved declaration
types, preserving the legacy exclusion of method parameters. This is not
a claim that all Java syntax, resource lifecycle rules or project semantics
are complete; labeled jumps, side-effecting postfix expressions, exceptional
finally completion and the remaining semantic rules still require further
implementation and verification.

`crates/cli/tests/java_bundled_rules.rs` copies the executable and a Java
fixture into an isolated temporary directory (without a rule directory), then
asserts all 16 recently migrated structural/comparison/loop rule IDs in CLI output.
`crates/baseline/tests/argument_contract.rs` checks the shared call/constructor
argument predicates for Java and C#, including negative and missing-argument
cases; constructor predicates no longer silently omit null, boolean,
nonliteral or excluded-string constraints.

Java expression regressions now cover indexed reads/writes, typed array
receivers, reference/array casts, conditional precedence, nested lambdas and
comment/literal boundaries. Conditional local assignments are merged from
independent arm environments; boolean-literal conditions only evaluate the
selected arm. Unknown conditions remain conservative, and this does not claim
complete path-sensitive expression or exception semantics.

`crates/taint/tests/java_legacy_expression_rules.rs` selects the actual embedded
Servlet query-string source and JDBC SQL-injection sink, preserving its original
label predicates, for focused positive/negative execution tests. The separate
`java_taint_bundled_rules` CLI test copies only the binary and Java fixture into
an isolated directory and runs with the complete default Java model catalog;
it requires the original SQL rule at the tainted sink and excludes its safe
constant counterpart. It passes under a 25-second process-group timeout. This
is an end-to-end test of this rule family, not per-rule verification of all
4,511 Java sink models.

The array regression also guards solver convergence: local function summaries
resolve existing heap cells without recursively allocating inferred access
paths. The heap bridge may still create conservative wildcard projections.
Region adjacency is built by set union with a pairwise-equivalence regression;
external calls without internal callees skip discarded context traversals and
retain the fallback points-to partition.

Java library call chains use an embedded exact-owner/arity return-signature
catalog shared by the frontend and unified IR lowering. Its 62 expanded signatures
cover the Runtime command factory, servlet writers/dispatchers, JDBC connection,
statement, prepared/callable statement and result-set factories, URL connections,
streams, process streams, ScriptEngine, XPath, DocumentBuilder and NIO Path factories/projections;
user-defined project methods continue to take precedence and custom
owners or unsupported arities do not fall back by simple method name. Multiple
legacy source rules attached to the same call output now contribute a union of
taint labels to compound sink conditions, while distinct call sites remain
separate. Focused original-rule tests cover Runtime command injection, servlet
writer XSS and chained DataSource SQL injection with safe constants. Three
`java_taint_call_chains_bundled_rules` cases repeat one positive chain
per short-timeout process from an isolated executable using the complete
embedded Java catalog; the focused tests retain the three safe-constant
negatives.
The focused prepared-statement regression executes the original Servlet source
and original PreparedStatement `setString` sink through a chained DataSource
factory and retains a safe-constant negative. A separate short-timeout isolated
CLI case repeats the positive with the full embedded Java catalog.

Java prefix/postfix numeric updates now retain an explicit HIR operator and an
IR `NumericStep`: the result is the old/new value as appropriate, while storage
receives the new value. Field receivers and array indices are evaluated once;
Java assignment locations are evaluated before the RHS without changing
Python's RHS-first semantics. Focused HIR/IR regressions cover argument order,
assignment expressions, branch merges, loop backedges, and project symbol remapping.
Numeric taint edges preserve source labels without creating value/object aliases.
The literal-index solver uses a monotone pending/constant/varying lattice, so a
changing loop backedge or unknown phi input cannot retain a stale exact index.
Integral updates use the declared Java byte/short/char/int/long width; unknown
types and floating-point updates remain nonconstant rather than guessing.
`java_legacy_numeric_updates` executes the original Servlet numeric source with
all three labels and the original PreparedStatement database-access sink, keeping
the original sink predicates and metadata. It covers prefix/postfix results,
writeback, heap updates, safe overwrite, and distinct array indices. A separate
isolated-executable CLI regression runs the numeric update chain with the full
embedded catalog. These cases do not certify all Java rules or complete
path-sensitive heap/exception semantics.

`java_legacy_script_xml` executes the original ScriptEngine `eval`, XPath
`compile`/`evaluate`, and XML parser argument rules through their actual library
factory chains. Tests retain the original source labels, sink conditions and
localized knowledge text, and cover safe constants, local aliases and custom
owners. Three separate `java_taint_call_chains_bundled_rules` tests repeat the
positive cases with the complete embedded model catalog from an isolated binary.
The expanded return signatures are backed by Java SE API references recorded in
`rules/signatures/java-api-returns.tsv`. XML factory hardening now retains Java
boolean constants as `true`/`false`, accumulates the original general/parameter
entity receiver transforms, transfers them through `newDocumentBuilder`, and
joins the resulting parser state into sink conditions in lowered call order.
Focused tests require both flags, reject a single flag, keep configuration after
the parse from suppressing an earlier finding, and prevent state from leaking
between distinct factories. This ordering is exact for straight-line calls;
must-state joins across arbitrary exceptional/interprocedural control flow remain
a separate completeness boundary.

`java_legacy_path_redirect_deserialization` executes original path traversal,
open redirect, Jackson JSON deserialization and SnakeYAML deserialization sinks
with safe constants and custom-owner negatives. It additionally executes the
original `Paths.get` propagator and `getFileName` safe-path transform. Isolated
CLI cases verify these rules and the hardened XML negative from the executable's
full embedded catalog without a rules directory.

Kotlin type invocation now lowers to the same constructor identity as Java,
including fully-qualified external types, while known function values and
ordinary lower-case calls remain calls. Generic JVM parameter types are
canonicalized without punctuation whitespace and use the same exact-owner,
exact-arity return catalog. The retargeted original URL SSRF rule has focused
Kotlin positive, safe-constant and custom-owner tests. JSP scriptlets recognize
lower-case package prefixes in qualified Java declarations, keep top-level
receiver calls as calls, and assign the standard Servlet/JSP types to the nine
container-provided implicit objects. A focused JSP test executes the same
original SSRF rule from the implicit `request` object with safe and custom-owner
negatives.

Additional Java source-level and isolated-executable witnesses execute the
original unsafe-reflection `ClassLoader.loadClass`, URLConnection header
manipulation and Zip Entry Overwrite `Files.copy` rules. They retain compound
label conditions, exact owner matching, the `URL.openConnection` return type,
the original `ZipEntry.getName` source and the `Paths.get` propagator; focused
safe-constant and custom-owner negatives guard each family.

The original Java regular-expression injection (`Pattern.compile`), OGNL
expression injection and Velocity server-side template injection rules likewise
have focused positive/safe/custom-owner cases and isolated-executable bundle
witnesses. These tests execute the original sink conditions and metadata rather
than substitute hand-written equivalents.

Original XMLDecoder constructor injection, XStream XML deserialization and
Spring LDAP/JNDI reference-injection rules have the same two-layer coverage.
The XMLDecoder witness uses the original ServletRequest stream source, while
the JNDI witness preserves both declared argument-type gates; isolated runs
verify that all three retain their original bundled knowledge records.

Multi-file HIR merging now remaps dynamic-call target expressions and resolved
target symbols, including callee expression IDs, type IDs and source spans.
Python factory results remain unknown unless their return type is established;
they no longer alias the factory function itself. Cache version 8 also rejects
HIR produced before the Kotlin/JSP and JavaScript keyword-set changes,
with a poisoned-cache regression and current-version roundtrip.

Heap regressions cover weak-store retention, exact array-slot bridges, recursive
shape bounds, equal-cardinality solver-state changes, and contextual points-to
partitions. Summary path lookup is read-only and cached per call snapshot.
Loads no longer eagerly equate all historical stores with their result before
alias analysis. Sparse queries connect strong reads to the stores visible at
each read, retaining old reads while excluding overwritten values from later
reads. Return-region correspondence is not treated as an actual store. Exact
Java/Python field/index projections are separated before shared pointee labels;
native union overlap is not rejected by field name alone. Focused callback
tests assert the actual final callback target, rather than the first resolved
factory/installer call. These changes do not establish complete control-flow
dominance, context sensitivity or native layout semantics.

The Java model catalog additionally has partitioned executable-witness gates
for every compiled matcher and condition: 1,639 sources, 4,511 sinks, 403
sanitizers, 538 label transforms, 3,238 propagators, 278 call conditions and
4,511 sink conditions. Regex witnesses are derived from parsed regex HIR rather
than guessed strings; generated call arity must make every referenced
argument/range port material. Condition witnesses must remain compatible with
their owning matcher, including compound kind, receiver/argument type and
constant predicates. These catalog contracts prove that no compiled entry is
structurally unreachable; they complement, but do not replace, source-level
end-to-end tests for language syntax and framework return signatures.

The JVM compiler also imports the original `BugInfos` knowledge records and
both tagged `ruleMap` and `RuleSets` mappings. Source descriptions and remediation
advice are retained as static text; dynamic report templates are never executed.
All 4,511 Java sinks retain original message IDs and mapped standards. The
bundled presentation layer is complete for `zh-CN`, `en`, and `zh-TW`: original
text is preserved, missing Simplified Chinese or English fields fall back to the
reviewed rule title/message, and missing Traditional Chinese is generated with
the pure-Rust, embedded-dictionary `zhhz` Taiwan conversion. The audit separately
records source provenance: 4,502 rules have original Chinese prose, 631 have
original English prose, none have source Traditional Chinese, and two referenced
knowledge IDs remain unresolved. Thus fallback cannot hide a source-data gap.
`java-taint-metadata-report.json` records both coverage layers.
Use `compile-legacy-jvm-rules --metadata-report-out <path>` to reproduce this audit.

`enrich-legacy-jvm-baseline --input rules/baseline/legacy-java-ast.yml
--knowledge rules/legacy/source/dataflow/java --output <path>
--metadata-report-out <path>` attaches knowledge text by exact `LEGACY-MSG` IDs
without changing native matcher, severity, title or fallback-message semantics.
Original prose resolves for 30/130 Java AST rules; all 130 carry nonempty bundled
`zh-CN`, `en`, and `zh-TW` presentations under the same deterministic fallback
policy. Unresolved IDs remain in `java-ast-metadata-report.json`; ID namespaces
are not rewritten by guessing. Focused compiler, native-pack metadata, and
isolated CLI regressions exercise the imports, fallback, and final report output.

The JavaScript Semgrep archive contains 185 rules. Thirty-one search rules are
compiled into the executable baseline and nine taint rules into the unified
dataflow catalog. In addition to template and lexical rules, native
HIR matchers preserve required/forbidden receivers, exact arity, string versus
non-string arguments, exact boolean arguments, and variadic final-argument
semantics. This covers Angular SCE disabling, wildcard `postMessage`, Buffer
`noAssert`, dynamic `eval`/`require`, dynamic jQuery/FBJS HTML APIs, debugging
calls, `replaceAll`, both weak-randomness source definitions, and Mustache/Pug
unescaped/script-tag template patterns. JavaScript input discovery includes the
original template extensions so these rules execute through the CLI as well.
HIR assignment matching additionally covers Angular redirects, dynamic
`innerHTML`, disabled Mustache escaping, and declarations/assignments to
`undefined`; exact argument-pair matching covers the manual and incomplete
HTML-escaping replacement checks. Taint models cover dynamic require and RegExp,
MD5 password use, untrusted JSON mass assignment, Node.js child_process, and
Bluebird package-scoped flows. CommonJS module provenance survives assignments
and member access, so unrelated packages do not match. The same provenance now
tracks mysql/mysql2, mssql, and node-postgres client factories and queries;
mysql `parseInt` sanitization is scoped to that rule kind. Focused positive and
negative tests cover each migrated ID. The remaining 145
structural and taint rules stay explicitly counted as pending native migration.

Thirty Ruby search rules are compiled from the 111-rule Semgrep source set
with comment/literal-aware matching and focused tests. Native HIR rules now add
dynamic `open`, Open3 pipeline, XmlMini backend, nested-attribute, and sensitive
Rails `permit` checks. JWT rules preserve same-file `require 'jwt'`, receiver,
argument, verification, algorithm, function-parameter and latest string-secret
constraints. The other 81 Ruby rules,
including all remaining taint-mode definitions, are retained as explicit
pending migrations rather than silently approximated.

The C/C++ AST source set contains 53 rules. All 53 direct-call, lexical,
preprocessor, declaration, expression, operator and statement rules are now
native and tested. Statement ownership tests cover braces, else-if,
empty statements, switch labels, break targets and literal loop conditions in
both source-only and HIR scans. Preprocessor continuations are masked without
changing diagnostic offsets. These AST counts do not include the separate
280-entry Clang checker migration inventory.
`c_statement_bundled_rules` additionally checks all nine newly migrated
statement rules from a standalone executable without a rules directory.

Six legacy preprocessor rules additionally use a dedicated pure-Rust macro
index. Backslash-newline splicing (including CRLF) precedes comment recognition,
with offsets mapped back to the original source. Function-like macros include
empty parameter lists; whitespace/comments between the name and opening
parenthesis make a macro object-like. The original replacement-text regexes
are retained: hash characters inside literals are visible, `##` alone does not
satisfy the repeated-hash predicate, and the parentheses rule requires both
endpoints to be unwrapped. These differ intentionally from the existing Clang
macro checkers' token-count predicates. Rule-specific tests cover these
boundaries, file gates, source/HIR parity and original diagnostic locations.
The six rules retain every source message ID and include Simplified Chinese,
English and Traditional Chinese presentations; the inventory and standalone
`c_preprocessor_bundled_rules` CLI tests enforce those contracts.

Ten declaration rules use a separate pure-Rust C declarator index, preserving
name-outward pointer/array/function operator order, function ownership and
aggregate membership. Focused tests cover function-pointer prototypes, nested
functions, lambda return isolation, extern linkage blocks, parameter descendants,
single-declaration brace-initialized unsized arrays and comment-sensitive legacy
return predicates. Missing-return checks are syntactic, not all-path proofs.
The index is not a complete C++ compiler frontend (template-dependent types,
macro expansion and overload resolution are not inferred). Source/HIR parity,
original coordinates, matcher exclusivity, message IDs and three presentations
are checked independently; `c_declaration_bundled_rules` exercises all ten from
an isolated executable without an external rules directory.

The final nine AST entries use balanced expression facts for assignment/update,
call, conditional, binary and comma ownership plus declarator facts for null
pointer initialization. Their tests preserve the source rules' distinctions
between expression statements and conditions, declaration initializers and
assignment expressions, call/for separators and comma expressions, nested
calls and registry API ownership. `c_expression_bundled_rules` exercises every
entry from an isolated binary. This closes the 53-entry C AST archive only; it
does not change the separately tracked 280-entry Clang checker inventory.

The C# AST source set contains 33 executable rules with focused testcase
references. The inventory gate verifies unique source-to-native mappings and
legacy message IDs (including the two files sharing source ID `SCS0002`).
Method attributes use balanced declaration ownership; typed calls, fields,
argument positions and catch contexts use HIR. Parameter/declaration provenance,
earlier-if exclusions and same-origin property checks retain the legacy AST
heuristics. These exclusions are not sanitizers for the separate taint engine.
The malformed legacy XPath/LINQ receiver regexes with empty alternatives are
restricted to their intended `XPathNavigator`/`DataContext` types, with unrelated
receiver negative cases. `encapsulation_external` retains the source spelling
`Reponse`, and XSS header flag checking retains its original token predicate.
This inventory does not prove complete C# language or framework support.
The isolated `csharp_bundled_rules` CLI testcase runs an executable copy without
any rule directory and requires diagnostics from every one of these 33 rules.

Fifty-two of the 54 SQL rules are now executable. Twelve lexical rules use
SQL-aware comment handling; another forty use the shared balanced SQL token,
IF-branch and BEGIN-block index plus control-flow, exception, query and symbol
analysis with source/HIR parity, focused positive/safe tests and three-locale
messages. `InvalidReferenceToObject` still needs an Oracle Forms object inventory,
while `XPath` is a configurable custom-rule facility rather than a fixed diagnostic;
those two remain explicit instead of being represented by placeholder findings.
