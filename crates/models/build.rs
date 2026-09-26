use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    env, fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
};
use uniflow_rules::{RuleMetadata, RuleSet};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let rules = manifest.join("../../rules/legacy");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));

    encrypt_mit_assets(&manifest, &out);

    compile_pack(
        &rules,
        &out,
        "java",
        &["java-taint.yml", "java-taint-supplement.yml"],
        true,
    );
    compile_pack(
        &rules,
        &out,
        "javascript",
        &["javascript-taint.yml", "javascript-semgrep-taint.yml"],
        false,
    );
    compile_pack(&rules, &out, "c-cpp", &["c-cpp-taint.yml"], false);
    compile_pack(
        &rules,
        &out,
        "objc-objcpp",
        &["objc-objcpp-taint.yml"],
        false,
    );
    compile_pack(&rules, &out, "python", &["python-taint.yml"], false);
    compile_pack(&rules, &out, "go", &["go-taint.yml"], false);
    compile_pack(&rules, &out, "csharp", &["csharp-taint.yml"], false);
    compile_pack(
        &rules,
        &out,
        "ruby",
        &["ruby-semgrep-taint.yml"],
        false,
    );
}

fn compile_pack(
    rules_dir: &Path,
    out_dir: &Path,
    name: &str,
    inputs: &[&str],
    java_policy: bool,
) {
    // Bincode serializes structs positionally. Bump this whenever RuleSet's
    // serialized field layout changes so cached bundled tables cannot be
    // accepted with a stale schema.
    // Bumped to v7: RuleMetadata gained a `categories` field, changing the
    // bincode-serialized layout of both the rule table and the metadata
    // archive below — a stale cached artifact from v6 decodes with the
    // wrong field layout instead of failing loudly, so the fingerprint must
    // change even though none of the source YAML files did.
    // Bumped to v8: ApiMatcher gained `receiver_origin_regex`.
    const FORMAT_VERSION: &str = "uniflow-rule-table-v8";
    let output = out_dir.join(format!("legacy-{name}.bin"));
    let metadata_output = out_dir.join(format!("legacy-{name}.metadata.bin"));
    let stamp = out_dir.join(format!("legacy-{name}.stamp"));
    let mut fingerprint = DefaultHasher::new();
    FORMAT_VERSION.hash(&mut fingerprint);
    let mut sources = Vec::with_capacity(inputs.len());
    for input in inputs {
        let path = rules_dir.join(input);
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        input.hash(&mut fingerprint);
        bytes.hash(&mut fingerprint);
        sources.push((path, bytes));
    }
    let fingerprint = format!("{:016x}", fingerprint.finish());
    if output.is_file()
        && metadata_output.is_file()
        && stamp
            .is_file()
            .then(|| fs::read_to_string(&stamp).ok())
            .flatten()
            .is_some_and(|current| current == fingerprint)
    {
        return;
    }
    // An interrupted build can finish the atomic rule-table write before it
    // writes the tiny stamp. The table was produced by this build-script
    // format and bincode decoding will still reject any truncated artifact.
    if output.is_file() && metadata_output.is_file() && !stamp.exists() {
        fs::write(&stamp, &fingerprint)
            .unwrap_or_else(|error| panic!("failed to adopt compiled {name} rule table: {error}"));
        return;
    }

    let mut merged = RuleSet::default();
    for (path, bytes) in sources {
        let yaml = String::from_utf8(bytes)
            .unwrap_or_else(|error| panic!("{} is not UTF-8: {error}", path.display()));
        let parsed = serde_yaml::from_str::<RuleSet>(&yaml)
            .unwrap_or_else(|error| panic!("failed to compile {}: {error}", path.display()));
        merged.merge(parsed);
    }
    if java_policy {
        remove_unconstrained_java_taint_models(&mut merged);
        attach_general_java_sanitization_policy(&mut merged);
    }
    merged
        .validate()
        .unwrap_or_else(|error| panic!("compiled {name} rule pack is invalid: {error}"));
    let metadata = std::mem::take(&mut merged.metadata);
    let bytes = bincode::serialize(&merged)
        .unwrap_or_else(|error| panic!("failed to serialize {name} rule pack: {error}"));
    let metadata_bytes = encode_metadata_archive(&metadata);
    let temporary = out_dir.join(format!("legacy-{name}.bin.tmp"));
    let metadata_temporary = out_dir.join(format!("legacy-{name}.metadata.bin.tmp"));
    fs::write(&temporary, bytes)
        .unwrap_or_else(|error| panic!("failed to write compiled {name} rule pack: {error}"));
    fs::write(&metadata_temporary, metadata_bytes).unwrap_or_else(|error| {
        panic!("failed to write compiled {name} metadata catalog: {error}")
    });
    fs::rename(&temporary, &output)
        .unwrap_or_else(|error| panic!("failed to install compiled {name} rule pack: {error}"));
    fs::rename(&metadata_temporary, &metadata_output).unwrap_or_else(|error| {
        panic!("failed to install compiled {name} metadata catalog: {error}")
    });
    fs::write(&stamp, fingerprint)
        .unwrap_or_else(|error| panic!("failed to stamp compiled {name} rule pack: {error}"));
}

/// Some legacy Java exports contain fallback models equivalent to “every
/// dotted receiver and every method”.  Those are neither source nor sink
/// specifications: they turn ordinary bootstrap/configuration calls into
/// database and XSS findings.  Keep every constrained migrated model, while
/// refusing this provably uninformative wildcard pair at bundle time.
fn remove_unconstrained_java_taint_models(rules: &mut RuleSet) {
    let mut removed = HashSet::new();
    rules.sources.retain(|rule| {
        let keep = !is_unconstrained_java_api_model(&rule.matcher);
        if !keep {
            removed.insert(rule.id.clone());
        }
        keep
    });
    rules.sinks.retain(|rule| {
        let keep = !is_unconstrained_java_api_model(&rule.matcher);
        if !keep {
            removed.insert(rule.id.clone());
        }
        keep
    });
    // A removed executable model must not leave a dangling report or a
    // condition that validation would later attach to an unrelated rule.
    rules.metadata.retain(|metadata| !removed.contains(&metadata.id));
    rules.sink_conditions.retain(|rule| !removed.contains(&rule.sink_rule_id));
    rules.call_conditions.retain(|rule| !removed.contains(&rule.rule_id));
    rules.sink_reports.retain(|rule| {
        !removed.contains(&rule.sink_rule_id) && !removed.contains(&rule.report_rule_id)
    });
    rules.model_dependencies.retain(|rule| !removed.contains(&rule.rule_id));
}

fn is_unconstrained_java_api_model(matcher: &uniflow_rules::ApiMatcher) -> bool {
    matcher.exact.is_none()
        && matcher.contains.is_none()
        && matcher.regex.is_none()
        && matcher.containing_function_regex.is_none()
        && matcher.receiver_type.is_none()
        && matcher.receiver_contains.is_none()
        && matcher.receiver_parameter.is_none()
        && matcher.receiver_regex.as_deref() == Some("^(?:.*)\\.(?:.*)$")
        && matcher.method_name.is_none()
        && matcher.method_contains.is_none()
        && matcher.method_regex.as_deref() == Some("^(?:.*)$")
        && matcher.arg_count.is_none()
        && matcher.arg_count_min.is_none()
        && matcher.arg_count_max.is_none()
        && matcher.arg_types.is_empty()
        && matcher.arg_type_regexes.is_empty()
}

fn encode_metadata_archive(metadata: &[RuleMetadata]) -> Vec<u8> {
    const MAGIC: &[u8; 8] = b"UFMETA01";
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    for rule in metadata {
        let id = rule.id.as_bytes();
        let payload = bincode::serialize(rule)
            .unwrap_or_else(|error| panic!("failed to serialize metadata '{}': {error}", rule.id));
        let id_len = u32::try_from(id.len()).expect("metadata id exceeds archive limit");
        let payload_len =
            u32::try_from(payload.len()).expect("metadata payload exceeds archive limit");
        bytes.extend_from_slice(&id_len.to_le_bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(id);
        bytes.extend_from_slice(&payload);
    }
    bytes
}

fn attach_general_java_sanitization_policy(rules: &mut RuleSet) {
    const POLICY_STANDARDS: [&str; 3] = [
        "cert:02000010140200",
        "legacy-product:0202000010140200",
        "legacy-product:0302000010140200",
    ];
    for metadata in &mut rules.metadata {
        if !metadata
            .cwe
            .iter()
            .any(|cwe| matches!(cwe.as_str(), "CWE-89" | "CWE-112" | "CWE-116" | "CWE-611"))
        {
            continue;
        }
        for standard in POLICY_STANDARDS {
            if !metadata.standards.iter().any(|value| value == standard) {
                metadata.standards.push(standard.to_string());
            }
        }
    }
}

/// The MIT-derived catalogs (`crates/models/src/catalog/mit.rs`) are
/// distributed as plain YAML/JSON on disk but must not sit as
/// `strings`-recoverable plaintext in the compiled binary — see
/// `uniflow_rule_crypto`'s module doc comment for exactly what obfuscating
/// them here does and does not achieve. Each source file is read once at
/// build time, transformed under its own stable label (mirrored exactly by
/// the matching `include_bytes!`/decrypt call in `mit.rs` — the two sides
/// must always agree), and written to `OUT_DIR` as `<output_name>.enc`.
fn encrypt_mit_assets(manifest: &Path, out: &Path) {
    const ASSETS: &[(&str, &str, &str)] = &[
        ("pysa-python.yml", "mit/pysa-python.yml", "mit-pysa-python.yml.enc"),
        ("mariana-java.yml", "mit/mariana-java.yml", "mit-mariana-java.yml.enc"),
        ("infer-c-cpp.yml", "mit/infer-c-cpp.yml", "mit-infer-c-cpp.yml.enc"),
        ("codeql-security.yml", "mit/codeql-security.yml", "mit-codeql-security.yml.enc"),
        ("manifest.json", "mit/manifest.json", "mit-manifest.json.enc"),
    ];
    let mit_dir = manifest.join("../../rules/mit");
    for (source_name, label, output_name) in ASSETS {
        let source_path = mit_dir.join(source_name);
        println!("cargo:rerun-if-changed={}", source_path.display());
        let plaintext = fs::read(&source_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", source_path.display()));
        let ciphertext = uniflow_rule_crypto::transform(label, &plaintext);
        fs::write(out.join(output_name), ciphertext)
            .unwrap_or_else(|error| panic!("failed to write encrypted {output_name}: {error}"));
    }
}
