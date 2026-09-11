use std::{
    collections::hash_map::DefaultHasher,
    env, fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
};
use uniflow_rules::{RuleMetadata, RuleSet};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let rules = manifest.join("../../rules/legacy");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));

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
    const FORMAT_VERSION: &str = "uniflow-rule-table-v3";
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
