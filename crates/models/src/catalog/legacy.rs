use anyhow::Context;
use std::collections::HashSet;

const LEGACY_JAVA_RULES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-java.bin"));
const LEGACY_JAVA_METADATA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-java.metadata.bin"));
const LEGACY_JAVASCRIPT_RULES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-javascript.bin"));
const LEGACY_JAVASCRIPT_METADATA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-javascript.metadata.bin"));
const LEGACY_C_CPP_RULES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-c-cpp.bin"));
const LEGACY_C_CPP_METADATA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-c-cpp.metadata.bin"));
const LEGACY_OBJC_OBJCPP_RULES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-objc-objcpp.bin"));
const LEGACY_OBJC_OBJCPP_METADATA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-objc-objcpp.metadata.bin"));
const LEGACY_PYTHON_RULES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-python.bin"));
const LEGACY_PYTHON_METADATA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-python.metadata.bin"));
const LEGACY_GO_RULES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/legacy-go.bin"));
const LEGACY_GO_METADATA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-go.metadata.bin"));
const LEGACY_CSHARP_RULES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-csharp.bin"));
const LEGACY_CSHARP_METADATA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-csharp.metadata.bin"));
const LEGACY_RUBY_RULES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-ruby.bin"));
const LEGACY_RUBY_METADATA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/legacy-ruby.metadata.bin"));

pub fn legacy_models_for(language: Language) -> Result<RuleSet> {
    let mut rules = legacy_analysis_models_for(language.clone())?;
    rules.metadata = decode_metadata_archive(legacy_metadata_bytes(&language), None)?;
    Ok(rules)
}

pub fn legacy_analysis_models_for(language: Language) -> Result<RuleSet> {
    let rules = match language {
        Language::Cpp => decode_legacy_pack(LEGACY_C_CPP_RULES, "C/C++")?,
        Language::C => retarget_models(
            decode_legacy_pack(LEGACY_C_CPP_RULES, "C/C++")?,
            language,
        ),
        Language::ObjC => decode_legacy_pack(LEGACY_OBJC_OBJCPP_RULES, "Objective-C")?,
        Language::ObjCpp => retarget_models(
            decode_legacy_pack(LEGACY_OBJC_OBJCPP_RULES, "Objective-C++")?,
            language,
        ),
        Language::Java => decode_legacy_pack(LEGACY_JAVA_RULES, "Java")?,
        Language::Kotlin | Language::Jsp => {
            retarget_models(decode_legacy_pack(LEGACY_JAVA_RULES, "Java")?, language)
        }
        Language::JavaScript => decode_legacy_pack(LEGACY_JAVASCRIPT_RULES, "JavaScript")?,
        Language::Python => decode_legacy_pack(LEGACY_PYTHON_RULES, "Python")?,
        Language::Go => decode_legacy_pack(LEGACY_GO_RULES, "Go")?,
        Language::CSharp => decode_legacy_pack(LEGACY_CSHARP_RULES, "C#")?,
        Language::Ruby => decode_legacy_pack(LEGACY_RUBY_RULES, "Ruby")?,
        _ => RuleSet::default(),
    };
    Ok(rules)
}

fn decode_legacy_pack(bytes: &[u8], name: &str) -> Result<RuleSet> {
    bincode::deserialize(bytes).with_context(|| format!("invalid bundled {name} rule table"))
}

pub fn attach_legacy_metadata_for_ids(
    language: &Language,
    rules: &mut RuleSet,
    requested: &HashSet<String>,
) -> Result<()> {
    if requested.is_empty() {
        return Ok(());
    }
    let existing = rules
        .metadata
        .iter()
        .map(|metadata| metadata.id.clone())
        .collect::<HashSet<_>>();
    let mut metadata = decode_metadata_archive(legacy_metadata_bytes(language), Some(requested))?;
    metadata.retain(|item| !existing.contains(&item.id));
    rules.metadata.extend(metadata);
    Ok(())
}

fn legacy_metadata_bytes(language: &Language) -> &'static [u8] {
    match language {
        Language::C | Language::Cpp => LEGACY_C_CPP_METADATA,
        Language::ObjC | Language::ObjCpp => LEGACY_OBJC_OBJCPP_METADATA,
        Language::Java | Language::Kotlin | Language::Jsp => LEGACY_JAVA_METADATA,
        Language::JavaScript => LEGACY_JAVASCRIPT_METADATA,
        Language::Python => LEGACY_PYTHON_METADATA,
        Language::Go => LEGACY_GO_METADATA,
        Language::CSharp => LEGACY_CSHARP_METADATA,
        Language::Ruby => LEGACY_RUBY_METADATA,
        _ => &[],
    }
}

fn decode_metadata_archive(
    mut bytes: &[u8],
    requested: Option<&HashSet<String>>,
) -> Result<Vec<RuleMetadata>> {
    const MAGIC: &[u8; 8] = b"UFMETA01";
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        anyhow::bail!("invalid bundled metadata archive magic");
    }
    bytes = &bytes[MAGIC.len()..];
    let count = take_u32(&mut bytes)? as usize;
    let mut metadata = Vec::new();
    for _ in 0..count {
        let id_len = take_u32(&mut bytes)? as usize;
        let payload_len = take_u32(&mut bytes)? as usize;
        let id_bytes = take_bytes(&mut bytes, id_len)?;
        let payload = take_bytes(&mut bytes, payload_len)?;
        let id = std::str::from_utf8(id_bytes).context("metadata archive id is not UTF-8")?;
        if requested.is_some_and(|ids| !ids.contains(id)) {
            continue;
        }
        let rule: RuleMetadata = bincode::deserialize(payload)
            .with_context(|| format!("invalid bundled metadata for '{id}'"))?;
        if rule.id != id {
            anyhow::bail!("bundled metadata index mismatch for '{id}'");
        }
        metadata.push(rule);
    }
    Ok(metadata)
}

fn take_u32(bytes: &mut &[u8]) -> Result<u32> {
    let raw = take_bytes(bytes, 4)?;
    Ok(u32::from_le_bytes(raw.try_into().expect("four bytes")))
}

fn take_bytes<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    if bytes.len() < length {
        anyhow::bail!("truncated bundled metadata archive");
    }
    let (head, tail) = bytes.split_at(length);
    *bytes = tail;
    Ok(head)
}
