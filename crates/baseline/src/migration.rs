use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyRuleInventory {
    pub id: String,
    pub source: String,
    pub expected_rule_count: usize,
    pub rules: Vec<LegacyRuleEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyRuleEntry {
    pub legacy_id: String,
    #[serde(default)]
    pub state: MigrationState,
    #[serde(default)]
    pub source_files: Vec<String>,
    #[serde(default)]
    pub execution_model: String,
    #[serde(default)]
    pub testcase: Option<String>,
    #[serde(default)]
    pub native_rule_ids: Vec<String>,
    #[serde(default)]
    pub standards: Vec<String>,
    #[serde(default)]
    pub translations_complete: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    #[default]
    PendingSource,
    Classified,
    Implemented,
    Verified,
    BlockedEncrypted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyAssetKind {
    ClangSource,
    TableGenRegistry,
    StructuredRules,
    Documentation,
    Archive,
    NativeBinary,
    Encrypted,
    Opaque,
}

/// Encryption formats used by the legacy rule packages. These values were
/// recovered from the corresponding legacy source/JVM bytecode; decryption is
/// implemented locally so importing rules never executes a legacy binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyEncryptionProfile {
    JavaNodeAes128Cfb,
    CppAes256Cbc,
}

const JAVA_NODE_KEY: [u8; 16] = [
    0xe7, 0x98, 0x9b, 0xe6, 0x8f, 0x23, 0x6a, 0x01, 0xcd, 0x88, 0x78, 0x31, 0x29, 0xa1, 0x5f, 0x95,
];
const JAVA_NODE_IV: [u8; 16] = [
    0x2d, 0xd4, 0x78, 0x86, 0x60, 0x74, 0xf8, 0x29, 0x10, 0x36, 0xd1, 0xa8, 0x87, 0x2e, 0x56, 0x36,
];
const CPP_KEY: [u8; 32] = [
    0x80, 0xcb, 0x45, 0xad, 0x6a, 0xe4, 0x0a, 0x3a, 0x54, 0x5d, 0x8c, 0xcd, 0xec, 0x5a, 0x90, 0xbb,
    0x46, 0xf9, 0x97, 0x98, 0xcc, 0x91, 0x92, 0x21, 0xaa, 0x49, 0x0d, 0xb3, 0xcb, 0xf4, 0xfb, 0xa5,
];
const CPP_IV: [u8; 16] = [
    0xbe, 0x50, 0x56, 0x3d, 0x7f, 0x60, 0x5a, 0xae, 0xe1, 0xff, 0xf2, 0x18, 0xa1, 0x36, 0x2a, 0xf0,
];

pub fn legacy_encryption_profile(path: &Path) -> Option<LegacyEncryptionProfile> {
    if !path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("enc"))
    {
        return None;
    }
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if components.iter().any(|component| component == "java")
        || components.iter().any(|component| component == "nodejs")
    {
        Some(LegacyEncryptionProfile::JavaNodeAes128Cfb)
    } else if components.iter().any(|component| component == "cpp") {
        Some(LegacyEncryptionProfile::CppAes256Cbc)
    } else {
        None
    }
}

pub fn decrypt_legacy_rule_asset(path: &Path, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let profile = legacy_encryption_profile(path).with_context(|| {
        format!(
            "no supported legacy encryption profile for {}",
            path.display()
        )
    })?;
    let plaintext = match profile {
        LegacyEncryptionProfile::JavaNodeAes128Cfb => decrypt_aes128_cfb(ciphertext),
        LegacyEncryptionProfile::CppAes256Cbc => decrypt_aes256_cbc(ciphertext)?,
    };
    anyhow::ensure!(
        std::str::from_utf8(&plaintext).is_ok(),
        "decrypted legacy rule {} is not UTF-8",
        path.display()
    );
    Ok(plaintext)
}

pub fn decrypt_legacy_rule_tree(
    input_root: &Path,
    output_root: &Path,
    overwrite: bool,
) -> Result<LegacyDecryptionReport> {
    anyhow::ensure!(
        input_root.is_dir(),
        "legacy encrypted-rule root is not a directory: {}",
        input_root.display()
    );
    anyhow::ensure!(
        absolute_path(input_root)? != absolute_path(output_root)?,
        "legacy decrypted-rule output must differ from the input root"
    );

    let mut paths = Vec::new();
    collect_files(input_root, input_root, &mut paths)?;
    paths.retain(|path| legacy_encryption_profile(path).is_some());
    paths.sort();
    fs::create_dir_all(output_root).with_context(|| {
        format!(
            "failed to create legacy decrypted-rule root {}",
            output_root.display()
        )
    })?;

    let mut assets = Vec::with_capacity(paths.len());
    for source in paths {
        let relative = source
            .strip_prefix(input_root)
            .with_context(|| format!("legacy rule escaped input root: {}", source.display()))?;
        let mut output = output_root.join(relative);
        if output.extension().is_some_and(|value| value == "enc") {
            output.set_extension("");
        }
        if output.exists() && !overwrite {
            anyhow::bail!(
                "refusing to overwrite decrypted legacy rule {}",
                output.display()
            );
        }

        let ciphertext = fs::read(&source)
            .with_context(|| format!("failed to read encrypted rule {}", source.display()))?;
        let profile = legacy_encryption_profile(&source).expect("filtered encryption profile");
        let plaintext = decrypt_legacy_rule_asset(&source, &ciphertext)?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create decrypted rule directory {}",
                    parent.display()
                )
            })?;
        }
        write_decrypted_file(&output, &plaintext, overwrite)?;
        assets.push(LegacyDecryptedAsset {
            source: relative.to_string_lossy().replace('\\', "/"),
            output: output
                .strip_prefix(output_root)
                .unwrap_or(&output)
                .to_string_lossy()
                .replace('\\', "/"),
            profile,
            plaintext_size: plaintext.len(),
        });
    }

    Ok(LegacyDecryptionReport {
        input_root: input_root.display().to_string(),
        output_root: output_root.display().to_string(),
        assets,
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("failed to resolve current directory")?
            .join(path))
    }
}

fn write_decrypted_file(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let temporary = path.with_extension(format!(
        "{}.uniflow-tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("rule")
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("failed to create temporary rule {}", temporary.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to write decrypted rule {}", path.display()));
    }
    drop(file);
    if overwrite && path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to replace decrypted rule {}", path.display()))?;
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to publish decrypted rule {}", path.display()));
    }
    Ok(())
}

fn decrypt_aes128_cfb(ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(&JAVA_NODE_KEY));
    let mut feedback = JAVA_NODE_IV;
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let mut stream = GenericArray::clone_from_slice(&feedback);
        cipher.encrypt_block(&mut stream);
        plaintext.extend(
            chunk
                .iter()
                .zip(stream.iter())
                .map(|(left, right)| left ^ right),
        );
        if chunk.len() == 16 {
            feedback.copy_from_slice(chunk);
        }
    }
    plaintext
}

fn decrypt_aes256_cbc(ciphertext: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(
        !ciphertext.is_empty() && ciphertext.len() % 16 == 0,
        "legacy C/C++ ciphertext length must be a non-zero multiple of 16"
    );
    let cipher = Aes256::new(GenericArray::from_slice(&CPP_KEY));
    let mut previous = CPP_IV;
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend(
            block
                .iter()
                .zip(previous.iter())
                .map(|(left, right)| left ^ right),
        );
        previous.copy_from_slice(chunk);
    }
    strip_pkcs7(&mut plaintext)?;
    Ok(plaintext)
}

fn strip_pkcs7(bytes: &mut Vec<u8>) -> Result<()> {
    let padding = *bytes.last().context("decrypted legacy rule is empty")? as usize;
    anyhow::ensure!(
        (1..=16).contains(&padding) && bytes.len() >= padding,
        "legacy C/C++ rule has invalid PKCS#7 padding"
    );
    anyhow::ensure!(
        bytes[bytes.len() - padding..]
            .iter()
            .all(|byte| *byte as usize == padding),
        "legacy C/C++ rule has inconsistent PKCS#7 padding"
    );
    bytes.truncate(bytes.len() - padding);
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyAsset {
    pub path: String,
    pub size: u64,
    pub kind: LegacyAssetKind,
    pub encryption_hint: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyAssetAudit {
    pub root: String,
    pub files: Vec<LegacyAsset>,
    pub encrypted_candidates: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyDecryptedAsset {
    pub source: String,
    pub output: String,
    pub profile: LegacyEncryptionProfile,
    pub plaintext_size: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyDecryptionReport {
    pub input_root: String,
    pub output_root: String,
    pub assets: Vec<LegacyDecryptedAsset>,
}

pub fn classify_legacy_asset(path: &Path, bytes: &[u8]) -> LegacyAssetKind {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let known_native = bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(b"MZ");
    if known_native || matches!(extension.as_str(), "dylib" | "so" | "dll" | "exe") {
        return LegacyAssetKind::NativeBinary;
    }
    if matches!(
        extension.as_str(),
        "enc" | "encrypted" | "aes" | "gpg" | "pgp"
    ) || bytes.starts_with(b"Salted__")
        || bytes.starts_with(b"-----BEGIN PGP MESSAGE-----")
        || bytes.starts_with(b"age-encryption.org/")
        || looks_high_entropy(bytes)
    {
        return LegacyAssetKind::Encrypted;
    }
    if extension == "td" || file_name == "checkerscpp.td" {
        return LegacyAssetKind::TableGenRegistry;
    }
    if matches!(
        extension.as_str(),
        "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" | "inc"
    ) {
        return LegacyAssetKind::ClangSource;
    }
    if matches!(
        extension.as_str(),
        "json" | "yaml" | "yml" | "xml" | "csv" | "toml" | "plist" | "rules"
    ) {
        return LegacyAssetKind::StructuredRules;
    }
    if matches!(extension.as_str(), "md" | "txt" | "rst" | "html" | "htm") {
        return LegacyAssetKind::Documentation;
    }
    if matches!(
        extension.as_str(),
        "zip" | "gz" | "tgz" | "tar" | "xz" | "bz2" | "7z"
    ) || bytes.starts_with(b"PK\x03\x04")
    {
        return LegacyAssetKind::Archive;
    }
    LegacyAssetKind::Opaque
}

pub fn audit_legacy_rule_tree(root: &Path) -> Result<LegacyAssetAudit> {
    anyhow::ensure!(
        root.is_dir(),
        "legacy rule root is not a directory: {}",
        root.display()
    );
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to stat legacy asset {}", path.display()))?;
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read legacy asset {}", path.display()))?;
        let kind = classify_legacy_asset(&path, &bytes);
        files.push(LegacyAsset {
            path: path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/"),
            size: metadata.len(),
            encryption_hint: kind == LegacyAssetKind::Encrypted,
            kind,
        });
    }
    let encrypted_candidates = files.iter().filter(|file| file.encryption_hint).count();
    Ok(LegacyAssetAudit {
        root: root.display().to_string(),
        files,
        encrypted_candidates,
    })
}

fn collect_files(root: &Path, directory: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory).with_context(|| {
        format!(
            "failed to list legacy rule directory {}",
            directory.display()
        )
    })? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_files(root, &path, out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }
    let _ = root;
    Ok(())
}

fn looks_high_entropy(bytes: &[u8]) -> bool {
    if bytes.len() < 256 || std::str::from_utf8(bytes).is_ok() {
        return false;
    }
    let sample = &bytes[..bytes.len().min(64 * 1024)];
    let mut counts = [0usize; 256];
    for byte in sample {
        counts[*byte as usize] += 1;
    }
    let length = sample.len() as f64;
    let entropy = counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum::<f64>();
    entropy >= 7.5
}

impl LegacyRuleInventory {
    pub fn from_json_str(text: &str) -> Result<Self> {
        let inventory: Self =
            serde_json::from_str(text).context("invalid legacy rule inventory")?;
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.id.trim().is_empty(), "legacy inventory id is empty");
        anyhow::ensure!(
            !self.source.trim().is_empty(),
            "legacy inventory source is empty"
        );
        anyhow::ensure!(
            self.rules.len() == self.expected_rule_count,
            "legacy inventory {} expected {} rules but contains {}",
            self.id,
            self.expected_rule_count,
            self.rules.len()
        );
        let mut ids = HashSet::new();
        for rule in &self.rules {
            anyhow::ensure!(!rule.legacy_id.trim().is_empty(), "legacy rule id is empty");
            anyhow::ensure!(
                rule.legacy_id == "scs.taint" || rule.legacy_id.starts_with("anzu."),
                "unsupported legacy checker namespace: {}",
                rule.legacy_id
            );
            anyhow::ensure!(
                ids.insert(rule.legacy_id.as_str()),
                "duplicate legacy checker id {}",
                rule.legacy_id
            );
            if matches!(
                rule.state,
                MigrationState::Implemented | MigrationState::Verified
            ) {
                anyhow::ensure!(
                    !rule.execution_model.trim().is_empty(),
                    "implemented legacy checker {} has no execution model",
                    rule.legacy_id
                );
                anyhow::ensure!(
                    !rule.native_rule_ids.is_empty(),
                    "implemented legacy checker {} has no native UniFlow rule id",
                    rule.legacy_id
                );
                anyhow::ensure!(
                    rule.testcase
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty()),
                    "implemented legacy checker {} has no testcase",
                    rule.legacy_id
                );
            }
            if rule.state == MigrationState::Verified {
                anyhow::ensure!(
                    !rule.source_files.is_empty(),
                    "verified legacy checker {} has no source provenance",
                    rule.legacy_id
                );
                anyhow::ensure!(
                    rule.translations_complete,
                    "verified legacy checker {} is missing zh-CN/en/zh-TW content",
                    rule.legacy_id
                );
            }
            if rule.state == MigrationState::BlockedEncrypted {
                anyhow::ensure!(
                    !rule.source_files.is_empty(),
                    "encrypted legacy checker {} has no blocked source file",
                    rule.legacy_id
                );
            }
        }
        anyhow::ensure!(
            ids.contains("scs.taint"),
            "legacy inventory is missing scs.taint"
        );
        Ok(())
    }
}

pub fn legacy_cpp_inventory() -> Result<LegacyRuleInventory> {
    LegacyRuleInventory::from_json_str(include_str!(
        "../../../rules/migration/anzu-cpp-checkers.json"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(pair, 16).expect("valid hex")
            })
            .collect()
    }

    #[test]
    fn legacy_cpp_inventory_contains_all_registered_checkers() {
        let inventory = legacy_cpp_inventory().expect("valid legacy C/C++ checker inventory");
        assert_eq!(inventory.expected_rule_count, 280);
        assert_eq!(inventory.rules.len(), 280);
        assert_eq!(inventory.rules[0].legacy_id, "scs.taint");
        assert!(inventory
            .rules
            .iter()
            .any(|rule| rule.legacy_id == "anzu.SizeofParamArrayChecker"));
    }

    #[test]
    fn implemented_inventory_entries_require_testcases() {
        let inventory = LegacyRuleInventory {
            id: "test".to_string(),
            source: "test.td".to_string(),
            expected_rule_count: 1,
            rules: vec![LegacyRuleEntry {
                legacy_id: "anzu.TestChecker".to_string(),
                state: MigrationState::Implemented,
                source_files: vec!["TestChecker.cpp".to_string()],
                execution_model: "frontend".to_string(),
                testcase: None,
                native_rule_ids: vec!["anzu.TestChecker".to_string()],
                standards: Vec::new(),
                translations_complete: true,
            }],
        };
        assert!(inventory.validate().is_err());
    }

    #[test]
    fn classifies_source_registry_rules_and_encrypted_assets() {
        assert_eq!(
            classify_legacy_asset(Path::new("CheckersCpp.td"), b"def Checker;"),
            LegacyAssetKind::TableGenRegistry
        );
        assert_eq!(
            classify_legacy_asset(Path::new("AssignmentChecker.cpp"), b"class Checker {};"),
            LegacyAssetKind::ClangSource
        );
        assert_eq!(
            classify_legacy_asset(Path::new("rules.yaml"), b"rules: []"),
            LegacyAssetKind::StructuredRules
        );
        assert_eq!(
            classify_legacy_asset(Path::new("rules.enc"), b"Salted__ciphertext"),
            LegacyAssetKind::Encrypted
        );
    }

    #[test]
    fn audits_nested_legacy_rule_tree_without_executing_assets() {
        let root =
            std::env::temp_dir().join(format!("uniflow-legacy-rule-audit-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale audit fixture");
        }
        fs::create_dir_all(root.join("checker")).expect("fixture directory");
        fs::write(root.join("checker/CheckersCpp.td"), "def Checker;").expect("registry fixture");
        fs::write(root.join("rules.enc"), "Salted__ciphertext").expect("encrypted fixture");

        let audit = audit_legacy_rule_tree(&root).expect("legacy audit");
        assert_eq!(audit.files.len(), 2);
        assert_eq!(audit.encrypted_candidates, 1);
        assert!(audit.files.iter().any(|file| {
            file.path == "checker/CheckersCpp.td" && file.kind == LegacyAssetKind::TableGenRegistry
        }));
        assert!(audit
            .files
            .iter()
            .any(|file| { file.path == "rules.enc" && file.kind == LegacyAssetKind::Encrypted }));
        fs::remove_dir_all(&root).expect("remove audit fixture");
    }

    #[test]
    fn decrypts_java_and_node_aes_cfb_rule_assets() {
        let ciphertext = decode_hex(concat!(
            "a56f9d1fa0651665f86c1a89fc17769c",
            "0b67363577bdcad0a20d83b874f7e275",
            "6c7b9183408f7614b8301807d66b450a",
            "d4b1dd9068e8995d14e933ef2dc0b4fb",
            "2002bf6593d151f8f7ca44b766f1854b",
            "87bda44386d58731a3e0101435c81f84"
        ));
        let plaintext =
            decrypt_legacy_rule_asset(Path::new("sast/java/rules/java_a.yaml.enc"), &ciphertext)
                .expect("decrypt Java rule prefix");
        assert!(String::from_utf8(plaintext)
            .expect("UTF-8 YAML")
            .starts_with("rules:\n- !sourceRule\n  id: 6C33FFFC-60B4-4E34-891D-E9700D7F009B"));
        assert_eq!(
            legacy_encryption_profile(Path::new("sast/nodejs/rules/javascript_a.yaml.enc")),
            Some(LegacyEncryptionProfile::JavaNodeAes128Cfb)
        );
    }

    #[test]
    fn decrypts_cpp_aes_cbc_rule_assets_and_validates_padding() {
        let ciphertext = decode_hex("85e92f2722d5c27fcc1a60cbb0ca3aa7");
        let plaintext = decrypt_legacy_rule_asset(
            Path::new("sast/cpp/rules/rules/cpp/CPP_dataflow.yaml.enc"),
            &ciphertext,
        )
        .expect("decrypt C/C++ rule");
        assert_eq!(plaintext, b"rules: []\n");

        let mut truncated = ciphertext;
        truncated.pop();
        assert!(decrypt_legacy_rule_asset(
            Path::new("sast/cpp/rules/rules/cpp/CPP_dataflow.yaml.enc"),
            &truncated
        )
        .is_err());
    }

    #[test]
    fn decrypts_supported_rule_tree_without_overwriting_outputs() {
        let fixture =
            std::env::temp_dir().join(format!("uniflow-legacy-decryption-{}", std::process::id()));
        if fixture.exists() {
            fs::remove_dir_all(&fixture).expect("remove stale decryption fixture");
        }
        let input = fixture.join("input");
        let output = fixture.join("output");
        let encrypted = input.join("sast/cpp/rules/rules/cpp/fixture.yaml.enc");
        fs::create_dir_all(encrypted.parent().expect("fixture parent"))
            .expect("create fixture directory");
        fs::write(&encrypted, decode_hex("85e92f2722d5c27fcc1a60cbb0ca3aa7"))
            .expect("write encrypted fixture");

        let report = decrypt_legacy_rule_tree(&input, &output, false).expect("decrypt rule tree");
        assert_eq!(report.assets.len(), 1);
        assert_eq!(
            report.assets[0].profile,
            LegacyEncryptionProfile::CppAes256Cbc
        );
        assert_eq!(
            fs::read(output.join("sast/cpp/rules/rules/cpp/fixture.yaml"))
                .expect("read decrypted fixture"),
            b"rules: []\n"
        );
        assert!(decrypt_legacy_rule_tree(&input, &output, false).is_err());
        fs::remove_dir_all(&fixture).expect("remove decryption fixture");
    }
}
