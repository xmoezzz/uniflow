//! Language packages *installed* in a root filesystem (a squashed container
//! image), as opposed to declared in a source tree's manifests. An image
//! usually ships no lockfile for what `pip install` / `npm install -g` /
//! `COPY app.jar` put into it, so a manifest-only scan sees none of it —
//! the benchmark's "`pip@9.0.3` in the Rocky image" miss that every other
//! scanner reports. Evidence read, per ecosystem:
//! - PyPI: `*.dist-info/METADATA` and `*.egg-info` (`PKG-INFO`) under any
//!   `site-packages` / `dist-packages`, and `*.whl` files anywhere — e.g.
//!   RHEL-family `/usr/share/python3-wheels/pip-21.2.3-….whl`, which
//!   ensurepip installs into every venv created on the system;
//! - npm: `node_modules/<name>/package.json` and `node_modules/@scope/<name>/…`;
//! - Maven: `META-INF/maven/<g>/<a>/pom.properties` inside `.jar`/`.war`/
//!   `.ear` files, recursing into nested jars (Spring Boot `BOOT-INF/lib`,
//!   `WEB-INF/lib`, shaded jars);
//! - Go: the build info the Go linker embeds in every binary (Go ≥ 1.18
//!   format) — module dependencies plus the toolchain as `stdlib`;
//! - Cargo: the `.dep-v0` section `cargo auditable` embeds in ELF binaries.
//!
//! Everything is read-only and bounded (file sizes, nesting depth, entry
//! counts) because an image is untrusted input.
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use uniflow_sca_core::{Dependency, ScanWarning};

/// Largest single file read for binary inspection (Go/Rust executables).
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
/// Largest archive opened for jar inspection, and nested-jar entry size.
const MAX_JAR_BYTES: u64 = 512 * 1024 * 1024;
const MAX_NESTED_JAR_BYTES: u64 = 128 * 1024 * 1024;
const MAX_JAR_DEPTH: usize = 3;

pub fn inventory(root: &Path) -> (Vec<Dependency>, Vec<ScanWarning>) {
    let mut deps = Vec::new();
    let mut warnings = Vec::new();
    let mut seen_python: BTreeSet<(String, String)> = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy();
        let in_site_packages = path.parent().and_then(|p| p.file_name()).is_some_and(|p| p == "site-packages" || p == "dist-packages");
        if entry.file_type().is_dir() {
            if in_site_packages && (name.ends_with(".dist-info") || name.ends_with(".egg-info")) {
                let meta = if name.ends_with(".dist-info") { path.join("METADATA") } else { path.join("PKG-INFO") };
                if let Some(dep) = python_metadata(&meta, &path.display().to_string()) {
                    if seen_python.insert((dep.name.to_ascii_lowercase(), dep.version.clone())) {
                        deps.push(dep);
                    }
                }
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        if in_site_packages && name.ends_with(".egg-info") {
            // A single-file egg-info is the PKG-INFO itself.
            if let Some(dep) = python_metadata(path, &path.display().to_string()) {
                if seen_python.insert((dep.name.to_ascii_lowercase(), dep.version.clone())) {
                    deps.push(dep);
                }
            }
            continue;
        }
        if let Some((pkg, version)) = wheel_name_version(&name) {
            if seen_python.insert((pkg.to_ascii_lowercase(), version.clone())) {
                deps.push(installed("pypi", &pkg, &version, &path.display().to_string()));
            }
            continue;
        }
        if name == "package.json" && is_node_module_manifest(path) {
            if let Some(dep) = node_package(path) {
                deps.push(dep);
            }
            continue;
        }
        if name.ends_with(".jar") || name.ends_with(".war") || name.ends_with(".ear") {
            match jar_artifacts(path) {
                Ok(found) => deps.extend(found),
                Err(error) => warnings.push(ScanWarning::new(
                    "installed_package_unreadable",
                    Some(path.display().to_string()),
                    format!("could not read {name}: {error:#}"),
                    &[("file", name.to_string())],
                )),
            }
            continue;
        }
        if entry.metadata().is_ok_and(|m| m.len() <= MAX_BINARY_BYTES && m.len() >= 4) && is_executable_candidate(path) {
            if let Ok(bytes) = std::fs::read(path) {
                let display = path.display().to_string();
                deps.extend(go_build_info(&bytes, &display));
                deps.extend(cargo_auditable(&bytes, &display));
            }
        }
    }
    (deps, warnings)
}

fn installed(ecosystem: &str, name: &str, version: &str, evidence: &str) -> Dependency {
    // `direct` means "the application asked for it"; for an image there is
    // no application manifest to say so — every installed package counts
    // as something the image itself ships.
    Dependency { ecosystem: ecosystem.into(), name: name.to_string(), version: version.to_string(), manifest_path: evidence.to_string(), direct: true }
}

// ------------------------------------------------------------------ PyPI --

/// `Name:` / `Version:` from core metadata (RFC 822 headers, up to the
/// first blank line).
fn python_metadata(path: &Path, evidence: &str) -> Option<Dependency> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(v) = line.strip_prefix("Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
    }
    Some(installed("pypi", &name?, &version?, evidence))
}

/// PEP 427: `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl`,
/// with `-` in the distribution name escaped as `_`.
fn wheel_name_version(file_name: &str) -> Option<(String, String)> {
    let stem = file_name.strip_suffix(".whl")?;
    let parts: Vec<&str> = stem.split('-').collect();
    if !(5..=6).contains(&parts.len()) || !parts[1].starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some((parts[0].to_string(), parts[1].to_string()))
}

// ------------------------------------------------------------------- npm --

/// `…/node_modules/<name>/package.json` or `…/node_modules/@scope/<name>/package.json`
/// — not a package's nested fixture/test `package.json`.
fn is_node_module_manifest(path: &Path) -> bool {
    let Some(dir) = path.parent() else { return false };
    let Some(parent) = dir.parent() else { return false };
    if parent.file_name().is_some_and(|n| n == "node_modules") {
        return true;
    }
    parent.file_name().is_some_and(|n| n.to_string_lossy().starts_with('@')) && parent.parent().and_then(|p| p.file_name()).is_some_and(|n| n == "node_modules")
}

fn node_package(path: &Path) -> Option<Dependency> {
    let text = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let name = json.get("name")?.as_str()?;
    let version = json.get("version")?.as_str()?;
    Some(installed("npm", name, version, &path.display().to_string()))
}

// ----------------------------------------------------------------- Maven --

fn jar_artifacts(path: &Path) -> anyhow::Result<Vec<Dependency>> {
    if std::fs::metadata(path)?.len() > MAX_JAR_BYTES {
        anyhow::bail!("larger than {} MB", MAX_JAR_BYTES / 1024 / 1024);
    }
    let file = std::fs::File::open(path)?;
    let mut out = Vec::new();
    jar_walk(zip::ZipArchive::new(file)?, &path.display().to_string(), 0, &mut out)?;
    Ok(out)
}

fn jar_walk<R: std::io::Read + std::io::Seek>(mut archive: zip::ZipArchive<R>, evidence: &str, depth: usize, out: &mut Vec<Dependency>) -> anyhow::Result<()> {
    for index in 0..archive.len().min(200_000) {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_string();
        if name.starts_with("META-INF/maven/") && name.ends_with("/pom.properties") {
            let mut text = String::new();
            entry.by_ref().take(64 * 1024).read_to_string(&mut text)?;
            let prop = |key: &str| {
                text.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.trim_start().strip_prefix('=')).map(|v| v.trim().to_string()))
            };
            if let (Some(group), Some(artifact), Some(version)) = (prop("groupId"), prop("artifactId"), prop("version")) {
                out.push(installed("maven", &format!("{group}:{artifact}"), &version, &format!("{evidence}!/{name}")));
            }
        } else if depth < MAX_JAR_DEPTH && (name.ends_with(".jar") || name.ends_with(".war")) && entry.size() <= MAX_NESTED_JAR_BYTES {
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            entry.by_ref().take(MAX_NESTED_JAR_BYTES).read_to_end(&mut bytes)?;
            if let Ok(nested) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) {
                jar_walk(nested, &format!("{evidence}!/{name}"), depth + 1, out)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- binaries --

/// ELF, Mach-O or PE by magic — the only files worth reading whole.
fn is_executable_candidate(path: &Path) -> bool {
    let mut magic = [0u8; 4];
    let Ok(mut file) = std::fs::File::open(path) else { return false };
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    magic == *b"\x7fELF" || magic[..2] == *b"MZ" || matches!(u32::from_le_bytes(magic), 0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe)
}

const GO_BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// Go ≥ 1.18 embeds `\xff Go buildinf:` + ptr size + flags (bit 1 = the
/// strings follow inline) at a 16-byte aligned offset, then two
/// uvarint-length-prefixed strings: the toolchain version and the module
/// info (`mod`/`dep`/`=>` lines between 16-byte sentinels). Pre-1.18
/// binaries store pointers instead and are not decoded here.
pub fn go_build_info(bytes: &[u8], evidence: &str) -> Vec<Dependency> {
    let Some(at) = find_aligned(bytes, GO_BUILDINFO_MAGIC, 16) else { return Vec::new() };
    let header = &bytes[at..];
    if header.len() < 32 || header[15] & 0x2 == 0 {
        return Vec::new();
    }
    let mut cursor = &header[32..];
    let Some(toolchain) = read_uvarint_string(&mut cursor) else { return Vec::new() };
    let modinfo = read_uvarint_string(&mut cursor).unwrap_or_default();
    let mut deps = Vec::new();
    if let Some(version) = toolchain.strip_prefix("go") {
        // OSV tracks the standard library as module `stdlib`.
        let version = version.split([' ', '-']).next().unwrap_or(version);
        deps.push(installed("go", "stdlib", &format!("v{version}"), evidence));
    }
    for line in modinfo.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["dep", path, version, ..] => deps.push(installed("go", path, version, evidence)),
            // A replacement applies to the dep line just before it.
            ["=>", path, version, ..] => {
                if let Some(last) = deps.last_mut() {
                    if version.starts_with('v') {
                        last.name = path.to_string();
                        last.version = version.to_string();
                    } else {
                        deps.pop();
                    }
                }
            }
            _ => {}
        }
    }
    deps
}

fn find_aligned(haystack: &[u8], needle: &[u8], align: usize) -> Option<usize> {
    let mut offset = 0;
    while offset + needle.len() <= haystack.len() {
        if &haystack[offset..offset + needle.len()] == needle {
            return Some(offset);
        }
        offset += align;
    }
    None
}

fn read_uvarint_string(cursor: &mut &[u8]) -> Option<String> {
    let mut len: u64 = 0;
    let mut shift = 0;
    loop {
        let (&byte, rest) = cursor.split_first()?;
        *cursor = rest;
        len |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    let len = usize::try_from(len).ok()?;
    if len > cursor.len() {
        return None;
    }
    let (s, rest) = cursor.split_at(len);
    *cursor = rest;
    Some(String::from_utf8_lossy(s).into_owned())
}

/// `cargo auditable` stores zlib-compressed JSON
/// (`{"packages":[{"name","version","source",…}]}`) in an ELF section
/// named `.dep-v0`. Only ELF is decoded (the common container case).
pub fn cargo_auditable(bytes: &[u8], evidence: &str) -> Vec<Dependency> {
    let Some(section) = elf_section(bytes, ".dep-v0") else { return Vec::new() };
    let mut json = Vec::new();
    if flate2::read::ZlibDecoder::new(section).take(8 * 1024 * 1024).read_to_end(&mut json).is_err() {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&json) else { return Vec::new() };
    let Some(packages) = value.get("packages").and_then(|p| p.as_array()) else { return Vec::new() };
    packages
        .iter()
        .filter(|p| p.get("root").and_then(|r| r.as_bool()) != Some(true))
        .filter(|p| p.get("source").and_then(|s| s.as_str()).is_none_or(|s| s == "crates.io" || s.starts_with("registry")))
        .filter_map(|p| Some(installed("cargo", p.get("name")?.as_str()?, p.get("version")?.as_str()?, evidence)))
        .collect()
}

/// The bytes of the section named `wanted`, from the ELF section header
/// table (32/64-bit, either endianness).
fn elf_section<'a>(bytes: &'a [u8], wanted: &str) -> Option<&'a [u8]> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        return None;
    }
    let is64 = bytes[4] == 2;
    let le = bytes[5] == 1;
    let u16_at = |o: usize| -> Option<u64> {
        let b: [u8; 2] = bytes.get(o..o + 2)?.try_into().ok()?;
        Some(u64::from(if le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) }))
    };
    let u32_at = |o: usize| -> Option<u64> {
        let b: [u8; 4] = bytes.get(o..o + 4)?.try_into().ok()?;
        Some(u64::from(if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }))
    };
    let u64_at = |o: usize| -> Option<u64> {
        let b: [u8; 8] = bytes.get(o..o + 8)?.try_into().ok()?;
        Some(if le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) })
    };
    let word = |o: usize| if is64 { u64_at(o) } else { u32_at(o) };
    let (shoff, shentsize, shnum, shstrndx) =
        if is64 { (u64_at(0x28)?, u16_at(0x3a)?, u16_at(0x3c)?, u16_at(0x3e)?) } else { (u32_at(0x20)?, u16_at(0x2e)?, u16_at(0x30)?, u16_at(0x32)?) };
    let header = |i: u64| -> Option<(u64, u64, u64)> {
        let base = usize::try_from(shoff + i * shentsize).ok()?;
        // (name offset, file offset, size)
        if is64 {
            Some((u32_at(base)?, word(base + 0x18)?, word(base + 0x20)?))
        } else {
            Some((u32_at(base)?, word(base + 0x10)?, word(base + 0x14)?))
        }
    };
    let (_, strtab_off, strtab_size) = header(shstrndx)?;
    let strtab = bytes.get(usize::try_from(strtab_off).ok()?..usize::try_from(strtab_off + strtab_size).ok()?)?;
    for i in 0..shnum.min(4096) {
        let (name_off, off, size) = header(i)?;
        let name = strtab.get(usize::try_from(name_off).ok()?..)?;
        let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
        if name == wanted.as_bytes() {
            return bytes.get(usize::try_from(off).ok()?..usize::try_from(off + size).ok()?);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn uvarint(mut n: usize, out: &mut Vec<u8>) {
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }

    #[test]
    fn decodes_go_1_18_inline_build_info() {
        let mut bin = vec![0u8; 48];
        bin.extend_from_slice(GO_BUILDINFO_MAGIC);
        bin.push(8); // pointer size
        bin.push(0x2); // flags: inline strings
        bin.resize(48 + 32, 0);
        let modinfo = "0w\u{af}\u{c}\u{92}t\u{8}\u{2}A\u{e1}\u{c1}\u{7}\u{e6}\u{d6}\u{18}\u{e6}path\texample.com/app\nmod\texample.com/app\t(devel)\t\ndep\tgolang.org/x/net\tv0.7.0\th1:x=\ndep\tgithub.com/old/lib\tv1.0.0\th1:y=\n=>\tgithub.com/fork/lib\tv1.0.1\th1:z=\n";
        for s in ["go1.20.3", modinfo] {
            uvarint(s.len(), &mut bin);
            bin.extend_from_slice(s.as_bytes());
        }
        let deps = go_build_info(&bin, "/usr/local/bin/app");
        let got: Vec<(String, String)> = deps.iter().map(|d| (d.name.clone(), d.version.clone())).collect();
        assert_eq!(
            got,
            vec![
                ("stdlib".into(), "v1.20.3".into()),
                ("golang.org/x/net".into(), "v0.7.0".into()),
                ("github.com/fork/lib".into(), "v1.0.1".into()),
            ]
        );
    }

    /// A minimal 64-bit little-endian ELF with `.shstrtab` and `.dep-v0`.
    fn elf_with_section(name: &str, data: &[u8]) -> Vec<u8> {
        let shstrtab = format!("\0.shstrtab\0{name}\0");
        let mut out = vec![0u8; 64];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        let strtab_off = out.len();
        out.extend_from_slice(shstrtab.as_bytes());
        let data_off = out.len();
        out.extend_from_slice(data);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let shoff = out.len();
        let mut sh = |name_off: u32, off: usize, size: usize| {
            let mut h = [0u8; 64];
            h[..4].copy_from_slice(&name_off.to_le_bytes());
            h[0x18..0x20].copy_from_slice(&(off as u64).to_le_bytes());
            h[0x20..0x28].copy_from_slice(&(size as u64).to_le_bytes());
            out.extend_from_slice(&h);
        };
        sh(0, 0, 0);
        sh(1, strtab_off, shstrtab.len());
        sh(11, data_off, data.len());
        out[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        out[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        out[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes());
        out[0x3e..0x40].copy_from_slice(&1u16.to_le_bytes());
        out
    }

    #[test]
    fn wheel_file_names_follow_pep_427() {
        assert_eq!(wheel_name_version("pip-21.2.3-py3-none-any.whl"), Some(("pip".into(), "21.2.3".into())));
        assert_eq!(wheel_name_version("typing_extensions-4.7.1-1-py3-none-any.whl"), Some(("typing_extensions".into(), "4.7.1".into())));
        assert_eq!(wheel_name_version("not-a-wheel.whl"), None);
    }

    #[test]
    fn decodes_cargo_auditable_dependency_data() {
        let json = br#"{"packages":[{"name":"app","version":"0.1.0","source":"local","root":true},{"name":"smallvec","version":"1.6.0","source":"crates.io"},{"name":"inhouse","version":"2.0.0","source":"git"}]}"#;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(json).unwrap();
        let bin = elf_with_section(".dep-v0", &z.finish().unwrap());
        let deps = cargo_auditable(&bin, "/usr/bin/app");
        assert_eq!(deps.len(), 1, "the root crate and git sources are not registry packages");
        assert_eq!((deps[0].name.as_str(), deps[0].version.as_str()), ("smallvec", "1.6.0"));
    }

    #[test]
    fn inventories_site_packages_node_modules_and_fat_jars() {
        let root = tempfile::tempdir().unwrap();
        let sp = root.path().join("usr/lib/python3.6/site-packages");
        std::fs::create_dir_all(sp.join("pip-9.0.3.dist-info")).unwrap();
        std::fs::write(sp.join("pip-9.0.3.dist-info/METADATA"), "Metadata-Version: 2.0\nName: pip\nVersion: 9.0.3\n\nlong description Name: nope\n").unwrap();
        std::fs::write(sp.join("setuptools-39.2.0-py3.6.egg-info"), "Metadata-Version: 1.1\nName: setuptools\nVersion: 39.2.0\n").unwrap();
        std::fs::create_dir_all(root.path().join("usr/share/python3-wheels")).unwrap();
        std::fs::write(root.path().join("usr/share/python3-wheels/pip-21.2.3-py3-none-any.whl"), b"PK").unwrap();
        let nm = root.path().join("usr/lib/node_modules");
        std::fs::create_dir_all(nm.join("npm/node_modules/@babel/core/test")).unwrap();
        std::fs::write(nm.join("npm/package.json"), r#"{"name":"npm","version":"6.14.4"}"#).unwrap();
        std::fs::write(nm.join("npm/node_modules/@babel/core/package.json"), r#"{"name":"@babel/core","version":"7.8.0"}"#).unwrap();
        std::fs::write(nm.join("npm/node_modules/@babel/core/test/package.json"), r#"{"name":"fixture","version":"0.0.0"}"#).unwrap();

        // A Spring Boot fat jar with one nested library jar.
        let lib = {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            w.start_file("META-INF/maven/org.yaml/snakeyaml/pom.properties", zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(b"#Generated\nversion=1.26\ngroupId=org.yaml\nartifactId=snakeyaml\n").unwrap();
            w.finish().unwrap().into_inner()
        };
        let mut w = zip::ZipWriter::new(std::fs::File::create(root.path().join("app.jar")).unwrap());
        w.start_file("META-INF/maven/com.acme/app/pom.properties", zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(b"groupId=com.acme\nartifactId=app\nversion=1.0.0\n").unwrap();
        w.start_file("BOOT-INF/lib/snakeyaml-1.26.jar", zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(&lib).unwrap();
        w.finish().unwrap();

        let (deps, warnings) = inventory(root.path());
        assert!(warnings.is_empty(), "{warnings:?}");
        let mut got: Vec<(String, String, String)> = deps.iter().map(|d| (d.ecosystem.clone(), d.name.clone(), d.version.clone())).collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("maven".into(), "com.acme:app".into(), "1.0.0".into()),
                ("maven".into(), "org.yaml:snakeyaml".into(), "1.26".into()),
                ("npm".into(), "@babel/core".into(), "7.8.0".into()),
                ("npm".into(), "npm".into(), "6.14.4".into()),
                ("pypi".into(), "pip".into(), "21.2.3".into()),
                ("pypi".into(), "pip".into(), "9.0.3".into()),
                ("pypi".into(), "setuptools".into(), "39.2.0".into()),
            ]
        );
    }
}
