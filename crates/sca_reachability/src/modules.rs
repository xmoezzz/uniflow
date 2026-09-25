//! Package → importable-module mapping per ecosystem. This is the join
//! key between "a vulnerable *package* is in the lockfile" and "first-party
//! code imports a *module*", and the place most naive reachability tools
//! quietly get wrong: a PyPI distribution's import name routinely differs
//! from its registry name (`PyYAML` → `yaml`), and a Maven coordinate says
//! nothing reliable about the Java packages inside the jar.
//!
//! Resolution order, most to least authoritative:
//! 1. Installed metadata found under the scanned tree (a virtualenv's
//!    `*.dist-info/top_level.txt`/`RECORD`, a jar's own class entries).
//! 2. A curated table of well-known mismatches.
//! 3. The ecosystem's naming convention.
//!
//! [`ModuleMapping::authoritative`] records whether 1 or 2 applied, which
//! is what lets "not imported" be reported with high rather than medium
//! confidence.
use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct ModuleMapping {
    /// Canonical module prefixes, in the notation first-party imports use
    /// (`yaml`, `@babel/core`, `github.com/x/y`, `org.yaml.snakeyaml`,
    /// `tokio_util`).
    pub modules: Vec<String>,
    pub authoritative: bool,
}

/// PyPI distributions whose import name isn't the normalized dist name.
/// Only well-known, frequently-vulnerable ones — anything else falls back to
/// installed metadata or the naming convention.
const PYPI_KNOWN: &[(&str, &[&str])] = &[
    ("pyyaml", &["yaml"]),
    ("pillow", &["PIL"]),
    ("beautifulsoup4", &["bs4"]),
    ("scikit-learn", &["sklearn"]),
    ("scikit-image", &["skimage"]),
    ("python-dateutil", &["dateutil"]),
    ("opencv-python", &["cv2"]),
    ("opencv-python-headless", &["cv2"]),
    ("opencv-contrib-python", &["cv2"]),
    ("pycryptodome", &["Crypto"]),
    ("pycryptodomex", &["Cryptodome"]),
    ("pycrypto", &["Crypto"]),
    ("pyjwt", &["jwt"]),
    ("python-jose", &["jose"]),
    ("pyopenssl", &["OpenSSL"]),
    ("protobuf", &["google.protobuf"]),
    ("google-cloud-storage", &["google.cloud.storage"]),
    ("msgpack-python", &["msgpack"]),
    ("python-multipart", &["multipart"]),
    ("python-ldap", &["ldap"]),
    ("mysql-connector-python", &["mysql.connector"]),
    ("mysqlclient", &["MySQLdb"]),
    ("psycopg2-binary", &["psycopg2"]),
    ("pymupdf", &["fitz"]),
    ("attrs", &["attr", "attrs"]),
    ("setuptools", &["setuptools", "pkg_resources"]),
    ("pyzmq", &["zmq"]),
    ("pysaml2", &["saml2"]),
    ("python-magic", &["magic"]),
    ("typing-extensions", &["typing_extensions"]),
    ("django-rest-framework", &["rest_framework"]),
    ("djangorestframework", &["rest_framework"]),
    ("gitpython", &["git"]),
    ("paddlepaddle", &["paddle"]),
    ("tensorflow-cpu", &["tensorflow"]),
    ("tensorflow-gpu", &["tensorflow"]),
    ("websocket-client", &["websocket"]),
    ("pyasn1-modules", &["pyasn1_modules"]),
    ("ruamel.yaml", &["ruamel.yaml"]),
];

/// Maven artifacts whose Java packages aren't derivable from the groupId.
const MAVEN_KNOWN: &[(&str, &[&str])] = &[
    ("com.fasterxml.jackson.core:jackson-databind", &["com.fasterxml.jackson.databind"]),
    ("com.fasterxml.jackson.core:jackson-core", &["com.fasterxml.jackson.core"]),
    ("org.apache.logging.log4j:log4j-core", &["org.apache.logging.log4j"]),
    ("org.apache.logging.log4j:log4j-api", &["org.apache.logging.log4j"]),
    ("log4j:log4j", &["org.apache.log4j"]),
    ("org.apache.commons:commons-text", &["org.apache.commons.text"]),
    ("org.apache.commons:commons-lang3", &["org.apache.commons.lang3"]),
    ("org.apache.commons:commons-collections4", &["org.apache.commons.collections4"]),
    ("commons-collections:commons-collections", &["org.apache.commons.collections"]),
    ("commons-io:commons-io", &["org.apache.commons.io"]),
    ("commons-fileupload:commons-fileupload", &["org.apache.commons.fileupload"]),
    ("commons-beanutils:commons-beanutils", &["org.apache.commons.beanutils"]),
    ("org.yaml:snakeyaml", &["org.yaml.snakeyaml"]),
    ("com.google.guava:guava", &["com.google.common"]),
    ("com.google.code.gson:gson", &["com.google.gson"]),
    ("com.google.protobuf:protobuf-java", &["com.google.protobuf"]),
    ("com.alibaba:fastjson", &["com.alibaba.fastjson"]),
    ("com.alibaba.fastjson2:fastjson2", &["com.alibaba.fastjson2"]),
    ("com.thoughtworks.xstream:xstream", &["com.thoughtworks.xstream"]),
    ("org.apache.shiro:shiro-core", &["org.apache.shiro"]),
    ("org.apache.shiro:shiro-web", &["org.apache.shiro"]),
    ("org.apache.struts:struts2-core", &["org.apache.struts2", "com.opensymphony.xwork2"]),
    ("org.apache.tomcat.embed:tomcat-embed-core", &["org.apache.catalina", "org.apache.tomcat", "org.apache.coyote"]),
    ("org.springframework:spring-core", &["org.springframework.core", "org.springframework.util"]),
    ("org.springframework:spring-beans", &["org.springframework.beans"]),
    ("org.springframework:spring-web", &["org.springframework.web", "org.springframework.http"]),
    ("org.springframework:spring-webmvc", &["org.springframework.web.servlet"]),
    ("org.springframework:spring-context", &["org.springframework.context"]),
    ("org.springframework:spring-expression", &["org.springframework.expression"]),
    ("io.netty:netty-all", &["io.netty"]),
    ("io.netty:netty-codec-http", &["io.netty.handler.codec.http"]),
    ("com.h2database:h2", &["org.h2"]),
    ("mysql:mysql-connector-java", &["com.mysql"]),
    ("org.postgresql:postgresql", &["org.postgresql"]),
    ("org.bouncycastle:bcprov-jdk15on", &["org.bouncycastle"]),
    ("org.bouncycastle:bcprov-jdk18on", &["org.bouncycastle"]),
    ("dom4j:dom4j", &["org.dom4j"]),
    ("org.dom4j:dom4j", &["org.dom4j"]),
    ("xerces:xercesImpl", &["org.apache.xerces"]),
    ("org.jsoup:jsoup", &["org.jsoup"]),
    ("io.jsonwebtoken:jjwt", &["io.jsonwebtoken"]),
    ("org.apache.httpcomponents:httpclient", &["org.apache.http"]),
];

/// Installed-metadata lookups discovered once per scan.
#[derive(Debug, Default)]
pub struct InstalledMetadata {
    /// PEP 503-normalized dist name → top-level import names.
    pypi_top_level: HashMap<String, BTreeSet<String>>,
    /// Jar paths found in the tree, by file name (lowercased).
    jars: Vec<PathBuf>,
}

fn pep503(name: &str) -> String {
    let mut out = String::new();
    let mut last_sep = false;
    for c in name.trim().chars() {
        if matches!(c, '-' | '_' | '.') {
            if !last_sep {
                out.push('-');
            }
            last_sep = true;
        } else {
            out.extend(c.to_lowercase());
            last_sep = false;
        }
    }
    out
}

impl InstalledMetadata {
    /// Looks for virtualenv `site-packages` and bundled jars under `root`.
    /// Walks with a depth cap (virtualenvs sit near the project root) and
    /// never descends into `node_modules`/`.git`, which can be huge and hold
    /// neither.
    pub fn discover(root: &Path) -> Self {
        let mut meta = Self::default();
        let walker = walkdir::WalkDir::new(root).max_depth(8).into_iter().filter_entry(|entry| {
            let name = entry.file_name().to_str().unwrap_or_default();
            !(entry.file_type().is_dir() && matches!(name, "node_modules" | ".git" | "target" | "__pycache__"))
        });
        for entry in walker.filter_map(Result::ok) {
            let path = entry.path();
            let name = entry.file_name().to_str().unwrap_or_default();
            if entry.file_type().is_dir() && name.ends_with(".dist-info") {
                meta.read_dist_info(path);
            } else if entry.file_type().is_file() && name.ends_with(".jar") {
                meta.jars.push(path.to_path_buf());
            }
        }
        meta
    }

    fn read_dist_info(&mut self, dir: &Path) {
        let Some(stem) = dir.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".dist-info")) else { return };
        // `<name>-<version>.dist-info`; names can't contain '-' after
        // wheel normalization, so the first '-' splits name from version.
        let dist = pep503(stem.split('-').next().unwrap_or(stem));
        let mut modules = BTreeSet::new();
        if let Ok(text) = std::fs::read_to_string(dir.join("top_level.txt")) {
            modules.extend(text.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string));
        }
        if modules.is_empty() {
            // No top_level.txt (common for modern build backends): derive
            // from RECORD's first path segment of installed .py files.
            if let Ok(text) = std::fs::read_to_string(dir.join("RECORD")) {
                for line in text.lines() {
                    let file = line.split(',').next().unwrap_or_default();
                    let first = file.split('/').next().unwrap_or_default();
                    if first.ends_with(".dist-info") || first.ends_with(".data") || first == ".." || first.is_empty() {
                        continue;
                    }
                    let module = first.strip_suffix(".py").unwrap_or(first);
                    if file.ends_with(".py") && !module.starts_with('_') || file.ends_with("/__init__.py") {
                        modules.insert(module.to_string());
                    }
                }
            }
        }
        if !modules.is_empty() {
            self.pypi_top_level.entry(dist).or_default().extend(modules);
        }
    }

    /// Java package prefixes from a bundled jar's class entries —
    /// `artifactId-version.jar` (Maven's own naming) anywhere under the
    /// tree (`WEB-INF/lib`, `target/lib`, `libs/`, ...).
    fn jar_packages(&self, artifact: &str, version: &str) -> Option<Vec<String>> {
        let wanted = format!("{artifact}-{version}.jar").to_ascii_lowercase();
        let jar = self.jars.iter().find(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.to_ascii_lowercase() == wanted))?;
        let file = std::fs::File::open(jar).ok()?;
        let mut archive = zip::ZipArchive::new(file).ok()?;
        let mut packages: BTreeSet<String> = BTreeSet::new();
        for i in 0..archive.len() {
            let Ok(mut entry) = archive.by_index(i) else { continue };
            let name = entry.name().to_string();
            if name.starts_with("META-INF/") || !name.ends_with(".class") || name.contains('$') {
                continue;
            }
            if let Some((dir, _)) = name.rsplit_once('/') {
                packages.insert(dir.replace('/', "."));
            }
            // Drain nothing else — only names are needed.
            let _ = entry.read(&mut [0u8; 0]);
        }
        // Collapse to the shortest prefixes: `a.b` subsumes `a.b.c`.
        let mut minimal: Vec<String> = Vec::new();
        for package in packages {
            if !minimal.iter().any(|p| package == *p || package.starts_with(&format!("{p}."))) {
                minimal.push(package);
            }
        }
        (!minimal.is_empty()).then_some(minimal)
    }
}

pub fn module_mapping(ecosystem: &str, package: &str, version: &str, installed: &InstalledMetadata) -> ModuleMapping {
    match ecosystem {
        "pypi" => {
            let dist = pep503(package);
            if let Some(modules) = installed.pypi_top_level.get(&dist) {
                return ModuleMapping { modules: modules.iter().cloned().collect(), authoritative: true };
            }
            if let Some((_, modules)) = PYPI_KNOWN.iter().find(|(name, _)| *name == dist) {
                return ModuleMapping { modules: modules.iter().map(|m| m.to_string()).collect(), authoritative: true };
            }
            // Convention: import name = dist name with `-` → `_`. Namespace
            // dists (`zope.interface`) keep their dotted form as a prefix.
            let conventional = package.trim().replace('-', "_");
            let mut modules = vec![conventional.clone()];
            let lowered = conventional.to_lowercase();
            if lowered != conventional {
                modules.push(lowered);
            }
            ModuleMapping { modules, authoritative: false }
        }
        // npm specifiers *are* the package name (or `name/subpath`).
        "npm" => ModuleMapping { modules: vec![package.trim().to_string()], authoritative: true },
        // A Go module path is the import-path prefix of all its packages.
        "go" => ModuleMapping { modules: vec![package.trim().to_string()], authoritative: true },
        "cargo" => ModuleMapping { modules: vec![package.trim().replace('-', "_")], authoritative: true },
        "maven" => {
            let coordinate = package.trim();
            let (group, artifact) = coordinate.split_once(':').unwrap_or((coordinate, ""));
            if let Some(packages) = installed.jar_packages(artifact, version) {
                return ModuleMapping { modules: packages, authoritative: true };
            }
            if let Some((_, modules)) = MAVEN_KNOWN.iter().find(|(c, _)| c.eq_ignore_ascii_case(coordinate)) {
                return ModuleMapping { modules: modules.iter().map(|m| m.to_string()).collect(), authoritative: true };
            }
            // Heuristic: most artifacts put their classes under the groupId
            // (`org.jsoup`) or groupId + artifact (`io.netty` +
            // `netty-codec` → `io.netty.codec`). The groupId prefix alone
            // is the safer superset — it can only turn "not imported" into
            // "imported", never the reverse.
            ModuleMapping { modules: vec![group.to_string()], authoritative: false }
        }
        "rubygems" => {
            let name = package.trim();
            let mut modules = vec![name.to_string()];
            if name.contains('-') {
                modules.push(name.replace('-', "/"));
            }
            ModuleMapping { modules, authoritative: false }
        }
        _ => ModuleMapping::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pypi_known_mismatches_and_convention() {
        let none = InstalledMetadata::default();
        assert_eq!(module_mapping("pypi", "PyYAML", "5.3", &none).modules, vec!["yaml"]);
        assert_eq!(module_mapping("pypi", "Pillow", "8", &none).modules, vec!["PIL"]);
        assert_eq!(module_mapping("pypi", "beautifulsoup4", "4", &none).modules, vec!["bs4"]);
        assert_eq!(module_mapping("pypi", "scikit-learn", "1", &none).modules, vec!["sklearn"]);
        assert_eq!(module_mapping("pypi", "python_dateutil", "2", &none).modules, vec!["dateutil"]);
        let conventional = module_mapping("pypi", "requests-oauthlib", "1", &none);
        assert_eq!(conventional.modules, vec!["requests_oauthlib"]);
        assert!(!conventional.authoritative);
    }

    #[test]
    fn pypi_installed_top_level_wins() {
        let dir = tempfile::tempdir().unwrap();
        let info = dir.path().join(".venv/lib/python3.12/site-packages/weird_dist-1.0.dist-info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(info.join("top_level.txt"), "actual_module\n").unwrap();
        let rec = dir.path().join(".venv/lib/python3.12/site-packages/other-2.0.dist-info");
        std::fs::create_dir_all(&rec).unwrap();
        std::fs::write(rec.join("RECORD"), "othermod/__init__.py,sha256=x,1\nothermod/core.py,sha256=y,2\nother-2.0.dist-info/METADATA,,\n").unwrap();
        let meta = InstalledMetadata::discover(dir.path());
        let mapping = module_mapping("pypi", "Weird-Dist", "1.0", &meta);
        assert_eq!(mapping.modules, vec!["actual_module"]);
        assert!(mapping.authoritative);
        assert_eq!(module_mapping("pypi", "other", "2.0", &meta).modules, vec!["othermod"]);
    }

    #[test]
    fn maven_known_table_group_fallback_and_jar_listing() {
        let none = InstalledMetadata::default();
        assert_eq!(module_mapping("maven", "com.fasterxml.jackson.core:jackson-databind", "2.9", &none).modules, vec!["com.fasterxml.jackson.databind"]);
        assert_eq!(module_mapping("maven", "org.acme:thing", "1", &none).modules, vec!["org.acme"]);

        let dir = tempfile::tempdir().unwrap();
        let lib = dir.path().join("WEB-INF/lib");
        std::fs::create_dir_all(&lib).unwrap();
        let file = std::fs::File::create(lib.join("thing-1.0.jar")).unwrap();
        let mut jar = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        for entry in ["META-INF/MANIFEST.MF", "com/elsewhere/thing/A.class", "com/elsewhere/thing/sub/B.class", "com/elsewhere/thing/A$1.class"] {
            jar.start_file(entry, opts).unwrap();
        }
        jar.finish().unwrap();
        let meta = InstalledMetadata::discover(dir.path());
        let mapping = module_mapping("maven", "org.acme:thing", "1.0", &meta);
        assert_eq!(mapping.modules, vec!["com.elsewhere.thing"]);
        assert!(mapping.authoritative);
    }

    #[test]
    fn cargo_npm_go() {
        let none = InstalledMetadata::default();
        assert_eq!(module_mapping("cargo", "tokio-util", "0.7", &none).modules, vec!["tokio_util"]);
        assert_eq!(module_mapping("npm", "@babel/core", "7", &none).modules, vec!["@babel/core"]);
        assert_eq!(module_mapping("go", "golang.org/x/net", "v0.1.0", &none).modules, vec!["golang.org/x/net"]);
    }
}
