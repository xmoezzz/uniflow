//! Inventories the OS packages installed in a root filesystem — a squashed
//! container image, or `/` on a live host — together with *which*
//! distribution release it is (see [`distro`]), since OS advisories only
//! mean anything per release.
//!
//! Covers every package manager mainstream server distros use: apk
//! (Alpine, Wolfi), dpkg (Debian, Ubuntu, Kylin/UOS desktop — including
//! distroless images' `status.d/`), and rpm in all three database formats
//! (see [`rpm`]).
//!
//! Deliberately NOT a `ManifestParser` plugged into `sca_orchestrator`'s
//! generic by-basename walk: `var/lib/dpkg/status`'s basename ("status")
//! is generic enough that matching it during an ordinary source-tree scan
//! would risk false positives, so this is invoked directly, only against
//! known-absolute paths, by whatever is scanning a real OS filesystem root.
pub mod distro;
pub mod rpm;

pub use distro::Distro;
use serde::Serialize;
use std::path::Path;
use uniflow_sca_core::OsPackage;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Apk,
    Dpkg,
    Rpm,
}

#[derive(Clone, Debug, Serialize)]
pub struct OsInventory {
    pub distro: Option<Distro>,
    pub package_manager: Option<PackageManager>,
    /// The database file(s) read, for evidence/debugging.
    pub db_path: Option<String>,
    /// `sqlite` / `bdb` / `ndb` for rpm; `None` otherwise.
    pub db_format: Option<&'static str>,
    pub packages: Vec<OsPackage>,
    /// Things the user should know — a database that exists but couldn't
    /// be read (permissions, corruption) must not look like "no packages".
    pub warnings: Vec<String>,
}

/// Detects the distro and reads whichever package database is present.
pub fn inventory(root: &Path) -> OsInventory {
    let mut warnings = Vec::new();
    let mut packages = Vec::new();
    let mut manager = None;
    let mut db_path = None;
    let mut db_format = None;

    let apk_path = root.join("lib/apk/db/installed");
    let dpkg_status = root.join("var/lib/dpkg/status");
    let dpkg_status_d = root.join("var/lib/dpkg/status.d");

    if apk_path.is_file() {
        manager = Some(PackageManager::Apk);
        db_path = Some(apk_path.display().to_string());
        match std::fs::read_to_string(&apk_path) {
            Ok(text) => packages = parse_apk_installed(&text),
            Err(e) => warnings.push(format!("cannot read {}: {e}", apk_path.display())),
        }
    } else if dpkg_status.is_file() || dpkg_status_d.is_dir() {
        manager = Some(PackageManager::Dpkg);
        if dpkg_status.is_file() {
            db_path = Some(dpkg_status.display().to_string());
            match std::fs::read_to_string(&dpkg_status) {
                Ok(text) => packages.extend(parse_dpkg_status(&text)),
                Err(e) => warnings.push(format!("cannot read {}: {e}", dpkg_status.display())),
            }
        }
        // Distroless images have no `status`; each package gets its own
        // single-stanza file under `status.d/` instead.
        if let Ok(entries) = std::fs::read_dir(&dpkg_status_d) {
            db_path.get_or_insert_with(|| dpkg_status_d.display().to_string());
            let mut files: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
            files.sort();
            for file in files {
                if file.extension().is_some_and(|ext| ext == "md5sums") {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&file) {
                    packages.extend(parse_dpkg_status(&text));
                }
            }
        }
    } else if let Some(result) = rpm::find_and_read(root) {
        manager = Some(PackageManager::Rpm);
        match result {
            Ok(db) => {
                if db.unparseable > 0 {
                    warnings.push(format!("{} rpm headers in {} could not be parsed", db.unparseable, db.path));
                }
                db_path = Some(db.path);
                db_format = Some(db.format);
                packages = db
                    .packages
                    .into_iter()
                    .map(|h| OsPackage {
                        version: h.evr(),
                        source_name: h.source_name(),
                        source_version: None,
                        arch: (!h.arch.is_empty()).then_some(h.arch.clone()),
                        module: (!h.modularity_label.is_empty()).then_some(h.modularity_label.clone()),
                        name: h.name,
                    })
                    .collect();
            }
            Err(e) => warnings.push(format!("cannot read the rpm database: {e:#}")),
        }
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.arch.cmp(&b.arch)));
    packages.dedup();

    let distro = distro::detect(root, manager == Some(PackageManager::Dpkg), manager == Some(PackageManager::Rpm));
    if manager.is_some() && distro.is_none() {
        warnings.push("no /etc/os-release — installed packages were found but the distribution release is unknown, so they cannot be matched against distro advisories".to_string());
    }
    OsInventory { distro, package_manager: manager, db_path, db_format, packages, warnings }
}

/// Alpine's `apk` installed-db: blank-line-separated stanzas of
/// `<letter>:<value>` lines — `P` name, `V` version, `A` arch, `o` origin
/// (the source package Alpine's secdb keys advisories by).
fn parse_apk_installed(text: &str) -> Vec<OsPackage> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n") {
        let (mut name, mut version, mut arch, mut origin) = (None, None, None, None);
        for line in stanza.lines() {
            match line.split_once(':') {
                Some(("P", v)) => name = Some(v.trim()),
                Some(("V", v)) => version = Some(v.trim()),
                Some(("A", v)) => arch = Some(v.trim()),
                Some(("o", v)) => origin = Some(v.trim()),
                _ => {}
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            out.push(OsPackage {
                name: name.to_string(),
                version: version.to_string(),
                source_name: origin.map(str::to_string),
                source_version: None,
                arch: arch.map(str::to_string),
                module: None,
            });
        }
    }
    out
}

/// Debian/Ubuntu's dpkg status file: blank-line-separated RFC822-style
/// stanzas. Only packages whose `Status` ends in `installed` are on disk
/// (dpkg keeps `deinstall`/`config-files` records too). `Source:` is
/// `name` or `name (version)` when the source version differs from the
/// binary one; absent means source name = binary name.
fn parse_dpkg_status(text: &str) -> Vec<OsPackage> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n") {
        let (mut name, mut version, mut status, mut arch, mut source) = (None, None, None, None, None);
        for line in stanza.lines() {
            if line.starts_with([' ', '\t']) {
                continue; // continuation of a multi-line field (Description, Conffiles)
            }
            match line.split_once(':') {
                Some(("Package", v)) => name = Some(v.trim()),
                Some(("Version", v)) => version = Some(v.trim()),
                Some(("Status", v)) => status = Some(v.trim()),
                Some(("Architecture", v)) => arch = Some(v.trim()),
                Some(("Source", v)) => source = Some(v.trim()),
                _ => {}
            }
        }
        // Distroless `status.d` stanzas have no Status field: presence is
        // installation.
        let installed = status.is_none_or(|s| s.ends_with(" installed"));
        let (Some(name), Some(version)) = (name, version) else { continue };
        if !installed {
            continue;
        }
        let (source_name, source_version) = match source {
            Some(src) => match src.split_once(' ') {
                Some((n, v)) => (n.to_string(), Some(v.trim().trim_start_matches('(').trim_end_matches(')').to_string())),
                None => (src.to_string(), None),
            },
            None => (name.to_string(), None),
        };
        out.push(OsPackage {
            name: name.to_string(),
            version: version.to_string(),
            source_name: Some(source_name),
            source_version,
            arch: arch.map(str::to_string),
            module: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, path: &str, body: &str) {
        let full = dir.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, body).unwrap();
    }

    #[test]
    fn parses_apk_installed_db_stanzas_with_origin() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "etc/os-release", "ID=alpine\nVERSION_ID=3.19.1\n");
        write(
            dir.path(),
            "lib/apk/db/installed",
            "C:Q1abc=\nP:libcrypto3\nV:3.1.4-r5\nA:x86_64\no:openssl\n\nP:musl\nV:1.2.4_git20230717-r4\nA:x86_64\no:musl\n",
        );
        let inv = inventory(dir.path());
        assert_eq!(inv.package_manager, Some(PackageManager::Apk));
        assert_eq!(inv.distro.unwrap().key(), "alpine:3.19");
        assert_eq!(inv.packages.len(), 2);
        let crypto = inv.packages.iter().find(|p| p.name == "libcrypto3").unwrap();
        assert_eq!(crypto.source_name.as_deref(), Some("openssl"));
    }

    #[test]
    fn parses_dpkg_status_with_source_and_skips_removed_packages() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
        write(
            dir.path(),
            "var/lib/dpkg/status",
            "Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl\nVersion: 3.0.11-1~deb12u2\nDescription: x\n more\n\n\
             Package: libc6\nStatus: install ok installed\nSource: glibc (2.36-9+deb12u4)\nVersion: 2.36-9+deb12u4+b1\n\n\
             Package: old\nStatus: deinstall ok config-files\nVersion: 1.0\n\n\
             Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2+b2\n",
        );
        let inv = inventory(dir.path());
        assert_eq!(inv.packages.len(), 3);
        let libc = inv.packages.iter().find(|p| p.name == "libc6").unwrap();
        assert_eq!(libc.source_name.as_deref(), Some("glibc"));
        assert_eq!(libc.source_version.as_deref(), Some("2.36-9+deb12u4"));
        let bash = inv.packages.iter().find(|p| p.name == "bash").unwrap();
        assert_eq!(bash.source_name.as_deref(), Some("bash"));
    }

    #[test]
    fn reads_distroless_status_d() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
        write(dir.path(), "var/lib/dpkg/status.d/libssl3", "Package: libssl3\nVersion: 3.0.11-1~deb12u2\nSource: openssl\nArchitecture: amd64\n");
        write(dir.path(), "var/lib/dpkg/status.d/libssl3.md5sums", "abc  usr/lib/x\n");
        let inv = inventory(dir.path());
        assert_eq!(inv.package_manager, Some(PackageManager::Dpkg));
        assert_eq!(inv.packages.len(), 1);
    }

    #[test]
    fn packages_without_os_release_are_inventoried_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "lib/apk/db/installed", "P:musl\nV:1.2.3-r0\n\n");
        let inv = inventory(dir.path());
        assert!(inv.distro.is_none());
        assert_eq!(inv.packages.len(), 1);
        assert!(!inv.warnings.is_empty());
    }
}
