//! Which distribution (and which release of it) a root filesystem is.
//! Everything downstream keys on this: advisories are published per
//! release (`Debian:12`, `Ubuntu:22.04`, `Rocky Linux:9`), and a package
//! version that is patched on one release can be vulnerable on another, so
//! a scan that doesn't know the exact release can only guess.
//!
//! `ID_LIKE` is deliberately *not* used to pick advisory data. Ubuntu is
//! `ID_LIKE=debian`, but an Ubuntu package matched against Debian's
//! tracker is simply wrong (different versions, different backports). The
//! only cross-distro mappings are the binary-compatible rebuilds listed in
//! [`Distro::data_keys`], and each is surfaced to the user as such.
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Distro {
    /// Normalized distribution id: `debian`, `ubuntu`, `alpine`, `rhel`,
    /// `centos`, `rocky`, `almalinux`, `ol`, `amzn`, `fedora`, `sles`,
    /// `opensuse-leap`, `opensuse-tumbleweed`, `openeuler`, `anolis`,
    /// `opencloudos`, `kylin`/`kylin-desktop`, `uos`/`uos-server`,
    /// `azurelinux`, `wolfi`, `chainguard`, or the raw os-release `ID`.
    pub id: String,
    /// Release as advisories name it: `12`, `22.04`, `3.19`, `9`,
    /// `22.03-lts-sp4`, `15.5`, `v10`. Empty for rolling distros.
    pub release: String,
    /// os-release `PRETTY_NAME` (or a synthesized one), for display.
    pub pretty_name: String,
    /// Raw `VERSION_ID`, kept for display/audit.
    pub version_id: String,
    pub codename: Option<String>,
    /// Raw `ID_LIKE` entries — informational only (see module docs).
    pub id_like: Vec<String>,
}

impl Distro {
    /// `<id>:<release>` — the ecosystem tag OS advisories are stored under.
    pub fn key(&self) -> String {
        if self.release.is_empty() {
            self.id.clone()
        } else {
            format!("{}:{}", self.id, self.release)
        }
    }

    /// Advisory datasets to match this system against, most specific
    /// first. A rebuild whose packages are the upstream's own binaries (or
    /// byte-identical rebuilds with the same NEVRA) is matched against the
    /// upstream's data when it publishes none of its own: CentOS Linux
    /// 7/8 against RHEL (what Red Hat's own tooling and Trivy do). Nothing
    /// else crosses distro boundaries.
    pub fn data_keys(&self) -> Vec<String> {
        let mut keys = vec![self.key()];
        if self.id == "centos" && !self.release.is_empty() {
            keys.push(format!("rhel:{}", self.release));
        }
        keys
    }

    /// "Ubuntu 22.04", "Rocky Linux 9" — short label for badges.
    pub fn label(&self) -> String {
        let name = match self.id.as_str() {
            "debian" => "Debian",
            "ubuntu" => "Ubuntu",
            "alpine" => "Alpine",
            "rhel" => "RHEL",
            "centos" => "CentOS",
            "rocky" => "Rocky Linux",
            "almalinux" => "AlmaLinux",
            "ol" => "Oracle Linux",
            "amzn" => "Amazon Linux",
            "fedora" => "Fedora",
            "sles" => "SLES",
            "opensuse-leap" => "openSUSE Leap",
            "opensuse-tumbleweed" => "openSUSE Tumbleweed",
            "openeuler" => "openEuler",
            "anolis" => "Anolis OS",
            "opencloudos" => "OpenCloudOS",
            "kylin" | "kylin-desktop" => "Kylin",
            "uos" | "uos-server" => "UOS",
            "azurelinux" => "Azure Linux",
            "wolfi" => "Wolfi",
            "chainguard" => "Chainguard",
            other => return format!("{other} {}", self.release).trim().to_string(),
        };
        if self.release.is_empty() {
            name.to_string()
        } else {
            format!("{name} {}", self.release.to_uppercase().replace('-', " "))
        }
    }
}

/// `KEY=value` / `KEY="value"` lines (os-release(5)).
fn parse_os_release(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let (k, v) = line.split_once('=')?;
            let v = v.trim().trim_matches('"').trim_matches('\'');
            Some((k.trim().to_string(), v.to_string()))
        })
        .collect()
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

fn major(version: &str) -> String {
    version.split(['.', '-', ' ']).next().unwrap_or(version).to_string()
}

fn major_minor(version: &str) -> String {
    let mut parts = version.split(['.', '_', '-']);
    match (parts.next(), parts.next()) {
        (Some(a), Some(b)) if b.chars().all(|c| c.is_ascii_digit()) && !b.is_empty() => format!("{a}.{b}"),
        (Some(a), _) => a.to_string(),
        _ => version.to_string(),
    }
}

/// Detects the distribution under `root`. `rpm_based` / `dpkg_based`
/// disambiguate vendors that ship both desktop (dpkg) and server (rpm)
/// lines under one os-release ID (Kylin, UOS).
pub fn detect(root: &Path, has_dpkg: bool, has_rpm: bool) -> Option<Distro> {
    let text = read(root, "etc/os-release").or_else(|| read(root, "usr/lib/os-release"));
    let fields = text.as_deref().map(parse_os_release).unwrap_or_default();
    let raw_id = fields.get("ID").map(|s| s.to_ascii_lowercase());
    let version_id = fields.get("VERSION_ID").cloned().unwrap_or_default();
    let version = fields.get("VERSION").cloned().unwrap_or_default();
    let id_like: Vec<String> = fields.get("ID_LIKE").map(|s| s.split_whitespace().map(str::to_ascii_lowercase).collect()).unwrap_or_default();
    let codename = fields.get("VERSION_CODENAME").filter(|c| !c.is_empty()).cloned();
    let mut pretty = fields.get("PRETTY_NAME").cloned().unwrap_or_default();

    let (id, release) = match raw_id.as_deref() {
        Some("debian") => {
            let v = if version_id.is_empty() { read(root, "etc/debian_version").unwrap_or_default().trim().to_string() } else { version_id.clone() };
            // testing/sid report `trixie/sid` — no stable release to match.
            let release = if v.chars().next().is_some_and(|c| c.is_ascii_digit()) { major(&v) } else { String::new() };
            ("debian".to_string(), release)
        }
        Some("ubuntu") => ("ubuntu".to_string(), version_id.clone()),
        Some("alpine") => {
            let v = if version_id.is_empty() { read(root, "etc/alpine-release").unwrap_or_default().trim().to_string() } else { version_id.clone() };
            let release = if v.contains("_alpha") || v.contains("edge") { "edge".to_string() } else { major_minor(&v) };
            ("alpine".to_string(), release)
        }
        Some("rhel") => ("rhel".to_string(), major(&version_id)),
        Some("centos") => ("centos".to_string(), major(&version_id)),
        Some("rocky") => ("rocky".to_string(), major(&version_id)),
        Some("almalinux") => ("almalinux".to_string(), major(&version_id)),
        Some("ol") => ("ol".to_string(), major(&version_id)),
        Some("amzn") => ("amzn".to_string(), major(&version_id)),
        Some("fedora") => ("fedora".to_string(), version_id.clone()),
        Some("sles") | Some("sled") => ("sles".to_string(), version_id.replace("-SP", ".").to_ascii_lowercase()),
        Some("opensuse-leap") => ("opensuse-leap".to_string(), version_id.clone()),
        Some("opensuse-tumbleweed") | Some("opensuse-slowroll") => ("opensuse-tumbleweed".to_string(), String::new()),
        Some("openeuler") => {
            // VERSION="22.03 (LTS-SP4)" → `22.03-lts-sp4`, the form openEuler's
            // own advisories (and OSV's `openEuler:22.03-LTS-SP4`) use.
            let qualifier = version.split_once('(').map(|(_, q)| q.trim_end_matches(')').trim().to_string()).unwrap_or_default();
            let release = if qualifier.is_empty() { version_id.clone() } else { format!("{version_id}-{qualifier}") };
            ("openeuler".to_string(), release.to_ascii_lowercase())
        }
        Some("anolis") => ("anolis".to_string(), major(&version_id)),
        Some("opencloudos") => ("opencloudos".to_string(), major(&version_id)),
        Some("kylin") => {
            let id = if has_rpm && !has_dpkg { "kylin" } else { "kylin-desktop" };
            (id.to_string(), version_id.to_ascii_lowercase())
        }
        Some("uos") | Some("uniontech") => {
            let id = if has_rpm && !has_dpkg { "uos-server" } else { "uos" };
            (id.to_string(), major(&version_id))
        }
        Some("azurelinux") | Some("mariner") => ("azurelinux".to_string(), major(&version_id)),
        Some("wolfi") => ("wolfi".to_string(), String::new()),
        Some("chainguard") => ("chainguard".to_string(), String::new()),
        Some(other) => (other.to_string(), version_id.clone()),
        None => {
            // Minimal images without os-release (old CentOS, scratch-ish
            // builds): the classic release files.
            if let Some(v) = read(root, "etc/alpine-release") {
                ("alpine".to_string(), major_minor(v.trim()))
            } else if let Some(v) = read(root, "etc/kylin-release") {
                let v = v.to_ascii_lowercase();
                let release = v.split_whitespace().find(|w| w.starts_with('v')).unwrap_or("").to_string();
                ("kylin".to_string(), release)
            } else if let Some(v) = read(root, "etc/redhat-release").or_else(|| read(root, "etc/centos-release")) {
                let lower = v.to_ascii_lowercase();
                let number = lower.split_whitespace().find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit())).map(major).unwrap_or_default();
                let id = if lower.contains("centos") {
                    "centos"
                } else if lower.contains("rocky") {
                    "rocky"
                } else if lower.contains("alma") {
                    "almalinux"
                } else {
                    "rhel"
                };
                pretty = v.trim().to_string();
                (id.to_string(), number)
            } else {
                let v = read(root, "etc/debian_version")?;
                let v = v.trim();
                let release = if v.chars().next().is_some_and(|c| c.is_ascii_digit()) { major(v) } else { String::new() };
                ("debian".to_string(), release)
            }
        }
    };
    let mut distro = Distro { id, release, pretty_name: pretty, version_id, codename, id_like };
    if distro.pretty_name.is_empty() {
        distro.pretty_name = distro.label();
    }
    Some(distro)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(files: &[(&str, &str)], dpkg: bool, rpm: bool) -> Distro {
        let dir = tempfile::tempdir().unwrap();
        for (path, body) in files {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, body).unwrap();
        }
        detect(dir.path(), dpkg, rpm).expect("detected")
    }

    #[test]
    fn normalizes_real_os_release_files() {
        // Verbatim from the respective images.
        let cases: &[(&str, &str, &str)] = &[
            ("ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"", "debian:12", "Debian 12"),
            ("NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\nID_LIKE=debian", "ubuntu:22.04", "Ubuntu 22.04"),
            ("NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.19.1", "alpine:3.19", "Alpine 3.19"),
            ("NAME=\"Rocky Linux\"\nVERSION=\"9.4 (Blue Onyx)\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"", "rocky:9", "Rocky Linux 9"),
            ("NAME=\"CentOS Linux\"\nVERSION=\"7 (Core)\"\nID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"", "centos:7", "CentOS 7"),
            ("NAME=\"openEuler\"\nVERSION=\"22.03 (LTS-SP4)\"\nID=\"openEuler\"\nVERSION_ID=\"22.03\"", "openeuler:22.03-lts-sp4", "openEuler 22.03 LTS SP4"),
            ("NAME=\"Anolis OS\"\nVERSION=\"8.8\"\nID=\"anolis\"\nID_LIKE=\"rhel fedora centos\"\nVERSION_ID=\"8.8\"", "anolis:8", "Anolis OS 8"),
            ("NAME=\"OpenCloudOS\"\nVERSION=\"9.0\"\nID=\"opencloudos\"\nVERSION_ID=\"9.0\"", "opencloudos:9", "OpenCloudOS 9"),
            ("NAME=\"SLES\"\nVERSION=\"15-SP5\"\nVERSION_ID=\"15.5\"\nID=\"sles\"", "sles:15.5", "SLES 15.5"),
            ("NAME=\"openSUSE Leap\"\nVERSION=\"15.5\"\nID=\"opensuse-leap\"\nVERSION_ID=\"15.5\"", "opensuse-leap:15.5", "openSUSE Leap 15.5"),
            ("NAME=\"Oracle Linux Server\"\nVERSION=\"8.9\"\nID=\"ol\"\nVERSION_ID=\"8.9\"", "ol:8", "Oracle Linux 8"),
            ("NAME=\"Kylin Linux Advanced Server\"\nVERSION=\"V10 (Lance)\"\nID=\"kylin\"\nVERSION_ID=\"V10\"", "kylin:v10", "Kylin V10"),
        ];
        for (os_release, key, label) in cases {
            let rpm = !key.starts_with("debian") && !key.starts_with("ubuntu") && !key.starts_with("alpine");
            let distro = with(&[("etc/os-release", os_release)], !rpm, rpm);
            assert_eq!(distro.key(), *key);
            assert_eq!(distro.label(), *label);
        }
    }

    #[test]
    fn ubuntu_never_falls_back_to_debian_data() {
        let d = with(&[("etc/os-release", "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"")], true, false);
        assert_eq!(d.data_keys(), vec!["ubuntu:24.04"]);
    }

    #[test]
    fn centos_falls_back_to_rhel_data_and_nothing_else_does() {
        let c = with(&[("etc/os-release", "ID=\"centos\"\nVERSION_ID=\"7\"")], false, true);
        assert_eq!(c.data_keys(), vec!["centos:7", "rhel:7"]);
        let a = with(&[("etc/os-release", "ID=\"anolis\"\nID_LIKE=\"rhel\"\nVERSION_ID=\"8.8\"")], false, true);
        assert_eq!(a.data_keys(), vec!["anolis:8"]);
    }

    #[test]
    fn falls_back_to_release_files_without_os_release() {
        assert_eq!(with(&[("etc/redhat-release", "CentOS release 6.10 (Final)\n")], false, true).key(), "centos:6");
        assert_eq!(with(&[("etc/alpine-release", "3.18.4\n")], false, false).key(), "alpine:3.18");
        assert_eq!(with(&[("etc/debian_version", "11.9\n")], true, false).key(), "debian:11");
    }

    #[test]
    fn kylin_desktop_and_server_are_told_apart_by_package_manager() {
        let os = "ID=kylin\nVERSION_ID=\"V10\"";
        assert_eq!(with(&[("etc/os-release", os)], true, false).key(), "kylin-desktop:v10");
        assert_eq!(with(&[("etc/os-release", os)], false, true).key(), "kylin:v10");
    }
}
