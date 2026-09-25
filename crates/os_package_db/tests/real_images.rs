//! Against package databases extracted from real distribution images
//! (`docker cp` of the rpmdb/dpkg/apk files + os-release). The files are
//! tens of MB and belong to their distributions, so they are not vendored;
//! point `UNIFLOW_OS_FIXTURE_ROOTS` at a directory of extracted roots (one
//! subdirectory per image, laid out as the image's own paths) to run.
//! Expected counts are what the image's own `rpm -qa` (minus gpg-pubkey),
//! `dpkg-query -W` and `apk info` print.
use std::path::PathBuf;
use uniflow_os_package_db::{inventory, PackageManager};

fn roots() -> Option<PathBuf> {
    std::env::var_os("UNIFLOW_OS_FIXTURE_ROOTS").map(PathBuf::from)
}

#[test]
fn inventories_match_the_package_managers_own_listing() {
    let Some(base) = roots() else {
        eprintln!("UNIFLOW_OS_FIXTURE_ROOTS not set; skipping");
        return;
    };
    // (root dir, distro key, package manager, db format, package count, a known package evr)
    let cases: &[(&str, &str, PackageManager, Option<&str>, usize, (&str, &str))] = &[
        ("centos_7", "centos:7", PackageManager::Rpm, Some("bdb"), 148, ("openssl-libs", "1:1.0.2k-19.el7")),
        ("almalinux_8", "almalinux:8", PackageManager::Rpm, Some("bdb"), 154, ("openssl-libs", "1:1.1.1k-17.el8_6")),
        ("oraclelinux_8", "ol:8", PackageManager::Rpm, Some("bdb"), 195, ("bash", "4.4.20-6.el8_10")),
        ("openanolis_anolisos_8", "anolis:8", PackageManager::Rpm, Some("bdb"), 181, ("openssl-libs", "1:1.1.1k-7.0.2.an8")),
        ("rockylinux_9", "rocky:9", PackageManager::Rpm, Some("sqlite"), 141, ("openssl-libs", "1:3.0.7-24.el9")),
        ("redhat_ubi9", "rhel:9", PackageManager::Rpm, Some("sqlite"), 186, ("openssl-libs", "1:3.5.8-1.el9_8")),
        ("fedora_40", "fedora:40", PackageManager::Rpm, Some("sqlite"), 144, ("bash", "5.2.26-3.fc40")),
        ("opencloudos_opencloudos_9.0", "opencloudos:9", PackageManager::Rpm, Some("sqlite"), 131, ("openssl-libs", "3.0.12-3.oc9")),
        ("openeuler_openeuler_22.03-lts-sp4", "openeuler:22.03-lts-sp4", PackageManager::Rpm, Some("ndb"), 136, ("openssl-libs", "1:1.1.1wa-16.oe2203sp4")),
        ("opensuse_leap_15.5", "opensuse-leap:15.5", PackageManager::Rpm, Some("ndb"), 130, ("bash", "4.4-150400.25.22")),
        ("debian_12", "debian:12", PackageManager::Dpkg, None, 88, ("bash", "5.2.15-2+b13")),
        ("ubuntu_22.04", "ubuntu:22.04", PackageManager::Dpkg, None, 101, ("bash", "")),
        ("alpine_3.19", "alpine:3.19", PackageManager::Apk, None, 15, ("musl", "")),
        ("distroless", "debian:12", PackageManager::Dpkg, None, 7, ("libc6", "")),
    ];
    let mut failures = Vec::new();
    for (dir, key, manager, format, count, (pkg, evr)) in cases {
        let root = base.join(dir);
        if !root.exists() {
            eprintln!("{dir}: fixture missing, skipped");
            continue;
        }
        let inv = inventory(&root);
        let got_key = inv.distro.as_ref().map(|d| d.key()).unwrap_or_default();
        let found = inv.packages.iter().find(|p| p.name == *pkg).map(|p| p.version.clone()).unwrap_or_default();
        let line = format!(
            "{dir}: key={got_key} manager={:?} format={:?} packages={} {pkg}={found} warnings={:?}",
            inv.package_manager, inv.db_format, inv.packages.len(), inv.warnings
        );
        eprintln!("{line}");
        let ok = got_key == *key
            && inv.package_manager == Some(*manager)
            && inv.db_format == *format
            && inv.packages.len() == *count
            && (evr.is_empty() && !found.is_empty() || found == *evr);
        if !ok {
            failures.push(line);
        }
    }
    assert!(failures.is_empty(), "mismatches:\n{}", failures.join("\n"));
}
