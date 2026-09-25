//! The RPM installed-package database, in all three on-disk formats rpm
//! has used — each one still common on real servers:
//! - **BerkeleyDB Hash** `Packages`: RHEL/CentOS ≤ 8, Kylin/UOS server,
//!   Amazon Linux 2, older openEuler — the bulk of Chinese production
//!   servers.
//! - **SQLite** `rpmdb.sqlite`: RHEL 9+, Fedora 33+, Rocky/Alma 9,
//!   openEuler 22.03+, OpenCloudOS 9.
//! - **NDB** `Packages.db`: SUSE/openSUSE.
//!
//! All three store the same thing per package: rpm's *header blob*
//! (`headerExport` format). The BDB and NDB readers are pure-Rust ports of
//! the page/slot walking in knqyf263/go-rpmdb (which Trivy and Grype use),
//! read-only and without the BerkeleyDB library; SQLite goes through
//! rusqlite's bundled SQLite.
use anyhow::{bail, ensure, Context, Result};
use std::path::Path;

/// One installed binary package, straight from its header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpmHeader {
    pub name: String,
    pub epoch: Option<u32>,
    pub version: String,
    pub release: String,
    pub arch: String,
    /// `openssl-3.0.7-27.el9.src.rpm` — the source package this binary was
    /// built from. Several distros (openEuler, Anolis) key advisories by
    /// source package name.
    pub source_rpm: String,
    pub vendor: String,
    pub modularity_label: String,
}

impl RpmHeader {
    /// `[epoch:]version-release` — the form rpm-based advisories compare.
    pub fn evr(&self) -> String {
        match self.epoch {
            Some(e) if e > 0 => format!("{e}:{}-{}", self.version, self.release),
            _ => format!("{}-{}", self.version, self.release),
        }
    }

    /// `openssl` out of `openssl-3.0.7-27.el9.src.rpm`: strip `.src.rpm`
    /// (or `.nosrc.rpm`), then the last two `-` fields (version, release).
    pub fn source_name(&self) -> Option<String> {
        let base = self.source_rpm.strip_suffix(".src.rpm").or_else(|| self.source_rpm.strip_suffix(".nosrc.rpm"))?;
        let (rest, _release) = base.rsplit_once('-')?;
        let (name, _version) = rest.rsplit_once('-')?;
        (!name.is_empty()).then(|| name.to_string())
    }
}

const TAG_NAME: i32 = 1000;
const TAG_VERSION: i32 = 1001;
const TAG_RELEASE: i32 = 1002;
const TAG_EPOCH: i32 = 1003;
const TAG_VENDOR: i32 = 1011;
const TAG_ARCH: i32 = 1022;
const TAG_SOURCERPM: i32 = 1044;
const TAG_MODULARITYLABEL: i32 = 5096;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_I18NSTRING: u32 = 9;

fn be_u32(b: &[u8], at: usize) -> Result<u32> {
    let s = b.get(at..at + 4).context("header blob truncated")?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parses one exported header blob: `il` index entries of 16 bytes
/// (tag, type, offset, count — big-endian) followed by `dl` bytes of data.
pub fn parse_header_blob(blob: &[u8]) -> Result<RpmHeader> {
    let il = be_u32(blob, 0)? as usize;
    let dl = be_u32(blob, 4)? as usize;
    // rpm's own sanity limits (hdrchkTags / hdrchkData).
    ensure!(il > 0 && il < 0x0000_ffff, "implausible header index count {il}");
    ensure!(dl < 0x0fff_ffff, "implausible header data length {dl}");
    let data_start = 8 + il * 16;
    let data = blob.get(data_start..data_start + dl).context("header data region truncated")?;

    let string_at = |offset: usize| -> String {
        data.get(offset..).map(|d| {
            let end = d.iter().position(|&c| c == 0).unwrap_or(d.len());
            String::from_utf8_lossy(&d[..end]).into_owned()
        }).unwrap_or_default()
    };

    let mut header = RpmHeader {
        name: String::new(),
        epoch: None,
        version: String::new(),
        release: String::new(),
        arch: String::new(),
        source_rpm: String::new(),
        vendor: String::new(),
        modularity_label: String::new(),
    };
    for i in 0..il {
        let entry = 8 + i * 16;
        let tag = be_u32(blob, entry)? as i32;
        let kind = be_u32(blob, entry + 4)?;
        let offset = be_u32(blob, entry + 8)? as usize;
        let is_string = kind == TYPE_STRING || kind == TYPE_I18NSTRING;
        match tag {
            TAG_NAME if is_string => header.name = string_at(offset),
            TAG_VERSION if is_string => header.version = string_at(offset),
            TAG_RELEASE if is_string => header.release = string_at(offset),
            TAG_ARCH if is_string => header.arch = string_at(offset),
            TAG_SOURCERPM if is_string => header.source_rpm = string_at(offset),
            TAG_VENDOR if is_string => header.vendor = string_at(offset),
            TAG_MODULARITYLABEL if is_string => header.modularity_label = string_at(offset),
            TAG_EPOCH if kind == TYPE_INT32 => header.epoch = be_u32(data, offset).ok(),
            _ => {}
        }
    }
    ensure!(!header.name.is_empty() && !header.version.is_empty(), "header has no name/version");
    Ok(header)
}

/// Blobs whose header didn't parse are skipped, not fatal: rpm itself
/// tolerates a damaged entry, and one bad package must not hide the rest.
fn parse_all(blobs: Vec<Vec<u8>>) -> (Vec<RpmHeader>, usize) {
    let mut out = Vec::with_capacity(blobs.len());
    let mut bad = 0;
    for blob in blobs {
        match parse_header_blob(&blob) {
            // `gpg-pubkey` entries are imported signing keys, not software.
            Ok(h) if h.name == "gpg-pubkey" => {}
            Ok(h) => out.push(h),
            Err(_) => bad += 1,
        }
    }
    (out, bad)
}

// ------------------------------------------------------- BerkeleyDB ----

const BDB_HASH_MAGIC: u32 = 0x0006_1561;
const BDB_PAGE_HASH_UNSORTED: u8 = 2;
const BDB_PAGE_HASH: u8 = 13;
const BDB_H_OFFPAGE: u8 = 3;
const BDB_PAGE_HEADER: usize = 26;

/// Reads every value of a BerkeleyDB Hash database: walks hash pages,
/// takes each key/value pair's value item (rpm stores headers as
/// off-page items), and concatenates the overflow-page chain.
pub fn read_bdb(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    ensure!(bytes.len() >= 72, "file too small for a BerkeleyDB metadata page");
    // The metadata page is stored in the writer's native byte order; the
    // magic tells us which one.
    let magic_le = u32::from_le_bytes(bytes[12..16].try_into()?);
    let magic_be = u32::from_be_bytes(bytes[12..16].try_into()?);
    let le = if magic_le == BDB_HASH_MAGIC {
        true
    } else if magic_be == BDB_HASH_MAGIC {
        false
    } else {
        bail!("not a BerkeleyDB Hash database (magic {magic_le:#x})");
    };
    let u32_at = |b: &[u8], at: usize| -> u32 {
        let a: [u8; 4] = b[at..at + 4].try_into().unwrap_or([0; 4]);
        if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
    };
    let u16_at = |b: &[u8], at: usize| -> u16 {
        let a: [u8; 2] = b[at..at + 2].try_into().unwrap_or([0; 2]);
        if le { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) }
    };
    ensure!(bytes[24] == 0, "encrypted BerkeleyDB databases are not supported");
    let page_size = u32_at(bytes, 20) as usize;
    ensure!((512..=65536).contains(&page_size) && page_size.is_power_of_two(), "bad page size {page_size}");
    let last_page = u32_at(bytes, 32) as usize;
    let page_count = (last_page + 1).min(bytes.len() / page_size);

    let page = |n: usize| -> Option<&[u8]> { bytes.get(n * page_size..(n + 1) * page_size) };
    let mut values = Vec::new();
    for page_no in 1..page_count {
        let Some(p) = page(page_no) else { break };
        let page_type = p[25];
        if page_type != BDB_PAGE_HASH && page_type != BDB_PAGE_HASH_UNSORTED {
            continue;
        }
        let entries = u16_at(p, 20) as usize;
        // Index slots alternate key, value.
        for pair in (0..entries).step_by(2) {
            let slot = BDB_PAGE_HEADER + (pair + 1) * 2;
            if slot + 2 > p.len() {
                break;
            }
            let item = u16_at(p, slot) as usize;
            if item + 12 > p.len() || p[item] != BDB_H_OFFPAGE {
                continue;
            }
            let mut next = u32_at(p, item + 4) as usize;
            let total = u32_at(p, item + 8) as usize;
            let mut value = Vec::with_capacity(total);
            let mut hops = 0;
            while next != 0 && hops <= page_count {
                let Some(o) = page(next) else { break };
                let following = u32_at(o, 16) as usize;
                let used = if following == 0 { (u16_at(o, 22) as usize).min(page_size - BDB_PAGE_HEADER) } else { page_size - BDB_PAGE_HEADER };
                value.extend_from_slice(&o[BDB_PAGE_HEADER..BDB_PAGE_HEADER + used]);
                next = following;
                hops += 1;
            }
            value.truncate(total);
            if !value.is_empty() {
                values.push(value);
            }
        }
    }
    Ok(values)
}

// -------------------------------------------------------------- NDB ----

const NDB_HEADER_MAGIC: u32 = u32::from_le_bytes(*b"RpmP");
const NDB_SLOT_MAGIC: u32 = u32::from_le_bytes(*b"Slot");
const NDB_BLOB_MAGIC: u32 = u32::from_le_bytes(*b"BlbS");
const NDB_BLOCK: usize = 16;
const NDB_SLOTS_PER_PAGE: usize = 4096 / 16;

/// rpm's own "ndb" format: a slot table mapping package index → block
/// offset, each block a `BlbS` header followed by the header blob.
pub fn read_ndb(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let le = |at: usize| -> Option<u32> { bytes.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])) };
    ensure!(le(0) == Some(NDB_HEADER_MAGIC), "not an rpm NDB database");
    ensure!(le(4) == Some(0), "unsupported NDB version");
    let slot_pages = le(12).context("truncated NDB header")? as usize;
    // The 32-byte file header occupies the first two slot positions.
    let slots = (slot_pages * NDB_SLOTS_PER_PAGE).saturating_sub(2);
    let mut values = Vec::new();
    for i in 0..slots {
        let at = 32 + i * 16;
        let (Some(magic), Some(pkg), Some(block)) = (le(at), le(at + 4), le(at + 8)) else { break };
        if magic != NDB_SLOT_MAGIC || pkg == 0 {
            continue;
        }
        let start = block as usize * NDB_BLOCK;
        let (Some(blob_magic), Some(blob_pkg), Some(len)) = (le(start), le(start + 4), le(start + 12)) else { continue };
        if blob_magic != NDB_BLOB_MAGIC || blob_pkg != pkg {
            continue;
        }
        if let Some(blob) = bytes.get(start + 16..start + 16 + len as usize) {
            values.push(blob.to_vec());
        }
    }
    Ok(values)
}

// ----------------------------------------------------------- SQLite ----

pub fn read_sqlite(path: &Path) -> Result<Vec<Vec<u8>>> {
    use rusqlite::{Connection, OpenFlags};
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI;
    // A normal read-only open sees committed-but-uncheckpointed WAL data,
    // but needs to create the `-shm` file; when the directory isn't
    // writable (a non-root scan of `/`, a read-only image mount) fall back
    // to `immutable=1`, which reads the main file alone.
    let conn = match Connection::open_with_flags(path, flags) {
        Ok(conn) if conn.query_row("select count(*) from Packages", [], |_| Ok(())).is_ok() => conn,
        _ => Connection::open_with_flags(format!("file:{}?immutable=1", path.display()), flags)
            .with_context(|| format!("opening {}", path.display()))?,
    };
    let mut stmt = conn.prepare("select blob from Packages")?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// Which rpmdb file was found, and its packages.
pub struct RpmDb {
    pub path: String,
    pub format: &'static str,
    pub packages: Vec<RpmHeader>,
    pub unparseable: usize,
}

/// Locations in the order rpm itself prefers them: the SQLite backend
/// (current), then NDB, then legacy BDB — both under the classic
/// `/var/lib/rpm` and the newer `/usr/lib/sysimage/rpm` (Fedora, SUSE).
pub fn find_and_read(root: &Path) -> Option<Result<RpmDb>> {
    for dir in ["var/lib/rpm", "usr/lib/sysimage/rpm"] {
        let base = root.join(dir);
        let sqlite = base.join("rpmdb.sqlite");
        if sqlite.is_file() {
            return Some(read_sqlite(&sqlite).map(|blobs| finish(sqlite.display().to_string(), "sqlite", blobs)));
        }
        for (file, format) in [("Packages.db", "ndb"), ("Packages", "bdb")] {
            let path = base.join(file);
            if path.is_file() {
                let read = std::fs::read(&path).with_context(|| format!("reading {}", path.display())).and_then(|bytes| match format {
                    "ndb" => read_ndb(&bytes),
                    _ => read_bdb(&bytes),
                });
                return Some(read.map(|blobs| finish(path.display().to_string(), format, blobs)));
            }
        }
    }
    None
}

fn finish(path: String, format: &'static str, blobs: Vec<Vec<u8>>) -> RpmDb {
    let (packages, unparseable) = parse_all(blobs);
    RpmDb { path, format, packages, unparseable }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an exported header blob the way `headerExport` lays it out.
    pub(crate) fn blob(name: &str, epoch: Option<u32>, version: &str, release: &str, arch: &str, srpm: &str) -> Vec<u8> {
        let mut entries: Vec<(i32, u32, Vec<u8>)> = vec![
            (TAG_NAME, TYPE_STRING, format!("{name}\0").into_bytes()),
            (TAG_VERSION, TYPE_STRING, format!("{version}\0").into_bytes()),
            (TAG_RELEASE, TYPE_STRING, format!("{release}\0").into_bytes()),
            (TAG_ARCH, TYPE_STRING, format!("{arch}\0").into_bytes()),
            (TAG_SOURCERPM, TYPE_STRING, format!("{srpm}\0").into_bytes()),
        ];
        if let Some(e) = epoch {
            entries.push((TAG_EPOCH, TYPE_INT32, e.to_be_bytes().to_vec()));
        }
        let mut index = Vec::new();
        let mut data = Vec::new();
        for (tag, kind, bytes) in &entries {
            while kind == &TYPE_INT32 && data.len() % 4 != 0 {
                data.push(0);
            }
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&kind.to_be_bytes());
            index.extend_from_slice(&(data.len() as u32).to_be_bytes());
            index.extend_from_slice(&1u32.to_be_bytes());
            data.extend_from_slice(bytes);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend(index);
        out.extend(data);
        out
    }

    #[test]
    fn parses_a_header_blob() {
        let h = parse_header_blob(&blob("openssl-libs", Some(1), "3.0.7", "27.el9", "x86_64", "openssl-3.0.7-27.el9.src.rpm")).unwrap();
        assert_eq!(h.name, "openssl-libs");
        assert_eq!(h.evr(), "1:3.0.7-27.el9");
        assert_eq!(h.source_name().as_deref(), Some("openssl"));
    }

    #[test]
    fn source_names_with_dashes_survive() {
        let h = parse_header_blob(&blob("python3-dnf", None, "4.14.0", "9.el9", "noarch", "dnf-plugins-core-4.3.0-13.el9.src.rpm")).unwrap();
        assert_eq!(h.source_name().as_deref(), Some("dnf-plugins-core"));
        assert_eq!(h.evr(), "4.14.0-9.el9");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_header_blob(&[0, 0, 0, 0]).is_err());
        assert!(read_bdb(&[0; 4096]).is_err());
        assert!(read_ndb(&[0; 64]).is_err());
    }

    #[test]
    fn reads_a_synthetic_ndb_file() {
        let header_blob = blob("bash", None, "4.4", "150400.25.22", "x86_64", "bash-4.4-150400.25.22.src.rpm");
        let mut file = vec![0u8; 4096 + 16 + header_blob.len() + 16];
        file[0..4].copy_from_slice(b"RpmP");
        file[12..16].copy_from_slice(&1u32.to_le_bytes());
        // slot 0 (after the 32-byte header): package 1 at block 256 (= byte 4096)
        file[32..36].copy_from_slice(b"Slot");
        file[36..40].copy_from_slice(&1u32.to_le_bytes());
        file[40..44].copy_from_slice(&256u32.to_le_bytes());
        file[4096..4100].copy_from_slice(b"BlbS");
        file[4100..4104].copy_from_slice(&1u32.to_le_bytes());
        file[4108..4112].copy_from_slice(&(header_blob.len() as u32).to_le_bytes());
        file[4112..4112 + header_blob.len()].copy_from_slice(&header_blob);
        let blobs = read_ndb(&file).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(parse_header_blob(&blobs[0]).unwrap().name, "bash");
    }
}
