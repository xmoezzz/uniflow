//! `.pyc` file header (CPython 3.7+ layout: 16 bytes — 4-byte magic, 4-byte
//! bit field, then either an 8-byte `(mtime, source_size)` pair or an
//! 8-byte source hash, depending on bit 0 of the bit field).

use anyhow::{bail, Result};

use crate::version::{version_for_magic, PyVersion};

pub struct PycHeader {
    pub version: PyVersion,
    pub body_offset: usize,
}

pub fn parse_header(bytes: &[u8]) -> Result<PycHeader> {
    if bytes.len() < 16 {
        bail!("file is only {} bytes, too short for a .pyc header", bytes.len());
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    // bytes[2..4] are the traditional carriage-return/newline sentinel
    // (`\r\n`), present in every version's magic number; not itself
    // version-discriminating.
    let Some(version) = version_for_magic(magic) else {
        bail!(
            "unrecognized .pyc magic number {magic} (raw bytes {:?}) — only CPython 3.6-3.10 wordcode bytecode is supported (3.11+ uses adaptive/specialized instructions this frontend does not decode)",
            &bytes[0..4]
        );
    };
    if version.minor < 6 {
        bail!("CPython {}.{} predates the wordcode bytecode format and is not supported", version.major, version.minor);
    }
    Ok(PycHeader { version, body_offset: 16 })
}
