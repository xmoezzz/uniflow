use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    Elf,
    PeExecutable,
    MachO,
    Zip,
    Gzip,
    Xz,
    Bzip2,
    Tar,
    SevenZip,
    Rar,
    Text,
    Unsupported(&'static str),
}

const SIGNATURES: &[(&[u8], FileKind)] = &[
    (b"\x7fELF", FileKind::Elf),
    (b"MZ", FileKind::PeExecutable),
    (b"\xfe\xed\xfa\xce", FileKind::MachO),
    (b"\xfe\xed\xfa\xcf", FileKind::MachO),
    (b"\xce\xfa\xed\xfe", FileKind::MachO),
    (b"\xcf\xfa\xed\xfe", FileKind::MachO),
    (b"PK\x03\x04", FileKind::Zip),
    (b"PK\x05\x06", FileKind::Zip),
    (b"\x1f\x8b", FileKind::Gzip),
    (b"\xfd7zXZ\x00", FileKind::Xz),
    (b"BZh", FileKind::Bzip2),
    (b"7z\xbc\xaf\x27\x1c", FileKind::SevenZip),
    (b"Rar!\x1a\x07", FileKind::Rar),
];

pub fn detect(path: &Path) -> anyhow::Result<FileKind> {
    let mut buf = [0u8; 264];
    let mut file = File::open(path)?;
    let n = file.read(&mut buf)?;
    let head = &buf[..n];

    for (signature, kind) in SIGNATURES {
        if head.starts_with(signature) {
            return Ok(*kind);
        }
    }
    if n >= 262 && &head[257..262] == b"ustar" {
        return Ok(FileKind::Tar);
    }
    if is_probably_text(head) {
        return Ok(FileKind::Text);
    }
    Ok(FileKind::Unsupported("unrecognized binary signature"))
}

fn is_probably_text(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| matches!(byte, 0x09 | 0x0a | 0x0d | 0x20..=0x7e | 0x80..=0xff))
}
