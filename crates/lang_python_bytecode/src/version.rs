//! `.pyc` magic-number recognition and version gating.
//!
//! Only CPython 3.6–3.10's "wordcode" bytecode format is supported: every
//! instruction is exactly 2 bytes (1 opcode + 1 oparg byte, `EXTENDED_ARG`-
//! prefixed for a larger oparg), the same instruction-encoding shape since
//! 3.6. 3.11 introduced per-instruction inline caches and adaptive
//! specialization that make the raw bytecode stream not directly meaningful
//! without additional despecialization — deliberately out of scope; such a
//! file is rejected with a clear error rather than silently misdecoded.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PyVersion {
    pub major: u8,
    pub minor: u8,
}

impl PyVersion {
    /// 3.10 changed `hasjrel`/`hasjabs` opargs from raw byte offsets to
    /// "code unit" (2-byte instruction) counts.
    pub fn jump_oparg_is_in_code_units(&self) -> bool {
        self.minor >= 10
    }
}

/// Magic-number -> version. The 3.9 entry is verified against a real
/// `python3.9` interpreter in this environment (`importlib.util.MAGIC_NUMBER`
/// on CPython 3.9 is `3425`, i.e. bytes `61 0d 0d 0a`); the others are the
/// well-documented, stable values CPython has used for each release's
/// initial magic number (a version may bump its magic a few times during
/// alpha/beta churn, but final releases are stable for the run of this
/// table).
const MAGIC_TABLE: &[(u16, PyVersion)] = &[
    (3379, PyVersion { major: 3, minor: 6 }),
    (3394, PyVersion { major: 3, minor: 7 }),
    (3413, PyVersion { major: 3, minor: 8 }),
    (3425, PyVersion { major: 3, minor: 9 }),
    (3439, PyVersion { major: 3, minor: 10 }),
];

pub fn version_for_magic(magic: u16) -> Option<PyVersion> {
    MAGIC_TABLE.iter().find(|(m, _)| *m == magic).map(|(_, v)| *v)
}
