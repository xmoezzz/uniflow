use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    Little,
    Big,
}

/// A source-analysis target profile.
///
/// This is deliberately not a compiler target specification. It only records
/// facts that frontends and semantic models may use to simulate platform-
/// dependent source behavior without compiling the program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformProfile {
    pub name: String,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub vendor: Option<String>,
    pub environment: Option<String>,
    pub pointer_width: Option<u8>,
    pub endianness: Option<Endianness>,
    pub defines: BTreeMap<String, Option<String>>,
    pub features: BTreeSet<String>,
    /// When true, an absent define or feature is treated as false. For an
    /// open-world profile, absence remains unknown and both paths may be kept.
    pub closed_world: bool,
}

impl Default for PlatformProfile {
    fn default() -> Self {
        Self::generic()
    }
}

impl PlatformProfile {
    pub fn generic() -> Self {
        Self {
            name: "generic".to_string(),
            os: None,
            arch: None,
            vendor: None,
            environment: None,
            pointer_width: None,
            endianness: None,
            defines: BTreeMap::new(),
            features: BTreeSet::new(),
            closed_world: false,
        }
    }

    pub fn linux_x86_64_gnu() -> Self {
        Self::preset(
            "linux-x86_64-gnu",
            "linux",
            "x86_64",
            "unknown",
            "gnu",
            64,
            Endianness::Little,
            [
                "__linux__",
                "linux",
                "__unix__",
                "unix",
                "__x86_64__",
                "__amd64__",
            ],
        )
    }

    pub fn windows_x86_64_msvc() -> Self {
        Self::preset(
            "windows-x86_64-msvc",
            "windows",
            "x86_64",
            "pc",
            "msvc",
            64,
            Endianness::Little,
            ["_WIN32", "_WIN64", "_M_X64", "_M_AMD64"],
        )
    }

    pub fn macos_aarch64() -> Self {
        Self::preset(
            "macos-aarch64",
            "macos",
            "aarch64",
            "apple",
            "darwin",
            64,
            Endianness::Little,
            [
                "__APPLE__",
                "__MACH__",
                "__aarch64__",
                "__arm64__",
                "__unix__",
                "unix",
            ],
        )
    }

    pub fn from_preset_name(name: &str) -> Option<Self> {
        match name {
            "generic" => Some(Self::generic()),
            "linux-x86_64-gnu" | "linux" => Some(Self::linux_x86_64_gnu()),
            "windows-x86_64-msvc" | "windows" => Some(Self::windows_x86_64_msvc()),
            "macos-aarch64" | "macos" => Some(Self::macos_aarch64()),
            _ => None,
        }
    }

    pub fn with_define(mut self, name: impl Into<String>, value: Option<String>) -> Self {
        self.defines.insert(name.into(), value);
        self
    }

    pub fn with_feature(mut self, feature: impl Into<String>) -> Self {
        self.features.insert(feature.into());
        self
    }

    pub fn define_truth(&self, name: &str) -> crate::condition::TruthValue {
        if self.defines.contains_key(name) {
            crate::condition::TruthValue::True
        } else if self.closed_world {
            crate::condition::TruthValue::False
        } else {
            crate::condition::TruthValue::Unknown
        }
    }

    pub fn feature_truth(&self, name: &str) -> crate::condition::TruthValue {
        if self.features.contains(name) {
            crate::condition::TruthValue::True
        } else if self.closed_world {
            crate::condition::TruthValue::False
        } else {
            crate::condition::TruthValue::Unknown
        }
    }

    fn preset<const N: usize>(
        name: &str,
        os: &str,
        arch: &str,
        vendor: &str,
        environment: &str,
        pointer_width: u8,
        endianness: Endianness,
        defines: [&str; N],
    ) -> Self {
        Self {
            name: name.to_string(),
            os: Some(os.to_string()),
            arch: Some(arch.to_string()),
            vendor: Some(vendor.to_string()),
            environment: Some(environment.to_string()),
            pointer_width: Some(pointer_width),
            endianness: Some(endianness),
            defines: defines
                .into_iter()
                .map(|name| (name.to_string(), None))
                .collect(),
            features: BTreeSet::new(),
            closed_world: true,
        }
    }
}
