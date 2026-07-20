use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use uniflow_platform::PlatformProfile;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontendOptions {
    pub platform: PlatformProfile,
    #[serde(default)]
    pub defines: BTreeMap<String, Option<String>>,
    #[serde(default)]
    pub undefines: BTreeSet<String>,
    #[serde(default)]
    pub include_paths: Vec<PathBuf>,
    #[serde(default)]
    pub language_standard: Option<String>,
    #[serde(default)]
    pub target_triple: Option<String>,
    #[serde(default)]
    pub compile_commands: Option<PathBuf>,
}
