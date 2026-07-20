//! Stable external-checker SDK for UniFlow.
//!
//! The dynamic-library boundary uses versioned C ABI tables and UTF-8 JSON
//! payloads. No Rust trait object or Rust-owned allocation crosses the ABI.
//! ABI v2 adds a table size, capability flags, and nullable callbacks while the
//! host continues to accept ABI v1 plugins.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::{c_char, c_void, CStr, CString};

pub const CHECKER_ABI_VERSION_V1: u32 = 1;
pub const CHECKER_ABI_VERSION_V2: u32 = 2;
pub const CHECKER_ABI_VERSION_CURRENT: u32 = CHECKER_ABI_VERSION_V2;
pub const CHECKER_ENTRY_SYMBOL_V1: &[u8] = b"uniflow_checker_entry_v1\0";
pub const CHECKER_ENTRY_SYMBOL_V2: &[u8] = b"uniflow_checker_entry_v2\0";

pub mod capability {
    /// The checker accepts the event/response JSON protocol defined by this SDK.
    pub const JSON_EVENTS: u64 = 1 << 0;
}

pub mod event_kind {
    pub const ANALYSIS_START: &str = "analysis_start";
    pub const HIR_PROGRAM: &str = "hir_program";
    pub const IR_PROGRAM: &str = "ir_program";
    pub const FLOW_SUMMARY: &str = "flow_summary";
    pub const CALL: &str = "call";
    pub const TAINT_FINDING: &str = "taint_finding";
    pub const ANALYSIS_END: &str = "analysis_end";
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckerManifest {
    pub abi_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub event_kinds: Vec<String>,
}

impl CheckerManifest {
    pub fn new(id: impl Into<String>, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            abi_version: CHECKER_ABI_VERSION_CURRENT,
            id: id.into(),
            name: name.into(),
            version: version.into(),
            description: String::new(),
            event_kinds: Vec::new(),
        }
    }

    pub fn subscribes_to(&self, kind: &str) -> bool {
        self.event_kinds.is_empty() || self.event_kinds.iter().any(|item| item == kind)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckerEvent {
    pub kind: String,
    pub sequence: u64,
    pub payload: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CheckerLocation {
    pub uri: String,
    #[serde(default = "default_line")]
    pub line: u32,
    #[serde(default = "default_column")]
    pub column: u32,
    #[serde(default)]
    pub label: String,
}

const fn default_line() -> u32 {
    1
}

const fn default_column() -> u32 {
    1
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CheckerPathStep {
    pub location: CheckerLocation,
    #[serde(default)]
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckerFinding {
    pub rule_id: String,
    pub message: String,
    #[serde(default = "default_level")]
    pub level: String,
    pub location: CheckerLocation,
    #[serde(default)]
    pub related_locations: Vec<CheckerLocation>,
    #[serde(default)]
    pub code_flow: Vec<CheckerPathStep>,
    #[serde(default)]
    pub properties: BTreeMap<String, Value>,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

fn default_level() -> String {
    "warning".to_string()
}

impl CheckerFinding {
    pub fn new(
        rule_id: impl Into<String>,
        message: impl Into<String>,
        location: CheckerLocation,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            message: message.into(),
            level: default_level(),
            location,
            related_locations: Vec::new(),
            code_flow: Vec::new(),
            properties: BTreeMap::new(),
            fingerprint: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CheckerResponse {
    #[serde(default)]
    pub findings: Vec<CheckerFinding>,
    #[serde(default)]
    pub error: Option<String>,
}

pub trait Checker: Default + 'static {
    fn manifest(&self) -> CheckerManifest;
    fn on_event(&mut self, event: &CheckerEvent) -> Vec<CheckerFinding>;
}

pub type CheckerManifestJsonFn = unsafe extern "C" fn() -> *mut c_char;
pub type CheckerCreateFn = unsafe extern "C" fn() -> *mut c_void;
pub type CheckerOnEventJsonFn =
    unsafe extern "C" fn(instance: *mut c_void, event_json: *const c_char) -> *mut c_char;
pub type CheckerDestroyFn = unsafe extern "C" fn(instance: *mut c_void);
pub type CheckerFreeStringFn = unsafe extern "C" fn(value: *mut c_char);

/// Legacy ABI table. Callback fields are nullable so a malformed foreign table
/// can be rejected before invocation instead of creating an invalid Rust
/// function pointer.
#[repr(C)]
pub struct UniflowCheckerV1 {
    pub abi_version: u32,
    pub manifest_json: Option<CheckerManifestJsonFn>,
    pub create: Option<CheckerCreateFn>,
    pub on_event_json: Option<CheckerOnEventJsonFn>,
    pub destroy: Option<CheckerDestroyFn>,
    pub free_string: Option<CheckerFreeStringFn>,
}

/// Current ABI table. `struct_size` allows future hosts to read only fields
/// present in an older table and reject truncated tables safely.
#[repr(C)]
pub struct UniflowCheckerV2 {
    pub abi_version: u32,
    pub struct_size: u64,
    pub capabilities: u64,
    pub manifest_json: Option<CheckerManifestJsonFn>,
    pub create: Option<CheckerCreateFn>,
    pub on_event_json: Option<CheckerOnEventJsonFn>,
    pub destroy: Option<CheckerDestroyFn>,
    pub free_string: Option<CheckerFreeStringFn>,
}

pub type CheckerEntryV1 = unsafe extern "C" fn() -> *const UniflowCheckerV1;
pub type CheckerEntryV2 = unsafe extern "C" fn() -> *const UniflowCheckerV2;

#[doc(hidden)]
pub fn encode_owned_json<T: Serialize>(value: &T) -> *mut c_char {
    let text = serde_json::to_string(value).unwrap_or_else(|error| {
        format!(
            "{{\"findings\":[],\"error\":\"serialization failed: {}\"}}",
            error.to_string().replace('"', "'")
        )
    });
    CString::new(text.replace('\0', "\\u0000"))
        .expect("JSON string must not contain interior NUL bytes")
        .into_raw()
}

#[doc(hidden)]
pub unsafe fn decode_event(value: *const c_char) -> Result<CheckerEvent, String> {
    if value.is_null() {
        return Err("event pointer is null".to_string());
    }
    let text = unsafe { CStr::from_ptr(value) }
        .to_str()
        .map_err(|error| format!("event is not valid UTF-8: {error}"))?;
    serde_json::from_str(text).map_err(|error| format!("invalid checker event JSON: {error}"))
}

#[doc(hidden)]
pub unsafe fn free_owned_string(value: *mut c_char) {
    if !value.is_null() {
        unsafe { drop(CString::from_raw(value)) };
    }
}

/// Export a Rust checker through both supported UniFlow checker ABIs.
///
/// New hosts prefer ABI v2. The v1 entry remains available so an independently
/// built checker can be used with older UniFlow 0.x hosts.
#[macro_export]
macro_rules! export_checker {
    ($checker_ty:ty) => {
        fn __uniflow_manifest(abi_version: u32) -> *mut ::std::ffi::c_char {
            let response = ::std::panic::catch_unwind(|| {
                let checker = <$checker_ty as ::std::default::Default>::default();
                let mut manifest = <$checker_ty as $crate::Checker>::manifest(&checker);
                manifest.abi_version = abi_version;
                manifest
            });
            match response {
                Ok(manifest) => $crate::encode_owned_json(&manifest),
                Err(_) => $crate::encode_owned_json(&$crate::CheckerResponse {
                    findings: Vec::new(),
                    error: Some("checker panicked while producing its manifest".to_string()),
                }),
            }
        }

        unsafe extern "C" fn __uniflow_manifest_json_v1() -> *mut ::std::ffi::c_char {
            __uniflow_manifest($crate::CHECKER_ABI_VERSION_V1)
        }

        unsafe extern "C" fn __uniflow_manifest_json_v2() -> *mut ::std::ffi::c_char {
            __uniflow_manifest($crate::CHECKER_ABI_VERSION_V2)
        }

        unsafe extern "C" fn __uniflow_create() -> *mut ::std::ffi::c_void {
            match ::std::panic::catch_unwind(|| <$checker_ty as ::std::default::Default>::default())
            {
                Ok(checker) => Box::into_raw(Box::new(checker)).cast::<::std::ffi::c_void>(),
                Err(_) => ::std::ptr::null_mut(),
            }
        }

        unsafe extern "C" fn __uniflow_on_event_json(
            instance: *mut ::std::ffi::c_void,
            event_json: *const ::std::ffi::c_char,
        ) -> *mut ::std::ffi::c_char {
            if instance.is_null() {
                return $crate::encode_owned_json(&$crate::CheckerResponse {
                    findings: Vec::new(),
                    error: Some("checker instance is null".to_string()),
                });
            }
            let response = ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                let event = unsafe { $crate::decode_event(event_json) }?;
                let checker = unsafe { &mut *instance.cast::<$checker_ty>() };
                Ok::<_, String>($crate::CheckerResponse {
                    findings: <$checker_ty as $crate::Checker>::on_event(checker, &event),
                    error: None,
                })
            }));
            match response {
                Ok(Ok(value)) => $crate::encode_owned_json(&value),
                Ok(Err(error)) => $crate::encode_owned_json(&$crate::CheckerResponse {
                    findings: Vec::new(),
                    error: Some(error),
                }),
                Err(_) => $crate::encode_owned_json(&$crate::CheckerResponse {
                    findings: Vec::new(),
                    error: Some("checker panicked while handling an event".to_string()),
                }),
            }
        }

        unsafe extern "C" fn __uniflow_destroy(instance: *mut ::std::ffi::c_void) {
            if !instance.is_null() {
                unsafe { drop(Box::from_raw(instance.cast::<$checker_ty>())) };
            }
        }

        unsafe extern "C" fn __uniflow_free_string(value: *mut ::std::ffi::c_char) {
            unsafe { $crate::free_owned_string(value) };
        }

        static __UNIFLOW_CHECKER_V1: $crate::UniflowCheckerV1 = $crate::UniflowCheckerV1 {
            abi_version: $crate::CHECKER_ABI_VERSION_V1,
            manifest_json: Some(__uniflow_manifest_json_v1),
            create: Some(__uniflow_create),
            on_event_json: Some(__uniflow_on_event_json),
            destroy: Some(__uniflow_destroy),
            free_string: Some(__uniflow_free_string),
        };

        static __UNIFLOW_CHECKER_V2: $crate::UniflowCheckerV2 = $crate::UniflowCheckerV2 {
            abi_version: $crate::CHECKER_ABI_VERSION_V2,
            struct_size: ::std::mem::size_of::<$crate::UniflowCheckerV2>() as u64,
            capabilities: $crate::capability::JSON_EVENTS,
            manifest_json: Some(__uniflow_manifest_json_v2),
            create: Some(__uniflow_create),
            on_event_json: Some(__uniflow_on_event_json),
            destroy: Some(__uniflow_destroy),
            free_string: Some(__uniflow_free_string),
        };

        #[no_mangle]
        pub unsafe extern "C" fn uniflow_checker_entry_v1() -> *const $crate::UniflowCheckerV1 {
            &__UNIFLOW_CHECKER_V1
        }

        #[no_mangle]
        pub unsafe extern "C" fn uniflow_checker_entry_v2() -> *const $crate::UniflowCheckerV2 {
            &__UNIFLOW_CHECKER_V2
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_defaults_to_current_abi() {
        let manifest = CheckerManifest::new("example.checker", "Example", "1.0.0");
        assert_eq!(manifest.abi_version, CHECKER_ABI_VERSION_CURRENT);
        assert!(manifest.subscribes_to(event_kind::CALL));
    }

    #[test]
    fn event_subscription_is_explicit_when_present() {
        let mut manifest = CheckerManifest::new("example.checker", "Example", "1.0.0");
        manifest.event_kinds = vec![event_kind::CALL.to_string()];
        assert!(manifest.subscribes_to(event_kind::CALL));
        assert!(!manifest.subscribes_to(event_kind::HIR_PROGRAM));
    }

    #[test]
    fn finding_json_defaults_are_stable() {
        let finding: CheckerFinding = serde_json::from_value(serde_json::json!({
            "rule_id": "rule",
            "message": "message",
            "location": { "uri": "demo.c" }
        }))
        .expect("finding");
        assert_eq!(finding.level, "warning");
        assert_eq!(finding.location.line, 1);
        assert_eq!(finding.location.column, 1);
    }

    #[test]
    fn v2_table_is_large_enough_for_callbacks() {
        assert!(std::mem::size_of::<UniflowCheckerV2>() > std::mem::size_of::<UniflowCheckerV1>());
    }
}
