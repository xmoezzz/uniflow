use crate::profile::{Endianness, PlatformProfile};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TruthValue {
    True,
    False,
    Unknown,
}

impl TruthValue {
    pub fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }

    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }

    pub fn may_be_true(self) -> bool {
        !matches!(self, Self::False)
    }

    pub fn is_definitely_true(self) -> bool {
        matches!(self, Self::True)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Condition {
    Always,
    Never,
    Define(String),
    Feature(String),
    Os(String),
    Arch(String),
    Vendor(String),
    Environment(String),
    PointerWidth(u8),
    Endianness(Endianness),
    Not(Box<Condition>),
    All(Vec<Condition>),
    Any(Vec<Condition>),
}

impl Condition {
    pub fn evaluate(&self, profile: &PlatformProfile) -> TruthValue {
        match self {
            Self::Always => TruthValue::True,
            Self::Never => TruthValue::False,
            Self::Define(name) => profile.define_truth(name),
            Self::Feature(name) => profile.feature_truth(name),
            Self::Os(expected) => match_text(profile.os.as_deref(), expected),
            Self::Arch(expected) => match_text(profile.arch.as_deref(), expected),
            Self::Vendor(expected) => match_text(profile.vendor.as_deref(), expected),
            Self::Environment(expected) => match_text(profile.environment.as_deref(), expected),
            Self::PointerWidth(expected) => match profile.pointer_width {
                Some(actual) if actual == *expected => TruthValue::True,
                Some(_) => TruthValue::False,
                None => TruthValue::Unknown,
            },
            Self::Endianness(expected) => match profile.endianness {
                Some(actual) if actual == *expected => TruthValue::True,
                Some(_) => TruthValue::False,
                None => TruthValue::Unknown,
            },
            Self::Not(inner) => inner.evaluate(profile).not(),
            Self::All(conditions) => conditions
                .iter()
                .fold(TruthValue::True, |state, condition| {
                    state.and(condition.evaluate(profile))
                }),
            Self::Any(conditions) => conditions
                .iter()
                .fold(TruthValue::False, |state, condition| {
                    state.or(condition.evaluate(profile))
                }),
        }
    }
}

fn match_text(actual: Option<&str>, expected: &str) -> TruthValue {
    match actual {
        Some(actual) if actual.eq_ignore_ascii_case(expected) => TruthValue::True,
        Some(_) => TruthValue::False,
        None => TruthValue::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_closed_world_platform_facts() {
        let profile = PlatformProfile::windows_x86_64_msvc();
        assert_eq!(
            Condition::Define("_WIN32".into()).evaluate(&profile),
            TruthValue::True
        );
        assert_eq!(
            Condition::Define("__linux__".into()).evaluate(&profile),
            TruthValue::False
        );
        assert_eq!(
            Condition::Os("windows".into()).evaluate(&profile),
            TruthValue::True
        );
    }

    #[test]
    fn generic_profile_keeps_unknown_conditions() {
        let profile = PlatformProfile::generic();
        assert_eq!(
            Condition::Define("PROJECT_PLATFORM".into()).evaluate(&profile),
            TruthValue::Unknown
        );
        assert!(Condition::Define("PROJECT_PLATFORM".into())
            .evaluate(&profile)
            .may_be_true());
    }
}
