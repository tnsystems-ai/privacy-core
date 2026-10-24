use std::borrow::Cow;

use crate::error::EngineError;
use crate::types::PiiType;

pub const DEFAULT_MAX_INPUT_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    enabled: [bool; PiiType::COUNT],
    replacements: [Cow<'static, str>; PiiType::COUNT],
    max_input_bytes: usize,
}

impl Default for Ruleset {
    fn default() -> Self {
        Self {
            enabled: [true; PiiType::COUNT],
            replacements: PiiType::ALL.map(|t| Cow::Borrowed(t.default_replacement())),
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
        }
    }
}

impl Ruleset {
    pub const PRESETS: &'static [&'static str] = &["default", "eu_fintech"];

    pub fn preset(name: &str) -> Result<Self, EngineError> {
        match name {
            "default" | "eu_fintech" => Ok(Self::default()),
            _ => Err(EngineError::UnknownPreset(name.to_owned())),
        }
    }

    pub fn none() -> Self {
        Self {
            enabled: [false; PiiType::COUNT],
            ..Self::default()
        }
    }

    #[must_use]
    pub fn enable(mut self, pii_type: PiiType) -> Self {
        self.enabled[pii_type.index()] = true;
        self
    }

    #[must_use]
    pub fn disable(mut self, pii_type: PiiType) -> Self {
        self.enabled[pii_type.index()] = false;
        self
    }

    #[must_use]
    pub fn with_replacement(
        mut self,
        pii_type: PiiType,
        tag: impl Into<Cow<'static, str>>,
    ) -> Self {
        self.replacements[pii_type.index()] = tag.into();
        self
    }

    #[must_use]
    pub fn with_max_input_bytes(mut self, max: usize) -> Self {
        self.max_input_bytes = max;
        self
    }

    #[inline]
    pub fn is_enabled(&self, pii_type: PiiType) -> bool {
        self.enabled[pii_type.index()]
    }

    #[inline]
    pub fn replacement(&self, pii_type: PiiType) -> &str {
        &self.replacements[pii_type.index()]
    }

    #[inline]
    pub fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    #[inline]
    pub(crate) fn enabled_mask(&self) -> &[bool; PiiType::COUNT] {
        &self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_resolve() {
        for name in Ruleset::PRESETS {
            assert!(Ruleset::preset(name).is_ok());
        }
        assert_eq!(
            Ruleset::preset("nope"),
            Err(EngineError::UnknownPreset("nope".into()))
        );
    }

    #[test]
    fn builder() {
        let r = Ruleset::none()
            .enable(PiiType::Iban)
            .with_replacement(PiiType::Iban, "<IBAN>")
            .with_max_input_bytes(10);
        assert!(r.is_enabled(PiiType::Iban));
        assert!(!r.is_enabled(PiiType::CreditCard));
        assert_eq!(r.replacement(PiiType::Iban), "<IBAN>");
        assert_eq!(r.replacement(PiiType::CreditCard), "[CREDIT_CARD_REDACTED]");
        assert_eq!(r.max_input_bytes(), 10);
    }
}
