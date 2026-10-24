use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum PiiType {
    Iban = 0,
    CreditCard = 1,
}

impl PiiType {
    pub const COUNT: usize = 2;
    pub const ALL: [PiiType; Self::COUNT] = [PiiType::Iban, PiiType::CreditCard];

    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            PiiType::Iban => "IBAN",
            PiiType::CreditCard => "CREDIT_CARD",
        }
    }

    pub const fn default_replacement(self) -> &'static str {
        match self {
            PiiType::Iban => "[IBAN_REDACTED]",
            PiiType::CreditCard => "[CREDIT_CARD_REDACTED]",
        }
    }
}

impl fmt::Display for PiiType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A detected entity. `start..end` is a byte range into the original input
/// and always lies on UTF-8 char boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Detection {
    pub pii_type: PiiType,
    pub start: usize,
    pub end: usize,
}

impl Detection {
    #[inline]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    pub text: String,
    pub detections: Vec<Detection>,
}
