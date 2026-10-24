use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineError {
    InputTooLarge { len: usize, max: usize },
    UnknownPreset(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::InputTooLarge { len, max } => {
                write!(f, "input of {len} bytes exceeds limit of {max} bytes")
            }
            EngineError::UnknownPreset(name) => write!(f, "unknown ruleset preset: {name:?}"),
        }
    }
}

impl std::error::Error for EngineError {}
