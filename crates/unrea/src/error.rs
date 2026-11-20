//! Error and result types for the crate.

use std::fmt;

/// The result type used throughout `unrea`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can arise while building payloads or obfuscating source.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A model name/alias was requested that is not present in the registry.
    UnknownModel(String),
    /// No target model was selected but the requested operation needs one.
    NoModelSelected,
    /// The caller requested an empty set of techniques / targets.
    EmptySelection(&'static str),
    /// A technique could not be applied to the given input (with a reason).
    TechniqueFailed {
        /// The name of the technique that failed.
        technique: &'static str,
        /// A human-readable reason.
        reason: String,
    },
    /// The provided source code was empty where non-empty input was required.
    EmptySource,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownModel(name) => {
                write!(f, "unknown model '{name}' (not found in registry)")
            }
            Error::NoModelSelected => {
                write!(
                    f,
                    "no target model selected for an operation that requires one"
                )
            }
            Error::EmptySelection(what) => write!(f, "empty selection: {what}"),
            Error::TechniqueFailed { technique, reason } => {
                write!(f, "technique '{technique}' failed: {reason}")
            }
            Error::EmptySource => write!(f, "source code was empty"),
        }
    }
}

impl std::error::Error for Error {}
