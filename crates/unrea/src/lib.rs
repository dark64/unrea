//! # unrea
//!
//! A toolkit for defending code against **AI/LLM-driven reverse engineering and
//! code analysis**. It embeds *model-aware markers* and *adversarial payloads* that
//! cause an agentic reverse-engineering system (decompiler + LLM) to refuse, stall,
//! or report a benign, incorrect result.
//!
//! ## Quick start
//!
//! ```
//! use unrea::prelude::*;
//!
//! // Embed protections into Rust source for DeepSeek + Qwen analysts.
//! let protected = Unrea::new()
//!     .target_models(["deepseek", "qwen"])
//!     .claim_benign_analysis("formats log lines")
//!     .seed(42)
//!     .obfuscate("fn main() { println!(\"hello\"); }")
//!     .unwrap();
//! assert!(protected.contains("#[used]"));
//!
//! // Or just build an embeddable payload.
//! let payload = Unrea::new().target_model("deepseek").payload().unwrap();
//! assert!(!payload.bytes.is_empty());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod codegen;
pub mod error;
pub mod inject;
pub mod marker;
pub mod model;
pub mod obfuscate;
pub mod rng;
pub mod technique;

pub use builder::{ModelPayload, Unrea};
pub use error::{Error, Result};
pub use inject::{Evasion, Injector, Payload};
pub use obfuscate::{Obfuscator, Protection, Target};
pub use technique::Intensity;

/// The common imports.
pub mod prelude {
    pub use crate::builder::{ModelPayload, Unrea};
    pub use crate::error::{Error, Result};
    pub use crate::inject::{Evasion, Payload};
    pub use crate::model::{ModelProfile, ModelRegistry};
    pub use crate::obfuscate::Target;
    pub use crate::technique::{Intensity, Technique};
}
