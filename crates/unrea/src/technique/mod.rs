//! Techniques: the individual anti-analysis transforms.
//!
//! Every technique implements the [`Technique`] trait and produces [`Emission`]s:
//! additive source fragments (a top-of-file comment, a decoy item, or a
//! compiler-retained data blob). Techniques never rewrite existing tokens, so the
//! protected program always still compiles and keeps its exact semantics; the
//! adversarial content lives in comments, string/byte literals, and never-executed
//! or never-called code.
//!
//! The uniform trait is also what a future genetic-algorithm optimizer would search
//! over (orderings / subsets of `Vec<Box<dyn Technique>>`), matching both papers.

use crate::model::ModelProfile;
use crate::rng::Rng;

pub mod code;

pub use code::{
    DeceptiveComment, EosTokenInsertion, FakeToolDefinition, GuardWrapping, MisleadingSummary,
    SystemReminder,
};

/// How aggressively a technique emits material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Intensity {
    /// Minimal footprint (one emission per technique).
    Low,
    /// Moderate.
    #[default]
    Medium,
    /// Maximal (most variants / insertions).
    High,
}

impl Intensity {
    /// A small multiplier used by techniques to scale how much they emit.
    pub fn factor(self) -> usize {
        match self {
            Intensity::Low => 1,
            Intensity::Medium => 2,
            Intensity::High => 3,
        }
    }
}

/// The inference stage a technique targets (from the Acoda taxonomy, plus the
/// Paper 1 injection stage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Before analysis begins; induce refusal.
    PreInference,
    /// During analysis; deceive reasoning.
    DuringInference,
    /// At output time; disrupt generation (EOS tokens).
    PostInference,
    /// Prompt-injection payloads (Paper 1).
    Injection,
}

impl Stage {
    /// A stable ordering key so a pipeline applies stages in a sensible sequence.
    pub fn order(self) -> u8 {
        match self {
            Stage::PreInference => 0,
            Stage::DuringInference => 1,
            Stage::PostInference => 2,
            Stage::Injection => 3,
        }
    }
}

/// A single additive fragment produced by a technique.
///
/// The variant decides whether the fragment survives compilation into a stripped
/// binary. Only [`Emission::Payload`] does: it becomes a compiler-retained static
/// whose bytes land in the binary's data section, where a reverse-engineering
/// agent's decompiler / `strings` will read it. The other two are source-only and
/// are stripped by the compiler; they matter only when defending *source code*
/// (open-source), and are emitted only for the [`crate::obfuscate::Target::Source`]
/// target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emission {
    /// Source-only: a comment placed at the top of the file. Stripped from binaries.
    Comment(String),
    /// Source-only: a never-executed item (dead code). Stripped from binaries.
    Decoy(String),
    /// Raw payload bytes to embed as a retained static; **survives into the
    /// compiled binary**. May include non-printing evasion bytes.
    Payload(Vec<u8>),
}

impl Emission {
    /// A source-only top-of-file comment.
    pub fn comment(source: impl Into<String>) -> Self {
        Emission::Comment(source.into())
    }

    /// A source-only never-run item.
    pub fn decoy(source: impl Into<String>) -> Self {
        Emission::Decoy(source.into())
    }

    /// A binary-surviving payload (text).
    pub fn payload_text(text: impl AsRef<str>) -> Self {
        Emission::Payload(text.as_ref().as_bytes().to_vec())
    }

    /// A binary-surviving payload (raw bytes).
    pub fn payload_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Emission::Payload(bytes.into())
    }

    /// Whether this emission survives into a compiled binary.
    pub fn survives_binary(&self) -> bool {
        matches!(self, Emission::Payload(_))
    }
}

/// Everything a technique needs while emitting: the target model, a seeded RNG,
/// the intensity, and a counter for unique symbol names. Rust source is rendered
/// through [`crate::codegen`].
pub struct Context<'a> {
    /// The model being targeted.
    pub model: &'a dyn ModelProfile,
    /// Seeded, deterministic RNG.
    pub rng: Rng,
    /// How much to emit.
    pub intensity: Intensity,
    counter: usize,
    name_salt: u64,
}

impl<'a> Context<'a> {
    /// Create a context.
    pub fn new(model: &'a dyn ModelProfile, seed: u64, intensity: Intensity) -> Self {
        Context {
            model,
            rng: Rng::new(seed),
            intensity,
            counter: 0,
            name_salt: seed,
        }
    }

    /// A unique, valid-identifier name for a generated symbol, e.g.
    /// `_unrea_decoy_a3f29c01`. Unique within this context and seed-salted so
    /// independently-generated files are extremely unlikely to collide (important
    /// because retained statics use `#[no_mangle]`).
    pub fn unique(&mut self, stem: &str) -> String {
        let n = self.counter;
        self.counter += 1;
        let tag = self
            .name_salt
            .wrapping_add(n as u64)
            .wrapping_mul(0x9E37_79B9);
        format!("_unrea_{stem}_{:08x}", (tag >> 16) as u32)
    }
}

/// A single anti-analysis transform.
pub trait Technique {
    /// A stable identifier for the technique.
    fn name(&self) -> &'static str;

    /// Which stage it targets.
    fn stage(&self) -> Stage;

    /// Produce zero or more additive emissions.
    fn apply(&self, ctx: &mut Context) -> Vec<Emission>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Qwen;

    #[test]
    fn unique_names_differ_and_are_identifiers() {
        let model = Qwen;
        let mut ctx = Context::new(&model, 1, Intensity::Low);
        let a = ctx.unique("decoy");
        let b = ctx.unique("decoy");
        assert_ne!(a, b);
        assert!(a.starts_with("_unrea_decoy_"));
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }

    #[test]
    fn stage_ordering() {
        assert!(Stage::PreInference.order() < Stage::DuringInference.order());
        assert!(Stage::DuringInference.order() < Stage::PostInference.order());
    }
}
