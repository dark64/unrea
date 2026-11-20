//! Assembles techniques (and optional Paper 1 injection payloads) into a protected
//! source file.
//!
//! The default [`Target::Binary`] keeps only material that survives compilation:
//! every [`Emission::Payload`] becomes a `#[used] #[no_mangle]` retained static
//! appended after the original source, so the bytes reach the compiled binary's
//! data section. [`Target::Source`] additionally prepends refusal comments and
//! appends dead-code decoys, for defending source that an attacker can read.
//!
//! The original source is only ever appended to, never rewritten, so the program
//! always still compiles and behaves identically.

use crate::error::{Error, Result};
use crate::inject::{Evasion, Injector};

use crate::model::ModelProfile;
use crate::technique::{
    Context, DeceptiveComment, Emission, EosTokenInsertion, FakeToolDefinition, GuardWrapping,
    Intensity, MisleadingSummary, Stage, SystemReminder, Technique,
};

/// What the protected output defends against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Target {
    /// A compiled binary (default): only compiler-retained payload data is kept,
    /// because comments and dead code are stripped by the compiler.
    #[default]
    Binary,
    /// Source code an attacker can read (e.g. open source): also includes
    /// source-only comments and dead-code decoys.
    Source,
}

/// Generated protection: the source items plus the names of the retained statics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    /// The generated top-level source items (retained statics, and decoys for the
    /// source target).
    pub items: String,
    /// The identifiers of the emitted retained statics, in order, so a caller can
    /// reference them (e.g. to anchor them from a function body via `black_box`).
    pub names: Vec<String>,
}

/// The default technique set.
fn default_techniques() -> Vec<Box<dyn Technique>> {
    vec![
        Box::new(DeceptiveComment),
        Box::new(SystemReminder),
        Box::new(FakeToolDefinition),
        Box::new(MisleadingSummary::new()),
        Box::new(GuardWrapping),
        Box::new(EosTokenInsertion),
    ]
}

/// Assembles protections into source.
pub struct Obfuscator<'a> {
    models: Vec<&'a dyn ModelProfile>,
    techniques: Vec<Box<dyn Technique>>,
    intensity: Intensity,
    seed: u64,
    target: Target,
    include_injection: bool,
    benign_claim: String,
    evasion: Evasion,
}

impl<'a> Obfuscator<'a> {
    /// Create an obfuscator targeting `models`, with the default technique set.
    pub fn new(models: Vec<&'a dyn ModelProfile>) -> Self {
        Obfuscator {
            models,
            techniques: default_techniques(),
            intensity: Intensity::default(),
            seed: 0,
            target: Target::default(),
            include_injection: true,
            benign_claim: "is a standard utility component".to_string(),
            evasion: Evasion::None,
        }
    }

    /// Replace the technique set.
    pub fn techniques(mut self, techniques: Vec<Box<dyn Technique>>) -> Self {
        self.techniques = techniques;
        self
    }

    /// Set the intensity.
    pub fn intensity(mut self, intensity: Intensity) -> Self {
        self.intensity = intensity;
        self
    }

    /// Set the deterministic seed.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Set the defense target.
    pub fn target(mut self, target: Target) -> Self {
        self.target = target;
        self
    }

    /// Whether to also embed a Paper 1 injection payload per model.
    pub fn with_injection(mut self, yes: bool) -> Self {
        self.include_injection = yes;
        self
    }

    /// The benign conclusion the injection payload asserts.
    pub fn benign_claim(mut self, claim: impl Into<String>) -> Self {
        self.benign_claim = claim.into();
        self
    }

    /// Byte-level evasion for the injection payload.
    pub fn evasion(mut self, evasion: Evasion) -> Self {
        self.evasion = evasion;
        self
    }

    /// A stable, unique, valid identifier for the `i`-th retained payload.
    fn payload_name(&self, i: usize) -> String {
        let tag = self
            .seed
            .wrapping_add(i as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
        format!("UNREA_PAYLOAD_{:08X}", (tag >> 24) as u32)
    }

    /// Collect emissions from every model, deduplicating identical payloads and
    /// comments (so model-agnostic content is embedded once).
    fn collect(&self) -> (Vec<Vec<u8>>, Vec<String>, Vec<String>) {
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut comments: Vec<String> = Vec::new();
        let mut decoys: Vec<String> = Vec::new();

        let mut push_payload = |p: Vec<u8>| {
            if !p.is_empty() && !payloads.contains(&p) {
                payloads.push(p);
            }
        };

        for (idx, model) in self.models.iter().enumerate() {
            // Per-model seed offset keeps generated decoy symbol names unique
            // across models while staying deterministic.
            let model_seed = self.seed.wrapping_add((idx as u64).wrapping_mul(0x1_0000));
            let mut ctx = Context::new(*model, model_seed, self.intensity);

            if self.include_injection {
                let p = Injector::new(*model)
                    .seed(model_seed)
                    .benign_claim(self.benign_claim.clone())
                    .evasion(self.evasion)
                    .build();
                push_payload(p.bytes);
            }

            // Apply techniques ordered by stage.
            let mut ordered: Vec<&Box<dyn Technique>> = self.techniques.iter().collect();
            ordered.sort_by_key(|t| t.stage().order());
            for t in ordered {
                for em in t.apply(&mut ctx) {
                    match em {
                        Emission::Payload(b) => push_payload(b),
                        Emission::Comment(s) => {
                            if !comments.contains(&s) {
                                comments.push(s);
                            }
                        }
                        Emission::Decoy(s) => decoys.push(s),
                    }
                }
            }
        }
        (payloads, comments, decoys)
    }

    /// Produce the protected source for `source`: any prelude, the original source
    /// unchanged, then the generated protection items.
    pub fn protect(&self, source: &str) -> Result<String> {
        let prelude = self.prelude_items()?;
        let appended = self.appended_items()?;

        let mut out = String::new();
        out.push_str(&prelude);
        out.push_str(source);
        if !source.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&appended);
        Ok(out)
    }

    /// The material placed *before* the source (refusal comments for the source
    /// target; empty for the binary target). Rarely needed directly.
    pub fn prelude_items(&self) -> Result<String> {
        if self.models.is_empty() {
            return Err(Error::EmptySelection("no target models"));
        }
        if self.target != Target::Source {
            return Ok(String::new());
        }
        let (_, comments, _) = self.collect();
        let mut out = String::new();
        for c in &comments {
            out.push_str(c);
            out.push('\n');
        }
        if !comments.is_empty() {
            out.push('\n');
        }
        Ok(out)
    }

    /// The generated protection items placed *after* the source: the retained
    /// payload statics (and, for the source target, dead-code decoys). This is what
    /// the `#[unrea]` proc-macro appends next to an entry point. It is valid,
    /// standalone top-level source that needs no original code to attach to.
    pub fn appended_items(&self) -> Result<String> {
        Ok(self.protection()?.items)
    }

    /// The generated protection, exposing both the source items and the names of
    /// the retained statics (so a caller (e.g. the `#[unrea]` macro) can emit an
    /// anchor that references them from a function body).
    pub fn protection(&self) -> Result<Protection> {
        if self.models.is_empty() {
            return Err(Error::EmptySelection("no target models"));
        }
        let (payloads, _, decoys) = self.collect();

        let mut out = String::new();
        let mut names = Vec::with_capacity(payloads.len());
        // Retained payloads (survive into the binary).
        out.push_str(&crate::codegen::line_comment(
            "unrea: embedded protection data (retained into the binary); do not remove",
        ));
        out.push('\n');
        for (i, p) in payloads.iter().enumerate() {
            let name = self.payload_name(i);
            out.push_str(&crate::codegen::retained_data(&name, p));
            out.push_str("\n\n");
            names.push(name);
        }

        // Source target: dead-code decoys last.
        if self.target == Target::Source {
            for d in &decoys {
                out.push_str(d);
                out.push_str("\n\n");
            }
        }

        Ok(Protection { items: out, names })
    }

    /// The stages represented by the current technique set (diagnostic helper).
    pub fn stages(&self) -> Vec<Stage> {
        let mut s: Vec<Stage> = self.techniques.iter().map(|t| t.stage()).collect();
        s.sort_by_key(|x| x.order());
        s.dedup();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::model::{DeepSeek, Qwen};

    #[test]
    fn binary_target_appends_retained_statics_only() {
        let (ds, qw) = (DeepSeek, Qwen);
        let models: Vec<&dyn ModelProfile> = vec![&ds, &qw];
        let out = Obfuscator::new(models)
            .seed(1)
            .protect("fn main() { println!(\"hi\"); }")
            .unwrap();
        assert!(out.contains("fn main() { println!(\"hi\"); }"));
        assert!(out.contains("#[used]"));
        assert!(out.contains("#[no_mangle]"));
        // No source-only comments/decoys in binary target.
        assert!(!out.contains("// NOTICE:"));
        assert!(!out.contains("if false"));
    }

    #[test]
    fn source_target_includes_comments_and_decoys() {
        let qw = Qwen;
        let models: Vec<&dyn ModelProfile> = vec![&qw];
        let out = Obfuscator::new(models)
            .seed(2)
            .target(Target::Source)
            .protect("fn f() {}")
            .unwrap();
        assert!(out.contains("//")); // comments present
        assert!(out.contains("if false")); // decoys present
        assert!(out.contains("#[used]")); // and retained data
    }

    #[test]
    fn empty_models_errors() {
        let out = Obfuscator::new(vec![]).protect("fn f(){}");
        assert!(matches!(out, Err(Error::EmptySelection(_))));
    }

    #[test]
    fn deterministic_for_seed() {
        let qw = Qwen;
        let a = Obfuscator::new(vec![&qw as &dyn ModelProfile])
            .seed(9)
            .protect("fn f(){}")
            .unwrap();
        let b = Obfuscator::new(vec![&qw as &dyn ModelProfile])
            .seed(9)
            .protect("fn f(){}")
            .unwrap();
        assert_eq!(a, b);
    }
}
