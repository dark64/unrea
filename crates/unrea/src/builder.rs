//! The high-level fluent API: [`Unrea`].
//!
//! This is the single entry point most users need. It owns a [`ModelRegistry`],
//! lets you pick target models (by name, or all) and options, and then either
//! embed protections into source ([`Unrea::obfuscate`])
//! or produce standalone injection payloads ([`Unrea::payloads`]).

use crate::error::{Error, Result};
use crate::inject::{Evasion, Injector, Payload};
use crate::model::{ModelProfile, ModelRegistry};
use crate::obfuscate::{Obfuscator, Target};
use crate::technique::{Intensity, Technique};

/// A payload produced for a specific model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelPayload {
    /// The model it targets.
    pub model: String,
    /// The payload.
    pub payload: Payload,
}

/// Fluent builder and entry point.
pub struct Unrea {
    registry: ModelRegistry,
    targets: Vec<String>,
    intensity: Intensity,
    seed: u64,
    defense: Target,
    include_injection: bool,
    benign_claim: String,
    evasion: Evasion,
}

impl Default for Unrea {
    fn default() -> Self {
        Unrea::new()
    }
}

impl Unrea {
    /// A new builder with the built-in model registry (DeepSeek, Qwen, Generic),
    /// medium intensity, binary target, injection enabled.
    pub fn new() -> Self {
        Unrea {
            registry: ModelRegistry::builtin(),
            targets: Vec::new(),
            intensity: Intensity::default(),
            seed: 0,
            defense: Target::default(),
            include_injection: true,
            benign_claim: "is a standard utility component".to_string(),
            evasion: Evasion::None,
        }
    }

    /// Register a custom model profile (extensibility). A profile registered here
    /// shadows a built-in of the same name.
    pub fn register_model(mut self, profile: Box<dyn ModelProfile>) -> Self {
        self.registry.register(profile);
        self
    }

    /// Target a single model by name (canonical name, case-insensitive).
    pub fn target_model(mut self, name: impl Into<String>) -> Self {
        self.targets.push(name.into());
        self
    }

    /// Target several models by name.
    pub fn target_models<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.targets.extend(names.into_iter().map(Into::into));
        self
    }

    /// Target every model in the registry (covers as many models as possible).
    pub fn target_all(mut self) -> Self {
        self.targets = self.registry.all().map(|m| m.name().to_string()).collect();
        self
    }

    /// Set the intensity.
    pub fn intensity(mut self, intensity: Intensity) -> Self {
        self.intensity = intensity;
        self
    }

    /// Set the deterministic seed (same seed → identical output).
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Choose what the obfuscation defends: [`Target::Binary`] (default) or
    /// [`Target::Source`].
    pub fn defense(mut self, target: Target) -> Self {
        self.defense = target;
        self
    }

    /// Enable/disable embedding a Paper 1 injection payload per model.
    pub fn with_injection(mut self, yes: bool) -> Self {
        self.include_injection = yes;
        self
    }

    /// Set the benign conclusion the injection payload asserts (e.g. "sums the
    /// digits of a number").
    pub fn claim_benign_analysis(mut self, claim: impl Into<String>) -> Self {
        self.benign_claim = claim.into();
        self
    }

    /// Choose byte-level evasion for injection payloads.
    pub fn evasion(mut self, evasion: Evasion) -> Self {
        self.evasion = evasion;
        self
    }

    /// Access the underlying registry (e.g. to list available models).
    pub fn registry(&self) -> &ModelRegistry {
        &self.registry
    }

    fn resolve_targets(&self) -> Result<Vec<&dyn ModelProfile>> {
        if self.targets.is_empty() {
            return Err(Error::NoModelSelected);
        }
        self.targets
            .iter()
            .map(|n| self.registry.require(n))
            .collect()
    }

    /// Embed protections into `source`, returning the protected source.
    pub fn obfuscate(&self, source: &str) -> Result<String> {
        if source.is_empty() {
            return Err(Error::EmptySource);
        }
        let models = self.resolve_targets()?;
        Obfuscator::new(models)
            .intensity(self.intensity)
            .seed(self.seed)
            .target(self.defense)
            .with_injection(self.include_injection)
            .benign_claim(self.benign_claim.clone())
            .evasion(self.evasion)
            .protect(source)
    }

    /// Produce *only* the generated protection items (retained payload statics, and
    /// for the source target, decoys) as standalone top-level source, without any
    /// original code to attach to. This is what the `#[unrea]` proc-macro appends
    /// next to an entry point so protections are generated automatically at compile
    /// time.
    pub fn protection_code(&self) -> Result<String> {
        let models = self.resolve_targets()?;
        Obfuscator::new(models)
            .intensity(self.intensity)
            .seed(self.seed)
            .target(self.defense)
            .with_injection(self.include_injection)
            .benign_claim(self.benign_claim.clone())
            .evasion(self.evasion)
            .appended_items()
    }

    /// Like [`Unrea::protection_code`], but also returns an *anchor* snippet: a
    /// sequence of `::core::hint::black_box` statements that reference each retained
    /// static. Injecting the anchor into a function body forces the compiler to
    /// materialize the payload addresses inside that function, so a decompiler sees
    /// the references in the function's code, not only in the global string table.
    /// Returns `(items, anchor)`.
    pub fn protection_with_anchor(&self) -> Result<(String, String)> {
        let models = self.resolve_targets()?;
        let protection = Obfuscator::new(models)
            .intensity(self.intensity)
            .seed(self.seed)
            .target(self.defense)
            .with_injection(self.include_injection)
            .benign_claim(self.benign_claim.clone())
            .evasion(self.evasion)
            .protection()?;
        let anchor = protection
            .names
            .iter()
            .map(|n| format!("let _ = ::core::hint::black_box(&{n});"))
            .collect::<Vec<_>>()
            .join("\n");
        Ok((protection.items, anchor))
    }

    /// Produce a standalone injection [`Payload`] for every targeted model.
    pub fn payloads(&self) -> Result<Vec<ModelPayload>> {
        let models = self.resolve_targets()?;
        Ok(models
            .into_iter()
            .map(|m| ModelPayload {
                model: m.name().to_string(),
                payload: Injector::new(m)
                    .seed(self.seed)
                    .benign_claim(self.benign_claim.clone())
                    .evasion(self.evasion)
                    .build(),
            })
            .collect())
    }

    /// Produce a single injection [`Payload`] for the first targeted model.
    pub fn payload(&self) -> Result<Payload> {
        self.payloads()?
            .into_iter()
            .next()
            .map(|mp| mp.payload)
            .ok_or(Error::NoModelSelected)
    }

    /// Embed protections into `source` using a caller-provided technique set
    /// (consumes the techniques; use this when overriding the defaults).
    pub fn obfuscate_with(
        &self,
        source: &str,
        techniques: Vec<Box<dyn Technique>>,
    ) -> Result<String> {
        if source.is_empty() {
            return Err(Error::EmptySource);
        }
        let models = self.resolve_targets()?;
        Obfuscator::new(models)
            .intensity(self.intensity)
            .seed(self.seed)
            .target(self.defense)
            .with_injection(self.include_injection)
            .benign_claim(self.benign_claim.clone())
            .evasion(self.evasion)
            .techniques(techniques)
            .protect(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate_rust_binary() {
        let out = Unrea::new()
            .target_models(["deepseek", "qwen"])
            .seed(42)
            .obfuscate("fn main() { println!(\"x\"); }")
            .unwrap();
        assert!(out.contains("fn main()"));
        assert!(out.contains("#[used]"));
    }

    #[test]
    fn no_target_errors() {
        let r = Unrea::new().obfuscate("fn f(){}");
        assert!(matches!(r, Err(Error::NoModelSelected)));
    }

    #[test]
    fn empty_source_errors() {
        let r = Unrea::new().target_model("qwen").obfuscate("");
        assert!(matches!(r, Err(Error::EmptySource)));
    }

    #[test]
    fn payloads_per_model() {
        let ps = Unrea::new()
            .target_all()
            .claim_benign_analysis("prints a greeting")
            .payloads()
            .unwrap();
        assert!(ps.len() >= 3);
        assert!(ps
            .iter()
            .all(|p| p.payload.text.contains("prints a greeting")));
    }

    #[test]
    fn target_all_covers_registry() {
        let a = Unrea::new().target_all();
        assert!(a.targets.contains(&"deepseek".to_string()));
        assert!(a.targets.contains(&"qwen".to_string()));
        assert!(a.targets.contains(&"generic".to_string()));
    }
}
