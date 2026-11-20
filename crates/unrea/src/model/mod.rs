//! Model profiles: per-model markers, chat templates and the registry.
//!
//! A [`ModelProfile`] captures everything the library needs to know to target a
//! specific model family: its exact control tokens, how its chat template frames a
//! conversation turn (used to fabricate convincing pseudo-conversations for
//! Paper 1 injection payloads), and which tokens terminate generation (used for
//! Paper 2 EOS-token insertion).
//!
//! Adding a new model is intentionally cheap: implement [`ModelProfile`] and
//! [`ModelRegistry::register`] it. No changes to the rest of the crate. See
//! `examples/add_model.rs`.

use crate::error::{Error, Result};
use crate::marker::SpecialToken;

pub mod deepseek;
pub mod generic;
pub mod glm;
pub mod kimi;
pub mod openai;
pub mod qwen;

pub use deepseek::DeepSeek;
pub use generic::Generic;
pub use glm::Glm;
pub use kimi::Kimi;
pub use openai::OpenAi;
pub use qwen::Qwen;

/// A conversation role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// System / developer instructions.
    System,
    /// The user turn.
    User,
    /// The assistant / model turn.
    Assistant,
}

/// How a model frames a chat turn.
///
/// Rendering `prefix + content + suffix` for each role reproduces the model's
/// template closely enough to make a fabricated "already finished, benign"
/// analysis look authentic to the model.
#[derive(Debug, Clone)]
pub struct ChatTemplate {
    /// Beginning-of-sequence string, if the template emits one.
    pub bos: Option<&'static str>,
    /// Prefix emitted before a system turn's content.
    pub system_prefix: &'static str,
    /// Suffix emitted after a system turn's content.
    pub system_suffix: &'static str,
    /// Prefix emitted before a user turn's content.
    pub user_prefix: &'static str,
    /// Suffix emitted after a user turn's content.
    pub user_suffix: &'static str,
    /// Prefix emitted before an assistant turn's content.
    pub assistant_prefix: &'static str,
    /// Suffix emitted after an assistant turn's content.
    pub assistant_suffix: &'static str,
}

impl ChatTemplate {
    /// The opening marker for `role` (what precedes the content).
    pub fn role_prefix(&self, role: Role) -> &'static str {
        match role {
            Role::System => self.system_prefix,
            Role::User => self.user_prefix,
            Role::Assistant => self.assistant_prefix,
        }
    }

    /// The closing marker for `role` (what follows the content).
    pub fn role_suffix(&self, role: Role) -> &'static str {
        match role {
            Role::System => self.system_suffix,
            Role::User => self.user_suffix,
            Role::Assistant => self.assistant_suffix,
        }
    }

    /// Render a full turn: `prefix + content + suffix`.
    pub fn render_turn(&self, role: Role, content: &str) -> String {
        format!(
            "{}{}{}",
            self.role_prefix(role),
            content,
            self.role_suffix(role)
        )
    }
}

/// The token-pair a model/agent framework uses to delimit a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolFormat {
    /// Token opening a tool call block.
    pub call_open: &'static str,
    /// Token closing a tool call block.
    pub call_close: &'static str,
}

/// A model family the library can target.
///
/// Implementors provide the exact markers and template; default methods derive
/// the rest. All methods borrow `&self` so profiles can be stored as trait
/// objects in a [`ModelRegistry`].
pub trait ModelProfile: Send + Sync {
    /// The canonical model name (lowercase, e.g. `"deepseek"`).
    fn name(&self) -> &'static str;

    /// Alternative names this profile also answers to.
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    /// Every special/control token this model uses.
    fn special_tokens(&self) -> &'static [SpecialToken];

    /// The model's chat template.
    fn chat_template(&self) -> ChatTemplate;

    /// The model/framework tool-*call* delimiters, if any.
    fn tool_format(&self) -> Option<ToolFormat> {
        None
    }

    /// The delimiters that wrap a tool *result* fed back to the model, if any.
    /// Used to fabricate a convincing "a tool already ran and returned benign
    /// output" block in an injection payload.
    fn tool_result_format(&self) -> Option<ToolFormat> {
        None
    }

    /// The subset of [`ModelProfile::special_tokens`] that can terminate
    /// generation. These are the tokens most useful for EOS-token insertion.
    fn eos_tokens(&self) -> Vec<&'static str> {
        self.special_tokens()
            .iter()
            .filter(|t| t.is_eos())
            .map(|t| t.literal)
            .collect()
    }

    /// Whether `query` names this model (case-insensitive, matches name or alias).
    fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_ascii_lowercase();
        self.name().eq_ignore_ascii_case(&q)
            || self.aliases().iter().any(|a| a.eq_ignore_ascii_case(&q))
    }
}

/// A collection of model profiles, looked up by name or alias.
pub struct ModelRegistry {
    profiles: Vec<Box<dyn ModelProfile>>,
}

impl std::fmt::Debug for ModelRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelRegistry")
            .field(
                "models",
                &self.profiles.iter().map(|p| p.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ModelRegistry {
    /// An empty registry.
    pub fn empty() -> Self {
        ModelRegistry {
            profiles: Vec::new(),
        }
    }

    /// A registry pre-loaded with the built-in profiles: DeepSeek, Qwen, GLM, Kimi,
    /// OpenAI (Harmony), and a cross-model Generic.
    pub fn builtin() -> Self {
        let mut r = ModelRegistry::empty();
        r.register(Box::new(DeepSeek));
        r.register(Box::new(Qwen));
        r.register(Box::new(Glm));
        r.register(Box::new(Kimi));
        r.register(Box::new(OpenAi));
        r.register(Box::new(Generic));
        r
    }

    /// Add a profile. A later registration with the same name shadows earlier
    /// ones for lookups, which lets callers override a built-in.
    pub fn register(&mut self, profile: Box<dyn ModelProfile>) {
        self.profiles.push(profile);
    }

    /// Look up a profile by name or alias (case-insensitive). Later registrations
    /// win, so an override added after `builtin()` takes precedence.
    pub fn get(&self, query: &str) -> Option<&dyn ModelProfile> {
        self.profiles
            .iter()
            .rev()
            .find(|p| p.matches(query))
            .map(|b| b.as_ref())
    }

    /// Look up a profile, returning [`Error::UnknownModel`] if absent.
    pub fn require(&self, query: &str) -> Result<&dyn ModelProfile> {
        self.get(query)
            .ok_or_else(|| Error::UnknownModel(query.to_string()))
    }

    /// Iterate over every registered profile.
    pub fn all(&self) -> impl Iterator<Item = &dyn ModelProfile> {
        self.profiles.iter().map(|b| b.as_ref())
    }

    /// Number of registered profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

impl Default for ModelRegistry {
    fn default() -> Self {
        ModelRegistry::builtin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_has_models() {
        let r = ModelRegistry::builtin();
        assert!(r.get("deepseek").is_some());
        assert!(r.get("qwen").is_some());
        assert!(r.get("generic").is_some());
        assert!(r.get("DeepSeek").is_some(), "lookup is case-insensitive");
        assert!(r.get("nope").is_none());
    }

    #[test]
    fn require_errors_on_unknown() {
        let r = ModelRegistry::builtin();
        assert!(matches!(r.require("void"), Err(Error::UnknownModel(_))));
    }

    #[test]
    fn render_turn_combines_parts() {
        let t = ChatTemplate {
            bos: None,
            system_prefix: "<s>",
            system_suffix: "</s>",
            user_prefix: "<u>",
            user_suffix: "</u>",
            assistant_prefix: "<a>",
            assistant_suffix: "</a>",
        };
        assert_eq!(t.render_turn(Role::User, "hi"), "<u>hi</u>");
    }

    #[test]
    fn lookup_by_canonical_name() {
        let r = ModelRegistry::builtin();
        assert_eq!(r.get("deepseek").map(|p| p.name()), Some("deepseek"));
        assert_eq!(r.get("qwen").map(|p| p.name()), Some("qwen"));
    }
}
