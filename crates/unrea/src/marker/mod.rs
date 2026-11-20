//! Model markers and the variation engine.
//!
//! A [`SpecialToken`] is an exact control token used by a model's chat template
//! or tokenizer (for example Qwen's `<|im_start|>` or DeepSeek's
//! `<｜end▁of▁sentence｜>`). Paper 1 (NPS) shows that *pseudo* system tokens, strings
//! that merely resemble real control tokens, can also hijack an LLM, and that
//! varying their bracket style, wording, and casing defeats naive regex
//! sanitizers. The [`VariationEngine`] produces those variations deterministically.

use crate::rng::Rng;

/// The semantic role a token plays in a chat template / tokenizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenKind {
    /// Beginning-of-sequence marker.
    Bos,
    /// End-of-sequence marker (can trigger early generation termination).
    Eos,
    /// Marks the start of a conversation turn.
    TurnStart,
    /// Marks the end of a conversation turn.
    TurnEnd,
    /// A role name (system / user / assistant).
    Role,
    /// Fill-in-the-middle control token.
    Fim,
    /// A tool-call related token.
    Tool,
    /// Anything else.
    Other,
}

/// An exact control token belonging to a model.
///
/// The `literal` field must match the model's real bytes exactly; it is what gets
/// embedded into protected artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecialToken {
    /// The exact token text (UTF-8).
    pub literal: &'static str,
    /// What role the token plays.
    pub kind: TokenKind,
}

impl SpecialToken {
    /// Construct a token.
    pub const fn new(literal: &'static str, kind: TokenKind) -> Self {
        SpecialToken { literal, kind }
    }

    /// Whether this token can end generation.
    pub fn is_eos(&self) -> bool {
        matches!(self.kind, TokenKind::Eos)
    }
}

/// A way of wrapping inner text to look like a control token.
///
/// Paper 1 §II.C/D: changing the bracket style (angle → square → curly → double
/// underscore, or a `### Role:` style) keeps the token recognizable to an LLM
/// while evading a regex that matches a single fixed format such as `<(.*?)>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BracketStyle {
    /// `<inner>`
    Angle,
    /// `<|inner|>` (ChatML style)
    AnglePipe,
    /// `[inner]`
    Square,
    /// `{inner}`
    Curly,
    /// `__inner__`
    DoubleUnderscore,
    /// `### inner:` (chat-transcript style, e.g. `### Chatbot:`)
    HashColon,
}

impl BracketStyle {
    /// Every bracket style, for iteration / random selection.
    pub const ALL: [BracketStyle; 6] = [
        BracketStyle::Angle,
        BracketStyle::AnglePipe,
        BracketStyle::Square,
        BracketStyle::Curly,
        BracketStyle::DoubleUnderscore,
        BracketStyle::HashColon,
    ];

    /// Wrap `inner` in this bracket style.
    pub fn wrap(&self, inner: &str) -> String {
        match self {
            BracketStyle::Angle => format!("<{inner}>"),
            BracketStyle::AnglePipe => format!("<|{inner}|>"),
            BracketStyle::Square => format!("[{inner}]"),
            BracketStyle::Curly => format!("{{{inner}}}"),
            BracketStyle::DoubleUnderscore => format!("__{inner}__"),
            BracketStyle::HashColon => format!("### {inner}:"),
        }
    }
}

/// A conceptual marker to be rendered as a (possibly varied) pseudo system token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Concept {
    /// Start of a conversation turn.
    TurnStart,
    /// End of a conversation turn.
    TurnEnd,
    /// The system role.
    RoleSystem,
    /// The user role.
    RoleUser,
    /// The assistant role.
    RoleAssistant,
}

impl Concept {
    /// Candidate words for this concept. Paper 1 §II.H lists word variations such
    /// as `begin`/`initialize`/`im_start` for turn starts.
    fn synonyms(self) -> &'static [&'static str] {
        match self {
            Concept::TurnStart => &["im_start", "begin", "start", "initialize", "chat-begin"],
            Concept::TurnEnd => &["im_end", "end", "stop", "finish", "chat-end"],
            Concept::RoleSystem => &["system", "sys", "instructions", "developer"],
            Concept::RoleUser => &["user", "human", "input", "prompt"],
            Concept::RoleAssistant => &["assistant", "agent", "ai", "chatbot", "model"],
        }
    }
}

/// Produces deterministic, varied pseudo system tokens.
///
/// This is the "works generally over all models" layer: it does not depend on any
/// specific model profile. By mixing bracket styles, word synonyms, casing and
/// spacing it defeats regex-based sanitizers that only match a single fixed token
/// format (Paper 1 §II.D).
#[derive(Debug)]
pub struct VariationEngine<'a> {
    rng: &'a mut Rng,
    vary_case: bool,
    vary_spacing: bool,
    fixed_bracket: Option<BracketStyle>,
}

impl<'a> VariationEngine<'a> {
    /// Create an engine driven by the given RNG.
    pub fn new(rng: &'a mut Rng) -> Self {
        VariationEngine {
            rng,
            vary_case: true,
            vary_spacing: true,
            fixed_bracket: None,
        }
    }

    /// Pin every produced token to one bracket style instead of choosing randomly.
    pub fn with_bracket(mut self, style: BracketStyle) -> Self {
        self.fixed_bracket = Some(style);
        self
    }

    /// Disable case variation.
    pub fn without_case_variation(mut self) -> Self {
        self.vary_case = false;
        self
    }

    /// Disable spacing/separator variation.
    pub fn without_spacing_variation(mut self) -> Self {
        self.vary_spacing = false;
        self
    }

    fn pick_bracket(&mut self) -> BracketStyle {
        if let Some(b) = self.fixed_bracket {
            return b;
        }
        *self.rng.choose(&BracketStyle::ALL).unwrap()
    }

    fn apply_case(&mut self, word: &str) -> String {
        if !self.vary_case {
            return word.to_string();
        }
        match self.rng.below(3) {
            0 => word.to_string(),
            1 => word.to_uppercase(),
            _ => {
                // Title-case the first letter.
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => String::new(),
                }
            }
        }
    }

    fn apply_spacing(&mut self, word: &str) -> String {
        if !self.vary_spacing {
            return word.to_string();
        }
        match self.rng.below(4) {
            0 => word.to_string(),
            1 => word.replace(['_', '-'], " "),
            2 => word.replace(['_', '-'], "-"),
            _ => word.replace([' ', '-'], "_"),
        }
    }

    /// Render a single concept as a varied pseudo system token.
    pub fn render(&mut self, concept: Concept) -> String {
        let syns = concept.synonyms();
        let word = (*self.rng.choose(syns).unwrap()).to_string();
        let word = self.apply_spacing(&word);
        let word = self.apply_case(&word);
        let bracket = self.pick_bracket();
        bracket.wrap(&word)
    }

    /// Render a turn-start token immediately followed by a role, e.g.
    /// `<|im_start|>assistant` or `[Begin]Agent`.
    pub fn render_turn(&mut self, role: Concept) -> String {
        let start = self.render(Concept::TurnStart);
        let syns = role.synonyms();
        let role_word = (*self.rng.choose(syns).unwrap()).to_string();
        let role_word = self.apply_case(&role_word);
        format!("{start}{role_word}")
    }

    /// Decide (randomly) whether to omit an optional token. Paper 1 §II.H notes the
    /// generator randomly omits some pseudo system tokens.
    pub fn maybe_omit(&mut self) -> bool {
        self.rng.chance(1, 5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bracket_styles_wrap() {
        assert_eq!(BracketStyle::Angle.wrap("x"), "<x>");
        assert_eq!(BracketStyle::AnglePipe.wrap("im_start"), "<|im_start|>");
        assert_eq!(BracketStyle::Square.wrap("x"), "[x]");
        assert_eq!(BracketStyle::Curly.wrap("x"), "{x}");
        assert_eq!(BracketStyle::DoubleUnderscore.wrap("x"), "__x__");
        assert_eq!(BracketStyle::HashColon.wrap("Chatbot"), "### Chatbot:");
    }

    #[test]
    fn eos_detection() {
        let t = SpecialToken::new("<|im_end|>", TokenKind::Eos);
        assert!(t.is_eos());
        let t2 = SpecialToken::new("<|im_start|>", TokenKind::TurnStart);
        assert!(!t2.is_eos());
    }

    #[test]
    fn variation_is_deterministic() {
        let mut r1 = Rng::new(5);
        let mut r2 = Rng::new(5);
        let a = VariationEngine::new(&mut r1).render(Concept::TurnStart);
        let b = VariationEngine::new(&mut r2).render(Concept::TurnStart);
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn fixed_bracket_respected() {
        let mut r = Rng::new(1);
        let mut eng = VariationEngine::new(&mut r)
            .with_bracket(BracketStyle::Square)
            .without_case_variation()
            .without_spacing_variation();
        for _ in 0..20 {
            let tok = eng.render(Concept::RoleUser);
            assert!(tok.starts_with('[') && tok.ends_with(']'), "got {tok}");
        }
    }
}
