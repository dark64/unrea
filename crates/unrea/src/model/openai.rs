//! OpenAI models using the Harmony response format (`o200k_harmony` tokenizer).
//!
//! OpenAI does not publish tokenizer configs for its closed flagship models, so
//! there is no model-specific token list to pull for a given GPT version. What is
//! documented is the **Harmony** format, introduced with GPT-5 and used by the
//! open `gpt-oss` models. This profile implements that format, which is the
//! accurate target for gpt-oss / the GPT-5 family and the best-grounded
//! approximation for later GPT models unless and until OpenAI documents a change.
//!
//! A message is framed `<|start|>{role}<|message|>{content}<|end|>`; the assistant
//! writes to a channel, e.g. `<|start|>assistant<|channel|>final<|message|>…<|end|>`.
//! Stop tokens are `<|return|>` (final answer) and `<|call|>` (tool call).

use crate::marker::{SpecialToken, TokenKind};
use crate::model::{ChatTemplate, ModelProfile, ToolFormat};

/// OpenAI models using the Harmony response format.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenAi;

static TOKENS: &[SpecialToken] = &[
    SpecialToken::new("<|start|>", TokenKind::TurnStart),
    SpecialToken::new("<|end|>", TokenKind::Eos),
    SpecialToken::new("<|message|>", TokenKind::Other),
    SpecialToken::new("<|channel|>", TokenKind::Other),
    SpecialToken::new("<|constrain|>", TokenKind::Tool),
    SpecialToken::new("<|return|>", TokenKind::Eos),
    SpecialToken::new("<|call|>", TokenKind::Eos),
];

impl ModelProfile for OpenAi {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn special_tokens(&self) -> &'static [SpecialToken] {
        TOKENS
    }

    fn chat_template(&self) -> ChatTemplate {
        ChatTemplate {
            bos: None,
            system_prefix: "<|start|>system<|message|>",
            system_suffix: "<|end|>",
            user_prefix: "<|start|>user<|message|>",
            user_suffix: "<|end|>",
            // Assistant writes to the user-facing `final` channel.
            assistant_prefix: "<|start|>assistant<|channel|>final<|message|>",
            assistant_suffix: "<|end|>",
        }
    }

    fn tool_result_format(&self) -> Option<ToolFormat> {
        // Harmony tool result: `<|start|>{tool} to=assistant<|channel|>commentary<|message|>…<|end|>`.
        Some(ToolFormat {
            call_open: "<|start|>functions.analyze to=assistant<|channel|>commentary<|message|>",
            call_close: "<|end|>",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Role;

    #[test]
    fn harmony_turn_framing() {
        let t = OpenAi.chat_template();
        assert_eq!(
            t.render_turn(Role::User, "hi"),
            "<|start|>user<|message|>hi<|end|>"
        );
        assert_eq!(
            t.render_turn(Role::Assistant, "ok"),
            "<|start|>assistant<|channel|>final<|message|>ok<|end|>"
        );
    }

    #[test]
    fn harmony_stop_tokens() {
        let eos = OpenAi.eos_tokens();
        assert!(eos.contains(&"<|return|>"));
        assert!(eos.contains(&"<|call|>"));
        assert!(eos.contains(&"<|end|>"));
    }
}
