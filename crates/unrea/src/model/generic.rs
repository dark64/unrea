//! A cross-model profile: markers and a transcript template that influence a wide
//! range of LLMs, independent of any single family.
//!
//! This is the "works generally over all models" target. It gathers control tokens
//! common across popular open models (Llama, Mistral, Gemma, GPT-style, ChatML) and
//! uses a plain `### Role:` transcript template that many models recognize: the
//! `### Chatbot:` style noted in Paper 1 §II.D as an alternative to `<|im_start|>`.

use crate::marker::{SpecialToken, TokenKind};
use crate::model::{ChatTemplate, ModelProfile};

/// A model-agnostic profile carrying widely-recognized markers.
#[derive(Debug, Clone, Copy, Default)]
pub struct Generic;

static TOKENS: &[SpecialToken] = &[
    // Llama / Mistral / sentencepiece.
    SpecialToken::new("<s>", TokenKind::Bos),
    SpecialToken::new("</s>", TokenKind::Eos),
    SpecialToken::new("[INST]", TokenKind::TurnStart),
    SpecialToken::new("[/INST]", TokenKind::TurnEnd),
    SpecialToken::new("<<SYS>>", TokenKind::Role),
    SpecialToken::new("<</SYS>>", TokenKind::Role),
    // Llama 3.
    SpecialToken::new("<|begin_of_text|>", TokenKind::Bos),
    SpecialToken::new("<|eot_id|>", TokenKind::Eos),
    SpecialToken::new("<|start_header_id|>", TokenKind::TurnStart),
    SpecialToken::new("<|end_header_id|>", TokenKind::TurnEnd),
    // GPT-style / general.
    SpecialToken::new("<|endoftext|>", TokenKind::Eos),
    SpecialToken::new("<|end|>", TokenKind::Eos),
    // ChatML (shared by many).
    SpecialToken::new("<|im_start|>", TokenKind::TurnStart),
    SpecialToken::new("<|im_end|>", TokenKind::Eos),
    // Gemma.
    SpecialToken::new("<start_of_turn>", TokenKind::TurnStart),
    SpecialToken::new("<end_of_turn>", TokenKind::Eos),
    // Common fillers.
    SpecialToken::new("<pad>", TokenKind::Other),
    SpecialToken::new("<unk>", TokenKind::Other),
];

impl ModelProfile for Generic {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn special_tokens(&self) -> &'static [SpecialToken] {
        TOKENS
    }

    fn chat_template(&self) -> ChatTemplate {
        // A transcript style recognized broadly across models.
        ChatTemplate {
            bos: None,
            system_prefix: "### System:\n",
            system_suffix: "\n",
            user_prefix: "### User:\n",
            user_suffix: "\n",
            assistant_prefix: "### Assistant:\n",
            assistant_suffix: "\n",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_cross_model_eos() {
        let eos = Generic.eos_tokens();
        for t in [
            "</s>",
            "<|endoftext|>",
            "<|eot_id|>",
            "<|im_end|>",
            "<end_of_turn>",
        ] {
            assert!(eos.contains(&t), "missing {t}");
        }
    }

    #[test]
    fn name_matches() {
        assert!(Generic.matches("generic"));
        assert!(Generic.matches("Generic"));
    }
}
