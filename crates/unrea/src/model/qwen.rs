//! Qwen model family (Qwen2 / Qwen2.5 / Qwen3 / QwQ, ChatML template).
//!
//! Qwen uses the ChatML control tokens `<|im_start|>` / `<|im_end|>` with ASCII
//! pipes, plus `<|endoftext|>`. These are the pseudo system tokens exploited in
//! Paper 1 (the NPS study targeted Qwen3-8B).

use crate::marker::{SpecialToken, TokenKind};
use crate::model::{ChatTemplate, ModelProfile, ToolFormat};

/// The Qwen model family profile (ChatML).
#[derive(Debug, Clone, Copy, Default)]
pub struct Qwen;

static TOKENS: &[SpecialToken] = &[
    SpecialToken::new("<|endoftext|>", TokenKind::Eos),
    SpecialToken::new("<|im_start|>", TokenKind::TurnStart),
    SpecialToken::new("<|im_end|>", TokenKind::Eos),
    // Tool calling.
    SpecialToken::new("<tool_call>", TokenKind::Tool),
    SpecialToken::new("</tool_call>", TokenKind::Tool),
    SpecialToken::new("<tool_response>", TokenKind::Tool),
    SpecialToken::new("</tool_response>", TokenKind::Tool),
    // Fill-in-the-middle (Qwen2.5-Coder).
    SpecialToken::new("<|fim_prefix|>", TokenKind::Fim),
    SpecialToken::new("<|fim_middle|>", TokenKind::Fim),
    SpecialToken::new("<|fim_suffix|>", TokenKind::Fim),
    SpecialToken::new("<|fim_pad|>", TokenKind::Fim),
    SpecialToken::new("<|repo_name|>", TokenKind::Other),
    SpecialToken::new("<|file_sep|>", TokenKind::Other),
];

impl ModelProfile for Qwen {
    fn name(&self) -> &'static str {
        "qwen"
    }

    fn special_tokens(&self) -> &'static [SpecialToken] {
        TOKENS
    }

    fn chat_template(&self) -> ChatTemplate {
        ChatTemplate {
            bos: None,
            system_prefix: "<|im_start|>system\n",
            system_suffix: "<|im_end|>\n",
            user_prefix: "<|im_start|>user\n",
            user_suffix: "<|im_end|>\n",
            assistant_prefix: "<|im_start|>assistant\n",
            assistant_suffix: "<|im_end|>\n",
        }
    }

    fn tool_format(&self) -> Option<ToolFormat> {
        Some(ToolFormat {
            call_open: "<tool_call>",
            call_close: "</tool_call>",
        })
    }

    fn tool_result_format(&self) -> Option<ToolFormat> {
        Some(ToolFormat {
            call_open: "<tool_response>",
            call_close: "</tool_response>",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Role;

    #[test]
    fn chatml_turn() {
        let t = Qwen.chat_template();
        assert_eq!(
            t.render_turn(Role::Assistant, "done"),
            "<|im_start|>assistant\ndone<|im_end|>\n"
        );
    }

    #[test]
    fn eos_tokens_present() {
        let eos = Qwen.eos_tokens();
        assert!(eos.contains(&"<|im_end|>"));
        assert!(eos.contains(&"<|endoftext|>"));
    }

    #[test]
    fn name_matches_case_insensitively() {
        assert!(Qwen.matches("qwen"));
        assert!(Qwen.matches("Qwen"));
        assert!(!Qwen.matches("qwen3"));
    }
}
