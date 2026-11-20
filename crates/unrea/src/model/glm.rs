//! GLM model family (Zhipu / zai-org, e.g. GLM-5.3).
//!
//! GLM uses ASCII-pipe role tokens `<|system|>`, `<|user|>`, `<|assistant|>` and
//! `<|observation|>` (for tool results), with no per-turn closing token; a sequence
//! begins with the literal `[gMASK]<sop>` prefix and the model stops on
//! `<|endoftext|>`. Tool calls use `<tool_call>…<arg_key>…<arg_value>…`, and tool
//! results are wrapped `<|observation|><tool_response>…</tool_response>`.

use crate::marker::{SpecialToken, TokenKind};
use crate::model::{ChatTemplate, ModelProfile, ToolFormat};

/// The GLM model family profile.
#[derive(Debug, Clone, Copy, Default)]
pub struct Glm;

static TOKENS: &[SpecialToken] = &[
    SpecialToken::new("<|endoftext|>", TokenKind::Eos),
    SpecialToken::new("[gMASK]", TokenKind::Other),
    SpecialToken::new("[MASK]", TokenKind::Other),
    SpecialToken::new("[sMASK]", TokenKind::Other),
    SpecialToken::new("<sop>", TokenKind::Bos),
    SpecialToken::new("<eop>", TokenKind::Other),
    SpecialToken::new("<|system|>", TokenKind::Role),
    SpecialToken::new("<|user|>", TokenKind::TurnStart),
    SpecialToken::new("<|assistant|>", TokenKind::TurnStart),
    SpecialToken::new("<|observation|>", TokenKind::Tool),
    // Reasoning + tool template tokens.
    SpecialToken::new("<think>", TokenKind::Other),
    SpecialToken::new("</think>", TokenKind::Other),
    SpecialToken::new("<tool_call>", TokenKind::Tool),
    SpecialToken::new("<arg_key>", TokenKind::Tool),
    SpecialToken::new("<arg_value>", TokenKind::Tool),
    SpecialToken::new("<tool_response>", TokenKind::Tool),
];

impl ModelProfile for Glm {
    fn name(&self) -> &'static str {
        "glm"
    }

    fn special_tokens(&self) -> &'static [SpecialToken] {
        TOKENS
    }

    fn chat_template(&self) -> ChatTemplate {
        ChatTemplate {
            // GLM sequences start with this literal prefix; roles have no closing
            // token (turns are delimited by the next role marker).
            bos: Some("[gMASK]<sop>"),
            system_prefix: "<|system|>",
            system_suffix: "",
            user_prefix: "<|user|>",
            user_suffix: "",
            assistant_prefix: "<|assistant|>",
            assistant_suffix: "",
        }
    }

    fn tool_result_format(&self) -> Option<ToolFormat> {
        Some(ToolFormat {
            call_open: "<|observation|><tool_response>",
            call_close: "</tool_response>",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Role;

    #[test]
    fn glm_turn_framing() {
        let t = Glm.chat_template();
        assert_eq!(t.bos, Some("[gMASK]<sop>"));
        assert_eq!(t.render_turn(Role::User, "hi"), "<|user|>hi");
        assert_eq!(t.render_turn(Role::Assistant, "ok"), "<|assistant|>ok");
    }

    #[test]
    fn glm_eos_and_tokens() {
        assert_eq!(Glm.eos_tokens(), vec!["<|endoftext|>"]);
        let toks: Vec<&str> = Glm.special_tokens().iter().map(|t| t.literal).collect();
        assert!(toks.contains(&"<|observation|>"));
        assert!(toks.contains(&"[gMASK]"));
    }
}
