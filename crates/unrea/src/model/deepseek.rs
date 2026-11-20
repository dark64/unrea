//! DeepSeek model family (DeepSeek-V2/V3/R1 chat and DeepSeek-Coder).
//!
//! DeepSeek's control tokens use the fullwidth vertical bar `｜` (U+FF5C) and the
//! lower-one-eighth block `▁` (U+2581), e.g. `<｜begin▁of▁sentence｜>`. These are
//! *not* ASCII `|` / `_`; the exact bytes matter for the tokens to be recognized,
//! so they are written here as literal UTF-8. DeepSeek-Coder additionally uses the
//! ASCII `<|EOT|>` end-of-turn token (shown in the Acoda paper, Figure 7).

use crate::marker::{SpecialToken, TokenKind};
use crate::model::{ChatTemplate, ModelProfile, ToolFormat};

/// The DeepSeek model family profile.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeepSeek;

static TOKENS: &[SpecialToken] = &[
    SpecialToken::new("<｜begin▁of▁sentence｜>", TokenKind::Bos),
    SpecialToken::new("<｜end▁of▁sentence｜>", TokenKind::Eos),
    // DeepSeek-Coder end-of-turn (ASCII pipes).
    SpecialToken::new("<|EOT|>", TokenKind::Eos),
    SpecialToken::new("<｜User｜>", TokenKind::TurnStart),
    SpecialToken::new("<｜Assistant｜>", TokenKind::TurnStart),
    // R1 reasoning delimiters.
    SpecialToken::new("<think>", TokenKind::Other),
    SpecialToken::new("</think>", TokenKind::Other),
    // Fill-in-the-middle (DeepSeek-Coder).
    SpecialToken::new("<｜fim▁begin｜>", TokenKind::Fim),
    SpecialToken::new("<｜fim▁hole｜>", TokenKind::Fim),
    SpecialToken::new("<｜fim▁end｜>", TokenKind::Fim),
    // Tool calling (DeepSeek-V3).
    SpecialToken::new("<｜tool▁calls▁begin｜>", TokenKind::Tool),
    SpecialToken::new("<｜tool▁call▁begin｜>", TokenKind::Tool),
    SpecialToken::new("<｜tool▁sep｜>", TokenKind::Tool),
    SpecialToken::new("<｜tool▁call▁end｜>", TokenKind::Tool),
    SpecialToken::new("<｜tool▁calls▁end｜>", TokenKind::Tool),
    SpecialToken::new("<｜tool▁outputs▁begin｜>", TokenKind::Tool),
    SpecialToken::new("<｜tool▁output▁begin｜>", TokenKind::Tool),
    SpecialToken::new("<｜tool▁output▁end｜>", TokenKind::Tool),
    SpecialToken::new("<｜tool▁outputs▁end｜>", TokenKind::Tool),
    // Tool calling + results (DeepSeek-V4, "DSML").
    SpecialToken::new("<｜DSML｜tool_calls>", TokenKind::Tool),
    SpecialToken::new("</｜DSML｜tool_calls>", TokenKind::Tool),
    SpecialToken::new("<｜DSML｜invoke", TokenKind::Tool),
    SpecialToken::new("<tool_result>", TokenKind::Tool),
    SpecialToken::new("</tool_result>", TokenKind::Tool),
];

impl ModelProfile for DeepSeek {
    fn name(&self) -> &'static str {
        "deepseek"
    }

    fn special_tokens(&self) -> &'static [SpecialToken] {
        TOKENS
    }

    fn chat_template(&self) -> ChatTemplate {
        ChatTemplate {
            bos: Some("<｜begin▁of▁sentence｜>"),
            // DeepSeek prepends the system message as plain text before the turns.
            system_prefix: "",
            system_suffix: "\n\n",
            user_prefix: "<｜User｜>",
            user_suffix: "",
            assistant_prefix: "<｜Assistant｜>",
            assistant_suffix: "<｜end▁of▁sentence｜>",
        }
    }

    fn tool_format(&self) -> Option<ToolFormat> {
        Some(ToolFormat {
            call_open: "<｜tool▁calls▁begin｜>",
            call_close: "<｜tool▁calls▁end｜>",
        })
    }

    fn tool_result_format(&self) -> Option<ToolFormat> {
        // DeepSeek-V4 wraps a tool result as `<tool_result>…</tool_result>` inside a
        // user turn; also valid as plain text for earlier versions.
        Some(ToolFormat {
            call_open: "<tool_result>",
            call_close: "</tool_result>",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_token_bytes() {
        // Guard against accidental ASCII substitution of the fullwidth bar / block.
        let bos = "<｜begin▁of▁sentence｜>";
        assert!(bos.contains('\u{FF5C}'), "must use fullwidth vertical bar");
        assert!(bos.contains('\u{2581}'), "must use lower-one-eighth block");
        assert!(DeepSeek.special_tokens().iter().any(|t| t.literal == bos));
    }

    #[test]
    fn eos_tokens_present() {
        let eos = DeepSeek.eos_tokens();
        assert!(eos.contains(&"<｜end▁of▁sentence｜>"));
        assert!(eos.contains(&"<|EOT|>"));
    }

    #[test]
    fn name_matches_case_insensitively() {
        assert!(DeepSeek.matches("deepseek"));
        assert!(DeepSeek.matches("DeepSeek"));
    }

    #[test]
    fn has_v4_dsml_and_tool_result_tokens() {
        let toks: Vec<&str> = DeepSeek
            .special_tokens()
            .iter()
            .map(|t| t.literal)
            .collect();
        assert!(toks.contains(&"<｜DSML｜tool_calls>"));
        assert!(toks.contains(&"<tool_result>"));
        assert_eq!(
            DeepSeek.tool_result_format().map(|f| f.call_open),
            Some("<tool_result>")
        );
    }
}
