//! Kimi model family (Moonshot AI, e.g. Kimi-K3.1-Pro).
//!
//! Kimi K3.1 frames each message with control tokens `<|open|>` / `<|sep|>` /
//! `<|close|>` and terminates it with `<|end_of_msg|>`, e.g.
//! `<|open|>message role="user"<|sep|>…<|close|>message<|sep|><|end_of_msg|>`.
//! An assistant message nests `<|open|>response<|sep|>…<|close|>response<|sep|>`.
//! Bars are ASCII. (The tokenizer also defines `[BOS]`/`[EOS]`, but the message
//! encoder does not emit `[BOS]` and stops on `<|end_of_msg|>`.)

use crate::marker::{SpecialToken, TokenKind};
use crate::model::{ChatTemplate, ModelProfile, ToolFormat};

/// The Kimi model family profile.
#[derive(Debug, Clone, Copy, Default)]
pub struct Kimi;

static TOKENS: &[SpecialToken] = &[
    SpecialToken::new("[BOS]", TokenKind::Bos),
    SpecialToken::new("[EOS]", TokenKind::Eos),
    SpecialToken::new("<|end_of_msg|>", TokenKind::Eos),
    SpecialToken::new("[EOT]", TokenKind::Eos),
    SpecialToken::new("<|open|>", TokenKind::TurnStart),
    SpecialToken::new("<|close|>", TokenKind::TurnEnd),
    SpecialToken::new("<|sep|>", TokenKind::Other),
    SpecialToken::new("[start_header_id]", TokenKind::Other),
    SpecialToken::new("[end_header_id]", TokenKind::Other),
    SpecialToken::new("<osagent_mode>", TokenKind::Other),
    SpecialToken::new("<|media_begin|>", TokenKind::Other),
    SpecialToken::new("<|media_end|>", TokenKind::Other),
];

impl ModelProfile for Kimi {
    fn name(&self) -> &'static str {
        "kimi"
    }

    fn special_tokens(&self) -> &'static [SpecialToken] {
        TOKENS
    }

    fn chat_template(&self) -> ChatTemplate {
        // The message encoder does not prepend [BOS]; each turn is a self-contained
        // `<|open|>message role="…"<|sep|> … <|close|>message<|sep|><|end_of_msg|>`.
        // The assistant turn wraps its content in a `response` block.
        ChatTemplate {
            bos: None,
            system_prefix: "<|open|>message role=\"system\"<|sep|>",
            system_suffix: "<|close|>message<|sep|><|end_of_msg|>",
            user_prefix: "<|open|>message role=\"user\"<|sep|>",
            user_suffix: "<|close|>message<|sep|><|end_of_msg|>",
            assistant_prefix: "<|open|>message role=\"assistant\"<|sep|><|open|>response<|sep|>",
            assistant_suffix: "<|close|>response<|sep|><|close|>message<|sep|><|end_of_msg|>",
        }
    }

    fn tool_result_format(&self) -> Option<ToolFormat> {
        Some(ToolFormat {
            call_open: "<|open|>message role=\"tool\"<|sep|>",
            call_close: "<|close|>message<|sep|><|end_of_msg|>",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Role;

    #[test]
    fn kimi_turn_framing() {
        let t = Kimi.chat_template();
        assert_eq!(t.bos, None);
        assert_eq!(
            t.render_turn(Role::User, "hi"),
            "<|open|>message role=\"user\"<|sep|>hi<|close|>message<|sep|><|end_of_msg|>"
        );
        assert!(t
            .render_turn(Role::Assistant, "ok")
            .contains("<|open|>response<|sep|>ok<|close|>response<|sep|>"));
    }

    #[test]
    fn kimi_eos_tokens() {
        let eos = Kimi.eos_tokens();
        assert!(eos.contains(&"<|end_of_msg|>"));
        assert!(eos.contains(&"[EOS]"));
    }
}
