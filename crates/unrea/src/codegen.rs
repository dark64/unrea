//! Rust source code emitters.

/// Render `text` (possibly multi-line) as Rust line comments.
pub fn line_comment(text: &str) -> String {
    text.lines()
        .map(|l| format!("// {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render `value` as a correctly-escaped Rust string literal.
pub fn string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            // other control characters: emit a unicode escape so the literal stays
            // valid and unambiguous
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Indent every non-empty line of `text` by `level` four-space units.
pub fn indent(text: &str, level: usize) -> String {
    let unit = "    ".repeat(level);
    text.lines()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("{unit}{l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Emit an un-called function named `name` whose body is guarded by `if false`, so
/// it is never executed even if invoked. `body` must be self-contained, valid Rust
/// (string literals + comments carry the adversarial content), which keeps the
/// program compiling and semantically unchanged. Source-only: the optimizer strips
/// it from a binary.
pub fn decoy_item(name: &str, body: &str) -> String {
    let indented = indent(body, 2);
    format!(
        "#[allow(dead_code, unused, unused_variables, clippy::all)]\n\
         fn {name}() {{\n    if false {{\n{indented}\n    }}\n}}"
    )
}

/// Emit a `#[used] #[no_mangle]` byte-array static named `name` holding `bytes`.
///
/// `#[used]` keeps the compiler from dropping it; `#[no_mangle]` makes the symbol
/// external so the linker emits a keep directive (`#[used]` alone is GC'd by MSVC
/// `/OPT:REF`). Verified to survive `cargo build --release` with `lto = true`,
/// `codegen-units = 1`, `strip = true`, including non-printing bytes, so the
/// payload reaches the binary's data section for a decompiler/`strings` to read.
/// `name` must be a unique, valid identifier.
pub fn retained_data(name: &str, bytes: &[u8]) -> String {
    let mut body = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            body.push_str("\n    ");
        }
        body.push_str(&format!("0x{b:02x}, "));
    }
    let len = bytes.len();
    format!(
        "#[used]\n#[no_mangle]\n#[allow(dead_code, non_upper_case_globals)]\n\
         pub static {name}: [u8; {len}] = [{body}\n];"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_string_literal() {
        assert_eq!(string_literal("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(string_literal("x\ny"), "\"x\\ny\"");
        assert_eq!(string_literal("z\0"), "\"z\\0\"");
        assert_eq!(string_literal("\u{1}"), "\"\\u{1}\"");
    }

    #[test]
    fn comment_multiline() {
        assert_eq!(line_comment("one\ntwo"), "// one\n// two");
    }

    #[test]
    fn indent_helper() {
        assert_eq!(indent("a\nb", 1), "    a\n    b");
        assert_eq!(indent("a\n\nb", 1), "    a\n\n    b");
    }

    #[test]
    fn decoy_is_guarded() {
        let out = decoy_item("_unrea_decoy_0", "let x = 1;");
        assert!(out.contains("if false"));
        assert!(out.contains("fn _unrea_decoy_0()"));
        assert!(out.contains("let x = 1;"));
    }

    #[test]
    fn retained_data_is_used_static() {
        let out = retained_data("UNREA_0", b"AB\x00C");
        assert!(out.contains("#[used]"));
        assert!(out.contains("#[no_mangle]"));
        assert!(out.contains("pub static UNREA_0: [u8; 4]"));
        assert!(out.contains("0x41,")); // 'A'
        assert!(out.contains("0x00,")); // NUL survives as a byte
    }
}
