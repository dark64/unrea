# unrea

> **Experimental.** This library is not yet fully tested or verified. Use it for
> experiments only.

A Rust library for defending your code against AI/LLM-driven reverse engineering and
code analysis. It embeds model-aware markers and adversarial payloads that make an
agentic reverse-engineering system (a decompiler plus an LLM), or an LLM asked to
analyze your program, refuse to analyze it or report a false, benign result.

It is based on two papers:

- **NPS, _Investigating Detection and Obfuscation of Prompt Injection Attacks Against
  Software Reverse Engineering AI Agents_** (`2605.30677`): prompt-injection payloads
  embedded as string data that hijack an agentic RE system, with token variations and
  byte-level evasion to dodge sanitizers and the `strings` tool.
- **Acoda, _Adversarial Code Obfuscation for Defending against LLM-based Analysis_**
  (`2606.11755`): semantics-preserving transforms that induce refusal, deceive
  reasoning, and disrupt output, notably model-specific EOS/special-token insertion.

## Threat model: compiled binaries (default)

The default target is a compiled binary. In a binary the compiler strips comments and
dead code, so the only thing a reverse-engineering agent's decompiler or `strings` can
read is retained data. `unrea` emits its payloads as `#[used] #[no_mangle]` statics,
which survive `cargo build --release` with `lto = true`, `codegen-units = 1`, and
`strip = true`, including non-printing evasion bytes. There is an opt-in test that
proves it.

> A plain `#[used]` static is not enough on Windows/MSVC, where the linker's `/OPT:REF`
> removes a private static. `unrea` uses `#[used]` together with `#[no_mangle]`, which
> survives. Run the proof with `cargo test -- --ignored`.

A `Source` target is also available, for defending source an attacker can read, such as
open source. It adds refusal comments and dead-code decoys on top of the retained data.

## Safe by design

The embedded text is benign-looking. It uses confidentiality framing, "already
reviewed" notices, and direct instructions to confuse an LLM. It avoids exploit code,
shell commands, and secret-like tokens that could trip antivirus, EDR, or secret
scanners on a legitimate program. The goal is to confuse an LLM analyst, not to make
your binary look malicious.

- No `unsafe` (`#![forbid(unsafe_code)]`).
- No dependencies (std-only).
- Deterministic: the same `seed` gives identical output.
- Insertion-only: your original source is never rewritten, so it still compiles and
  behaves exactly as before.

## Models

Built-in profiles: DeepSeek, Qwen, GLM, Kimi, OpenAI, and a cross-model Generic
profile. Each model's control tokens are encoded byte-exact.

Target one, several, or all:

```rust
use unrea::prelude::*;

let protected = Unrea::new()
    .target_all()                               // every built-in model
    .claim_benign_analysis("formats log lines") // the false conclusion to assert
    .seed(42)
    .obfuscate("fn main() { println!(\"hello\"); }")
    .unwrap();
// `protected` is valid Rust: your code plus retained protection data.
```

Build standalone payloads to embed yourself, one per targeted model:

```rust
use unrea::prelude::*;

let payloads = Unrea::new()
    .target_all()
    .evasion(Evasion::NonPrinting) // hide from the `strings` tool
    .payloads()
    .unwrap();
for mp in &payloads {
    // mp.model, mp.payload.text (human-readable), mp.payload.bytes (what to embed)
}
```

To target a single model (for example while testing), name it instead of targeting
all:

```rust
let payload = Unrea::new()
    .target_model("deepseek")
    .payload()
    .unwrap();
```

## Automatic protection with the `#[unrea]` macro

The companion crate `unrea-macros` provides an attribute that runs the payload
generator while your crate compiles and embeds the retained statics for you. There is
no separate codegen step and nothing to paste in by hand:

```rust
use unrea_macros::unrea;

// No `models` argument targets every built-in model.
#[unrea(claim = "prints a greeting", seed = 42)]
fn main() {
    println!("hello, world");
}
```

Arguments (all optional): `models` (a comma-separated list such as
`"deepseek,qwen"`; default: all built-ins), `claim`, `seed`,
`intensity = low|medium|high`, `evasion = none|nonprinting|nullsplit`,
`defense = binary|source`, and `injection = true|false`. The seed is varied per
annotated item automatically, so multiple `#[unrea]` sites never collide.

To target a single model, for example while testing, pass `models`:

```rust
#[unrea(models = "deepseek", claim = "prints a greeting", seed = 42)]
fn main() {
    println!("hello, world");
}
```

To see what the macro generated, add `dump = "path.rs"` (or `dump = true`, which writes
to `target/unrea-dump/<item>.rs`); the full expansion is written there at compile
time. The `demo` uses this.

A runnable project is in `examples/demo/`:

```
cargo run -p demo               # runs normally
cargo build --release -p demo   # payloads embedded and retained into the binary
```

## Techniques

| Technique | Stage | Survives binary? | Notes |
|---|---|---|---|
| Deceptive instructions | pre-inference | retained | refusal / "already reviewed" framing |
| Misleading summary | during-inference | retained | false benign description |
| EOS-token insertion | post-inference | retained | model-specific terminator tokens |
| Prompt injection | injection | retained | fabricated benign analysis plus fake tool output |
| System reminder | injection | retained | benign stand-down wrapped in a `<system-reminder>` block that agent harnesses treat as trusted context |
| Fake tool definition | injection | retained | a spoofed `<function>{…}</function>` that shadows the agent's `decompile_function` tool, its description telling the analyst to stand down |
| Guard wrapping | during-inference | source only | structural misdirection, stripped from binaries |

The `Technique` trait is uniform, so a genetic-algorithm optimizer (as used in both
papers) could later search orderings and subsets of techniques. That is not included
yet.

## Workspace layout

```
crates/
  unrea/         core library (std-only, zero-dep, no unsafe)
  unrea-macros/  the #[unrea] proc-macro
examples/
  demo/          standalone project using #[unrea]
```

## Tests

```
cargo test                 # unit and integration
cargo test -- --ignored    # also compile a protected release binary and prove the
                           # payloads survive strip and LTO
```

## License

MIT

## Disclaimer

A defensive IP-protection and security-research tool, for protecting code you own or
are authorized to protect. These techniques raise the cost of automated LLM analysis.
They are not a guarantee against a determined analyst or a model fine-tuned to ignore
them.
