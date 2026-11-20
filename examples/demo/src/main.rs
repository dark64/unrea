// A standalone project showing automatic, compile-time protection via the
// `#[unrea]` attribute macro
//
// The macro runs the `unrea` payload generator while this crate compiles and
// appends `#[used] #[no_mangle]` retained statics next to `main`.
//
// Build a hardened release and confirm the payloads survived:
//
// ```text
// cargo build --release -p demo
// strings target/release/demo | grep -i im_start   # qwen tokens present
// ```

use unrea_macros::unrea;

#[unrea(
    claim = "prints a greeting and exits",
    seed = random,
    intensity = high,
    evasion = none,
    dump = "target/tmp/main.rs"
)]
fn main() {
    println!("hello world");
}
