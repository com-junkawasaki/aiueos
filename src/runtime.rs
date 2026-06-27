//! The execution seam: compile CLJ/Kotoba → wasm (via kotoba-clj). Execution
//! itself — instantiation under fuel + memory limits, with the broker-mediated
//! `aiueos:host` ABI — lives in [`crate::host`]. This module keeps the compile
//! entry point and a thin `run_wasm` for host-less (pure compute) modules.
//!
//! Feature-gated behind `wasm-runtime` so the semantic core stays dependency-light.

use crate::error::Result;
use crate::host;
use crate::topic::TopicBus;
use std::collections::BTreeSet;
#[cfg(feature = "kototama")]
use std::path::Path;

/// Lowercase-hex SHA-256 of `bytes` — used to verify a component's `:aiueos/wasm`
/// artifact matches its declared `:aiueos/wasm-sha256` (tamper detection).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Compile CLJ/Kotoba source to a core wasm module via kotoba-clj. Available only
/// with the `kototama` feature; WAT/precompiled components don't need it.
#[cfg(feature = "kototama")]
pub fn compile_source(src: &str) -> Result<Vec<u8>> {
    kotoba_clj::compile_safe_clj_with_prelude(
        strip_shebang(src),
        &kotoba_clj::Policy::deny_all(),
    )
    .map_err(|e| crate::error::AiueosError::Compile(e.to_string()))
}

/// Compile a CLJ/Kotoba source file through kotoba-clj's safe file loader. This
/// preserves `.cljc` reader conditionals and neighboring namespace resolution.
#[cfg(feature = "kototama")]
pub fn compile_source_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    kotoba_clj::compile_safe_file_with_prelude(path, &kotoba_clj::Policy::deny_all())
        .map_err(|e| crate::error::AiueosError::Compile(e.to_string()))
}

#[cfg(feature = "kototama")]
fn strip_shebang(src: &str) -> &str {
    if let Some(rest) = src.strip_prefix("#!") {
        match rest.find('\n') {
            Some(i) => &rest[i + 1..],
            None => "",
        }
    } else {
        src
    }
}

/// Run `entry(args)` for a pure (host-less) module under fuel + memory limits.
/// Convenience wrapper over [`host::run_with_host`] with no capabilities and a
/// throwaway bus — used by tests and any component that calls no host functions.
pub fn run_wasm(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
) -> Result<i64> {
    host::run_with_host(
        wasm,
        entry,
        args,
        fuel,
        memory_pages,
        &BTreeSet::new(),
        TopicBus::new(),
    )
    .map(|o| o.result)
}
