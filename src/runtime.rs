//! The execution seam: compile CLJ/Kotoba → wasm (kototama). Execution itself —
//! instantiation under fuel + memory limits, with the broker-mediated `aiueos:host`
//! ABI — lives in [`crate::host`]. This module keeps the compile entry point and
//! a thin `run_wasm` for host-less (pure compute) modules.
//!
//! Feature-gated behind `wasm-runtime` so the semantic core stays dependency-light.

use crate::error::Result;
use crate::host;
use crate::topic::TopicBus;
use std::collections::BTreeSet;

/// Lowercase-hex SHA-256 of `bytes` — used to verify a component's `:aiueos/wasm`
/// artifact matches its declared `:aiueos/wasm-sha256` (tamper detection).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Compile general CLJ/Kotoba source to a wasm module via kototama. Available
/// only with the `kototama` feature; WAT/precompiled components don't need it.
#[cfg(feature = "kototama")]
pub fn compile_source(src: &str) -> Result<Vec<u8>> {
    kototama::compile_clj(src).map_err(crate::error::AiueosError::Compile)
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
