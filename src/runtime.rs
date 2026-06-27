//! The execution seam: compile CLJ/Kotoba → wasm (via kotoba-clj). Execution
//! itself — instantiation under fuel + memory limits, with the broker-mediated
//! `aiueos:host` ABI — lives in [`crate::host`]. This module keeps the compile
//! entry point and a thin `run_wasm` for host-less (pure compute) modules.
//!
//! Feature-gated behind `wasm-runtime` so the semantic core stays dependency-light.

use crate::error::Result;
use crate::host;
#[cfg(feature = "kototama")]
use crate::manifest::Limits;
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
    compile_source_with_policy(src, &kotoba_clj::Policy::deny_all())
}

/// Compile a CLJ/Kotoba source file through kotoba-clj's safe file loader. This
/// preserves `.cljc` reader conditionals and neighboring namespace resolution.
#[cfg(feature = "kototama")]
pub fn compile_source_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    compile_source_file_with_policy(path, &kotoba_clj::Policy::deny_all())
}

/// Compile CLJ/Kotoba source against an explicit kotoba policy. This is the
/// aiueos broker path: verified manifest capabilities become kotoba safe-clj
/// grants before any host import can enter the emitted wasm.
#[cfg(feature = "kototama")]
pub fn compile_source_with_policy(src: &str, policy: &kotoba_clj::Policy) -> Result<Vec<u8>> {
    kotoba_clj::compile_safe_clj_with_prelude(strip_shebang(src), policy)
        .map_err(|e| crate::error::AiueosError::Compile(e.to_string()))
}

/// Compile a CLJ/Kotoba source file against an explicit kotoba policy while
/// retaining file-aware namespace and reader-conditional behavior.
#[cfg(feature = "kototama")]
pub fn compile_source_file_with_policy(
    path: impl AsRef<Path>,
    policy: &kotoba_clj::Policy,
) -> Result<Vec<u8>> {
    let src = kotoba_clj::compat::load_file_graph(path.as_ref(), kotoba_clj::ReaderTarget::Kotoba)
        .map_err(|e| crate::error::AiueosError::Compile(e.to_string()))?;
    kotoba_clj::compile_safe_clj_with_prelude(&src, policy)
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

/// Convert broker-conferred aiueos capabilities into kotoba safe-clj compile
/// grants. Capability names intentionally mirror EDN keyword spelling:
///
/// - `kotoba.graph-read/<cid>`
/// - `kotoba.graph-write/<cid>`
/// - `kotoba.infer/<model>`
/// - `kotoba.auth/self`
///
/// Use `*` as the target for a class-wide grant.
#[cfg(feature = "kototama")]
pub fn kotoba_policy_from_caps(caps: &BTreeSet<String>, limits: Limits) -> kotoba_clj::Policy {
    let clj_limits = kotoba_clj::Limits {
        memory_pages: limits.memory_pages,
        fuel: limits.fuel,
        ..kotoba_clj::Limits::defaults()
    };
    let mut policy = kotoba_clj::Policy::deny_all().with_limits(clj_limits);

    let graph_read = cap_targets(caps, "kotoba.graph-read/");
    if !graph_read.is_empty() {
        policy = policy.grant_graph_read(graph_read);
    }

    let graph_write = cap_targets(caps, "kotoba.graph-write/");
    if !graph_write.is_empty() {
        policy = policy.grant_graph_write(graph_write);
    }

    let infer = cap_targets(caps, "kotoba.infer/");
    if !infer.is_empty() {
        policy = policy.grant_infer(infer);
    }

    if caps.contains("kotoba.auth/self") || caps.contains("kotoba.auth/*") {
        policy = policy.grant_auth();
    }

    policy
}

#[cfg(feature = "kototama")]
fn cap_targets(caps: &BTreeSet<String>, prefix: &str) -> Vec<String> {
    caps.iter()
        .filter_map(|cap| cap.strip_prefix(prefix))
        .filter(|target| !target.is_empty())
        .map(str::to_string)
        .collect()
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
