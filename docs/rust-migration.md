# Rust Migration

`aiueos` no longer carries a Rust crate or Cargo workspace. The repository is now
the Kotoba/CLJC semantic authority for component manifests, capability policy
decisions, audit events, and the EDN shapes that host adapters must consume.

## Removed Rust Surface

| module | role | target |
|---|---|---|
| `Cargo.toml` / `Cargo.lock` | Rust package metadata | removed |
| `src/*.rs` | Rust manifest, graph, policy, broker, host, runtime modules | removed |
| `src/bin/aiueos.rs` | Rust CLI entry point | removed |
| `tests/*.rs` | Cargo integration tests | removed |
| `scripts/*.bb` | QEMU/Rust binary smoke helpers | removed |

## Current Authority

Authoritative:

- manifest schema contract
- policy decision contract
- audit event schema
- shared EDN examples and fixtures

Host adapter only:

- Wasm execution
- artifact hash calculation
- ed25519 verification implementation
- filesystem, VM, browser, and CLI execution
- native process lifecycle

## CLJC Authority

`src/aiueos/contract.cljc` now defines the first pure CLJC contract for the
shared authority layer: validators for a minimal component manifest, policy
decision, and audit event. The contract is intentionally data-only so Rust,
Kotoba, and other host adapters can conform to the same EDN shapes outside this
repository.

## Policy

1. No `Cargo.toml`, `Cargo.lock`, `.rs`, or Rust toolchain files in the default
   authority repository.
2. Runtime backends live in separate host adapter repositories and consume these
   CLJC/EDN contracts.
3. CI validates the CLJC contract with `clojure -M:test` and `bb test:cljc`.
