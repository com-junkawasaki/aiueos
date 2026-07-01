# aiueos

`aiueos` is the Kotoba/CLJC authority layer for a capability-secure component
operating-system model.

The repository defines EDN-first contracts for component manifests, policy
decisions, and audit events. Runtime implementations, native execution, Wasm
engines, VM boot flows, browser adapters, and CLI process management live in
host adapter repositories and consume these contracts.

## Model

```text
kotoba   = meaning, structure, policy, and capability data
aiueos   = CLJC contracts for component OS authority
adapters = host-specific execution that conforms to those contracts
```

The authority layer is deliberately data-only:

- component identity, kind, trust, entry, args, imports, exports, effects, and limits
- grant or deny policy decisions with explicit violation shapes
- append-only audit events that can be emitted by authority or host adapters
- EDN fixtures for systems, browser surfaces, robotics, computer-use, and policy examples

## Source Layout

| path | role |
|---|---|
| `src/aiueos/contract.cljc` | shared CLJC contract and validators |
| `test/aiueos/contract_test.cljc` | conformance tests for the contract |
| `examples/` | EDN/WAT fixtures consumed by adapters and docs |
| `docs/` | architecture notes and migration status |

## Development

Run the authority contract tests:

```bash
clojure -M:test
bb test:cljc
```

## Rust Status

The former Rust crate, Cargo metadata, Rust CLI, and QEMU/Rust smoke scripts have
been removed from this repository. `aiueos` should not contain `Cargo.toml`,
`Cargo.lock`, `.rs`, or Rust toolchain files on the default path.

If a host needs Wasm execution, signing, VM boot, filesystem access, or process
lifecycle management, implement it as an adapter that reads and writes the
CLJC/EDN contracts defined here.
