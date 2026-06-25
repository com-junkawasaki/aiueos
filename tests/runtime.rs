//! Integration tests for the execution seam (feature `wasm-runtime`): the
//! broker-conferred fuel + memory limits must actually be enforced, and the
//! kototama compile path must produce a real, runnable module.
#![cfg(feature = "kototama")]

use aiueos::runtime;

#[test]
fn compiles_and_runs_under_limits() {
    let wasm = runtime::compile_source("(defn main [n] (* n 2))").expect("compiles");
    assert_eq!(&wasm[0..4], b"\0asm", "real wasm magic");
    let r = runtime::run_wasm(&wasm, "main", &[21], 10_000_000, 16).expect("runs");
    assert_eq!(r, 42);
}

#[test]
fn fuel_limit_traps_runaway() {
    // Unbounded self-recursion must be stopped by the fuel budget, not hang the
    // host — capability enforcement, not cooperation.
    let wasm = runtime::compile_source("(defn loopy [n] (loopy n))").expect("compiles");
    let r = runtime::run_wasm(&wasm, "loopy", &[1], 50_000, 16);
    assert!(r.is_err(), "runaway should exhaust fuel / trap");
}

#[test]
fn memory_cap_is_enforced() {
    // Every kototama module exports a linear memory with ≥1 initial page. A
    // zero-page cap must reject instantiation rather than let it allocate.
    let wasm = runtime::compile_source("(defn main [n] (* n 2))").expect("compiles");
    assert!(
        runtime::run_wasm(&wasm, "main", &[21], 10_000_000, 0).is_err(),
        "0-page memory cap must trap the module's initial memory"
    );
    // A generous cap runs fine — proves it's the limit, not the module, failing.
    assert_eq!(
        runtime::run_wasm(&wasm, "main", &[21], 10_000_000, 16).unwrap(),
        42
    );
}

#[test]
fn missing_entry_function_is_a_run_error() {
    let wasm = runtime::compile_source("(defn main [n] n)").expect("compiles");
    assert!(runtime::run_wasm(&wasm, "nonexistent", &[1], 10_000, 16).is_err());
}
