//! The **cloud** deployment surface (ADR-0005): the `storage/kv` (`kv-set` /
//! `kv-get`) and `net/fetch` (`fetch`) providers. Phase-0 keeps them in-process
//! and deterministic — KV is an in-memory map threaded out through the outcome,
//! `fetch` is a URL→response fixture map (no real socket) — but they are gated
//! identically to every other capability, and a component that doesn't hold the
//! cap traps. WAT components exercise the ABI directly: `wasm-runtime`, no kototama.
#![cfg(feature = "wasm-runtime")]

use aiueos::host::{self, CloudSurface, DomSurface, KqeStore, LlmFixtures, TopicAccess};
use aiueos::manifest::Quota;
use aiueos::topic::TopicBus;
use std::collections::BTreeSet;

// kv-set("k", "val") then kv-get("k", buf[64]) -> bytes written.
const KV_ROUNDTRIP: &str = r#"(module
  (import "aiueos:host" "kv-set" (func $set (param i32 i32 i32 i32)))
  (import "aiueos:host" "kv-get" (func $get (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "k")
  (data (i32.const 8) "val")
  (func (export "run") (result i64)
    (call $set (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (i64.extend_i32_s (call $get (i32.const 0) (i32.const 1) (i32.const 64) (i32.const 64)))))"#;

// kv-get of a key that was never set.
const KV_MISS: &str = r#"(module
  (import "aiueos:host" "kv-get" (func $get (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "absent")
  (func (export "run") (result i64)
    (i64.extend_i32_s (call $get (i32.const 0) (i32.const 6) (i32.const 64) (i32.const 64)))))"#;

// fetch("https://api/health", buf[cap=arg]) -> bytes written.
const FETCH: &str = r#"(module
  (import "aiueos:host" "fetch" (func $fetch (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "https://api/health")
  (func (export "run") (param i32) (result i64)
    (i64.extend_i32_s (call $fetch (i32.const 0) (i32.const 18) (i32.const 64) (local.get 0)))))"#;

fn caps(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn run_cloud(
    wat: &str,
    args: &[i64],
    caps: &BTreeSet<String>,
    cloud: CloudSurface,
) -> aiueos::Result<host::HostOutcome> {
    host::run_with_host_restricted_with_kqe_llm_dom_cloud(
        wat.as_bytes(),
        "run",
        args,
        1_000_000,
        4,
        caps,
        TopicBus::new(),
        KqeStore::default(),
        LlmFixtures::default(),
        DomSurface::default(),
        cloud,
        &TopicAccess::unrestricted(),
        Quota::default(),
    )
}

#[test]
fn kv_set_then_get_round_trips_and_threads_out() {
    let o = run_cloud(
        KV_ROUNDTRIP,
        &[],
        &caps(&["storage/kv"]),
        CloudSurface::default(),
    )
    .expect("storage/kv granted");
    assert_eq!(o.result, 3, "kv-get returns the 3 bytes of \"val\"");
    // The mutation is visible in the outcome's cloud state (threadable to the next
    // component in a boot round, like the KQE store).
    assert_eq!(o.cloud.get("k"), Some(&b"val"[..]));
}

#[test]
fn kv_get_missing_key_returns_minus_one() {
    let o = run_cloud(
        KV_MISS,
        &[],
        &caps(&["storage/kv"]),
        CloudSurface::default(),
    )
    .expect("storage/kv granted");
    assert_eq!(o.result, -1, "absent key → -1");
}

#[test]
fn kv_traps_without_capability() {
    assert!(
        run_cloud(KV_MISS, &[], &BTreeSet::new(), CloudSurface::default()).is_err(),
        "kv-get without storage/kv must trap"
    );
}

#[test]
fn fetch_returns_fixture_body_when_granted() {
    let cloud = CloudSurface::with_fetch([("https://api/health", "ok")]);
    let o = run_cloud(FETCH, &[64], &caps(&["net/fetch"]), cloud).expect("net/fetch granted");
    assert_eq!(o.result, 2, "fixture body \"ok\" is 2 bytes");
    assert!(o
        .host_events
        .iter()
        .any(|e| e == "aiueos:host/fetch url=https://api/health bytes=2"));
}

#[test]
fn fetch_without_fixture_returns_minus_one() {
    let o = run_cloud(FETCH, &[64], &caps(&["net/fetch"]), CloudSurface::default())
        .expect("net/fetch granted");
    assert_eq!(o.result, -1, "no fixture for the URL → -1");
}

#[test]
fn fetch_undersized_buffer_returns_minus_two() {
    // cap=1 is smaller than "ok" (2 bytes).
    let cloud = CloudSurface::with_fetch([("https://api/health", "ok")]);
    let o = run_cloud(FETCH, &[1], &caps(&["net/fetch"]), cloud).expect("net/fetch granted");
    assert_eq!(o.result, -2, "buffer too small → -2");
}

#[test]
fn fetch_traps_without_capability() {
    let cloud = CloudSurface::with_fetch([("https://api/health", "ok")]);
    assert!(
        run_cloud(FETCH, &[64], &BTreeSet::new(), cloud).is_err(),
        "fetch without net/fetch must trap"
    );
}
