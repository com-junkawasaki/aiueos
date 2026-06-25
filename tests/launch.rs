//! Coverage for `Broker::launch` (the single-component path behind `aiue run`)
//! with host-importing WAT components and its `:aiue/wasm` error handling:
//! a missing file, malformed bytes, and a host call the component never imported.
//! Exec-only (WAT) — no kototama.
#![cfg(feature = "wasm-runtime")]

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::error::AiueError;
use aiueos::graph::CapabilityGraph;
use aiueos::manifest::Manifest;
use aiueos::policy::Policy;
use std::path::{Path, PathBuf};

fn broker() -> Broker {
    Broker::new(
        Policy::default(),
        AuditLog::new(std::env::temp_dir().join("aiueos-launch-test.edn")),
    )
}

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join("aiueos-launch-test");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn launch_in(dir: &Path, manifest: &str) -> aiueos::Result<i64> {
    let m = Manifest::load(&dir.join(manifest)).unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&m));
    broker().launch(&m, dir, &g)
}

#[test]
fn launch_runs_a_host_importing_component_with_a_fresh_bus() {
    // The example sensor imports :topic/publish (a kernel cap) → its grant lets
    // the publish through; launch runs it on a fresh bus and returns the reading.
    let m = Manifest::load(Path::new("examples/robot/sensor.edn")).expect("loads");
    let g = CapabilityGraph::build(std::slice::from_ref(&m));
    let r = broker()
        .launch(&m, Path::new("examples/robot"), &g)
        .expect("sensor launches");
    assert_eq!(r, 21);
}

#[test]
fn launch_traps_host_call_without_the_imported_capability() {
    // Publishes, but the manifest imports nothing → empty grant → publish traps.
    let dir = tmpdir();
    std::fs::write(
        dir.join("rogue.wat"),
        r#"(module
          (import "aiue:host" "publish" (func $p (param i32 i64)))
          (func (export "tick") (param i64) (result i64)
            (call $p (i32.const 1) (local.get 0))
            (local.get 0)))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("rogue.edn"),
        r#"{:aiue/component :driver/rogue :aiue/kind :driver
            :aiue/wasm "rogue.wat" :aiue/entry "tick" :aiue/args [5]}"#,
    )
    .unwrap();
    assert!(matches!(launch_in(&dir, "rogue.edn"), Err(AiueError::Run(_))));
}

#[test]
fn malformed_wasm_is_a_clean_run_error() {
    let dir = tmpdir();
    std::fs::write(dir.join("garbage.wat"), "this is not wasm or wat (((").unwrap();
    std::fs::write(
        dir.join("garbage.edn"),
        r#"{:aiue/component :app/garbage :aiue/kind :app
            :aiue/wasm "garbage.wat" :aiue/entry "main"}"#,
    )
    .unwrap();
    // Parse failure surfaces as a clean Run error, not a panic.
    assert!(matches!(launch_in(&dir, "garbage.edn"), Err(AiueError::Run(_))));
}

#[test]
fn missing_wasm_file_is_an_io_error() {
    let dir = tmpdir();
    std::fs::write(
        dir.join("ghost.edn"),
        r#"{:aiue/component :app/ghost :aiue/kind :app
            :aiue/wasm "nope.wat" :aiue/entry "main"}"#,
    )
    .unwrap();
    assert!(matches!(launch_in(&dir, "ghost.edn"), Err(AiueError::Io(_))));
}
