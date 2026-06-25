//! End-to-end coverage of the `aiue` binary: argument handling, exit codes, and
//! the commands that don't need the wasm runtime (help, unknown, check, audit,
//! verify). Drives the real built binary via `CARGO_BIN_EXE_aiueos`.

use std::path::PathBuf;
use std::process::Command;

/// Run the `aiue` binary with `args`; return (exit code, stdout, stderr).
fn aiue(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_aiueos"))
        .args(args)
        .output()
        .expect("spawn aiue");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("aiueos-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn write(name: &str, contents: &str) -> PathBuf {
    let p = scratch(name);
    std::fs::write(&p, contents).unwrap();
    p
}

// ---------------------------------------------------------------------------
// usage / dispatch
// ---------------------------------------------------------------------------

#[test]
fn no_args_prints_usage_and_exits_zero() {
    let (code, _out, err) = aiue(&[]);
    assert_eq!(code, 0);
    assert!(err.contains("USAGE"), "usage shown on stderr");
}

#[test]
fn help_exits_zero() {
    for flag in ["help", "-h", "--help"] {
        let (code, _o, _e) = aiue(&[flag]);
        assert_eq!(code, 0, "`aiue {flag}` exits 0");
    }
}

#[test]
fn unknown_command_exits_two() {
    let (code, _out, err) = aiue(&["wibble"]);
    assert_eq!(code, 2, "unknown command → exit 2");
    assert!(err.contains("unknown command"));
}

// ---------------------------------------------------------------------------
// check — safe-kotoba subset gate
// ---------------------------------------------------------------------------

#[test]
fn check_accepts_safe_source() {
    let p = write("ok.clj", "(defn f [n] (+ n 1))");
    let (code, out, _e) = aiue(&["check", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("safe-kotoba subset"));
}

#[test]
fn check_rejects_unsafe_source() {
    let p = write("bad.clj", r#"(defn f [] (slurp "/etc/passwd"))"#);
    let (code, _out, err) = aiue(&["check", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("slurp"));
}

#[test]
fn check_without_file_arg_errors() {
    let (code, _out, _err) = aiue(&["check"]);
    assert_eq!(code, 1);
}

// ---------------------------------------------------------------------------
// audit — replay
// ---------------------------------------------------------------------------

#[test]
fn audit_missing_log_reports_empty_and_exits_zero() {
    let p = scratch("nonexistent-audit.edn");
    let _ = std::fs::remove_file(&p);
    let (code, out, _e) = aiue(&["audit", "--log", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("no audit entries"));
}

#[test]
fn audit_replays_a_populated_log() {
    // `verify` writes a grant entry to <manifest-dir>/.aiue/audit.edn; replay it
    // and check the populated-log formatting (header + ts/event/component/detail).
    let manifest = write(
        "auditme.edn",
        "{:aiue/component :app/auditme :aiue/kind :app :aiue/imports #{:log/write}}",
    );
    let log = scratch(".aiue/audit.edn");
    let _ = std::fs::remove_file(&log);
    let (vc, _o, _e) = aiue(&["verify", manifest.to_str().unwrap()]);
    assert_eq!(vc, 0, "verify writes an audit entry");

    let (code, out, _e) = aiue(&["audit", "--log", log.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("entries"), "header with entry count");
    assert!(out.contains("grant"), "the grant event is rendered");
    assert!(out.contains("app/auditme"), "the component id is rendered");
    let _ = std::fs::remove_file(&log);
}

// ---------------------------------------------------------------------------
// verify — capability + policy check on a single manifest (no wasm needed)
// ---------------------------------------------------------------------------

#[test]
fn verify_clean_manifest_passes() {
    // imports only a kernel-provided capability → resolves with the default policy.
    let p = write(
        "ok.edn",
        "{:aiue/component :app/ok :aiue/kind :app :aiue/imports #{:log/write}}",
    );
    let (code, out, _err) = aiue(&["verify", p.to_str().unwrap()]);
    assert_eq!(code, 0, "clean manifest verifies");
    assert!(out.contains("verified"));
}

#[test]
fn verify_unresolved_import_is_denied() {
    let p = write(
        "lonely.edn",
        "{:aiue/component :app/lonely :aiue/kind :app :aiue/imports #{:gpu/render}}",
    );
    let (code, _out, err) = aiue(&["verify", p.to_str().unwrap()]);
    assert_eq!(code, 1, "unresolved import → denied");
    assert!(err.contains("unresolved-capability"));
}

// ---------------------------------------------------------------------------
// inspect — pure (no wasm), reads the bundled example system
// ---------------------------------------------------------------------------

#[test]
fn inspect_prints_the_capability_graph() {
    // Integration tests run with cwd = crate root, so the examples are present.
    let (code, out, _e) = aiue(&[
        "inspect",
        "examples/system.aiue.edn",
        "--policy",
        "examples/policy/default.edn",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("capability graph"));
    assert!(out.contains("driver/virtio-blk"));
    assert!(out.contains("log/write"));
}

#[test]
fn inspect_renders_policy_violations() {
    // No --policy → default policy grants no IOMMU → the driver's DMA is denied.
    // inspect reports (it doesn't gate), so it still exits 0 but shows the ✗ line.
    let (code, out, _e) = aiue(&["inspect", "examples/system.aiue.edn"]);
    assert_eq!(code, 0, "inspect reports rather than gating");
    assert!(
        out.contains("dma-without-iommu"),
        "the violation kind is rendered"
    );
    assert!(out.contains("driver/virtio-blk"));
}

// ---------------------------------------------------------------------------
// up / run — full boot + launch (need the wasm runtime, gated to match the
// binary's own feature set so `--no-default-features` stays consistent).
// ---------------------------------------------------------------------------

#[cfg(feature = "kototama")]
#[test]
fn up_boots_the_example_system_with_policy() {
    let (code, out, _e) = aiue(&[
        "up",
        "examples/system.aiue.edn",
        "--policy",
        "examples/policy/default.edn",
    ]);
    assert_eq!(code, 0, "boots with the iommu policy");
    assert!(out.contains("system up"));
    assert!(out.contains("4/4"));
}

#[cfg(feature = "kototama")]
#[test]
fn up_without_policy_aborts_on_dma_denial() {
    let (code, _out, err) = aiue(&["up", "examples/system.aiue.edn"]);
    assert_eq!(code, 1, "no iommu grant → boot aborts");
    assert!(err.contains("dma-without-iommu"));
}

#[cfg(feature = "kototama")]
#[test]
fn run_app_compiles_and_executes_to_42() {
    let (code, out, _e) = aiue(&[
        "run",
        "examples/apps/notes.edn",
        "--system",
        "examples/system.aiue.edn",
        "--policy",
        "examples/policy/default.edn",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("= 42"));
}

// ---------------------------------------------------------------------------
// compile — CLJ/manifest → wasm (wasm-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "kototama")]
#[test]
fn compile_clj_writes_wasm_next_to_source() {
    let p = write("comp_src.clj", "(defn main [n] (+ n 1))");
    let wasm = p.with_extension("wasm");
    let _ = std::fs::remove_file(&wasm);
    let (code, out, _e) = aiue(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("compiled"));
    let bytes = std::fs::read(&wasm).expect("wasm written next to source");
    assert_eq!(&bytes[0..4], b"\0asm", "real wasm magic");
    let _ = std::fs::remove_file(&wasm);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_honors_output_flag() {
    let p = write("comp_src2.clj", "(defn main [n] n)");
    let out_path = scratch("custom_out.wasm");
    let _ = std::fs::remove_file(&out_path);
    let (code, _o, _e) = aiue(&["compile", p.to_str().unwrap(), "-o", out_path.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out_path.exists(), "wasm written to the -o path");
    let _ = std::fs::remove_file(&out_path);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_rejects_unsafe_source_before_emitting() {
    let p = write("comp_bad.clj", r#"(defn f [] (slurp "x"))"#);
    let wasm = p.with_extension("wasm");
    let _ = std::fs::remove_file(&wasm);
    let (code, _o, err) = aiue(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("slurp"));
    assert!(!wasm.exists(), "no wasm emitted when the source is rejected");
}

#[cfg(feature = "kototama")]
#[test]
fn compile_manifest_reads_its_source() {
    let dir = std::env::temp_dir().join("aiueos-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("m_src.clj"), "(defn main [n] (* n 3))").unwrap();
    let manifest = dir.join("m.edn");
    std::fs::write(
        &manifest,
        r#"{:aiue/component :app/m :aiue/kind :app :aiue/source "m_src.clj"}"#,
    )
    .unwrap();
    let outp = dir.join("m_out.wasm");
    let _ = std::fs::remove_file(&outp);
    let (code, _o, _e) = aiue(&[
        "compile",
        manifest.to_str().unwrap(),
        "-o",
        outp.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "manifest's :aiue/source is compiled");
    assert!(outp.exists());
    let _ = std::fs::remove_file(&outp);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_manifest_without_source_errors() {
    let p = write("nosrc.edn", "{:aiue/component :app/n :aiue/kind :app}");
    let (code, _o, _e) = aiue(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 1, "manifest with no :aiue/source cannot compile");
}
