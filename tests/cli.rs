//! End-to-end coverage of the `aiueos` binary: argument handling, exit codes, and
//! the commands that don't need the wasm runtime (help, unknown, check, audit,
//! verify). Drives the real built binary via `CARGO_BIN_EXE_aiueos`.

use std::path::PathBuf;
use std::process::Command;

/// Run the `aiueos` binary with `args`; return (exit code, stdout, stderr).
fn aiueos(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_aiueos"))
        .args(args)
        .output()
        .expect("spawn aiueos");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn scratch_dir(name: &str) -> PathBuf {
    let tid = format!("{:?}", std::thread::current().id())
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let dir = std::env::temp_dir()
        .join("aiueos-cli-test")
        .join(format!("{}-{tid}", std::process::id()))
        .join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn scratch(name: &str) -> PathBuf {
    let dir = scratch_dir("default");
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
    let (code, _out, err) = aiueos(&[]);
    assert_eq!(code, 0);
    assert!(err.contains("USAGE"), "usage shown on stderr");
}

#[test]
fn help_exits_zero() {
    for flag in ["help", "-h", "--help"] {
        let (code, _out, err) = aiueos(&[flag]);
        assert_eq!(code, 0, "`aiueos {flag}` exits 0");
        assert!(
            err.contains("--kqe-store")
                && err.contains("--llm-fixture")
                && err.contains("aiueos image build")
                && err.contains("aiueos vm up"),
            "`aiueos {flag}` documents KQE/LLM fixture and VM flags: {err}"
        );
    }
}

#[test]
fn unknown_command_exits_two() {
    let (code, _out, err) = aiueos(&["wibble"]);
    assert_eq!(code, 2, "unknown command → exit 2");
    assert!(err.contains("unknown command"));
}

#[test]
fn surface_inspect_reports_every_provider_import() {
    let (code, out, err) = aiueos(&["surface", "inspect", "robot"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("topic/subscribe  ⇐  aiueos:host/poll"));
    assert!(out.contains("topic/subscribe  ⇐  aiueos:host/take"));
    assert!(out.contains("topic/subscribe  ⇐  aiueos:host/count"));
    let (code, out, err) = aiueos(&["surface", "inspect", "browser"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("input/event  ⇐  aiueos:host/input-event"));

    let (code, out, err) = aiueos(&["surface", "inspect", "cloud", "--edn"]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid surface EDN");
    let offered = aiueos::edn::get(&v, "aiueos", "offered").expect("offered vector");
    let rendered = kotoba_edn::to_string(offered);
    assert!(
        rendered.contains("\"kv-set\""),
        "kv-set provider present: {rendered}"
    );
    assert!(
        rendered.contains("\"kv-get\""),
        "kv-get provider present: {rendered}"
    );
}

#[test]
fn vm_up_dry_run_generates_a_lima_plan_after_verification() {
    let dir = scratch_dir("vmplan");
    let system = dir.join("system.aiueos.edn");
    std::fs::write(
        &system,
        r#"{:aiueos/system :vm-demo
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/vm-demo
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "vm",
        "up",
        system.to_str().unwrap(),
        "--provider",
        "lima",
        "--dry-run",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("provider: lima"), "prints provider: {out}");
    assert!(out.contains("limactl start"), "prints start command: {out}");
    assert!(out.contains("limactl shell"), "prints run command: {out}");
    let config = dir.join(".aiueos/vm/aiueos-vm-demo.lima.yaml");
    let yaml = std::fs::read_to_string(config).expect("vm config generated");
    assert!(
        yaml.contains("mountPoint: /workspace")
            && yaml.contains("mountPoint: /aiueos-input")
            && yaml.contains("cargo run --quiet -- up '/aiueos-input/system.aiueos.edn'"),
        "lima yaml mounts repo and runs aiueos: {yaml}"
    );
}

#[test]
fn vm_up_edn_reports_machine_readable_plan() {
    let dir = scratch_dir("vmedn");
    let system = dir.join("system.aiueos.edn");
    std::fs::write(
        &system,
        r#"{:aiueos/system :vm-edn
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/vm-edn
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "vm",
        "up",
        system.to_str().unwrap(),
        "--provider",
        "lima",
        "--edn",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid vm plan EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "vm-provider").and_then(|x| x.as_string()),
        Some("lima")
    );
    assert!(aiueos::edn::get(&v, "aiueos", "start")
        .and_then(|x| x.as_string())
        .is_some_and(|s| s.contains("limactl start")));
}

#[test]
fn image_build_dry_run_plans_minimal_initramfs() {
    let dir = scratch_dir("imageplan");
    let system = dir.join("system.aiueos.edn");
    std::fs::write(
        &system,
        r#"{:aiueos/system :image-demo
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/image-demo
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&["image", "build", system.to_str().unwrap(), "--dry-run"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("initramfs"), "prints initramfs path: {out}");
    assert!(
        out.contains("guest system: /etc/aiueos/system/system.aiueos.edn"),
        "prints guest system path: {out}"
    );
}

#[test]
fn image_build_edn_reports_machine_readable_plan() {
    let dir = scratch_dir("imageedn");
    let system = dir.join("system.aiueos.edn");
    std::fs::write(
        &system,
        r#"{:aiueos/system :image-edn
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/image-edn
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&["image", "build", system.to_str().unwrap(), "--edn"]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid image plan EDN");
    assert!(aiueos::edn::get(&v, "aiueos", "image")
        .and_then(|x| x.as_string())
        .is_some_and(|s| s.ends_with(".initramfs.cpio.gz")));
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "guest-system").and_then(|x| x.as_string()),
        Some("/etc/aiueos/system/system.aiueos.edn")
    );
}

#[test]
fn vm_boot_dry_run_uses_kernel_and_initramfs_without_distro_rootfs() {
    let dir = scratch_dir("vmboot");
    let system = dir.join("system.aiueos.edn");
    let kernel = dir.join("Image");
    std::fs::write(&kernel, "not-a-real-kernel").unwrap();
    std::fs::write(
        &system,
        r#"{:aiueos/system :boot-demo
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/boot-demo
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "vm",
        "boot",
        system.to_str().unwrap(),
        "--kernel",
        kernel.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        out.contains("qemu-system-aarch64"),
        "prints qemu command: {out}"
    );
    assert!(out.contains("-initrd"), "uses initramfs: {out}");
    assert!(out.contains("rdinit=/init"), "boots /init directly: {out}");
}

#[test]
fn vm_boot_dry_run_can_request_virtio_gpu_graphics() {
    let dir = scratch_dir("vmbootgui");
    let system = dir.join("system.aiueos.edn");
    let kernel = dir.join("Image");
    std::fs::write(&kernel, "not-a-real-kernel").unwrap();
    std::fs::write(
        &system,
        r#"{:aiueos/system :boot-gui-demo
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/boot-gui-demo
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "vm",
        "boot",
        system.to_str().unwrap(),
        "--kernel",
        kernel.to_str().unwrap(),
        "--graphics",
        "virtio-gpu",
        "--display",
        "cocoa",
        "--dry-run",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        out.contains("graphics: virtio-gpu"),
        "prints graphics: {out}"
    );
    assert!(out.contains("display: cocoa"), "prints display: {out}");
    assert!(
        out.contains("-device virtio-gpu-pci") && out.contains("-display 'cocoa'"),
        "qemu command exposes virtio-gpu: {out}"
    );
    assert!(
        !out.contains("-nographic"),
        "graphics mode must not keep -nographic: {out}"
    );
}

#[test]
fn vm_boot_dry_run_can_attach_virtio_blk_backing_file() {
    let dir = scratch_dir("vmbootblk");
    let system = dir.join("system.aiueos.edn");
    let kernel = dir.join("Image");
    let block = dir.join("block.raw");
    std::fs::write(&kernel, "not-a-real-kernel").unwrap();
    std::fs::write(&block, vec![0u8; 1024]).unwrap();
    std::fs::write(
        &system,
        r#"{:aiueos/system :boot-blk-demo
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/boot-blk-demo
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "vm",
        "boot",
        system.to_str().unwrap(),
        "--kernel",
        kernel.to_str().unwrap(),
        "--block",
        block.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("block:"), "prints block path: {out}");
    assert!(out.contains("-drive"), "qemu command has drive: {out}");
    assert!(
        out.contains("virtio-blk-pci,drive=aiueosblk"),
        "qemu command exposes virtio-blk: {out}"
    );
}

#[test]
fn vm_boot_dry_run_can_expose_virtio_console() {
    let dir = scratch_dir("vmbootconsole");
    let system = dir.join("system.aiueos.edn");
    let kernel = dir.join("Image");
    let socket = dir.join("aiueos-console.sock");
    std::fs::write(&kernel, "not-a-real-kernel").unwrap();
    std::fs::write(
        &system,
        r#"{:aiueos/system :boot-console-demo
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/boot-console-demo
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "vm",
        "boot",
        system.to_str().unwrap(),
        "--kernel",
        kernel.to_str().unwrap(),
        "--console",
        "virtio-console",
        "--console-socket",
        socket.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        out.contains("console: virtio-console"),
        "prints console mode: {out}"
    );
    assert!(
        out.contains("console-socket:"),
        "prints console socket path: {out}"
    );
    assert!(
        out.contains("-device virtio-serial-pci")
            && out.contains("virtconsole,chardev=aiueoscon,name=aiueos.console.0"),
        "qemu command exposes virtio-console: {out}"
    );
}

#[test]
fn vm_boot_edn_reports_virtio_gpu_graphics() {
    let dir = scratch_dir("vmbootguiedn");
    let system = dir.join("system.aiueos.edn");
    let kernel = dir.join("Image");
    std::fs::write(&kernel, "not-a-real-kernel").unwrap();
    std::fs::write(
        &system,
        r#"{:aiueos/system :boot-gui-edn
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/boot-gui-edn
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "vm",
        "boot",
        system.to_str().unwrap(),
        "--kernel",
        kernel.to_str().unwrap(),
        "--graphics",
        "virtio-gpu",
        "--edn",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid vm boot EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "graphics").and_then(|x| x.as_string()),
        Some("virtio-gpu")
    );
    assert!(aiueos::edn::get(&v, "aiueos", "qemu")
        .and_then(|x| x.as_string())
        .is_some_and(|s| s.contains("-device virtio-gpu-pci")));
}

#[test]
fn vm_boot_edn_reports_virtio_console() {
    let dir = scratch_dir("vmbootconsoleedn");
    let system = dir.join("system.aiueos.edn");
    let kernel = dir.join("Image");
    let socket = dir.join("aiueos-console.sock");
    std::fs::write(&kernel, "not-a-real-kernel").unwrap();
    std::fs::write(
        &system,
        r#"{:aiueos/system :boot-console-edn
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/boot-console-edn
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "vm",
        "boot",
        system.to_str().unwrap(),
        "--kernel",
        kernel.to_str().unwrap(),
        "--console",
        "virtio-console",
        "--console-socket",
        socket.to_str().unwrap(),
        "--edn",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid vm boot EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "console").and_then(|x| x.as_string()),
        Some("virtio-console")
    );
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "console-socket").and_then(|x| x.as_string()),
        Some(socket.to_str().unwrap())
    );
    assert!(aiueos::edn::get(&v, "aiueos", "qemu")
        .and_then(|x| x.as_string())
        .is_some_and(|s| s.contains("virtconsole,chardev=aiueoscon")));
}

#[test]
fn vm_boot_edn_reports_virtio_blk_backing_file() {
    let dir = scratch_dir("vmbootbl kedn");
    let system = dir.join("system.aiueos.edn");
    let kernel = dir.join("Image");
    let block = dir.join("block.raw");
    std::fs::write(&kernel, "not-a-real-kernel").unwrap();
    std::fs::write(&block, vec![0u8; 1024]).unwrap();
    std::fs::write(
        &system,
        r#"{:aiueos/system :boot-blk-edn
            :aiueos/components ["app.edn"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app.edn"),
        r#"{:aiueos/component :app/boot-blk-edn
            :aiueos/kind :app
            :aiueos/wasm "app.wat"
            :aiueos/exports #{:log/write}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "vm",
        "boot",
        system.to_str().unwrap(),
        "--kernel",
        kernel.to_str().unwrap(),
        "--block",
        block.to_str().unwrap(),
        "--edn",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid vm boot EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "block").and_then(|x| x.as_string()),
        Some(block.to_str().unwrap())
    );
    assert!(aiueos::edn::get(&v, "aiueos", "qemu")
        .and_then(|x| x.as_string())
        .is_some_and(|s| s.contains("virtio-blk-pci,drive=aiueosblk")));
}

// ---------------------------------------------------------------------------
// check — safe-kotoba subset gate
// ---------------------------------------------------------------------------

#[test]
fn check_accepts_safe_source() {
    let p = write("ok.clj", "(defn f [n] (+ n 1))");
    let (code, out, _e) = aiueos(&["check", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("safe-kotoba subset"));
}

#[test]
fn check_rejects_unsafe_source() {
    let p = write("bad.clj", r#"(defn f [] (slurp "/etc/passwd"))"#);
    let (code, _out, err) = aiueos(&["check", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("slurp"));
}

#[test]
fn check_without_file_arg_errors() {
    let (code, _out, _err) = aiueos(&["check"]);
    assert_eq!(code, 1);
}

// ---------------------------------------------------------------------------
// audit — replay
// ---------------------------------------------------------------------------

#[test]
fn audit_missing_log_reports_empty_and_exits_zero() {
    let p = scratch("nonexistent-audit.edn");
    let _ = std::fs::remove_file(&p);
    let (code, out, _e) = aiueos(&["audit", "--log", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("no audit entries"));
}

#[test]
fn audit_replays_a_populated_log() {
    // `verify` writes a grant entry to <manifest-dir>/.aiueos/audit.edn; replay it
    // and check the populated-log formatting (header + ts/event/component/detail).
    // ISOLATED dir so a parallel test can't truncate the shared audit log mid-test.
    let dir = scratch_dir("auditreplay");
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = dir.join("auditme.edn");
    std::fs::write(
        &manifest,
        "{:aiueos/component :app/auditme :aiueos/kind :app :aiueos/imports #{:log/write}}",
    )
    .unwrap();
    let log = dir.join(".aiueos/audit.edn");
    let _ = std::fs::remove_file(&log);
    let (vc, _o, _e) = aiueos(&["verify", manifest.to_str().unwrap()]);
    assert_eq!(vc, 0, "verify writes an audit entry");

    let (code, out, _e) = aiueos(&["audit", "--log", log.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("entries"), "header with entry count");
    assert!(out.contains("grant"), "the grant event is rendered");
    assert!(out.contains("app/auditme"), "the component id is rendered");
    let _ = std::fs::remove_file(&log);
}

#[test]
fn audit_edn_on_empty_log_is_an_empty_vector() {
    // An agent consuming --edn must get parseable EDN even when there's nothing —
    // an empty vector, not a human "(no audit entries)" line or an error.
    let p = scratch("nonexistent-audit-edn.edn");
    let _ = std::fs::remove_file(&p);
    let (code, out, _e) = aiueos(&["audit", "--log", p.to_str().unwrap(), "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN even when empty");
    assert_eq!(v.as_vector().map(|x| x.len()), Some(0), "empty log → []");
}

#[test]
fn audit_filters_by_event_and_emits_edn() {
    // Use an ISOLATED dir so verify's audit log isn't shared with other tests
    // (the negative filters below rely on the log containing only our entries).
    let dir = scratch_dir("auditfilter");
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = dir.join("filterme.edn");
    std::fs::write(
        &manifest,
        "{:aiueos/component :app/filterme :aiueos/kind :app :aiueos/imports #{:log/write}}",
    )
    .unwrap();
    let log = dir.join(".aiueos/audit.edn");
    let _ = std::fs::remove_file(&log);
    let (_c, _o, _e) = aiueos(&["verify", manifest.to_str().unwrap()]);

    // --event grant → only grant entries; --edn → an EDN vector.
    let (code, out, _e) = aiueos(&[
        "audit",
        "--log",
        log.to_str().unwrap(),
        "--event",
        "grant",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("filtered log is valid EDN");
    let items = v.as_vector().expect("a vector");
    assert!(!items.is_empty(), "at least one grant");
    assert!(
        items
            .iter()
            .all(|e| aiueos::edn::get_kw(e, "aiueos", "event").as_deref() == Some("grant")),
        "every entry matches the event filter"
    );

    // --event deny → no matches for this clean component.
    let (code, out, _e) = aiueos(&["audit", "--log", log.to_str().unwrap(), "--event", "deny"]);
    assert_eq!(code, 0);
    assert!(out.contains("no audit entries"));

    // --component matches the one we ran; a different id → no matches.
    let (code, out, _e) = aiueos(&[
        "audit",
        "--log",
        log.to_str().unwrap(),
        "--component",
        "app/filterme",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("app/filterme"));
    let (code, out, _e) = aiueos(&[
        "audit",
        "--log",
        log.to_str().unwrap(),
        "--component",
        "app/nobody",
    ]);
    assert_eq!(code, 0);
    assert!(
        out.contains("no audit entries"),
        "unknown component → no matches"
    );
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
        "{:aiueos/component :app/ok :aiueos/kind :app :aiueos/imports #{:log/write}}",
    );
    let (code, out, _err) = aiueos(&["verify", p.to_str().unwrap()]);
    assert_eq!(code, 0, "clean manifest verifies");
    assert!(out.contains("verified"));
}

#[test]
fn verify_unresolved_import_is_denied() {
    let p = write(
        "lonely.edn",
        "{:aiueos/component :app/lonely :aiueos/kind :app :aiueos/imports #{:gpu/render}}",
    );
    let (code, _out, err) = aiueos(&["verify", p.to_str().unwrap()]);
    assert_eq!(code, 1, "unresolved import → denied");
    assert!(err.contains("unresolved-capability"));
}

#[test]
fn verify_accepts_flags_before_the_path() {
    // `--policy <val>` before the target must not be mistaken for the target.
    let (code, out, _e) = aiueos(&[
        "verify",
        "--policy",
        "examples/policy/default.edn",
        "examples/system.aiueos.edn",
    ]);
    assert_eq!(
        code, 0,
        "policy-before-path applies the policy to the system"
    );
    assert!(out.contains("verified"));
}

#[test]
fn verify_edn_reports_structural_errors_as_edn() {
    // A missing file in --edn mode → EDN error on stdout (not human stderr), exit 1.
    let (code, out, _e) = aiueos(&["verify", "/no/such/system.aiueos.edn", "--edn"]);
    assert_eq!(code, 1);
    let v = kotoba_edn::parse(out.trim()).expect("error is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "kind")
            .and_then(|x| x.as_keyword().map(|k| k.name().to_string())),
        Some("io".to_string())
    );
    assert!(aiueos::edn::get(&v, "aiueos", "error").is_some());
}

#[test]
fn verify_edn_emits_machine_readable_verdict() {
    // pass: with the IOMMU policy → verified true, output is valid EDN.
    let (code, out, _e) = aiueos(&[
        "verify",
        "examples/system.aiueos.edn",
        "--policy",
        "examples/policy/default.edn",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("verdict is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "verified").and_then(|x| x.as_bool()),
        Some(true)
    );
    assert!(aiueos::edn::get(&v, "aiueos", "grants").is_some());

    // deny: no policy → verified false + violations, exit 1, still valid EDN.
    let (code, out, _e) = aiueos(&["verify", "examples/system.aiueos.edn", "--edn"]);
    assert_eq!(code, 1, "denial → exit 1 even in --edn mode");
    let v = kotoba_edn::parse(out.trim()).expect("denial verdict is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "verified").and_then(|x| x.as_bool()),
        Some(false)
    );
    assert!(aiueos::edn::get(&v, "aiueos", "violations").is_some());
}

// ---------------------------------------------------------------------------
// inspect — pure (no wasm), reads the bundled example system
// ---------------------------------------------------------------------------

#[test]
fn inspect_prints_the_capability_graph() {
    // Integration tests run with cwd = crate root, so the examples are present.
    let (code, out, _e) = aiueos(&[
        "inspect",
        "examples/system.aiueos.edn",
        "--policy",
        "examples/policy/default.edn",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("capability graph"));
    assert!(out.contains("driver/virtio-blk"));
    assert!(out.contains("log/write"));
    // the driver's device binding is surfaced
    assert!(out.contains("device: bus=pci"));
    assert!(out.contains("0x1af4:0x1001"));
}

#[test]
fn inspect_empty_graph_reports_no_capabilities() {
    // A system whose components export nothing → the capability graph is empty.
    write(
        "noexports.edn",
        "{:aiueos/component :app/q :aiueos/kind :app}",
    );
    let sys = write(
        "emptysys.aiueos.edn",
        r#"{:aiueos/system :empty :aiueos/components ["noexports.edn"]}"#,
    );
    let (code, out, _e) = aiueos(&["inspect", sys.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("no exported capabilities"));
}

#[test]
fn inspect_edn_emits_structured_snapshot() {
    let (code, out, _e) = aiueos(&["inspect", "examples/system.aiueos.edn", "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("snapshot is valid EDN");
    // top-level shape: system + components + graph + verdicts
    assert!(aiueos::edn::get(&v, "aiueos", "system").is_some());
    assert!(aiueos::edn::get(&v, "aiueos", "components").is_some());
    assert!(aiueos::edn::get(&v, "aiueos", "graph").is_some());
    assert!(aiueos::edn::get(&v, "aiueos", "verdicts").is_some());
}

#[test]
fn inspect_on_a_single_manifest_gives_a_helpful_error() {
    // A single component manifest isn't a system graph — inspect should say so
    // (and point at `verify`), not emit a cryptic ":aiueos/components" error.
    let p = write("single.edn", "{:aiueos/component :app/x :aiueos/kind :app}");
    let (code, _out, err) = aiueos(&["inspect", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("system graph") && err.contains("verify"));
}

#[test]
fn inspect_dot_renders_the_robot_topic_dataflow() {
    // Named topics ARE capability-graph edges, so --dot draws the actual
    // sensor → planner → actuator pipeline (the boot-order dataflow).
    let (code, out, _e) = aiueos(&["inspect", "examples/robot/robot.aiueos.edn", "--dot"]);
    assert_eq!(code, 0);
    assert!(out.contains(r#""driver/sensor" -> "agent/planner""#));
    assert!(out.contains(r#""agent/planner" -> "driver/actuator""#));
    assert!(out.contains("topic/scan") && out.contains("topic/cmd"));
}

#[test]
fn inspect_human_shows_topic_confinement() {
    // The robot nodes derive publishes/subscribes — the human view shows them
    // like it shows device bindings.
    let (code, out, _e) = aiueos(&["inspect", "examples/robot/robot.aiueos.edn"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("topics: pub["),
        "per-component topic confinement shown"
    );
}

#[test]
fn inspect_edn_includes_per_topic_isolation() {
    // The robot components declare/derive publishes/subscribes — inspect --edn
    // should expose them so an agent sees the topic confinement.
    let (code, out, _e) = aiueos(&["inspect", "examples/robot/robot.aiueos.edn", "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    let comps = aiueos::edn::get(&v, "aiueos", "components")
        .and_then(|x| x.as_vector())
        .expect("components vector");
    // component fields are bare keywords (:id, :publishes, …)
    let sensor = comps
        .iter()
        .find(|c| {
            aiueos::edn::get_bare(c, "id").and_then(|x| x.as_string()) == Some("driver/sensor")
        })
        .expect("sensor present");
    // sensor publishes to topic 1 (derived from its :topic/scan export)
    assert!(aiueos::edn::get_bare(sensor, "publishes").is_some());
}

#[test]
fn inspect_dot_emits_a_graphviz_digraph() {
    let (code, out, _e) = aiueos(&["inspect", "examples/system.aiueos.edn", "--dot"]);
    assert_eq!(code, 0);
    assert!(out.contains("digraph aiueos"));
    assert!(out.contains("->"), "has at least one dependency edge");
    // the driver provides block/* to the fs service
    assert!(out.contains(r#""driver/virtio-blk" -> "service/fs""#));
}

#[test]
fn inspect_renders_policy_violations() {
    // No --policy → default policy grants no IOMMU → the driver's DMA is denied.
    // inspect reports (it doesn't gate), so it still exits 0 but shows the ✗ line.
    let (code, out, _e) = aiueos(&["inspect", "examples/system.aiueos.edn"]);
    assert_eq!(code, 0, "inspect reports rather than gating");
    assert!(
        out.contains("dma-without-iommu"),
        "the violation kind is rendered"
    );
    assert!(out.contains("driver/virtio-blk"));
}

// ---------------------------------------------------------------------------
// up / run on the WAT robot system — exercises boot + launch + the host ABI
// through the binary without the CLJ compiler (standalone-capable).
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm-runtime")]
#[test]
fn hash_prints_sha256_matching_the_library() {
    let p = write("hashme.wat", "(module)");
    let want = aiueos::runtime::sha256_hex(b"(module)");
    let (code, out, _e) = aiueos(&["hash", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(
        out.contains(&want),
        "prints the sha256 the broker will check against"
    );
    // --edn form is parseable and carries the same digest
    let (code, out, _e) = aiueos(&["hash", p.to_str().unwrap(), "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "sha256").and_then(|x| x.as_string()),
        Some(want.as_str())
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn admit_cli_runs_clean_code_and_blocks_self_escalation() {
    // The agent code-as-data gate from the CLI: a clean component is admitted
    // (exit 0, result in the verdict); a manifest claiming :trusted with a
    // :network effect is rejected (exit 1) because trust is floored to
    // :ai-generated — the agent can't grant itself trust.
    write(
        "adm.wat",
        r#"(module (func (export "main") (result i64) (i64.const 7)))"#,
    );
    let ok = write(
        "adm-ok.edn",
        r#"{:aiueos/component :agent/ok :aiueos/kind :app :aiueos/wasm "adm.wat"
            :aiueos/entry "main"}"#,
    );
    let (code, out, _e) = aiueos(&["admit", ok.to_str().unwrap(), "--edn"]);
    assert_eq!(code, 0, "clean agent code is admitted");
    let v = kotoba_edn::parse(out.trim()).unwrap();
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "admitted").and_then(|x| x.as_bool()),
        Some(true)
    );
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "result").and_then(|x| x.as_integer()),
        Some(7)
    );

    let evil = write(
        "adm-evil.edn",
        r#"{:aiueos/component :agent/evil :aiueos/kind :app :aiueos/trust :trusted
            :aiueos/wasm "adm.wat" :aiueos/entry "main" :aiueos/effects #{:network}}"#,
    );
    let (code, out, _e) = aiueos(&["admit", evil.to_str().unwrap(), "--edn"]);
    assert_eq!(
        code, 1,
        "self-claimed :trusted is floored → :network rejected"
    );
    let v = kotoba_edn::parse(out.trim()).unwrap();
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "admitted").and_then(|x| x.as_bool()),
        Some(false)
    );
    assert_eq!(
        aiueos::edn::get_kw(&v, "aiueos", "reason-code").as_deref(),
        Some("denied"),
        "stable machine-readable reason code for agent branching"
    );
    assert!(aiueos::edn::get_str(&v, "aiueos", "reason")
        .unwrap_or_default()
        .contains("network"));
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn run_executes_a_component_and_emits_edn() {
    // The robot sensor launches standalone (imports only the kernel topic cap) and
    // returns 21. Exercises the `run` CLI surface end-to-end, human and --edn.
    let (code, out, _e) = aiueos(&["run", "examples/robot/sensor.edn"]);
    assert_eq!(code, 0);
    assert!(out.contains("driver/sensor"));

    let (code, out, _e) = aiueos(&["run", "examples/robot/sensor.edn", "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "component").and_then(|x| x.as_string()),
        Some("driver/sensor")
    );
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "result").and_then(|x| x.as_integer()),
        Some(21)
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn run_browser_surface_renders_dom_and_writes_browser_out() {
    let html = scratch_dir("browser-run").join("browser.html");
    let html_arg = html.to_str().unwrap();

    let (code, out, err) = aiueos(&[
        "run",
        "examples/browser/app.edn",
        "--policy",
        "examples/browser/policy.edn",
        "--surface",
        "browser",
        "--dom-events",
        "examples/browser/dom-events.edn",
        "--browser-out",
        html_arg,
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        out.contains("dom-rendered: 1 fragment(s)") && out.contains("browser-out:"),
        "human output reports DOM render and browser bridge: {out}"
    );
    let rendered = std::fs::read_to_string(&html).expect("browser-out written");
    assert!(
        rendered.contains("<h1>aiueos browser surface</h1>"),
        "HTML bridge contains rendered DOM fragment: {rendered}"
    );

    let edn_html = scratch_dir("browser-run-edn").join("browser.html");
    let (code, out, err) = aiueos(&[
        "run",
        "examples/browser/app.edn",
        "--policy",
        "examples/browser/policy.edn",
        "--edn",
        "--browser-out",
        edn_html.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "result").and_then(|x| x.as_integer()),
        Some(83)
    );
    assert!(out.contains(":aiueos/dom-rendered"));
    assert!(edn_html.exists(), "--edn still writes the browser bridge");
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn run_browser_framebuffer_surface_presents_a_frame() {
    let (code, out, err) = aiueos(&[
        "run",
        "examples/browser/framebuffer.edn",
        "--policy",
        "examples/browser/policy.edn",
        "--surface",
        "browser",
        "--edn",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "result").and_then(|x| x.as_integer()),
        Some(8)
    );
    let outcome = aiueos::edn::get(&v, "aiueos", "outcome").expect("outcome present");
    assert_eq!(
        aiueos::edn::get(outcome, "aiueos", "framebuffer-frames").and_then(|x| x.as_integer()),
        Some(1)
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn run_browser_input_surface_reads_input_event_fixture() {
    let (code, out, err) = aiueos(&[
        "run",
        "examples/browser/input.edn",
        "--policy",
        "examples/browser/policy.edn",
        "--surface",
        "browser",
        "--input-events",
        "examples/browser/input-events.edn",
        "--edn",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "result").and_then(|x| x.as_integer()),
        Some(9)
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_browser_surface_renders_system_dom() {
    let html = scratch_dir("browser-up").join("browser.html");
    let (code, out, err) = aiueos(&[
        "up",
        "examples/browser/browser.aiueos.edn",
        "--policy",
        "examples/browser/policy.edn",
        "--dom-events",
        "examples/browser/dom-events.edn",
        "--browser-out",
        html.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        out.contains("dom-rendered: 1 fragment(s)") && out.contains("browser-out:"),
        "up reports browser surface output: {out}"
    );
    let rendered = std::fs::read_to_string(&html).expect("browser-out written");
    assert!(rendered.contains("rendered by /init-capable aiueos"));
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn browser_manifest_on_robot_surface_is_denied() {
    let (code, _out, err) = aiueos(&[
        "run",
        "examples/browser/app.edn",
        "--policy",
        "examples/browser/policy.edn",
        "--surface",
        "robot",
    ]);
    assert_eq!(code, 1, "browser manifest cannot run on robot surface");
    assert!(
        err.contains("surface-mismatch") || err.contains("unresolved-capability"),
        "denial names the surface/capability reason: {err}"
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn run_system_flag_resolves_imports_against_the_graph() {
    // `run --system` resolves a component's imports against the declared system
    // graph: an import with no provider is denied alone, but resolves when a
    // sibling in the system exports it.
    write(
        "rs-consumer.wat",
        r#"(module (func (export "main") (result i64) (i64.const 5)))"#,
    );
    let consumer = write(
        "rs-consumer.edn",
        r#"{:aiueos/component :app/consumer :aiueos/kind :app :aiueos/wasm "rs-consumer.wat"
            :aiueos/entry "main" :aiueos/imports #{:topic/scan}}"#,
    );
    write(
        "rs-provider.edn",
        "{:aiueos/component :driver/provider :aiueos/kind :driver :aiueos/exports #{:topic/scan}}",
    );
    let system = write(
        "rs-system.edn",
        r#"{:aiueos/system :rs :aiueos/components ["rs-consumer.edn" "rs-provider.edn"]}"#,
    );

    // alone: :topic/scan has no provider → denied
    let (code, _o, _e) = aiueos(&["run", consumer.to_str().unwrap()]);
    assert_eq!(code, 1, "unresolved import denied without the system graph");

    // with --system: the provider exports :topic/scan → resolves → runs
    let (code, out, _e) = aiueos(&[
        "run",
        consumer.to_str().unwrap(),
        "--system",
        system.to_str().unwrap(),
        "--edn",
    ]);
    assert_eq!(code, 0, "import resolves against the system graph");
    let v = kotoba_edn::parse(out.trim()).unwrap();
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "result").and_then(|x| x.as_integer()),
        Some(5)
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn hash_missing_file_errors() {
    let (code, _o, _e) = aiueos(&["hash", "/no/such/artifact.wasm"]);
    assert_eq!(code, 1);
}

#[cfg(feature = "signing")]
#[test]
fn verify_edn_surfaces_authenticity_per_component() {
    // An agent verifying a component should see provenance in --edn, not just pass/fail.
    let (code, out, _e) = aiueos(&[
        "verify",
        "examples/signed/demo.edn",
        "--policy",
        "examples/signed/policy.edn",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    let auth = aiueos::edn::get(&v, "aiueos", "authenticity").expect("authenticity present");
    // authenticity is a {component-id-string status-string} map
    let status = match auth {
        kotoba_edn::EdnValue::Map(m) => m
            .iter()
            .find(|(k, _)| k.as_string() == Some("app/signed-demo"))
            .and_then(|(_, val)| val.as_string()),
        _ => None,
    };
    assert_eq!(
        status,
        Some("verified:demo"),
        "names the signer that vouched for the component"
    );
}

#[cfg(feature = "signing")]
#[test]
fn verify_edn_reports_denied_authenticity_for_an_unregistered_signer() {
    // The signed example under the DEFAULT policy (no :aiueos/signers) → the signer
    // is unregistered → the verdict is verified:false with authenticity "denied".
    let (code, out, _e) = aiueos(&["verify", "examples/signed/demo.edn", "--edn"]);
    assert_eq!(code, 1, "an unregistered signer is denied");
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN even on denial");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "verified").and_then(|x| x.as_bool()),
        Some(false)
    );
    let status = match aiueos::edn::get(&v, "aiueos", "authenticity") {
        Some(kotoba_edn::EdnValue::Map(m)) => m
            .iter()
            .find(|(k, _)| k.as_string() == Some("app/signed-demo"))
            .and_then(|(_, val)| val.as_string()),
        _ => None,
    };
    assert_eq!(status, Some("denied"), "authenticity reports the denial");
}

#[cfg(feature = "signing")]
#[test]
fn the_signed_example_verifies_only_with_its_signer_policy() {
    // The bundled signed example verifies under the policy that registers its
    // signer, and is denied without it (unregistered signer). Keeps the example
    // and its committed signature honest.
    let (code, out, _e) = aiueos(&[
        "verify",
        "examples/signed/demo.edn",
        "--policy",
        "examples/signed/policy.edn",
    ]);
    assert_eq!(code, 0, "signed example verifies with its signer policy");
    assert!(out.contains("verified"));

    // default policy has no signers → the signer is unregistered → denied
    let (code, _o, _e) = aiueos(&["verify", "examples/signed/demo.edn"]);
    assert_eq!(code, 1, "denied without the signer registered");
}

#[cfg(feature = "signing")]
#[test]
fn sign_output_is_consumable_by_the_verifier() {
    // sign a manifest via the CLI, then feed the emitted signature + public key
    // back into the library verifier — the full sign → verify cycle.
    let p = write(
        "tosign.edn",
        r#"{:aiueos/component :app/demo :aiueos/kind :app :aiueos/wasm-sha256 "abc123"}"#,
    );
    let seed = "07".repeat(32); // 32-byte hex seed
    let (code, out, _e) = aiueos(&["sign", p.to_str().unwrap(), "--key", &seed, "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    let sig = aiueos::edn::get(&v, "aiueos", "signature")
        .and_then(|x| x.as_string())
        .unwrap()
        .to_string();
    let pk = aiueos::edn::get(&v, "aiueos", "public-key")
        .and_then(|x| x.as_string())
        .unwrap()
        .to_string();

    let signed = aiueos::manifest::Manifest::parse_str(&format!(
        r#"{{:aiueos/component :app/demo :aiueos/kind :app :aiueos/wasm-sha256 "abc123"
            :aiueos/signer "dev" :aiueos/signature "{sig}"}}"#
    ))
    .unwrap();
    let policy = aiueos::policy::Policy::from_edn(
        &kotoba_edn::parse(&format!("{{:aiueos/signers {{:dev \"{pk}\"}}}}")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        aiueos::signing::verify(&signed, &policy).unwrap(),
        aiueos::signing::SigStatus::Verified("dev".into()),
        "the CLI-produced signature verifies"
    );

    // signing a manifest with no artifact hash to bind → error
    let nohash = write("nohash.edn", "{:aiueos/component :app/n :aiueos/kind :app}");
    let (code, _o, _e) = aiueos(&["sign", nohash.to_str().unwrap(), "--key", &seed]);
    assert_eq!(code, 1, "no :aiueos/wasm-sha256 → nothing to sign");
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_on_a_single_manifest_gives_a_helpful_error() {
    let p = write(
        "single-for-up.edn",
        "{:aiueos/component :app/x :aiueos/kind :app}",
    );
    let (code, _out, err) = aiueos(&["up", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("system graph") && err.contains("run"));
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn dry_run_validates_the_clj_system_without_the_compiler() {
    // The CLJ example system can't be *booted* without the kototama feature, but
    // --dry-run stops before compilation — so it validates the system's manifests,
    // wiring, and policy even in the default/standalone build.
    let (code, out, _e) = aiueos(&[
        "up",
        "examples/system.aiueos.edn",
        "--policy",
        "examples/policy/default.edn",
        "--dry-run",
    ]);
    assert_eq!(code, 0, "dry-run validates without compiling CLJ");
    assert!(out.contains("4 component(s) would launch"));
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_dry_run_verifies_without_launching() {
    let (code, out, _e) = aiueos(&["up", "examples/robot/robot.aiueos.edn", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(out.contains("dry-run"));
    // nothing is launched, so no component result lines
    assert!(!out.contains("→ 21"), "no component is actually executed");

    // --edn form
    let (code, out, _e) = aiueos(&[
        "up",
        "examples/robot/robot.aiueos.edn",
        "--dry-run",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "dry-run").and_then(|x| x.as_bool()),
        Some(true)
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_boots_the_robot_system() {
    let (code, out, _e) = aiueos(&["up", "examples/robot/robot.aiueos.edn"]);
    assert_eq!(code, 0, "robot boots with the default policy");
    assert!(out.contains("system up"));
    assert!(out.contains("3/3"));
    assert!(out.contains("driver/actuator"));
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_rounds_runs_n_cycles() {
    let (code, out, _e) = aiueos(&[
        "up",
        "examples/robot/robot.aiueos.edn",
        "--rounds",
        "2",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    // multi-round → :aiueos/rounds is a vector of 2 rounds; :aiueos/launched kept.
    let rounds = aiueos::edn::get(&v, "aiueos", "rounds").expect("rounds present");
    assert_eq!(rounds.as_vector().map(|r| r.len()), Some(2));
    assert!(aiueos::edn::get(&v, "aiueos", "launched").is_some());
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn up_edn_emits_machine_readable_boot_report() {
    let (code, out, _e) = aiueos(&["up", "examples/robot/robot.aiueos.edn", "--edn"]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("boot report is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "system").and_then(|x| x.as_string()),
        Some("robot")
    );
    assert!(aiueos::edn::get(&v, "aiueos", "launched").is_some());
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn run_edn_emits_machine_readable_result() {
    let (code, out, _e) = aiueos(&[
        "run",
        "examples/robot/sensor.edn",
        "--system",
        "examples/robot/robot.aiueos.edn",
        "--edn",
    ]);
    assert_eq!(code, 0);
    let v = kotoba_edn::parse(out.trim()).expect("run result is valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "result").and_then(|x| x.as_integer()),
        Some(21)
    );
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "component").and_then(|x| x.as_string()),
        Some("driver/sensor")
    );
}

#[cfg(feature = "wasm-runtime")]
#[test]
fn run_a_host_importing_component() {
    let (code, out, _e) = aiueos(&[
        "run",
        "examples/robot/sensor.edn",
        "--system",
        "examples/robot/robot.aiueos.edn",
    ]);
    assert_eq!(code, 0);
    assert!(
        out.contains("= 21"),
        "sensor publishes & returns its reading"
    );
}

// ---------------------------------------------------------------------------
// up / run / compile on the CLJ example system — needs the kototama feature
// (aiueos wired to the sibling kotoba-clj compiler).
// ---------------------------------------------------------------------------

#[cfg(feature = "kototama")]
#[test]
fn up_boots_the_example_system_with_policy() {
    let (code, out, _e) = aiueos(&[
        "up",
        "examples/system.aiueos.edn",
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
    let (code, _out, err) = aiueos(&["up", "examples/system.aiueos.edn"]);
    assert_eq!(code, 1, "no iommu grant → boot aborts");
    assert!(err.contains("dma-without-iommu"));
}

#[cfg(feature = "kototama")]
#[test]
fn run_app_compiles_and_executes_to_42() {
    let (code, out, _e) = aiueos(&[
        "run",
        "examples/apps/notes.edn",
        "--system",
        "examples/system.aiueos.edn",
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
    let (code, out, _e) = aiueos(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("compiled"));
    let bytes = std::fs::read(&wasm).expect("wasm written next to source");
    assert_eq!(&bytes[0..4], b"\0asm", "real wasm magic");
    let _ = std::fs::remove_file(&wasm);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_kotoba_writes_wasm_next_to_source() {
    let p = write(
        "comp_src.kotoba",
        "#!/usr/bin/env kotoba-clj\n(defn main [n] (+ n 1))",
    );
    let wasm = p.with_extension("wasm");
    let _ = std::fs::remove_file(&wasm);
    let (code, out, _e) = aiueos(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("compiled"));
    let bytes = std::fs::read(&wasm).expect("wasm written next to source");
    assert_eq!(&bytes[0..4], b"\0asm", "real wasm magic");
    let _ = std::fs::remove_file(&wasm);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_cljc_honors_kotoba_reader_conditionals() {
    let p = write(
        "comp_cond.cljc",
        r#"(defn main [n] #?(:kotoba (+ n 1) :clj (+ n 100) :default 0))"#,
    );
    let wasm = p.with_extension("wasm");
    let _ = std::fs::remove_file(&wasm);
    let (code, out, err) = aiueos(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("compiled"));
    let bytes = std::fs::read(&wasm).expect("wasm written next to source");
    let result = aiueos::runtime::run_wasm(&bytes, "main", &[41], 1_000_000, 64).unwrap();
    assert_eq!(result, 42, "kotoba reader branch was selected");
    let _ = std::fs::remove_file(&wasm);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_honors_output_flag() {
    let p = write("comp_src2.clj", "(defn main [n] n)");
    let out_path = scratch("custom_out.wasm");
    let _ = std::fs::remove_file(&out_path);
    let (code, _o, _e) = aiueos(&[
        "compile",
        p.to_str().unwrap(),
        "-o",
        out_path.to_str().unwrap(),
    ]);
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
    let (code, _o, err) = aiueos(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("slurp"));
    assert!(
        !wasm.exists(),
        "no wasm emitted when the source is rejected"
    );
}

#[cfg(feature = "kototama")]
#[test]
fn compile_rejects_safe_clj_type_errors_before_emitting() {
    let p = write("comp_type_bad.kotoba", r#"(defn main [] (+ "a" 1))"#);
    let wasm = p.with_extension("wasm");
    let _ = std::fs::remove_file(&wasm);
    let (code, _o, err) = aiueos(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(
        err.contains("type error"),
        "safe compiler should reject the type error, stderr: {err}"
    );
    assert!(!wasm.exists(), "no wasm emitted for rejected source");
}

#[cfg(feature = "kototama")]
#[test]
fn run_kotoba_source_manifest_executes_to_42() {
    let dir = scratch_dir("kotoba-source-run");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("source.kotoba"),
        "#!/usr/bin/env kotoba-clj\n(defn main [n] (* n 2))",
    )
    .unwrap();
    let manifest = dir.join("source.edn");
    std::fs::write(
        &manifest,
        r#"{:aiueos/component :app/kotoba-src
            :aiueos/kind :app
            :aiueos/trust :untrusted
            :aiueos/source "source.kotoba"
            :aiueos/entry "main"
            :aiueos/args [21]}"#,
    )
    .unwrap();
    let (code, out, err) = aiueos(&["run", manifest.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("= 42"), "stdout: {out}");
}

#[cfg(feature = "kototama")]
#[test]
fn run_kotoba_source_manifest_binds_kqe_host_imports_from_policy() {
    let dir = scratch_dir("kotoba-kqe-run");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("kqe_source.kotoba"),
        r#"(defn main []
             (if (kqe-assert! "kg" "alice" "kg/name" "v") 42 0))"#,
    )
    .unwrap();
    let manifest = dir.join("kqe_source.edn");
    std::fs::write(
        &manifest,
        r#"{:aiueos/component :app/kqe-src
            :aiueos/kind :app
            :aiueos/trust :untrusted
            :aiueos/imports #{:kotoba.graph-write/kg}
            :aiueos/source "kqe_source.kotoba"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    let policy = dir.join("kqe_policy.edn");
    std::fs::write(
        &policy,
        r#"{:aiueos/grants {:app/kqe-src #{:kotoba.graph-write/kg}}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "run",
        manifest.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("= 42"), "stdout: {out}");
}

#[cfg(feature = "kototama")]
#[test]
fn run_kotoba_source_manifest_binds_llm_fixture_from_policy() {
    let dir = scratch_dir("kotoba-llm-run");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("agent.kotoba"),
        r#"(defn main []
             (str-len (llm-infer "modelA" "hello")))"#,
    )
    .unwrap();
    let manifest = dir.join("agent.edn");
    std::fs::write(
        &manifest,
        r#"{:aiueos/component :app/llm-run
            :aiueos/kind :app
            :aiueos/imports #{:kotoba.infer/modelA}
            :aiueos/source "agent.kotoba"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    let policy = dir.join("policy.edn");
    std::fs::write(
        &policy,
        r#"{:aiueos/grants {:app/llm-run #{:kotoba.infer/modelA}}}"#,
    )
    .unwrap();
    let fixture = dir.join("llm.edn");
    std::fs::write(&fixture, r#"{:aiueos/llm {"modelA" "fixture-answer"}}"#).unwrap();

    let (code, out, err) = aiueos(&[
        "run",
        manifest.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--llm-fixture",
        fixture.to_str().unwrap(),
        "--edn",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    assert_eq!(
        aiueos::edn::get(&v, "aiueos", "result").and_then(|x| x.as_integer()),
        Some(14),
        "llm-infer returns the fixture response bytes"
    );
    let audit = std::fs::read_to_string(dir.join(".aiueos/audit.edn")).expect("audit log");
    assert!(
        audit.contains("kotoba:kais/llm.infer model=modelA prompt-bytes=5"),
        "audit records LLM host target: {audit}"
    );
}

#[cfg(feature = "kototama")]
#[test]
fn run_kotoba_kqe_source_without_policy_grant_is_denied() {
    let dir = scratch_dir("kotoba-kqe-denied");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("kqe_denied.kotoba"),
        r#"(defn main []
             (if (kqe-assert! "kg" "alice" "kg/name" "v") 42 0))"#,
    )
    .unwrap();
    let manifest = dir.join("kqe_denied.edn");
    std::fs::write(
        &manifest,
        r#"{:aiueos/component :app/kqe-denied
            :aiueos/kind :app
            :aiueos/imports #{:kotoba.graph-write/kg}
            :aiueos/source "kqe_denied.kotoba"
            :aiueos/entry "main"}"#,
    )
    .unwrap();

    let (code, _out, err) = aiueos(&["run", manifest.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(
        err.contains("unresolved-capability") && err.contains("kotoba.graph-write/kg"),
        "stderr: {err}"
    );
}

#[cfg(feature = "kototama")]
#[test]
fn run_kotoba_kqe_query_rejects_bad_edn_filter() {
    let dir = scratch_dir("kotoba-kqe-bad-filter");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("bad_filter.kotoba"),
        r#"(defn main []
             (kqe-count (kqe-query "{:graph \"kg\" :unknown \"x\"}")))"#,
    )
    .unwrap();
    let manifest = dir.join("bad_filter.edn");
    std::fs::write(
        &manifest,
        r#"{:aiueos/component :app/kqe-bad-filter
            :aiueos/kind :app
            :aiueos/imports #{:kotoba.graph-read/kg}
            :aiueos/source "bad_filter.kotoba"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    let policy = dir.join("policy.edn");
    std::fs::write(
        &policy,
        r#"{:aiueos/grants {:app/kqe-bad-filter #{:kotoba.graph-read/kg}}}"#,
    )
    .unwrap();

    let (code, _out, err) = aiueos(&[
        "run",
        manifest.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("run error"), "stderr: {err}");
    let audit = std::fs::read_to_string(dir.join(".aiueos/audit.edn")).expect("audit log");
    assert!(
        audit.contains(":reject") && audit.contains("run failed"),
        "runtime filter denial is audited: {audit}"
    );
}

#[cfg(feature = "kototama")]
#[test]
fn up_threads_kqe_store_between_kotoba_components() {
    let dir = scratch_dir("kotoba-kqe-system");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("writer.kotoba"),
        r#"(defn main []
             (do
               (kqe-assert! "kg" "alice" "kg/name" "v")
               (if (kqe-assert! "kg" "alice" "kg/role" "admin") 1 0)))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("reader.kotoba"),
        r#"(defn main []
             (let [by-spo (kqe-get-objects "kg" "alice" "kg/name")
                   by-query (kqe-query "kg/role")
                   by-map (kqe-query "{:graph \"kg\" :subject \"alice\" :predicate \"kg/role\"}")
                  by-datomic (kqe-query "{:graph \"kg\" :datomic {:find [?name] :where [[?e :kg/role \"admin\"] [?e :kg/name ?name]]}}")]
               (+ (* 1000 (kqe-count by-datomic))
                  (* 100 (kqe-count by-map))
                  (* 10 (kqe-count by-spo))
                  (kqe-count by-query))))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("writer.edn"),
        r#"{:aiueos/component :app/kqe-writer
            :aiueos/kind :app
            :aiueos/imports #{:kotoba.graph-write/kg}
            :aiueos/exports #{:kotoba.graph-read/kg}
            :aiueos/source "writer.kotoba"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("reader.edn"),
        r#"{:aiueos/component :app/kqe-reader
            :aiueos/kind :app
            :aiueos/imports #{:kotoba.graph-read/kg}
            :aiueos/source "reader.kotoba"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    let system = dir.join("system.aiueos.edn");
    std::fs::write(
        &system,
        r#"{:aiueos/system :kqe-flow
            :aiueos/components ["writer.edn" "reader.edn"]}"#,
    )
    .unwrap();
    let policy = dir.join("policy.edn");
    std::fs::write(
        &policy,
        r#"{:aiueos/grants {:app/kqe-writer #{:kotoba.graph-write/kg}}}"#,
    )
    .unwrap();

    let (code, out, err) = aiueos(&[
        "up",
        system.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--edn",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    let launched = aiueos::edn::get(&v, "aiueos", "launched")
        .and_then(|x| x.as_vector())
        .expect("launched vector");
    let reader = launched
        .iter()
        .find(|c| {
            aiueos::edn::get_bare(c, "component").and_then(|x| x.as_string())
                == Some("app/kqe-reader")
        })
        .expect("reader launched");
    assert_eq!(
        aiueos::edn::get_bare(reader, "result").and_then(|x| x.as_integer()),
        Some(1111),
        "reader sees writer's KQE assertion and query filters by predicate/map/datomic"
    );
    let audit = std::fs::read_to_string(dir.join(".aiueos/audit.edn")).expect("audit log");
    assert!(
        audit.contains("kotoba:kais/kqe.assert-quad kg/alice/kg/name")
            && audit.contains("kotoba:kais/kqe.get-objects kg/alice/kg/name count=1")
            && audit
                .contains("kotoba:kais/kqe.query graph=None subject=None predicate=Some(\\\"kg/role\\\") count=1")
            && audit
                .contains("kotoba:kais/kqe.query graph=Some(\\\"kg\\\") subject=Some(\\\"alice\\\") predicate=Some(\\\"kg/role\\\") count=1")
            && audit
                .contains("kotoba:kais/kqe.query datomic graph=Some(\\\"kg\\\") count=1"),
        "audit records KQE host targets: {audit}"
    );
}

#[cfg(feature = "kototama")]
#[test]
fn up_persists_kqe_store_between_invocations() {
    let dir = scratch_dir("kotoba-kqe-persist");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("writer.kotoba"),
        r#"(defn main []
             (if (kqe-assert! "kg" "persisted" "kg/name" "v") 7 0))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("reader.kotoba"),
        r#"(defn main []
             (kqe-count (kqe-get-objects "kg" "persisted" "kg/name")))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("writer.edn"),
        r#"{:aiueos/component :app/kqe-persist-writer
            :aiueos/kind :app
            :aiueos/imports #{:kotoba.graph-write/kg}
            :aiueos/source "writer.kotoba"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("reader.edn"),
        r#"{:aiueos/component :app/kqe-persist-reader
            :aiueos/kind :app
            :aiueos/imports #{:kotoba.graph-read/kg}
            :aiueos/source "reader.kotoba"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    let writer_system = dir.join("writer-system.aiueos.edn");
    std::fs::write(
        &writer_system,
        r#"{:aiueos/system :kqe-persist-write
            :aiueos/components ["writer.edn"]}"#,
    )
    .unwrap();
    let reader_system = dir.join("reader-system.aiueos.edn");
    std::fs::write(
        &reader_system,
        r#"{:aiueos/system :kqe-persist-read
            :aiueos/components ["reader.edn"]}"#,
    )
    .unwrap();
    let policy = dir.join("policy.edn");
    std::fs::write(
        &policy,
        r#"{:aiueos/grants {:app/kqe-persist-writer #{:kotoba.graph-write/kg}
                           :app/kqe-persist-reader #{:kotoba.graph-read/kg}}}"#,
    )
    .unwrap();
    let store = dir.join("kqe-store.edn");

    let (code, _out, err) = aiueos(&[
        "up",
        writer_system.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--kqe-store",
        store.to_str().unwrap(),
        "--edn",
    ]);
    assert_eq!(code, 0, "writer stderr: {err}");
    let saved = std::fs::read_to_string(&store).expect("kqe store saved");
    assert!(saved.contains("persisted"), "store contains asserted quad");

    let (code, out, err) = aiueos(&[
        "up",
        reader_system.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--kqe-store",
        store.to_str().unwrap(),
        "--edn",
    ]);
    assert_eq!(code, 0, "reader stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    let launched = aiueos::edn::get(&v, "aiueos", "launched")
        .and_then(|x| x.as_vector())
        .expect("launched vector");
    let reader = launched
        .iter()
        .find(|c| {
            aiueos::edn::get_bare(c, "component").and_then(|x| x.as_string())
                == Some("app/kqe-persist-reader")
        })
        .expect("reader launched");
    assert_eq!(
        aiueos::edn::get_bare(reader, "result").and_then(|x| x.as_integer()),
        Some(1),
        "reader sees KQE data persisted by a previous up invocation"
    );
}

#[cfg(feature = "kototama")]
#[test]
fn up_runs_kotoba_llm_infer_with_fixture() {
    let dir = scratch_dir("kotoba-llm-fixture");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("agent.kotoba"),
        r#"(defn main []
             (str-len (llm-infer "modelA" "hello")))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("agent.edn"),
        r#"{:aiueos/component :app/llm-agent
            :aiueos/kind :app
            :aiueos/imports #{:kotoba.infer/modelA}
            :aiueos/source "agent.kotoba"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    let system = dir.join("system.aiueos.edn");
    std::fs::write(
        &system,
        r#"{:aiueos/system :llm-fixture
            :aiueos/components ["agent.edn"]}"#,
    )
    .unwrap();
    let policy = dir.join("policy.edn");
    std::fs::write(
        &policy,
        r#"{:aiueos/grants {:app/llm-agent #{:kotoba.infer/modelA}}}"#,
    )
    .unwrap();
    let fixture = dir.join("llm.edn");
    std::fs::write(&fixture, r#"{:aiueos/llm {"modelA" "fixture-answer"}}"#).unwrap();

    let (code, out, err) = aiueos(&[
        "up",
        system.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--llm-fixture",
        fixture.to_str().unwrap(),
        "--edn",
    ]);
    assert_eq!(code, 0, "stderr: {err}");
    let v = kotoba_edn::parse(out.trim()).expect("valid EDN");
    let launched = aiueos::edn::get(&v, "aiueos", "launched")
        .and_then(|x| x.as_vector())
        .expect("launched vector");
    let agent = launched
        .iter()
        .find(|c| {
            aiueos::edn::get_bare(c, "component").and_then(|x| x.as_string())
                == Some("app/llm-agent")
        })
        .expect("agent launched");
    assert_eq!(
        aiueos::edn::get_bare(agent, "result").and_then(|x| x.as_integer()),
        Some(14),
        "llm-infer returns the fixture response bytes"
    );
    let audit = std::fs::read_to_string(dir.join(".aiueos/audit.edn")).expect("audit log");
    assert!(
        audit.contains("kotoba:kais/llm.infer model=modelA prompt-bytes=5"),
        "audit records LLM host target: {audit}"
    );
}

#[cfg(feature = "kototama")]
#[test]
fn compile_manifest_reads_its_source() {
    let dir = scratch_dir("manifest-compile");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("m_src.clj"), "(defn main [n] (* n 3))").unwrap();
    let manifest = dir.join("m.edn");
    std::fs::write(
        &manifest,
        r#"{:aiueos/component :app/m :aiueos/kind :app :aiueos/source "m_src.clj"}"#,
    )
    .unwrap();
    let outp = dir.join("m_out.wasm");
    let _ = std::fs::remove_file(&outp);
    let (code, _o, _e) = aiueos(&[
        "compile",
        manifest.to_str().unwrap(),
        "-o",
        outp.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "manifest's :aiueos/source is compiled");
    assert!(outp.exists());
    let _ = std::fs::remove_file(&outp);
}

#[cfg(feature = "kototama")]
#[test]
fn compile_manifest_without_source_errors() {
    let p = write("nosrc.edn", "{:aiueos/component :app/n :aiueos/kind :app}");
    let (code, _o, _e) = aiueos(&["compile", p.to_str().unwrap()]);
    assert_eq!(code, 1, "manifest with no :aiueos/source cannot compile");
}
