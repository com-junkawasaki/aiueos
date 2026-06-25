//! Integration test for the boot sequence (`aiue up`): the example system must
//! boot in dependency order with the IOMMU policy, and must refuse to boot
//! without it.
#![cfg(feature = "kototama")]

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::graph::System;
use aiueos::manifest::Manifest;
use aiueos::policy::Policy;
use std::path::Path;

fn scratch_audit(name: &str) -> AuditLog {
    AuditLog::new(std::env::temp_dir().join(name))
}

#[test]
fn boots_the_example_system_in_dependency_order() {
    let sys = System::load(Path::new("examples/system.aiue.edn")).expect("system loads");
    let policy = Policy::load(Path::new("examples/policy/default.edn")).expect("policy loads");
    let broker = Broker::new(policy, scratch_audit("aiueos-boot-ok.edn"));

    // Providers must precede consumers: driver before fs, fs+log before the app.
    let order = sys.boot_order().expect("acyclic");
    let pos = |id: &str| order.iter().position(|&i| sys.components[i].id == id).unwrap();
    assert!(pos("driver/virtio-blk") < pos("service/fs"));
    assert!(pos("service/fs") < pos("app/notes"));
    assert!(pos("service/log") < pos("app/notes"));

    let report = broker.boot(&sys, Path::new("examples")).expect("boots");
    assert_eq!(report.launched.len(), 4);
    let notes = report
        .launched
        .iter()
        .find(|o| o.component == "app/notes")
        .expect("app launched");
    assert_eq!(notes.result, Some(42), "main(21) = 42");
}

#[test]
fn resident_component_with_no_code_launches_as_resident() {
    // A pure manifest (no :aiue/source / :aiue/wasm) passes the gate but has
    // nothing to execute — it boots as a resident with no result.
    let svc = Manifest::parse_str(
        "{:aiue/component :svc/resident :aiue/kind :service :aiue/exports #{:x/y}}",
    )
    .unwrap();
    let sys = System::from_manifests("resident-demo", vec![svc]);
    let broker = Broker::new(Policy::default(), scratch_audit("aiueos-boot-resident.edn"));
    let report = broker.boot(&sys, Path::new(".")).expect("boots");
    assert_eq!(report.launched.len(), 1);
    assert_eq!(report.launched[0].component, "svc/resident");
    assert!(
        report.launched[0].result.is_none(),
        "no code → resident (no result)"
    );
}

#[test]
fn boot_aborts_without_iommu_grant() {
    let sys = System::load(Path::new("examples/system.aiue.edn")).expect("system loads");
    let broker = Broker::new(Policy::default(), scratch_audit("aiueos-boot-deny.edn"));
    // Default policy grants no IOMMU → the driver's :dma effect is denied → no boot.
    assert!(broker.boot(&sys, Path::new("examples")).is_err());
}
