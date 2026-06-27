//! Code-as-data admission (ADR-0004): the agent front door. An agent-submitted
//! component is floored to :ai-generated trust — it cannot grant itself trust —
//! while a clean component is admitted with its result. Exec-only (WAT).
#![cfg(feature = "wasm-runtime")]

use aiueos::broker::Broker;
use aiueos::graph::CapabilityGraph;
use aiueos::manifest::Manifest;
use aiueos::policy::Policy;

fn broker() -> Broker {
    Broker::new(
        Policy::default(),
        aiueos::audit::AuditLog::new(std::env::temp_dir().join("aiueos-admit-test.edn")),
    )
}

fn tmpdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join("aiueos-admit-test");
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn admit_floors_trust_so_code_cannot_escalate_itself() {
    // The manifest LIES — it claims :trusted and a :network effect. Under launch
    // that trust would be honored; admit floors it to :ai-generated, for which
    // :network is forbidden → rejected with a reason, not admitted.
    let dir = tmpdir();
    std::fs::write(
        dir.join("evil.wat"),
        r#"(module (func (export "main") (result i64) (i64.const 0)))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("evil.edn"),
        r#"{:aiueos/component :agent/evil :aiueos/kind :app :aiueos/trust :trusted
            :aiueos/wasm "evil.wat" :aiueos/entry "main" :aiueos/effects #{:network}}"#,
    )
    .unwrap();
    let m = Manifest::load(&dir.join("evil.edn")).unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&m));

    let outcome = broker().admit(&m, &dir, &g);
    assert!(
        !outcome.admitted,
        "self-claimed :trusted must not bypass the floor"
    );
    assert!(
        outcome.reason.as_deref().unwrap_or("").contains("network"),
        "reason explains the forbidden effect: {:?}",
        outcome.reason
    );
    assert!(outcome.result.is_none());
}

#[test]
fn admit_runs_a_clean_agent_component() {
    // A component with no forbidden effects, importing only a kernel cap, is
    // admitted and its result returned — the agent loop's success path.
    let dir = tmpdir();
    std::fs::write(
        dir.join("ok.wat"),
        r#"(module (func (export "main") (result i64) (i64.const 7)))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("ok.edn"),
        r#"{:aiueos/component :agent/ok :aiueos/kind :app :aiueos/wasm "ok.wat"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    let m = Manifest::load(&dir.join("ok.edn")).unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&m));

    let outcome = broker().admit(&m, &dir, &g);
    assert!(
        outcome.admitted,
        "clean component admitted: {:?}",
        outcome.reason
    );
    assert_eq!(outcome.result, Some(7));
    assert_eq!(outcome.component, "agent/ok");
}

#[test]
fn admit_rejects_a_runtime_trap_with_a_reason() {
    // A component that traps at runtime is rejected (not a panic), reason carried.
    let dir = tmpdir();
    std::fs::write(
        dir.join("trap.wat"),
        r#"(module (func (export "main") (result i64) (unreachable)))"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("trap.edn"),
        r#"{:aiueos/component :agent/trap :aiueos/kind :app :aiueos/wasm "trap.wat"
            :aiueos/entry "main"}"#,
    )
    .unwrap();
    let m = Manifest::load(&dir.join("trap.edn")).unwrap();
    let g = CapabilityGraph::build(std::slice::from_ref(&m));

    let outcome = broker().admit(&m, &dir, &g);
    assert!(!outcome.admitted);
    assert!(outcome.reason.is_some(), "a trap carries a reason");
}
