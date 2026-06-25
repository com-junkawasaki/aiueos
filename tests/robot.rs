//! Robotics pipeline over the broker-mediated host ABI + topic bus: a
//! sensor → planner → actuator dataflow where each node is a capability-gated
//! wasm component. Needs only wasm *execution* (WAT components), not the kototama
//! CLJ compiler — so it's gated on `wasm-runtime`, not `kototama`.
#![cfg(feature = "wasm-runtime")]

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::graph::System;
use aiueos::host::{self, EMPTY};
use aiueos::policy::Policy;
use aiueos::topic::TopicBus;
use std::collections::BTreeSet;
use std::path::Path;

const SENSOR: &str = r#"(module
  (import "aiue:host" "publish" (func $publish (param i32 i64)))
  (func (export "tick") (param $v i64) (result i64)
    (call $publish (i32.const 1) (local.get $v))
    (local.get $v)))"#;

const PLANNER: &str = r#"(module
  (import "aiue:host" "poll"    (func $poll    (param i32) (result i64)))
  (import "aiue:host" "publish" (func $publish (param i32 i64)))
  (func (export "tick") (param i64) (result i64)
    (local $cmd i64)
    (local.set $cmd (i64.mul (call $poll (i32.const 1)) (i64.const 2)))
    (call $publish (i32.const 2) (local.get $cmd))
    (local.get $cmd)))"#;

const ACTUATOR: &str = r#"(module
  (import "aiue:host" "poll" (func $poll (param i32) (result i64)))
  (func (export "tick") (param i64) (result i64)
    (call $poll (i32.const 2))))"#;

fn caps(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn sensor_planner_actuator_pipeline_over_the_bus() {
    // sensor publishes 21 → topic 1; planner polls 21, publishes 42 → topic 2;
    // actuator polls 42. The bus is threaded through each run.
    let bus = TopicBus::new();

    let s = host::run_with_host(
        SENSOR.as_bytes(),
        "tick",
        &[21],
        1_000_000,
        4,
        &caps(&["topic/publish"]),
        bus,
    )
    .expect("sensor runs");
    assert_eq!(s.result, 21);
    assert_eq!(s.host_calls, 1);

    let p = host::run_with_host(
        PLANNER.as_bytes(),
        "tick",
        &[0],
        1_000_000,
        4,
        &caps(&["topic/subscribe", "topic/publish"]),
        s.bus,
    )
    .expect("planner runs");
    assert_eq!(p.result, 42, "scan(21) * 2");

    let a = host::run_with_host(
        ACTUATOR.as_bytes(),
        "tick",
        &[0],
        1_000_000,
        4,
        &caps(&["topic/subscribe"]),
        p.bus,
    )
    .expect("actuator runs");
    assert_eq!(a.result, 42, "actuator drives the commanded value");
    assert_eq!(a.bus.latest(1), Some(21), "scan retained");
    assert_eq!(a.bus.latest(2), Some(42), "cmd retained");
}

#[test]
fn host_call_without_capability_traps() {
    // The sensor publishes, but we confer no capabilities → the publish traps.
    let r = host::run_with_host(
        SENSOR.as_bytes(),
        "tick",
        &[21],
        1_000_000,
        4,
        &BTreeSet::new(),
        TopicBus::new(),
    );
    assert!(r.is_err(), "publish without topic/publish must trap");
}

#[test]
fn poll_of_empty_topic_returns_sentinel() {
    // Actuator polls topic 2 with nothing published → EMPTY sentinel, no trap.
    let a = host::run_with_host(
        ACTUATOR.as_bytes(),
        "tick",
        &[0],
        1_000_000,
        4,
        &caps(&["topic/subscribe"]),
        TopicBus::new(),
    )
    .expect("poll of empty topic is not an error");
    assert_eq!(a.result, EMPTY);
}

#[test]
fn boots_the_example_robot_system() {
    // End-to-end through the broker: load the on-disk robot system (WAT
    // components), boot under the default policy, actuator drives 42.
    let sys = System::load(Path::new("examples/robot/robot.aiue.edn")).expect("loads");
    let audit = AuditLog::new(std::env::temp_dir().join("aiueos-robot-boot.edn"));
    let broker = Broker::new(Policy::default(), audit);
    let report = broker
        .boot(&sys, Path::new("examples/robot"))
        .expect("robot boots");
    let act = report
        .launched
        .iter()
        .find(|o| o.component == "driver/actuator")
        .expect("actuator launched");
    assert_eq!(act.result, Some(42), "sensor(21) → planner ×2 → actuator");
}
