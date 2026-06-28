//! The **browser** deployment surface (ADR-0005): the `dom/render` and
//! `dom/event` providers. Phase-0 keeps them in-process and deterministic —
//! `dom/render` appends painted markup to a host-side log, `dom/event` delivers
//! injected semantic events FIFO, `input-event` delivers low-level input events
//! FIFO, and `fb-present` records deterministic framebuffer frames — but they are
//! gated identically to every other capability, and a component that doesn't hold
//! the cap traps. WAT components exercise the ABI directly: `wasm-runtime`, no
//! kototama.
#![cfg(feature = "wasm-runtime")]

use aiueos::host::{self, DomSurface, KqeStore, LlmFixtures, TopicAccess};
use aiueos::manifest::Quota;
use aiueos::topic::TopicBus;
use std::collections::BTreeSet;

// Paints an 11-byte markup string via dom/render, then returns 0.
const RENDER: &str = r#"(module
  (import "aiueos:host" "dom-render" (func $render (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "<h1>hi</h1>")
  (func (export "run") (result i64)
    (call $render (i32.const 0) (i32.const 11))
    (i64.const 0)))"#;

// Reads the next injected input event into a buffer at offset 64 whose capacity
// is the i32 argument, returning whatever dom/event reports (bytes / -1 / -2).
const EVENT: &str = r#"(module
  (import "aiueos:host" "dom-event" (func $event (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i64)
    (i64.extend_i32_s (call $event (i32.const 64) (local.get 0)))))"#;

// Reads the next low-level input event into a buffer at offset 64.
const INPUT_EVENT: &str = r#"(module
  (import "aiueos:host" "input-event" (func $event (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i64)
    (i64.extend_i32_s (call $event (i32.const 64) (local.get 0)))))"#;

// Presents two RGBA pixels as a 2x1 linear framebuffer frame.
const FB_PRESENT: &str = r#"(module
  (import "aiueos:host" "fb-present" (func $present (param i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\ff\00\00\ff\00\ff\00\ff")
  (func (export "run") (result i64)
    (i64.extend_i32_s
      (call $present
        (i32.const 0)  ;; ptr
        (i32.const 8)  ;; len
        (i32.const 2)  ;; width
        (i32.const 1)  ;; height
        (i32.const 8)))))"#;

fn caps(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn run_dom(
    wat: &str,
    args: &[i64],
    caps: &BTreeSet<String>,
    dom: DomSurface,
) -> aiueos::Result<host::HostOutcome> {
    host::run_with_host_restricted_with_kqe_llm_dom(
        wat.as_bytes(),
        "run",
        args,
        1_000_000,
        4,
        caps,
        TopicBus::new(),
        KqeStore::default(),
        LlmFixtures::default(),
        dom,
        &TopicAccess::unrestricted(),
        Quota::default(),
    )
}

#[test]
fn dom_render_captures_painted_markup_when_granted() {
    let o = run_dom(RENDER, &[], &caps(&["dom/render"]), DomSurface::default())
        .expect("dom/render granted");
    assert_eq!(o.dom_rendered, vec!["<h1>hi</h1>".to_string()]);
    assert!(o
        .host_events
        .iter()
        .any(|e| e == "aiueos:host/dom-render bytes=11"));
}

#[test]
fn dom_render_traps_without_capability() {
    // The robot surface never offers dom/render, so a robot component never holds
    // it; here we prove the runtime gate itself denies the call.
    assert!(
        run_dom(RENDER, &[], &BTreeSet::new(), DomSurface::default()).is_err(),
        "dom-render without dom/render must trap"
    );
}

#[test]
fn dom_event_delivers_injected_input_fifo() {
    // buffer capacity 64 is plenty for "click:#go" (9 bytes).
    let dom = DomSurface::with_events(["click:#go", "input:hi"]);
    let o = run_dom(EVENT, &[64], &caps(&["dom/event"]), dom).expect("dom/event granted");
    assert_eq!(o.result, 9, "first event is 9 bytes (click:#go)");
    assert!(o
        .host_events
        .iter()
        .any(|e| e == "aiueos:host/dom-event bytes=9"));
}

#[test]
fn dom_event_returns_minus_one_when_drained() {
    let o = run_dom(EVENT, &[64], &caps(&["dom/event"]), DomSurface::default())
        .expect("dom/event granted");
    assert_eq!(o.result, -1, "no pending events → -1");
}

#[test]
fn dom_event_undersized_buffer_returns_minus_two_and_retains_event() {
    // cap=4 is smaller than "click:#go" (9), so the host must report -2 without
    // dropping the event.
    let dom = DomSurface::with_events(["click:#go"]);
    let o = run_dom(EVENT, &[4], &caps(&["dom/event"]), dom).expect("dom/event granted");
    assert_eq!(o.result, -2, "buffer too small → -2");
    assert!(o
        .host_events
        .iter()
        .any(|e| e.starts_with("aiueos:host/dom-event buffer-too-small")));
}

#[test]
fn dom_event_traps_without_capability() {
    let dom = DomSurface::with_events(["click:#go"]);
    assert!(
        run_dom(EVENT, &[64], &BTreeSet::new(), dom).is_err(),
        "dom-event without dom/event must trap"
    );
}

#[test]
fn input_event_delivers_low_level_input_fifo() {
    // buffer capacity 64 is plenty for "key:Enter" (9 bytes).
    let dom = DomSurface::with_input_events(["key:Enter", "pointer:10,20"]);
    let o = run_dom(INPUT_EVENT, &[64], &caps(&["input/event"]), dom).expect("input/event granted");
    assert_eq!(o.result, 9, "first input event is 9 bytes");
    assert!(o
        .host_events
        .iter()
        .any(|e| e == "aiueos:host/input-event bytes=9"));
}

#[test]
fn input_event_traps_without_capability() {
    let dom = DomSurface::with_input_events(["key:Enter"]);
    assert!(
        run_dom(INPUT_EVENT, &[64], &BTreeSet::new(), dom).is_err(),
        "input-event without input/event must trap"
    );
}

#[test]
fn framebuffer_present_records_a_frame_when_granted() {
    let o = run_dom(
        FB_PRESENT,
        &[],
        &caps(&["framebuffer/present"]),
        DomSurface::default(),
    )
    .expect("framebuffer/present granted");
    assert_eq!(o.result, 8, "fb-present returns accepted byte count");
    assert_eq!(o.framebuffer_presented.len(), 1);
    let frame = &o.framebuffer_presented[0];
    assert_eq!((frame.width, frame.height, frame.stride), (2, 1, 8));
    assert_eq!(frame.bytes.len(), 8);
    assert!(o
        .host_events
        .iter()
        .any(|e| { e == "aiueos:host/fb-present bytes=8 width=2 height=1 stride=8" }));
}

#[test]
fn framebuffer_present_traps_without_capability() {
    assert!(
        run_dom(FB_PRESENT, &[], &BTreeSet::new(), DomSurface::default()).is_err(),
        "fb-present without framebuffer/present must trap"
    );
}
