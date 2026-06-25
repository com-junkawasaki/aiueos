//! Coverage for `AiueError`'s `Display` rendering — the multi-violation and
//! multi-reason aggregation paths that the CLI relies on for its error output.

use aiueos::error::AiueError;
use aiueos::policy::{Violation, ViolationKind};

#[test]
fn denied_display_lists_every_violation() {
    let e = AiueError::Denied(vec![
        Violation {
            component: "agent/leaky".into(),
            kind: ViolationKind::ForbiddenEffect,
            message: "network forbidden".into(),
        },
        Violation {
            component: "app/lonely".into(),
            kind: ViolationKind::UnresolvedCapability,
            message: "no provider".into(),
        },
    ]);
    let s = e.to_string();
    assert!(s.contains("2 violation"), "count rendered");
    assert!(s.contains("forbidden-effect") && s.contains("unresolved-capability"));
    assert!(s.contains("agent/leaky") && s.contains("app/lonely"));
}

#[test]
fn unsafe_display_lists_every_reason() {
    let e = AiueError::Unsafe(vec![
        "forbidden symbol `eval`".into(),
        "forbidden symbol `slurp`".into(),
    ]);
    let s = e.to_string();
    assert!(s.contains("safe-kotoba"));
    assert!(s.contains("eval") && s.contains("slurp"));
}

#[test]
fn scalar_variants_render_their_kind() {
    assert!(AiueError::Schema("bad shape".into())
        .to_string()
        .contains("schema error"));
    assert!(AiueError::Run("trap".into()).to_string().contains("run error"));
    assert!(AiueError::Edn("eof".into())
        .to_string()
        .contains("edn parse error"));
    assert!(AiueError::Compile("nope".into())
        .to_string()
        .contains("compile error"));
}

#[test]
fn io_error_converts_via_from() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
    let e: AiueError = io.into();
    assert!(matches!(e, AiueError::Io(_)));
    assert!(e.to_string().contains("io error"));
}
