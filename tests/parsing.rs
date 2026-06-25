//! Negative-path & round-trip coverage for the semantic core (no wasm runtime):
//! manifest schema errors, policy `from_edn` merge semantics, the audit log
//! round-trip, and the safe-kotoba subset edge cases.

use aiueos::audit::{AuditLog, Event};
use aiueos::error::AiueError;
use aiueos::manifest::{Kind, Manifest, Trust};
use aiueos::policy::Policy;
use aiueos::{edn, safe};

// ---------------------------------------------------------------------------
// manifest: schema validation
// ---------------------------------------------------------------------------

#[test]
fn manifest_non_map_is_schema_error() {
    assert!(matches!(
        Manifest::parse_str("[:not :a :map]"),
        Err(AiueError::Schema(_))
    ));
}

#[test]
fn manifest_missing_component_id_is_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiue/kind :app}"),
        Err(AiueError::Schema(_))
    ));
}

#[test]
fn manifest_missing_kind_is_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiue/component :app/x}"),
        Err(AiueError::Schema(_))
    ));
}

#[test]
fn manifest_unknown_kind_is_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiue/component :x/y :aiue/kind :wizard}"),
        Err(AiueError::Schema(_))
    ));
}

#[test]
fn manifest_unknown_trust_is_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiue/component :x/y :aiue/kind :app :aiue/trust :godmode}"),
        Err(AiueError::Schema(_))
    ));
}

#[test]
fn manifest_bad_edn_is_parse_error() {
    assert!(matches!(
        Manifest::parse_str("{:aiue/component"),
        Err(AiueError::Edn(_))
    ));
}

#[test]
fn manifest_defaults_kernel_extension_to_trusted() {
    let m = Manifest::parse_str("{:aiue/component :k/x :aiue/kind :kernel-extension}").unwrap();
    assert_eq!(m.trust, Trust::Trusted);
    assert_eq!(m.kind, Kind::KernelExtension);
}

#[test]
fn manifest_applies_default_limits_and_entry() {
    let m = Manifest::parse_str("{:aiue/component :app/x :aiue/kind :app}").unwrap();
    assert_eq!(m.limits.memory_pages, 16);
    assert_eq!(m.limits.fuel, 10_000_000);
    assert_eq!(m.entry, "main");
    assert!(m.args.is_empty());
    assert_eq!(m.trust, Trust::Untrusted);
}

#[test]
fn manifest_partial_limits_keep_defaults_for_missing_keys() {
    // Only memory-pages given → fuel falls back to the default.
    let m =
        Manifest::parse_str("{:aiue/component :a/x :aiue/kind :app :aiue/limits {:memory-pages 4}}")
            .unwrap();
    assert_eq!(m.limits.memory_pages, 4);
    assert_eq!(m.limits.fuel, 10_000_000);
}

// ---------------------------------------------------------------------------
// policy: from_edn extends the defaults
// ---------------------------------------------------------------------------

fn policy(src: &str) -> Policy {
    Policy::from_edn(&kotoba_edn::parse(src).unwrap()).unwrap()
}

#[test]
fn policy_kernel_caps_extend_defaults() {
    let p = policy("{:aiue/kernel-caps #{:gpu/render}}");
    assert!(p.kernel_caps.contains("gpu/render"), "added cap present");
    assert!(p.kernel_caps.contains("log/write"), "default cap retained");
}

#[test]
fn policy_grants_are_merged_per_component() {
    let p = policy("{:aiue/grants {:driver/x #{:iommu :dma/map}}}");
    let g = p.grants.get("driver/x").expect("grant present");
    assert!(g.contains("iommu") && g.contains("dma/map"));
}

#[test]
fn policy_forbid_overrides_a_trust_level() {
    let p = policy("{:aiue/forbid {:untrusted #{:network :secrets}}}");
    let f = p.forbid_effects.get(&Trust::Untrusted).unwrap();
    assert!(f.contains("network") && f.contains("secrets"));
}

#[test]
fn policy_default_locks_down_ai_generated() {
    let p = Policy::default();
    let f = p.forbid_effects.get(&Trust::AiGenerated).unwrap();
    for eff in ["network", "secrets", "persistent-write"] {
        assert!(f.contains(eff), "ai-generated must forbid {eff}");
    }
}

// ---------------------------------------------------------------------------
// audit: append → read round-trip
// ---------------------------------------------------------------------------

#[test]
fn audit_round_trips_entries() {
    let path = std::env::temp_dir().join("aiueos-audit-roundtrip.edn");
    let _ = std::fs::remove_file(&path);
    let log = AuditLog::new(&path);
    log.append(Event::Grant, "app/x", "caps: log/write").unwrap();
    log.append(Event::Deny, "driver/y", "[dma-without-iommu] no grant").unwrap();

    let entries = log.read().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(edn::get_kw(&entries[0], "aiue", "event").as_deref(), Some("grant"));
    assert_eq!(
        edn::get_str(&entries[1], "aiue", "component").as_deref(),
        Some("driver/y")
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn audit_read_missing_file_is_empty() {
    let path = std::env::temp_dir().join("aiueos-audit-does-not-exist-xyz.edn");
    let _ = std::fs::remove_file(&path);
    assert!(AuditLog::new(&path).read().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// safe-kotoba subset edge cases
// ---------------------------------------------------------------------------

#[test]
fn safe_accepts_a_multi_form_pure_program() {
    let src = "(def x 10)\n(defn f [n] (+ n x))\n(defn g [n] (if (< n 0) 0 (f n)))";
    assert!(safe::check(src).is_ok());
}

#[test]
fn safe_rejects_dotted_host_class() {
    // Bare dotted class symbol (no `/`) — previously slipped through.
    assert!(matches!(
        safe::check("(defn f [] (java.util.ArrayList.))"),
        Err(AiueError::Unsafe(_))
    ));
}

#[test]
fn safe_rejects_namespaced_host_static() {
    // `System/exit` — namespace `System`.
    assert!(matches!(
        safe::check("(defn f [] (System/exit 1))"),
        Err(AiueError::Unsafe(_))
    ));
}

#[test]
fn safe_does_not_flag_innocent_lookalikes() {
    // `javascript` and `systemd-thing` are not under any denied root.
    assert!(safe::check("(defn f [javascript systemic] (+ javascript systemic))").is_ok());
}

// ---------------------------------------------------------------------------
// edn helpers
// ---------------------------------------------------------------------------

#[test]
fn edn_kw_collection_sorts_and_dedups_from_vector_or_set() {
    let v = kotoba_edn::parse("[:b/x :a/y :b/x]").unwrap();
    assert_eq!(edn::kw_collection(Some(&v)), vec!["a/y", "b/x"]);
    let s = kotoba_edn::parse("#{:a/y :b/x}").unwrap();
    assert_eq!(edn::kw_collection(Some(&s)), vec!["a/y", "b/x"]);
    assert!(edn::kw_collection(None).is_empty());
}
