//! Deployment surfaces (ADR-0005). The same component+manifest+capability model
//! runs on edge, robotics, cloud, browser, client — but the *capabilities a
//! surface can back* differ. A surface is, at the policy level, the set of
//! capability names it offers a provider for; `Policy::granted_to` intersects the
//! kernel caps with this set, so an import resolves to a kernel cap **only if the
//! active surface offers it** — a missing provider is a loud `unresolved-capability`
//! denial, never a silent no-op.
//!
//! This module is the **registry**: a [`Surface`] is data — a map of capability →
//! [`Provider`] — so the offered set, the policy intersection, and `aiueos surface
//! inspect` all read one source of truth. `src/host.rs` implements the actual
//! host-function closures behind these providers and installs them from this
//! registry.

use std::collections::{BTreeMap, BTreeSet};

/// One host-function provider: the `aiueos:host` import a component calls plus the
/// capability it is gated on. The declarative half of a provider — what a surface
/// offers and under which capability. The closure itself is bound in `src/host.rs`,
/// where every call still passes `gate(ctx, cap, name)` first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The host import the wasm calls, e.g. `"dom-render"`.
    pub name: &'static str,
    /// The capability `gate()` checks before the closure runs, e.g. `"dom/render"`.
    pub cap: &'static str,
}

const fn p(name: &'static str, cap: &'static str) -> Provider {
    Provider { name, cap }
}

/// A deployment target: the capabilities it *offers* and the provider behind each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surface {
    id: String,
    providers: BTreeMap<String, Provider>, // host import name -> provider
}

impl Surface {
    fn of(id: &str, providers: &[Provider]) -> Surface {
        Surface {
            id: id.to_string(),
            providers: providers
                .iter()
                .map(|pr| (pr.name.to_string(), pr.clone()))
                .collect(),
        }
    }

    /// The in-process robot — the only surface with real host providers today: the
    /// topic bus, clock/log/random, plus the device-broker primitives (ADR-0001).
    pub fn robot() -> Surface {
        Surface::of(
            "robot",
            &[
                p("publish", "topic/publish"),
                p("poll", "topic/subscribe"),
                p("take", "topic/subscribe"),
                p("count", "topic/subscribe"),
                p("clock", "clock/monotonic"),
                p("log", "log/write"),
                p("random", "random/bytes"),
                p("pci-config", "pci/config"),
                p("dma-map", "dma/map"),
                p("irq-subscribe", "irq/subscribe"),
                p("mmio-map", "mmio/map"),
            ],
        )
    }

    /// The browser surface: DOM render/event shims over the host page, a Phase-0
    /// input event FIFO, framebuffer present log, plus a `fetch` broker.
    pub fn browser() -> Surface {
        Surface::of(
            "browser",
            &[
                p("dom-render", "dom/render"),
                p("dom-event", "dom/event"),
                p("input-event", "input/event"),
                p("fb-present", "framebuffer/present"),
                p("fetch", "net/fetch"),
                p("log", "log/write"),
                p("clock", "clock/monotonic"),
            ],
        )
    }

    /// The cloud surface: a KV store broker + a socket/HTTP `fetch` broker.
    pub fn cloud() -> Surface {
        Surface::of(
            "cloud",
            &[
                p("kv-set", "storage/kv"),
                p("kv-get", "storage/kv"),
                p("fetch", "net/fetch"),
                p("log", "log/write"),
                p("clock", "clock/monotonic"),
                p("random", "random/bytes"),
            ],
        )
    }

    /// Look up a known surface by id, or `None` for an id aiueos doesn't know.
    /// Keep the arms in sync with the ADR-0005 table.
    pub fn by_id(id: &str) -> Option<Surface> {
        Some(match id {
            "robot" => Surface::robot(),
            "browser" => Surface::browser(),
            "cloud" => Surface::cloud(),
            _ => return None,
        })
    }

    /// This surface's id (`"robot" | "browser" | "cloud"`, or a composed id).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The capabilities this surface can back — generalizes `kernel_caps`.
    pub fn offered(&self) -> BTreeSet<String> {
        self.providers.values().map(|p| p.cap.to_string()).collect()
    }

    /// The providers, ordered by capability.
    pub fn providers(&self) -> impl Iterator<Item = &Provider> {
        self.providers.values()
    }

    /// The provider backing `cap` on this surface, if any.
    pub fn provider(&self, cap: &str) -> Option<&Provider> {
        self.providers.values().find(|p| p.cap == cap)
    }

    /// The provider for a specific `aiueos:host` import name, if this surface
    /// installs it.
    pub fn provider_by_name(&self, name: &str) -> Option<&Provider> {
        self.providers.get(name)
    }

    /// Compose two surfaces (e.g. an edge gateway = robot ∪ cloud). Where both
    /// back a capability, `self`'s provider wins.
    pub fn union(&self, other: &Surface) -> Surface {
        let mut providers = other.providers.clone();
        providers.extend(self.providers.clone());
        Surface {
            id: format!("{}+{}", self.id, other.id),
            providers,
        }
    }
}

/// The capabilities a known surface can back, or `None` for an unknown surface id.
/// A thin wrapper over the [`Surface`] registry so policy and tooling share one
/// source of truth.
pub fn offered(id: &str) -> Option<BTreeSet<String>> {
    Surface::by_id(id).map(|s| s.offered())
}

/// Whether `id` names a surface aiueos knows (so its offered set is defined).
pub fn is_known(id: &str) -> bool {
    Surface::by_id(id).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_surfaces_offer_caps_and_unknown_is_none() {
        assert!(offered("robot").unwrap().contains("topic/publish"));
        assert!(offered("browser").unwrap().contains("dom/render"));
        assert!(!offered("browser").unwrap().contains("topic/publish"));
        assert_eq!(offered("teapot"), None);
        assert!(is_known("cloud") && !is_known("teapot"));
    }

    #[test]
    fn offered_set_matches_the_registered_providers() {
        let browser = Surface::browser();
        let offered = browser.offered();
        // Every offered cap has a provider, and the provider names its host import.
        for cap in &offered {
            assert!(browser.provider(cap).is_some());
        }
        assert_eq!(browser.provider("dom/render").unwrap().name, "dom-render");
        assert_eq!(browser.provider("dom/event").unwrap().name, "dom-event");
        assert_eq!(
            browser.provider("framebuffer/present").unwrap().name,
            "fb-present"
        );
        assert_eq!(browser.provider("input/event").unwrap().name, "input-event");
        assert_eq!(
            browser.provider_by_name("fb-present").unwrap().cap,
            "framebuffer/present"
        );
        // The free `offered(id)` wrapper agrees with the registry value.
        assert_eq!(super::offered("browser").unwrap(), offered);
    }

    #[test]
    fn a_capability_can_have_multiple_host_imports() {
        let robot = Surface::robot();
        assert!(robot.offered().contains("topic/subscribe"));
        assert_eq!(
            robot.provider_by_name("poll").unwrap().cap,
            "topic/subscribe"
        );
        assert_eq!(
            robot.provider_by_name("take").unwrap().cap,
            "topic/subscribe"
        );
        assert_eq!(
            robot.provider_by_name("count").unwrap().cap,
            "topic/subscribe"
        );

        let cloud = Surface::cloud();
        assert!(cloud.offered().contains("storage/kv"));
        assert_eq!(cloud.provider_by_name("kv-set").unwrap().cap, "storage/kv");
        assert_eq!(cloud.provider_by_name("kv-get").unwrap().cap, "storage/kv");
    }

    #[test]
    fn a_surface_does_not_offer_another_surfaces_caps() {
        // The robot has no DOM; the browser has no device IO. This is the
        // "the host refuses to provide what that surface shouldn't" rule as data.
        assert!(Surface::robot().provider("dom/render").is_none());
        assert!(Surface::browser().provider("pci/config").is_none());
        assert!(Surface::cloud().provider("dom/event").is_none());
    }

    #[test]
    fn union_composes_offered_sets_with_self_winning() {
        let edge = Surface::robot().union(&Surface::cloud());
        // Edge gateway backs both the bus and the KV store.
        assert!(edge.offered().contains("topic/publish"));
        assert!(edge.offered().contains("storage/kv"));
        assert_eq!(edge.id(), "robot+cloud");
        // A shared cap (log/write) resolves to the left (robot) provider.
        assert_eq!(edge.provider("log/write").unwrap().name, "log");
    }
}
