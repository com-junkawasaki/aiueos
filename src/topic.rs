//! The topic bus — aiueos's in-process publish/subscribe substrate, the ROS-topic
//! analogue. Components don't share memory or call each other directly: a
//! producer `publish`es an i64 sample to a numeric topic id, a consumer `poll`s
//! the latest value. Both go through the broker-mediated host ABI (see
//! [`crate::host`]), so every publish/poll is capability-gated and audited.
//!
//! Phase-0 keeps it deliberately small: latest-value semantics (last write wins)
//! + a per-topic publish count, numeric topic ids, i64 payloads. Queued history,
//! typed messages and named topics are later phases.

use std::collections::BTreeMap;

/// A numeric topic identifier. Phase-0 uses integers; named topics with their own
/// per-topic capabilities (`topic/scan`, `topic/cmd`) are a later refinement that
/// would also make topic wiring show up as capability-graph edges.
pub type TopicId = i32;

#[derive(Debug, Default, Clone)]
pub struct TopicBus {
    latest: BTreeMap<TopicId, i64>,
    counts: BTreeMap<TopicId, u64>,
}

impl TopicBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `value` to `topic` (last write wins) and bump its publish count.
    pub fn publish(&mut self, topic: TopicId, value: i64) {
        self.latest.insert(topic, value);
        *self.counts.entry(topic).or_insert(0) += 1;
    }

    /// The most recent value on `topic`, or `None` if nothing was ever published.
    pub fn latest(&self, topic: TopicId) -> Option<i64> {
        self.latest.get(&topic).copied()
    }

    /// How many times `topic` has been published to.
    pub fn count(&self, topic: TopicId) -> u64 {
        self.counts.get(&topic).copied().unwrap_or(0)
    }

    /// Topics that currently hold a value.
    pub fn topics(&self) -> impl Iterator<Item = TopicId> + '_ {
        self.latest.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_sets_latest_and_counts() {
        let mut bus = TopicBus::new();
        assert_eq!(bus.latest(1), None);
        assert_eq!(bus.count(1), 0);

        bus.publish(1, 10);
        bus.publish(1, 20);
        assert_eq!(bus.latest(1), Some(20), "last write wins");
        assert_eq!(bus.count(1), 2);
    }

    #[test]
    fn topics_are_independent() {
        let mut bus = TopicBus::new();
        bus.publish(1, 100);
        bus.publish(2, 200);
        assert_eq!(bus.latest(1), Some(100));
        assert_eq!(bus.latest(2), Some(200));
        assert_eq!(bus.latest(3), None);
        let mut ts: Vec<_> = bus.topics().collect();
        ts.sort();
        assert_eq!(ts, vec![1, 2]);
    }
}
