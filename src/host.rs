//! The broker-mediated host ABI (`aiueos:host`). This is where capabilities stop
//! being a static manifest claim and become **runtime enforcement**: a component
//! can only call a host function if its conferred capability set contains the
//! matching capability. A call without the capability *traps* — it does not
//! cooperate, it cannot proceed.
//!
//! The ABI is intentionally numeric (no linear-memory marshaling) for Phase-0:
//!
//! | import                | capability         | meaning                          |
//! |-----------------------|--------------------|----------------------------------|
//! | `log(i64)`            | `log/write`        | emit an i64 log sample           |
//! | `clock() -> i64`      | `clock/monotonic`  | monotonic cycle (control loop)   |
//! | `random() -> i64`     | `random/bytes`     | deterministic pseudo-random      |
//! | `publish(i32, i64)`   | `topic/publish`    | publish a sample to a topic      |
//! | `poll(i32) -> i64`    | `topic/subscribe`  | latest sample on a topic         |
//! | `count(i32) -> i64`   | `topic/subscribe`  | #samples published to a topic    |
//! | `take(i32) -> i64`    | `topic/subscribe`  | pop oldest unread sample (FIFO)  |
//!
//! `poll` of an empty topic returns [`EMPTY`]. The topic bus is threaded *by
//! value* through each run so the broker can pass one bus across a whole booted
//! system — producer → consumer dataflow without shared mutable state.

use crate::error::{AiueosError, Result};
use crate::topic::TopicBus;
use std::collections::{BTreeMap, BTreeSet};
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Val, ValType,
};

type KqeKey = (String, String, String);

/// In-process KQE graph state threaded by the broker across component launches.
/// Objects are raw CBOR/list<u8> bytes as exposed by the kotoba:kais ABI.
#[derive(Debug, Clone, Default)]
pub struct KqeStore {
    quads: BTreeMap<KqeKey, Vec<Vec<u8>>>,
}

/// Returned by `poll` when a topic has never been published to.
pub const EMPTY: i64 = i64::MIN;

/// Per-topic access restriction. `None` means unrestricted (any topic id);
/// `Some(set)` restricts to exactly those topic ids — so a component can only
/// publish to / read the topics it declared, not another node's topics.
#[derive(Debug, Clone, Default)]
pub struct TopicAccess {
    pub publish: Option<BTreeSet<i32>>,
    pub subscribe: Option<BTreeSet<i32>>,
}

impl TopicAccess {
    /// No per-topic restriction (only the coarse capability gate applies).
    pub fn unrestricted() -> Self {
        Self::default()
    }
}

fn topic_ok(set: &Option<BTreeSet<i32>>, topic: i32) -> bool {
    set.as_ref().map_or(true, |s| s.contains(&topic))
}

/// FNV-1a over `bytes`, continuing from `h`.
fn fnv1a(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// A deterministic per-run seed from the run signature (entry + args + caps).
/// Distinct components → distinct seeds → independent `random()` streams; two
/// truly identical runs share a stream (they're indistinguishable). `caps` is a
/// BTreeSet, so iteration order is stable.
fn run_seed(entry: &str, args: &[i64], caps: &BTreeSet<String>) -> u64 {
    let mut h = fnv1a(0xcbf2_9ce4_8422_2325, entry.as_bytes());
    for a in args {
        h = fnv1a(h, &a.to_le_bytes());
    }
    for c in caps {
        h = fnv1a(h, c.as_bytes());
    }
    h
}

/// What a host call costs against the per-cycle quota (ADR-0006).
enum Charge {
    /// An ordinary gated host call.
    Call,
    /// A `publish`, which also draws on the separate publish budget.
    Publish,
}

/// Charge one host call against the component's per-cycle quota, trapping if the
/// budget is exhausted — so an over-quota call fails exactly like an ungranted
/// capability or an undeclared topic. Increments the call counter.
fn charge(ctx: &mut HostCtx, kind: Charge) -> anyhow::Result<()> {
    ctx.calls += 1;
    if ctx.calls as u64 > ctx.quota.host_calls {
        anyhow::bail!(
            "host-call quota exceeded ({} per cycle)",
            ctx.quota.host_calls
        );
    }
    if matches!(kind, Charge::Publish) {
        ctx.publishes += 1;
        if ctx.publishes > ctx.quota.publishes {
            anyhow::bail!("publish quota exceeded ({} per cycle)", ctx.quota.publishes);
        }
    }
    Ok(())
}

/// splitmix64 — a fast, well-distributed mixing function. Used to make `random()`
/// deterministic-yet-varied from a seed (reproducible Phase-0 randomness).
fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The store context every host call sees: the conferred capabilities (the gate),
/// the topic bus, the per-topic restriction, and call/log accounting.
pub struct HostCtx {
    limits: StoreLimits,
    caps: BTreeSet<String>,
    topics: TopicAccess,
    bus: TopicBus,
    logs: Vec<i64>,
    calls: usize,
    /// Per-cycle host-call quota (ADR-0006) and the publish sub-counter.
    quota: crate::manifest::Quota,
    publishes: u64,
    /// Per-run base seed for `random()` — derived from the run signature
    /// (entry + args + caps) so distinct components draw *independent* streams
    /// rather than the same value at the same cycle.
    seed: u64,
    /// KQE graph state for kotoba:kais host calls, threaded by the broker across
    /// component launches like TopicBus.
    kqe: KqeStore,
}

/// What a host-enabled run produced.
pub struct HostOutcome {
    pub result: i64,
    pub logs: Vec<i64>,
    pub host_calls: usize,
    /// The bus after this component ran — pass it to the next component.
    pub bus: TopicBus,
    /// The KQE store after this component ran — pass it to the next component.
    pub kqe: KqeStore,
}

fn run_err(e: impl std::fmt::Display) -> AiueosError {
    AiueosError::Run(e.to_string())
}

/// The capability gate. Returns a trap (host error) when `cap` isn't granted.
fn gate(ctx: &HostCtx, cap: &str, what: &str) -> anyhow::Result<()> {
    if ctx.caps.contains(cap) {
        Ok(())
    } else {
        anyhow::bail!("capability `{cap}` not granted — host call `{what}` denied")
    }
}

fn gate_target(ctx: &HostCtx, prefix: &str, target: &str, what: &str) -> anyhow::Result<()> {
    if ctx.caps.contains(&format!("{prefix}{target}")) || ctx.caps.contains(&format!("{prefix}*")) {
        Ok(())
    } else {
        anyhow::bail!("capability `{prefix}{target}` not granted — host call `{what}` denied")
    }
}

fn has_target(ctx: &HostCtx, prefix: &str, target: &str) -> bool {
    ctx.caps.contains(&format!("{prefix}{target}")) || ctx.caps.contains(&format!("{prefix}*"))
}

fn gate_class(ctx: &HostCtx, prefix: &str, what: &str) -> anyhow::Result<()> {
    if ctx
        .caps
        .iter()
        .any(|cap| cap.strip_prefix(prefix).is_some())
    {
        Ok(())
    } else {
        anyhow::bail!("capability `{prefix}<target>` not granted — host call `{what}` denied")
    }
}

fn memory(c: &mut Caller<'_, HostCtx>) -> anyhow::Result<wasmtime::Memory> {
    c.get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| anyhow::anyhow!("guest exports no memory"))
}

fn check_range(ptr: i32, len: i32) -> anyhow::Result<(usize, usize)> {
    if ptr < 0 || len < 0 {
        anyhow::bail!("negative guest pointer/length");
    }
    let start = ptr as usize;
    let len = len as usize;
    let end = start
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("guest pointer range overflow"))?;
    Ok((start, end))
}

fn read_guest_bytes(c: &mut Caller<'_, HostCtx>, ptr: i32, len: i32) -> anyhow::Result<Vec<u8>> {
    let (start, end) = check_range(ptr, len)?;
    let mem = memory(c)?;
    let data = mem.data(&mut *c);
    if end > data.len() {
        anyhow::bail!("guest memory read out of bounds");
    }
    Ok(data[start..end].to_vec())
}

fn read_guest_string(c: &mut Caller<'_, HostCtx>, ptr: i32, len: i32) -> anyhow::Result<String> {
    let bytes = read_guest_bytes(c, ptr, len)?;
    String::from_utf8(bytes).map_err(|e| anyhow::anyhow!("guest string is not utf-8: {e}"))
}

fn write_guest_bytes(c: &mut Caller<'_, HostCtx>, ptr: i32, bytes: &[u8]) -> anyhow::Result<()> {
    let (start, end) = check_range(ptr, bytes.len() as i32)?;
    let mem = memory(c)?;
    let data = mem.data_mut(&mut *c);
    if end > data.len() {
        anyhow::bail!("guest memory write out of bounds");
    }
    data[start..end].copy_from_slice(bytes);
    Ok(())
}

fn write_guest_u8(c: &mut Caller<'_, HostCtx>, ptr: i32, value: u8) -> anyhow::Result<()> {
    write_guest_bytes(c, ptr, &[value])
}

fn write_guest_i32(c: &mut Caller<'_, HostCtx>, ptr: i32, value: i32) -> anyhow::Result<()> {
    write_guest_bytes(c, ptr, &value.to_le_bytes())
}

fn guest_alloc(c: &mut Caller<'_, HostCtx>, len: usize, align: i32) -> anyhow::Result<i32> {
    if len == 0 {
        return Ok(0);
    }
    let realloc = c
        .get_export("cabi_realloc")
        .and_then(|e| e.into_func())
        .ok_or_else(|| anyhow::anyhow!("guest exports no cabi_realloc"))?;
    let mut results = [Val::I32(0)];
    realloc.call(
        &mut *c,
        &[
            Val::I32(0),
            Val::I32(0),
            Val::I32(align),
            Val::I32(len as i32),
        ],
        &mut results,
    )?;
    match results[0] {
        Val::I32(ptr) => Ok(ptr),
        ref other => anyhow::bail!("cabi_realloc returned unexpected value {other:?}"),
    }
}

fn guest_alloc_bytes(c: &mut Caller<'_, HostCtx>, bytes: &[u8]) -> anyhow::Result<i32> {
    let ptr = guest_alloc(c, bytes.len(), 1)?;
    if !bytes.is_empty() {
        write_guest_bytes(c, ptr, bytes)?;
    }
    Ok(ptr)
}

/// Instantiate `wasm` (binary or WAT text) with the `aiueos:host` ABI bound, run
/// `entry(args)` under fuel + memory limits with `caps` gating every host call,
/// threading `bus` through. A denied host call traps and surfaces as
/// [`AiueosError::Run`]. No per-topic restriction — see [`run_with_host_restricted`].
pub fn run_with_host(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
) -> Result<HostOutcome> {
    run_with_host_restricted(
        wasm,
        entry,
        args,
        fuel,
        memory_pages,
        caps,
        bus,
        &TopicAccess::unrestricted(),
        crate::manifest::Quota::default(),
    )
}

/// Like [`run_with_host`], but additionally restricts which topic ids the
/// component may publish to / read, per `topics`. A publish/poll/take/count to a
/// topic outside the declared set traps even when the coarse capability is held.
#[allow(clippy::too_many_arguments)]
pub fn run_with_host_restricted(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
    topics: &TopicAccess,
    quota: crate::manifest::Quota,
) -> Result<HostOutcome> {
    run_with_host_restricted_with_kqe(
        wasm,
        entry,
        args,
        fuel,
        memory_pages,
        caps,
        bus,
        KqeStore::default(),
        topics,
        quota,
    )
}

/// Like [`run_with_host_restricted`], but also threads KQE graph state across
/// component launches.
#[allow(clippy::too_many_arguments)]
pub fn run_with_host_restricted_with_kqe(
    wasm: &[u8],
    entry: &str,
    args: &[i64],
    fuel: u64,
    memory_pages: u32,
    caps: &BTreeSet<String>,
    bus: TopicBus,
    kqe: KqeStore,
    topics: &TopicAccess,
    quota: crate::manifest::Quota,
) -> Result<HostOutcome> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(run_err)?;
    // Module::new accepts a binary module or WAT text (wasmtime's default `wat`).
    let module = Module::new(&engine, wasm).map_err(run_err)?;

    let mut linker: Linker<HostCtx> = Linker::new(&engine);
    linker
        .func_wrap(
            "aiueos:host",
            "log",
            |mut c: Caller<'_, HostCtx>, v: i64| -> anyhow::Result<()> {
                gate(c.data(), "log/write", "log")?;
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                d.logs.push(v);
                Ok(())
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "clock",
            |mut c: Caller<'_, HostCtx>| -> anyhow::Result<i64> {
                gate(c.data(), "clock/monotonic", "clock")?;
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                Ok(d.bus.tick() as i64) // monotonic control-loop cycle (Phase-0 stand-in)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "random",
            |mut c: Caller<'_, HostCtx>| -> anyhow::Result<i64> {
                gate(c.data(), "random/bytes", "random")?;
                // Deterministic (reproducible) pseudo-random: splitmix64 over the
                // per-run seed + control-loop cycle + this run's call index. Same
                // run + same cycle + same call order → same stream, by design
                // (Phase-0 determinism); distinct components → independent streams.
                // NOT a CSPRNG — predictable; never use for keys/nonces/secrets.
                let d = c.data_mut();
                // seed uses the pre-charge call index (unchanged determinism)
                let mixed = d
                    .seed
                    .wrapping_add(d.bus.tick().wrapping_mul(0x9E37_79B9_7F4A_7C15))
                    .wrapping_add(d.calls as u64);
                charge(d, Charge::Call)?;
                Ok(splitmix64(mixed) as i64)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "publish",
            |mut c: Caller<'_, HostCtx>, topic: i32, value: i64| -> anyhow::Result<()> {
                gate(c.data(), "topic/publish", "publish")?;
                if !topic_ok(&c.data().topics.publish, topic) {
                    anyhow::bail!("topic {topic} not in this component's :aiueos/publishes set");
                }
                let d = c.data_mut();
                charge(d, Charge::Publish)?;
                d.bus.publish(topic, value);
                Ok(())
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "poll",
            |mut c: Caller<'_, HostCtx>, topic: i32| -> anyhow::Result<i64> {
                gate(c.data(), "topic/subscribe", "poll")?;
                if !topic_ok(&c.data().topics.subscribe, topic) {
                    anyhow::bail!("topic {topic} not in this component's :aiueos/subscribes set");
                }
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                Ok(d.bus.latest(topic).unwrap_or(EMPTY))
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "count",
            |mut c: Caller<'_, HostCtx>, topic: i32| -> anyhow::Result<i64> {
                // how many samples have been published to `topic` — lets a
                // consumer notice missed/extra readings. Same capability as poll.
                gate(c.data(), "topic/subscribe", "count")?;
                if !topic_ok(&c.data().topics.subscribe, topic) {
                    anyhow::bail!("topic {topic} not in this component's :aiueos/subscribes set");
                }
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                Ok(d.bus.count(topic) as i64)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "aiueos:host",
            "take",
            |mut c: Caller<'_, HostCtx>, topic: i32| -> anyhow::Result<i64> {
                // pop the oldest unread sample (FIFO) so a consumer never misses
                // one; EMPTY when drained. Same capability as poll.
                gate(c.data(), "topic/subscribe", "take")?;
                if !topic_ok(&c.data().topics.subscribe, topic) {
                    anyhow::bail!("topic {topic} not in this component's :aiueos/subscribes set");
                }
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                Ok(d.bus.take(topic).unwrap_or(EMPTY))
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/auth@0.1.0",
            "has-capability",
            |mut c: Caller<'_, HostCtx>,
             resource_ptr: i32,
             resource_len: i32,
             ability_ptr: i32,
             ability_len: i32|
             -> anyhow::Result<i32> {
                gate(c.data(), "kotoba.auth/self", "has-capability")?;
                let resource = read_guest_string(&mut c, resource_ptr, resource_len)?;
                let ability = read_guest_string(&mut c, ability_ptr, ability_len)?;
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                let cap = format!("{resource}/{ability}");
                Ok((d.caps.contains(&cap) || d.caps.contains(&format!("{resource}/*"))) as i32)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/kqe@0.1.0",
            "assert-quad",
            |mut c: Caller<'_, HostCtx>,
             g_ptr: i32,
             g_len: i32,
             s_ptr: i32,
             s_len: i32,
             p_ptr: i32,
             p_len: i32,
             o_ptr: i32,
             o_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let graph = read_guest_string(&mut c, g_ptr, g_len)?;
                let subject = read_guest_string(&mut c, s_ptr, s_len)?;
                let predicate = read_guest_string(&mut c, p_ptr, p_len)?;
                let object = read_guest_bytes(&mut c, o_ptr, o_len)?;
                gate_target(c.data(), "kotoba.graph-write/", &graph, "assert-quad")?;
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                d.kqe
                    .quads
                    .entry((graph, subject, predicate))
                    .or_default()
                    .push(object);
                write_guest_u8(&mut c, ret, 0)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/kqe@0.1.0",
            "retract-quad",
            |mut c: Caller<'_, HostCtx>,
             g_ptr: i32,
             g_len: i32,
             s_ptr: i32,
             s_len: i32,
             p_ptr: i32,
             p_len: i32,
             o_ptr: i32,
             o_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let graph = read_guest_string(&mut c, g_ptr, g_len)?;
                let subject = read_guest_string(&mut c, s_ptr, s_len)?;
                let predicate = read_guest_string(&mut c, p_ptr, p_len)?;
                let object = read_guest_bytes(&mut c, o_ptr, o_len)?;
                gate_target(c.data(), "kotoba.graph-write/", &graph, "retract-quad")?;
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                if let Some(objects) = d.kqe.quads.get_mut(&(graph, subject, predicate)) {
                    objects.retain(|existing| existing != &object);
                }
                write_guest_u8(&mut c, ret, 0)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/kqe@0.1.0",
            "get-objects",
            |mut c: Caller<'_, HostCtx>,
             g_ptr: i32,
             g_len: i32,
             s_ptr: i32,
             s_len: i32,
             p_ptr: i32,
             p_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let graph = read_guest_string(&mut c, g_ptr, g_len)?;
                let subject = read_guest_string(&mut c, s_ptr, s_len)?;
                let predicate = read_guest_string(&mut c, p_ptr, p_len)?;
                gate_target(c.data(), "kotoba.graph-read/", &graph, "get-objects")?;
                {
                    let d = c.data_mut();
                    charge(d, Charge::Call)?;
                }
                let objects = c
                    .data()
                    .kqe
                    .quads
                    .get(&(graph, subject, predicate))
                    .cloned()
                    .unwrap_or_default();
                let array_ptr = guest_alloc(&mut c, objects.len() * 8, 4)?;
                for (i, object) in objects.iter().enumerate() {
                    let ptr = guest_alloc_bytes(&mut c, object)?;
                    let base = array_ptr + (i * 8) as i32;
                    write_guest_i32(&mut c, base, ptr)?;
                    write_guest_i32(&mut c, base + 4, object.len() as i32)?;
                }
                write_guest_i32(&mut c, ret, array_ptr)?;
                write_guest_i32(&mut c, ret + 4, objects.len() as i32)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/kqe@0.1.0",
            "query",
            |mut c: Caller<'_, HostCtx>,
             filter_ptr: i32,
             filter_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let _filter = read_guest_string(&mut c, filter_ptr, filter_len)?;
                gate_class(c.data(), "kotoba.graph-read/", "query")?;
                {
                    let d = c.data_mut();
                    charge(d, Charge::Call)?;
                }
                let quads: Vec<(String, String, String, Vec<u8>)> = c
                    .data()
                    .kqe
                    .quads
                    .iter()
                    .filter(|((graph, _, _), _)| has_target(c.data(), "kotoba.graph-read/", graph))
                    .flat_map(|((graph, subject, predicate), objects)| {
                        objects.iter().cloned().map(|object| {
                            (graph.clone(), subject.clone(), predicate.clone(), object)
                        })
                    })
                    .collect();
                let array_ptr = guest_alloc(&mut c, quads.len() * 32, 4)?;
                for (i, (graph, subject, predicate, object)) in quads.iter().enumerate() {
                    let graph_ptr = guest_alloc_bytes(&mut c, graph.as_bytes())?;
                    let subject_ptr = guest_alloc_bytes(&mut c, subject.as_bytes())?;
                    let predicate_ptr = guest_alloc_bytes(&mut c, predicate.as_bytes())?;
                    let object_ptr = guest_alloc_bytes(&mut c, object)?;
                    let base = array_ptr + (i * 32) as i32;
                    write_guest_i32(&mut c, base, graph_ptr)?;
                    write_guest_i32(&mut c, base + 4, graph.len() as i32)?;
                    write_guest_i32(&mut c, base + 8, subject_ptr)?;
                    write_guest_i32(&mut c, base + 12, subject.len() as i32)?;
                    write_guest_i32(&mut c, base + 16, predicate_ptr)?;
                    write_guest_i32(&mut c, base + 20, predicate.len() as i32)?;
                    write_guest_i32(&mut c, base + 24, object_ptr)?;
                    write_guest_i32(&mut c, base + 28, object.len() as i32)?;
                }
                write_guest_u8(&mut c, ret, 0)?;
                write_guest_i32(&mut c, ret + 4, array_ptr)?;
                write_guest_i32(&mut c, ret + 8, quads.len() as i32)
            },
        )
        .map_err(run_err)?;
    linker
        .func_wrap(
            "kotoba:kais/llm@0.1.0",
            "infer",
            |mut c: Caller<'_, HostCtx>,
             model_ptr: i32,
             model_len: i32,
             prompt_ptr: i32,
             prompt_len: i32,
             ret: i32|
             -> anyhow::Result<()> {
                let model = read_guest_string(&mut c, model_ptr, model_len)?;
                let _prompt = read_guest_bytes(&mut c, prompt_ptr, prompt_len)?;
                gate_target(c.data(), "kotoba.infer/", &model, "infer")?;
                let d = c.data_mut();
                charge(d, Charge::Call)?;
                // No model provider is wired into aiueos yet. Return an ok empty
                // payload so the ABI is executable without granting ambient LLM IO.
                write_guest_u8(&mut c, ret, 0)?;
                write_guest_i32(&mut c, ret + 4, 0)?;
                write_guest_i32(&mut c, ret + 8, 0)
            },
        )
        .map_err(run_err)?;

    let limits = StoreLimitsBuilder::new()
        .memory_size(memory_pages as usize * 64 * 1024)
        .build();
    let ctx = HostCtx {
        limits,
        caps: caps.clone(),
        topics: topics.clone(),
        bus,
        logs: Vec::new(),
        calls: 0,
        quota,
        publishes: 0,
        seed: run_seed(entry, args, caps),
        kqe,
    };
    let mut store = Store::new(&engine, ctx);
    store.limiter(|c| &mut c.limits);
    store.set_fuel(fuel).map_err(run_err)?;

    let instance = linker.instantiate(&mut store, &module).map_err(run_err)?;
    let f = instance
        .get_func(&mut store, entry)
        .ok_or_else(|| AiueosError::Run(format!("module has no exported function `{entry}`")))?;

    let ty = f.ty(&store);
    let params: Vec<Val> = ty
        .params()
        .enumerate()
        .map(|(i, t)| {
            let a = args.get(i).copied().unwrap_or(0);
            match t {
                ValType::I32 => Val::I32(a as i32),
                _ => Val::I64(a),
            }
        })
        .collect();
    let mut results: Vec<Val> = ty
        .results()
        .map(|t| match t {
            ValType::I32 => Val::I32(0),
            _ => Val::I64(0),
        })
        .collect();

    f.call(&mut store, &params, &mut results).map_err(run_err)?;

    let result = match results.first() {
        Some(Val::I32(v)) => *v as i64,
        Some(Val::I64(v)) => *v,
        None => 0,
        other => {
            return Err(AiueosError::Run(format!(
                "unexpected result kind: {other:?}"
            )))
        }
    };
    let data = store.into_data();
    Ok(HostOutcome {
        result,
        logs: data.logs,
        host_calls: data.calls,
        bus: data.bus,
        kqe: data.kqe,
    })
}
