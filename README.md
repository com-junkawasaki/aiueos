# aiueos

[![CI](https://github.com/com-junkawasaki/aiueos/actions/workflows/ci.yml/badge.svg)](https://github.com/com-junkawasaki/aiueos/actions/workflows/ci.yml)
[![docs](https://img.shields.io/badge/site-com--junkawasaki.github.io%2Faiueos-7cc4ff)](https://com-junkawasaki.github.io/aiueos/)

**A capability-secure, Wasm-component operating system — Kotoba-defined,
Kototama-executed, AI-agent-native.**

aiueos models an operating system not as *“a set of processes”* but as a
**graph of meaning-annotated capability components**. Everything a component
*is* — its kind, trust, imports, exports, effects, limits — is written as
**kotoba** (EDN). A trusted **broker** turns that description into either a
running component or a documented denial; nothing runs without passing the
capability graph and the policy reasoner, and every decision is audited.

```text
OS を「プロセスの集合」ではなく
「意味づけされた capability component の graph」として扱う。
```

## Why aiueos

- **Built to survive mythos-class adversaries.** The security model is
  deny-by-default capabilities, a deliberately small TCB, Wasm isolation per
  component, runtime-enforced capability gates, and an append-only audit trail.
  A component can touch *only* what its manifest was granted — and only by
  *calling* a gate that checks at runtime, not by convention. The aim is to make
  a compromised component a contained event, not a system-wide one. (See
  [`SECURITY.md`](SECURITY.md) for the honest threat model — this is an
  architecture for containment, not a claim of invulnerability.)
- **One model, many surfaces.** The substrate is just *components + capabilities
  + manifests + audit* over Wasm, so the same component runs wherever a Wasm
  engine does: **edge, robotics, cloud, browser, client**. Capabilities differ
  per deployment (a robot grants `topic/*` + device buses; a browser grants
  DOM/fetch shims) but the meaning model and the gate do not.
- **Code as data, AI-agent-native.** Components are *kotoba* — data the OS
  reasons over. An AI agent can author a component, and the OS treats it as
  `:ai-generated`: untrusted, ephemeral, denied network/secrets/persistence by
  default. Generating, verifying, launching and auditing AI-written code is a
  first-class path, not a bolt-on.

This crate is the **Phase-0 substrate**: `aiueos run/up` on a host OS, mock
services, a virtio-blk *logic* stub, and a working robot pipeline over the host
ABI. The microkernel, real device ABIs (MMIO/DMA/IRQ), per-surface capability
providers and the microVM image are later phases — but the seams they need
(`:effects`, `:requires #{:iommu}`, kernel-provided capabilities, the
`aiueos:host` gate) are already modeled, so those phases slot in without reshaping
the core.

## Where it sits

```text
kotoba   = OS の意味・構造・ポリシー・能力を記述する層   →  kotoba-edn (EDN reader)
kototama = kotoba/clj subset から Wasm component を生成   →  kototama (CLJ→wasm) + wasmtime
aiueos   = component 群を OS として構成する runtime       →  this crate
```

aiueos depends on two sibling repos:

- [`kotoba-edn`](../kotoba/crates/kotoba-edn) — the single source-of-truth EDN
  reader. Manifests, policies, device schemas and the audit log are all kotoba.
- [`kototama`](../kototama) — the Clojure/EDN-subset → WebAssembly compiler, run
  on `wasmtime` with a fuel budget.

## The layers

| module | role |
|---|---|
| `manifest` | `:aiueos/...` component descriptions → `Manifest` |
| `graph` | system graph → capability graph (capability → providers) |
| `policy` | the reasoner: resolve imports, enforce effects & the driver-DMA rule |
| `broker` | the trusted seam: verify → safe-check → compile → run, all audited; `boot` launches a whole system in dependency order |
| `safe` | the safe-kotoba subset gate (no eval/require/slurp/reflection) |
| `audit` | append-only EDN audit log (itself kotoba) |
| `topic` | in-process publish/subscribe bus — the ROS-topic analogue |
| `host` | the broker-mediated `aiueos:host` ABI: capability-gated host calls (feature `wasm-runtime`) |
| `runtime` | kototama compile (`kototama`) + wasm execution (`wasm-runtime`) |

### Features

- **`wasm-runtime`** — *execute* wasm (binary or WAT) under fuel + memory limits
  with the `aiueos:host` ABI. Needs only wasmtime.
- **`kototama`** — *compile* CLJ/Kotoba source → wasm (pulls the kototama
  toolchain); implies `wasm-runtime`. Split out so the host ABI and WAT
  components build and test without the CLJ compiler.

The semantic core (everything except `runtime`) has **zero heavy dependencies** —
build it with `--no-default-features` for a fast manifest/policy/graph engine.

## The model in one breath

1. **Everything is a component** — apps, services, drivers, agents, brokers,
   policies. (`:aiueos/kind`)
2. **Everything is a capability** — a component lists what it `:aiueos/imports`
   and `:aiueos/exports`; it can touch nothing else. Imports must resolve to
   another component’s export, a kernel primitive, or an explicit grant.
3. **Everything is kotoba** — the description is data the OS *reasons over*, not
   a config file: the policy reasoner decides DMA grants, effect legality, and
   trust-based lockdown from it.

### Policy rules enforced today

- **Capability linking** — every import is provided by some exporter, a
  kernel-provided primitive, or a policy grant; otherwise *unresolved-capability*.
- **Effect/trust** — `:ai-generated` components get no `:network`/`:secrets`/
  `:persistent-write`; `:untrusted` get no `:secrets`. Otherwise *forbidden-effect*.
- **Driver DMA policy** — anything with the `:dma` effect must
  `:requires #{:iommu}` *and* be granted `:iommu`; otherwise *dma-without-iommu*.
  (A Wasm driver’s whole point is to be evicted from the TCB — DMA is the one
  thing that can still escape the sandbox, so the IOMMU gate is mandatory.)
- **Device exclusivity** — a fully-specified `bus:vendor:device` binding can have
  exactly one driver; two drivers claiming the same hardware is rejected.

### Fail loud, never silently degrade

Manifests are validated strictly at parse time — a malformed field is a hard
error, never a silent default. This matters most for security-relevant fields: a
typo'd `:aiueos/effcts` can't quietly drop a `:dma` effect (and slip past the
IOMMU gate), a negative `:memory-pages` can't wrap to a huge limit, and
non-integer `:aiueos/args` can't reach the entry as the wrong arguments. Unknown
`:aiueos/*` keys, out-of-range limits, non-integer args, an empty `:aiueos/entry`,
unknown `:aiueos/kind`/`:aiueos/trust`, and duplicate component ids are all
rejected.

## CLI

```bash
# standalone clone:
cargo build            # → target/debug/aiueos
BIN=target/debug/aiueos
# (inside the monorepo, a parent .cargo/config defaults to wasm32, so add
#  --target "$(rustc -vV | sed -n 's/host: //p')" and use that target dir.)

# boot the robot system (WAT components → no compiler needed; works standalone):
# link → order (derived from topic dataflow) → verify → launch, all audited
$BIN up examples/robot/robot.aiueos.edn
#  aiueos boot — system `robot`
#    order: driver/sensor → agent/planner → driver/actuator
#    ✓ driver/sensor    (driver) → 21     # publishes 21 to topic "scan"
#    ✓ agent/planner    (agent)  → 42     # polls scan, publishes scan×2 to "cmd"
#    ✓ driver/actuator  (driver) → 42     # polls cmd, drives it
#  ✓ system up — 3/3 components launched

# inspect a capability graph + per-component verdicts
$BIN inspect examples/system.aiueos.edn

# verify (default policy grants no IOMMU → the driver's DMA is denied, exit 1)
$BIN verify examples/system.aiueos.edn

# run a single host-importing component (fresh bus, audited)
$BIN run examples/robot/sensor.edn --system examples/robot/robot.aiueos.edn
#  ✓ driver/sensor :: tick([21]) = 21

# gate a source against the safe-kotoba subset
$BIN check examples/apps/notes.clj

# replay the audit log
$BIN audit --log examples/robot/.aiueos/audit.edn

# machine-readable verdict for tooling / AI agents (EDN, exit code = pass/fail):
$BIN verify examples/system.aiueos.edn --policy examples/policy/default.edn --edn
#  {:aiueos/grants {"app/notes" #{"fs/open" "log/write"} ...} :aiueos/verified true}
$BIN inspect examples/system.aiueos.edn --edn
#  {:aiueos/system "demo" :aiueos/components [...] :aiueos/graph {...}
#   :aiueos/verdicts [{:component "..." :verified true :caps #{...}} ...]}
```

> The CLJ example system (`examples/system.aiueos.edn`, with `.clj` components)
> and `aiueos compile` need the **`kototama`** feature — a monorepo-only build,
> since the kototama compiler resolves only alongside its sibling repos. The
> robot system above is pure WAT and needs nothing but the default build.

```text
aiueos verify  <manifest|system>.edn [--policy p.edn] [--edn]   capability + policy check
aiueos inspect <system>.edn          [--policy p.edn] [--edn]   print the capability graph
aiueos up      <system>.edn          [--policy p.edn] [--edn]   boot the whole system (Stage 0–4)
aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn] [--edn]
aiueos compile <source.clj|manifest> [-o out.wasm]      CLJ/Kotoba → wasm
aiueos check   <source.clj>                             safe-kotoba subset gate
aiueos hash    <file> [--edn]                           sha256 for :aiueos/wasm-sha256
aiueos audit   [--log <audit.edn>]                      replay the audit log
```

All four inspection/execution commands (`verify`/`inspect`/`up`/`run`) accept
`--edn` for machine-readable output — success verdicts, denials, *and* structural
errors are emitted as EDN, so an AI agent can drive the whole lifecycle as data.

### Supply-chain integrity

A precompiled/WAT component can pin its artifact's hash; the broker refuses to run
bytes that don't match (tamper detection):

```bash
$BIN hash mydriver.wasm            # → <sha256>  mydriver.wasm
# in the manifest:  :aiueos/wasm "mydriver.wasm"  :aiueos/wasm-sha256 "<sha256>"
```

This is *integrity*, not *authenticity* — signed manifests / provenance are a
later phase (see [`SECURITY.md`](SECURITY.md)).

## Example: a virtio-blk driver

The device *meaning* is data the OS reasons over; the driver *logic* is
safe-kotoba; the lowest layer (real MMIO/DMA/IRQ) is a kernel-provided unsafe
adapter and is later-phase work — but the `:effects`/`:requires` seams are
already declared so policy can gate DMA today.

```edn
{:aiueos/component :driver/virtio-blk
 :aiueos/kind :driver
 :aiueos/source "virtio_blk.clj"
 :aiueos/imports #{:pci/config :dma/map :irq/subscribe :mmio/map}
 :aiueos/exports #{:block/read :block/write}
 :aiueos/effects #{:device-io :dma :interrupt}
 :aiueos/requires #{:iommu}
 :aiueos/limits {:memory-pages 32 :fuel 10000000}}
```

## Robotics: capabilities you actually *call* at run time

Capabilities aren't just a static manifest claim — the broker-mediated
`aiueos:host` ABI **enforces them at call time**. A component may call a host
function only if its conferred capability set contains the matching capability;
a call without it **traps**.

| import              | capability        | meaning                          |
|---------------------|-------------------|----------------------------------|
| `log(i64)`          | `log/write`       | emit a log sample                |
| `clock() -> i64`    | `clock/monotonic` | monotonic tick                   |
| `publish(i32,i64)`  | `topic/publish`   | publish a sample to a topic      |
| `poll(i32) -> i64`  | `topic/subscribe` | latest sample (peek)             |
| `take(i32) -> i64`  | `topic/subscribe` | pop oldest unread sample (FIFO)  |
| `count(i32) -> i64` | `topic/subscribe` | #samples published to a topic    |

The [`topic`](src/topic.rs) bus is the ROS-topic analogue (numeric topic ids,
i64 samples). It keeps both the latest value (`poll`, peek) and a per-topic FIFO
of unread samples (`take`, drain) — so a slow consumer can read *every* reading,
not just the newest. On `boot`, one bus is threaded through every component, so a
producer's `publish` is visible to a later consumer's `poll`/`take` — a running
sensor → planner → actuator dataflow over capability-gated nodes:

```bash
$BIN up examples/robot/robot.aiueos.edn
#  aiueos boot — system `robot`
#    order: driver/sensor → agent/planner → driver/actuator
#    ✓ driver/sensor    (driver) → 21     # publishes 21 to topic "scan"
#    ✓ agent/planner    (agent)  → 42     # polls scan, publishes scan×2 to "cmd"
#    ✓ driver/actuator  (driver) → 42     # polls cmd, drives it
#  ✓ system up — 3/3 components launched
```

Run it as a **periodic control loop** with `--rounds N` — one bus is threaded
across all rounds, so samples accumulate and a consumer drains them each cycle:

```bash
$BIN up examples/robot/robot.aiueos.edn --rounds 10   # 10 control cycles
```

The planner is an `:agent` (AI-generated trust): it may use the topic bus, but
the default policy still forbids it network/secrets/persistent-write. The
actuator imports only `topic/subscribe`, so a `publish` call from it would trap —
the actuator structurally *cannot* command the bus, only read it.

Isolation reaches **individual topics**: a manifest declares the topic ids it may
touch, and the broker confines it to those — a publish/read to any other topic
traps even with the coarse `topic/*` capability:

```edn
{:aiueos/component :driver/sensor ... :aiueos/publishes #{1}}    ; can only publish to "scan"
{:aiueos/component :driver/actuator ... :aiueos/subscribes #{2}} ; can only read "cmd"
```

So a compromised sensor cannot reach the actuator's command topic. This is the
robot-OS payoff of the capability model: "the vision node cannot drive the
motors" is enforced by the runtime, not by convention. (Real device drivers,
named topics wired into the graph, and a real-time scheduler are later phases;
today the nodes are WAT/compute and topics are numeric ids.)

## Build & test

A standalone clone builds out of the box — `kotoba-edn` is a git dependency, so
no sibling checkout is needed for the default (execution + robotics) build:

```bash
# default = execute wasm (binary/WAT) + the aiueos:host ABI + robotics
cargo test
cargo test --no-default-features            # semantic core only (no wasmtime)
cargo test --features wasm-runtime          # explicit; same as default
```

The **`kototama`** feature (compile CLJ/Kotoba source → wasm) is opt-in and only
resolves **inside the monorepo** — kototama is a path dependency whose own
manifest points at its siblings:

```bash
# from a full com-junkawasaki checkout (aiueos next to kotoba/ and kototama/):
cargo test --features kototama --target "$(rustc -vV | sed -n 's/host: //p')"
```

(The `--target` is only needed in the monorepo, where a parent `.cargo/config`
defaults the build target to wasm32.)

## Roadmap (this crate = Phase 0)

| phase | scope | status |
|---|---|---|
| 0 | manifests (fail-loud validation), capability graph, policy reasoner, broker, safe-check, append-only **+ queryable** audit, staged boot (`aiueos up`, Stage 0–4) | ✅ this crate |
| 0+ | **runtime-enforced capabilities**: `aiueos:host` ABI (log/clock/publish/poll/take/count) + pub/sub topic bus with FIFO queues; **per-topic isolation**; **periodic control loop** (`--rounds`); device binding + exclusivity; **artifact integrity** (`:aiueos/wasm-sha256`); machine-readable `--edn` surface (verify/inspect/up/run/audit) → sensor→planner→actuator robot demo | ✅ this crate |
| 1 | richer kotoba manifest/policy/**proof** system (signed manifests / provenance) | 🔜 |
| 2 | typed safe-kotoba compiler (effects + capabilities in the type system) | 🔜 |
| 3 | real service components (log/kv/vfs/net-proxy) | 🔜 |
| 4 | virtio mock drivers as components | partial (logic stub) |
| 5 | microVM image (unikernel / minimal Linux host) | 🔜 |
| 6 | aiueos microkernel (boot/mem/IPC/cap table/sched/IRQ) | 🔜 |
| 7 | real drivers: serial → fb → virtio-blk/net/input/gpu → NVMe → USB → GPU → Wi-Fi | 🔜 |

The design keeps the **TCB small**: microkernel + Wasm runtime + kototama +
broker + manifest/proof verifier + tiny unsafe hardware adapters. Apps, services,
drivers and agents all live *outside* it as capability components.

## License

MIT.
