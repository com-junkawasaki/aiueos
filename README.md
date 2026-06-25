# aiueos

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
`aiue:host` gate) are already modeled, so those phases slot in without reshaping
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
| `manifest` | `:aiue/...` component descriptions → `Manifest` |
| `graph` | system graph → capability graph (capability → providers) |
| `policy` | the reasoner: resolve imports, enforce effects & the driver-DMA rule |
| `broker` | the trusted seam: verify → safe-check → compile → run, all audited; `boot` launches a whole system in dependency order |
| `safe` | the safe-kotoba subset gate (no eval/require/slurp/reflection) |
| `audit` | append-only EDN audit log (itself kotoba) |
| `topic` | in-process publish/subscribe bus — the ROS-topic analogue |
| `host` | the broker-mediated `aiue:host` ABI: capability-gated host calls (feature `wasm-runtime`) |
| `runtime` | kototama compile (`kototama`) + wasm execution (`wasm-runtime`) |

### Features

- **`wasm-runtime`** — *execute* wasm (binary or WAT) under fuel + memory limits
  with the `aiue:host` ABI. Needs only wasmtime.
- **`kototama`** — *compile* CLJ/Kotoba source → wasm (pulls the kototama
  toolchain); implies `wasm-runtime`. Split out so the host ABI and WAT
  components build and test without the CLJ compiler.

The semantic core (everything except `runtime`) has **zero heavy dependencies** —
build it with `--no-default-features` for a fast manifest/policy/graph engine.

## The model in one breath

1. **Everything is a component** — apps, services, drivers, agents, brokers,
   policies. (`:aiue/kind`)
2. **Everything is a capability** — a component lists what it `:aiue/imports`
   and `:aiue/exports`; it can touch nothing else. Imports must resolve to
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

## CLI

```bash
# build for your host (a .cargo/config defaults the workspace to wasm32):
cargo build --target aarch64-apple-darwin
BIN=target/aarch64-apple-darwin/debug/aiueos

# inspect the capability graph + per-component verdicts
$BIN inspect examples/system.aiue.edn --policy examples/policy/default.edn

# boot the whole system: link → order → verify → launch in dependency order
$BIN up examples/system.aiue.edn --policy examples/policy/default.edn
#  aiueos boot — system `demo`
#    link: 8 capabilities across 4 components
#    order: service/log → driver/virtio-blk → service/fs → app/notes
#    ✓ service/log         (service) → 0
#    ✓ driver/virtio-blk   (driver)  → 42
#    ✓ service/fs          (service) → 0
#    ✓ app/notes           (app)     → 42
#  ✓ system up — 4/4 components launched
# (without --policy the driver's DMA is denied and the boot aborts before launch)

# verify (no policy → the driver's DMA is denied, exit 1)
$BIN verify examples/system.aiue.edn

# compile + run a component under its fuel/memory limits (audited)
$BIN run examples/apps/notes.edn --system examples/system.aiue.edn \
                                 --policy examples/policy/default.edn
#  ✓ app/notes :: main([21]) = 42

# gate a source against the safe-kotoba subset
$BIN check examples/apps/notes.clj

# replay the audit log
$BIN audit --log examples/.aiue/audit.edn
```

```text
aiueos verify  <manifest|system>.edn [--policy p.edn]   capability + policy check
aiueos inspect <system>.edn          [--policy p.edn]   print the capability graph
aiueos up      <system>.edn          [--policy p.edn]   boot the whole system (Stage 0–4)
aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn]
aiueos compile <source.clj|manifest> [-o out.wasm]      CLJ/Kotoba → wasm
aiueos check   <source.clj>                             safe-kotoba subset gate
aiueos audit   [--log <audit.edn>]                      replay the audit log
```

## Example: a virtio-blk driver

The device *meaning* is data the OS reasons over; the driver *logic* is
safe-kotoba; the lowest layer (real MMIO/DMA/IRQ) is a kernel-provided unsafe
adapter and is later-phase work — but the `:effects`/`:requires` seams are
already declared so policy can gate DMA today.

```edn
{:aiue/component :driver/virtio-blk
 :aiue/kind :driver
 :aiue/source "virtio_blk.clj"
 :aiue/imports #{:pci/config :dma/map :irq/subscribe :mmio/map}
 :aiue/exports #{:block/read :block/write}
 :aiue/effects #{:device-io :dma :interrupt}
 :aiue/requires #{:iommu}
 :aiue/limits {:memory-pages 32 :fuel 10000000}}
```

## Robotics: capabilities you actually *call* at run time

Capabilities aren't just a static manifest claim — the broker-mediated
`aiue:host` ABI **enforces them at call time**. A component may call a host
function only if its conferred capability set contains the matching capability;
a call without it **traps**.

| import              | capability        | meaning                       |
|---------------------|-------------------|-------------------------------|
| `log(i64)`          | `log/write`       | emit a log sample             |
| `clock() -> i64`    | `clock/monotonic` | monotonic tick                |
| `publish(i32,i64)`  | `topic/publish`   | publish a sample to a topic   |
| `poll(i32) -> i64`  | `topic/subscribe` | latest sample on a topic       |

The [`topic`](src/topic.rs) bus is the ROS-topic analogue (numeric topic ids,
i64 samples, last-write-wins). On `boot`, one bus is threaded through every
component, so a producer's `publish` is visible to a later consumer's `poll` —
a running sensor → planner → actuator dataflow over capability-gated nodes:

```bash
$BIN up examples/robot/robot.aiue.edn
#  aiueos boot — system `robot`
#    order: driver/sensor → agent/planner → driver/actuator
#    ✓ driver/sensor    (driver) → 21     # publishes 21 to topic "scan"
#    ✓ agent/planner    (agent)  → 42     # polls scan, publishes scan×2 to "cmd"
#    ✓ driver/actuator  (driver) → 42     # polls cmd, drives it
#  ✓ system up — 3/3 components launched
```

The planner is an `:agent` (AI-generated trust): it may use the topic bus, but
the default policy still forbids it network/secrets/persistent-write. The
actuator imports only `topic/subscribe`, so a `publish` call from it would trap —
the actuator structurally *cannot* command the bus, only read it. This is the
robot-OS payoff of the capability model: "the vision node cannot drive the
motors" is enforced by the runtime, not by convention. (Real device drivers,
named topics, and a real-time scheduler are later phases; today the nodes are
WAT/compute and topics are numeric.)

## Build & test

```bash
HOST=$(rustc -vV | sed -n 's/host: //p')

# fast: semantic core only (no wasmtime)
cargo test --no-default-features --target "$HOST"

# execution + host ABI + robotics, without the CLJ compiler
cargo test --no-default-features --features wasm-runtime --target "$HOST"

# full: + kototama CLJ→wasm compilation
cargo test --target "$HOST"
```

## Roadmap (this crate = Phase 0)

| phase | scope | status |
|---|---|---|
| 0 | manifests, capability graph, policy reasoner, broker, safe-check, audit, `aiueos run`, staged boot (`aiueos up`, Stage 0–4) | ✅ this crate |
| 0+ | **runtime-enforced capabilities**: `aiue:host` ABI + pub/sub topic bus → sensor→planner→actuator robot demo | ✅ this crate |
| 1 | richer kotoba manifest/policy/proof system | 🔜 |
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
