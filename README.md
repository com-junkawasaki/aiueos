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

# run the deterministic browser GUI surface and write a static HTML bridge
$BIN run examples/browser/app.edn --policy examples/browser/policy.edn \
  --surface browser --dom-events examples/browser/dom-events.edn \
  --browser-out /tmp/aiueos-browser.html
#  ✓ app/browser-demo :: run([]) = 83
#    dom-rendered: 1 fragment(s)
#    browser-out: /tmp/aiueos-browser.html

# present one deterministic framebuffer frame through the same browser GUI surface
$BIN run examples/browser/framebuffer.edn --policy examples/browser/policy.edn \
  --surface browser
#  ✓ app/framebuffer-demo :: run([]) = 8
#    framebuffer: 1 frame(s)

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
aiueos verify  <manifest|system>.edn [--policy p.edn] [--edn]        capability + policy check
aiueos inspect <system>.edn          [--policy p.edn] [--edn|--dot]  capability graph (text / EDN / Graphviz)
aiueos up      <system>.edn          [--policy p.edn] [--surface id] [--edn] [--rounds N] [--dry-run] [--kqe-store s.edn] [--llm-fixture f.edn] [--dom-events f.edn] [--input-events f.edn] [--cloud-fixture f.edn] [--browser-out out.html]   boot the system
aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn] [--surface id] [--edn] [--llm-fixture f.edn] [--dom-events f.edn] [--input-events f.edn] [--cloud-fixture f.edn] [--browser-out out.html]
aiueos image build <system>.edn      --aiueos-bin <linux-bin> [--policy p.edn] [--out initramfs.cpio.gz] [--dry-run] [--edn]
aiueos vm up   <system>.edn          [--policy p.edn] [--name N] [--provider auto|lima] [--dry-run] [--edn]   run through a Mac microVM provider
aiueos vm boot <system>.edn          --kernel Image --aiueos-bin <linux-bin> [--policy p.edn] [--block raw.img] [--console pl011|virtio-console] [--console-socket path] [--graphics none|virtio-gpu] [--display cocoa|gtk|sdl] [--dry-run] [--edn]   boot kernel+initramfs
aiueos surface inspect <id>          [--edn]                         inspect robot|browser|cloud providers
aiueos compile <source.clj|manifest> [-o out.wasm]                   CLJ/Kotoba → wasm (kototama feature)
aiueos check   <source.clj>                                          safe-kotoba subset gate
aiueos hash    <file> [--edn]                                        sha256 for :aiueos/wasm-sha256
aiueos sign    <manifest>.edn --key <hex-seed> [--edn]               ed25519-sign the (id, hash) binding
aiueos audit   [--log <audit.edn>] [--event K] [--component C] [--edn]   replay/query the audit log
```

**Authenticity (ADR-0003).** `aiueos hash` an artifact → set `:aiueos/wasm-sha256`
→ `aiueos sign --key <seed>` → paste the `:aiueos/signature` and register the
printed public key in the policy's `:aiueos/signers {:name "hex"}`. A valid
signature elevates the component to `:verified`; `:aiueos/require-signed true`
rejects any unsigned component. (Built with the default `signing` feature.)

`--edn` (machine-readable) is accepted by `verify`/`inspect`/`up`/`run`/`audit`;
`up --rounds N` runs a periodic control loop; `up --dry-run` validates without
launching; `up --kqe-store s.edn` persists the in-process KQE graph across boot
invocations; `run`/`up --llm-fixture f.edn` injects deterministic LLM responses
for `kotoba:kais/llm.infer`; `--surface browser` enables the browser DOM/input
provider set, `--dom-events` injects deterministic semantic browser events,
`--input-events` injects low-level input events, and
`--browser-out` writes the rendered fragments to a static HTML bridge;
`inspect --dot` emits Graphviz.

All four inspection/execution commands (`verify`/`inspect`/`up`/`run`) accept
`--edn` for machine-readable output — success verdicts, denials, *and* structural
errors are emitted as EDN, so an AI agent can drive the whole lifecycle as data.

### Bootable image path

aiueos can now build a minimal initramfs where `/init` is the aiueos binary
itself. This removes the Ubuntu userspace dependency from the boot path:

```bash
# macOS/aarch64 convenience path: build Linux /init, fetch a virt kernel,
# build the robot initramfs, then boot QEMU/HVF.
bb robot:boot

# CI/smoke path: boot, wait for PID 1 idle, stop QEMU, exit 0.
bb robot:smoke

# CI/smoke path with a raw virtio-blk backing file exposed to the guest.
bb robot:block-smoke

# CI/smoke path with an additional virtio-console device exposed to the guest.
bb robot:console-smoke
```

```bash
$BIN image build examples/robot/robot.aiueos.edn \
  --aiueos-bin target/aarch64-unknown-linux-musl/release/aiueos \
  --dry-run

$BIN vm boot examples/robot/robot.aiueos.edn \
  --kernel /path/to/linux/arch/arm64/boot/Image \
  --aiueos-bin target/aarch64-unknown-linux-musl/release/aiueos \
  --dry-run

$BIN vm boot examples/robot/robot.aiueos.edn \
  --kernel /path/to/linux/arch/arm64/boot/Image \
  --aiueos-bin target/aarch64-unknown-linux-musl/release/aiueos \
  --block /path/to/block.raw \
  --dry-run

$BIN vm boot examples/robot/robot.aiueos.edn \
  --kernel /path/to/linux/arch/arm64/boot/Image \
  --aiueos-bin target/aarch64-unknown-linux-musl/release/aiueos \
  --console virtio-console \
  --console-socket /tmp/aiueos-console.sock \
  --dry-run

$BIN vm boot examples/robot/robot.aiueos.edn \
  --kernel /path/to/linux/arch/arm64/boot/Image \
  --aiueos-bin target/aarch64-unknown-linux-musl/release/aiueos \
  --graphics virtio-gpu --display cocoa \
  --dry-run
```

The resulting initramfs contains:

- `/init` — the Linux-target aiueos binary
- `/etc/aiueos/boot.edn` — points `/init` at the system graph and optional policy
- `/etc/aiueos/system/...` — the system graph directory

`vm boot` launches QEMU with `-kernel Image -initrd <initramfs> -append
"console=ttyAMA0 panic=0 rdinit=/init"`. This is not yet the final aiueos
microkernel image, but it is a distro-free boot path where aiueos is PID 1.
The convenience script downloads Alpine's aarch64 `vmlinuz-virt` as a kernel
only; no Alpine or Ubuntu rootfs is used.

`vm boot --graphics virtio-gpu` removes `-nographic` and exposes
`-device virtio-gpu-pci` to the guest. Linux still owns the early scanout in this
path; the aiueos-native virtio-gpu driver is a later increment.

`vm boot --block block.raw` exposes a raw backing file with
`-device virtio-blk-pci`. This is now reflected in dry-run and `--edn` boot
plans, matching the safe/file-backed virtio-blk provider core. The
`robot:block-smoke` bb task creates `examples/robot/.aiueos/image/aiueos-robot.raw`
by default; override it with `AIUEOS_BLOCK=/path/to/block.raw`.

`vm boot --console virtio-console` keeps the PL011 kernel console as the boot
console and additionally exposes `virtio-serial-pci` plus a named `virtconsole`
backed by a host socket. This gives the native guest driver path a stable QEMU
device to bind while keeping the current PID-1 smoke path deterministic.

For development on macOS, the older wrapper path remains available:

```bash
$BIN vm up examples/robot/robot.aiueos.edn --provider lima --dry-run
```

That path runs aiueos inside a Linux microVM provider. Use `vm boot` when you
want the kernel+initramfs path without a distro rootfs.

### Supply-chain integrity

A precompiled/WAT component can pin its artifact's hash; the broker refuses to run
bytes that don't match (tamper detection):

```bash
$BIN hash mydriver.wasm            # → <sha256>  mydriver.wasm
# in the manifest:  :aiueos/wasm "mydriver.wasm"  :aiueos/wasm-sha256 "<sha256>"
```

This is *integrity*. **Authenticity** is also available: `aiueos sign` an
ed25519 signature over the `(id, hash)` binding, register the public key in the
policy's `:aiueos/signers`, and a valid signature elevates the component to
`:verified` (see [`SECURITY.md`](SECURITY.md) and [ADR-0003](90-docs/adr/0003-signed-manifests.md)).

### Code as data: admitting agent-written components

aiueos is built to run components an **AI agent emits at runtime**. `aiueos admit`
is the front door: it runs a submitted component through the gate with its trust
**floored to `:ai-generated`** — the agent *cannot grant itself trust* (a human
signature can still elevate it). It returns a structured verdict an agent loop
reads to iterate:

```bash
$BIN admit generated.edn --edn
# admitted:   {:aiueos/admitted true  :aiueos/result 42}
# rejected:   {:aiueos/admitted false :aiueos/reason-code :denied :aiueos/reason "..."}
```

The stable `:aiueos/reason-code` (`:denied` / `:unsafe` / `:run` / …) lets the
agent branch on *why* without parsing prose — drop a forbidden capability, fix an
escape hatch, or fix the logic — and resubmit. See
[ADR-0004](90-docs/adr/0004-code-as-data-admit.md).

## Example: a virtio-blk driver

The device *meaning* is data the OS reasons over; the driver *logic* is
safe-kotoba; the lowest layer (real MMIO/DMA/IRQ) is a kernel-provided unsafe
adapter and is later-phase work — but the `:effects`/`:requires` seams are
already declared so policy can gate DMA today.

The safe native virtio core is now present in `src/virtio.rs`: transport status
handshake, feature negotiation, queue-size validation, feature-aware
descriptor-chain validation, split-queue memory layout calculation, and
available/used ring accounting. It also defines a virtio-mmio register I/O
boundary, a bounded volatile MMIO accessor for already-mapped device windows,
and safe MMIO transport adapter for header validation, feature selection, queue
address programming, queue notification, and interrupt status decode/ack.
Descriptor buffers and queue memory are checked against a directional DMA map
before programming the device, and allocator-provided DMA allocations can be
validated and installed through an explicit IOMMU programming boundary with
rollback on map failure. A checked IOMMU backend enforces aperture bounds,
overlap rejection, active mapping introspection, and exact unmap matching. A
deterministic DMA aperture allocator can allocate and program split-queue
backing memory through that boundary. IRQ lines can be subscribed through an
explicit interrupt-controller boundary; a checked IRQ backend rejects duplicate
lines and delivers only subscribed interrupt sources into provider event sinks.
Pending virtio interrupt status can be taken and acknowledged before delivery.
The core also includes a
virtio-blk service core: read/write requests are encoded as three-descriptor
chains with directional DMA validation, submitted through an available ring,
tracked as pending descriptor heads, and completed from used-ring entries with
status decoding. A component-facing provider adapter now materializes requests
through a backend boundary, submits only after backend success, notifies the
queue, and polls decoded completions. A synchronous emulated block backend
exercises the same provider/backend contract against real guest-memory bytes and
sector storage for read/write E2E coverage; a file-backed backend presents a
regular host file as a sector-addressed block device for host/VM smoke paths.
The virtio-console core now mirrors that shape for one-descriptor receive and
transmit buffers: RX buffers are device-writable, TX buffers are
device-readable, descriptor heads are tracked through available/used rings, and
an emulated console backend moves bytes between guest memory and deterministic
input/output queues.
Virtio PCI vendor capabilities
are modeled and resolved into common/notify/ISR/device regions with notify
offset validation; PCI config-space capability lists are walked and parsed into
that model. Kernel-provided BAR mappings are checked against those regions
before volatile MMIO slices are produced. Host-specific hardware IOMMU/IRQ
adapters and VM MMIO-backed block/console-device backends are still later-phase
work.

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

### Manifest reference (`:aiueos/*`)

Every recognized key — anything else in the `:aiueos/` namespace is rejected.

| key | meaning |
|---|---|
| `:aiueos/component` | canonical id, e.g. `:driver/virtio-blk` (required) |
| `:aiueos/kind` | `:app` `:service` `:driver` `:broker` `:agent` `:kernel-extension` `:compat` (required) |
| `:aiueos/trust` | `:trusted` `:verified` `:untrusted` `:ai-generated` (defaults by kind) |
| `:aiueos/source` | CLJ/Kotoba source path (compiled by kototama; monorepo feature) |
| `:aiueos/wasm` | precompiled `.wasm` / `.wat` path (alternative to source) |
| `:aiueos/wasm-sha256` | expected hex SHA-256 of the artifact — mismatch is rejected |
| `:aiueos/signer` | key id of the signer vouching for this component (resolved via the policy `:aiueos/signers` registry) |
| `:aiueos/signature` | hex ed25519 signature over `"<id>\n<wasm-sha256>"`; valid → trust elevated to `:verified`, forged → denied (ADR-0003) |
| `:aiueos/imports` | capabilities needed (must resolve to a provider/kernel/grant) |
| `:aiueos/exports` | capabilities provided to others |
| `:aiueos/effects` | side effects (`:dma` `:network` `:device-io` …) — gated by trust/DMA rules |
| `:aiueos/requires` | hardware/runtime requirements (e.g. `:iommu`) |
| `:aiueos/limits` | `{:memory-pages 1..65536 :fuel ≥1}` — per-run CPU/RAM caps |
| `:aiueos/quota` | `{:host-calls N :publishes N}` — per-cycle host-call rate caps; an over-budget call traps (ADR-0006) |
| `:aiueos/schedule` | `{:period-ms :deadline-ms :priority :cycle-ms}` — cooperative scheduling, derived to cycles; period-skipping + priority within dependency depth (ADR-0006) |
| `:aiueos/entry` | exported wasm fn to call (default `"main"`) |
| `:aiueos/args` | i64 arguments to the entry |
| `:aiueos/device` | driver device binding `{:bus :vendor :device …}` (exclusive) |
| `:aiueos/topics` | named-topic → id map; `publishes`/`subscribes` are *derived* from the exported/imported `:topic/<name>` capabilities via this map |
| `:aiueos/publishes` | topic ids this component may publish to (per-topic isolation; overrides derivation) |
| `:aiueos/subscribes` | topic ids this component may read (overrides derivation) |

### Safe Kotoba host capabilities

With the `kototama` feature, `:aiueos/source` may point at `.kotoba`, `.clj`, or
`.cljc` source. `.kotoba` is treated as the Kotoba reader target; `.cljc` reader
conditionals select the `:kotoba` branch. The broker converts verified aiueos
capabilities into a deny-by-default `kotoba_clj::Policy`, compiles the safe
subset with the policy-aware prelude, then re-checks the concrete target at
runtime.

| source call | aiueos capability | runtime behavior |
|---|---|---|
| `(has-capability? r a)` | `:kotoba.auth/self` | self-introspection only |
| `(kqe-assert! g s p obj)` / `(kqe-retract! ...)` | `:kotoba.graph-write/<graph>` | mutates the in-process KQE store |
| `(kqe-get-objects g s p)` | `:kotoba.graph-read/<graph>` | SPO lookup scoped to the granted graph |
| `(kqe-query filter)` | `:kotoba.graph-read/<graph>` or `:kotoba.graph-read/*` | snapshot query filtered by readable graph |
| `(llm-infer model prompt)` | `:kotoba.infer/<model>` | fixture-backed deterministic inference |

`kqe-query` accepts `""` (all readable quads), a plain predicate string such as
`"kg/role"`, or an EDN map string such as
`"{:graph \"kg\" :subject \"alice\" :predicate \"kg/role\"}"`. With the
`kototama` feature, the map may also contain `:datomic` with a kotoba-datomic
query:

```clojure
(kqe-query "{:graph \"kg\"
             :datomic {:find [?name]
                       :where [[?e :kg/role \"admin\"]
                               [?e :kg/name ?name]]}}")
```

If `:graph` is present, the host re-checks `kotoba.graph-read/<graph>` before
scanning or materializing the Datomic snapshot.

KQE persistence uses:

```bash
$BIN up system.aiueos.edn --policy policy.edn --kqe-store kqe-store.edn
```

LLM fixtures use:

```edn
{:aiueos/llm {"modelA" "fixture-answer"}}
```

and are wired with either:

```bash
$BIN run agent.edn --policy policy.edn --llm-fixture llm.edn
$BIN up system.aiueos.edn --policy policy.edn --llm-fixture llm.edn
```

This surface is specified in
[ADR-0007](90-docs/adr/0007-kotoba-kais-host-surface.md).

## GUI surface

The GUI path implemented today is the deterministic **browser surface**:
`dom/render` appends rendered markup, `dom/event` consumes injected input events,
`input/event` consumes lower-level input events, `framebuffer/present` records
linear framebuffer frames, and `--browser-out` writes the DOM render log as a
static HTML bridge. A whole system can be booted the same way:

```bash
$BIN up examples/browser/browser.aiueos.edn --policy examples/browser/policy.edn \
  --surface browser --dom-events examples/browser/dom-events.edn \
  --browser-out /tmp/aiueos-browser.html
```

This is not yet a native VM compositor. The in-memory framebuffer ABI is present,
and `vm boot --graphics virtio-gpu` can expose a QEMU display device; the native
aiueos virtio-gpu scanout driver is specified, but not implemented, in
[ADR-0009](90-docs/adr/0009-gui-surface-and-framebuffer.md).

## Robotics: capabilities you actually *call* at run time

Capabilities aren't just a static manifest claim — the broker-mediated
`aiueos:host` ABI **enforces them at call time**. A component may call a host
function only if its conferred capability set contains the matching capability;
a call without it **traps**.

| import              | capability        | meaning                          |
|---------------------|-------------------|----------------------------------|
| `log(i64)`          | `log/write`       | emit a log sample                |
| `clock() -> i64`    | `clock/monotonic` | monotonic control-loop cycle     |
| `random() -> i64`   | `random/bytes`    | deterministic pseudo-random      |
| `publish(i32,i64)`  | `topic/publish`   | publish a sample to a topic      |
| `poll(i32) -> i64`  | `topic/subscribe` | latest sample (peek)             |
| `take(i32) -> i64`  | `topic/subscribe` | pop oldest unread sample (FIFO)  |
| `count(i32) -> i64` | `topic/subscribe` | #samples published to a topic    |

A component imports the host functions it needs and is described by a manifest
that grants the matching capabilities (here a noisy sensor):

(This is a runnable example — see [`examples/authoring/`](examples/authoring).)

```wat
;; sensor.wat — import only what you call
(module
  (import "aiueos:host" "publish" (func $publish (param i32 i64)))
  (import "aiueos:host" "random"  (func $random  (result i64)))
  (func (export "tick") (result i64)
    (local $r i64)
    (local.set $r (call $random))                ;; a (deterministic) reading
    (call $publish (i32.const 1) (local.get $r)) ;; → topic 1 ("scan")
    (local.get $r)))
```
```edn
{:aiueos/component :driver/sensor :aiueos/kind :driver
 :aiueos/wasm "sensor.wat" :aiueos/entry "tick"
 :aiueos/imports #{:topic/publish :random/bytes} :aiueos/exports #{:topic/scan}
 :aiueos/topics {:scan 1}}   ; → publishes #{1} derived; calling random() without
                             ; :random/bytes, or publishing to any other topic, traps
```

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

## Roadmap

| phase | scope | status |
|---|---|---|
| 0 | manifests (fail-loud), capability graph, policy reasoner, broker, safe-check, queryable audit, staged boot; **runtime-enforced** `aiueos:host` ABI (log/clock/random/publish/poll/take/count) + FIFO topic bus, per-topic isolation, `--rounds` control loop, artifact integrity, `--edn` agent surface | ✅ |
| 1 | **authenticity** — ed25519 signed manifests, signer registry, trust elevation, provenance, `require-signed`, `aiueos sign` ([ADR-0003](90-docs/adr/0003-signed-manifests.md)) | ✅ |
| 2 | **code as data** — `aiueos admit`: trust floored to `:ai-generated`, structured verdict + reason-codes for an agent loop ([ADR-0004](90-docs/adr/0004-code-as-data-admit.md)) | ✅ |
| 3 | **multi-surface providers** — robot/cloud/browser providers, `--surface`, fixtures, browser bridge ([ADR-0005](90-docs/adr/0005-multi-surface-providers.md), [ADR-0009](90-docs/adr/0009-gui-surface-and-framebuffer.md)) | ✅ runtime path |
| 4 | **scheduler + IO quota** — per-cycle host-call caps, cooperative period/priority scheduling ([ADR-0006](90-docs/adr/0006-scheduler-and-io-quota.md)) | ✅ |
| 5 | **safe Kotoba runtime surface** — `.kotoba`/`.cljc` source, policy-aware compile, KQE graph host calls, deterministic LLM fixtures ([ADR-0007](90-docs/adr/0007-kotoba-kais-host-surface.md)) | ✅ |
| 6 | cross-machine messaging + publisher authentication | 🔜 |
| 7 | aiueos microkernel (boot/mem/IPC/cap table/preemptive sched/IRQ) | 🔜 |
| 8 | real drivers: serial → fb → virtio-blk/net → NVMe → USB → GPU → Wi-Fi (safe virtio queue/volatile-MMIO/PCI traversal/BAR mapping IRQ/DMA validation + checked IOMMU/IRQ backends + queue allocator + virtio-blk provider/emulated/file backend exists; hardware adapters/VM MMIO backend next) | 🧱 core |

The design keeps the **TCB small**: microkernel + Wasm runtime + kototama +
broker + manifest/proof verifier + tiny unsafe hardware adapters. Apps, services,
drivers and agents all live *outside* it as capability components.

## License

MIT.
