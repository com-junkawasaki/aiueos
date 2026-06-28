//! Minimal aiueos-native virtio core logic.
//!
//! This is deliberately hardware-light: it models the parts every native virtio
//! provider needs before volatile MMIO/PCI/IRQ adapters are wired in. The unsafe
//! adapters can read/write device registers later; this module keeps feature
//! negotiation, virtqueue descriptor validation, MMIO register sequencing, and
//! DMA range validation testable in the safe core.

use crate::{AiueosError, Result};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ptr::NonNull;

/// Virtio MMIO register offsets used by the native backend boundary.
pub mod mmio {
    pub const MAGIC_VALUE: u64 = 0x000;
    pub const VERSION: u64 = 0x004;
    pub const DEVICE_ID: u64 = 0x008;
    pub const VENDOR_ID: u64 = 0x00c;
    pub const DEVICE_FEATURES: u64 = 0x010;
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const DRIVER_FEATURES: u64 = 0x020;
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const INTERRUPT_STATUS: u64 = 0x060;
    pub const INTERRUPT_ACK: u64 = 0x064;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    pub const QUEUE_DRIVER_LOW: u64 = 0x090;
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
    pub const QUEUE_DEVICE_LOW: u64 = 0x0a0;
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0a4;

    pub const MAGIC: u32 = 0x7472_6976;
    pub const VERSION_2: u32 = 2;
}

/// Virtio interrupt status bits.
pub mod interrupt {
    pub const USED_RING: u32 = 1;
    pub const CONFIG_CHANGE: u32 = 2;
}

/// Virtio PCI capability config types.
pub mod pci {
    pub const STATUS: u16 = 0x06;
    pub const CAP_POINTER: u16 = 0x34;
    pub const CONFIG_SPACE_LEN: u16 = 256;
    pub const FIRST_CAPABILITY: u8 = 0x40;
    pub const STATUS_CAPABILITIES: u16 = 1 << 4;
    pub const CAP_ID_VENDOR_SPECIFIC: u8 = 0x09;

    pub const COMMON_CFG: u8 = 1;
    pub const NOTIFY_CFG: u8 = 2;
    pub const ISR_CFG: u8 = 3;
    pub const DEVICE_CFG: u8 = 4;
    pub const PCI_CFG: u8 = 5;
}

/// Virtio device status bits.
pub mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// Decoded virtio interrupt status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptStatus {
    pub bits: u32,
}

impl InterruptStatus {
    pub fn new(bits: u32) -> InterruptStatus {
        InterruptStatus { bits }
    }

    pub fn none(self) -> bool {
        self.bits == 0
    }

    pub fn used_ring(self) -> bool {
        self.bits & interrupt::USED_RING != 0
    }

    pub fn config_change(self) -> bool {
        self.bits & interrupt::CONFIG_CHANGE != 0
    }

    pub fn unknown_bits(self) -> u32 {
        self.bits & !(interrupt::USED_RING | interrupt::CONFIG_CHANGE)
    }
}

/// Kernel IRQ line assigned to a virtio device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IrqLine(u32);

impl IrqLine {
    pub fn new(line: u32) -> Result<IrqLine> {
        if line == 0 {
            return Err(AiueosError::Schema("IRQ line must be non-zero".into()));
        }
        Ok(IrqLine(line))
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

/// A subscribed virtio IRQ source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioIrqSubscription {
    pub line: IrqLine,
    pub device_type: DeviceType,
}

impl VirtioIrqSubscription {
    pub fn new(line: IrqLine, device_type: DeviceType) -> VirtioIrqSubscription {
        VirtioIrqSubscription { line, device_type }
    }
}

/// Decoded virtio interrupt event delivered to a component-facing provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioInterruptEvent {
    pub subscription: VirtioIrqSubscription,
    pub status: InterruptStatus,
}

/// Kernel interrupt-controller boundary for registering virtio IRQs.
pub trait VirtioIrqController {
    fn subscribe_virtio_irq(&mut self, subscription: VirtioIrqSubscription) -> Result<()>;
}

/// A source that can atomically take and acknowledge a virtio interrupt status.
pub trait VirtioInterruptSource {
    fn take_interrupts(&mut self) -> InterruptStatus;
}

/// Delivery boundary from low-level IRQ handling into a provider event loop.
pub trait VirtioInterruptSink {
    fn deliver_virtio_interrupt(&mut self, event: VirtioInterruptEvent) -> Result<()>;
}

pub fn subscribe_virtio_irq<C: VirtioIrqController>(
    controller: &mut C,
    line: IrqLine,
    device_type: DeviceType,
) -> Result<VirtioIrqSubscription> {
    let subscription = VirtioIrqSubscription::new(line, device_type);
    controller.subscribe_virtio_irq(subscription)?;
    Ok(subscription)
}

pub fn deliver_pending_virtio_interrupt<S: VirtioInterruptSource, K: VirtioInterruptSink>(
    source: &mut S,
    subscription: VirtioIrqSubscription,
    sink: &mut K,
) -> Result<Option<VirtioInterruptEvent>> {
    let status = source.take_interrupts();
    if status.none() {
        return Ok(None);
    }
    let event = VirtioInterruptEvent {
        subscription,
        status,
    };
    sink.deliver_virtio_interrupt(event)?;
    Ok(Some(event))
}

/// Stateful interrupt-controller backend used before a host-specific IRQ chip
/// driver is wired in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedVirtioIrqController {
    subscriptions: BTreeMap<IrqLine, VirtioIrqSubscription>,
}

impl CheckedVirtioIrqController {
    pub fn new() -> CheckedVirtioIrqController {
        CheckedVirtioIrqController {
            subscriptions: BTreeMap::new(),
        }
    }

    pub fn subscription(&self, line: IrqLine) -> Option<VirtioIrqSubscription> {
        self.subscriptions.get(&line).copied()
    }

    pub fn subscriptions(&self) -> impl Iterator<Item = VirtioIrqSubscription> + '_ {
        self.subscriptions.values().copied()
    }

    pub fn deliver_line<S: VirtioInterruptSource, K: VirtioInterruptSink>(
        &self,
        line: IrqLine,
        source: &mut S,
        sink: &mut K,
    ) -> Result<Option<VirtioInterruptEvent>> {
        let subscription = self.subscription(line).ok_or_else(|| {
            AiueosError::Run(format!("virtio IRQ line {} is not subscribed", line.get()))
        })?;
        deliver_pending_virtio_interrupt(source, subscription, sink)
    }
}

impl Default for CheckedVirtioIrqController {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioIrqController for CheckedVirtioIrqController {
    fn subscribe_virtio_irq(&mut self, subscription: VirtioIrqSubscription) -> Result<()> {
        if let Some(existing) = self.subscriptions.get(&subscription.line) {
            return Err(AiueosError::Run(format!(
                "virtio IRQ line {} already subscribed for {:?}",
                subscription.line.get(),
                existing.device_type
            )));
        }
        self.subscriptions.insert(subscription.line, subscription);
        Ok(())
    }
}

/// Virtio device ids used by aiueos provider planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Network = 1,
    Block = 2,
    Console = 3,
    Gpu = 16,
    Input = 18,
}

impl DeviceType {
    pub fn capability(self) -> &'static str {
        self.capabilities()[0]
    }

    pub fn capabilities(self) -> &'static [&'static str] {
        match self {
            DeviceType::Network => &["net/fetch"],
            DeviceType::Block => &["block/read", "block/write"],
            DeviceType::Console => &["console/read", "console/write"],
            DeviceType::Gpu => &["framebuffer/present"],
            DeviceType::Input => &["input/event"],
        }
    }
}

impl TryFrom<u32> for DeviceType {
    type Error = AiueosError;

    fn try_from(value: u32) -> Result<DeviceType> {
        match value {
            1 => Ok(DeviceType::Network),
            2 => Ok(DeviceType::Block),
            3 => Ok(DeviceType::Console),
            16 => Ok(DeviceType::Gpu),
            18 => Ok(DeviceType::Input),
            _ => Err(AiueosError::Schema(format!(
                "unsupported virtio device id {value}"
            ))),
        }
    }
}

/// A negotiated feature set. Virtio features are 64 bits in the modern spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features(pub u64);

impl Features {
    pub const VERSION_1: Features = Features(1 << 32);
    pub const RING_EVENT_IDX: Features = Features(1 << 29);
    pub const RING_INDIRECT_DESC: Features = Features(1 << 28);

    pub const fn empty() -> Features {
        Features(0)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub fn contains(self, other: Features) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn union(self, other: Features) -> Features {
        Features(self.0 | other.0)
    }
}

/// A BAR-backed region advertised through a virtio PCI capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciBarRegion {
    pub bar: u8,
    pub offset: u64,
    pub length: u64,
}

impl PciBarRegion {
    pub fn new(bar: u8, offset: u64, length: u64) -> Result<PciBarRegion> {
        if bar > 5 {
            return Err(AiueosError::Schema(format!(
                "virtio PCI BAR index must be in 0..=5, got {bar}"
            )));
        }
        if length == 0 {
            return Err(AiueosError::Schema(
                "virtio PCI BAR region length must be non-zero".into(),
            ));
        }
        offset
            .checked_add(length)
            .ok_or_else(|| AiueosError::Schema("virtio PCI BAR region overflows".into()))?;
        Ok(PciBarRegion {
            bar,
            offset,
            length,
        })
    }

    pub fn end(self) -> u64 {
        self.offset + self.length
    }

    pub fn contains(self, offset: u64, length: u64) -> bool {
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        self.offset <= offset && end <= self.end()
    }
}

/// One parsed virtio PCI vendor capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciCapability {
    pub cfg_type: u8,
    pub region: PciBarRegion,
    pub notify_off_multiplier: u32,
}

impl PciCapability {
    pub fn new(
        cfg_type: u8,
        bar: u8,
        offset: u64,
        length: u64,
        notify_off_multiplier: u32,
    ) -> Result<PciCapability> {
        match cfg_type {
            pci::COMMON_CFG | pci::NOTIFY_CFG | pci::ISR_CFG | pci::DEVICE_CFG | pci::PCI_CFG => {}
            _ => {
                return Err(AiueosError::Schema(format!(
                    "unknown virtio PCI capability type {cfg_type}"
                )))
            }
        }
        if cfg_type == pci::NOTIFY_CFG && notify_off_multiplier == 0 {
            return Err(AiueosError::Schema(
                "virtio PCI notify capability requires a non-zero multiplier".into(),
            ));
        }
        Ok(PciCapability {
            cfg_type,
            region: PciBarRegion::new(bar, offset, length)?,
            notify_off_multiplier,
        })
    }
}

/// Required PCI transport regions after validating virtio vendor capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciTransportRegions {
    pub common: PciBarRegion,
    pub notify: PciBarRegion,
    pub isr: PciBarRegion,
    pub device: Option<PciBarRegion>,
    pub notify_off_multiplier: u32,
}

/// Kernel-provided mapping provenance for one PCI BAR.
#[derive(Debug, Clone, Copy)]
pub struct PciBarMapping {
    pub bar: u8,
    pub base: NonNull<u8>,
    pub length: u64,
}

impl PciBarMapping {
    /// Create provenance for an already-mapped PCI BAR.
    ///
    /// # Safety
    ///
    /// `base..base+length` must be a valid, live, exclusively-owned MMIO mapping
    /// for BAR `bar`. The caller must ensure the mapping provenance came from
    /// the kernel's PCI/BAR mapping path for the same device.
    pub unsafe fn new(bar: u8, base: *mut u8, length: u64) -> Result<PciBarMapping> {
        if bar > 5 {
            return Err(AiueosError::Schema(format!(
                "PCI BAR mapping index must be in 0..=5, got {bar}"
            )));
        }
        if length == 0 {
            return Err(AiueosError::Schema(
                "PCI BAR mapping length must be non-zero".into(),
            ));
        }
        let base = NonNull::new(base).ok_or_else(|| {
            AiueosError::Schema("PCI BAR mapping base pointer must not be null".into())
        })?;
        Ok(PciBarMapping { bar, base, length })
    }

    pub fn contains(self, region: PciBarRegion) -> bool {
        self.bar == region.bar && region.end() <= self.length
    }

    pub fn volatile_region(self, region: PciBarRegion) -> Result<VolatileMmio> {
        if !self.contains(region) {
            return Err(AiueosError::Schema(format!(
                "virtio PCI BAR{} region 0x{:x}..0x{:x} outside mapped length 0x{:x}",
                region.bar,
                region.offset,
                region.end(),
                self.length
            )));
        }
        // Range was checked above; provenance and liveness come from `new`.
        let base = unsafe { self.base.as_ptr().add(region.offset as usize) };
        unsafe { VolatileMmio::new(base, region.length) }
    }
}

/// Mapping provenance for all regions needed by a virtio PCI transport.
#[derive(Debug, Clone, Copy)]
pub struct PciMappedTransport {
    pub common: VolatileMmio,
    pub notify: VolatileMmio,
    pub isr: VolatileMmio,
    pub device: Option<VolatileMmio>,
    pub notify_off_multiplier: u32,
}

pub fn map_pci_transport_regions(
    regions: PciTransportRegions,
    mappings: impl IntoIterator<Item = PciBarMapping>,
) -> Result<PciMappedTransport> {
    let mappings: Vec<_> = mappings.into_iter().collect();
    Ok(PciMappedTransport {
        common: map_pci_region(&mappings, regions.common)?,
        notify: map_pci_region(&mappings, regions.notify)?,
        isr: map_pci_region(&mappings, regions.isr)?,
        device: regions
            .device
            .map(|region| map_pci_region(&mappings, region))
            .transpose()?,
        notify_off_multiplier: regions.notify_off_multiplier,
    })
}

fn map_pci_region(mappings: &[PciBarMapping], region: PciBarRegion) -> Result<VolatileMmio> {
    let mapping = mappings
        .iter()
        .copied()
        .find(|mapping| mapping.bar == region.bar)
        .ok_or_else(|| AiueosError::Schema(format!("PCI BAR{} is not mapped", region.bar)))?;
    mapping.volatile_region(region)
}

pub fn resolve_pci_transport_regions(
    caps: impl IntoIterator<Item = PciCapability>,
) -> Result<PciTransportRegions> {
    let mut common = None;
    let mut notify = None;
    let mut isr = None;
    let mut device = None;
    let mut notify_off_multiplier = None;

    for cap in caps {
        match cap.cfg_type {
            pci::COMMON_CFG => assign_cap("common", &mut common, cap.region)?,
            pci::NOTIFY_CFG => {
                assign_cap("notify", &mut notify, cap.region)?;
                notify_off_multiplier = Some(cap.notify_off_multiplier);
            }
            pci::ISR_CFG => assign_cap("isr", &mut isr, cap.region)?,
            pci::DEVICE_CFG => assign_cap("device", &mut device, cap.region)?,
            pci::PCI_CFG => {}
            _ => unreachable!("PciCapability::new rejects unknown types"),
        }
    }

    Ok(PciTransportRegions {
        common: common.ok_or_else(|| {
            AiueosError::Schema("virtio PCI common config capability is missing".into())
        })?,
        notify: notify.ok_or_else(|| {
            AiueosError::Schema("virtio PCI notify config capability is missing".into())
        })?,
        isr: isr.ok_or_else(|| {
            AiueosError::Schema("virtio PCI ISR config capability is missing".into())
        })?,
        device,
        notify_off_multiplier: notify_off_multiplier.unwrap_or(0),
    })
}

fn assign_cap(name: &str, slot: &mut Option<PciBarRegion>, value: PciBarRegion) -> Result<()> {
    if slot.replace(value).is_some() {
        return Err(AiueosError::Schema(format!(
            "duplicate virtio PCI {name} capability"
        )));
    }
    Ok(())
}

impl PciTransportRegions {
    pub fn notify_addr(&self, queue_notify_off: u16) -> Result<(u8, u64)> {
        let offset = (queue_notify_off as u64)
            .checked_mul(self.notify_off_multiplier as u64)
            .and_then(|delta| self.notify.offset.checked_add(delta))
            .ok_or_else(|| AiueosError::Schema("virtio PCI notify offset overflows".into()))?;
        if !self.notify.contains(offset, 2) {
            return Err(AiueosError::Schema(format!(
                "virtio PCI notify offset 0x{offset:x} outside notify region"
            )));
        }
        Ok((self.notify.bar, offset))
    }
}

/// Safe read-only boundary for PCI configuration space.
pub trait PciConfigIo {
    fn read8(&mut self, offset: u16) -> u8;
    fn read16(&mut self, offset: u16) -> u16;
    fn read32(&mut self, offset: u16) -> u32;
}

/// Walk PCI configuration capabilities and parse virtio vendor capabilities.
pub fn scan_virtio_pci_capabilities<C: PciConfigIo>(cfg: &mut C) -> Result<Vec<PciCapability>> {
    if cfg.read16(pci::STATUS) & pci::STATUS_CAPABILITIES == 0 {
        return Ok(Vec::new());
    }

    let mut ptr = cfg.read8(pci::CAP_POINTER) & !0x3;
    if ptr == 0 {
        return Ok(Vec::new());
    }
    validate_pci_cap_ptr(ptr)?;

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for _ in 0..48 {
        if !seen.insert(ptr) {
            return Err(AiueosError::Schema(format!(
                "PCI capability list loops at 0x{ptr:02x}"
            )));
        }

        let cap_id = cfg.read8(ptr as u16);
        let next = cfg.read8(ptr as u16 + 1) & !0x3;
        if cap_id == pci::CAP_ID_VENDOR_SPECIFIC {
            let cap_len = cfg.read8(ptr as u16 + 2);
            if cap_len < 16 {
                return Err(AiueosError::Schema(format!(
                    "virtio PCI capability at 0x{ptr:02x} is too short: {cap_len}"
                )));
            }
            if ptr as u16 + cap_len as u16 > pci::CONFIG_SPACE_LEN {
                return Err(AiueosError::Schema(format!(
                    "virtio PCI capability at 0x{ptr:02x} extends past config space"
                )));
            }

            let cfg_type = cfg.read8(ptr as u16 + 3);
            let bar = cfg.read8(ptr as u16 + 4);
            let offset = cfg.read32(ptr as u16 + 8) as u64;
            let length = cfg.read32(ptr as u16 + 12) as u64;
            let notify_off_multiplier = if cfg_type == pci::NOTIFY_CFG {
                if cap_len < 20 {
                    return Err(AiueosError::Schema(format!(
                        "virtio PCI notify capability at 0x{ptr:02x} is too short: {cap_len}"
                    )));
                }
                cfg.read32(ptr as u16 + 16)
            } else {
                0
            };
            out.push(PciCapability::new(
                cfg_type,
                bar,
                offset,
                length,
                notify_off_multiplier,
            )?);
        }

        if next == 0 {
            return Ok(out);
        }
        validate_pci_cap_ptr(next)?;
        ptr = next;
    }

    Err(AiueosError::Schema(
        "PCI capability list exceeds traversal limit".into(),
    ))
}

fn validate_pci_cap_ptr(ptr: u8) -> Result<()> {
    if ptr < pci::FIRST_CAPABILITY || ptr as u16 >= pci::CONFIG_SPACE_LEN || ptr & 0x3 != 0 {
        return Err(AiueosError::Schema(format!(
            "invalid PCI capability pointer 0x{ptr:02x}"
        )));
    }
    Ok(())
}

/// Negotiate device features: all required bits must be offered; wanted bits are
/// accepted only when offered.
pub fn negotiate_features(
    offered: Features,
    required: Features,
    wanted: Features,
) -> Result<Features> {
    if !offered.contains(required) {
        let missing = required.0 & !offered.0;
        return Err(AiueosError::Run(format!(
            "virtio feature negotiation failed: missing required bits 0x{missing:016x}"
        )));
    }
    Ok(Features(required.0 | (wanted.0 & offered.0)))
}

/// Minimal register transport required by the safe virtio initialization path.
/// MMIO and PCI adapters implement this trait; tests use an in-memory transport.
pub trait Transport {
    fn device_type(&self) -> DeviceType;
    fn read_status(&self) -> u8;
    fn write_status(&mut self, status: u8);
    fn device_features(&self) -> Features;
    fn write_driver_features(&mut self, features: Features);
}

/// Register access boundary for virtio-mmio. Real kernels implement this with
/// volatile MMIO; tests use a deterministic in-memory register file.
pub trait MmioRegisterIo {
    fn read32(&mut self, offset: u64) -> u32;
    fn write32(&mut self, offset: u64, value: u32);
}

/// Volatile 32-bit MMIO register accessor over an already-mapped device window.
#[derive(Debug, Clone, Copy)]
pub struct VolatileMmio {
    base: NonNull<u8>,
    len: u64,
}

impl VolatileMmio {
    /// Create an accessor for a kernel-provided MMIO mapping.
    ///
    /// # Safety
    ///
    /// `base..base+len` must be a valid, live, exclusively-owned MMIO mapping for
    /// the lifetime of this accessor. The caller must ensure the mapping is not
    /// normal RAM shared with Rust references and that volatile 32-bit access is
    /// valid for the target device.
    pub unsafe fn new(base: *mut u8, len: u64) -> Result<VolatileMmio> {
        if len == 0 {
            return Err(AiueosError::Schema(
                "MMIO window length must be non-zero".into(),
            ));
        }
        let base = NonNull::new(base)
            .ok_or_else(|| AiueosError::Schema("MMIO base pointer must not be null".into()))?;
        Ok(VolatileMmio { base, len })
    }

    fn checked_reg(&self, offset: u64) -> Result<*mut u32> {
        if offset % 4 != 0 {
            return Err(AiueosError::Schema(format!(
                "MMIO offset 0x{offset:x} is not 32-bit aligned"
            )));
        }
        let end = offset
            .checked_add(4)
            .ok_or_else(|| AiueosError::Schema("MMIO register offset overflows".into()))?;
        if end > self.len {
            return Err(AiueosError::Schema(format!(
                "MMIO offset 0x{offset:x} outside mapped length 0x{:x}",
                self.len
            )));
        }
        // Pointer arithmetic stays inside the caller-provided MMIO window after
        // the range check above.
        Ok(unsafe { self.base.as_ptr().add(offset as usize).cast::<u32>() })
    }

    pub fn try_read32(&mut self, offset: u64) -> Result<u32> {
        let reg = self.checked_reg(offset)?;
        // The mapping is guaranteed by `new`; volatile preserves device access.
        Ok(unsafe { reg.read_volatile() })
    }

    pub fn try_write32(&mut self, offset: u64, value: u32) -> Result<()> {
        let reg = self.checked_reg(offset)?;
        // The mapping is guaranteed by `new`; volatile preserves device access.
        unsafe { reg.write_volatile(value) };
        Ok(())
    }
}

impl MmioRegisterIo for VolatileMmio {
    fn read32(&mut self, offset: u64) -> u32 {
        self.try_read32(offset)
            .unwrap_or_else(|err| panic!("invalid volatile MMIO read: {err}"))
    }

    fn write32(&mut self, offset: u64, value: u32) {
        self.try_write32(offset, value)
            .unwrap_or_else(|err| panic!("invalid volatile MMIO write: {err}"));
    }
}

/// Safe virtio-mmio transport adapter over an explicit register I/O boundary.
#[derive(Debug, Clone)]
pub struct MmioTransport<R> {
    regs: R,
}

impl<R: MmioRegisterIo> MmioTransport<R> {
    pub fn new(mut regs: R) -> Result<MmioTransport<R>> {
        let magic = regs.read32(mmio::MAGIC_VALUE);
        let version = regs.read32(mmio::VERSION);
        if magic != mmio::MAGIC {
            return Err(AiueosError::Run(format!(
                "virtio-mmio magic mismatch: got 0x{magic:08x}"
            )));
        }
        if version != mmio::VERSION_2 {
            return Err(AiueosError::Run(format!(
                "unsupported virtio-mmio version {version}"
            )));
        }
        Ok(MmioTransport { regs })
    }

    pub fn into_inner(self) -> R {
        self.regs
    }

    pub fn queue_max(&mut self, index: u16) -> Result<QueueSize> {
        self.regs.write32(mmio::QUEUE_SEL, index as u32);
        let max = self.regs.read32(mmio::QUEUE_NUM_MAX);
        let max = u16::try_from(max).map_err(|_| {
            AiueosError::Schema(format!("virtio queue {index} max size exceeds u16: {max}"))
        })?;
        QueueSize::new(max)
    }

    pub fn configure_split_queue(
        &mut self,
        index: u16,
        queue_size: QueueSize,
        layout: QueueLayout,
    ) -> Result<()> {
        let max = self.queue_max(index)?;
        if queue_size.get() > max.get() {
            return Err(AiueosError::Schema(format!(
                "virtio queue {index} size {} exceeds device max {}",
                queue_size.get(),
                max.get()
            )));
        }
        self.regs.write32(mmio::QUEUE_SEL, index as u32);
        self.regs.write32(mmio::QUEUE_NUM, queue_size.get() as u32);
        write_u64(
            &mut self.regs,
            mmio::QUEUE_DESC_LOW,
            layout.descriptor_table,
        );
        write_u64(
            &mut self.regs,
            mmio::QUEUE_DRIVER_LOW,
            layout.available_ring,
        );
        write_u64(&mut self.regs, mmio::QUEUE_DEVICE_LOW, layout.used_ring);
        self.regs.write32(mmio::QUEUE_READY, 1);
        Ok(())
    }

    pub fn configure_mapped_split_queue(
        &mut self,
        index: u16,
        queue_size: QueueSize,
        layout: QueueLayout,
        dma: &DmaMap,
    ) -> Result<()> {
        validate_queue_layout_dma(layout, queue_size, dma)?;
        self.configure_split_queue(index, queue_size, layout)
    }

    pub fn notify_queue(&mut self, index: u16) {
        self.regs.write32(mmio::QUEUE_NOTIFY, index as u32);
    }

    pub fn interrupt_status(&mut self) -> u32 {
        self.regs.read32(mmio::INTERRUPT_STATUS)
    }

    pub fn ack_interrupts(&mut self, bits: u32) {
        self.regs.write32(mmio::INTERRUPT_ACK, bits);
    }

    pub fn take_interrupts(&mut self) -> InterruptStatus {
        let status = InterruptStatus::new(self.interrupt_status());
        if !status.none() {
            self.ack_interrupts(status.bits);
        }
        status
    }
}

impl<R: MmioRegisterIo> VirtioInterruptSource for MmioTransport<R> {
    fn take_interrupts(&mut self) -> InterruptStatus {
        MmioTransport::take_interrupts(self)
    }
}

impl<R: MmioRegisterIo> MmioTransport<R> {
    fn write_status(&mut self, status: u8) {
        self.regs.write32(mmio::STATUS, status as u32);
    }

    fn expected_device_type(&mut self) -> Result<DeviceType> {
        DeviceType::try_from(self.regs.read32(mmio::DEVICE_ID))
    }

    fn read_status_mut(&mut self) -> u8 {
        self.regs.read32(mmio::STATUS) as u8
    }

    fn device_features_mut(&mut self) -> Features {
        self.regs.write32(mmio::DEVICE_FEATURES_SEL, 0);
        let low = self.regs.read32(mmio::DEVICE_FEATURES) as u64;
        self.regs.write32(mmio::DEVICE_FEATURES_SEL, 1);
        let high = self.regs.read32(mmio::DEVICE_FEATURES) as u64;
        Features(low | (high << 32))
    }

    fn write_driver_features(&mut self, features: Features) {
        self.regs.write32(mmio::DRIVER_FEATURES_SEL, 0);
        self.regs
            .write32(mmio::DRIVER_FEATURES, features.bits() as u32);
        self.regs.write32(mmio::DRIVER_FEATURES_SEL, 1);
        self.regs
            .write32(mmio::DRIVER_FEATURES, (features.bits() >> 32) as u32);
    }
}

fn write_u64<R: MmioRegisterIo>(regs: &mut R, low_offset: u64, value: u64) {
    regs.write32(low_offset, value as u32);
    regs.write32(low_offset + 4, (value >> 32) as u32);
}

/// Initialize a virtio-mmio device through the same status/features handshake as
/// the abstract transport path.
pub fn initialize_mmio_transport<R: MmioRegisterIo>(
    transport: &mut MmioTransport<R>,
    expected: DeviceType,
    required: Features,
    wanted: Features,
) -> Result<InitResult> {
    let actual = transport.expected_device_type()?;
    if actual != expected {
        return Err(AiueosError::Run(format!(
            "virtio device type mismatch: expected {expected:?}, got {actual:?}"
        )));
    }

    transport.write_status(0);
    transport.write_status(status::ACKNOWLEDGE);
    transport.write_status(status::ACKNOWLEDGE | status::DRIVER);

    let negotiated = negotiate_features(transport.device_features_mut(), required, wanted)?;
    transport.write_driver_features(negotiated);
    transport.write_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

    let after_features = transport.read_status_mut();
    if after_features & status::FEATURES_OK == 0 {
        transport.write_status(after_features | status::FAILED);
        return Err(AiueosError::Run(
            "virtio device rejected negotiated features".into(),
        ));
    }

    let ready = after_features | status::DRIVER_OK;
    transport.write_status(ready);
    Ok(InitResult {
        device_type: expected,
        features: negotiated,
        status: ready,
    })
}

/// Result of safe transport initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitResult {
    pub device_type: DeviceType,
    pub features: Features,
    pub status: u8,
}

/// Perform the common virtio initialization handshake. This is the safe core
/// shared by future MMIO/PCI adapters.
pub fn initialize_transport<T: Transport>(
    transport: &mut T,
    expected: DeviceType,
    required: Features,
    wanted: Features,
) -> Result<InitResult> {
    if transport.device_type() != expected {
        return Err(AiueosError::Run(format!(
            "virtio device type mismatch: expected {expected:?}, got {:?}",
            transport.device_type()
        )));
    }

    transport.write_status(0);
    transport.write_status(status::ACKNOWLEDGE);
    transport.write_status(status::ACKNOWLEDGE | status::DRIVER);

    let negotiated = negotiate_features(transport.device_features(), required, wanted)?;
    transport.write_driver_features(negotiated);
    transport.write_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

    let after_features = transport.read_status();
    if after_features & status::FEATURES_OK == 0 {
        transport.write_status(after_features | status::FAILED);
        return Err(AiueosError::Run(
            "virtio device rejected negotiated features".into(),
        ));
    }

    let ready = after_features | status::DRIVER_OK;
    transport.write_status(ready);
    Ok(InitResult {
        device_type: expected,
        features: negotiated,
        status: ready,
    })
}

/// Virtqueue size after device negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSize(u16);

impl QueueSize {
    pub fn new(size: u16) -> Result<QueueSize> {
        if size == 0 || !size.is_power_of_two() || size > 32768 {
            return Err(AiueosError::Schema(format!(
                "virtqueue size must be a power of two in 1..=32768, got {size}"
            )));
        }
        Ok(QueueSize(size))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

/// Virtqueue descriptor flags.
pub mod desc_flags {
    pub const NEXT: u16 = 1;
    pub const WRITE: u16 = 2;
    pub const INDIRECT: u16 = 4;
}

/// Permission bits for a guest-physical DMA range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaPerms(u8);

impl DmaPerms {
    pub const DEVICE_READ: DmaPerms = DmaPerms(1);
    pub const DEVICE_WRITE: DmaPerms = DmaPerms(2);
    pub const READ_WRITE: DmaPerms = DmaPerms(Self::DEVICE_READ.0 | Self::DEVICE_WRITE.0);

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, required: DmaPerms) -> bool {
        self.0 & required.0 == required.0
    }
}

/// A single mapped guest-physical range that may be passed to a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaRange {
    pub start: u64,
    pub len: u64,
    pub perms: DmaPerms,
}

impl DmaRange {
    pub fn new(start: u64, len: u64, perms: DmaPerms) -> Result<DmaRange> {
        if len == 0 {
            return Err(AiueosError::Schema(
                "DMA range length must be non-zero".into(),
            ));
        }
        start
            .checked_add(len)
            .ok_or_else(|| AiueosError::Schema("DMA range overflows address space".into()))?;
        if perms.bits() == 0 {
            return Err(AiueosError::Schema(
                "DMA range must grant at least one permission".into(),
            ));
        }
        Ok(DmaRange { start, len, perms })
    }

    pub fn end(self) -> u64 {
        self.start + self.len
    }

    pub fn contains(self, addr: u64, len: u64, required: DmaPerms) -> bool {
        if len == 0 || !self.perms.contains(required) {
            return false;
        }
        let Some(end) = addr.checked_add(len) else {
            return false;
        };
        self.start <= addr && end <= self.end()
    }
}

/// One allocator-provided DMA allocation before it is installed in the IOMMU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaAllocation {
    pub guest_phys: u64,
    pub len: u64,
    pub perms: DmaPerms,
}

impl DmaAllocation {
    pub fn new(guest_phys: u64, len: u64, perms: DmaPerms) -> Result<DmaAllocation> {
        DmaRange::new(guest_phys, len, perms)?;
        Ok(DmaAllocation {
            guest_phys,
            len,
            perms,
        })
    }

    pub fn range(self) -> Result<DmaRange> {
        DmaRange::new(self.guest_phys, self.len, self.perms)
    }
}

/// Kernel/IOMMU programming boundary for DMA windows.
pub trait Iommu {
    fn map_dma(&mut self, allocation: DmaAllocation) -> Result<()>;
    fn unmap_dma(&mut self, allocation: DmaAllocation) -> Result<()>;
}

/// Stateful IOMMU backend that validates a DMA aperture and active mappings
/// before a host-specific IOMMU adapter is wired in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedIommu {
    aperture: DmaRange,
    mappings: BTreeMap<u64, DmaAllocation>,
}

impl CheckedIommu {
    pub fn new(base: u64, len: u64) -> Result<CheckedIommu> {
        Ok(CheckedIommu {
            aperture: DmaRange::new(base, len, DmaPerms::READ_WRITE)?,
            mappings: BTreeMap::new(),
        })
    }

    pub fn aperture(&self) -> DmaRange {
        self.aperture
    }

    pub fn mappings(&self) -> impl Iterator<Item = DmaAllocation> + '_ {
        self.mappings.values().copied()
    }

    pub fn dma_map(&self) -> Result<DmaMap> {
        DmaMap::new(
            self.mappings
                .values()
                .copied()
                .map(DmaAllocation::range)
                .collect::<Result<Vec<_>>>()?,
        )
    }

    fn contains_allocation(&self, allocation: DmaAllocation) -> bool {
        self.aperture
            .contains(allocation.guest_phys, allocation.len, allocation.perms)
    }
}

impl Iommu for CheckedIommu {
    fn map_dma(&mut self, allocation: DmaAllocation) -> Result<()> {
        if !self.contains_allocation(allocation) {
            return Err(AiueosError::Run(format!(
                "DMA allocation 0x{:x}..0x{:x} outside IOMMU aperture 0x{:x}..0x{:x}",
                allocation.guest_phys,
                allocation.guest_phys.saturating_add(allocation.len),
                self.aperture.start,
                self.aperture.end()
            )));
        }
        let allocation_range = allocation.range()?;
        for mapped in self.mappings.values().copied() {
            let mapped_range = mapped.range()?;
            if allocation_range.start < mapped_range.end()
                && mapped_range.start < allocation_range.end()
            {
                return Err(AiueosError::Run(format!(
                    "DMA allocation 0x{:x}..0x{:x} overlaps active mapping 0x{:x}..0x{:x}",
                    allocation_range.start,
                    allocation_range.end(),
                    mapped_range.start,
                    mapped_range.end()
                )));
            }
        }
        self.mappings.insert(allocation.guest_phys, allocation);
        Ok(())
    }

    fn unmap_dma(&mut self, allocation: DmaAllocation) -> Result<()> {
        match self.mappings.get(&allocation.guest_phys).copied() {
            Some(mapped) if mapped == allocation => {
                self.mappings.remove(&allocation.guest_phys);
                Ok(())
            }
            Some(mapped) => Err(AiueosError::Run(format!(
                "DMA unmap mismatch at 0x{:x}: mapped len/perms {:?}, requested {:?}",
                allocation.guest_phys, mapped, allocation
            ))),
            None => Err(AiueosError::Run(format!(
                "DMA unmap for unknown mapping at 0x{:x}",
                allocation.guest_phys
            ))),
        }
    }
}

/// Allocator boundary for guest-physical DMA windows.
pub trait DmaAllocator {
    fn allocate_dma(&mut self, len: u64, align: u64, perms: DmaPerms) -> Result<DmaAllocation>;
}

/// Deterministic bump allocator for a kernel-provided DMA aperture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BumpDmaAllocator {
    next: u64,
    end: u64,
}

impl BumpDmaAllocator {
    pub fn new(base: u64, len: u64) -> Result<BumpDmaAllocator> {
        if len == 0 {
            return Err(AiueosError::Schema(
                "DMA allocator aperture length must be non-zero".into(),
            ));
        }
        let end = base
            .checked_add(len)
            .ok_or_else(|| AiueosError::Schema("DMA allocator aperture overflows".into()))?;
        Ok(BumpDmaAllocator { next: base, end })
    }

    pub fn remaining(&self) -> u64 {
        self.end.saturating_sub(self.next)
    }
}

impl DmaAllocator for BumpDmaAllocator {
    fn allocate_dma(&mut self, len: u64, align: u64, perms: DmaPerms) -> Result<DmaAllocation> {
        if len == 0 {
            return Err(AiueosError::Schema(
                "DMA allocation length must be non-zero".into(),
            ));
        }
        let start = align_up(self.next, align)?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| AiueosError::Schema("DMA allocation overflows".into()))?;
        if end > self.end {
            return Err(AiueosError::Run(format!(
                "DMA aperture exhausted: need 0x{len:x} bytes aligned to 0x{align:x}"
            )));
        }
        let allocation = DmaAllocation::new(start, len, perms)?;
        self.next = end;
        Ok(allocation)
    }
}

/// A set of DMA allocations that have been programmed into an IOMMU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgrammedDma {
    allocations: Vec<DmaAllocation>,
    map: DmaMap,
}

impl ProgrammedDma {
    pub fn program<I: Iommu>(
        iommu: &mut I,
        allocations: impl IntoIterator<Item = DmaAllocation>,
    ) -> Result<ProgrammedDma> {
        let allocations: Vec<_> = allocations.into_iter().collect();
        let ranges: Vec<_> = allocations
            .iter()
            .copied()
            .map(DmaAllocation::range)
            .collect::<Result<Vec<_>>>()?;
        let map = DmaMap::new(ranges)?;
        let mut programmed = Vec::new();
        for allocation in allocations {
            if let Err(err) = iommu.map_dma(allocation) {
                for mapped in programmed.iter().rev().copied() {
                    let _ = iommu.unmap_dma(mapped);
                }
                return Err(err);
            }
            programmed.push(allocation);
        }
        Ok(ProgrammedDma {
            allocations: programmed,
            map,
        })
    }

    pub fn dma_map(&self) -> &DmaMap {
        &self.map
    }

    pub fn allocations(&self) -> &[DmaAllocation] {
        &self.allocations
    }

    pub fn unprogram<I: Iommu>(self, iommu: &mut I) -> Result<()> {
        let mut first_err = None;
        for allocation in self.allocations.iter().rev().copied() {
            if let Err(err) = iommu.unmap_dma(allocation) {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        Ok(())
    }
}

/// A deterministic DMA map used before programming queue descriptors into a
/// device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmaMap {
    ranges: Vec<DmaRange>,
}

impl DmaMap {
    pub fn new(ranges: impl IntoIterator<Item = DmaRange>) -> Result<DmaMap> {
        let mut ranges: Vec<_> = ranges.into_iter().collect();
        ranges.sort_by_key(|r| r.start);
        for window in ranges.windows(2) {
            let left = window[0];
            let right = window[1];
            if left.end() > right.start {
                return Err(AiueosError::Schema(format!(
                    "DMA ranges overlap: 0x{:x}..0x{:x} and 0x{:x}..0x{:x}",
                    left.start,
                    left.end(),
                    right.start,
                    right.end()
                )));
            }
        }
        Ok(DmaMap { ranges })
    }

    pub fn empty() -> DmaMap {
        DmaMap { ranges: Vec::new() }
    }

    pub fn allows(&self, addr: u64, len: u64, required: DmaPerms) -> bool {
        self.ranges
            .iter()
            .any(|range| range.contains(addr, len, required))
    }

    pub fn validate_descriptor(&self, index: u16, desc: &Descriptor) -> Result<()> {
        let required = if desc.flags & desc_flags::WRITE == 0 {
            DmaPerms::DEVICE_READ
        } else {
            DmaPerms::DEVICE_WRITE
        };
        if !self.allows(desc.addr, desc.len as u64, required) {
            return Err(AiueosError::Run(format!(
                "descriptor {index} DMA range 0x{:x}..0x{:x} is not mapped for {:?}",
                desc.addr,
                desc.addr.saturating_add(desc.len as u64),
                required
            )));
        }
        Ok(())
    }
}

/// A safe representation of a virtqueue descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

impl Descriptor {
    pub fn read(addr: u64, len: u32) -> Descriptor {
        Descriptor {
            addr,
            len,
            flags: 0,
            next: 0,
        }
    }

    pub fn write(addr: u64, len: u32) -> Descriptor {
        Descriptor {
            addr,
            len,
            flags: desc_flags::WRITE,
            next: 0,
        }
    }

    pub fn with_next(mut self, next: u16) -> Descriptor {
        self.flags |= desc_flags::NEXT;
        self.next = next;
        self
    }

    pub fn indirect(mut self) -> Descriptor {
        self.flags |= desc_flags::INDIRECT;
        self
    }

    fn has_next(&self) -> bool {
        self.flags & desc_flags::NEXT != 0
    }
}

/// Validated descriptor chain summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorChain {
    pub head: u16,
    pub descriptors: Vec<u16>,
    pub readable_bytes: u64,
    pub writable_bytes: u64,
}

/// Validate a descriptor chain without touching guest memory.
pub fn validate_descriptor_chain(
    queue_size: QueueSize,
    table: &[Descriptor],
    head: u16,
) -> Result<DescriptorChain> {
    validate_descriptor_chain_with_features(queue_size, table, head, Features::empty())
}

/// Validate a descriptor chain without touching guest memory, using the
/// negotiated feature set to reject descriptors the device has not accepted.
pub fn validate_descriptor_chain_with_features(
    queue_size: QueueSize,
    table: &[Descriptor],
    head: u16,
    features: Features,
) -> Result<DescriptorChain> {
    let q = queue_size.get() as usize;
    if table.len() != q {
        return Err(AiueosError::Schema(format!(
            "descriptor table length {} does not match queue size {q}",
            table.len()
        )));
    }
    if head as usize >= q {
        return Err(AiueosError::Run(format!(
            "descriptor head {head} outside queue size {q}"
        )));
    }

    let mut seen = BTreeSet::new();
    let mut order = Vec::new();
    let mut readable_bytes = 0u64;
    let mut writable_bytes = 0u64;
    let mut current = head;

    loop {
        if current as usize >= q {
            return Err(AiueosError::Run(format!(
                "descriptor index {current} outside queue size {q}"
            )));
        }
        if !seen.insert(current) {
            return Err(AiueosError::Run(format!(
                "descriptor chain loops at index {current}"
            )));
        }
        let desc = &table[current as usize];
        if desc.len == 0 {
            return Err(AiueosError::Run(format!(
                "descriptor {current} has zero length"
            )));
        }
        if desc.flags & desc_flags::INDIRECT != 0
            && !features.contains(Features::RING_INDIRECT_DESC)
        {
            return Err(AiueosError::Run(format!(
                "descriptor {current} uses indirect descriptors without negotiated support"
            )));
        }
        if desc.flags & desc_flags::WRITE == 0 {
            readable_bytes = readable_bytes.saturating_add(desc.len as u64);
        } else {
            writable_bytes = writable_bytes.saturating_add(desc.len as u64);
        }
        order.push(current);
        if desc.has_next() {
            current = desc.next;
        } else {
            break;
        }
    }

    Ok(DescriptorChain {
        head,
        descriptors: order,
        readable_bytes,
        writable_bytes,
    })
}

/// Validate a descriptor chain and prove that every segment is covered by the
/// DMA map with the direction implied by the virtio descriptor flags.
pub fn validate_descriptor_chain_for_dma(
    queue_size: QueueSize,
    table: &[Descriptor],
    head: u16,
    features: Features,
    dma: &DmaMap,
) -> Result<DescriptorChain> {
    let chain = validate_descriptor_chain_with_features(queue_size, table, head, features)?;
    for index in &chain.descriptors {
        dma.validate_descriptor(*index, &table[*index as usize])?;
    }
    Ok(chain)
}

fn align_up(value: u64, align: u64) -> Result<u64> {
    if align == 0 || !align.is_power_of_two() {
        return Err(AiueosError::Schema(format!(
            "alignment must be a non-zero power of two, got {align}"
        )));
    }
    let mask = align - 1;
    value
        .checked_add(mask)
        .map(|v| v & !mask)
        .ok_or_else(|| AiueosError::Schema("virtqueue layout overflow".into()))
}

/// Byte layout for a split virtqueue in guest memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLayout {
    pub descriptor_table: u64,
    pub available_ring: u64,
    pub used_ring: u64,
    pub total_len: u64,
}

/// Compute the split virtqueue memory layout from a base guest-physical address.
///
/// The descriptor table is 16-byte aligned, the available ring follows it, and
/// the used ring is aligned to `used_ring_align` (usually the guest page size).
pub fn split_queue_layout(
    base: u64,
    queue_size: QueueSize,
    used_ring_align: u64,
) -> Result<QueueLayout> {
    let q = queue_size.get() as u64;
    let descriptor_table = align_up(base, 16)?;
    let descriptor_len = q
        .checked_mul(16)
        .ok_or_else(|| AiueosError::Schema("virtqueue descriptor layout overflow".into()))?;
    let available_ring = descriptor_table
        .checked_add(descriptor_len)
        .ok_or_else(|| AiueosError::Schema("virtqueue available layout overflow".into()))?;
    let available_len = 6u64
        .checked_add(q.checked_mul(2).ok_or_else(|| {
            AiueosError::Schema("virtqueue available ring layout overflow".into())
        })?)
        .ok_or_else(|| AiueosError::Schema("virtqueue available ring layout overflow".into()))?;
    let used_ring = align_up(
        available_ring
            .checked_add(available_len)
            .ok_or_else(|| AiueosError::Schema("virtqueue used ring layout overflow".into()))?,
        used_ring_align,
    )?;
    let used_len = 6u64
        .checked_add(
            q.checked_mul(8)
                .ok_or_else(|| AiueosError::Schema("virtqueue used ring layout overflow".into()))?,
        )
        .ok_or_else(|| AiueosError::Schema("virtqueue used ring layout overflow".into()))?;
    let total_len = used_ring
        .checked_add(used_len)
        .and_then(|end| end.checked_sub(base))
        .ok_or_else(|| AiueosError::Schema("virtqueue layout overflow".into()))?;
    Ok(QueueLayout {
        descriptor_table,
        available_ring,
        used_ring,
        total_len,
    })
}

impl QueueLayout {
    pub fn descriptor_len(self, queue_size: QueueSize) -> u64 {
        queue_size.get() as u64 * 16
    }

    pub fn available_len(self, queue_size: QueueSize) -> u64 {
        6 + queue_size.get() as u64 * 2
    }

    pub fn used_len(self, queue_size: QueueSize) -> u64 {
        6 + queue_size.get() as u64 * 8
    }
}

/// Validate that the queue memory itself is mapped for the device directions
/// required by a split virtqueue.
pub fn validate_queue_layout_dma(
    layout: QueueLayout,
    queue_size: QueueSize,
    dma: &DmaMap,
) -> Result<()> {
    let desc_len = layout.descriptor_len(queue_size);
    let avail_len = layout.available_len(queue_size);
    let used_len = layout.used_len(queue_size);

    if !dma.allows(layout.descriptor_table, desc_len, DmaPerms::DEVICE_READ) {
        return Err(AiueosError::Run(format!(
            "descriptor table DMA range 0x{:x}..0x{:x} is not mapped for device read",
            layout.descriptor_table,
            layout.descriptor_table.saturating_add(desc_len)
        )));
    }
    if !dma.allows(layout.available_ring, avail_len, DmaPerms::DEVICE_READ) {
        return Err(AiueosError::Run(format!(
            "available ring DMA range 0x{:x}..0x{:x} is not mapped for device read",
            layout.available_ring,
            layout.available_ring.saturating_add(avail_len)
        )));
    }
    if !dma.allows(layout.used_ring, used_len, DmaPerms::DEVICE_WRITE) {
        return Err(AiueosError::Run(format!(
            "used ring DMA range 0x{:x}..0x{:x} is not mapped for device write",
            layout.used_ring,
            layout.used_ring.saturating_add(used_len)
        )));
    }
    Ok(())
}

/// A split virtqueue allocation after the backing DMA window has been installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgrammedSplitQueue {
    pub layout: QueueLayout,
    pub queue_size: QueueSize,
    pub dma: ProgrammedDma,
}

impl ProgrammedSplitQueue {
    pub fn allocation(&self) -> Option<DmaAllocation> {
        self.dma.allocations().first().copied()
    }

    pub fn unprogram<I: Iommu>(self, iommu: &mut I) -> Result<()> {
        self.dma.unprogram(iommu)
    }
}

/// Allocate and program one split virtqueue from a DMA aperture.
pub fn allocate_programmed_split_queue<A: DmaAllocator, I: Iommu>(
    allocator: &mut A,
    iommu: &mut I,
    queue_size: QueueSize,
    used_ring_align: u64,
) -> Result<ProgrammedSplitQueue> {
    let zero_based = split_queue_layout(0, queue_size, used_ring_align)?;
    let allocation = allocator.allocate_dma(
        zero_based.total_len,
        used_ring_align.max(16),
        DmaPerms::READ_WRITE,
    )?;
    let layout = split_queue_layout(allocation.guest_phys, queue_size, used_ring_align)?;
    if layout.total_len > allocation.len {
        return Err(AiueosError::Schema(format!(
            "allocated split queue window too small: layout needs 0x{:x}, allocation has 0x{:x}",
            layout.total_len, allocation.len
        )));
    }
    let dma = ProgrammedDma::program(iommu, [allocation])?;
    validate_queue_layout_dma(layout, queue_size, dma.dma_map())?;
    Ok(ProgrammedSplitQueue {
        layout,
        queue_size,
        dma,
    })
}

/// Minimal available ring model. This lets drivers queue descriptor heads in a
/// deterministic way before MMIO notification is wired in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailRing {
    queue_size: QueueSize,
    idx: u16,
    ring: Vec<u16>,
}

impl AvailRing {
    pub fn new(queue_size: QueueSize) -> AvailRing {
        AvailRing {
            queue_size,
            idx: 0,
            ring: vec![0; queue_size.get() as usize],
        }
    }

    pub fn push(&mut self, head: u16) -> Result<u16> {
        if head >= self.queue_size.get() {
            return Err(AiueosError::Run(format!(
                "available descriptor head {head} outside queue size {}",
                self.queue_size.get()
            )));
        }
        let slot = self.idx % self.queue_size.get();
        self.ring[slot as usize] = head;
        self.idx = self.idx.wrapping_add(1);
        Ok(slot)
    }

    pub fn idx(&self) -> u16 {
        self.idx
    }
}

/// A processed descriptor entry from the used ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsedElement {
    pub id: u32,
    pub len: u32,
}

/// Minimal used ring model for deterministic completion accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedRing {
    queue_size: QueueSize,
    idx: u16,
    ring: Vec<UsedElement>,
}

impl UsedRing {
    pub fn new(queue_size: QueueSize) -> UsedRing {
        UsedRing {
            queue_size,
            idx: 0,
            ring: vec![UsedElement { id: 0, len: 0 }; queue_size.get() as usize],
        }
    }

    pub fn push(&mut self, id: u32, len: u32) -> Result<u16> {
        if id >= self.queue_size.get() as u32 {
            return Err(AiueosError::Run(format!(
                "used descriptor id {id} outside queue size {}",
                self.queue_size.get()
            )));
        }
        let slot = self.idx % self.queue_size.get();
        self.ring[slot as usize] = UsedElement { id, len };
        self.idx = self.idx.wrapping_add(1);
        Ok(slot)
    }

    pub fn idx(&self) -> u16 {
        self.idx
    }

    pub fn get(&self, slot: u16) -> Result<UsedElement> {
        if slot >= self.queue_size.get() {
            return Err(AiueosError::Run(format!(
                "used ring slot {slot} outside queue size {}",
                self.queue_size.get()
            )));
        }
        Ok(self.ring[slot as usize])
    }
}

/// Virtio block request kinds.
pub mod block {
    pub const T_IN: u32 = 0;
    pub const T_OUT: u32 = 1;

    pub const S_OK: u8 = 0;
    pub const S_IOERR: u8 = 1;
    pub const S_UNSUPP: u8 = 2;
}

/// A virtio-blk request header. The on-wire layout is little-endian
/// `type:u32`, `reserved:u32`, `sector:u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRequestHeader {
    pub request_type: u32,
    pub sector: u64,
}

impl BlockRequestHeader {
    pub const LEN: u32 = 16;

    pub fn read(sector: u64) -> BlockRequestHeader {
        BlockRequestHeader {
            request_type: block::T_IN,
            sector,
        }
    }

    pub fn write(sector: u64) -> BlockRequestHeader {
        BlockRequestHeader {
            request_type: block::T_OUT,
            sector,
        }
    }

    pub fn encode(self) -> [u8; Self::LEN as usize] {
        let mut out = [0u8; Self::LEN as usize];
        out[0..4].copy_from_slice(&self.request_type.to_le_bytes());
        out[4..8].copy_from_slice(&0u32.to_le_bytes());
        out[8..16].copy_from_slice(&self.sector.to_le_bytes());
        out
    }
}

/// A planned virtio-blk request descriptor chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRequestPlan {
    pub header: BlockRequestHeader,
    pub descriptors: Vec<Descriptor>,
    pub head: u16,
    pub data_len: u32,
}

impl BlockRequestPlan {
    pub fn chain(&self, queue_size: QueueSize, dma: &DmaMap) -> Result<DescriptorChain> {
        validate_descriptor_chain_for_dma(
            queue_size,
            &self.descriptors,
            self.head,
            Features::empty(),
            dma,
        )
    }
}

/// Direction of a submitted virtio-blk request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockRequestKind {
    Read,
    Write,
}

/// Request tracked between available-ring submission and used-ring completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedBlockRequest {
    pub kind: BlockRequestKind,
    pub head: u16,
    pub sector: u64,
    pub data_len: u32,
    pub available_slot: u16,
}

/// Completed virtio-blk request after status-byte decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedBlockRequest {
    pub request: SubmittedBlockRequest,
    pub used: UsedElement,
}

/// Safe virtio-blk queue service core.
///
/// Device-specific code still owns guest memory writes and MMIO notification;
/// this core owns request planning, available-ring submission, pending id
/// tracking, used-ring consumption, and status decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtioBlkServiceCore {
    queue_size: QueueSize,
    avail: AvailRing,
    pending: BTreeMap<u16, SubmittedBlockRequest>,
    last_used_idx: u16,
}

impl VirtioBlkServiceCore {
    pub fn new(queue_size: QueueSize) -> VirtioBlkServiceCore {
        VirtioBlkServiceCore {
            queue_size,
            avail: AvailRing::new(queue_size),
            pending: BTreeMap::new(),
            last_used_idx: 0,
        }
    }

    pub fn available_idx(&self) -> u16 {
        self.avail.idx()
    }

    pub fn last_used_idx(&self) -> u16 {
        self.last_used_idx
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn submit_read(
        &mut self,
        head: u16,
        header_addr: u64,
        data_addr: u64,
        data_len: u32,
        status_addr: u64,
        sector: u64,
        dma: &DmaMap,
    ) -> Result<BlockRequestPlan> {
        let plan = plan_block_read(
            self.queue_size,
            head,
            header_addr,
            data_addr,
            data_len,
            status_addr,
            sector,
            dma,
        )?;
        self.submit_plan(&plan, BlockRequestKind::Read)?;
        Ok(plan)
    }

    pub fn submit_write(
        &mut self,
        head: u16,
        header_addr: u64,
        data_addr: u64,
        data_len: u32,
        status_addr: u64,
        sector: u64,
        dma: &DmaMap,
    ) -> Result<BlockRequestPlan> {
        let plan = plan_block_write(
            self.queue_size,
            head,
            header_addr,
            data_addr,
            data_len,
            status_addr,
            sector,
            dma,
        )?;
        self.submit_plan(&plan, BlockRequestKind::Write)?;
        Ok(plan)
    }

    fn submit_plan(&mut self, plan: &BlockRequestPlan, kind: BlockRequestKind) -> Result<()> {
        if self.pending.contains_key(&plan.head) {
            return Err(AiueosError::Run(format!(
                "virtio-blk descriptor head {} is already pending",
                plan.head
            )));
        }
        let available_slot = self.avail.push(plan.head)?;
        self.pending.insert(
            plan.head,
            SubmittedBlockRequest {
                kind,
                head: plan.head,
                sector: plan.header.sector,
                data_len: plan.data_len,
                available_slot,
            },
        );
        Ok(())
    }

    pub fn complete_next(
        &mut self,
        used: &UsedRing,
        status_byte: u8,
    ) -> Result<Option<CompletedBlockRequest>> {
        if self.last_used_idx == used.idx() {
            return Ok(None);
        }
        let slot = self.last_used_idx % self.queue_size.get();
        let used_element = used.get(slot)?;
        let head = u16::try_from(used_element.id).map_err(|_| {
            AiueosError::Run(format!(
                "virtio-blk used id {} does not fit u16",
                used_element.id
            ))
        })?;
        let request = self.pending.remove(&head).ok_or_else(|| {
            AiueosError::Run(format!(
                "virtio-blk completion for unknown descriptor head {head}"
            ))
        })?;
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        decode_block_status(status_byte)?;
        Ok(Some(CompletedBlockRequest {
            request,
            used: used_element,
        }))
    }

    pub fn complete_used_element(
        &mut self,
        used_idx: u16,
        used_element: UsedElement,
        status_byte: u8,
    ) -> Result<Option<CompletedBlockRequest>> {
        if used_idx != self.last_used_idx {
            return Err(AiueosError::Run(format!(
                "virtio-blk completion idx {used_idx} does not match expected idx {}",
                self.last_used_idx
            )));
        }
        if used_element.id >= self.queue_size.get() as u32 {
            return Err(AiueosError::Run(format!(
                "virtio-blk used id {} outside queue size {}",
                used_element.id,
                self.queue_size.get()
            )));
        }
        let head = used_element.id as u16;
        let request = self.pending.remove(&head).ok_or_else(|| {
            AiueosError::Run(format!(
                "virtio-blk completion for unknown descriptor head {head}"
            ))
        })?;
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        decode_block_status(status_byte)?;
        Ok(Some(CompletedBlockRequest {
            request,
            used: used_element,
        }))
    }
}

/// Backend boundary that materializes virtio-blk requests in guest memory and
/// exposes queue completions from a real or emulated device.
pub trait VirtioBlkBackend {
    fn write_request(&mut self, plan: &BlockRequestPlan) -> Result<()>;
    fn notify_queue(&mut self, queue_index: u16) -> Result<()>;
    fn next_completion(&mut self, last_used_idx: u16) -> Result<Option<(UsedElement, u8)>>;
}

/// Guest-memory boundary used by emulated or kernel-backed virtio-blk devices.
pub trait GuestMemory {
    fn read_exact(&self, guest_phys: u64, len: usize) -> Result<Vec<u8>>;
    fn write_all(&mut self, guest_phys: u64, bytes: &[u8]) -> Result<()>;
}

/// In-memory guest RAM window for deterministic virtio-blk backend tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VecGuestMemory {
    base: u64,
    bytes: Vec<u8>,
}

impl VecGuestMemory {
    pub fn new(base: u64, len: usize) -> Result<VecGuestMemory> {
        if len == 0 {
            return Err(AiueosError::Schema(
                "guest memory window length must be non-zero".into(),
            ));
        }
        base.checked_add(len as u64)
            .ok_or_else(|| AiueosError::Schema("guest memory window overflows".into()))?;
        Ok(VecGuestMemory {
            base,
            bytes: vec![0; len],
        })
    }

    fn checked_slice(&self, guest_phys: u64, len: usize) -> Result<std::ops::Range<usize>> {
        let offset = guest_phys.checked_sub(self.base).ok_or_else(|| {
            AiueosError::Run(format!(
                "guest address 0x{guest_phys:x} below memory base 0x{:x}",
                self.base
            ))
        })?;
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| AiueosError::Run("guest memory access overflows".into()))?;
        if end > self.bytes.len() as u64 {
            return Err(AiueosError::Run(format!(
                "guest memory range 0x{guest_phys:x}..0x{:x} outside window 0x{:x}..0x{:x}",
                guest_phys.saturating_add(len as u64),
                self.base,
                self.base + self.bytes.len() as u64
            )));
        }
        Ok(offset as usize..end as usize)
    }
}

impl GuestMemory for VecGuestMemory {
    fn read_exact(&self, guest_phys: u64, len: usize) -> Result<Vec<u8>> {
        let range = self.checked_slice(guest_phys, len)?;
        Ok(self.bytes[range].to_vec())
    }

    fn write_all(&mut self, guest_phys: u64, bytes: &[u8]) -> Result<()> {
        let range = self.checked_slice(guest_phys, bytes.len())?;
        self.bytes[range].copy_from_slice(bytes);
        Ok(())
    }
}

/// Synchronous in-memory virtio-blk backend. It is not a production device
/// backend, but it exercises the same provider/backend contract with real
/// guest-memory and sector bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulatedVirtioBlkBackend<M> {
    memory: M,
    sectors: Vec<u8>,
    queue: BTreeMap<u16, BlockRequestPlan>,
    completions: BTreeMap<u16, (UsedElement, u8)>,
    next_used_idx: u16,
}

impl<M: GuestMemory> EmulatedVirtioBlkBackend<M> {
    pub fn new(memory: M, sectors: u64) -> Result<EmulatedVirtioBlkBackend<M>> {
        if sectors == 0 {
            return Err(AiueosError::Schema(
                "virtio-blk backend must expose at least one sector".into(),
            ));
        }
        let bytes = sectors
            .checked_mul(512)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| AiueosError::Schema("virtio-blk backend size overflows".into()))?;
        Ok(EmulatedVirtioBlkBackend {
            memory,
            sectors: vec![0; bytes],
            queue: BTreeMap::new(),
            completions: BTreeMap::new(),
            next_used_idx: 0,
        })
    }

    pub fn memory(&self) -> &M {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    pub fn sectors(&self) -> &[u8] {
        &self.sectors
    }

    pub fn sectors_mut(&mut self) -> &mut [u8] {
        &mut self.sectors
    }

    fn process_plan(&mut self, plan: BlockRequestPlan) -> Result<()> {
        let (status, used_len) = match self.apply_plan(&plan) {
            Ok(len) => (block::S_OK, len),
            Err(_) => (block::S_IOERR, 1),
        };
        let status_addr = plan.descriptors[plan.head as usize + 2].addr;
        self.memory.write_all(status_addr, &[status])?;
        self.completions.insert(
            self.next_used_idx,
            (
                UsedElement {
                    id: plan.head as u32,
                    len: used_len,
                },
                status,
            ),
        );
        self.next_used_idx = self.next_used_idx.wrapping_add(1);
        Ok(())
    }

    fn apply_plan(&mut self, plan: &BlockRequestPlan) -> Result<u32> {
        let header_addr = plan.descriptors[plan.head as usize].addr;
        self.memory.write_all(header_addr, &plan.header.encode())?;
        let data = &plan.descriptors[plan.head as usize + 1];
        let byte_offset = plan
            .header
            .sector
            .checked_mul(512)
            .ok_or_else(|| AiueosError::Run("virtio-blk sector offset overflows".into()))?;
        let end = byte_offset
            .checked_add(plan.data_len as u64)
            .ok_or_else(|| AiueosError::Run("virtio-blk request length overflows".into()))?;
        if end > self.sectors.len() as u64 {
            return Err(AiueosError::Run(format!(
                "virtio-blk request sector {} length {} outside device size {}",
                plan.header.sector,
                plan.data_len,
                self.sectors.len()
            )));
        }
        let range = byte_offset as usize..end as usize;
        match plan.header.request_type {
            block::T_IN => {
                self.memory.write_all(data.addr, &self.sectors[range])?;
                Ok(plan.data_len + 1)
            }
            block::T_OUT => {
                let bytes = self.memory.read_exact(data.addr, plan.data_len as usize)?;
                self.sectors[range].copy_from_slice(&bytes);
                Ok(1)
            }
            other => Err(AiueosError::Run(format!(
                "unsupported virtio-blk request type {other}"
            ))),
        }
    }
}

impl<M: GuestMemory> VirtioBlkBackend for EmulatedVirtioBlkBackend<M> {
    fn write_request(&mut self, plan: &BlockRequestPlan) -> Result<()> {
        if self.queue.contains_key(&plan.head) {
            return Err(AiueosError::Run(format!(
                "virtio-blk backend already queued descriptor head {}",
                plan.head
            )));
        }
        self.queue.insert(plan.head, plan.clone());
        Ok(())
    }

    fn notify_queue(&mut self, _queue_index: u16) -> Result<()> {
        let queued: Vec<_> = std::mem::take(&mut self.queue).into_values().collect();
        for plan in queued {
            self.process_plan(plan)?;
        }
        Ok(())
    }

    fn next_completion(&mut self, last_used_idx: u16) -> Result<Option<(UsedElement, u8)>> {
        Ok(self.completions.remove(&last_used_idx))
    }
}

/// File-backed virtio-blk backend for host/VM smoke paths that present a regular
/// file as a sector-addressed block device.
#[derive(Debug)]
pub struct FileBackedVirtioBlkBackend<M> {
    memory: M,
    file: std::fs::File,
    len: u64,
    queue: BTreeMap<u16, BlockRequestPlan>,
    completions: BTreeMap<u16, (UsedElement, u8)>,
    next_used_idx: u16,
}

impl<M: GuestMemory> FileBackedVirtioBlkBackend<M> {
    pub fn new(memory: M, file: std::fs::File) -> Result<FileBackedVirtioBlkBackend<M>> {
        let len = file.metadata()?.len();
        if len == 0 || len % 512 != 0 {
            return Err(AiueosError::Schema(format!(
                "virtio-blk backing file length must be a non-zero multiple of 512, got {len}"
            )));
        }
        Ok(FileBackedVirtioBlkBackend {
            memory,
            file,
            len,
            queue: BTreeMap::new(),
            completions: BTreeMap::new(),
            next_used_idx: 0,
        })
    }

    pub fn memory(&self) -> &M {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    fn process_plan(&mut self, plan: BlockRequestPlan) -> Result<()> {
        let (status, used_len) = match self.apply_plan(&plan) {
            Ok(len) => (block::S_OK, len),
            Err(_) => (block::S_IOERR, 1),
        };
        let status_addr = plan.descriptors[plan.head as usize + 2].addr;
        self.memory.write_all(status_addr, &[status])?;
        self.completions.insert(
            self.next_used_idx,
            (
                UsedElement {
                    id: plan.head as u32,
                    len: used_len,
                },
                status,
            ),
        );
        self.next_used_idx = self.next_used_idx.wrapping_add(1);
        Ok(())
    }

    fn apply_plan(&mut self, plan: &BlockRequestPlan) -> Result<u32> {
        use std::io::{Read, Seek, SeekFrom, Write};

        let header_addr = plan.descriptors[plan.head as usize].addr;
        self.memory.write_all(header_addr, &plan.header.encode())?;
        let data = &plan.descriptors[plan.head as usize + 1];
        let byte_offset = plan
            .header
            .sector
            .checked_mul(512)
            .ok_or_else(|| AiueosError::Run("virtio-blk sector offset overflows".into()))?;
        let end = byte_offset
            .checked_add(plan.data_len as u64)
            .ok_or_else(|| AiueosError::Run("virtio-blk request length overflows".into()))?;
        if end > self.len {
            return Err(AiueosError::Run(format!(
                "virtio-blk file request sector {} length {} outside backing length {}",
                plan.header.sector, plan.data_len, self.len
            )));
        }
        self.file.seek(SeekFrom::Start(byte_offset))?;
        match plan.header.request_type {
            block::T_IN => {
                let mut bytes = vec![0; plan.data_len as usize];
                self.file.read_exact(&mut bytes)?;
                self.memory.write_all(data.addr, &bytes)?;
                Ok(plan.data_len + 1)
            }
            block::T_OUT => {
                let bytes = self.memory.read_exact(data.addr, plan.data_len as usize)?;
                self.file.write_all(&bytes)?;
                self.file.flush()?;
                Ok(1)
            }
            other => Err(AiueosError::Run(format!(
                "unsupported virtio-blk request type {other}"
            ))),
        }
    }
}

impl<M: GuestMemory> VirtioBlkBackend for FileBackedVirtioBlkBackend<M> {
    fn write_request(&mut self, plan: &BlockRequestPlan) -> Result<()> {
        if self.queue.contains_key(&plan.head) {
            return Err(AiueosError::Run(format!(
                "virtio-blk backend already queued descriptor head {}",
                plan.head
            )));
        }
        self.queue.insert(plan.head, plan.clone());
        Ok(())
    }

    fn notify_queue(&mut self, _queue_index: u16) -> Result<()> {
        let queued: Vec<_> = std::mem::take(&mut self.queue).into_values().collect();
        for plan in queued {
            self.process_plan(plan)?;
        }
        Ok(())
    }

    fn next_completion(&mut self, last_used_idx: u16) -> Result<Option<(UsedElement, u8)>> {
        Ok(self.completions.remove(&last_used_idx))
    }
}

/// Component-facing block provider adapter over the safe virtio-blk service
/// core and a device backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtioBlkProviderCore {
    service: VirtioBlkServiceCore,
    queue_index: u16,
}

impl VirtioBlkProviderCore {
    pub fn new(queue_size: QueueSize, queue_index: u16) -> VirtioBlkProviderCore {
        VirtioBlkProviderCore {
            service: VirtioBlkServiceCore::new(queue_size),
            queue_index,
        }
    }

    pub fn service(&self) -> &VirtioBlkServiceCore {
        &self.service
    }

    pub fn submit_read<B: VirtioBlkBackend>(
        &mut self,
        backend: &mut B,
        head: u16,
        header_addr: u64,
        data_addr: u64,
        data_len: u32,
        status_addr: u64,
        sector: u64,
        dma: &DmaMap,
    ) -> Result<BlockRequestPlan> {
        let plan = plan_block_read(
            self.service.queue_size,
            head,
            header_addr,
            data_addr,
            data_len,
            status_addr,
            sector,
            dma,
        )?;
        backend.write_request(&plan)?;
        self.service.submit_plan(&plan, BlockRequestKind::Read)?;
        backend.notify_queue(self.queue_index)?;
        Ok(plan)
    }

    pub fn submit_write<B: VirtioBlkBackend>(
        &mut self,
        backend: &mut B,
        head: u16,
        header_addr: u64,
        data_addr: u64,
        data_len: u32,
        status_addr: u64,
        sector: u64,
        dma: &DmaMap,
    ) -> Result<BlockRequestPlan> {
        let plan = plan_block_write(
            self.service.queue_size,
            head,
            header_addr,
            data_addr,
            data_len,
            status_addr,
            sector,
            dma,
        )?;
        backend.write_request(&plan)?;
        self.service.submit_plan(&plan, BlockRequestKind::Write)?;
        backend.notify_queue(self.queue_index)?;
        Ok(plan)
    }

    pub fn poll_completion<B: VirtioBlkBackend>(
        &mut self,
        backend: &mut B,
    ) -> Result<Option<CompletedBlockRequest>> {
        let used_idx = self.service.last_used_idx();
        let Some((used, status)) = backend.next_completion(used_idx)? else {
            return Ok(None);
        };
        self.service.complete_used_element(used_idx, used, status)
    }
}

/// Plan a three-descriptor virtio-blk read request.
pub fn plan_block_read(
    queue_size: QueueSize,
    head: u16,
    header_addr: u64,
    data_addr: u64,
    data_len: u32,
    status_addr: u64,
    sector: u64,
    dma: &DmaMap,
) -> Result<BlockRequestPlan> {
    plan_block_request(
        queue_size,
        head,
        BlockRequestHeader::read(sector),
        header_addr,
        data_addr,
        data_len,
        status_addr,
        true,
        dma,
    )
}

/// Plan a three-descriptor virtio-blk write request.
pub fn plan_block_write(
    queue_size: QueueSize,
    head: u16,
    header_addr: u64,
    data_addr: u64,
    data_len: u32,
    status_addr: u64,
    sector: u64,
    dma: &DmaMap,
) -> Result<BlockRequestPlan> {
    plan_block_request(
        queue_size,
        head,
        BlockRequestHeader::write(sector),
        header_addr,
        data_addr,
        data_len,
        status_addr,
        false,
        dma,
    )
}

fn plan_block_request(
    queue_size: QueueSize,
    head: u16,
    header: BlockRequestHeader,
    header_addr: u64,
    data_addr: u64,
    data_len: u32,
    status_addr: u64,
    read_into_data: bool,
    dma: &DmaMap,
) -> Result<BlockRequestPlan> {
    if data_len == 0 || data_len % 512 != 0 {
        return Err(AiueosError::Schema(format!(
            "virtio-blk data length must be a non-zero multiple of 512, got {data_len}"
        )));
    }
    let q = queue_size.get();
    if head.checked_add(2).is_none_or(|tail| tail >= q) {
        return Err(AiueosError::Schema(format!(
            "virtio-blk request needs three contiguous descriptors starting at {head} in queue size {q}"
        )));
    }
    let data = if read_into_data {
        Descriptor::write(data_addr, data_len)
    } else {
        Descriptor::read(data_addr, data_len)
    };
    let mut descriptors = vec![Descriptor::read(0, 1); q as usize];
    descriptors[head as usize] =
        Descriptor::read(header_addr, BlockRequestHeader::LEN).with_next(head.saturating_add(1));
    descriptors[head as usize + 1] = data.with_next(head.saturating_add(2));
    descriptors[head as usize + 2] = Descriptor::write(status_addr, 1);

    validate_descriptor_chain_for_dma(queue_size, &descriptors, head, Features::empty(), dma)?;
    Ok(BlockRequestPlan {
        header,
        descriptors,
        head,
        data_len,
    })
}

/// Decode a virtio-blk status byte into a host result.
pub fn decode_block_status(status: u8) -> Result<()> {
    match status {
        block::S_OK => Ok(()),
        block::S_IOERR => Err(AiueosError::Run("virtio-blk I/O error".into())),
        block::S_UNSUPP => Err(AiueosError::Run(
            "virtio-blk request is unsupported by device".into(),
        )),
        other => Err(AiueosError::Run(format!(
            "unknown virtio-blk status {other}"
        ))),
    }
}

/// Direction of a submitted virtio-console buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleRequestKind {
    Receive,
    Transmit,
}

/// A planned virtio-console request. Console queues use a single descriptor:
/// receive buffers are device-writable, transmit buffers are device-readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleRequestPlan {
    pub kind: ConsoleRequestKind,
    pub descriptors: Vec<Descriptor>,
    pub head: u16,
    pub data_addr: u64,
    pub data_len: u32,
}

impl ConsoleRequestPlan {
    pub fn chain(&self, queue_size: QueueSize, dma: &DmaMap) -> Result<DescriptorChain> {
        validate_descriptor_chain_for_dma(
            queue_size,
            &self.descriptors,
            self.head,
            Features::empty(),
            dma,
        )
    }
}

/// Request tracked between available-ring submission and used-ring completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedConsoleRequest {
    pub kind: ConsoleRequestKind,
    pub head: u16,
    pub data_addr: u64,
    pub data_len: u32,
    pub available_slot: u16,
}

/// Completed virtio-console request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedConsoleRequest {
    pub request: SubmittedConsoleRequest,
    pub used: UsedElement,
}

/// Safe virtio-console queue service core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtioConsoleServiceCore {
    queue_size: QueueSize,
    avail: AvailRing,
    pending: BTreeMap<u16, SubmittedConsoleRequest>,
    last_used_idx: u16,
}

impl VirtioConsoleServiceCore {
    pub fn new(queue_size: QueueSize) -> VirtioConsoleServiceCore {
        VirtioConsoleServiceCore {
            queue_size,
            avail: AvailRing::new(queue_size),
            pending: BTreeMap::new(),
            last_used_idx: 0,
        }
    }

    pub fn available_idx(&self) -> u16 {
        self.avail.idx()
    }

    pub fn last_used_idx(&self) -> u16 {
        self.last_used_idx
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn submit_receive(
        &mut self,
        head: u16,
        data_addr: u64,
        data_len: u32,
        dma: &DmaMap,
    ) -> Result<ConsoleRequestPlan> {
        let plan = plan_console_receive(self.queue_size, head, data_addr, data_len, dma)?;
        self.submit_plan(&plan)?;
        Ok(plan)
    }

    pub fn submit_transmit(
        &mut self,
        head: u16,
        data_addr: u64,
        data_len: u32,
        dma: &DmaMap,
    ) -> Result<ConsoleRequestPlan> {
        let plan = plan_console_transmit(self.queue_size, head, data_addr, data_len, dma)?;
        self.submit_plan(&plan)?;
        Ok(plan)
    }

    fn submit_plan(&mut self, plan: &ConsoleRequestPlan) -> Result<()> {
        if self.pending.contains_key(&plan.head) {
            return Err(AiueosError::Run(format!(
                "virtio-console descriptor head {} is already pending",
                plan.head
            )));
        }
        let available_slot = self.avail.push(plan.head)?;
        self.pending.insert(
            plan.head,
            SubmittedConsoleRequest {
                kind: plan.kind,
                head: plan.head,
                data_addr: plan.data_addr,
                data_len: plan.data_len,
                available_slot,
            },
        );
        Ok(())
    }

    pub fn complete_next(&mut self, used: &UsedRing) -> Result<Option<CompletedConsoleRequest>> {
        if self.last_used_idx == used.idx() {
            return Ok(None);
        }
        let slot = self.last_used_idx % self.queue_size.get();
        let used_element = used.get(slot)?;
        self.complete_used_element(self.last_used_idx, used_element)
    }

    pub fn complete_used_element(
        &mut self,
        used_idx: u16,
        used_element: UsedElement,
    ) -> Result<Option<CompletedConsoleRequest>> {
        if used_idx != self.last_used_idx {
            return Err(AiueosError::Run(format!(
                "virtio-console completion idx {used_idx} does not match expected idx {}",
                self.last_used_idx
            )));
        }
        if used_element.id >= self.queue_size.get() as u32 {
            return Err(AiueosError::Run(format!(
                "virtio-console used id {} outside queue size {}",
                used_element.id,
                self.queue_size.get()
            )));
        }
        let head = used_element.id as u16;
        let request = self.pending.remove(&head).ok_or_else(|| {
            AiueosError::Run(format!(
                "virtio-console completion for unknown descriptor head {head}"
            ))
        })?;
        if used_element.len > request.data_len {
            return Err(AiueosError::Run(format!(
                "virtio-console completion length {} exceeds buffer length {}",
                used_element.len, request.data_len
            )));
        }
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Ok(Some(CompletedConsoleRequest {
            request,
            used: used_element,
        }))
    }
}

/// Backend boundary that materializes virtio-console buffers in guest memory
/// and exposes queue completions from a real or emulated device.
pub trait VirtioConsoleBackend {
    fn write_request(&mut self, plan: &ConsoleRequestPlan) -> Result<()>;
    fn notify_queue(&mut self, queue_index: u16) -> Result<()>;
    fn next_completion(&mut self, last_used_idx: u16) -> Result<Option<UsedElement>>;
}

/// Synchronous in-memory virtio-console backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulatedVirtioConsoleBackend<M> {
    memory: M,
    input: VecDeque<u8>,
    output: Vec<u8>,
    queue: BTreeMap<u16, ConsoleRequestPlan>,
    completions: BTreeMap<u16, UsedElement>,
    next_used_idx: u16,
}

impl<M: GuestMemory> EmulatedVirtioConsoleBackend<M> {
    pub fn new(memory: M) -> EmulatedVirtioConsoleBackend<M> {
        EmulatedVirtioConsoleBackend {
            memory,
            input: VecDeque::new(),
            output: Vec::new(),
            queue: BTreeMap::new(),
            completions: BTreeMap::new(),
            next_used_idx: 0,
        }
    }

    pub fn memory(&self) -> &M {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    pub fn push_input(&mut self, bytes: impl IntoIterator<Item = u8>) {
        self.input.extend(bytes);
    }

    pub fn output(&self) -> &[u8] {
        &self.output
    }

    fn process_plan(&mut self, plan: ConsoleRequestPlan) -> Result<()> {
        let used_len = match plan.kind {
            ConsoleRequestKind::Receive => {
                let max = plan.data_len as usize;
                let len = max.min(self.input.len());
                let bytes: Vec<u8> = self.input.drain(..len).collect();
                self.memory.write_all(plan.data_addr, &bytes)?;
                len as u32
            }
            ConsoleRequestKind::Transmit => {
                let bytes = self
                    .memory
                    .read_exact(plan.data_addr, plan.data_len as usize)?;
                self.output.extend_from_slice(&bytes);
                plan.data_len
            }
        };
        self.completions.insert(
            self.next_used_idx,
            UsedElement {
                id: plan.head as u32,
                len: used_len,
            },
        );
        self.next_used_idx = self.next_used_idx.wrapping_add(1);
        Ok(())
    }
}

impl<M: GuestMemory> VirtioConsoleBackend for EmulatedVirtioConsoleBackend<M> {
    fn write_request(&mut self, plan: &ConsoleRequestPlan) -> Result<()> {
        if self.queue.contains_key(&plan.head) {
            return Err(AiueosError::Run(format!(
                "virtio-console backend already queued descriptor head {}",
                plan.head
            )));
        }
        self.queue.insert(plan.head, plan.clone());
        Ok(())
    }

    fn notify_queue(&mut self, _queue_index: u16) -> Result<()> {
        let queued: Vec<_> = std::mem::take(&mut self.queue).into_values().collect();
        for plan in queued {
            self.process_plan(plan)?;
        }
        Ok(())
    }

    fn next_completion(&mut self, last_used_idx: u16) -> Result<Option<UsedElement>> {
        Ok(self.completions.remove(&last_used_idx))
    }
}

/// Component-facing console provider adapter over the safe virtio-console
/// service core and a device backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtioConsoleProviderCore {
    service: VirtioConsoleServiceCore,
    queue_index: u16,
}

impl VirtioConsoleProviderCore {
    pub fn new(queue_size: QueueSize, queue_index: u16) -> VirtioConsoleProviderCore {
        VirtioConsoleProviderCore {
            service: VirtioConsoleServiceCore::new(queue_size),
            queue_index,
        }
    }

    pub fn service(&self) -> &VirtioConsoleServiceCore {
        &self.service
    }

    pub fn submit_receive<B: VirtioConsoleBackend>(
        &mut self,
        backend: &mut B,
        head: u16,
        data_addr: u64,
        data_len: u32,
        dma: &DmaMap,
    ) -> Result<ConsoleRequestPlan> {
        let plan = plan_console_receive(self.service.queue_size, head, data_addr, data_len, dma)?;
        backend.write_request(&plan)?;
        self.service.submit_plan(&plan)?;
        backend.notify_queue(self.queue_index)?;
        Ok(plan)
    }

    pub fn submit_transmit<B: VirtioConsoleBackend>(
        &mut self,
        backend: &mut B,
        head: u16,
        data_addr: u64,
        data_len: u32,
        dma: &DmaMap,
    ) -> Result<ConsoleRequestPlan> {
        let plan = plan_console_transmit(self.service.queue_size, head, data_addr, data_len, dma)?;
        backend.write_request(&plan)?;
        self.service.submit_plan(&plan)?;
        backend.notify_queue(self.queue_index)?;
        Ok(plan)
    }

    pub fn poll_completion<B: VirtioConsoleBackend>(
        &mut self,
        backend: &mut B,
    ) -> Result<Option<CompletedConsoleRequest>> {
        let used_idx = self.service.last_used_idx();
        let Some(used) = backend.next_completion(used_idx)? else {
            return Ok(None);
        };
        self.service.complete_used_element(used_idx, used)
    }
}

/// Plan a one-descriptor virtio-console receive buffer.
pub fn plan_console_receive(
    queue_size: QueueSize,
    head: u16,
    data_addr: u64,
    data_len: u32,
    dma: &DmaMap,
) -> Result<ConsoleRequestPlan> {
    plan_console_request(
        queue_size,
        head,
        data_addr,
        data_len,
        ConsoleRequestKind::Receive,
        true,
        dma,
    )
}

/// Plan a one-descriptor virtio-console transmit buffer.
pub fn plan_console_transmit(
    queue_size: QueueSize,
    head: u16,
    data_addr: u64,
    data_len: u32,
    dma: &DmaMap,
) -> Result<ConsoleRequestPlan> {
    plan_console_request(
        queue_size,
        head,
        data_addr,
        data_len,
        ConsoleRequestKind::Transmit,
        false,
        dma,
    )
}

fn plan_console_request(
    queue_size: QueueSize,
    head: u16,
    data_addr: u64,
    data_len: u32,
    kind: ConsoleRequestKind,
    device_writes: bool,
    dma: &DmaMap,
) -> Result<ConsoleRequestPlan> {
    if data_len == 0 {
        return Err(AiueosError::Schema(
            "virtio-console data length must be non-zero".into(),
        ));
    }
    if head >= queue_size.get() {
        return Err(AiueosError::Schema(format!(
            "virtio-console descriptor head {head} outside queue size {}",
            queue_size.get()
        )));
    }
    let mut descriptors = vec![Descriptor::read(0, 1); queue_size.get() as usize];
    descriptors[head as usize] = if device_writes {
        Descriptor::write(data_addr, data_len)
    } else {
        Descriptor::read(data_addr, data_len)
    };
    validate_descriptor_chain_for_dma(queue_size, &descriptors, head, Features::empty(), dma)?;
    Ok(ConsoleRequestPlan {
        kind,
        descriptors,
        head,
        data_addr,
        data_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    struct MemTransport {
        device_type: DeviceType,
        status: u8,
        offered: Features,
        driver_features: Features,
        reject_features: bool,
    }

    impl MemTransport {
        fn new(device_type: DeviceType, offered: Features) -> MemTransport {
            MemTransport {
                device_type,
                status: 0,
                offered,
                driver_features: Features::empty(),
                reject_features: false,
            }
        }
    }

    impl Transport for MemTransport {
        fn device_type(&self) -> DeviceType {
            self.device_type
        }

        fn read_status(&self) -> u8 {
            self.status
        }

        fn write_status(&mut self, status: u8) {
            self.status = if self.reject_features && status & status::FEATURES_OK != 0 {
                status & !status::FEATURES_OK
            } else {
                status
            };
        }

        fn device_features(&self) -> Features {
            self.offered
        }

        fn write_driver_features(&mut self, features: Features) {
            self.driver_features = features;
        }
    }

    #[derive(Debug, Clone)]
    struct MemMmio {
        regs: BTreeMap<u64, u32>,
        device_feature_sel: u32,
        driver_feature_sel: u32,
        offered: Features,
        driver_features: Features,
        reject_features: bool,
    }

    impl MemMmio {
        fn new(device_type: DeviceType, offered: Features) -> MemMmio {
            let mut regs = BTreeMap::new();
            regs.insert(mmio::MAGIC_VALUE, mmio::MAGIC);
            regs.insert(mmio::VERSION, mmio::VERSION_2);
            regs.insert(mmio::DEVICE_ID, device_type as u32);
            regs.insert(mmio::QUEUE_NUM_MAX, 8);
            MemMmio {
                regs,
                device_feature_sel: 0,
                driver_feature_sel: 0,
                offered,
                driver_features: Features::empty(),
                reject_features: false,
            }
        }
    }

    impl MmioRegisterIo for MemMmio {
        fn read32(&mut self, offset: u64) -> u32 {
            match offset {
                mmio::DEVICE_FEATURES => {
                    if self.device_feature_sel == 0 {
                        self.offered.bits() as u32
                    } else {
                        (self.offered.bits() >> 32) as u32
                    }
                }
                _ => *self.regs.get(&offset).unwrap_or(&0),
            }
        }

        fn write32(&mut self, offset: u64, value: u32) {
            match offset {
                mmio::DEVICE_FEATURES_SEL => self.device_feature_sel = value,
                mmio::DRIVER_FEATURES_SEL => self.driver_feature_sel = value,
                mmio::DRIVER_FEATURES => {
                    let low = if self.driver_feature_sel == 0 {
                        value
                    } else {
                        self.driver_features.bits() as u32
                    };
                    let high = if self.driver_feature_sel == 1 {
                        value
                    } else {
                        (self.driver_features.bits() >> 32) as u32
                    };
                    self.driver_features = Features(low as u64 | ((high as u64) << 32));
                    self.regs.insert(offset, value);
                }
                mmio::STATUS if self.reject_features && value as u8 & status::FEATURES_OK != 0 => {
                    self.regs
                        .insert(offset, value & !(status::FEATURES_OK as u32));
                }
                _ => {
                    self.regs.insert(offset, value);
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    struct MemPciConfig {
        bytes: [u8; pci::CONFIG_SPACE_LEN as usize],
    }

    impl MemPciConfig {
        fn new() -> MemPciConfig {
            MemPciConfig {
                bytes: [0; pci::CONFIG_SPACE_LEN as usize],
            }
        }

        fn enable_caps(&mut self, first: u8) {
            self.write16(pci::STATUS, pci::STATUS_CAPABILITIES);
            self.write8(pci::CAP_POINTER, first);
        }

        fn write8(&mut self, offset: u16, value: u8) {
            self.bytes[offset as usize] = value;
        }

        fn write16(&mut self, offset: u16, value: u16) {
            self.bytes[offset as usize..offset as usize + 2].copy_from_slice(&value.to_le_bytes());
        }

        fn write32(&mut self, offset: u16, value: u32) {
            self.bytes[offset as usize..offset as usize + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn write_virtio_cap(
            &mut self,
            ptr: u8,
            next: u8,
            cfg_type: u8,
            bar: u8,
            offset: u32,
            length: u32,
            notify_mult: u32,
        ) {
            let cap_len = if cfg_type == pci::NOTIFY_CFG { 20 } else { 16 };
            self.write8(ptr as u16, pci::CAP_ID_VENDOR_SPECIFIC);
            self.write8(ptr as u16 + 1, next);
            self.write8(ptr as u16 + 2, cap_len);
            self.write8(ptr as u16 + 3, cfg_type);
            self.write8(ptr as u16 + 4, bar);
            self.write32(ptr as u16 + 8, offset);
            self.write32(ptr as u16 + 12, length);
            if cfg_type == pci::NOTIFY_CFG {
                self.write32(ptr as u16 + 16, notify_mult);
            }
        }
    }

    impl PciConfigIo for MemPciConfig {
        fn read8(&mut self, offset: u16) -> u8 {
            self.bytes[offset as usize]
        }

        fn read16(&mut self, offset: u16) -> u16 {
            u16::from_le_bytes([self.bytes[offset as usize], self.bytes[offset as usize + 1]])
        }

        fn read32(&mut self, offset: u16) -> u32 {
            u32::from_le_bytes([
                self.bytes[offset as usize],
                self.bytes[offset as usize + 1],
                self.bytes[offset as usize + 2],
                self.bytes[offset as usize + 3],
            ])
        }
    }

    #[derive(Debug, Default)]
    struct MemIommu {
        mapped: Vec<DmaAllocation>,
        fail_on: Option<u64>,
        unmapped: Vec<DmaAllocation>,
    }

    impl Iommu for MemIommu {
        fn map_dma(&mut self, allocation: DmaAllocation) -> Result<()> {
            if self.fail_on == Some(allocation.guest_phys) {
                return Err(AiueosError::Run(format!(
                    "IOMMU refused DMA mapping at 0x{:x}",
                    allocation.guest_phys
                )));
            }
            self.mapped.push(allocation);
            Ok(())
        }

        fn unmap_dma(&mut self, allocation: DmaAllocation) -> Result<()> {
            self.unmapped.push(allocation);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct MemIrqController {
        subscriptions: Vec<VirtioIrqSubscription>,
        fail: bool,
    }

    impl VirtioIrqController for MemIrqController {
        fn subscribe_virtio_irq(&mut self, subscription: VirtioIrqSubscription) -> Result<()> {
            if self.fail {
                return Err(AiueosError::Run(
                    "IRQ controller refused subscription".into(),
                ));
            }
            self.subscriptions.push(subscription);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct MemInterruptSink {
        events: Vec<VirtioInterruptEvent>,
        fail: bool,
    }

    impl VirtioInterruptSink for MemInterruptSink {
        fn deliver_virtio_interrupt(&mut self, event: VirtioInterruptEvent) -> Result<()> {
            if self.fail {
                return Err(AiueosError::Run("interrupt sink refused event".into()));
            }
            self.events.push(event);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct MemBlkBackend {
        written: Vec<BlockRequestPlan>,
        notified: Vec<u16>,
        completions: BTreeMap<u16, (UsedElement, u8)>,
        fail_write: bool,
    }

    impl VirtioBlkBackend for MemBlkBackend {
        fn write_request(&mut self, plan: &BlockRequestPlan) -> Result<()> {
            if self.fail_write {
                return Err(AiueosError::Run(
                    "virtio-blk backend refused request materialization".into(),
                ));
            }
            self.written.push(plan.clone());
            Ok(())
        }

        fn notify_queue(&mut self, queue_index: u16) -> Result<()> {
            self.notified.push(queue_index);
            Ok(())
        }

        fn next_completion(&mut self, last_used_idx: u16) -> Result<Option<(UsedElement, u8)>> {
            Ok(self.completions.remove(&last_used_idx))
        }
    }

    #[derive(Debug, Default)]
    struct MemConsoleBackend {
        written: Vec<ConsoleRequestPlan>,
        notified: Vec<u16>,
        completions: BTreeMap<u16, UsedElement>,
        fail_write: bool,
    }

    impl VirtioConsoleBackend for MemConsoleBackend {
        fn write_request(&mut self, plan: &ConsoleRequestPlan) -> Result<()> {
            if self.fail_write {
                return Err(AiueosError::Run(
                    "virtio-console backend refused request materialization".into(),
                ));
            }
            self.written.push(plan.clone());
            Ok(())
        }

        fn notify_queue(&mut self, queue_index: u16) -> Result<()> {
            self.notified.push(queue_index);
            Ok(())
        }

        fn next_completion(&mut self, last_used_idx: u16) -> Result<Option<UsedElement>> {
            Ok(self.completions.remove(&last_used_idx))
        }
    }

    fn temp_backing_file(name: &str, bytes: &[u8]) -> (std::path::PathBuf, std::fs::File) {
        let path = std::env::temp_dir().join(format!(
            "aiueos-virtio-blk-{}-{name}.img",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, bytes).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        (path, file)
    }

    #[test]
    fn volatile_mmio_reads_and_writes_32_bit_registers() {
        let mut regs = [0u32; 8];
        let mut mmio = unsafe { VolatileMmio::new(regs.as_mut_ptr().cast::<u8>(), 32).unwrap() };
        mmio.try_write32(4, 0xfeed_beef).unwrap();
        assert_eq!(mmio.try_read32(4).unwrap(), 0xfeed_beef);
        assert_eq!(regs[1], 0xfeed_beef);
    }

    #[test]
    fn device_type_reports_provider_capabilities() {
        assert_eq!(DeviceType::Console.capability(), "console/read");
        assert_eq!(
            DeviceType::Console.capabilities(),
            &["console/read", "console/write"]
        );
        assert_eq!(
            DeviceType::Block.capabilities(),
            &["block/read", "block/write"]
        );
    }

    #[test]
    fn volatile_mmio_rejects_bad_windows_and_offsets() {
        let mut regs = [0u32; 2];
        assert!(unsafe { VolatileMmio::new(std::ptr::null_mut(), 8) }.is_err());
        assert!(unsafe { VolatileMmio::new(regs.as_mut_ptr().cast::<u8>(), 0) }.is_err());

        let mut mmio = unsafe { VolatileMmio::new(regs.as_mut_ptr().cast::<u8>(), 8).unwrap() };
        assert!(mmio.try_read32(2).is_err());
        assert!(mmio.try_read32(8).is_err());
        assert!(mmio.try_write32(u64::MAX, 1).is_err());
    }

    #[test]
    fn volatile_mmio_can_back_the_mmio_transport() {
        let mut regs = [0u32; 80];
        regs[(mmio::MAGIC_VALUE / 4) as usize] = mmio::MAGIC;
        regs[(mmio::VERSION / 4) as usize] = mmio::VERSION_2;
        regs[(mmio::DEVICE_ID / 4) as usize] = DeviceType::Gpu as u32;
        regs[(mmio::DEVICE_FEATURES / 4) as usize] = Features::VERSION_1.bits() as u32;
        regs[(mmio::QUEUE_NUM_MAX / 4) as usize] = 8;

        let mmio = unsafe {
            VolatileMmio::new(
                regs.as_mut_ptr().cast::<u8>(),
                (regs.len() * std::mem::size_of::<u32>()) as u64,
            )
            .unwrap()
        };
        let mut transport = MmioTransport::new(mmio).unwrap();
        let init = initialize_mmio_transport(
            &mut transport,
            DeviceType::Gpu,
            Features::empty(),
            Features::empty(),
        )
        .unwrap();
        assert_eq!(init.device_type, DeviceType::Gpu);
        drop(transport);
        assert_eq!(
            regs[(mmio::STATUS / 4) as usize] as u8,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK
        );
    }

    #[test]
    fn pci_capability_validation_rejects_invalid_regions_and_notify_multiplier() {
        assert!(PciBarRegion::new(6, 0, 1).is_err());
        assert!(PciBarRegion::new(0, 0, 0).is_err());
        assert!(PciBarRegion::new(0, u64::MAX, 2).is_err());
        assert!(PciCapability::new(99, 0, 0, 16, 0).is_err());
        assert!(PciCapability::new(pci::NOTIFY_CFG, 0, 0, 16, 0).is_err());
    }

    #[test]
    fn pci_transport_regions_resolve_required_capabilities() {
        let regions = resolve_pci_transport_regions([
            PciCapability::new(pci::COMMON_CFG, 4, 0x1000, 0x100, 0).unwrap(),
            PciCapability::new(pci::NOTIFY_CFG, 4, 0x2000, 0x100, 4).unwrap(),
            PciCapability::new(pci::ISR_CFG, 4, 0x3000, 0x20, 0).unwrap(),
            PciCapability::new(pci::DEVICE_CFG, 4, 0x4000, 0x80, 0).unwrap(),
        ])
        .unwrap();
        assert_eq!(regions.common, PciBarRegion::new(4, 0x1000, 0x100).unwrap());
        assert_eq!(regions.notify, PciBarRegion::new(4, 0x2000, 0x100).unwrap());
        assert_eq!(regions.isr, PciBarRegion::new(4, 0x3000, 0x20).unwrap());
        assert_eq!(
            regions.device,
            Some(PciBarRegion::new(4, 0x4000, 0x80).unwrap())
        );
        assert_eq!(regions.notify_addr(3).unwrap(), (4, 0x200c));
    }

    #[test]
    fn pci_transport_regions_reject_missing_duplicate_and_bad_notify_offsets() {
        assert!(resolve_pci_transport_regions([
            PciCapability::new(pci::COMMON_CFG, 0, 0x1000, 0x100, 0).unwrap(),
            PciCapability::new(pci::ISR_CFG, 0, 0x3000, 0x20, 0).unwrap(),
        ])
        .is_err());

        assert!(resolve_pci_transport_regions([
            PciCapability::new(pci::COMMON_CFG, 0, 0x1000, 0x100, 0).unwrap(),
            PciCapability::new(pci::COMMON_CFG, 0, 0x1100, 0x100, 0).unwrap(),
            PciCapability::new(pci::NOTIFY_CFG, 0, 0x2000, 0x100, 4).unwrap(),
            PciCapability::new(pci::ISR_CFG, 0, 0x3000, 0x20, 0).unwrap(),
        ])
        .is_err());

        let regions = resolve_pci_transport_regions([
            PciCapability::new(pci::COMMON_CFG, 0, 0x1000, 0x100, 0).unwrap(),
            PciCapability::new(pci::NOTIFY_CFG, 0, 0x2000, 0x8, 4).unwrap(),
            PciCapability::new(pci::ISR_CFG, 0, 0x3000, 0x20, 0).unwrap(),
        ])
        .unwrap();
        assert!(regions.notify_addr(2).is_err());
    }

    #[test]
    fn pci_bar_mapping_slices_verified_regions() {
        let mut bar0 = [0u32; 128];
        let mut bar2 = [0u32; 128];
        let mapping0 = unsafe {
            PciBarMapping::new(
                0,
                bar0.as_mut_ptr().cast::<u8>(),
                (bar0.len() * std::mem::size_of::<u32>()) as u64,
            )
            .unwrap()
        };
        let mapping2 = unsafe {
            PciBarMapping::new(
                2,
                bar2.as_mut_ptr().cast::<u8>(),
                (bar2.len() * std::mem::size_of::<u32>()) as u64,
            )
            .unwrap()
        };
        let regions = PciTransportRegions {
            common: PciBarRegion::new(0, 0x10, 0x40).unwrap(),
            notify: PciBarRegion::new(0, 0x80, 0x40).unwrap(),
            isr: PciBarRegion::new(2, 0x00, 0x20).unwrap(),
            device: Some(PciBarRegion::new(2, 0x40, 0x20).unwrap()),
            notify_off_multiplier: 4,
        };
        let mut mapped = map_pci_transport_regions(regions, [mapping0, mapping2]).unwrap();
        mapped.common.try_write32(0, 0xaaaa_5555).unwrap();
        mapped.notify.try_write32(4, 0x1111_2222).unwrap();
        mapped.isr.try_write32(0, 0x3333_4444).unwrap();
        mapped
            .device
            .as_mut()
            .unwrap()
            .try_write32(0, 0x5555_6666)
            .unwrap();
        assert_eq!(bar0[0x10 / 4], 0xaaaa_5555);
        assert_eq!(bar0[(0x80 + 4) / 4], 0x1111_2222);
        assert_eq!(bar2[0], 0x3333_4444);
        assert_eq!(bar2[0x40 / 4], 0x5555_6666);
        assert_eq!(mapped.notify_off_multiplier, 4);
    }

    #[test]
    fn pci_bar_mapping_rejects_invalid_or_unproven_regions() {
        let mut bar0 = [0u32; 4];
        assert!(unsafe { PciBarMapping::new(6, bar0.as_mut_ptr().cast::<u8>(), 16) }.is_err());
        assert!(unsafe { PciBarMapping::new(0, std::ptr::null_mut(), 16) }.is_err());
        assert!(unsafe { PciBarMapping::new(0, bar0.as_mut_ptr().cast::<u8>(), 0) }.is_err());

        let mapping = unsafe { PciBarMapping::new(0, bar0.as_mut_ptr().cast::<u8>(), 16).unwrap() };
        assert!(mapping
            .volatile_region(PciBarRegion::new(0, 12, 8).unwrap())
            .is_err());

        let regions = PciTransportRegions {
            common: PciBarRegion::new(0, 0, 16).unwrap(),
            notify: PciBarRegion::new(1, 0, 16).unwrap(),
            isr: PciBarRegion::new(0, 0, 16).unwrap(),
            device: None,
            notify_off_multiplier: 4,
        };
        assert!(map_pci_transport_regions(regions, [mapping]).is_err());
    }

    #[test]
    fn pci_config_scan_returns_empty_without_capability_list() {
        let mut cfg = MemPciConfig::new();
        assert!(scan_virtio_pci_capabilities(&mut cfg).unwrap().is_empty());
    }

    #[test]
    fn pci_config_scan_extracts_virtio_vendor_capabilities() {
        let mut cfg = MemPciConfig::new();
        cfg.enable_caps(0x40);
        cfg.write8(0x40, 0x05);
        cfg.write8(0x41, 0x50);
        cfg.write_virtio_cap(
            pci::FIRST_CAPABILITY + 0x10,
            0x70,
            pci::COMMON_CFG,
            2,
            0x1000,
            0x100,
            0,
        );
        cfg.write_virtio_cap(0x70, 0x90, pci::NOTIFY_CFG, 2, 0x2000, 0x100, 4);
        cfg.write_virtio_cap(0x90, 0, pci::ISR_CFG, 2, 0x3000, 0x20, 0);

        let caps = scan_virtio_pci_capabilities(&mut cfg).unwrap();
        assert_eq!(caps.len(), 3);
        let regions = resolve_pci_transport_regions(caps).unwrap();
        assert_eq!(regions.common, PciBarRegion::new(2, 0x1000, 0x100).unwrap());
        assert_eq!(regions.notify_addr(1).unwrap(), (2, 0x2004));
        assert_eq!(regions.isr, PciBarRegion::new(2, 0x3000, 0x20).unwrap());
    }

    #[test]
    fn pci_config_scan_rejects_bad_capability_chains() {
        let mut looped = MemPciConfig::new();
        looped.enable_caps(0x40);
        looped.write8(0x40, 0x05);
        looped.write8(0x41, 0x40);
        assert!(scan_virtio_pci_capabilities(&mut looped).is_err());

        let mut short = MemPciConfig::new();
        short.enable_caps(0x40);
        short.write8(0x40, pci::CAP_ID_VENDOR_SPECIFIC);
        short.write8(0x42, 8);
        assert!(scan_virtio_pci_capabilities(&mut short).is_err());

        let mut bad_ptr = MemPciConfig::new();
        bad_ptr.enable_caps(0x20);
        assert!(scan_virtio_pci_capabilities(&mut bad_ptr).is_err());
    }

    #[test]
    fn programmed_dma_maps_allocations_and_exposes_dma_map() {
        let allocations = [
            DmaAllocation::new(0x1000, 0x100, DmaPerms::DEVICE_READ).unwrap(),
            DmaAllocation::new(0x2000, 0x100, DmaPerms::DEVICE_WRITE).unwrap(),
        ];
        let mut iommu = MemIommu::default();
        let programmed = ProgrammedDma::program(&mut iommu, allocations).unwrap();
        assert_eq!(iommu.mapped, allocations);
        assert!(programmed
            .dma_map()
            .allows(0x1010, 0x10, DmaPerms::DEVICE_READ));
        assert!(programmed
            .dma_map()
            .allows(0x2010, 0x10, DmaPerms::DEVICE_WRITE));
        assert_eq!(programmed.allocations(), allocations);

        programmed.unprogram(&mut iommu).unwrap();
        assert_eq!(iommu.unmapped, [allocations[1], allocations[0]]);
    }

    #[test]
    fn programmed_dma_rejects_overlaps_before_iommu_mapping() {
        let allocations = [
            DmaAllocation::new(0x1000, 0x100, DmaPerms::DEVICE_READ).unwrap(),
            DmaAllocation::new(0x1080, 0x100, DmaPerms::DEVICE_WRITE).unwrap(),
        ];
        let mut iommu = MemIommu::default();
        assert!(ProgrammedDma::program(&mut iommu, allocations).is_err());
        assert!(iommu.mapped.is_empty());
    }

    #[test]
    fn programmed_dma_rolls_back_iommu_maps_on_failure() {
        let allocations = [
            DmaAllocation::new(0x1000, 0x100, DmaPerms::DEVICE_READ).unwrap(),
            DmaAllocation::new(0x2000, 0x100, DmaPerms::DEVICE_WRITE).unwrap(),
        ];
        let mut iommu = MemIommu {
            fail_on: Some(0x2000),
            ..MemIommu::default()
        };
        assert!(ProgrammedDma::program(&mut iommu, allocations).is_err());
        assert_eq!(iommu.mapped, [allocations[0]]);
        assert_eq!(iommu.unmapped, [allocations[0]]);
    }

    #[test]
    fn checked_iommu_tracks_mappings_and_rejects_invalid_changes() {
        let mut iommu = CheckedIommu::new(0x1000, 0x1000).unwrap();
        let read = DmaAllocation::new(0x1000, 0x100, DmaPerms::DEVICE_READ).unwrap();
        let write = DmaAllocation::new(0x1200, 0x100, DmaPerms::DEVICE_WRITE).unwrap();
        ProgrammedDma::program(&mut iommu, [read, write]).unwrap();
        assert_eq!(iommu.mappings().collect::<Vec<_>>(), [read, write]);
        assert!(iommu
            .dma_map()
            .unwrap()
            .allows(0x1010, 0x10, DmaPerms::DEVICE_READ));
        assert!(iommu
            .dma_map()
            .unwrap()
            .allows(0x1210, 0x10, DmaPerms::DEVICE_WRITE));

        assert!(iommu
            .map_dma(DmaAllocation::new(0x1080, 0x100, DmaPerms::DEVICE_READ).unwrap())
            .is_err());
        assert!(iommu
            .map_dma(DmaAllocation::new(0x2000, 0x100, DmaPerms::DEVICE_READ).unwrap())
            .is_err());
        assert!(iommu
            .unmap_dma(DmaAllocation::new(0x1200, 0x80, DmaPerms::DEVICE_WRITE).unwrap())
            .is_err());
        iommu.unmap_dma(write).unwrap();
        iommu.unmap_dma(read).unwrap();
        assert!(iommu.mappings().next().is_none());
    }

    #[test]
    fn bump_dma_allocator_aligns_allocations_and_reports_exhaustion() {
        let mut allocator = BumpDmaAllocator::new(0x1003, 0x200).unwrap();
        let first = allocator
            .allocate_dma(0x40, 0x100, DmaPerms::DEVICE_READ)
            .unwrap();
        assert_eq!(
            first,
            DmaAllocation::new(0x1100, 0x40, DmaPerms::DEVICE_READ).unwrap()
        );
        assert!(allocator.remaining() < 0x100);
        assert!(allocator
            .allocate_dma(0x100, 0x100, DmaPerms::DEVICE_WRITE)
            .is_err());
    }

    #[test]
    fn programmed_split_queue_allocates_dma_and_programs_iommu() {
        let mut allocator = BumpDmaAllocator::new(0x4000, 0x4000).unwrap();
        let mut iommu = MemIommu::default();
        let queue = allocate_programmed_split_queue(
            &mut allocator,
            &mut iommu,
            QueueSize::new(8).unwrap(),
            4096,
        )
        .unwrap();
        let allocation = queue.allocation().unwrap();
        assert_eq!(allocation.guest_phys, 0x4000);
        assert_eq!(allocation.perms, DmaPerms::READ_WRITE);
        assert_eq!(iommu.mapped, [allocation]);
        assert!(queue.dma.dma_map().allows(
            queue.layout.descriptor_table,
            16 * 8,
            DmaPerms::DEVICE_READ
        ));
        assert!(queue.dma.dma_map().allows(
            queue.layout.used_ring,
            queue.layout.used_len(queue.queue_size),
            DmaPerms::DEVICE_WRITE
        ));

        queue.unprogram(&mut iommu).unwrap();
        assert_eq!(iommu.unmapped, [allocation]);
    }

    #[test]
    fn feature_negotiation_requires_required_bits_and_accepts_wanted_subset() {
        let offered = Features::VERSION_1.union(Features::RING_EVENT_IDX);
        let negotiated = negotiate_features(
            offered,
            Features::VERSION_1,
            Features::RING_EVENT_IDX.union(Features::RING_INDIRECT_DESC),
        )
        .unwrap();
        assert!(negotiated.contains(Features::VERSION_1));
        assert!(negotiated.contains(Features::RING_EVENT_IDX));
        assert!(!negotiated.contains(Features::RING_INDIRECT_DESC));

        assert!(
            negotiate_features(Features::empty(), Features::VERSION_1, Features::empty()).is_err()
        );
    }

    #[test]
    fn initialize_transport_runs_status_handshake_and_writes_features() {
        let offered = Features::VERSION_1.union(Features::RING_EVENT_IDX);
        let mut t = MemTransport::new(DeviceType::Gpu, offered);
        let init = initialize_transport(
            &mut t,
            DeviceType::Gpu,
            Features::VERSION_1,
            Features::RING_EVENT_IDX,
        )
        .unwrap();
        assert_eq!(init.device_type, DeviceType::Gpu);
        assert!(init.features.contains(Features::VERSION_1));
        assert!(init.features.contains(Features::RING_EVENT_IDX));
        assert_eq!(t.driver_features, init.features);
        assert!(t.read_status() & status::DRIVER_OK != 0);
    }

    #[test]
    fn initialize_transport_rejects_wrong_device_or_feature_failure() {
        let mut wrong = MemTransport::new(DeviceType::Input, Features::VERSION_1);
        assert!(initialize_transport(
            &mut wrong,
            DeviceType::Gpu,
            Features::VERSION_1,
            Features::empty()
        )
        .is_err());

        let mut reject = MemTransport::new(DeviceType::Gpu, Features::VERSION_1);
        reject.reject_features = true;
        assert!(initialize_transport(
            &mut reject,
            DeviceType::Gpu,
            Features::VERSION_1,
            Features::empty()
        )
        .is_err());
        assert!(reject.read_status() & status::FAILED != 0);
    }

    #[test]
    fn mmio_transport_initializes_features_and_status_registers() {
        let regs = MemMmio::new(
            DeviceType::Block,
            Features::VERSION_1.union(Features::RING_EVENT_IDX),
        );
        let mut transport = MmioTransport::new(regs).unwrap();
        let init = initialize_mmio_transport(
            &mut transport,
            DeviceType::Block,
            Features::VERSION_1,
            Features::RING_EVENT_IDX,
        )
        .unwrap();
        let regs = transport.into_inner();
        assert!(init.features.contains(Features::VERSION_1));
        assert!(init.features.contains(Features::RING_EVENT_IDX));
        assert_eq!(regs.driver_features, init.features);
        assert_eq!(
            regs.regs.get(&mmio::STATUS).copied().unwrap() as u8,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK
        );
    }

    #[test]
    fn mmio_transport_rejects_bad_header_and_feature_failure() {
        let mut bad = MemMmio::new(DeviceType::Gpu, Features::VERSION_1);
        bad.regs.insert(mmio::MAGIC_VALUE, 0);
        assert!(MmioTransport::new(bad).is_err());

        let mut regs = MemMmio::new(DeviceType::Gpu, Features::VERSION_1);
        regs.reject_features = true;
        let mut transport = MmioTransport::new(regs).unwrap();
        assert!(initialize_mmio_transport(
            &mut transport,
            DeviceType::Gpu,
            Features::VERSION_1,
            Features::empty()
        )
        .is_err());
        assert!(transport
            .into_inner()
            .regs
            .get(&mmio::STATUS)
            .is_some_and(|s| *s as u8 & status::FAILED != 0));
    }

    #[test]
    fn mmio_transport_configures_split_queue_addresses_and_notify() {
        let regs = MemMmio::new(DeviceType::Gpu, Features::VERSION_1);
        let mut transport = MmioTransport::new(regs).unwrap();
        let layout = split_queue_layout(0x1000, QueueSize::new(4).unwrap(), 4096).unwrap();
        transport
            .configure_split_queue(2, QueueSize::new(4).unwrap(), layout)
            .unwrap();
        transport.notify_queue(2);
        transport.ack_interrupts(3);
        let regs = transport.into_inner().regs;
        assert_eq!(regs.get(&mmio::QUEUE_SEL), Some(&2));
        assert_eq!(regs.get(&mmio::QUEUE_NUM), Some(&4));
        assert_eq!(regs.get(&mmio::QUEUE_DESC_LOW), Some(&0x1000));
        assert_eq!(regs.get(&mmio::QUEUE_DRIVER_LOW), Some(&0x1040));
        assert_eq!(regs.get(&mmio::QUEUE_DEVICE_LOW), Some(&0x2000));
        assert_eq!(regs.get(&mmio::QUEUE_READY), Some(&1));
        assert_eq!(regs.get(&mmio::QUEUE_NOTIFY), Some(&2));
        assert_eq!(regs.get(&mmio::INTERRUPT_ACK), Some(&3));
    }

    #[test]
    fn mmio_transport_decodes_and_acks_interrupt_status() {
        let mut regs = MemMmio::new(DeviceType::Gpu, Features::VERSION_1);
        regs.regs.insert(
            mmio::INTERRUPT_STATUS,
            interrupt::USED_RING | interrupt::CONFIG_CHANGE | 0x80,
        );
        let mut transport = MmioTransport::new(regs).unwrap();
        let status = transport.take_interrupts();
        assert!(status.used_ring());
        assert!(status.config_change());
        assert_eq!(status.unknown_bits(), 0x80);

        let regs = transport.into_inner().regs;
        assert_eq!(
            regs.get(&mmio::INTERRUPT_ACK),
            Some(&(interrupt::USED_RING | interrupt::CONFIG_CHANGE | 0x80))
        );
    }

    #[test]
    fn mmio_transport_does_not_ack_when_no_interrupt_is_pending() {
        let regs = MemMmio::new(DeviceType::Gpu, Features::VERSION_1);
        let mut transport = MmioTransport::new(regs).unwrap();
        let status = transport.take_interrupts();
        assert!(status.none());
        assert!(!status.used_ring());
        assert!(!status.config_change());
        assert_eq!(status.unknown_bits(), 0);
        assert!(!transport
            .into_inner()
            .regs
            .contains_key(&mmio::INTERRUPT_ACK));
    }

    #[test]
    fn virtio_irq_subscription_registers_device_line() {
        assert!(IrqLine::new(0).is_err());
        let mut controller = MemIrqController::default();
        let line = IrqLine::new(32).unwrap();
        let subscription = subscribe_virtio_irq(&mut controller, line, DeviceType::Block).unwrap();
        assert_eq!(
            subscription,
            VirtioIrqSubscription::new(line, DeviceType::Block)
        );
        assert_eq!(controller.subscriptions, [subscription]);

        let mut failing = MemIrqController {
            fail: true,
            ..MemIrqController::default()
        };
        assert!(subscribe_virtio_irq(&mut failing, line, DeviceType::Block).is_err());
        assert!(failing.subscriptions.is_empty());
    }

    #[test]
    fn checked_irq_controller_rejects_duplicate_lines_and_delivers_subscribed_events() {
        let mut controller = CheckedVirtioIrqController::new();
        let line = IrqLine::new(32).unwrap();
        let subscription = subscribe_virtio_irq(&mut controller, line, DeviceType::Block).unwrap();
        assert_eq!(controller.subscription(line), Some(subscription));
        assert_eq!(
            controller.subscriptions().collect::<Vec<_>>(),
            [subscription]
        );
        assert!(subscribe_virtio_irq(&mut controller, line, DeviceType::Gpu).is_err());

        let mut regs = MemMmio::new(DeviceType::Block, Features::VERSION_1);
        regs.regs
            .insert(mmio::INTERRUPT_STATUS, interrupt::USED_RING);
        let mut transport = MmioTransport::new(regs).unwrap();
        let mut sink = MemInterruptSink::default();
        assert!(controller
            .deliver_line(IrqLine::new(33).unwrap(), &mut transport, &mut sink)
            .is_err());
        let event = controller
            .deliver_line(line, &mut transport, &mut sink)
            .unwrap()
            .unwrap();
        assert_eq!(
            event,
            VirtioInterruptEvent {
                subscription,
                status: InterruptStatus::new(interrupt::USED_RING)
            }
        );
        assert_eq!(sink.events, [event]);
    }

    #[test]
    fn virtio_irq_delivery_takes_acknowledges_and_emits_pending_status() {
        let mut regs = MemMmio::new(DeviceType::Block, Features::VERSION_1);
        regs.regs
            .insert(mmio::INTERRUPT_STATUS, interrupt::USED_RING);
        let mut transport = MmioTransport::new(regs).unwrap();
        let subscription = VirtioIrqSubscription::new(IrqLine::new(41).unwrap(), DeviceType::Block);
        let mut sink = MemInterruptSink::default();

        let event =
            deliver_pending_virtio_interrupt(&mut transport, subscription, &mut sink).unwrap();
        assert_eq!(
            event,
            Some(VirtioInterruptEvent {
                subscription,
                status: InterruptStatus::new(interrupt::USED_RING)
            })
        );
        assert_eq!(sink.events, [event.unwrap()]);
        assert_eq!(
            transport.into_inner().regs.get(&mmio::INTERRUPT_ACK),
            Some(&interrupt::USED_RING)
        );
    }

    #[test]
    fn virtio_irq_delivery_ignores_empty_status_without_ack_or_event() {
        let regs = MemMmio::new(DeviceType::Block, Features::VERSION_1);
        let mut transport = MmioTransport::new(regs).unwrap();
        let subscription = VirtioIrqSubscription::new(IrqLine::new(42).unwrap(), DeviceType::Block);
        let mut sink = MemInterruptSink::default();

        assert_eq!(
            deliver_pending_virtio_interrupt(&mut transport, subscription, &mut sink).unwrap(),
            None
        );
        assert!(sink.events.is_empty());
        assert!(!transport
            .into_inner()
            .regs
            .contains_key(&mmio::INTERRUPT_ACK));
    }

    #[test]
    fn mmio_transport_configures_only_dma_mapped_split_queue() {
        let regs = MemMmio::new(DeviceType::Gpu, Features::VERSION_1);
        let mut transport = MmioTransport::new(regs).unwrap();
        let q = QueueSize::new(4).unwrap();
        let layout = split_queue_layout(0x1000, q, 4096).unwrap();
        let dma = DmaMap::new([
            DmaRange::new(0x1000, 0x100, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 0x100, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        transport
            .configure_mapped_split_queue(1, q, layout, &dma)
            .unwrap();

        let regs = transport.into_inner().regs;
        assert_eq!(regs.get(&mmio::QUEUE_SEL), Some(&1));
        assert_eq!(regs.get(&mmio::QUEUE_READY), Some(&1));

        let regs = MemMmio::new(DeviceType::Gpu, Features::VERSION_1);
        let mut transport = MmioTransport::new(regs).unwrap();
        let missing_used =
            DmaMap::new([DmaRange::new(0x1000, 0x100, DmaPerms::DEVICE_READ).unwrap()]).unwrap();
        assert!(transport
            .configure_mapped_split_queue(1, q, layout, &missing_used)
            .is_err());
    }

    #[test]
    fn queue_size_must_be_power_of_two_and_spec_bounded() {
        assert_eq!(QueueSize::new(8).unwrap().get(), 8);
        assert!(QueueSize::new(0).is_err());
        assert!(QueueSize::new(3).is_err());
    }

    #[test]
    fn descriptor_chain_sums_readable_and_writable_segments() {
        let q = QueueSize::new(4).unwrap();
        let table = vec![
            Descriptor::read(0x1000, 16).with_next(1),
            Descriptor::write(0x2000, 4),
            Descriptor::read(0, 1),
            Descriptor::read(0, 1),
        ];
        let chain = validate_descriptor_chain(q, &table, 0).unwrap();
        assert_eq!(chain.descriptors, vec![0, 1]);
        assert_eq!(chain.readable_bytes, 16);
        assert_eq!(chain.writable_bytes, 4);
    }

    #[test]
    fn descriptor_chain_rejects_loops_and_bad_indices() {
        let q = QueueSize::new(2).unwrap();
        let looped = vec![
            Descriptor::read(0x1000, 1).with_next(1),
            Descriptor::read(0x2000, 1).with_next(0),
        ];
        assert!(validate_descriptor_chain(q, &looped, 0).is_err());

        let bad_next = vec![
            Descriptor::read(0x1000, 1).with_next(7),
            Descriptor::read(0x2000, 1),
        ];
        assert!(validate_descriptor_chain(q, &bad_next, 0).is_err());
    }

    #[test]
    fn descriptor_chain_gates_indirect_descriptors_on_negotiated_feature() {
        let q = QueueSize::new(2).unwrap();
        let table = vec![
            Descriptor::read(0x1000, 16).indirect(),
            Descriptor::read(0, 1),
        ];
        assert!(validate_descriptor_chain(q, &table, 0).is_err());

        let chain =
            validate_descriptor_chain_with_features(q, &table, 0, Features::RING_INDIRECT_DESC)
                .unwrap();
        assert_eq!(chain.descriptors, vec![0]);
        assert_eq!(chain.readable_bytes, 16);
    }

    #[test]
    fn dma_map_rejects_overlaps_and_requires_directional_permissions() {
        assert!(DmaRange::new(0x1000, 0, DmaPerms::DEVICE_READ).is_err());
        assert!(DmaRange::new(u64::MAX, 2, DmaPerms::DEVICE_READ).is_err());
        assert!(DmaMap::new([
            DmaRange::new(0x1000, 0x20, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x1010, 0x20, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .is_err());

        let dma = DmaMap::new([
            DmaRange::new(0x1000, 0x40, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 0x40, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        assert!(dma.allows(0x1008, 8, DmaPerms::DEVICE_READ));
        assert!(!dma.allows(0x1008, 8, DmaPerms::DEVICE_WRITE));
        assert!(dma.allows(0x2008, 8, DmaPerms::DEVICE_WRITE));
        assert!(!dma.allows(0x2038, 16, DmaPerms::DEVICE_WRITE));
    }

    #[test]
    fn descriptor_chain_dma_validation_checks_each_segment_direction() {
        let q = QueueSize::new(4).unwrap();
        let table = vec![
            Descriptor::read(0x1000, 16).with_next(1),
            Descriptor::write(0x2000, 4),
            Descriptor::read(0, 1),
            Descriptor::read(0, 1),
        ];
        let dma = DmaMap::new([
            DmaRange::new(0x1000, 0x20, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 0x20, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        let chain =
            validate_descriptor_chain_for_dma(q, &table, 0, Features::empty(), &dma).unwrap();
        assert_eq!(chain.readable_bytes, 16);
        assert_eq!(chain.writable_bytes, 4);

        let wrong =
            DmaMap::new([DmaRange::new(0x1000, 0x2000, DmaPerms::DEVICE_READ).unwrap()]).unwrap();
        assert!(
            validate_descriptor_chain_for_dma(q, &table, 0, Features::empty(), &wrong).is_err()
        );
    }

    #[test]
    fn split_queue_layout_aligns_descriptor_and_used_regions() {
        let layout = split_queue_layout(0x1003, QueueSize::new(8).unwrap(), 4096).unwrap();
        assert_eq!(layout.descriptor_table, 0x1010);
        assert_eq!(layout.available_ring, 0x1090);
        assert_eq!(layout.used_ring, 0x2000);
        assert_eq!(layout.total_len, 0x2046 - 0x1003);
        assert!(split_queue_layout(0, QueueSize::new(8).unwrap(), 3).is_err());
    }

    #[test]
    fn queue_layout_dma_validation_checks_split_queue_regions() {
        let q = QueueSize::new(8).unwrap();
        let layout = split_queue_layout(0x1000, q, 4096).unwrap();
        let dma = DmaMap::new([
            DmaRange::new(0x1000, 0x1000, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 0x1000, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        validate_queue_layout_dma(layout, q, &dma).unwrap();

        let read_only =
            DmaMap::new([DmaRange::new(0x1000, 0x2000, DmaPerms::DEVICE_READ).unwrap()]).unwrap();
        assert!(validate_queue_layout_dma(layout, q, &read_only).is_err());
    }

    #[test]
    fn avail_ring_wraps_slots_and_rejects_invalid_heads() {
        let mut ring = AvailRing::new(QueueSize::new(2).unwrap());
        assert_eq!(ring.push(0).unwrap(), 0);
        assert_eq!(ring.push(1).unwrap(), 1);
        assert_eq!(ring.push(0).unwrap(), 0);
        assert_eq!(ring.idx(), 3);
        assert!(ring.push(2).is_err());
    }

    #[test]
    fn used_ring_wraps_slots_and_rejects_invalid_ids() {
        let mut ring = UsedRing::new(QueueSize::new(2).unwrap());
        assert_eq!(ring.push(0, 16).unwrap(), 0);
        assert_eq!(ring.push(1, 32).unwrap(), 1);
        assert_eq!(ring.push(0, 48).unwrap(), 0);
        assert_eq!(ring.idx(), 3);
        assert_eq!(ring.get(0).unwrap(), UsedElement { id: 0, len: 48 });
        assert_eq!(ring.get(1).unwrap(), UsedElement { id: 1, len: 32 });
        assert!(ring.push(2, 1).is_err());
        assert!(ring.get(2).is_err());
    }

    #[test]
    fn console_plans_validate_dma_direction() {
        let q = QueueSize::new(4).unwrap();
        let rx_dma =
            DmaMap::new([DmaRange::new(0x1000, 16, DmaPerms::DEVICE_WRITE).unwrap()]).unwrap();
        let rx = plan_console_receive(q, 1, 0x1000, 16, &rx_dma).unwrap();
        assert_eq!(rx.kind, ConsoleRequestKind::Receive);
        assert_eq!(rx.descriptors[1], Descriptor::write(0x1000, 16));
        assert_eq!(rx.chain(q, &rx_dma).unwrap().writable_bytes, 16);

        let tx_dma =
            DmaMap::new([DmaRange::new(0x2000, 5, DmaPerms::DEVICE_READ).unwrap()]).unwrap();
        let tx = plan_console_transmit(q, 0, 0x2000, 5, &tx_dma).unwrap();
        assert_eq!(tx.kind, ConsoleRequestKind::Transmit);
        assert_eq!(tx.descriptors[0], Descriptor::read(0x2000, 5));
        assert_eq!(tx.chain(q, &tx_dma).unwrap().readable_bytes, 5);

        assert!(plan_console_receive(q, 0, 0x2000, 5, &tx_dma).is_err());
        assert!(plan_console_transmit(q, 0, 0x1000, 5, &rx_dma).is_err());
        assert!(plan_console_receive(q, 4, 0x1000, 1, &rx_dma).is_err());
        assert!(plan_console_receive(q, 0, 0x1000, 0, &rx_dma).is_err());
    }

    #[test]
    fn console_service_submits_and_completes_used_entry() {
        let q = QueueSize::new(4).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 16, DmaPerms::DEVICE_WRITE).unwrap()]).unwrap();
        let mut service = VirtioConsoleServiceCore::new(q);
        service.submit_receive(1, 0x1000, 16, &dma).unwrap();
        assert_eq!(service.available_idx(), 1);
        assert_eq!(service.pending_len(), 1);
        assert!(service.submit_receive(1, 0x1000, 16, &dma).is_err());

        let mut unknown = UsedRing::new(q);
        unknown.push(2, 4).unwrap();
        assert!(service.complete_next(&unknown).is_err());

        let mut service = VirtioConsoleServiceCore::new(q);
        service.submit_receive(1, 0x1000, 16, &dma).unwrap();
        let mut used = UsedRing::new(q);
        used.push(1, 4).unwrap();
        let completed = service.complete_next(&used).unwrap().unwrap();
        assert_eq!(completed.used, UsedElement { id: 1, len: 4 });
        assert_eq!(completed.request.kind, ConsoleRequestKind::Receive);
        assert_eq!(completed.request.available_slot, 0);
        assert_eq!(service.pending_len(), 0);
        assert_eq!(service.last_used_idx(), 1);
        assert_eq!(service.complete_next(&used).unwrap(), None);
    }

    #[test]
    fn console_provider_materializes_notifies_and_polls_completion() {
        let q = QueueSize::new(4).unwrap();
        let dma = DmaMap::new([DmaRange::new(0x2000, 8, DmaPerms::DEVICE_READ).unwrap()]).unwrap();
        let mut provider = VirtioConsoleProviderCore::new(q, 3);
        let mut backend = MemConsoleBackend::default();
        let plan = provider
            .submit_transmit(&mut backend, 0, 0x2000, 8, &dma)
            .unwrap();
        assert_eq!(backend.written, [plan]);
        assert_eq!(backend.notified, [3]);
        assert_eq!(provider.service().pending_len(), 1);

        assert_eq!(provider.poll_completion(&mut backend).unwrap(), None);
        backend.completions.insert(0, UsedElement { id: 0, len: 8 });
        let completed = provider.poll_completion(&mut backend).unwrap().unwrap();
        assert_eq!(completed.request.kind, ConsoleRequestKind::Transmit);
        assert_eq!(provider.service().pending_len(), 0);
        assert_eq!(provider.service().last_used_idx(), 1);
    }

    #[test]
    fn console_provider_does_not_submit_when_backend_materialization_fails() {
        let q = QueueSize::new(4).unwrap();
        let dma = DmaMap::new([DmaRange::new(0x2000, 8, DmaPerms::DEVICE_READ).unwrap()]).unwrap();
        let mut provider = VirtioConsoleProviderCore::new(q, 3);
        let mut backend = MemConsoleBackend {
            fail_write: true,
            ..MemConsoleBackend::default()
        };
        assert!(provider
            .submit_transmit(&mut backend, 0, 0x2000, 8, &dma)
            .is_err());
        assert!(backend.written.is_empty());
        assert!(backend.notified.is_empty());
        assert_eq!(provider.service().pending_len(), 0);
        assert_eq!(provider.service().available_idx(), 0);
    }

    #[test]
    fn emulated_console_backend_receives_and_transmits_guest_memory() {
        let q = QueueSize::new(4).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 0x1000, DmaPerms::READ_WRITE).unwrap()]).unwrap();
        let memory = VecGuestMemory::new(0x1000, 0x1000).unwrap();
        let mut backend = EmulatedVirtioConsoleBackend::new(memory);
        backend.push_input(b"hello".iter().copied());
        let mut provider = VirtioConsoleProviderCore::new(q, 0);

        provider
            .submit_receive(&mut backend, 0, 0x1100, 16, &dma)
            .unwrap();
        let rx = provider.poll_completion(&mut backend).unwrap().unwrap();
        assert_eq!(rx.used, UsedElement { id: 0, len: 5 });
        assert_eq!(backend.memory().read_exact(0x1100, 5).unwrap(), b"hello");

        backend.memory_mut().write_all(0x1200, b"world").unwrap();
        provider
            .submit_transmit(&mut backend, 1, 0x1200, 5, &dma)
            .unwrap();
        let tx = provider.poll_completion(&mut backend).unwrap().unwrap();
        assert_eq!(tx.used, UsedElement { id: 1, len: 5 });
        assert_eq!(backend.output(), b"world");
    }

    #[test]
    fn block_request_header_encodes_virtio_blk_wire_format() {
        let header = BlockRequestHeader::read(42);
        let bytes = header.encode();
        assert_eq!(&bytes[0..4], &block::T_IN.to_le_bytes());
        assert_eq!(&bytes[4..8], &0u32.to_le_bytes());
        assert_eq!(&bytes[8..16], &42u64.to_le_bytes());

        let header = BlockRequestHeader::write(7);
        let bytes = header.encode();
        assert_eq!(&bytes[0..4], &block::T_OUT.to_le_bytes());
        assert_eq!(&bytes[8..16], &7u64.to_le_bytes());
    }

    #[test]
    fn block_read_plan_builds_dma_checked_descriptor_chain() {
        let q = QueueSize::new(8).unwrap();
        let dma = DmaMap::new([
            DmaRange::new(0x1000, 16, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 512, DmaPerms::DEVICE_WRITE).unwrap(),
            DmaRange::new(0x3000, 1, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        let plan = plan_block_read(q, 2, 0x1000, 0x2000, 512, 0x3000, 5, &dma).unwrap();
        assert_eq!(plan.header, BlockRequestHeader::read(5));
        assert_eq!(plan.head, 2);
        assert_eq!(
            plan.descriptors[2],
            Descriptor::read(0x1000, 16).with_next(3)
        );
        assert_eq!(
            plan.descriptors[3],
            Descriptor::write(0x2000, 512).with_next(4)
        );
        assert_eq!(plan.descriptors[4], Descriptor::write(0x3000, 1));

        let chain = plan.chain(q, &dma).unwrap();
        assert_eq!(chain.descriptors, vec![2, 3, 4]);
        assert_eq!(chain.readable_bytes, 16);
        assert_eq!(chain.writable_bytes, 513);
    }

    #[test]
    fn block_write_plan_requires_device_readable_payload() {
        let q = QueueSize::new(8).unwrap();
        let dma = DmaMap::new([
            DmaRange::new(0x1000, 16, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 512, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x3000, 1, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        let plan = plan_block_write(q, 0, 0x1000, 0x2000, 512, 0x3000, 9, &dma).unwrap();
        assert_eq!(plan.header, BlockRequestHeader::write(9));
        assert_eq!(
            plan.descriptors[0],
            Descriptor::read(0x1000, 16).with_next(1)
        );
        assert_eq!(
            plan.descriptors[1],
            Descriptor::read(0x2000, 512).with_next(2)
        );
        assert_eq!(plan.descriptors[2], Descriptor::write(0x3000, 1));

        let data_not_readable = DmaMap::new([
            DmaRange::new(0x1000, 16, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 512, DmaPerms::DEVICE_WRITE).unwrap(),
            DmaRange::new(0x3000, 1, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        assert!(
            plan_block_write(q, 0, 0x1000, 0x2000, 512, 0x3000, 9, &data_not_readable).is_err()
        );
    }

    #[test]
    fn block_request_plan_rejects_bad_lengths_and_queue_heads() {
        let q = QueueSize::new(4).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 0x3000, DmaPerms::READ_WRITE).unwrap()]).unwrap();
        assert!(plan_block_read(q, 0, 0x1000, 0x2000, 0, 0x3000, 0, &dma).is_err());
        assert!(plan_block_read(q, 0, 0x1000, 0x2000, 513, 0x3000, 0, &dma).is_err());
        assert!(plan_block_read(q, 2, 0x1000, 0x2000, 512, 0x3000, 0, &dma).is_err());
    }

    #[test]
    fn block_service_submits_read_and_completes_used_entry() {
        let q = QueueSize::new(8).unwrap();
        let dma = DmaMap::new([
            DmaRange::new(0x1000, 16, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 512, DmaPerms::DEVICE_WRITE).unwrap(),
            DmaRange::new(0x3000, 1, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        let mut service = VirtioBlkServiceCore::new(q);
        let plan = service
            .submit_read(2, 0x1000, 0x2000, 512, 0x3000, 12, &dma)
            .unwrap();
        assert_eq!(plan.head, 2);
        assert_eq!(service.available_idx(), 1);
        assert_eq!(service.pending_len(), 1);
        assert!(service
            .submit_read(2, 0x1000, 0x2000, 512, 0x3000, 12, &dma)
            .is_err());

        let mut used = UsedRing::new(q);
        used.push(2, 513).unwrap();
        let completed = service.complete_next(&used, block::S_OK).unwrap().unwrap();
        assert_eq!(completed.used, UsedElement { id: 2, len: 513 });
        assert_eq!(
            completed.request,
            SubmittedBlockRequest {
                kind: BlockRequestKind::Read,
                head: 2,
                sector: 12,
                data_len: 512,
                available_slot: 0
            }
        );
        assert_eq!(service.pending_len(), 0);
        assert_eq!(service.last_used_idx(), 1);
        assert_eq!(service.complete_next(&used, block::S_OK).unwrap(), None);
    }

    #[test]
    fn block_service_submits_write_and_rejects_bad_completions() {
        let q = QueueSize::new(8).unwrap();
        let dma = DmaMap::new([
            DmaRange::new(0x1000, 16, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 512, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x3000, 1, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        let mut service = VirtioBlkServiceCore::new(q);
        service
            .submit_write(0, 0x1000, 0x2000, 512, 0x3000, 99, &dma)
            .unwrap();

        let mut unknown = UsedRing::new(q);
        unknown.push(1, 1).unwrap();
        assert!(service.complete_next(&unknown, block::S_OK).is_err());

        let mut service = VirtioBlkServiceCore::new(q);
        service
            .submit_write(0, 0x1000, 0x2000, 512, 0x3000, 99, &dma)
            .unwrap();
        let mut used = UsedRing::new(q);
        used.push(0, 1).unwrap();
        assert!(service.complete_next(&used, block::S_IOERR).is_err());
        assert_eq!(service.pending_len(), 0);
        assert_eq!(service.last_used_idx(), 1);
    }

    #[test]
    fn block_provider_materializes_notifies_and_polls_completion() {
        let q = QueueSize::new(8).unwrap();
        let dma = DmaMap::new([
            DmaRange::new(0x1000, 16, DmaPerms::DEVICE_READ).unwrap(),
            DmaRange::new(0x2000, 512, DmaPerms::DEVICE_WRITE).unwrap(),
            DmaRange::new(0x3000, 1, DmaPerms::DEVICE_WRITE).unwrap(),
        ])
        .unwrap();
        let mut provider = VirtioBlkProviderCore::new(q, 0);
        let mut backend = MemBlkBackend::default();
        let plan = provider
            .submit_read(&mut backend, 2, 0x1000, 0x2000, 512, 0x3000, 3, &dma)
            .unwrap();
        assert_eq!(backend.written, [plan]);
        assert_eq!(backend.notified, [0]);
        assert_eq!(provider.service().pending_len(), 1);

        assert_eq!(provider.poll_completion(&mut backend).unwrap(), None);
        backend
            .completions
            .insert(0, (UsedElement { id: 2, len: 513 }, block::S_OK));
        let completed = provider.poll_completion(&mut backend).unwrap().unwrap();
        assert_eq!(completed.request.kind, BlockRequestKind::Read);
        assert_eq!(completed.request.sector, 3);
        assert_eq!(provider.service().pending_len(), 0);
        assert_eq!(provider.service().last_used_idx(), 1);
    }

    #[test]
    fn block_provider_does_not_submit_when_backend_materialization_fails() {
        let q = QueueSize::new(8).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 0x3000, DmaPerms::READ_WRITE).unwrap()]).unwrap();
        let mut provider = VirtioBlkProviderCore::new(q, 0);
        let mut backend = MemBlkBackend {
            fail_write: true,
            ..MemBlkBackend::default()
        };
        assert!(provider
            .submit_write(&mut backend, 0, 0x1000, 0x2000, 512, 0x3000, 4, &dma)
            .is_err());
        assert!(backend.written.is_empty());
        assert!(backend.notified.is_empty());
        assert_eq!(provider.service().pending_len(), 0);
        assert_eq!(provider.service().available_idx(), 0);
    }

    #[test]
    fn emulated_block_backend_reads_sector_bytes_into_guest_memory() {
        let q = QueueSize::new(8).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 0x4000, DmaPerms::READ_WRITE).unwrap()]).unwrap();
        let memory = VecGuestMemory::new(0x1000, 0x4000).unwrap();
        let mut backend = EmulatedVirtioBlkBackend::new(memory, 4).unwrap();
        for (i, byte) in backend.sectors_mut()[512..1024].iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        let mut provider = VirtioBlkProviderCore::new(q, 0);
        provider
            .submit_read(&mut backend, 0, 0x1000, 0x2000, 512, 0x3000, 1, &dma)
            .unwrap();
        let completed = provider.poll_completion(&mut backend).unwrap().unwrap();

        assert_eq!(completed.used, UsedElement { id: 0, len: 513 });
        assert_eq!(
            backend.memory().read_exact(0x1000, 16).unwrap(),
            BlockRequestHeader::read(1).encode().to_vec()
        );
        assert_eq!(
            backend.memory().read_exact(0x2000, 512).unwrap(),
            backend.sectors()[512..1024].to_vec()
        );
        assert_eq!(
            backend.memory().read_exact(0x3000, 1).unwrap(),
            vec![block::S_OK]
        );
    }

    #[test]
    fn emulated_block_backend_writes_guest_memory_into_sector_bytes() {
        let q = QueueSize::new(8).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 0x4000, DmaPerms::READ_WRITE).unwrap()]).unwrap();
        let mut memory = VecGuestMemory::new(0x1000, 0x4000).unwrap();
        let payload: Vec<u8> = (0..512).map(|i| (255 - (i % 251)) as u8).collect();
        memory.write_all(0x2000, &payload).unwrap();
        let mut backend = EmulatedVirtioBlkBackend::new(memory, 4).unwrap();
        let mut provider = VirtioBlkProviderCore::new(q, 0);
        provider
            .submit_write(&mut backend, 0, 0x1000, 0x2000, 512, 0x3000, 2, &dma)
            .unwrap();
        let completed = provider.poll_completion(&mut backend).unwrap().unwrap();

        assert_eq!(completed.used, UsedElement { id: 0, len: 1 });
        assert_eq!(&backend.sectors()[1024..1536], payload.as_slice());
        assert_eq!(
            backend.memory().read_exact(0x1000, 16).unwrap(),
            BlockRequestHeader::write(2).encode().to_vec()
        );
        assert_eq!(
            backend.memory().read_exact(0x3000, 1).unwrap(),
            vec![block::S_OK]
        );
    }

    #[test]
    fn emulated_block_backend_completes_out_of_range_requests_as_io_errors() {
        let q = QueueSize::new(8).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 0x4000, DmaPerms::READ_WRITE).unwrap()]).unwrap();
        let memory = VecGuestMemory::new(0x1000, 0x4000).unwrap();
        let mut backend = EmulatedVirtioBlkBackend::new(memory, 1).unwrap();
        let mut provider = VirtioBlkProviderCore::new(q, 0);
        provider
            .submit_read(&mut backend, 0, 0x1000, 0x2000, 512, 0x3000, 2, &dma)
            .unwrap();

        assert!(provider.poll_completion(&mut backend).is_err());
        assert_eq!(
            backend.memory().read_exact(0x3000, 1).unwrap(),
            vec![block::S_IOERR]
        );
    }

    #[test]
    fn file_backed_block_backend_reads_file_sector_into_guest_memory() {
        let q = QueueSize::new(8).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 0x4000, DmaPerms::READ_WRITE).unwrap()]).unwrap();
        let mut image = vec![0u8; 2048];
        for (i, byte) in image[512..1024].iter_mut().enumerate() {
            *byte = (i % 193) as u8;
        }
        let (path, file) = temp_backing_file("read", &image);
        let memory = VecGuestMemory::new(0x1000, 0x4000).unwrap();
        let mut backend = FileBackedVirtioBlkBackend::new(memory, file).unwrap();
        let mut provider = VirtioBlkProviderCore::new(q, 0);

        provider
            .submit_read(&mut backend, 0, 0x1000, 0x2000, 512, 0x3000, 1, &dma)
            .unwrap();
        let completed = provider.poll_completion(&mut backend).unwrap().unwrap();

        assert_eq!(completed.used, UsedElement { id: 0, len: 513 });
        assert_eq!(
            backend.memory().read_exact(0x2000, 512).unwrap(),
            image[512..1024].to_vec()
        );
        assert_eq!(
            backend.memory().read_exact(0x3000, 1).unwrap(),
            vec![block::S_OK]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn file_backed_block_backend_writes_guest_memory_into_file_sector() {
        let q = QueueSize::new(8).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 0x4000, DmaPerms::READ_WRITE).unwrap()]).unwrap();
        let (path, file) = temp_backing_file("write", &[0u8; 2048]);
        let mut memory = VecGuestMemory::new(0x1000, 0x4000).unwrap();
        let payload: Vec<u8> = (0..512).map(|i| (i % 227) as u8).collect();
        memory.write_all(0x2000, &payload).unwrap();
        let mut backend = FileBackedVirtioBlkBackend::new(memory, file).unwrap();
        let mut provider = VirtioBlkProviderCore::new(q, 0);

        provider
            .submit_write(&mut backend, 0, 0x1000, 0x2000, 512, 0x3000, 2, &dma)
            .unwrap();
        let completed = provider.poll_completion(&mut backend).unwrap().unwrap();
        assert_eq!(completed.used, UsedElement { id: 0, len: 1 });
        assert_eq!(
            backend.memory().read_exact(0x3000, 1).unwrap(),
            vec![block::S_OK]
        );
        drop(backend);

        let image = std::fs::read(&path).unwrap();
        assert_eq!(&image[1024..1536], payload.as_slice());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn file_backed_block_backend_rejects_bad_size_and_reports_bounds_errors() {
        let (bad_path, bad_file) = temp_backing_file("bad-size", &[0u8; 513]);
        assert!(FileBackedVirtioBlkBackend::new(
            VecGuestMemory::new(0x1000, 0x4000).unwrap(),
            bad_file,
        )
        .is_err());
        let _ = std::fs::remove_file(bad_path);

        let q = QueueSize::new(8).unwrap();
        let dma =
            DmaMap::new([DmaRange::new(0x1000, 0x4000, DmaPerms::READ_WRITE).unwrap()]).unwrap();
        let (path, file) = temp_backing_file("bounds", &[0u8; 512]);
        let memory = VecGuestMemory::new(0x1000, 0x4000).unwrap();
        let mut backend = FileBackedVirtioBlkBackend::new(memory, file).unwrap();
        let mut provider = VirtioBlkProviderCore::new(q, 0);
        provider
            .submit_read(&mut backend, 0, 0x1000, 0x2000, 512, 0x3000, 1, &dma)
            .unwrap();
        assert!(provider.poll_completion(&mut backend).is_err());
        assert_eq!(
            backend.memory().read_exact(0x3000, 1).unwrap(),
            vec![block::S_IOERR]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn block_status_decodes_device_completion() {
        assert!(decode_block_status(block::S_OK).is_ok());
        assert!(decode_block_status(block::S_IOERR).is_err());
        assert!(decode_block_status(block::S_UNSUPP).is_err());
        assert!(decode_block_status(99).is_err());
    }
}
