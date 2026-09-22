// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! In-process IP packet bridge for AntiNet: Go gVisor ↔ rust engine without
//! localhost UDP. Uplink is a lock-free queue drained by the dispatcher; downlink
//! is an optional C callback into the helper.

use crate::packet::{PacketBuf, PacketPool};
use arc_swap::ArcSwapOption;
use crossbeam_queue::ArrayQueue;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicPtr, Ordering},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub const UPLINK_CAPACITY: usize = 1024;

pub type PacketOutCb = extern "C" fn(*const u8, i32);

static PACKET_OUT: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static BRIDGE_READY: AtomicBool = AtomicBool::new(false);

fn uplink_slot() -> &'static ArcSwapOption<UplinkBridge> {
    static UPLINK: OnceLock<ArcSwapOption<UplinkBridge>> = OnceLock::new();
    UPLINK.get_or_init(ArcSwapOption::empty)
}

pub struct UplinkBridge {
    pub pool: Arc<PacketPool>,
    pub queue: ArrayQueue<PacketBuf>,
    pub notify: Arc<Notify>,
    pub cancel: CancellationToken,
}

pub fn set_packet_out(cb: Option<PacketOutCb>) {
    let ptr = cb.map(|f| f as *mut ()).unwrap_or(std::ptr::null_mut());
    PACKET_OUT.store(ptr, Ordering::Release);
}

pub fn packet_out() -> Option<PacketOutCb> {
    let ptr = PACKET_OUT.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut (), PacketOutCb>(ptr) })
    }
}

pub fn bridge_ready() -> bool {
    BRIDGE_READY.load(Ordering::Acquire)
}

pub fn clear_bridge() {
    BRIDGE_READY.store(false, Ordering::Release);
    uplink_slot().store(None);
}

pub fn install_uplink(bridge: Arc<UplinkBridge>) {
    uplink_slot().store(Some(bridge));
    BRIDGE_READY.store(true, Ordering::Release);
}

/// Copy `data` into a pool buffer and enqueue for the bridge reader.
/// Returns 0 on success, -1 if bridge is down, -2 if queue is full / pool exhausted.
pub fn inject_packet(data: &[u8]) -> i32 {
    if data.is_empty() || data.len() > crate::packet::PACKET_CAPACITY - crate::packet::PACKET_HEADROOM
    {
        return -3;
    }
    let Some(bridge) = uplink_slot().load_full() else {
        return -1;
    };
    if bridge.cancel.is_cancelled() {
        return -1;
    }
    // Idle scale-down exit trigger; a single atomic load unless we are actually idle.
    crate::idle::note_uplink(data);
    let Some(mut packet) = bridge.pool.try_acquire() else {
        return -2;
    };
    let area = packet.read_area();
    if data.len() > area.len() {
        return -3;
    }
    area[..data.len()].copy_from_slice(data);
    if packet.set_read_len(data.len()).is_err() {
        return -3;
    }
    if bridge.queue.push(packet).is_err() {
        return -2;
    }
    // Wake the reader only on empty → nonempty; it drains the whole queue per wake.
    if bridge.queue.len() == 1 {
        bridge.notify.notify_one();
    }
    0
}

pub fn deliver_downlink(packet: &[u8]) {
    if let Some(cb) = packet_out() {
        if !packet.is_empty() {
            cb(packet.as_ptr(), packet.len() as i32);
        }
    }
}
