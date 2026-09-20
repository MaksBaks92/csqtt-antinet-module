// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! In-process IP packet bridge for AntiNet: Go gVisor ↔ rust engine without
//! localhost UDP. Uplink is a lock-free queue drained by the dispatcher; downlink
//! is an optional C callback into the helper.

use crate::packet::{PacketBuf, PacketPool};
use crossbeam_queue::ArrayQueue;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicPtr, Ordering},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const UPLINK_CAPACITY: usize = 1024;

pub type PacketOutCb = extern "C" fn(*const u8, i32);

static PACKET_OUT: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static BRIDGE_READY: AtomicBool = AtomicBool::new(false);
static UPLINK: Mutex<Option<Arc<UplinkBridge>>> = Mutex::new(None);

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
    if let Ok(mut slot) = UPLINK.lock() {
        *slot = None;
    }
}

pub fn install_uplink(bridge: Arc<UplinkBridge>) {
    if let Ok(mut slot) = UPLINK.lock() {
        *slot = Some(bridge);
    }
    BRIDGE_READY.store(true, Ordering::Release);
}

/// Copy `data` into a pool buffer and enqueue for the bridge reader.
/// Returns 0 on success, -1 if bridge is down, -2 if queue is full / pool exhausted.
pub fn inject_packet(data: &[u8]) -> i32 {
    if data.is_empty() || data.len() > crate::packet::PACKET_CAPACITY - crate::packet::PACKET_HEADROOM
    {
        return -3;
    }
    let bridge = match UPLINK.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => None,
    };
    let Some(bridge) = bridge else {
        return -1;
    };
    if bridge.cancel.is_cancelled() {
        return -1;
    }
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
    bridge.notify.notify_one();
    0
}

pub fn deliver_downlink(packet: &[u8]) {
    if let Some(cb) = packet_out() {
        if !packet.is_empty() {
            cb(packet.as_ptr(), packet.len() as i32);
        }
    }
}
