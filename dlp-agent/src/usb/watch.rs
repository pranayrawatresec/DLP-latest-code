//! Device arrival/removal detection by **polling** (spec §3.2).
//!
//! Every poll interval the monitor snapshots the current removable-volume set
//! and diffs it against the previous snapshot to emit `Arrived` / `Removed`
//! events. Polling is chosen deliberately: it needs no message loop (a message
//! loop would hang `cargo test`) and the diff is a pure function that a unit
//! test drives with two successive volume sets.
//!
//! A `WM_DEVICECHANGE` message-only window is an OPTIONAL low-latency
//! enhancement (spec §3.2) and is intentionally NOT implemented here so no
//! message loop can ever reach a test path.

use super::device::DeviceIdentity;

/// A change in the removable-volume set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeEvent {
    /// A removable device appeared (full identity resolved).
    Arrived(DeviceIdentity),
    /// A removable device went away (identified by drive letter).
    Removed(String),
}

/// Pure diff of two volume snapshots, keyed by drive letter. Devices present in
/// `curr` but not `prev` are `Arrived`; those in `prev` but not `curr` are
/// `Removed`. A device whose identity *changed* at the same drive letter (a
/// different stick swapped into the same slot between polls) is reported as a
/// `Removed` followed by an `Arrived`.
pub fn diff_volumes(prev: &[DeviceIdentity], curr: &[DeviceIdentity]) -> Vec<VolumeEvent> {
    let mut events = Vec::new();

    // Removed or replaced: in prev, and either gone or changed identity in curr.
    for p in prev {
        match curr.iter().find(|c| c.drive_letter == p.drive_letter) {
            None => events.push(VolumeEvent::Removed(p.drive_letter.clone())),
            Some(c) if *c != *p => events.push(VolumeEvent::Removed(p.drive_letter.clone())),
            Some(_) => {}
        }
    }
    // Arrived or replaced: in curr, and either new or changed identity vs prev.
    for c in curr {
        match prev.iter().find(|p| p.drive_letter == c.drive_letter) {
            None => events.push(VolumeEvent::Arrived(c.clone())),
            Some(p) if *p != *c => events.push(VolumeEvent::Arrived(c.clone())),
            Some(_) => {}
        }
    }
    events
}

/// Stateful polling watcher: holds the last snapshot and turns each new one
/// into events. `run_monitor` feeds it real snapshots; tests feed it synthetic
/// ones. No Windows calls live here — snapshots come from `device.rs`.
#[derive(Default)]
pub struct VolumeWatcher {
    last: Vec<DeviceIdentity>,
}

impl VolumeWatcher {
    pub fn new() -> Self {
        VolumeWatcher { last: Vec::new() }
    }

    /// Feed the current snapshot; get the events since the previous one.
    pub fn poll(&mut self, current: Vec<DeviceIdentity>) -> Vec<VolumeEvent> {
        let events = diff_volumes(&self.last, &current);
        self.last = current;
        events
    }

    /// Drive letters currently mounted (for shutting down auditors on stop).
    pub fn current_letters(&self) -> Vec<String> {
        self.last.iter().map(|d| d.drive_letter.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(letter: &str, serial: &str) -> DeviceIdentity {
        DeviceIdentity {
            drive_letter: letter.into(),
            vendor_id: "V".into(),
            product_id: "P".into(),
            serial: serial.into(),
            product_name: "V P".into(),
            bus_type: "usb".into(),
            removable: true,
        }
    }

    #[test]
    fn arrival_is_detected() {
        let events = diff_volumes(&[], &[dev("E:", "s1")]);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], VolumeEvent::Arrived(d) if d.drive_letter == "E:"));
    }

    #[test]
    fn removal_is_detected() {
        let events = diff_volumes(&[dev("E:", "s1")], &[]);
        assert_eq!(events, vec![VolumeEvent::Removed("E:".into())]);
    }

    #[test]
    fn steady_state_emits_nothing() {
        let prev = vec![dev("E:", "s1"), dev("F:", "s2")];
        let curr = vec![dev("E:", "s1"), dev("F:", "s2")];
        assert!(diff_volumes(&prev, &curr).is_empty());
    }

    #[test]
    fn swap_same_slot_emits_removed_then_arrived() {
        let prev = vec![dev("E:", "old")];
        let curr = vec![dev("E:", "new")];
        let events = diff_volumes(&prev, &curr);
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], VolumeEvent::Removed(ref l) if l == "E:"));
        assert!(matches!(&events[1], VolumeEvent::Arrived(d) if d.serial == "new"));
    }

    #[test]
    fn watcher_tracks_state_across_polls() {
        let mut w = VolumeWatcher::new();
        assert_eq!(w.poll(vec![dev("E:", "s1")]).len(), 1); // arrival
        assert!(w.poll(vec![dev("E:", "s1")]).is_empty()); // steady
        assert_eq!(w.poll(vec![]), vec![VolumeEvent::Removed("E:".into())]); // removal
        assert!(w.current_letters().is_empty());
    }

    #[test]
    fn multiple_simultaneous_changes() {
        let prev = vec![dev("E:", "s1"), dev("F:", "s2")];
        let curr = vec![dev("F:", "s2"), dev("G:", "s3")];
        let events = diff_volumes(&prev, &curr);
        // E: removed, G: arrived; F: unchanged.
        assert!(events.contains(&VolumeEvent::Removed("E:".into())));
        assert!(events.iter().any(|e| matches!(e, VolumeEvent::Arrived(d) if d.drive_letter == "G:")));
        assert_eq!(events.len(), 2);
    }
}
