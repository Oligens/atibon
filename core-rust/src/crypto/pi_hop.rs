//! Deterministic relay hopping scheduler for the ATIBON egress plane.
//!
//! This module is a Moving Target Defense (MTD) scheduler, not a cryptographic
//! primitive. The decimal digits of π are public and therefore must never be
//! treated as secret entropy. A production deployment can layer a secret-derived
//! epoch/indexing value above this scheduler if unpredictability is required.
//!
//! Safety boundary: the scheduler can only select from the caller-provided
//! approved relay allowlist. It never creates arbitrary endpoints or performs
//! NAT/source-address rewriting.

/// Default hopping interval: 100 ms.
pub const DEFAULT_INTERVAL_MS: u64 = 100;
/// Jitter tolerance in scheduler slots: previous/current/next.
pub const JITTER_SLOTS: u64 = 1;

// Public, deterministic π digits. The decimal point is intentionally omitted.
// Keeping the table static avoids heap allocation in the critical selection path.
const PI_DIGITS: &[u8] = b"1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovedRelay {
    pub id: &'static str,
    pub endpoint: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct PiHopSchedule<'a> {
    relays: &'a [ApprovedRelay],
    epoch: u64,
    interval_ms: u64,
}

impl<'a> PiHopSchedule<'a> {
    /// Creates a scheduler over an existing approved relay allowlist.
    ///
    /// `epoch` is a logical schedule epoch. It does not provide secrecy by
    /// itself; it simply changes the deterministic starting position.
    pub const fn new(relays: &'a [ApprovedRelay], epoch: u64) -> Self {
        Self {
            relays,
            epoch,
            interval_ms: DEFAULT_INTERVAL_MS,
        }
    }

    /// Creates a scheduler with an explicit positive interval.
    pub const fn with_interval(relays: &'a [ApprovedRelay], epoch: u64, interval_ms: u64) -> Self {
        Self {
            relays,
            epoch,
            interval_ms,
        }
    }

    /// Returns the discrete scheduler slot for a monotonic millisecond value.
    #[inline]
    pub const fn slot(&self, now_ms: u64) -> u64 {
        now_ms / self.interval_ms
    }

    /// Returns the relay selected for the current slot without allocating.
    #[inline]
    pub fn relay_for(&self, now_ms: u64) -> Option<&'a ApprovedRelay> {
        if self.relays.is_empty() || self.interval_ms == 0 {
            return None;
        }
        let slot = self.slot(now_ms);
        self.relay_for_slot(slot)
    }

    /// Returns the relay selected by a specific deterministic slot.
    #[inline]
    pub fn relay_for_slot(&self, slot: u64) -> Option<&'a ApprovedRelay> {
        if self.relays.is_empty() || self.interval_ms == 0 {
            return None;
        }
        let index = self.relay_index(slot);
        self.relays.get(index)
    }

    /// Returns the deterministic relay index for a slot.
    #[inline]
    pub fn relay_index(&self, slot: u64) -> usize {
        // The epoch is mixed by wrapping addition. π supplies only a public,
        // deterministic schedule value; it is not cryptographic randomness.
        let mixed_slot = slot.wrapping_add(self.epoch);
        let entropy = PI_DIGITS[(mixed_slot as usize) % PI_DIGITS.len()] - b'0';
        (entropy as usize) % self.relays.len()
    }

    /// Accepts only the relay for k-1, k, or k+1 around the current slot.
    ///
    /// This tolerance is intentionally bounded: it prevents an old relay from
    /// remaining valid indefinitely while accommodating normal ±100 ms jitter.
    #[inline]
    pub fn accepts(&self, now_ms: u64, presented_relay: &ApprovedRelay) -> bool {
        if self.relays.is_empty() || self.interval_ms == 0 {
            return false;
        }
        let current = self.slot(now_ms);
        let previous = current.saturating_sub(JITTER_SLOTS);
        let next = current.saturating_add(JITTER_SLOTS);
        self.matches_slot(previous, presented_relay)
            || self.matches_slot(current, presented_relay)
            || self.matches_slot(next, presented_relay)
    }

    #[inline]
    fn matches_slot(&self, slot: u64, presented: &ApprovedRelay) -> bool {
        match self.relay_for_slot(slot) {
            Some(expected) => expected == presented,
            None => false,
        }
    }

    /// Exposes the configured logical epoch without allocation.
    #[inline]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Exposes the configured interval without allocation.
    #[inline]
    pub const fn interval_ms(&self) -> u64 {
        self.interval_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAYS: [ApprovedRelay; 4] = [
        ApprovedRelay { id: "relay-a", endpoint: "relay-a.internal" },
        ApprovedRelay { id: "relay-b", endpoint: "relay-b.internal" },
        ApprovedRelay { id: "relay-c", endpoint: "relay-c.internal" },
        ApprovedRelay { id: "relay-d", endpoint: "relay-d.internal" },
    ];

    #[test]
    fn rotates_on_100ms_slots() {
        let schedule = PiHopSchedule::new(&RELAYS, 0);
        assert_eq!(schedule.slot(0), 0);
        assert_eq!(schedule.slot(99), 0);
        assert_eq!(schedule.slot(100), 1);
        assert_eq!(schedule.slot(199), 1);
        assert_eq!(schedule.slot(200), 2);

        assert_eq!(schedule.relay_for(0), schedule.relay_for_slot(0));
        assert_eq!(schedule.relay_for(100), schedule.relay_for_slot(1));
        assert_ne!(schedule.relay_index(0), schedule.relay_index(1));
    }

    #[test]
    fn accepts_previous_current_and_next_slot() {
        let schedule = PiHopSchedule::new(&RELAYS, 0);
        let previous = *schedule.relay_for_slot(9).unwrap();
        let current = *schedule.relay_for_slot(10).unwrap();
        let next = *schedule.relay_for_slot(11).unwrap();

        assert!(schedule.accepts(1_000, &previous));
        assert!(schedule.accepts(1_000, &current));
        assert!(schedule.accepts(1_000, &next));

        let far = *schedule.relay_for_slot(12).unwrap();
        assert!(!schedule.accepts(1_000, &far));
    }

    #[test]
    fn jitter_boundary_is_exactly_one_slot() {
        let schedule = PiHopSchedule::new(&RELAYS, 0);
        let previous = *schedule.relay_for(899).unwrap();
        let current = *schedule.relay_for(900).unwrap();
        let next = *schedule.relay_for(1_000).unwrap();

        assert!(schedule.accepts(900, &previous));
        assert!(schedule.accepts(900, &current));
        assert!(schedule.accepts(900, &next));

        let two_slots_back = *schedule.relay_for(700).unwrap();
        let two_slots_forward = *schedule.relay_for(1_100).unwrap();
        assert!(!schedule.accepts(900, &two_slots_back));
        assert!(!schedule.accepts(900, &two_slots_forward));
    }

    #[test]
    fn empty_relays_fail_closed() {
        let empty: [ApprovedRelay; 0] = [];
        let schedule = PiHopSchedule::new(&empty, 0);
        assert!(schedule.relay_for(0).is_none());
        assert!(!schedule.accepts(0, &RELAYS[0]));
    }

    #[test]
    fn critical_path_returns_borrowed_relay_without_owned_result() {
        let schedule = PiHopSchedule::new(&RELAYS, 42);
        let relay = schedule.relay_for(12_345).unwrap();
        assert!(RELAYS.iter().any(|candidate| core::ptr::eq(candidate, relay)));
        assert_eq!(schedule.interval_ms(), 100);
    }

    #[test]
    fn epoch_changes_deterministic_schedule() {
        let a = PiHopSchedule::new(&RELAYS, 0);
        let b = PiHopSchedule::new(&RELAYS, 1);
        assert_ne!(a.relay_index(0), b.relay_index(0));
    }
}
