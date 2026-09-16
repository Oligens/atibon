use super::egress_governed::ApprovedRelay;

const DEFAULT_INTERVAL_MS: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledRelay<'a> {
    pub relay: &'a ApprovedRelay,
    pub slot: u64,
}

/// Deterministic scheduler for rotating through approved relays.
///
/// This scheduler never creates or fabricates network identities. It only
/// selects from the caller-provided approved relay set.
pub struct PiHopSchedule<'a> {
    relays: &'a [ApprovedRelay],
    epoch: u64,
    interval_ms: u64,
}

impl<'a> PiHopSchedule<'a> {
    /// Creates a scheduler using the fixed default interval.
    pub const fn new(relays: &'a [ApprovedRelay], epoch: u64) -> Self {
        Self {
            relays,
            epoch,
            interval_ms: DEFAULT_INTERVAL_MS,
        }
    }

    /// Creates a scheduler with an explicit interval. Zero is rejected by
    /// `is_valid`; callers should prefer `new` for the fixed 100 ms schedule.
    pub const fn with_interval(relays: &'a [ApprovedRelay], epoch: u64, interval_ms: u64) -> Self {
        Self {
            relays,
            epoch,
            interval_ms,
        }
    }

    /// Returns the discrete scheduler slot for a monotonic millisecond value.
    /// Returns `None` for an invalid zero interval instead of panicking.
    #[inline]
    pub const fn slot(&self, now_ms: u64) -> Option<u64> {
        now_ms.checked_div(self.interval_ms)
    }

    /// Returns the relay selected for the current slot without allocating.
    #[inline]
    pub fn relay_for(&self, now_ms: u64) -> Option<&'a ApprovedRelay> {
        let slot = self.slot(now_ms)?;
        self.relay_for_slot(slot)
    }

    /// Returns the current relay together with its exact slot provenance.
    #[inline]
    pub fn scheduled_relay_for(&self, now_ms: u64) -> Option<ScheduledRelay<'a>> {
        let slot = self.slot(now_ms)?;
        self.relay_for_slot(slot).map(|relay| ScheduledRelay { relay, slot })
    }

    /// Returns the relay selected for an explicit scheduler slot.
    #[inline]
    pub fn relay_for_slot(&self, slot: u64) -> Option<&'a ApprovedRelay> {
        if !self.is_valid() {
            return None;
        }
        let index = ((slot % self.relays.len() as u64) + self.epoch) % self.relays.len() as u64;
        self.relays.get(index as usize)
    }

    /// Validates that the schedule can safely select an approved relay.
    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.interval_ms != 0 && !self.relays.is_empty()
    }
}
