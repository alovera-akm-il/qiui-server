//! Keyholder-controlled countdown. All times are absolute UTC milliseconds
//! passed in by the caller, so the logic stays deterministic and testable.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    Idle,
    Running { ends_at_ms: i64 },
    Paused { remaining_ms: i64 },
    /// The countdown finished. Requests reopen; nothing unlocks by itself.
    Ended,
}

impl Timer {
    /// A running timer whose end has passed becomes `Ended`. Returns the end time if it did.
    pub fn settle(&mut self, now_ms: i64) -> Option<i64> {
        match *self {
            Timer::Running { ends_at_ms } if ends_at_ms <= now_ms => {
                *self = Timer::Ended;
                Some(ends_at_ms)
            }
            _ => None,
        }
    }

    /// True while the wearer must not be able to request or be granted an unlock.
    pub fn blocks_unlock(&self, now_ms: i64) -> bool {
        match *self {
            Timer::Running { ends_at_ms } => ends_at_ms > now_ms,
            Timer::Paused { .. } => true,
            Timer::Idle | Timer::Ended => false,
        }
    }

    pub fn remaining_ms(&self, now_ms: i64) -> Option<i64> {
        match *self {
            Timer::Running { ends_at_ms } => Some((ends_at_ms - now_ms).max(0)),
            Timer::Paused { remaining_ms } => Some(remaining_ms),
            Timer::Ended => Some(0),
            Timer::Idle => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Timer::Idle => "idle",
            Timer::Running { .. } => "running",
            Timer::Paused { .. } => "paused",
            Timer::Ended => "ended",
        }
    }

    /// (kind, milliseconds) pair for storage.
    pub fn to_parts(&self) -> (&'static str, Option<i64>) {
        match *self {
            Timer::Running { ends_at_ms } => (self.kind(), Some(ends_at_ms)),
            Timer::Paused { remaining_ms } => (self.kind(), Some(remaining_ms)),
            _ => (self.kind(), None),
        }
    }

    pub fn from_parts(kind: &str, ms: Option<i64>) -> Option<Timer> {
        Some(match (kind, ms) {
            ("idle", _) => Timer::Idle,
            ("ended", _) => Timer::Ended,
            ("running", Some(ends_at_ms)) => Timer::Running { ends_at_ms },
            ("paused", Some(remaining_ms)) => Timer::Paused { remaining_ms },
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_settles_to_ended_once() {
        let mut t = Timer::Running { ends_at_ms: 1_000 };
        assert!(t.blocks_unlock(999));
        assert_eq!(t.settle(999), None);
        assert_eq!(t.settle(1_000), Some(1_000));
        assert_eq!(t, Timer::Ended);
        assert!(!t.blocks_unlock(1_000));
        assert_eq!(t.settle(2_000), None);
    }

    #[test]
    fn paused_blocks_and_keeps_remaining() {
        let t = Timer::Paused { remaining_ms: 5_000 };
        assert!(t.blocks_unlock(0));
        assert_eq!(t.remaining_ms(1_000_000), Some(5_000));
    }

    #[test]
    fn storage_round_trip() {
        for t in [Timer::Idle, Timer::Ended, Timer::Running { ends_at_ms: 7 }, Timer::Paused { remaining_ms: 9 }] {
            let (k, ms) = t.to_parts();
            assert_eq!(Timer::from_parts(k, ms), Some(t));
        }
        assert_eq!(Timer::from_parts("running", None), None);
    }
}
