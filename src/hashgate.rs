//! Limits how many password checks run at once.
//!
//! A check is deliberately slow and memory-hungry, and with no lockout it is the only brake on guessing.
//! Run freely, a flood of guesses would eat all the memory and CPU, and (if done while holding the
//! database lock) freeze every other request. So at most a couple run at a time, a bounded queue
//! waits behind them, and anything beyond that is turned away with "busy". Nobody is ever locked out:
//! the next attempt simply goes through the same queue.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Semaphore;

/// Password checks allowed to run at the same time.
pub const MAX_CONCURRENT: usize = 2;
/// How many more may wait their turn before new ones are refused.
pub const MAX_WAITING: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub struct Busy;

pub struct HashGate {
    permits: Semaphore,
    waiting: AtomicUsize,
    max_waiting: usize,
}

impl Default for HashGate {
    fn default() -> Self {
        Self::new(MAX_CONCURRENT, MAX_WAITING)
    }
}

impl HashGate {
    pub fn new(concurrent: usize, max_waiting: usize) -> Self {
        Self { permits: Semaphore::new(concurrent), waiting: AtomicUsize::new(0), max_waiting }
    }

    /// Run slow, blocking work once a slot is free. `Err(Busy)` if too many are already waiting.
    pub async fn run<T, F>(&self, work: F) -> Result<T, Busy>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        // A free slot means no waiting at all. Only a request that has to queue counts toward the cap.
        let permit = match self.permits.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                if self.waiting.fetch_add(1, Ordering::SeqCst) >= self.max_waiting {
                    self.waiting.fetch_sub(1, Ordering::SeqCst);
                    return Err(Busy);
                }
                let permit = self.permits.acquire().await;
                self.waiting.fetch_sub(1, Ordering::SeqCst);
                permit.map_err(|_| Busy)?
            }
        };
        let out = tokio::task::spawn_blocking(work).await.map_err(|_| Busy);
        drop(permit);
        out
    }
}

/// Attempts the gate turned away, counted per route in memory. A rejection has to stay cheap, or a flood
/// could amplify itself, so nothing is written per attempt: the first after a quiet spell is written at once
/// (by the caller), and the rest are folded into the database every few seconds.
#[derive(Default)]
pub struct TurnedAway {
    counts: std::sync::Mutex<std::collections::HashMap<&'static str, u64>>,
}

impl TurnedAway {
    /// Count one for this route. True if it is the first since the last flush.
    pub fn note(&self, route: &'static str) -> bool {
        let mut m = self.counts.lock().expect("turned-away lock");
        let n = m.entry(route).or_insert(0);
        *n += 1;
        *n == 1
    }

    /// The counts beyond each route's first (which was written when it happened), without resetting them.
    pub fn peek_extra(&self) -> Vec<(&'static str, u64)> {
        self.counts.lock().expect("turned-away lock").iter().filter(|(_, n)| **n > 1).map(|(r, n)| (*r, *n - 1)).collect()
    }

    /// Take the counts beyond each route's first and start over, so the next rejection is a first again.
    pub fn take_extra(&self) -> Vec<(&'static str, u64)> {
        let mut m = self.counts.lock().expect("turned-away lock");
        let out = m.iter().filter(|(_, n)| **n > 1).map(|(r, n)| (*r, *n - 1)).collect();
        m.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn never_more_than_the_limit_run_at_once() {
        let gate = Arc::new(HashGate::new(2, 100));
        let (running, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let (gate, running, peak) = (gate.clone(), running.clone(), peak.clone());
                tokio::spawn(async move {
                    gate.run(move || {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(30));
                        running.fetch_sub(1, Ordering::SeqCst);
                    })
                    .await
                })
            })
            .collect();
        for t in tasks {
            assert!(t.await.unwrap().is_ok(), "waiting is not refusing");
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn turned_away_attempts_are_counted_per_route_and_the_first_is_flagged() {
        let t = TurnedAway::default();
        assert!(t.note("login_busy"), "the first after a quiet spell is flagged, to be written at once");
        assert!(!t.note("login_busy"));
        assert!(!t.note("login_busy"));
        assert!(t.note("password_change_busy"), "another route has its own first");
        assert_eq!(t.peek_extra(), vec![("login_busy", 2)], "the counts beyond each first, visible without resetting");
        assert_eq!(t.take_extra(), vec![("login_busy", 2)]);
        assert!(t.take_extra().is_empty(), "each count is taken once");
        assert!(t.note("login_busy"), "and the next rejection is a first again");
    }

    #[tokio::test]
    async fn with_no_queue_allowed_a_free_slot_still_works() {
        let gate = HashGate::new(1, 0);
        assert_eq!(gate.run(|| 1).await, Ok(1));
        assert_eq!(gate.run(|| 2).await, Ok(2));
    }

    #[tokio::test]
    async fn once_the_queue_is_full_new_work_is_turned_away_and_the_gate_recovers() {
        let gate = Arc::new(HashGate::new(1, 1));
        let slow = |gate: Arc<HashGate>| tokio::spawn(async move { gate.run(|| std::thread::sleep(Duration::from_millis(200))).await });
        let running = slow(gate.clone());
        tokio::time::sleep(Duration::from_millis(40)).await;
        let waiting = slow(gate.clone());
        tokio::time::sleep(Duration::from_millis(40)).await;

        // One is running and one is waiting: a third is refused at once, not queued.
        assert_eq!(gate.run(|| ()).await, Err(Busy));
        assert!(running.await.unwrap().is_ok());
        assert!(waiting.await.unwrap().is_ok());

        // Nothing was locked out: as soon as there is room, work goes through again.
        assert_eq!(gate.run(|| 7).await, Ok(7));
    }
}
