//! Lock state machine. Every rule about who may do what lives here, so the
//! HTTP API, the CLI and the BLE layer cannot disagree about it.
//!
//! Callers `tick(now)` first (the store does), then call one action. Actions
//! validate before mutating, so a rejected action leaves the machine untouched.
//! Unlock/lock are split into `check_*` (may this happen?) and `record_*`
//! (it physically happened), because the BLE step sits in between.

use serde_json::{Value, json};
use thiserror::Error;

use crate::timer::Timer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Locked,
    Requested,
    Approved,
    Unlocked,
}

impl LockState {
    pub fn as_str(&self) -> &'static str {
        match self {
            LockState::Locked => "locked",
            LockState::Requested => "requested",
            LockState::Approved => "approved",
            LockState::Unlocked => "unlocked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "locked" => LockState::Locked,
            "requested" => LockState::Requested,
            "approved" => LockState::Approved,
            "unlocked" => LockState::Unlocked,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    Wearer,
    Keyholder,
    System,
}

impl Actor {
    pub fn as_str(&self) -> &'static str {
        match self {
            Actor::Wearer => "wearer",
            Actor::Keyholder => "keyholder",
            Actor::System => "system",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("only the keyholder can do this")]
    NotPermitted,
    #[error("not possible while the lock is {}", .0.as_str())]
    WrongState(LockState),
    #[error("a timer is running or paused; the keyholder must clear it first")]
    TimerBlocking,
    #[error("{0}")]
    TimerState(&'static str),
    #[error("the unlock approval has expired")]
    ApprovalExpired,
    #[error("duration must be positive, and min must not exceed max")]
    InvalidDuration,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub actor: Actor,
    pub kind: &'static str,
    pub detail: Value,
}

fn ev(actor: Actor, kind: &'static str, detail: Value) -> Event {
    Event { actor, kind, detail }
}

fn keyholder_only(actor: Actor) -> Result<()> {
    if actor == Actor::Keyholder { Ok(()) } else { Err(Error::NotPermitted) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Machine {
    pub state: LockState,
    pub approval_expires_ms: Option<i64>,
    pub timer: Timer,
}

impl Default for Machine {
    fn default() -> Self {
        Self { state: LockState::Locked, approval_expires_ms: None, timer: Timer::Idle }
    }
}

impl Machine {
    /// Apply the passage of time: end finished timers, expire stale approvals.
    pub fn tick(&mut self, now_ms: i64) -> Vec<Event> {
        let mut events = Vec::new();
        if let Some(ends_at) = self.timer.settle(now_ms) {
            events.push(ev(Actor::System, "timer_ended", json!({ "ends_at_ms": ends_at })));
        }
        if self.state == LockState::Approved && self.approval_expires_ms.is_some_and(|t| t <= now_ms) {
            self.state = LockState::Locked;
            self.approval_expires_ms = None;
            events.push(ev(Actor::System, "approval_expired", json!({})));
        }
        events
    }

    // ---- wearer side ----

    pub fn request_unlock(&mut self, actor: Actor, now_ms: i64) -> Result<Vec<Event>> {
        if actor != Actor::Wearer {
            return Err(Error::NotPermitted);
        }
        if self.state != LockState::Locked {
            return Err(Error::WrongState(self.state));
        }
        if self.timer.blocks_unlock(now_ms) {
            return Err(Error::TimerBlocking);
        }
        self.state = LockState::Requested;
        Ok(vec![ev(actor, "unlock_requested", json!({}))])
    }

    /// The wearer withdraws a pending request or an unused approval.
    pub fn cancel_request(&mut self, actor: Actor) -> Result<Vec<Event>> {
        if actor != Actor::Wearer {
            return Err(Error::NotPermitted);
        }
        match self.state {
            LockState::Requested | LockState::Approved => {
                self.state = LockState::Locked;
                self.approval_expires_ms = None;
                Ok(vec![ev(actor, "request_cancelled", json!({}))])
            }
            other => Err(Error::WrongState(other)),
        }
    }

    // ---- keyholder decisions ----

    pub fn approve(&mut self, actor: Actor, now_ms: i64, ttl_ms: i64) -> Result<Vec<Event>> {
        keyholder_only(actor)?;
        if self.state != LockState::Requested {
            return Err(Error::WrongState(self.state));
        }
        if self.timer.blocks_unlock(now_ms) {
            return Err(Error::TimerBlocking);
        }
        if ttl_ms <= 0 {
            return Err(Error::InvalidDuration);
        }
        let expires = now_ms + ttl_ms;
        self.state = LockState::Approved;
        self.approval_expires_ms = Some(expires);
        Ok(vec![ev(actor, "unlock_approved", json!({ "expires_at_ms": expires }))])
    }

    /// Deny a pending request, or revoke an approval that has not been used yet.
    pub fn deny(&mut self, actor: Actor) -> Result<Vec<Event>> {
        keyholder_only(actor)?;
        let kind = match self.state {
            LockState::Requested => "request_denied",
            LockState::Approved => "approval_revoked",
            other => return Err(Error::WrongState(other)),
        };
        self.state = LockState::Locked;
        self.approval_expires_ms = None;
        Ok(vec![ev(actor, kind, json!({}))])
    }

    // ---- unlock / lock ----

    /// May this actor unlock right now? The wearer needs a live approval; the
    /// keyholder may unlock directly. Nobody unlocks while a timer blocks it.
    pub fn check_unlock(&self, actor: Actor, now_ms: i64) -> Result<()> {
        match actor {
            Actor::System => return Err(Error::NotPermitted),
            Actor::Wearer => match self.state {
                LockState::Approved => {
                    if self.approval_expires_ms.is_none_or(|t| t <= now_ms) {
                        return Err(Error::ApprovalExpired);
                    }
                }
                other => return Err(Error::WrongState(other)),
            },
            Actor::Keyholder => {
                if self.state == LockState::Unlocked {
                    return Err(Error::WrongState(self.state));
                }
            }
        }
        if self.timer.blocks_unlock(now_ms) {
            return Err(Error::TimerBlocking);
        }
        Ok(())
    }

    /// The pod physically unlocked. Deliberately unconditional: it records a fact.
    /// `via` says which Bluetooth path did it: "server" or "phone".
    pub fn record_unlocked(&mut self, actor: Actor, via: &str) -> Vec<Event> {
        self.state = LockState::Unlocked;
        self.approval_expires_ms = None;
        vec![ev(actor, "unlocked", json!({ "via": via }))]
    }

    /// The wearer can lock what they unlocked. The keyholder can always lock: the pod may
    /// be physically open even when the last thing we recorded says otherwise.
    pub fn check_lock(&self, actor: Actor) -> Result<()> {
        match actor {
            Actor::System => Err(Error::NotPermitted),
            Actor::Keyholder => Ok(()),
            Actor::Wearer if self.state == LockState::Unlocked => Ok(()),
            Actor::Wearer => Err(Error::WrongState(self.state)),
        }
    }

    pub fn record_locked(&mut self, actor: Actor, via: &str) -> Vec<Event> {
        self.state = LockState::Locked;
        self.approval_expires_ms = None;
        vec![ev(actor, "locked", json!({ "via": via }))]
    }

    // ---- timer (keyholder only) ----

    pub fn set_timer(&mut self, actor: Actor, now_ms: i64, duration_ms: i64) -> Result<Vec<Event>> {
        keyholder_only(actor)?;
        if duration_ms <= 0 {
            return Err(Error::InvalidDuration);
        }
        let mut events = self.start_timer(actor, now_ms, duration_ms);
        events.insert(0, ev(actor, "timer_set", json!({ "duration_ms": duration_ms, "ends_at_ms": now_ms + duration_ms })));
        Ok(events)
    }

    /// Random duration in `min..=max`, chosen by the caller (`chosen_ms`) so the
    /// machine itself stays deterministic. The range and the roll are both audited.
    pub fn roll_timer(&mut self, actor: Actor, now_ms: i64, min_ms: i64, max_ms: i64, chosen_ms: i64) -> Result<Vec<Event>> {
        keyholder_only(actor)?;
        if min_ms <= 0 || min_ms > max_ms || chosen_ms < min_ms || chosen_ms > max_ms {
            return Err(Error::InvalidDuration);
        }
        let mut events = self.start_timer(actor, now_ms, chosen_ms);
        events.insert(
            0,
            ev(actor, "timer_rolled", json!({ "min_ms": min_ms, "max_ms": max_ms, "chosen_ms": chosen_ms, "ends_at_ms": now_ms + chosen_ms })),
        );
        Ok(events)
    }

    pub fn pause_timer(&mut self, actor: Actor, now_ms: i64) -> Result<Vec<Event>> {
        keyholder_only(actor)?;
        match self.timer {
            Timer::Running { ends_at_ms } if ends_at_ms > now_ms => {
                let remaining_ms = ends_at_ms - now_ms;
                self.timer = Timer::Paused { remaining_ms };
                Ok(vec![ev(actor, "timer_paused", json!({ "remaining_ms": remaining_ms }))])
            }
            _ => Err(Error::TimerState("there is no running timer to pause")),
        }
    }

    pub fn resume_timer(&mut self, actor: Actor, now_ms: i64) -> Result<Vec<Event>> {
        keyholder_only(actor)?;
        match self.timer {
            Timer::Paused { remaining_ms } => {
                self.timer = Timer::Running { ends_at_ms: now_ms + remaining_ms };
                Ok(vec![ev(actor, "timer_resumed", json!({ "ends_at_ms": now_ms + remaining_ms }))])
            }
            _ => Err(Error::TimerState("the timer is not paused")),
        }
    }

    pub fn clear_timer(&mut self, actor: Actor) -> Result<Vec<Event>> {
        keyholder_only(actor)?;
        if self.timer == Timer::Idle {
            return Err(Error::TimerState("there is no timer to clear"));
        }
        self.timer = Timer::Idle;
        Ok(vec![ev(actor, "timer_cleared", json!({}))])
    }

    /// Starting a timer revokes any pending request or approval: they were
    /// granted under rules that no longer hold.
    fn start_timer(&mut self, actor: Actor, now_ms: i64, duration_ms: i64) -> Vec<Event> {
        self.timer = Timer::Running { ends_at_ms: now_ms + duration_ms };
        if matches!(self.state, LockState::Requested | LockState::Approved) {
            self.state = LockState::Locked;
            self.approval_expires_ms = None;
            return vec![ev(actor, "approval_revoked", json!({ "reason": "timer started" }))];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000;
    const M: i64 = 60 * S;
    const H: i64 = 60 * M;

    fn kinds(events: &[Event]) -> Vec<&'static str> {
        events.iter().map(|e| e.kind).collect()
    }

    fn approved_machine() -> Machine {
        let mut m = Machine::default();
        m.request_unlock(Actor::Wearer, 0).unwrap();
        m.approve(Actor::Keyholder, 0, 15 * M).unwrap();
        m
    }

    #[test]
    fn happy_path_request_approve_unlock_lock() {
        let mut m = Machine::default();
        m.request_unlock(Actor::Wearer, 0).unwrap();
        assert_eq!(m.state, LockState::Requested);
        m.approve(Actor::Keyholder, 10 * S, 15 * M).unwrap();
        assert_eq!(m.state, LockState::Approved);
        m.check_unlock(Actor::Wearer, 20 * S).unwrap();
        m.record_unlocked(Actor::Wearer, "server");
        assert_eq!(m.state, LockState::Unlocked);
        m.check_lock(Actor::Wearer).unwrap();
        m.record_locked(Actor::Wearer, "server");
        assert_eq!(m.state, LockState::Locked);
        // Locking again starts the whole cycle over: no standing approval.
        assert!(m.check_unlock(Actor::Wearer, 30 * S).is_err());
    }

    #[test]
    fn wearer_can_never_use_keyholder_powers() {
        let mut m = Machine::default();
        m.request_unlock(Actor::Wearer, 0).unwrap();
        assert_eq!(m.approve(Actor::Wearer, 0, M), Err(Error::NotPermitted));
        assert_eq!(m.deny(Actor::Wearer), Err(Error::NotPermitted));
        assert_eq!(m.set_timer(Actor::Wearer, 0, H), Err(Error::NotPermitted));
        assert_eq!(m.roll_timer(Actor::Wearer, 0, H, 2 * H, H), Err(Error::NotPermitted));
        assert_eq!(m.pause_timer(Actor::Wearer, 0), Err(Error::NotPermitted));
        assert_eq!(m.resume_timer(Actor::Wearer, 0), Err(Error::NotPermitted));
        assert_eq!(m.clear_timer(Actor::Wearer), Err(Error::NotPermitted));
        assert_eq!(m.approve(Actor::System, 0, M), Err(Error::NotPermitted));
        assert_eq!(m.state, LockState::Requested);
    }

    #[test]
    fn wearer_cannot_unlock_without_approval() {
        let mut m = Machine::default();
        assert_eq!(m.check_unlock(Actor::Wearer, 0), Err(Error::WrongState(LockState::Locked)));
        m.request_unlock(Actor::Wearer, 0).unwrap();
        assert_eq!(m.check_unlock(Actor::Wearer, 0), Err(Error::WrongState(LockState::Requested)));
    }

    #[test]
    fn the_keyholder_can_lock_in_any_state_but_the_wearer_only_after_unlocking() {
        let mut m = Machine::default();
        assert_eq!(m.check_lock(Actor::Wearer), Err(Error::WrongState(LockState::Locked)));
        m.check_lock(Actor::Keyholder).unwrap();
        assert_eq!(m.check_lock(Actor::System), Err(Error::NotPermitted));
        m.record_unlocked(Actor::Keyholder, "server");
        m.check_lock(Actor::Wearer).unwrap();
    }

    #[test]
    fn keyholder_can_unlock_directly_but_system_cannot() {
        let m = Machine::default();
        m.check_unlock(Actor::Keyholder, 0).unwrap();
        assert_eq!(m.check_unlock(Actor::System, 0), Err(Error::NotPermitted));
    }

    #[test]
    fn running_timer_blocks_request_until_it_ends_then_needs_approval() {
        let mut m = Machine::default();
        m.set_timer(Actor::Keyholder, 0, 2 * H).unwrap();
        assert_eq!(m.request_unlock(Actor::Wearer, H), Err(Error::TimerBlocking));

        let ended = m.tick(2 * H);
        assert_eq!(kinds(&ended), ["timer_ended"]);
        assert_eq!(m.timer, Timer::Ended);

        // Ending only reopens requests; it never unlocks by itself.
        assert_eq!(m.state, LockState::Locked);
        assert!(m.check_unlock(Actor::Wearer, 2 * H).is_err());
        m.request_unlock(Actor::Wearer, 2 * H).unwrap();
        m.approve(Actor::Keyholder, 2 * H, 15 * M).unwrap();
        m.check_unlock(Actor::Wearer, 2 * H).unwrap();
    }

    #[test]
    fn keyholder_must_pause_or_clear_timer_before_unlocking() {
        let mut m = Machine::default();
        m.set_timer(Actor::Keyholder, 0, 2 * H).unwrap();
        assert_eq!(m.check_unlock(Actor::Keyholder, H), Err(Error::TimerBlocking));

        // Pausing is not enough: a paused timer still blocks.
        m.pause_timer(Actor::Keyholder, H).unwrap();
        assert_eq!(m.check_unlock(Actor::Keyholder, H), Err(Error::TimerBlocking));

        m.clear_timer(Actor::Keyholder).unwrap();
        m.check_unlock(Actor::Keyholder, H).unwrap();
    }

    #[test]
    fn pause_and_resume_preserve_remaining_time() {
        let mut m = Machine::default();
        m.set_timer(Actor::Keyholder, 0, 10 * H).unwrap();
        let e = m.pause_timer(Actor::Keyholder, 4 * H).unwrap();
        assert_eq!(e[0].detail["remaining_ms"], 6 * H);
        // Time passing while paused changes nothing.
        assert!(m.tick(100 * H).is_empty());
        m.resume_timer(Actor::Keyholder, 100 * H).unwrap();
        assert_eq!(m.timer, Timer::Running { ends_at_ms: 106 * H });
    }

    #[test]
    fn approval_expires_and_cannot_be_used_afterwards() {
        let mut m = approved_machine();
        assert_eq!(m.check_unlock(Actor::Wearer, 15 * M), Err(Error::ApprovalExpired));
        let e = m.tick(15 * M);
        assert_eq!(kinds(&e), ["approval_expired"]);
        assert_eq!(m.state, LockState::Locked);
        assert_eq!(m.check_unlock(Actor::Wearer, 15 * M), Err(Error::WrongState(LockState::Locked)));
    }

    #[test]
    fn starting_a_timer_revokes_pending_request_and_approval() {
        let mut requested = Machine::default();
        requested.request_unlock(Actor::Wearer, 0).unwrap();
        let e = requested.set_timer(Actor::Keyholder, 0, H).unwrap();
        assert_eq!(kinds(&e), ["timer_set", "approval_revoked"]);
        assert_eq!(requested.state, LockState::Locked);

        let mut approved = approved_machine();
        approved.set_timer(Actor::Keyholder, M, H).unwrap();
        assert_eq!(approved.state, LockState::Locked);
        assert_eq!(approved.approval_expires_ms, None);
        assert!(approved.check_unlock(Actor::Wearer, M).is_err());
    }

    #[test]
    fn keyholder_cannot_approve_while_timer_blocks() {
        let mut m = Machine::default();
        m.request_unlock(Actor::Wearer, 0).unwrap();
        // Bypass set_timer's auto-revoke to model a timer that started earlier.
        m.timer = Timer::Running { ends_at_ms: H };
        assert_eq!(m.approve(Actor::Keyholder, 0, M), Err(Error::TimerBlocking));
    }

    #[test]
    fn rejected_actions_leave_the_machine_unchanged() {
        let mut m = approved_machine();
        let before = m.clone();
        let _ = m.request_unlock(Actor::Wearer, 0);
        let _ = m.approve(Actor::Wearer, 0, M);
        let _ = m.set_timer(Actor::Keyholder, 0, -1);
        let _ = m.pause_timer(Actor::Keyholder, 0);
        assert_eq!(m, before);
    }

    #[test]
    fn roll_records_range_and_result_and_validates_them() {
        let mut m = Machine::default();
        let e = m.roll_timer(Actor::Keyholder, 0, H, 3 * H, 2 * H).unwrap();
        assert_eq!(kinds(&e), ["timer_rolled"]);
        assert_eq!(e[0].detail["chosen_ms"], 2 * H);
        assert_eq!(m.timer, Timer::Running { ends_at_ms: 2 * H });
        assert_eq!(m.roll_timer(Actor::Keyholder, 0, 3 * H, H, 2 * H), Err(Error::InvalidDuration));
        assert_eq!(m.roll_timer(Actor::Keyholder, 0, H, 3 * H, 4 * H), Err(Error::InvalidDuration));
    }

    #[test]
    fn wearer_can_withdraw_but_keyholder_can_revoke() {
        let mut m = approved_machine();
        m.cancel_request(Actor::Wearer).unwrap();
        assert_eq!(m.state, LockState::Locked);

        let mut m = approved_machine();
        let e = m.deny(Actor::Keyholder).unwrap();
        assert_eq!(kinds(&e), ["approval_revoked"]);
        assert_eq!(m.state, LockState::Locked);
    }
}
