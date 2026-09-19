//! Coordinates access to the pod. The server's own Bluetooth runs one session
//! at a time. Phone-relay sessions are tracked here too: each is tied to one
//! paired device, expires after two minutes, and remembers how far along the
//! handshake-then-command sequence it is, so the server (not the phone) decides
//! when an unlock or lock command may be minted.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::accounts::random_token;
use crate::cloud::Cloud;
use crate::pod::{PodError, PodLink, PodOp, PodStatus};
use crate::queue::Command;

pub const RELAY_TTL_MS: i64 = 2 * 60 * 1000;
/// The wearer's Sync button cannot be used to hammer the pod's battery and QIUI's API.
pub const SYNC_COOLDOWN_MS: i64 = 15 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Status,
    Unlock,
    Lock,
    /// Carry out the keyholder's queued command from the wearer's phone.
    Queued { command: Command, queue_id: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Waiting for the pod's reply to the handshake token.
    Handshake,
    /// The unlock/lock command was handed out; waiting for the pod's acknowledgement.
    Command,
}

#[derive(Debug, Clone)]
pub struct Relay {
    pub device_id: i64,
    pub intent: Intent,
    pub stage: Stage,
    pub started_ms: i64,
}

pub struct Hardware {
    pub cloud: Arc<dyn Cloud>,
    pod: Arc<dyn PodLink>,
    gate: tokio::sync::Mutex<()>,
    relays: Mutex<HashMap<String, Relay>>,
    last_sync_ms: Mutex<i64>,
}

impl Hardware {
    pub fn new(cloud: Arc<dyn Cloud>, pod: Arc<dyn PodLink>) -> Self {
        Self { cloud, pod, gate: tokio::sync::Mutex::new(()), relays: Mutex::new(HashMap::new()), last_sync_ms: Mutex::new(i64::MIN) }
    }

    /// One short session over the server's own Bluetooth. Never two at once.
    pub async fn direct(&self, op: PodOp) -> Result<PodStatus, PodError> {
        // Fail before spending a Bluetooth scan on a session that cannot get its commands.
        self.cloud.is_ready().await?;
        let _one_at_a_time = self.gate.lock().await;
        self.pod.run(&*self.cloud, op).await
    }

    /// True if a wearer-triggered sync may run now (and starts the cooldown).
    pub fn sync_due(&self, now_ms: i64) -> bool {
        let mut last = self.last_sync_ms.lock().expect("sync lock");
        if now_ms.saturating_sub(*last) < SYNC_COOLDOWN_MS {
            return false;
        }
        *last = now_ms;
        true
    }

    /// Begin a relay session for this device, replacing any earlier one it had.
    pub fn start_relay(&self, device_id: i64, intent: Intent, now_ms: i64) -> String {
        let id = random_token();
        let mut relays = self.relays.lock().expect("relay lock");
        relays.retain(|_, r| r.device_id != device_id && now_ms - r.started_ms < RELAY_TTL_MS);
        relays.insert(id.clone(), Relay { device_id, intent, stage: Stage::Handshake, started_ms: now_ms });
        id
    }

    /// The session, if it exists, belongs to this device and has not expired.
    pub fn relay(&self, id: &str, device_id: i64, now_ms: i64) -> Option<Relay> {
        let mut relays = self.relays.lock().expect("relay lock");
        match relays.get(id) {
            Some(r) if r.device_id == device_id && now_ms - r.started_ms < RELAY_TTL_MS => Some(r.clone()),
            Some(r) if now_ms - r.started_ms >= RELAY_TTL_MS => {
                relays.remove(id);
                None
            }
            _ => None,
        }
    }

    pub fn advance_relay(&self, id: &str) {
        if let Some(r) = self.relays.lock().expect("relay lock").get_mut(id) {
            r.stage = Stage::Command;
        }
    }

    pub fn end_relay(&self, id: &str) {
        self.relays.lock().expect("relay lock").remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::{FakeCloud, FakePod};

    fn hw() -> Hardware {
        Hardware::new(Arc::new(FakeCloud::default()), Arc::new(FakePod::default()))
    }

    #[test]
    fn a_relay_session_belongs_to_one_device_and_expires() {
        let h = hw();
        let id = h.start_relay(1, Intent::Unlock, 0);
        assert!(h.relay(&id, 1, 1).is_some());
        assert!(h.relay(&id, 2, 1).is_none(), "another device must not be able to use it");
        assert!(h.relay(&id, 1, RELAY_TTL_MS).is_none());
        assert!(h.relay(&id, 1, 1).is_none(), "an expired session is gone for good");
    }

    #[test]
    fn a_device_has_at_most_one_relay_session() {
        let h = hw();
        let first = h.start_relay(1, Intent::Status, 0);
        let second = h.start_relay(1, Intent::Unlock, 1);
        assert!(h.relay(&first, 1, 2).is_none());
        assert!(h.relay(&second, 1, 2).is_some());
    }

    #[test]
    fn stages_advance_and_sessions_end() {
        let h = hw();
        let id = h.start_relay(1, Intent::Lock, 0);
        assert_eq!(h.relay(&id, 1, 1).unwrap().stage, Stage::Handshake);
        h.advance_relay(&id);
        assert_eq!(h.relay(&id, 1, 1).unwrap().stage, Stage::Command);
        h.end_relay(&id);
        assert!(h.relay(&id, 1, 1).is_none());
    }

    #[test]
    fn sync_has_a_cooldown() {
        let h = hw();
        assert!(h.sync_due(1_000));
        assert!(!h.sync_due(1_000 + SYNC_COOLDOWN_MS - 1));
        assert!(h.sync_due(1_000 + SYNC_COOLDOWN_MS));
    }
}
