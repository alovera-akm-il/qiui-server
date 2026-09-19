//! One short Bluetooth session with the pod: connect, handshake, run one
//! command, disconnect. Nothing here keeps a connection open between actions.
//!
//! The order inside a session is fixed by what the pod and QIUI's server need
//! (see RESEARCH.md §10): write the handshake token, wait for the pod's reply,
//! have the cloud decrypt it, and only then ask the cloud for an unlock or lock
//! command. Skipping the decrypt gives bytes the pod ignores.

use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::ble::{self, KeyPod};
use crate::cloud::{Cloud, CloudError};

/// Hard cap on one whole session, scan and retries included.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodOp {
    Status,
    Unlock,
    Lock,
}

impl PodOp {
    /// The `commentType` the pod uses to acknowledge this operation.
    fn expected_reply(&self) -> Option<&'static str> {
        match self {
            PodOp::Status => None,
            PodOp::Unlock => Some("02"),
            PodOp::Lock => Some("03"),
        }
    }
}

/// What the pod reported, decoded by QIUI's server. `comment_type`: `01` handshake,
/// `02` unlock acknowledged, `03` lock acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PodStatus {
    pub battery: Option<i64>,
    pub comment_type: String,
    pub is_unlocking: bool,
}

#[derive(Debug, Error)]
pub enum PodError {
    #[error("the pod is not within Bluetooth range of the server")]
    NotInRange,
    #[error("Bluetooth problem: {0}")]
    Ble(String),
    #[error("QIUI's cloud refused: {0}")]
    Cloud(String),
    #[error("control of the pod was lost: it is now bound outside this server")]
    ControlLost,
    #[error("the pod answered with something unexpected")]
    Unexpected,
    #[error("the pod did not answer in time")]
    Timeout,
}

impl From<CloudError> for PodError {
    fn from(e: CloudError) -> Self {
        match e {
            CloudError::BoundElsewhere => PodError::ControlLost,
            CloudError::Other(m) => PodError::Cloud(m),
        }
    }
}

/// Write one command to the pod and return its reply, hex-encoded.
#[async_trait]
pub trait Transport: Send {
    async fn exchange(&mut self, cmd_hex: &str) -> Result<String, PodError>;
}

/// Something that can run one operation against the pod in a single short session.
#[async_trait]
pub trait PodLink: Send + Sync {
    async fn run(&self, cloud: &dyn Cloud, op: PodOp) -> Result<PodStatus, PodError>;
}

/// The handshake-then-command sequence over an already open connection.
pub async fn run_session(cloud: &dyn Cloud, link: &mut dyn Transport, op: PodOp) -> Result<PodStatus, PodError> {
    let token_cmd = cloud.device_token_cmd().await?;
    let reply = link.exchange(&token_cmd).await?;
    // The cloud must see the handshake reply before it will mint a working command.
    let handshake = cloud.decrypt_reply(&reply).await?;

    let command = match op {
        PodOp::Status => return Ok(handshake),
        PodOp::Unlock => cloud.unlock_cmd().await?,
        PodOp::Lock => cloud.lock_cmd().await?,
    };
    let reply = link.exchange(&command).await?;
    let status = cloud.decrypt_reply(&reply).await?;
    if Some(status.comment_type.as_str()) != op.expected_reply() {
        return Err(PodError::Unexpected);
    }
    Ok(status)
}

/// The real thing: Bluetooth through btleplug.
pub struct BlePod {
    pub mac: String,
    pub debug: bool,
}

impl BlePod {
    async fn attempt(&self, cloud: &dyn Cloud, op: PodOp) -> Result<PodStatus, PodError> {
        let mut pod = KeyPod::connect(&self.mac, self.debug).await.map_err(|e| {
            if e.downcast_ref::<ble::NotFound>().is_some() { PodError::NotInRange } else { PodError::Ble(format!("{e:#}")) }
        })?;
        let result = run_session(cloud, &mut pod, op).await;
        // Always leave: nothing stays connected once the action is done.
        pod.disconnect().await.ok();
        result
    }
}

#[async_trait]
impl PodLink for BlePod {
    async fn run(&self, cloud: &dyn Cloud, op: PodOp) -> Result<PodStatus, PodError> {
        let session = async {
            match self.attempt(cloud, op).await {
                // The first connection after the pod wakes often drops within seconds. Once more.
                Err(PodError::Ble(first)) => {
                    if self.debug {
                        eprintln!("  BLE session failed ({first}); retrying once");
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    self.attempt(cloud, op).await
                }
                other => other,
            }
        };
        tokio::time::timeout(SESSION_TIMEOUT, session).await.map_err(|_| PodError::Timeout)?
    }
}

/// Demo mode: a pod that always obeys, and is either always in range of the server or never.
/// For trying the app out only.
pub struct SimulatedPod {
    pub in_range: bool,
}

#[async_trait]
impl PodLink for SimulatedPod {
    async fn run(&self, _cloud: &dyn Cloud, op: PodOp) -> Result<PodStatus, PodError> {
        tokio::time::sleep(Duration::from_millis(600)).await;
        if !self.in_range {
            return Err(PodError::NotInRange);
        }
        let comment_type = match op {
            PodOp::Status => "01",
            PodOp::Unlock => "02",
            PodOp::Lock => "03",
        };
        Ok(PodStatus { battery: None, comment_type: comment_type.into(), is_unlocking: op == PodOp::Unlock })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::{FakeCloud, FakeTransport};

    #[tokio::test]
    async fn unlock_runs_token_then_decrypt_then_mint_then_command() {
        let cloud = FakeCloud::default();
        let mut link = FakeTransport::new(["reply-to-token", "reply-to-unlock"]);
        let status = run_session(&cloud, &mut link, PodOp::Unlock).await.unwrap();
        assert_eq!(status.comment_type, "02");

        assert_eq!(cloud.calls(), ["device_token_cmd", "decrypt:reply-to-token", "unlock_cmd", "decrypt:reply-to-unlock"]);
        assert_eq!(link.written(), ["TOKEN-1", "UNLOCK-1"]);
    }

    #[tokio::test]
    async fn the_unlock_is_never_minted_before_the_handshake_reply_is_decrypted() {
        let cloud = FakeCloud::default();
        let mut link = FakeTransport::new(["r-token", "r-unlock"]);
        run_session(&cloud, &mut link, PodOp::Unlock).await.unwrap();
        let calls = cloud.calls();
        let decrypt = calls.iter().position(|c| c.starts_with("decrypt:")).unwrap();
        let mint = calls.iter().position(|c| c == "unlock_cmd").unwrap();
        assert!(decrypt < mint);
    }

    #[tokio::test]
    async fn status_does_only_the_handshake() {
        let cloud = FakeCloud::default();
        let mut link = FakeTransport::new(["only-reply"]);
        let status = run_session(&cloud, &mut link, PodOp::Status).await.unwrap();
        assert_eq!(status.comment_type, "01");
        assert_eq!(cloud.calls(), ["device_token_cmd", "decrypt:only-reply"]);
        assert_eq!(link.written().len(), 1);
    }

    #[tokio::test]
    async fn lock_expects_the_lock_acknowledgement() {
        let cloud = FakeCloud::default();
        let mut link = FakeTransport::new(["r-token", "r-lock"]);
        assert_eq!(run_session(&cloud, &mut link, PodOp::Lock).await.unwrap().comment_type, "03");
    }

    #[tokio::test]
    async fn a_wrong_acknowledgement_is_an_error_not_a_success() {
        let cloud = FakeCloud::default();
        cloud.set_reply_type("a", "01");
        cloud.set_reply_type("b", "03"); // lock ack in reply to an unlock
        let mut link = FakeTransport::new(["a", "b"]);
        assert!(matches!(run_session(&cloud, &mut link, PodOp::Unlock).await, Err(PodError::Unexpected)));
    }

    #[tokio::test]
    async fn if_the_cloud_refuses_to_mint_nothing_more_is_written() {
        let cloud = FakeCloud::default();
        cloud.fail_minting();
        let mut link = FakeTransport::new(["a", "b"]);
        assert!(matches!(run_session(&cloud, &mut link, PodOp::Unlock).await, Err(PodError::Cloud(_))));
        assert_eq!(link.written(), ["TOKEN-1"], "only the handshake token may have been written");
    }

    #[tokio::test]
    async fn a_pod_bound_elsewhere_is_reported_as_control_lost() {
        let cloud = FakeCloud::default();
        cloud.bound_elsewhere();
        let mut link = FakeTransport::new(["a"]);
        assert!(matches!(run_session(&cloud, &mut link, PodOp::Status).await, Err(PodError::ControlLost)));
        assert!(link.written().is_empty());
    }
}
