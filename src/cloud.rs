//! The QIUI cloud as the pod session needs it: mint handshake/unlock/lock
//! commands and decode the pod's replies. `QiuiCloud` is the real client and
//! also keeps the 12-hour platform token fresh.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::api::system_now_ms;
use crate::client::{ApiCodeError, BOUND_ELSEWHERE_CODES, DeviceInfo, QiuiClient};
use crate::pod::PodStatus;

/// Renew this long before the token runs out.
const REFRESH_MARGIN_MS: i64 = 30 * 60 * 1000;
/// If QIUI hands back a token that is still near expiry, do not ask again for a while.
const RETRY_AFTER_MS: i64 = 60 * 1000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CloudError {
    /// The pod is now bound in the consumer app or on another platform.
    #[error("the pod is bound outside this server")]
    BoundElsewhere,
    #[error("{0}")]
    Other(String),
}

fn classify(e: anyhow::Error) -> CloudError {
    match e.downcast_ref::<ApiCodeError>() {
        Some(c) if BOUND_ELSEWHERE_CODES.contains(&c.code) => CloudError::BoundElsewhere,
        _ => CloudError::Other(format!("{e:#}")),
    }
}

#[async_trait]
pub trait Cloud: Send + Sync {
    async fn device_token_cmd(&self) -> Result<String, CloudError>;
    async fn decrypt_reply(&self, reply_hex: &str) -> Result<PodStatus, CloudError>;
    async fn unlock_cmd(&self) -> Result<String, CloudError>;
    async fn lock_cmd(&self) -> Result<String, CloudError>;
}

struct Inner {
    client: QiuiClient,
    device: Option<Arc<DeviceInfo>>,
    last_token_attempt_ms: i64,
}

pub struct QiuiCloud {
    inner: Mutex<Inner>,
    mac: String,
}

impl QiuiCloud {
    pub fn new(client_id: &str, mac: &str, debug: bool) -> Self {
        Self {
            inner: Mutex::new(Inner { client: QiuiClient::new(client_id, debug), device: None, last_token_attempt_ms: 0 }),
            mac: mac.to_string(),
        }
    }

    /// Make sure the platform token is valid for at least the refresh margin. The token is kept in
    /// memory only: QIUI returns the same token until it expires, so fetching again after a restart
    /// gives the same result, and no live credential ever needs to sit in the database.
    async fn ensure_token(&self, inner: &mut Inner) -> Result<(), CloudError> {
        let now = system_now_ms();
        let fresh = inner.client.token_expires_at_ms().is_some_and(|t| t - now > REFRESH_MARGIN_MS);
        if fresh || now - inner.last_token_attempt_ms < RETRY_AFTER_MS && inner.client.token_expires_at_ms().is_some_and(|t| t > now) {
            return Ok(());
        }
        inner.last_token_attempt_ms = now;
        let still_valid = inner.client.token_expires_at_ms().is_some_and(|t| t > now);
        if still_valid && inner.client.refresh_platform_token().await.is_ok() {
            return Ok(());
        }
        inner.client.get_platform_token().await.map_err(classify)
    }

    /// Renew the token if it is close to expiring. Returns when the current one expires.
    pub async fn refresh_token_if_needed(&self) -> Result<Option<i64>, CloudError> {
        let mut inner = self.inner.lock().await;
        self.ensure_token(&mut inner).await?;
        Ok(inner.client.token_expires_at_ms())
    }

    pub async fn token_expires_at_ms(&self) -> Option<i64> {
        self.inner.lock().await.client.token_expires_at_ms()
    }

    async fn ready(&self) -> Result<(tokio::sync::MutexGuard<'_, Inner>, Arc<DeviceInfo>), CloudError> {
        let mut inner = self.inner.lock().await;
        self.ensure_token(&mut inner).await?;
        if inner.device.is_none() {
            let dev = inner.client.ensure_bound(&self.mac).await.map_err(classify)?;
            inner.device = Some(Arc::new(dev));
        }
        let dev = inner.device.clone().expect("device was just set");
        Ok((inner, dev))
    }
}

#[async_trait]
impl Cloud for QiuiCloud {
    async fn device_token_cmd(&self) -> Result<String, CloudError> {
        let (inner, dev) = self.ready().await?;
        inner.client.device_token_cmd(&self.mac, &dev).await.map_err(classify)
    }

    async fn decrypt_reply(&self, reply_hex: &str) -> Result<PodStatus, CloudError> {
        let (inner, dev) = self.ready().await?;
        let s = inner.client.decrypt_reply(reply_hex, &dev).await.map_err(classify)?;
        Ok(PodStatus { battery: s.battery, comment_type: s.comment_type.unwrap_or_default(), is_unlocking: s.is_unlocking.unwrap_or(false) })
    }

    async fn unlock_cmd(&self) -> Result<String, CloudError> {
        let (inner, dev) = self.ready().await?;
        inner.client.unlock_cmd(&self.mac, &dev).await.map_err(classify)
    }

    async fn lock_cmd(&self) -> Result<String, CloudError> {
        let (inner, dev) = self.ready().await?;
        inner.client.lock_cmd(&self.mac, &dev).await.map_err(classify)
    }
}

/// Stands in until QIUI credentials are configured, so the server can still run
/// (accounts, timers, messages) and say clearly why pod control does not work.
pub struct UnconfiguredCloud;

impl UnconfiguredCloud {
    fn err<T>() -> Result<T, CloudError> {
        Err(CloudError::Other("QIUI credentials are not configured. Run `qiui-server config set-client-id`.".into()))
    }
}

#[async_trait]
impl Cloud for UnconfiguredCloud {
    async fn device_token_cmd(&self) -> Result<String, CloudError> {
        Self::err()
    }
    async fn decrypt_reply(&self, _: &str) -> Result<PodStatus, CloudError> {
        Self::err()
    }
    async fn unlock_cmd(&self) -> Result<String, CloudError> {
        Self::err()
    }
    async fn lock_cmd(&self) -> Result<String, CloudError> {
        Self::err()
    }
}

/// Demo mode: answers like a healthy pod without any QIUI account or hardware.
pub struct SimulatedCloud;

#[async_trait]
impl Cloud for SimulatedCloud {
    async fn device_token_cmd(&self) -> Result<String, CloudError> {
        Ok("5301".into())
    }
    async fn decrypt_reply(&self, reply_hex: &str) -> Result<PodStatus, CloudError> {
        // A simulated pod answers a command "53xx" with a reply starting "xx":
        // "01" handshake, "02" unlock, "03" lock.
        let comment_type = if reply_hex.len() >= 2 { reply_hex[..2].to_string() } else { "01".into() };
        Ok(PodStatus { battery: None, is_unlocking: comment_type == "02", comment_type })
    }
    async fn unlock_cmd(&self) -> Result<String, CloudError> {
        Ok("5502".into())
    }
    async fn lock_cmd(&self) -> Result<String, CloudError> {
        Ok("5503".into())
    }
}
