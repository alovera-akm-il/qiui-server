//! Stand-ins for the QIUI cloud and the pod, so the rules around them can be tested
//! without hardware. Test builds only.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::cloud::{Cloud, CloudError};
use crate::pod::{PodError, PodLink, PodOp, PodStatus, Transport};
use crate::push::{PushError, PushSender, Subscription};

#[derive(Default)]
pub struct FakeCloud {
    calls: Mutex<Vec<String>>,
    counter: Mutex<u32>,
    reply_types: Mutex<HashMap<String, String>>,
    fail_mint: Mutex<bool>,
    bound_elsewhere: Mutex<bool>,
}

impl FakeCloud {
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// Make `decrypt_reply(reply)` report this `commentType`.
    pub fn set_reply_type(&self, reply: &str, comment_type: &str) {
        self.reply_types.lock().unwrap().insert(reply.to_string(), comment_type.to_string());
    }

    pub fn fail_minting(&self) {
        *self.fail_mint.lock().unwrap() = true;
    }

    pub fn bound_elsewhere(&self) {
        *self.bound_elsewhere.lock().unwrap() = true;
    }

    fn record(&self, call: impl Into<String>) {
        self.calls.lock().unwrap().push(call.into());
    }

    fn next(&self, prefix: &str) -> Result<String, CloudError> {
        if *self.bound_elsewhere.lock().unwrap() {
            return Err(CloudError::BoundElsewhere);
        }
        if prefix != "TOKEN" && *self.fail_mint.lock().unwrap() {
            return Err(CloudError::Other("refused".into()));
        }
        let mut n = self.counter.lock().unwrap();
        *n += 1;
        Ok(format!("{prefix}-{}", *n))
    }

    fn count_of(&self, prefix: &str) -> u32 {
        self.calls.lock().unwrap().iter().filter(|c| c.as_str() == prefix).count() as u32
    }
}

#[async_trait]
impl Cloud for FakeCloud {
    async fn device_token_cmd(&self) -> Result<String, CloudError> {
        self.record("device_token_cmd");
        let out = self.next("TOKEN");
        // Numbered per kind so tests can name the exact bytes they expect.
        out.map(|_| format!("TOKEN-{}", self.count_of("device_token_cmd")))
    }

    async fn decrypt_reply(&self, reply_hex: &str) -> Result<PodStatus, CloudError> {
        self.record(format!("decrypt:{reply_hex}"));
        if *self.bound_elsewhere.lock().unwrap() {
            return Err(CloudError::BoundElsewhere);
        }
        let comment_type = self.reply_types.lock().unwrap().get(reply_hex).cloned().unwrap_or_else(|| {
            // Default: infer from the reply's name so simple tests need no setup.
            if reply_hex.contains("unlock") {
                "02".into()
            } else if reply_hex.contains("lock") {
                "03".into()
            } else {
                "01".into()
            }
        });
        Ok(PodStatus { battery: Some(0), is_unlocking: comment_type == "02", comment_type })
    }

    async fn unlock_cmd(&self) -> Result<String, CloudError> {
        self.record("unlock_cmd");
        self.next("UNLOCK").map(|_| format!("UNLOCK-{}", self.count_of("unlock_cmd")))
    }

    async fn lock_cmd(&self) -> Result<String, CloudError> {
        self.record("lock_cmd");
        self.next("LOCK").map(|_| format!("LOCK-{}", self.count_of("lock_cmd")))
    }
}

/// A pod connection that answers with canned replies, in order.
pub struct FakeTransport {
    replies: Vec<String>,
    written: Vec<String>,
}

impl FakeTransport {
    pub fn new<const N: usize>(replies: [&str; N]) -> Self {
        Self { replies: replies.iter().rev().map(|s| s.to_string()).collect(), written: Vec::new() }
    }

    pub fn written(&self) -> Vec<String> {
        self.written.clone()
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn exchange(&mut self, cmd_hex: &str) -> Result<String, PodError> {
        self.written.push(cmd_hex.to_string());
        self.replies.pop().ok_or(PodError::Timeout)
    }
}

/// A whole-session stand-in for the pod, for server-level tests.
pub struct FakePod {
    in_range: Mutex<bool>,
    ops: Mutex<Vec<PodOp>>,
}

impl Default for FakePod {
    fn default() -> Self {
        Self { in_range: Mutex::new(true), ops: Mutex::new(Vec::new()) }
    }
}

impl FakePod {
    pub fn set_in_range(&self, yes: bool) {
        *self.in_range.lock().unwrap() = yes;
    }

    pub fn ops(&self) -> Vec<PodOp> {
        self.ops.lock().unwrap().clone()
    }
}

#[async_trait]
impl PodLink for FakePod {
    async fn run(&self, _cloud: &dyn Cloud, op: PodOp) -> Result<PodStatus, PodError> {
        if !*self.in_range.lock().unwrap() {
            return Err(PodError::NotInRange);
        }
        self.ops.lock().unwrap().push(op);
        let comment_type = match op {
            PodOp::Status => "01",
            PodOp::Unlock => "02",
            PodOp::Lock => "03",
        };
        Ok(PodStatus { battery: Some(0), comment_type: comment_type.into(), is_unlocking: op == PodOp::Unlock })
    }
}

/// Collects what would have been pushed instead of contacting a push service.
#[derive(Default)]
pub struct FakeSender {
    sent: Mutex<Vec<serde_json::Value>>,
    gone: Mutex<bool>,
}

impl FakeSender {
    pub fn sent(&self) -> Vec<serde_json::Value> {
        self.sent.lock().unwrap().clone()
    }

    /// Make the "push service" answer that the subscription no longer exists.
    pub fn set_gone(&self) {
        *self.gone.lock().unwrap() = true;
    }
}

#[async_trait]
impl PushSender for FakeSender {
    async fn send(&self, _sub: &Subscription, payload: &[u8]) -> Result<(), PushError> {
        if *self.gone.lock().unwrap() {
            return Err(PushError::Gone);
        }
        self.sent.lock().unwrap().push(serde_json::from_slice(payload).unwrap());
        Ok(())
    }
}
