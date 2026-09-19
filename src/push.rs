//! Web Push for the wearer's device: the server's VAPID identity, the device's
//! subscription, and turning audit-log events into notifications.
//!
//! The push service (Google, Mozilla, Apple) only ever sees an encrypted
//! payload it cannot read. The server sends to the URL the wearer's device
//! supplies, so that URL is restricted to https on the known push services:
//! otherwise a wearer could point the server at something inside the network.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;
use web_push_native::jwt_simple::algorithms::{ECDSAP256PublicKeyLike, ES256KeyPair};
use web_push_native::p256::PublicKey;
use web_push_native::{Auth, WebPushBuilder};

use crate::api::{self, AppState};
use crate::audit;

/// Hosts a browser's push endpoint can legitimately be on.
const PUSH_HOST_SUFFIXES: [&str; 5] = ["googleapis.com", "mozilla.com", "push.apple.com", "notify.windows.com", "mozaws.net"];
pub const DEFAULT_CONTACT: &str = "mailto:keyholder@example.com";

// ---------- server identity ----------

/// The server's VAPID keypair. The public half goes to the browser so it will
/// only accept pushes signed by this server.
pub struct Vapid {
    pair: ES256KeyPair,
    public_b64: String,
}

impl Vapid {
    pub fn from_pair(pair: ES256KeyPair) -> Self {
        let public = pair.public_key().public_key().to_bytes_uncompressed();
        Self { public_b64: Base64UrlUnpadded::encode_string(&public), pair }
    }

    /// Load `vapid.key` from the data directory, creating it (owner-only) on first run.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let path = dir.join("vapid.key");
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(mut f) => {
                let pair = ES256KeyPair::generate();
                f.write_all(&pair.to_bytes())?;
                Ok(Self::from_pair(pair))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                crate::datadir::require_private(&path)?;
                let pair = ES256KeyPair::from_bytes(&fs::read(&path)?).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                Ok(Self::from_pair(pair))
            }
            Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
        }
    }

    /// What the browser's `applicationServerKey` needs: the uncompressed public key, base64url.
    pub fn public_key(&self) -> &str {
        &self.public_b64
    }
}

// ---------- subscription storage ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub device_id: i64,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS push_subscriptions (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id),
            endpoint TEXT NOT NULL,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            created_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS push_cursor (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_audit_id INTEGER NOT NULL
        );",
    )
}

/// Reject anything that is not an https push-service URL with well-formed keys.
pub fn validate(sub: &Subscription) -> std::result::Result<(), &'static str> {
    let url = reqwest::Url::parse(&sub.endpoint).map_err(|_| "endpoint is not a valid URL")?;
    if url.scheme() != "https" || sub.endpoint.len() > 2048 {
        return Err("endpoint must be an https URL");
    }
    let host = url.host_str().ok_or("endpoint has no host")?;
    if !PUSH_HOST_SUFFIXES.iter().any(|s| host == *s || host.ends_with(&format!(".{s}"))) {
        return Err("endpoint is not a known push service");
    }
    let key = Base64UrlUnpadded::decode_vec(&sub.p256dh).map_err(|_| "p256dh is not base64url")?;
    PublicKey::from_sec1_bytes(&key).map_err(|_| "p256dh is not a valid public key")?;
    let auth = Base64UrlUnpadded::decode_vec(&sub.auth).map_err(|_| "auth is not base64url")?;
    if auth.len() != 16 {
        return Err("auth must be 16 bytes");
    }
    Ok(())
}

pub fn save_subscription(conn: &Connection, sub: &Subscription, now_ms: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO push_subscriptions (device_id, endpoint, p256dh, auth, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(device_id) DO UPDATE SET endpoint = ?2, p256dh = ?3, auth = ?4, created_ms = ?5",
        params![sub.device_id, sub.endpoint, sub.p256dh, sub.auth, now_ms],
    )?;
    Ok(())
}

pub fn delete_subscription(conn: &Connection, device_id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM push_subscriptions WHERE device_id = ?1", [device_id])?;
    Ok(())
}

/// The subscription of the wearer's active (unrevoked) device, if it has one.
pub fn active_subscription(conn: &Connection) -> rusqlite::Result<Option<Subscription>> {
    conn.query_row(
        "SELECT s.device_id, s.endpoint, s.p256dh, s.auth FROM push_subscriptions s
         JOIN devices d ON d.id = s.device_id WHERE d.revoked_ms IS NULL LIMIT 1",
        [],
        |r| Ok(Subscription { device_id: r.get(0)?, endpoint: r.get(1)?, p256dh: r.get(2)?, auth: r.get(3)? }),
    )
    .optional()
}

// ---------- what the wearer gets told ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notification {
    pub title: String,
    pub body: String,
    /// Same tag replaces the previous notification instead of stacking.
    pub tag: String,
    pub url: String,
}

fn note(kind: &str, title: &str, body: &str) -> Option<Notification> {
    Some(Notification { title: title.into(), body: body.into(), tag: kind.into(), url: "/".into() })
}

/// The notification, if any, that an audit event deserves. Things the wearer did themselves
/// are not notified, and details (such as a rolled timer length) are never included.
pub fn notification_for(kind: &str, actor: &str, message_body: Option<&str>) -> Option<Notification> {
    match kind {
        "unlock_approved" => note(kind, "Unlock approved", "Your keyholder said yes. Open Tether to unlock."),
        "request_denied" => note(kind, "Request denied", "Your keyholder turned down your request."),
        "approval_revoked" => note(kind, "Approval withdrawn", "Your unlock approval is no longer valid."),
        "approval_expired" => note(kind, "Approval expired", "Ask again if you still need to unlock."),
        "timer_ended" => note(kind, "Timer finished", "You can ask to be unlocked now."),
        "timer_set" | "timer_rolled" => note("timer", "Timer started", "Your keyholder started a timer."),
        "timer_paused" => note("timer", "Timer paused", "Your keyholder paused the timer."),
        "timer_resumed" => note("timer", "Timer resumed", "Your keyholder restarted the timer."),
        "timer_cleared" => note("timer", "Timer cleared", "Your keyholder cleared the timer."),
        "command_queued" => note(kind, "Keyholder command waiting", "Open Tether and connect to the pod to apply it."),
        "locked" if actor == "keyholder" => note(kind, "Locked", "Your keyholder locked the pod."),
        "unlocked" if actor == "keyholder" => note(kind, "Unlocked", "Your keyholder unlocked the pod."),
        "message_sent" => {
            let text = message_body.unwrap_or("You have a new message.");
            let text: String = text.chars().take(140).collect();
            Some(Notification { title: "Message from your keyholder".into(), body: text, tag: "message".into(), url: "/".into() })
        }
        _ => None,
    }
}

// ---------- sending ----------

#[derive(Debug, PartialEq, Eq)]
pub enum PushError {
    /// The push service says the subscription no longer exists (404 or 410).
    Gone,
    Other(String),
}

#[async_trait]
pub trait PushSender: Send + Sync {
    async fn send(&self, sub: &Subscription, payload: &[u8]) -> std::result::Result<(), PushError>;
}

pub struct HttpPushSender {
    vapid: Arc<Vapid>,
    contact: String,
    http: reqwest::Client,
}

impl HttpPushSender {
    pub fn new(vapid: Arc<Vapid>, contact: &str) -> Self {
        // No redirects: a push service has no reason to send us anywhere else.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .expect("push http client");
        Self { vapid, contact: contact.to_string(), http }
    }
}

#[async_trait]
impl PushSender for HttpPushSender {
    async fn send(&self, sub: &Subscription, payload: &[u8]) -> std::result::Result<(), PushError> {
        validate(sub).map_err(|e| PushError::Other(e.to_string()))?;
        let other = |e: &dyn std::fmt::Display| PushError::Other(e.to_string());
        let p256dh = PublicKey::from_sec1_bytes(&Base64UrlUnpadded::decode_vec(&sub.p256dh).map_err(|e| other(&e))?).map_err(|e| other(&e))?;
        let auth = Auth::clone_from_slice(&Base64UrlUnpadded::decode_vec(&sub.auth).map_err(|e| other(&e))?);
        let request = WebPushBuilder::new(sub.endpoint.parse().map_err(|e| other(&e))?, p256dh, auth)
            .with_vapid(&self.vapid.pair, &self.contact)
            .build(payload.to_vec())
            .map_err(|e| other(&e))?;
        let (parts, body) = request.into_parts();
        let resp = self.http.post(parts.uri.to_string()).headers(parts.headers).body(body).send().await.map_err(|e| other(&e))?;
        match resp.status().as_u16() {
            200..=299 => Ok(()),
            404 | 410 => Err(PushError::Gone),
            code => Err(PushError::Other(format!("push service answered HTTP {code}"))),
        }
    }
}

// ---------- the worker ----------

/// One pass: persist anything time has changed (a timer ending), then send a
/// notification for each audit event since the last pass. Returns how many were sent.
/// Notifications are at-most-once: the cursor moves on before sending, so a failure
/// loses one notification rather than repeating it.
pub async fn notify_once(st: &AppState, sender: &dyn PushSender) -> usize {
    let batch = api::db(st, |store, _, now| {
        store.apply(now, |_| Ok(Vec::new()))?;
        let conn = store.connection();
        let cursor: Option<i64> = conn.query_row("SELECT last_audit_id FROM push_cursor WHERE id = 1", [], |r| r.get(0)).optional()?;
        let latest = audit::latest_id(conn)?;
        let Some(cursor) = cursor else {
            // First run: start from now rather than announcing history.
            conn.execute("INSERT INTO push_cursor (id, last_audit_id) VALUES (1, ?1)", [latest])?;
            return Ok(None);
        };
        let entries = audit::entries_after(conn, cursor, 50)?;
        let Some(last) = entries.last().map(|e| e.id) else { return Ok(None) };
        conn.execute("UPDATE push_cursor SET last_audit_id = ?1 WHERE id = 1", [last])?;
        let Some(sub) = active_subscription(conn)? else { return Ok(None) };

        let mut notes = Vec::new();
        for e in entries {
            let body = if e.kind == "message_sent" {
                let detail: Value = serde_json::from_str(&e.detail).unwrap_or(Value::Null);
                detail["id"].as_i64().and_then(|id| crate::accounts::message_body(conn, id).ok().flatten())
            } else {
                None
            };
            if let Some(n) = notification_for(&e.kind, &e.actor, body.as_deref()) {
                notes.push(n);
            }
        }
        Ok(Some((sub, notes)))
    })
    .await;

    let Ok(Some((sub, notes))) = batch else { return 0 };
    let mut sent = 0;
    for n in notes {
        let Ok(payload) = serde_json::to_vec(&n) else { continue };
        match sender.send(&sub, &payload).await {
            Ok(()) => sent += 1,
            Err(PushError::Gone) => {
                // The device unsubscribed or was uninstalled: forget it.
                let device = sub.device_id;
                let _ = api::db(st, move |store, _, _| Ok(delete_subscription(store.connection(), device)?)).await;
                break;
            }
            Err(PushError::Other(e)) => eprintln!("push: {e}"),
        }
    }
    sent
}

#[cfg(test)]
mod tests {
    use super::*;
    use web_push_native::p256::SecretKey;

    #[test]
    fn the_vapid_key_is_created_owner_only_and_reloads_identically() {
        let dir = std::env::temp_dir().join(format!("qiui-vapid-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let first = Vapid::load_or_create(&dir).unwrap();
        let again = Vapid::load_or_create(&dir).unwrap();
        assert_eq!(first.public_key(), again.public_key());
        // An uncompressed P-256 point is 65 bytes.
        assert_eq!(Base64UrlUnpadded::decode_vec(first.public_key()).unwrap().len(), 65);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(dir.join("vapid.key")).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    fn good_keys() -> (String, String) {
        let secret = SecretKey::random(&mut web_push_native::p256::elliptic_curve::rand_core::OsRng);
        let public = secret.public_key();
        use web_push_native::p256::elliptic_curve::sec1::ToEncodedPoint;
        (Base64UrlUnpadded::encode_string(public.to_encoded_point(false).as_bytes()), Base64UrlUnpadded::encode_string(&[7u8; 16]))
    }

    fn sub(endpoint: &str) -> Subscription {
        let (p256dh, auth) = good_keys();
        Subscription { device_id: 1, endpoint: endpoint.into(), p256dh, auth }
    }

    #[test]
    fn only_https_urls_on_known_push_services_are_accepted() {
        for ok in ["https://fcm.googleapis.com/fcm/send/abc", "https://updates.push.services.mozilla.com/wpush/v2/x", "https://web.push.apple.com/Qx"] {
            assert_eq!(validate(&sub(ok)), Ok(()), "{ok}");
        }
        for bad in [
            "http://fcm.googleapis.com/x",
            "https://127.0.0.1/x",
            "https://localhost:8443/api/keyholder/state",
            "https://192.168.1.10/x",
            "https://evilgoogleapis.com/x",
            "https://fcm.googleapis.com.evil.example/x",
            "not a url",
        ] {
            assert!(validate(&sub(bad)).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let mut s = sub("https://fcm.googleapis.com/x");
        s.auth = Base64UrlUnpadded::encode_string(&[1u8; 8]);
        assert!(validate(&s).is_err());
        let mut s = sub("https://fcm.googleapis.com/x");
        s.p256dh = "AAAA".into();
        assert!(validate(&s).is_err());
    }

    #[test]
    fn a_push_payload_can_only_be_read_by_the_subscribed_device() {
        let secret = SecretKey::random(&mut web_push_native::p256::elliptic_curve::rand_core::OsRng);
        let auth = Auth::clone_from_slice(&[9u8; 16]);
        let n = Notification { title: "Timer finished".into(), body: "You can ask to be unlocked now.".into(), tag: "timer_ended".into(), url: "/".into() };
        let sealed = web_push_native::encrypt(serde_json::to_vec(&n).unwrap(), &secret.public_key(), &auth).unwrap();
        assert!(!String::from_utf8_lossy(&sealed).contains("Timer finished"), "the payload must be encrypted");
        let opened = web_push_native::decrypt(sealed, &secret, &auth).unwrap();
        let back: Value = serde_json::from_slice(&opened).unwrap();
        assert_eq!(back["title"], "Timer finished");
    }

    #[test]
    fn notifications_cover_what_the_wearer_should_hear_and_nothing_internal() {
        assert_eq!(notification_for("unlock_approved", "keyholder", None).unwrap().title, "Unlock approved");
        assert_eq!(notification_for("timer_ended", "system", None).unwrap().title, "Timer finished");
        let m = notification_for("message_sent", "keyholder", Some("Back at 6.")).unwrap();
        assert_eq!((m.title.as_str(), m.body.as_str()), ("Message from your keyholder", "Back at 6."));
        assert_eq!(notification_for("message_sent", "keyholder", Some(&"x".repeat(500))).unwrap().body.len(), 140);

        // The wearer's own actions and internal events are silent.
        for kind in ["unlock_requested", "request_cancelled", "login", "login_failed", "device_paired", "relay_unlock_issued", "control_lost", "password_reset", "pairing_code_created"] {
            assert!(notification_for(kind, "wearer", None).is_none(), "{kind}");
        }
        assert!(notification_for("unlocked", "wearer", None).is_none());
        assert!(notification_for("unlocked", "keyholder", None).is_some());
        // Timer changes share one tag, so they replace each other rather than stack.
        assert_eq!(notification_for("timer_paused", "keyholder", None).unwrap().tag, notification_for("timer_set", "keyholder", None).unwrap().tag);
    }
}
