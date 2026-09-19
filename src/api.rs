//! HTTP API. Two audiences with separate routes and separate credentials:
//! `/api/keyholder/*` (password login) and `/api/wearer/*` (paired device token).
//! A wearer token is refused on every keyholder route, and every state change
//! goes through `Store::apply`, so the rules in `machine.rs` cannot be bypassed.
//!
//! Lock and unlock over Bluetooth arrive with the BLE layer; this module covers
//! everything decided on the server: requests, approvals, timers, messages,
//! pairing and the audit log.

use std::sync::{Arc, Mutex};

use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::Extension;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::accounts::{self, Auth, AuthError, Principal, Role};
use crate::audit;
use crate::cloud::{CloudError, LazyCloud};
use crate::hardware::{Hardware, Intent, Stage};
use crate::hashgate::{Busy, HashGate, TurnedAway};
use crate::machine::{self, Actor, Machine};
use crate::pod::{PodError, PodOp, PodStatus};
use crate::queue::{self, Command, QueueError, Queued};
use crate::store::{ApplyError, Store};
use crate::timer::Timer;

const MAX_TIMER_SECS: i64 = 365 * 24 * 60 * 60;
const DEFAULT_APPROVAL_MINUTES: i64 = 15;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub auth: Arc<Auth>,
    pub hardware: Arc<Hardware>,
    /// The VAPID public key, when push notifications are set up.
    pub push_key: Option<String>,
    /// The QIUI credentials, if they are stored encrypted: unlocked by the keyholder's sign-in.
    pub vault: Option<Arc<LazyCloud>>,
    /// Where `config.json` lives, so a password change can re-seal the credentials.
    pub config_root: Option<std::path::PathBuf>,
    /// Keeps a flood of password guesses from taking all the memory and CPU. See `hashgate.rs`.
    pub hash_gate: Arc<HashGate>,
    /// Password attempts the gate turned away, counted per route so a flood is never invisible.
    pub turned_away: Arc<TurnedAway>,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl AppState {
    pub fn new(store: Store, auth: Auth, hardware: Hardware) -> Self {
        Self { store: Arc::new(Mutex::new(store)), auth: Arc::new(auth), hardware: Arc::new(hardware), push_key: None, vault: None, config_root: None, hash_gate: Arc::new(HashGate::default()), turned_away: Arc::new(TurnedAway::default()), clock: Arc::new(system_now_ms) }
    }

    pub fn with_push_key(mut self, key: String) -> Self {
        self.push_key = Some(key);
        self
    }

    pub fn with_vault(mut self, vault: Arc<LazyCloud>, config_root: std::path::PathBuf) -> Self {
        self.vault = Some(vault);
        self.config_root = Some(config_root);
        self
    }

    pub(crate) fn now(&self) -> i64 {
        (self.clock)()
    }
}

pub fn system_now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

// ---------- errors ----------

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
    /// Stable machine-readable reason, e.g. "out_of_range", for clients that branch on it.
    code: Option<&'static str>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into(), code: None }
    }

    fn coded(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, message: message.into(), code: Some(code) }
    }

    fn internal(detail: impl std::fmt::Display) -> Self {
        eprintln!("internal error: {detail}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong on the server")
    }

    fn bad_request(message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.message });
        if let Some(code) = self.code {
            body["code"] = code.into();
        }
        (self.status, Json(body)).into_response()
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Invalid => Self::new(StatusCode::UNAUTHORIZED, "That did not match."),
            AuthError::NotInitialised => Self::new(StatusCode::SERVICE_UNAVAILABLE, "The keyholder account has not been set up yet."),
            AuthError::AlreadyInitialised | AuthError::DeviceAlreadyPaired => Self::new(StatusCode::CONFLICT, e.to_string()),
            AuthError::Weak(msg) => Self::bad_request(msg),
            AuthError::Db(err) => Self::internal(err),
            AuthError::Internal => Self::internal("auth"),
        }
    }
}

impl From<machine::Error> for ApiError {
    fn from(e: machine::Error) -> Self {
        let status = match e {
            machine::Error::NotPermitted => StatusCode::FORBIDDEN,
            machine::Error::InvalidDuration | machine::Error::TimerTooLong => StatusCode::BAD_REQUEST,
            _ => StatusCode::CONFLICT,
        };
        Self::new(status, e.to_string())
    }
}

impl From<ApplyError> for ApiError {
    fn from(e: ApplyError) -> Self {
        match e {
            ApplyError::Rule(r) => r.into(),
            ApplyError::Db(d) => Self::internal(d),
        }
    }
}

fn control_lost() -> ApiError {
    ApiError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "control_lost",
        "The pod is no longer under this server's control. Its keyholder has been alerted.",
    )
}

fn busy() -> ApiError {
    ApiError::coded(StatusCode::SERVICE_UNAVAILABLE, "busy", "The server is busy checking passwords. Try again in a moment.")
}

/// The gate was full, so this password attempt was not even checked. Say so in the audit trail: the first
/// after a quiet spell gets its own row at once, and the rest are counted in memory (shown to the keyholder
/// immediately, and folded into the log every few seconds).
async fn turned_away(st: &AppState, route: &'static str) -> ApiError {
    if st.turned_away.note(route) {
        let _ = db(st, move |store, _, now| Ok(store.log_failure(now, "system", route)?)).await;
    }
    busy()
}

fn credentials_locked() -> ApiError {
    ApiError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "credentials_locked",
        "The keyholder needs to sign in once after the server starts before the pod can be controlled.",
    )
}

fn pod_error(e: PodError) -> ApiError {
    match e {
        PodError::Locked => credentials_locked(),
        PodError::NotInRange => ApiError::coded(StatusCode::CONFLICT, "out_of_range", e.to_string()),
        PodError::ControlLost => control_lost(),
        PodError::Timeout => ApiError::coded(StatusCode::GATEWAY_TIMEOUT, "pod_timeout", e.to_string()),
        other => ApiError::coded(StatusCode::BAD_GATEWAY, "pod_error", other.to_string()),
    }
}

fn cloud_error(e: CloudError) -> ApiError {
    match e {
        CloudError::Locked => credentials_locked(),
        CloudError::BoundElsewhere => control_lost(),
        CloudError::Other(m) => ApiError::coded(StatusCode::BAD_GATEWAY, "cloud_error", m),
    }
}

/// Turn a pod failure into a response. Losing control of the pod is written to the audit log.
async fn fail_pod(st: &AppState, e: PodError) -> ApiError {
    if matches!(e, PodError::ControlLost) {
        let _ = db(st, |store, _, now| Ok(store.log(now, "system", "control_lost", &json!({}))?)).await;
    }
    pod_error(e)
}

async fn fail_cloud(st: &AppState, e: CloudError) -> ApiError {
    if e == CloudError::BoundElsewhere {
        let _ = db(st, |store, _, now| Ok(store.log(now, "system", "control_lost", &json!({}))?)).await;
    }
    cloud_error(e)
}

impl From<Busy> for ApiError {
    fn from(_: Busy) -> Self {
        busy()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        Self::internal(e)
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

/// Run database work off the async threads: Argon2 is deliberately slow.
pub(crate) async fn db<T, F>(st: &AppState, f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(&mut Store, &Auth, i64) -> Result<T, ApiError> + Send + 'static,
{
    let st = st.clone();
    tokio::task::spawn_blocking(move || {
        let mut store = st.store.lock().map_err(|_| ApiError::internal("store lock poisoned"))?;
        f(&mut store, &st.auth, st.now())
    })
    .await
    .map_err(|e| ApiError::internal(e))?
}

// ---------- views ----------

fn timer_view(t: &Timer, now: i64) -> Value {
    match *t {
        Timer::Idle => json!({ "kind": "idle" }),
        Timer::Running { ends_at_ms } => {
            json!({ "kind": "running", "ends_at_ms": ends_at_ms, "remaining_ms": (ends_at_ms - now).max(0) })
        }
        Timer::Paused { remaining_ms } => json!({ "kind": "paused", "remaining_ms": remaining_ms }),
        Timer::Ended => json!({ "kind": "ended" }),
    }
}

/// When the pod was last reached and how. Battery is included only if the pod reported one.
fn pod_view(p: Option<(i64, String, Option<i64>)>) -> Value {
    let Some((checked_ms, via, battery)) = p else { return Value::Null };
    let mut v = json!({ "checked_ms": checked_ms, "via": via });
    if let Some(b) = battery {
        v["battery"] = b.into();
    }
    v
}

fn queued_view(q: Option<Queued>) -> Value {
    match q {
        Some(q) => json!({ "command": q.command.as_str(), "queued_ms": q.queued_ms }),
        None => Value::Null,
    }
}

/// `server_time_ms` lets the app count down from the server's clock, not the phone's.
fn state_view(m: &Machine, store: &Store, now: i64) -> Result<Value, ApiError> {
    Ok(json!({
        "server_time_ms": now,
        "lock": m.state.as_str(),
        "approval_expires_ms": m.approval_expires_ms,
        "timer": timer_view(&m.timer, now),
        "unread_messages": accounts::unread_count(store.connection())?,
        "queued_command": queued_view(queue::pending(store.connection())?),
        "pod": pod_view(store.pod_status()?),
    }))
}

/// Apply time first (ending timers, expiring approvals) so a read never shows stale state.
fn current(store: &mut Store, now: i64) -> Result<Machine, ApiError> {
    store.apply(now, |_| Ok(Vec::new()))?;
    Ok(store.machine()?)
}

fn wearer_state(store: &mut Store, now: i64) -> ApiResult {
    let m = current(store, now)?;
    Ok(Json(state_view(&m, store, now)?))
}

fn keyholder_state(store: &mut Store, now: i64) -> ApiResult {
    let m = current(store, now)?;
    let mut view = state_view(&m, store, now)?;
    let devices: Vec<Value> = accounts::list_devices(store.connection())?
        .into_iter()
        .filter(|d| d.revoked_ms.is_none())
        .map(|d| json!({ "id": d.id, "name": d.name, "paired_ms": d.paired_ms, "last_seen_ms": d.last_seen_ms }))
        .collect();
    view["paired_devices"] = Value::Array(devices);
    Ok(Json(view))
}

// ---------- authentication middleware ----------

fn bearer(req: &Request) -> Option<String> {
    req.headers().get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ").map(str::to_owned)
}

async fn authorize(st: AppState, mut req: Request, next: Next, role: Role) -> Result<Response, ApiError> {
    let unauthorised = || ApiError::new(StatusCode::UNAUTHORIZED, "Sign in first.");
    let token = bearer(&req).ok_or_else(unauthorised)?;
    let principal = db(&st, move |store, _, now| Ok(accounts::authenticate(store.connection(), &token, now)?)).await?;
    let principal = principal.ok_or_else(unauthorised)?;
    if principal.role != role {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "This account cannot do that."));
    }
    req.extensions_mut().insert(principal);
    Ok(next.run(req).await)
}

async fn require_keyholder(State(st): State<AppState>, req: Request, next: Next) -> Result<Response, ApiError> {
    authorize(st, req, next, Role::Keyholder).await
}

async fn require_wearer(State(st): State<AppState>, req: Request, next: Next) -> Result<Response, ApiError> {
    authorize(st, req, next, Role::Wearer).await
}

// ---------- public routes ----------

#[derive(Deserialize)]
struct LoginReq {
    password: String,
}

async fn keyholder_login(State(st): State<AppState>, Json(req): Json<LoginReq>) -> ApiResult {
    // 1. The stored hash: quick, under the database lock.
    let hash = db(&st, |store, _, _| Ok(accounts::stored_password_hash(store.connection())?)).await?;

    // 2. The slow check happens off the lock, a couple at a time, so guessing cannot stall anything else.
    //    A right password made under weaker settings is re-hashed here, while it is in hand.
    let (auth, password) = (st.auth.clone(), req.password);
    let checked = st
        .hash_gate
        .run({
            let (auth, password, hash) = (auth.clone(), password.clone(), hash.clone());
            move || {
                let ok = auth.verify_secret(&password, &hash);
                let upgraded = if ok && auth.needs_rehash(&hash) { auth.hash_secret(&password).ok() } else { None };
                (ok, upgraded)
            }
        })
        .await;
    let (ok, upgraded) = match checked {
        Ok(done) => done,
        Err(Busy) => return Err(turned_away(&st, "login_busy").await),
    };
    if !ok {
        db(&st, |store, _, now| Ok(store.log_failure(now, "system", "login_failed")?)).await?;
        return Err(AuthError::Invalid.into());
    }

    // 3. The session and the audit trail: quick, under the lock.
    let token = db(&st, move |store, _, now| {
        if let Some(new_hash) = &upgraded {
            accounts::upgrade_password_hash(store.connection(), new_hash)?;
            store.log(now, "system", "kdf_upgraded", &json!({ "what": "password hash" }))?;
        }
        let token = accounts::start_keyholder_session(store.connection(), now)?;
        store.log(now, "keyholder", "login", &json!({}))?;
        Ok(token)
    })
    .await?;

    // 4. The password is right there: decrypt the QIUI credentials into memory, and strengthen how they are
    //    sealed if they were sealed under older settings. Slow, so also off the lock.
    if let Some(vault) = st.vault.clone() {
        let root = st.config_root.clone();
        let work = st
            .hash_gate
            .run(move || {
                let unlocked = vault.unlock(&auth, &password);
                let upgraded = match (&unlocked, &root) {
                    (Ok(_), Some(root)) => crate::datadir::upgrade_sealed(root, &auth, &password).unwrap_or(false),
                    _ => false,
                };
                (unlocked, upgraded)
            })
            .await;
        if let Ok((unlocked, upgraded)) = work {
            db(&st, move |store, _, now| {
                match unlocked {
                    Ok(true) => store.log(now, "system", "credentials_unlocked", &json!({}))?,
                    Ok(false) => {}
                    Err(e) => store.log(now, "system", "credentials_unlock_failed", &json!({ "error": e.to_string() }))?,
                }
                if upgraded {
                    store.log(now, "system", "kdf_upgraded", &json!({ "what": "sealed credentials" }))?;
                }
                Ok(())
            })
            .await?;
        }
    }
    Ok(Json(json!({ "token": token, "expires_in_secs": accounts::KEYHOLDER_SESSION_MS / 1000 })))
}

#[derive(Deserialize)]
struct PairReq {
    code: String,
    #[serde(default)]
    device_name: String,
}

async fn wearer_pair(State(st): State<AppState>, Json(req): Json<PairReq>) -> ApiResult {
    db(&st, move |store, _, now| match accounts::pair_device(store.connection(), &req.code, &req.device_name, now) {
        Ok(token) => {
            store.log(now, "wearer", "device_paired", &json!({ "name": req.device_name.trim() }))?;
            Ok(Json(json!({ "token": token })))
        }
        Err(AuthError::Invalid) => {
            store.log_failure(now, "system", "pairing_failed")?;
            Err(AuthError::Invalid.into())
        }
        Err(e) => Err(e.into()),
    })
    .await
}

// ---------- wearer routes ----------

async fn wearer_get_state(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| wearer_state(store, now)).await
}

async fn wearer_request_unlock(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| {
        store.apply(now, |m| m.request_unlock(Actor::Wearer, now))?;
        wearer_state(store, now)
    })
    .await
}

async fn wearer_cancel_request(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| {
        store.apply(now, |m| m.cancel_request(Actor::Wearer))?;
        wearer_state(store, now)
    })
    .await
}

fn messages_json(list: Vec<accounts::Message>) -> Value {
    Value::Array(list.into_iter().map(|m| json!({ "id": m.id, "ts_ms": m.ts_ms, "body": m.body, "read": m.read_ms.is_some() })).collect())
}

async fn wearer_messages(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| {
        let list = accounts::list_messages(store.connection(), 100)?;
        let view = messages_json(list);
        accounts::mark_messages_read(store.connection(), now)?;
        Ok(Json(json!({ "messages": view })))
    })
    .await
}

// ---------- keyholder routes ----------

async fn kh_state(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| keyholder_state(store, now)).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ApproveReq {
    ttl_minutes: Option<i64>,
}

async fn kh_approve(State(st): State<AppState>, Json(req): Json<ApproveReq>) -> ApiResult {
    let minutes = req.ttl_minutes.unwrap_or(DEFAULT_APPROVAL_MINUTES);
    if !(1..=240).contains(&minutes) {
        return Err(ApiError::bad_request("ttl_minutes must be between 1 and 240"));
    }
    db(&st, move |store, _, now| {
        store.apply(now, |m| m.approve(Actor::Keyholder, now, minutes * 60_000))?;
        keyholder_state(store, now)
    })
    .await
}

async fn kh_deny(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| {
        store.apply(now, |m| m.deny(Actor::Keyholder))?;
        keyholder_state(store, now)
    })
    .await
}

#[derive(Deserialize)]
struct SetTimerReq {
    duration_secs: i64,
}

async fn kh_timer_set(State(st): State<AppState>, Json(req): Json<SetTimerReq>) -> ApiResult {
    if !(1..=MAX_TIMER_SECS).contains(&req.duration_secs) {
        return Err(ApiError::bad_request("duration_secs must be between 1 second and 365 days"));
    }
    db(&st, move |store, _, now| {
        store.apply(now, |m| m.set_timer(Actor::Keyholder, now, req.duration_secs * 1000))?;
        keyholder_state(store, now)
    })
    .await
}

#[derive(Deserialize)]
struct RollTimerReq {
    min_secs: i64,
    max_secs: i64,
}

async fn kh_timer_roll(State(st): State<AppState>, Json(req): Json<RollTimerReq>) -> ApiResult {
    if req.min_secs < 1 || req.min_secs > req.max_secs || req.max_secs > MAX_TIMER_SECS {
        return Err(ApiError::bad_request("need 1 <= min_secs <= max_secs <= 365 days"));
    }
    db(&st, move |store, _, now| {
        let span = (req.max_secs - req.min_secs + 1) as u64;
        let chosen = req.min_secs + accounts::random_below(span) as i64;
        let (min_ms, max_ms) = (req.min_secs * 1000, req.max_secs * 1000);
        store.apply(now, |m| m.roll_timer(Actor::Keyholder, now, min_ms, max_ms, chosen * 1000))?;
        // The keyholder may see what was rolled; the wearer's view never includes it.
        let mut view = keyholder_state(store, now)?;
        view.0["rolled_secs"] = chosen.into();
        Ok(view)
    })
    .await
}

#[derive(Deserialize)]
struct AddTimerReq {
    duration_secs: i64,
}

async fn kh_timer_add(State(st): State<AppState>, Json(req): Json<AddTimerReq>) -> ApiResult {
    if !(1..=MAX_TIMER_SECS).contains(&req.duration_secs) {
        return Err(ApiError::bad_request("duration_secs must be between 1 second and 365 days"));
    }
    db(&st, move |store, _, now| {
        store.apply(now, |m| m.extend_timer(Actor::Keyholder, now, req.duration_secs * 1000))?;
        keyholder_state(store, now)
    })
    .await
}

async fn kh_timer_add_roll(State(st): State<AppState>, Json(req): Json<RollTimerReq>) -> ApiResult {
    if req.min_secs < 1 || req.min_secs > req.max_secs || req.max_secs > MAX_TIMER_SECS {
        return Err(ApiError::bad_request("need 1 <= min_secs <= max_secs <= 365 days"));
    }
    db(&st, move |store, _, now| {
        let span = (req.max_secs - req.min_secs + 1) as u64;
        let chosen = req.min_secs + accounts::random_below(span) as i64;
        let (min_ms, max_ms) = (req.min_secs * 1000, req.max_secs * 1000);
        store.apply(now, |m| m.extend_timer_roll(Actor::Keyholder, now, min_ms, max_ms, chosen * 1000))?;
        let mut view = keyholder_state(store, now)?;
        view.0["rolled_secs"] = chosen.into();
        Ok(view)
    })
    .await
}

async fn kh_timer_pause(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| {
        store.apply(now, |m| m.pause_timer(Actor::Keyholder, now))?;
        keyholder_state(store, now)
    })
    .await
}

async fn kh_timer_resume(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| {
        store.apply(now, |m| m.resume_timer(Actor::Keyholder, now))?;
        keyholder_state(store, now)
    })
    .await
}

async fn kh_timer_clear(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| {
        store.apply(now, |m| m.clear_timer(Actor::Keyholder))?;
        keyholder_state(store, now)
    })
    .await
}

#[derive(Deserialize)]
struct MessageReq {
    body: String,
}

async fn kh_message(State(st): State<AppState>, Json(req): Json<MessageReq>) -> ApiResult {
    db(&st, move |store, _, now| {
        let id = accounts::add_message(store.connection(), &req.body, now)?;
        store.log(now, "keyholder", "message_sent", &json!({ "id": id }))?;
        Ok(Json(json!({ "id": id })))
    })
    .await
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<u32>,
}

async fn kh_audit(State(st): State<AppState>, Query(q): Query<AuditQuery>) -> ApiResult {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let in_memory = st.turned_away.peek_extra();
    db(&st, move |store, _, _| {
        let conn = store.connection();
        let intact = audit::verify(conn)?.is_none();
        let entries: Vec<Value> = audit::entries(conn, limit)?
            .into_iter()
            .map(|e| {
                let detail: Value = serde_json::from_str(&e.detail).unwrap_or(Value::Null);
                json!({ "id": e.id, "ts_ms": e.ts_ms, "actor": e.actor, "kind": e.kind, "detail": detail })
            })
            .collect();
        // Failures folded into the next row are shown here at once, so a burst is never hidden by summarising.
        let mut counts = accounts::pending_failures(conn)?;
        // Attempts turned away since the last fold into the database are added on top, so nothing is behind.
        for (route, n) in in_memory {
            let key = format!("system:{route}");
            match counts.iter_mut().find(|p| p.actor == "system" && p.kind == route) {
                Some(p) => p.count += n as i64,
                None => {
                    let since_ms = accounts::failure_window_start(conn, &key)?.unwrap_or_default();
                    counts.push(accounts::PendingFailure { actor: "system".into(), kind: route.into(), count: n as i64, since_ms });
                }
            }
        }
        let pending: Vec<Value> =
            counts.into_iter().map(|p| json!({ "actor": p.actor, "kind": p.kind, "count": p.count, "since_ms": p.since_ms })).collect();
        Ok(Json(json!({ "chain_intact": intact, "entries": entries, "pending_failures": pending })))
    })
    .await
}

async fn kh_pairing_code(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| {
        let code = accounts::create_pairing_code(store.connection(), now)?;
        store.log(now, "keyholder", "pairing_code_created", &json!({}))?;
        Ok(Json(json!({ "code": code, "expires_ms": now + accounts::PAIRING_CODE_TTL_MS })))
    })
    .await
}

async fn kh_devices(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, _| {
        let devices: Vec<Value> = accounts::list_devices(store.connection())?
            .into_iter()
            .map(|d| json!({ "id": d.id, "name": d.name, "paired_ms": d.paired_ms, "last_seen_ms": d.last_seen_ms, "revoked_ms": d.revoked_ms }))
            .collect();
        Ok(Json(json!({ "devices": devices })))
    })
    .await
}

async fn kh_revoke_device(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    db(&st, move |store, _, now| {
        if !accounts::revoke_device(store.connection(), id, now)? {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "No active device with that id."));
        }
        store.log(now, "keyholder", "device_revoked", &json!({ "id": id }))?;
        Ok(Json(json!({ "revoked": id })))
    })
    .await
}

#[derive(Deserialize)]
struct PasswordReq {
    current_password: String,
    new_password: String,
}

async fn kh_change_password(State(st): State<AppState>, Json(req): Json<PasswordReq>) -> ApiResult {
    // Cheap check first, so a too-short password never costs a hash.
    accounts::check_password(&req.new_password)?;

    // Every slow step is off the database lock and goes through the gate.
    let hash = db(&st, |store, _, _| Ok(accounts::stored_password_hash(store.connection())?)).await?;
    let auth = st.auth.clone();
    let current_ok = match st
        .hash_gate
        .run({
            let (auth, current) = (auth.clone(), req.current_password.clone());
            move || auth.verify_secret(&current, &hash)
        })
        .await
    {
        Ok(ok) => ok,
        Err(Busy) => return Err(turned_away(&st, "password_change_busy").await),
    };
    if !current_ok {
        db(&st, |store, _, now| Ok(store.log_failure(now, "system", "password_change_failed")?)).await?;
        return Err(AuthError::Invalid.into());
    }
    let new_hash = st
        .hash_gate
        .run({
            let (auth, new) = (auth.clone(), req.new_password.clone());
            move || auth.hash_secret(&new)
        })
        .await??;
    db(&st, move |store, _, now| {
        accounts::replace_password_hash(store.connection(), &new_hash, now)?;
        store.log(now, "keyholder", "password_changed", &json!({}))?;
        Ok(())
    })
    .await?;

    // The sealed QIUI credentials are keyed to the password, so they must move to the new one.
    let credentials = match st.config_root.clone() {
        None => "none",
        Some(root) => {
            let (current, new) = (req.current_password, req.new_password);
            let outcome = st.hash_gate.run(move || crate::datadir::reseal_config(&root, &auth, &current, &new)).await?;
            match outcome {
                Ok(true) => "resealed",
                Ok(false) => "none",
                Err(e) => {
                    let error = e.to_string();
                    db(&st, move |store, _, now| Ok(store.log(now, "system", "credentials_reseal_failed", &json!({ "error": error }))?)).await?;
                    "failed"
                }
            }
        }
    };
    let note = if credentials == "failed" {
        "The password was changed, but the QIUI credentials could not be re-encrypted. Run `qiui-server config set-client-id` again."
    } else {
        "All sessions were signed out. Sign in again."
    };
    Ok(Json(json!({ "changed": true, "credentials": credentials, "note": note })))
}

async fn kh_logout(State(st): State<AppState>, req: Request) -> ApiResult {
    let token = bearer(&req).unwrap_or_default();
    db(&st, move |store, _, now| {
        accounts::logout(store.connection(), &token, now)?;
        Ok(Json(json!({ "signed_out": true })))
    })
    .await
}


// ---------- pod control: server Bluetooth ----------

/// Check the rules first (this also applies time), talk to the pod, then record what happened.
async fn server_unlock(st: &AppState, actor: Actor) -> ApiResult {
    db(st, move |store, _, now| {
        store.apply(now, |m| m.check_unlock(actor, now).map(|()| Vec::new()))?;
        Ok(())
    })
    .await?;
    let status = st.hardware.direct(PodOp::Unlock).await;
    finish_direct(st, actor, PodOp::Unlock, status).await
}

async fn server_lock(st: &AppState, actor: Actor) -> ApiResult {
    db(st, move |store, _, now| {
        store.apply(now, |m| m.check_lock(actor).map(|()| Vec::new()))?;
        Ok(())
    })
    .await?;
    let status = st.hardware.direct(PodOp::Lock).await;
    finish_direct(st, actor, PodOp::Lock, status).await
}

async fn finish_direct(st: &AppState, actor: Actor, op: PodOp, result: Result<PodStatus, PodError>) -> ApiResult {
    let status = match result {
        Ok(s) => s,
        Err(e) => return Err(fail_pod(st, e).await),
    };
    db(st, move |store, _, now| {
        store.apply(now, |m| {
            Ok(match op {
                PodOp::Unlock => m.record_unlocked(actor, "server"),
                _ => m.record_locked(actor, "server"),
            })
        })?;
        store.save_pod_status(now, "server", status.battery)?;
        state_for(store, actor, now)
    })
    .await
}

fn state_for(store: &mut Store, actor: Actor, now: i64) -> ApiResult {
    if actor == Actor::Keyholder { keyholder_state(store, now) } else { wearer_state(store, now) }
}

/// Refresh what we know about the pod. Out of range is an answer, not an error.
async fn server_sync(st: &AppState, actor: Actor) -> ApiResult {
    if actor == Actor::Wearer && !st.hardware.sync_due(st.now()) {
        return db(st, move |store, _, now| {
            let mut view = state_for(store, actor, now)?;
            view.0["in_range"] = Value::Null;
            view.0["cooldown"] = true.into();
            Ok(view)
        })
        .await;
    }
    let (in_range, battery) = match st.hardware.direct(PodOp::Status).await {
        Ok(status) => (true, Some(status.battery)),
        Err(PodError::NotInRange) => (false, None),
        Err(e) => return Err(fail_pod(st, e).await),
    };
    db(st, move |store, _, now| {
        if let Some(b) = battery {
            store.save_pod_status(now, "server", b)?;
        }
        let mut view = state_for(store, actor, now)?;
        view.0["in_range"] = in_range.into();
        view.0["cooldown"] = false.into();
        Ok(view)
    })
    .await
}

async fn wearer_unlock(State(st): State<AppState>) -> ApiResult {
    server_unlock(&st, Actor::Wearer).await
}

async fn wearer_lock(State(st): State<AppState>) -> ApiResult {
    server_lock(&st, Actor::Wearer).await
}

async fn wearer_sync(State(st): State<AppState>) -> ApiResult {
    server_sync(&st, Actor::Wearer).await
}

async fn kh_unlock(State(st): State<AppState>) -> ApiResult {
    server_unlock(&st, Actor::Keyholder).await
}

async fn kh_lock(State(st): State<AppState>) -> ApiResult {
    server_lock(&st, Actor::Keyholder).await
}

async fn kh_sync(State(st): State<AppState>) -> ApiResult {
    server_sync(&st, Actor::Keyholder).await
}

/// Write the summary rows for runs of failed attempts whose window has closed. The server calls this every
/// few seconds, so a burst of guesses is recorded even when nothing else fails afterwards.
pub async fn flush_failure_summaries(st: &AppState) -> usize {
    let extra = st.turned_away.take_extra();
    db(st, move |store, _, now| {
        for (route, n) in extra {
            accounts::add_pending_failures(store.connection(), &format!("system:{route}"), n as i64, now)?;
        }
        Ok(store.flush_failures(now)?)
    })
    .await
    .unwrap_or(0)
}

/// Write an event that has no request behind it (background workers).
pub async fn audit_event(st: &AppState, actor: &'static str, kind: &'static str, detail: Value) {
    let _ = db(st, move |store, _, now| Ok(store.log(now, actor, kind, &detail)?)).await;
}

// ---------- keyholder's queue ----------

#[derive(Deserialize)]
struct QueueReq {
    command: String,
}

async fn kh_queue(State(st): State<AppState>, Json(req): Json<QueueReq>) -> ApiResult {
    let command = Command::parse(&req.command).ok_or_else(|| ApiError::bad_request("command must be \"lock\" or \"unlock\""))?;
    db(&st, move |store, _, now| {
        match queue::enqueue(store.connection(), command, now) {
            Ok(id) => store.log(now, "keyholder", "command_queued", &json!({ "id": id, "command": command.as_str() }))?,
            Err(QueueError::AlreadyPending) => return Err(ApiError::new(StatusCode::CONFLICT, QueueError::AlreadyPending.to_string())),
            Err(QueueError::Db(e)) => return Err(e.into()),
        }
        keyholder_state(store, now)
    })
    .await
}

async fn kh_queue_cancel(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, now| {
        let Some(q) = queue::cancel(store.connection(), now)? else {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "Nothing is queued."));
        };
        store.log(now, "keyholder", "command_cancelled", &json!({ "id": q.id, "command": q.command.as_str() }))?;
        keyholder_state(store, now)
    })
    .await
}

/// Try the keyholder's queued command over the server's Bluetooth. Returns true if it ran.
/// Called on a timer; the rules are checked again now, so a queued unlock is dropped if a
/// timer has started since.
pub async fn run_queue_once(st: &AppState) -> bool {
    let checked = db(st, |store, _, now| {
        store.apply(now, |_| Ok(Vec::new()))?;
        let Some(q) = queue::pending(store.connection())? else { return Ok(None) };
        let m = store.machine()?;
        let allowed = match q.command {
            Command::Unlock => m.check_unlock(Actor::Keyholder, now),
            Command::Lock => m.check_lock(Actor::Keyholder),
        };
        if let Err(reason) = allowed {
            queue::finish(store.connection(), q.id, now, &format!("dropped: {reason}"))?;
            store.log(now, "system", "queued_command_dropped", &json!({ "command": q.command.as_str(), "reason": reason.to_string() }))?;
            return Ok(None);
        }
        Ok(Some(q))
    })
    .await;
    let Ok(Some(q)) = checked else { return false };

    let op = if q.command == Command::Unlock { PodOp::Unlock } else { PodOp::Lock };
    let Ok(status) = st.hardware.direct(op).await else { return false };
    db(st, move |store, _, now| {
        store.apply(now, |m| {
            Ok(if op == PodOp::Unlock { m.record_unlocked(Actor::Keyholder, "server") } else { m.record_locked(Actor::Keyholder, "server") })
        })?;
        queue::finish(store.connection(), q.id, now, "done via server")?;
        store.log(now, "system", "queued_command_done", &json!({ "command": q.command.as_str(), "via": "server" }))?;
        store.save_pod_status(now, "server", status.battery)?;
        Ok(true)
    })
    .await
    .unwrap_or(false)
}

// ---------- pod control: the wearer's phone relays Bluetooth ----------
//
// The phone only carries bytes. The server tells it what to write next, and it
// mints an unlock or lock command only after the pod's handshake reply has been
// decoded AND the rules still allow the action.

#[derive(Deserialize)]
struct RelayStartReq {
    intent: String,
}

#[derive(Deserialize)]
struct RelayReplyReq {
    session_id: String,
    hex: String,
}

fn device_id(p: &Principal) -> Result<i64, ApiError> {
    p.device_id.ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "This account cannot do that."))
}

fn valid_hex(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The rule that must hold for this intent, evaluated against the current state.
fn intent_allowed(store: &mut Store, intent: Intent, now: i64) -> Result<(), ApiError> {
    let m = current(store, now)?;
    match intent {
        Intent::Status => {}
        Intent::Unlock => m.check_unlock(Actor::Wearer, now)?,
        Intent::Lock => m.check_lock(Actor::Wearer)?,
        Intent::Queued { command, queue_id } => {
            match queue::pending(store.connection())? {
                Some(q) if q.id == queue_id => {}
                _ => return Err(ApiError::new(StatusCode::CONFLICT, "That queued command is no longer pending.")),
            }
            match command {
                Command::Unlock => m.check_unlock(Actor::Keyholder, now)?,
                Command::Lock => m.check_lock(Actor::Keyholder)?,
            }
        }
    }
    Ok(())
}

fn actor_for(intent: Intent) -> Actor {
    if matches!(intent, Intent::Queued { .. }) { Actor::Keyholder } else { Actor::Wearer }
}

fn is_unlock(intent: Intent) -> bool {
    matches!(intent, Intent::Unlock | Intent::Queued { command: Command::Unlock, .. })
}

async fn relay_start(State(st): State<AppState>, Extension(p): Extension<Principal>, Json(req): Json<RelayStartReq>) -> ApiResult {
    let device = device_id(&p)?;
    let intent = db(&st, move |store, _, now| {
        let intent = match req.intent.as_str() {
            "status" => Intent::Status,
            "unlock" => Intent::Unlock,
            "lock" => Intent::Lock,
            "queued" => {
                let q = queue::pending(store.connection())?.ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "Nothing is queued."))?;
                Intent::Queued { command: q.command, queue_id: q.id }
            }
            _ => return Err(ApiError::bad_request("intent must be status, unlock, lock or queued")),
        };
        intent_allowed(store, intent, now)?;
        Ok(intent)
    })
    .await?;

    let cmd = match st.hardware.cloud.device_token_cmd().await {
        Ok(c) => c,
        Err(e) => return Err(fail_cloud(&st, e).await),
    };
    let session_id = st.hardware.start_relay(device, intent, st.now());
    Ok(Json(json!({ "session_id": session_id, "cmd": cmd })))
}

async fn relay_reply(State(st): State<AppState>, Extension(p): Extension<Principal>, Json(req): Json<RelayReplyReq>) -> ApiResult {
    let device = device_id(&p)?;
    if !valid_hex(&req.hex) {
        return Err(ApiError::bad_request("hex must be an even number of hexadecimal digits"));
    }
    let gone = || ApiError::coded(StatusCode::GONE, "relay_expired", "That Bluetooth session has expired. Start again.");
    let relay = st.hardware.relay(&req.session_id, device, st.now()).ok_or_else(gone)?;

    let status = match st.hardware.cloud.decrypt_reply(&req.hex).await {
        Ok(s) => s,
        Err(e) => {
            st.hardware.end_relay(&req.session_id);
            return Err(fail_cloud(&st, e).await);
        }
    };

    match relay.stage {
        Stage::Handshake => handshake_reply(&st, &req.session_id, device, relay.intent, status).await,
        Stage::Command => command_reply(&st, &req.session_id, relay.intent, status).await,
    }
}

async fn handshake_reply(st: &AppState, id: &str, device: i64, intent: Intent, status: PodStatus) -> ApiResult {
    if intent == Intent::Status {
        st.hardware.end_relay(id);
        return db(st, move |store, _, now| {
            store.save_pod_status(now, "phone", status.battery)?;
            let mut view = wearer_state(store, now)?;
            view.0["done"] = true.into();
            Ok(view)
        })
        .await;
    }

    // The action may have stopped being allowed while the phone was connecting.
    let allowed = db(st, move |store, _, now| intent_allowed(store, intent, now)).await;
    if let Err(e) = allowed {
        st.hardware.end_relay(id);
        return Err(e);
    }

    let minted = if is_unlock(intent) { st.hardware.cloud.unlock_cmd().await } else { st.hardware.cloud.lock_cmd().await };
    let cmd = match minted {
        Ok(c) => c,
        Err(e) => {
            st.hardware.end_relay(id);
            return Err(fail_cloud(st, e).await);
        }
    };
    if is_unlock(intent) {
        // The unlock bytes are now on the wearer's phone. Say so in the log.
        db(st, move |store, _, now| Ok(store.log(now, "system", "relay_unlock_issued", &json!({ "device_id": device }))?)).await?;
    }
    st.hardware.advance_relay(id);
    Ok(Json(json!({ "done": false, "cmd": cmd })))
}

async fn command_reply(st: &AppState, id: &str, intent: Intent, status: PodStatus) -> ApiResult {
    st.hardware.end_relay(id);
    let expected = if is_unlock(intent) { "02" } else { "03" };
    if status.comment_type != expected {
        return Err(ApiError::coded(StatusCode::BAD_GATEWAY, "pod_error", PodError::Unexpected.to_string()));
    }
    let actor = actor_for(intent);
    db(st, move |store, _, now| {
        store.apply(now, |m| {
            Ok(if is_unlock(intent) { m.record_unlocked(actor, "phone") } else { m.record_locked(actor, "phone") })
        })?;
        if let Intent::Queued { command, queue_id } = intent {
            queue::finish(store.connection(), queue_id, now, "done via phone")?;
            store.log(now, "system", "queued_command_done", &json!({ "command": command.as_str(), "via": "phone" }))?;
        }
        store.save_pod_status(now, "phone", status.battery)?;
        let mut view = wearer_state(store, now)?;
        view.0["done"] = true.into();
        Ok(view)
    })
    .await
}


// ---------- wearer: activity and push ----------

/// What the wearer may see of the audit log: their own lock's story, never the keyholder's
/// internals. Only the actor and how the pod was reached are exposed; no details, so a
/// rolled timer's length can never leak through here.
const ACTIVITY_KINDS: [&str; 21] = [
    "unlock_requested",
    "request_cancelled",
    "request_denied",
    "unlock_approved",
    "approval_revoked",
    "approval_expired",
    "unlocked",
    "locked",
    "timer_set",
    "timer_rolled",
    "timer_extended",
    "timer_extension_rolled",
    "timer_paused",
    "timer_resumed",
    "timer_cleared",
    "timer_ended",
    "command_queued",
    "command_cancelled",
    "queued_command_done",
    "queued_command_dropped",
    "message_sent",
];

async fn wearer_activity(State(st): State<AppState>) -> ApiResult {
    db(&st, |store, _, _| {
        let entries: Vec<Value> = audit::entries(store.connection(), 400)?
            .into_iter()
            .filter(|e| ACTIVITY_KINDS.contains(&e.kind.as_str()))
            .take(60)
            .map(|e| {
                let via = serde_json::from_str::<Value>(&e.detail).ok().and_then(|d| d["via"].as_str().map(str::to_owned));
                json!({ "id": e.id, "ts_ms": e.ts_ms, "kind": e.kind, "by": e.actor, "via": via })
            })
            .collect();
        Ok(Json(json!({ "activity": entries })))
    })
    .await
}

async fn push_key(State(st): State<AppState>) -> ApiResult {
    match &st.push_key {
        Some(k) => Ok(Json(json!({ "public_key": k }))),
        None => Err(ApiError::coded(StatusCode::NOT_FOUND, "push_unavailable", "Notifications are not set up on this server.")),
    }
}

#[derive(Deserialize)]
struct PushKeys {
    p256dh: String,
    auth: String,
}

#[derive(Deserialize)]
struct PushSubscribeReq {
    endpoint: String,
    keys: PushKeys,
}

async fn push_subscribe(State(st): State<AppState>, Extension(p): Extension<Principal>, Json(req): Json<PushSubscribeReq>) -> ApiResult {
    let sub = crate::push::Subscription { device_id: device_id(&p)?, endpoint: req.endpoint, p256dh: req.keys.p256dh, auth: req.keys.auth };
    crate::push::validate(&sub).map_err(ApiError::bad_request)?;
    db(&st, move |store, _, now| {
        crate::push::save_subscription(store.connection(), &sub, now)?;
        store.log(now, "wearer", "push_subscribed", &json!({}))?;
        Ok(Json(json!({ "subscribed": true })))
    })
    .await
}

async fn push_unsubscribe(State(st): State<AppState>, Extension(p): Extension<Principal>) -> ApiResult {
    let device = device_id(&p)?;
    db(&st, move |store, _, now| {
        crate::push::delete_subscription(store.connection(), device)?;
        store.log(now, "wearer", "push_unsubscribed", &json!({}))?;
        Ok(Json(json!({ "subscribed": false })))
    })
    .await
}

// ---------- router ----------

pub fn router(state: AppState) -> Router {
    let keyholder = Router::new()
        .route("/api/keyholder/state", get(kh_state))
        .route("/api/keyholder/approve", post(kh_approve))
        .route("/api/keyholder/deny", post(kh_deny))
        .route("/api/keyholder/timer", post(kh_timer_set))
        .route("/api/keyholder/timer/roll", post(kh_timer_roll))
        .route("/api/keyholder/timer/add", post(kh_timer_add))
        .route("/api/keyholder/timer/add-roll", post(kh_timer_add_roll))
        .route("/api/keyholder/timer/pause", post(kh_timer_pause))
        .route("/api/keyholder/timer/resume", post(kh_timer_resume))
        .route("/api/keyholder/timer/clear", post(kh_timer_clear))
        .route("/api/keyholder/messages", post(kh_message))
        .route("/api/keyholder/audit", get(kh_audit))
        .route("/api/keyholder/pairing-code", post(kh_pairing_code))
        .route("/api/keyholder/devices", get(kh_devices))
        .route("/api/keyholder/devices/{id}/revoke", post(kh_revoke_device))
        .route("/api/keyholder/password", post(kh_change_password))
        .route("/api/keyholder/logout", post(kh_logout))
        .route("/api/keyholder/unlock", post(kh_unlock))
        .route("/api/keyholder/lock", post(kh_lock))
        .route("/api/keyholder/sync", post(kh_sync))
        .route("/api/keyholder/queue", post(kh_queue))
        .route("/api/keyholder/queue/cancel", post(kh_queue_cancel))
        .layer(middleware::from_fn_with_state(state.clone(), require_keyholder));

    let wearer = Router::new()
        .route("/api/wearer/state", get(wearer_get_state))
        .route("/api/wearer/request-unlock", post(wearer_request_unlock))
        .route("/api/wearer/cancel-request", post(wearer_cancel_request))
        .route("/api/wearer/messages", get(wearer_messages))
        .route("/api/wearer/unlock", post(wearer_unlock))
        .route("/api/wearer/lock", post(wearer_lock))
        .route("/api/wearer/sync", post(wearer_sync))
        .route("/api/wearer/relay/start", post(relay_start))
        .route("/api/wearer/relay/reply", post(relay_reply))
        .route("/api/wearer/activity", get(wearer_activity))
        .route("/api/wearer/push/key", get(push_key))
        .route("/api/wearer/push/subscribe", post(push_subscribe))
        .route("/api/wearer/push/unsubscribe", post(push_unsubscribe))
        .layer(middleware::from_fn_with_state(state.clone(), require_wearer));

    let api = Router::new()
        .route("/api/keyholder/login", post(keyholder_login))
        .route("/api/wearer/pair", post(wearer_pair))
        .merge(keyholder)
        .merge(wearer)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::map_response(|mut r: Response| async move {
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }));

    // Everything that is not an API route is the wearer's web app (or a 404).
    Router::new().merge(api).fallback(crate::web::serve).layer(middleware::map_response(security_headers)).with_state(state)
}

async fn security_headers(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(crate::web::CONTENT_SECURITY_POLICY));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert("permissions-policy", HeaderValue::from_static("bluetooth=(self), camera=(), microphone=(), geolocation=()"));
    r
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::fakes::{FakeCloud, FakePod, FakeSender};

    const PW: &str = "correct horse battery";
    const PIN: &str = "482913";
    const MIN: i64 = 60_000;
    const HOUR: i64 = 60 * MIN;

    struct Harness {
        app: Router,
        now: Arc<AtomicI64>,
        pod: Arc<FakePod>,
        cloud: Arc<FakeCloud>,
        state: AppState,
    }

    fn harness() -> Harness {
        let store = Store::open_in_memory().unwrap();
        let auth = Auth::for_tests(b"api test pepper");
        accounts::init_keyholder(store.connection(), &auth, PW, PIN).unwrap();
        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let pod = Arc::new(FakePod::default());
        let cloud = Arc::new(FakeCloud::default());
        let mut state = AppState::new(store, auth, Hardware::new(cloud.clone(), pod.clone()));
        state.clock = Arc::new(move || clock.load(Ordering::SeqCst));
        Harness { app: router(state.clone()), now, pod, cloud, state }
    }

    impl Harness {
        fn advance(&self, ms: i64) {
            self.now.fetch_add(ms, Ordering::SeqCst);
        }

        async fn call(&self, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
            let mut req = Request::builder().method(method).uri(path);
            if let Some(t) = token {
                req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
            }
            let body = match body {
                Some(b) => {
                    req = req.header(header::CONTENT_TYPE, "application/json");
                    Body::from(b.to_string())
                }
                None => Body::empty(),
            };
            let resp = self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
        }

        async fn keyholder(&self) -> String {
            let (s, v) = self.call("POST", "/api/keyholder/login", None, Some(json!({ "password": PW }))).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            v["token"].as_str().unwrap().to_string()
        }

        async fn wearer(&self, kh: &str) -> String {
            let (_, v) = self.call("POST", "/api/keyholder/pairing-code", Some(kh), None).await;
            let code = v["code"].as_str().unwrap().to_string();
            let (s, v) = self.call("POST", "/api/wearer/pair", None, Some(json!({ "code": code, "device_name": "Pixel" }))).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            v["token"].as_str().unwrap().to_string()
        }
    }

    #[tokio::test]
    async fn request_approve_flow_with_the_wearer_seeing_each_step() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        let (_, s) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(s["lock"], "locked");
        assert!(s["server_time_ms"].as_i64().unwrap() > 0);

        let (st, s) = h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        assert_eq!((st, s["lock"].as_str()), (StatusCode::OK, Some("requested")));

        let (st, s) = h.call("POST", "/api/keyholder/approve", Some(&kh), Some(json!({ "ttl_minutes": 10 }))).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(s["lock"], "approved");
        assert_eq!(s["approval_expires_ms"].as_i64().unwrap(), 1_000_000 + 10 * MIN);

        let (_, s) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(s["lock"], "approved");

        // The approval lapses on its own; the wearer's next read shows it.
        h.advance(10 * MIN);
        let (_, s) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(s["lock"], "locked");
    }

    #[tokio::test]
    async fn wearer_tokens_are_refused_on_every_keyholder_route_and_anonymous_calls_are_refused_everywhere() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        let keyholder_routes = [
            ("GET", "/api/keyholder/state"),
            ("POST", "/api/keyholder/approve"),
            ("POST", "/api/keyholder/deny"),
            ("POST", "/api/keyholder/timer"),
            ("POST", "/api/keyholder/timer/roll"),
            ("POST", "/api/keyholder/timer/add"),
            ("POST", "/api/keyholder/timer/add-roll"),
            ("POST", "/api/keyholder/timer/pause"),
            ("POST", "/api/keyholder/timer/resume"),
            ("POST", "/api/keyholder/timer/clear"),
            ("POST", "/api/keyholder/messages"),
            ("GET", "/api/keyholder/audit"),
            ("POST", "/api/keyholder/pairing-code"),
            ("GET", "/api/keyholder/devices"),
            ("POST", "/api/keyholder/devices/1/revoke"),
            ("POST", "/api/keyholder/password"),
            ("POST", "/api/keyholder/logout"),
            ("POST", "/api/keyholder/unlock"),
            ("POST", "/api/keyholder/lock"),
            ("POST", "/api/keyholder/sync"),
            ("POST", "/api/keyholder/queue"),
            ("POST", "/api/keyholder/queue/cancel"),
        ];
        for (method, path) in keyholder_routes {
            let (s, _) = h.call(method, path, Some(&w), Some(json!({}))).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "wearer token on {method} {path}");
            let (s, _) = h.call(method, path, None, Some(json!({}))).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "no token on {method} {path}");
            let (s, _) = h.call(method, path, Some("0000"), Some(json!({}))).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "junk token on {method} {path}");
        }
        // And the keyholder token is not a wearer token, on any wearer route.
        for (method, path) in [
            ("GET", "/api/wearer/state"),
            ("POST", "/api/wearer/unlock"),
            ("POST", "/api/wearer/lock"),
            ("POST", "/api/wearer/sync"),
            ("POST", "/api/wearer/relay/start"),
            ("POST", "/api/wearer/relay/reply"),
            ("GET", "/api/wearer/activity"),
            ("GET", "/api/wearer/push/key"),
            ("POST", "/api/wearer/push/subscribe"),
            ("POST", "/api/wearer/push/unsubscribe"),
        ] {
            let (s, _) = h.call(method, path, Some(&kh), Some(json!({}))).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "keyholder token on {method} {path}");
        }
        assert!(h.pod.ops().is_empty(), "nothing the wearer tried may have touched the pod");
        assert!(h.cloud.calls().is_empty());

        // Nothing the wearer tried changed the lock.
        let (_, s) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert_eq!(s["lock"], "locked");
        assert_eq!(s["timer"]["kind"], "idle");
    }

    #[tokio::test]
    async fn timer_blocks_requests_then_reopens_them_but_never_unlocks() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        let (s, v) = h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 2 * 3600 }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["timer"]["kind"], "running");

        let (_, ws) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(ws["timer"]["remaining_ms"].as_i64().unwrap(), 2 * HOUR);
        assert!(ws.get("rolled_secs").is_none());

        let (s, _) = h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        assert_eq!(s, StatusCode::CONFLICT);

        h.advance(2 * HOUR);
        let (_, ws) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(ws["timer"]["kind"], "ended");
        assert_eq!(ws["lock"], "locked");

        let (s, ws) = h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        assert_eq!((s, ws["lock"].as_str()), (StatusCode::OK, Some("requested")));
    }

    #[tokio::test]
    async fn keyholder_cannot_approve_under_a_running_timer_but_can_after_clearing_it() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        // Starting a timer revokes the pending request, so the wearer must ask again later.
        h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 3600 }))).await;
        let (_, v) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert_eq!(v["lock"], "locked");

        let (s, _) = h.call("POST", "/api/keyholder/approve", Some(&kh), Some(json!({}))).await;
        assert_eq!(s, StatusCode::CONFLICT);

        h.call("POST", "/api/keyholder/timer/pause", Some(&kh), None).await;
        let (s, _) = h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        assert_eq!(s, StatusCode::CONFLICT, "a paused timer still blocks requests");

        h.call("POST", "/api/keyholder/timer/clear", Some(&kh), None).await;
        let (s, _) = h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = h.call("POST", "/api/keyholder/approve", Some(&kh), Some(json!({}))).await;
        assert_eq!(s, StatusCode::OK);
    }

    #[tokio::test]
    async fn random_timer_is_within_range_and_only_the_keyholder_sees_the_roll() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        let (s, v) = h.call("POST", "/api/keyholder/timer/roll", Some(&kh), Some(json!({ "min_secs": 3600, "max_secs": 7200 }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let rolled = v["rolled_secs"].as_i64().unwrap();
        assert!((3600..=7200).contains(&rolled));
        assert_eq!(v["timer"]["remaining_ms"].as_i64().unwrap(), rolled * 1000);

        let (_, ws) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert!(!ws.to_string().contains("min_secs") && ws.get("rolled_secs").is_none());

        let (s, _) = h.call("POST", "/api/keyholder/timer/roll", Some(&kh), Some(json!({ "min_secs": 10, "max_secs": 5 }))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        // Both the range and the result are in the audit log.
        let (_, a) = h.call("GET", "/api/keyholder/audit", Some(&kh), None).await;
        let rolled_entry = a["entries"].as_array().unwrap().iter().find(|e| e["kind"] == "timer_rolled").unwrap();
        assert_eq!(rolled_entry["detail"]["min_ms"], 3_600_000);
        assert_eq!(rolled_entry["detail"]["chosen_ms"].as_i64().unwrap(), rolled * 1000);
    }

    #[tokio::test]
    async fn wrong_passwords_never_lock_the_keyholder_out_and_the_log_summarises_them() {
        let h = harness();
        for _ in 0..40 {
            let (s, v) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "not the password" }))).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED);
            assert!(v.get("retry_after_secs").is_none());
        }
        // Straight after, at the same instant, the right password works.
        let kh = h.keyholder().await;

        // Forty failures made one log row, not forty; the next one after the window carries the count.
        h.advance(31_000);
        h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "still wrong" }))).await;
        let (_, a) = h.call("GET", "/api/keyholder/audit?limit=200", Some(&kh), None).await;
        let rows: Vec<&Value> = a["entries"].as_array().unwrap().iter().filter(|e| e["kind"] == "login_failed").collect();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0]["detail"]["suppressed"], 39, "the newest row says how many were folded in");
        assert_eq!(rows[1]["detail"]["suppressed"], 0);
    }

    #[tokio::test]
    async fn pairing_revocation_and_password_change_cut_off_the_right_sessions() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        let (_, d) = h.call("GET", "/api/keyholder/devices", Some(&kh), None).await;
        let id = d["devices"][0]["id"].as_i64().unwrap();
        let (s, _) = h.call("POST", &format!("/api/keyholder/devices/{id}/revoke"), Some(&kh), None).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "a revoked device is signed out at once");

        let (s, _) = h
            .call("POST", "/api/keyholder/password", Some(&kh), Some(json!({ "current_password": PW, "new_password": "a brand new password" })))
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "the old keyholder session ends after a password change");
    }

    #[tokio::test]
    async fn messages_reach_the_wearer_and_are_marked_read() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/keyholder/messages", Some(&kh), Some(json!({ "body": "Good morning." }))).await;

        let (_, s) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(s["unread_messages"], 1);
        let (_, m) = h.call("GET", "/api/wearer/messages", Some(&w), None).await;
        assert_eq!(m["messages"][0]["body"], "Good morning.");
        let (_, s) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(s["unread_messages"], 0);

        let (s, _) = h.call("POST", "/api/keyholder/messages", Some(&kh), Some(json!({ "body": "   " }))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn every_action_is_in_the_audit_log_and_the_chain_verifies() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        h.call("POST", "/api/keyholder/approve", Some(&kh), Some(json!({}))).await;
        // A refused attempt by the wearer must not be logged as an approval.
        h.call("POST", "/api/keyholder/approve", Some(&w), Some(json!({}))).await;

        let (_, a) = h.call("GET", "/api/keyholder/audit", Some(&kh), None).await;
        assert_eq!(a["chain_intact"], true);
        let kinds: Vec<&str> = a["entries"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
        for expected in ["login", "pairing_code_created", "device_paired", "unlock_requested", "unlock_approved"] {
            assert!(kinds.contains(&expected), "missing {expected} in {kinds:?}");
        }
        assert_eq!(kinds.iter().filter(|k| **k == "unlock_approved").count(), 1);
    }

    // ---------- hardware ----------

    impl Harness {
        /// Wearer has asked and the keyholder has approved: the state in which unlocking is allowed.
        async fn approved(&self, kh: &str, w: &str) {
            self.call("POST", "/api/wearer/request-unlock", Some(w), None).await;
            let (s, v) = self.call("POST", "/api/keyholder/approve", Some(kh), Some(json!({}))).await;
            assert_eq!(s, StatusCode::OK, "{v}");
        }

        async fn audit_kinds(&self, kh: &str) -> Vec<String> {
            let (_, a) = self.call("GET", "/api/keyholder/audit?limit=200", Some(kh), None).await;
            a["entries"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect()
        }

        async fn lock_state(&self, kh: &str) -> String {
            let (_, v) = self.call("GET", "/api/keyholder/state", Some(kh), None).await;
            v["lock"].as_str().unwrap().to_string()
        }
    }

    #[tokio::test]
    async fn the_wearer_unlocks_and_locks_over_the_servers_bluetooth_only_after_approval() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        // No approval, no contact with the pod.
        let (s, _) = h.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        assert_eq!(s, StatusCode::CONFLICT);
        h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        let (s, _) = h.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(h.pod.ops().is_empty());

        h.call("POST", "/api/keyholder/approve", Some(&kh), Some(json!({}))).await;
        let (s, v) = h.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        assert_eq!((s, v["lock"].as_str()), (StatusCode::OK, Some("unlocked")));
        assert_eq!(h.pod.ops(), [PodOp::Unlock]);
        assert_eq!(v["pod"]["via"], "server");

        // The approval was used up: unlocking again needs a fresh one.
        let (s, _) = h.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(h.pod.ops(), [PodOp::Unlock]);

        let (s, v) = h.call("POST", "/api/wearer/lock", Some(&w), None).await;
        assert_eq!((s, v["lock"].as_str()), (StatusCode::OK, Some("locked")));
        assert_eq!(h.pod.ops(), [PodOp::Unlock, PodOp::Lock]);
        let (s, _) = h.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        assert_eq!(s, StatusCode::CONFLICT, "locking again does not leave an approval behind");
    }

    #[tokio::test]
    async fn out_of_range_is_reported_and_changes_nothing_then_works_once_in_range() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.approved(&kh, &w).await;

        h.pod.set_in_range(false);
        let (s, v) = h.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(v["code"], "out_of_range");
        assert_eq!(h.lock_state(&kh).await, "approved", "a failed attempt must not spend the approval");

        h.pod.set_in_range(true);
        let (s, _) = h.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        assert_eq!(s, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_keyholder_cannot_unlock_under_a_timer_but_can_lock_any_time() {
        let h = harness();
        let kh = h.keyholder().await;
        h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 3600 }))).await;

        let (s, _) = h.call("POST", "/api/keyholder/unlock", Some(&kh), None).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(h.pod.ops().is_empty(), "the pod must not be contacted for a refused unlock");

        h.call("POST", "/api/keyholder/timer/clear", Some(&kh), None).await;
        let (s, v) = h.call("POST", "/api/keyholder/unlock", Some(&kh), None).await;
        assert_eq!((s, v["lock"].as_str()), (StatusCode::OK, Some("unlocked")));
        let (s, v) = h.call("POST", "/api/keyholder/lock", Some(&kh), None).await;
        assert_eq!((s, v["lock"].as_str()), (StatusCode::OK, Some("locked")));
        let (s, _) = h.call("POST", "/api/keyholder/lock", Some(&kh), None).await;
        assert_eq!(s, StatusCode::OK, "the pod may be open although we last recorded it locked");
    }

    #[tokio::test]
    async fn sync_records_when_the_pod_was_reached_and_the_wearers_sync_has_a_cooldown() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        let (_, v) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert!(v["pod"].is_null());

        let (s, v) = h.call("POST", "/api/wearer/sync", Some(&w), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["in_range"], true);
        assert_eq!(v["pod"]["via"], "server");
        assert!(v["pod"].get("battery").is_none(), "a battery of 0 means unreported and is not shown");

        let (_, v) = h.call("POST", "/api/wearer/sync", Some(&w), None).await;
        assert_eq!(v["cooldown"], true);
        assert_eq!(h.pod.ops(), [PodOp::Status], "the cooldown must stop a second Bluetooth session");

        // The keyholder is not throttled, and out of range is an answer rather than an error.
        h.pod.set_in_range(false);
        let (s, v) = h.call("POST", "/api/keyholder/sync", Some(&kh), None).await;
        assert_eq!((s, v["in_range"].as_bool()), (StatusCode::OK, Some(false)));
    }

    #[tokio::test]
    async fn losing_control_of_the_pod_is_reported_and_logged() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.approved(&kh, &w).await;
        h.cloud.bound_elsewhere();

        let (s, v) = h.call("POST", "/api/keyholder/sync", Some(&kh), None).await;
        // The fake pod does not consult the cloud, so exercise the relay path, which does.
        assert_eq!(s, StatusCode::OK, "{v}");
        let (s, v) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "unlock" }))).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["code"], "control_lost");
        assert!(h.audit_kinds(&kh).await.contains(&"control_lost".to_string()));
        assert_eq!(h.lock_state(&kh).await, "approved");
    }

    // ---------- phone relay ----------

    #[tokio::test]
    async fn relay_unlock_mints_the_command_only_after_the_handshake_reply_and_records_the_exposure() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.approved(&kh, &w).await;

        let (s, v) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "unlock" }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["cmd"], "TOKEN-1");
        let session = v["session_id"].as_str().unwrap().to_string();
        assert_eq!(h.cloud.calls(), ["device_token_cmd"], "no unlock bytes yet");

        let (s, v) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "aa11" }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!((v["done"].as_bool(), v["cmd"].as_str()), (Some(false), Some("UNLOCK-1")));
        assert_eq!(h.cloud.calls(), ["device_token_cmd", "decrypt:aa11", "unlock_cmd"], "decrypt must precede the mint");
        assert_eq!(h.lock_state(&kh).await, "approved", "not unlocked until the pod acknowledges");

        h.cloud.set_reply_type("bb22", "02");
        let (s, v) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "bb22" }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!((v["done"].as_bool(), v["lock"].as_str()), (Some(true), Some("unlocked")));
        assert_eq!(v["pod"]["via"], "phone");

        let kinds = h.audit_kinds(&kh).await;
        assert_eq!(kinds.iter().filter(|k| *k == "relay_unlock_issued").count(), 1);
        assert!(kinds.contains(&"unlocked".to_string()));

        // The session is over: replaying into it gets nothing.
        let (s, _) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "bb22" }))).await;
        assert_eq!(s, StatusCode::GONE);
    }

    #[tokio::test]
    async fn relay_refuses_to_start_without_approval_and_contacts_the_cloud_for_nothing() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        let (s, _) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "unlock" }))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        let (s, _) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "unlock" }))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(h.cloud.calls().is_empty(), "not even a handshake token may be minted");
    }

    #[tokio::test]
    async fn relay_never_mints_the_unlock_if_the_approval_lapses_or_a_timer_starts_mid_session() {
        for interrupt in ["expire", "timer"] {
            let h = harness();
            let kh = h.keyholder().await;
            let w = h.wearer(&kh).await;
            // A one-minute approval, so it can lapse inside the two-minute relay session.
            h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
            h.call("POST", "/api/keyholder/approve", Some(&kh), Some(json!({ "ttl_minutes": 1 }))).await;
            let (_, v) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "unlock" }))).await;
            let session = v["session_id"].as_str().unwrap().to_string();

            if interrupt == "expire" {
                h.advance(90_000);
            } else {
                h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 3600 }))).await;
            }
            let (s, _) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "aa11" }))).await;
            assert_eq!(s, StatusCode::CONFLICT, "{interrupt}");
            assert!(!h.cloud.calls().contains(&"unlock_cmd".to_string()), "{interrupt}: unlock bytes must not be minted");
        }
    }

    #[tokio::test]
    async fn relay_treats_a_wrong_acknowledgement_as_failure_and_bad_input_as_bad_input() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.approved(&kh, &w).await;

        let (_, v) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "unlock" }))).await;
        let session = v["session_id"].as_str().unwrap().to_string();
        let (s, _) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "not hex" }))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "aa11" }))).await;
        // The pod "acknowledges" with a handshake-type reply instead of an unlock.
        let (s, _) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "cc33" }))).await;
        assert_eq!(s, StatusCode::BAD_GATEWAY);
        assert_eq!(h.lock_state(&kh).await, "approved");

        let (s, _) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "hack" }))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": "nope", "hex": "aa11" }))).await;
        assert_eq!(s, StatusCode::GONE);
    }

    #[tokio::test]
    async fn relay_status_refreshes_the_pod_info_without_minting_any_command() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        let (_, v) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "status" }))).await;
        let session = v["session_id"].as_str().unwrap().to_string();
        let (s, v) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "aa11" }))).await;
        assert_eq!((s, v["done"].as_bool()), (StatusCode::OK, Some(true)));
        assert_eq!(v["pod"]["via"], "phone");
        assert_eq!(h.cloud.calls(), ["device_token_cmd", "decrypt:aa11"]);
    }

    #[tokio::test]
    async fn the_wearers_lock_over_relay_needs_the_lock_to_be_open_and_records_the_phone_path() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        let (s, _) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "lock" }))).await;
        assert_eq!(s, StatusCode::CONFLICT, "nothing to lock while it is locked");

        h.call("POST", "/api/keyholder/unlock", Some(&kh), None).await;
        let (_, v) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "lock" }))).await;
        let session = v["session_id"].as_str().unwrap().to_string();
        let (_, v) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "aa11" }))).await;
        assert_eq!(v["cmd"], "LOCK-1");
        h.cloud.set_reply_type("dd44", "03");
        let (_, v) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "dd44" }))).await;
        assert_eq!(v["lock"], "locked");
    }

    // ---------- keyholder's queue ----------

    #[tokio::test]
    async fn the_keyholder_queues_one_command_and_can_cancel_it_and_the_wearer_sees_it() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        let (s, v) = h.call("POST", "/api/keyholder/queue", Some(&kh), Some(json!({ "command": "lock" }))).await;
        assert_eq!((s, v["queued_command"]["command"].as_str()), (StatusCode::OK, Some("lock")));
        let (_, v) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(v["queued_command"]["command"], "lock");

        let (s, _) = h.call("POST", "/api/keyholder/queue", Some(&kh), Some(json!({ "command": "unlock" }))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        let (s, _) = h.call("POST", "/api/keyholder/queue", Some(&kh), Some(json!({ "command": "explode" }))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        let (s, v) = h.call("POST", "/api/keyholder/queue/cancel", Some(&kh), None).await;
        assert_eq!((s, v["queued_command"].is_null()), (StatusCode::OK, true));
        let (s, _) = h.call("POST", "/api/keyholder/queue/cancel", Some(&kh), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_queued_lock_is_carried_out_by_the_wearers_phone_when_they_next_connect() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/keyholder/queue", Some(&kh), Some(json!({ "command": "lock" }))).await;

        let (s, v) = h.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "queued" }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let session = v["session_id"].as_str().unwrap().to_string();
        let (_, v) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "aa11" }))).await;
        assert_eq!(v["cmd"], "LOCK-1");
        h.cloud.set_reply_type("dd44", "03");
        let (_, v) = h.call("POST", "/api/wearer/relay/reply", Some(&w), Some(json!({ "session_id": session, "hex": "dd44" }))).await;
        assert_eq!(v["done"], true);
        assert!(v["queued_command"].is_null());

        let (_, a) = h.call("GET", "/api/keyholder/audit?limit=50", Some(&kh), None).await;
        let done = a["entries"].as_array().unwrap().iter().find(|e| e["kind"] == "queued_command_done").unwrap();
        assert_eq!(done["detail"]["via"], "phone");
        let locked = a["entries"].as_array().unwrap().iter().find(|e| e["kind"] == "locked").unwrap();
        assert_eq!(locked["actor"], "keyholder", "a queued command is the keyholder's act, not the wearer's");
    }

    #[tokio::test]
    async fn a_queued_unlock_is_dropped_if_a_timer_has_started_and_never_reaches_the_pod() {
        let h = harness();
        let kh = h.keyholder().await;
        h.call("POST", "/api/keyholder/queue", Some(&kh), Some(json!({ "command": "unlock" }))).await;
        h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 3600 }))).await;

        assert!(!run_queue_once(&h.state).await);
        assert!(h.pod.ops().is_empty());
        assert!(h.audit_kinds(&kh).await.contains(&"queued_command_dropped".to_string()));
        let (_, v) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert!(v["queued_command"].is_null());
    }

    #[tokio::test]
    async fn the_server_runs_a_queued_command_itself_once_the_pod_is_in_range() {
        let h = harness();
        let kh = h.keyholder().await;
        h.call("POST", "/api/keyholder/unlock", Some(&kh), None).await;
        h.call("POST", "/api/keyholder/queue", Some(&kh), Some(json!({ "command": "lock" }))).await;

        h.pod.set_in_range(false);
        assert!(!run_queue_once(&h.state).await, "out of range: try again later");
        let (_, v) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert_eq!(v["queued_command"]["command"], "lock");

        h.pod.set_in_range(true);
        assert!(run_queue_once(&h.state).await);
        let (_, v) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert_eq!((v["lock"].as_str(), v["queued_command"].is_null()), (Some("locked"), true));
        assert_eq!(h.pod.ops(), [PodOp::Unlock, PodOp::Lock]);
        assert!(!run_queue_once(&h.state).await, "nothing left to run");
    }

    // ---------- activity and push ----------

    fn good_subscription() -> Value {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use web_push_native::p256::elliptic_curve::sec1::ToEncodedPoint;
        let secret = web_push_native::p256::SecretKey::random(&mut web_push_native::p256::elliptic_curve::rand_core::OsRng);
        json!({
            "endpoint": "https://fcm.googleapis.com/fcm/send/abc123",
            "keys": {
                "p256dh": Base64UrlUnpadded::encode_string(secret.public_key().to_encoded_point(false).as_bytes()),
                "auth": Base64UrlUnpadded::encode_string(&[3u8; 16]),
            }
        })
    }

    #[tokio::test]
    async fn the_activity_feed_tells_the_wearers_story_without_leaking_internals() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        h.call("POST", "/api/keyholder/approve", Some(&kh), Some(json!({}))).await;
        h.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        h.call("POST", "/api/keyholder/timer/roll", Some(&kh), Some(json!({ "min_secs": 3600, "max_secs": 7200 }))).await;
        h.call("POST", "/api/keyholder/messages", Some(&kh), Some(json!({ "body": "secret words" }))).await;

        let (s, v) = h.call("GET", "/api/wearer/activity", Some(&w), None).await;
        assert_eq!(s, StatusCode::OK);
        let text = v.to_string();
        let kinds: Vec<&str> = v["activity"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
        for expected in ["unlock_requested", "unlock_approved", "unlocked", "timer_rolled"] {
            assert!(kinds.contains(&expected), "{expected} missing from {kinds:?}");
        }
        for internal in ["login", "device_paired", "pairing_code_created", "relay_unlock_issued", "control_lost"] {
            assert!(!kinds.contains(&internal), "{internal} must not be visible to the wearer");
        }
        assert!(!text.contains("chosen_ms") && !text.contains("min_ms") && !text.contains("3600"), "a rolled timer's length must not leak: {text}");
        assert!(!text.contains("secret words"), "message text belongs in Messages, not Activity");
        let unlocked = v["activity"].as_array().unwrap().iter().find(|e| e["kind"] == "unlocked").unwrap();
        assert_eq!((unlocked["by"].as_str(), unlocked["via"].as_str()), (Some("wearer"), Some("server")));
    }

    #[tokio::test]
    async fn push_subscriptions_are_validated_stored_and_removable() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        // No key configured yet.
        let (s, v) = h.call("GET", "/api/wearer/push/key", Some(&w), None).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::NOT_FOUND, Some("push_unavailable")));

        // A subscription that would make the server call something inside the network is refused.
        let mut evil = good_subscription();
        evil["endpoint"] = json!("https://127.0.0.1:8443/api/keyholder/state");
        let (s, _) = h.call("POST", "/api/wearer/push/subscribe", Some(&w), Some(evil)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(crate::push::active_subscription(h.state.store.lock().unwrap().connection()).unwrap().is_none());

        let (s, _) = h.call("POST", "/api/wearer/push/subscribe", Some(&w), Some(good_subscription())).await;
        assert_eq!(s, StatusCode::OK);
        assert!(crate::push::active_subscription(h.state.store.lock().unwrap().connection()).unwrap().is_some());

        let (s, _) = h.call("POST", "/api/wearer/push/unsubscribe", Some(&w), None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(crate::push::active_subscription(h.state.store.lock().unwrap().connection()).unwrap().is_none());
    }

    #[tokio::test]
    async fn the_notifier_tells_the_wearer_about_the_keyholders_actions_and_only_those() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/wearer/push/subscribe", Some(&w), Some(good_subscription())).await;
        let sender = FakeSender::default();

        // First pass only sets the cursor: history is not announced.
        assert_eq!(crate::push::notify_once(&h.state, &sender).await, 0);

        h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;            // the wearer's own act: silent
        h.call("POST", "/api/keyholder/approve", Some(&kh), Some(json!({}))).await;     // told
        h.call("POST", "/api/keyholder/messages", Some(&kh), Some(json!({ "body": "Back at 6." }))).await; // told, with text
        assert_eq!(crate::push::notify_once(&h.state, &sender).await, 2);
        let titles: Vec<String> = sender.sent().iter().map(|n| n["title"].as_str().unwrap().to_string()).collect();
        assert_eq!(titles, ["Unlock approved", "Message from your keyholder"]);
        assert_eq!(sender.sent()[1]["body"], "Back at 6.");

        // Nothing new, nothing sent: no repeats.
        assert_eq!(crate::push::notify_once(&h.state, &sender).await, 0);
    }

    #[tokio::test]
    async fn a_timer_ending_by_itself_is_noticed_and_pushed() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/wearer/push/subscribe", Some(&w), Some(good_subscription())).await;
        let sender = FakeSender::default();
        crate::push::notify_once(&h.state, &sender).await;

        h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 3600 }))).await;
        h.advance(2 * HOUR);
        // Nobody has asked for state since; the worker itself has to notice time passing.
        assert!(crate::push::notify_once(&h.state, &sender).await >= 2);
        let titles: Vec<String> = sender.sent().iter().map(|n| n["title"].as_str().unwrap().to_string()).collect();
        assert!(titles.contains(&"Timer started".to_string()), "{titles:?}");
        assert!(titles.contains(&"Timer finished".to_string()), "{titles:?}");
    }

    #[tokio::test]
    async fn a_subscription_the_push_service_says_is_gone_is_forgotten() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/wearer/push/subscribe", Some(&w), Some(good_subscription())).await;
        let sender = FakeSender::default();
        crate::push::notify_once(&h.state, &sender).await;

        sender.set_gone();
        h.call("POST", "/api/keyholder/messages", Some(&kh), Some(json!({ "body": "hello" }))).await;
        assert_eq!(crate::push::notify_once(&h.state, &sender).await, 0);
        assert!(crate::push::active_subscription(h.state.store.lock().unwrap().connection()).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_revoked_device_stops_receiving_notifications() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/wearer/push/subscribe", Some(&w), Some(good_subscription())).await;
        let sender = FakeSender::default();
        crate::push::notify_once(&h.state, &sender).await;

        let (_, d) = h.call("GET", "/api/keyholder/devices", Some(&kh), None).await;
        let id = d["devices"][0]["id"].as_i64().unwrap();
        h.call("POST", &format!("/api/keyholder/devices/{id}/revoke"), Some(&kh), None).await;
        h.call("POST", "/api/keyholder/messages", Some(&kh), Some(json!({ "body": "hello" }))).await;
        assert_eq!(crate::push::notify_once(&h.state, &sender).await, 0);
        assert!(sender.sent().is_empty());
    }

    // ---------- the web app ----------

    #[tokio::test]
    async fn the_app_is_served_with_a_strict_policy_and_the_api_still_answers_api_requests() {
        let h = harness();
        let req = |uri: &str| Request::builder().uri(uri).body(Body::empty()).unwrap();

        let resp = h.app.clone().oneshot(req("/")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers().clone();
        assert!(headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/html"));
        let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'") && !csp.contains("unsafe-inline"));
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(headers["permissions-policy"].to_str().unwrap().contains("bluetooth=(self)"));
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("<title>Tether</title>"));

        for (path, mime) in [("/app.js", "javascript"), ("/sw.js", "javascript"), ("/app.css", "css"), ("/manifest.webmanifest", "manifest+json")] {
            let r = h.app.clone().oneshot(req(path)).await.unwrap();
            assert_eq!(r.status(), StatusCode::OK, "{path}");
            assert!(r.headers()[header::CONTENT_TYPE].to_str().unwrap().contains(mime), "{path}");
            assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache", "{path} must revalidate so updates are picked up");
        }

        // API routes are untouched: JSON, never cached, and unauthenticated calls still refused.
        let r = h.app.clone().oneshot(req("/api/wearer/state")).await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");

        let r = h.app.clone().oneshot(req("/nothing-here")).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = h.app.clone().oneshot(req("/api/keyholder/nothing")).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }


    // ---------- adding time to a timer ----------

    #[tokio::test]
    async fn the_keyholder_can_add_time_to_a_running_and_a_paused_timer_and_the_wearer_sees_it() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;

        h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 3600 }))).await;
        let (s, v) = h.call("POST", "/api/keyholder/timer/add", Some(&kh), Some(json!({ "duration_secs": 1800 }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["timer"]["remaining_ms"].as_i64().unwrap(), 90 * MIN);
        let (_, ws) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(ws["timer"]["remaining_ms"].as_i64().unwrap(), 90 * MIN);

        h.call("POST", "/api/keyholder/timer/pause", Some(&kh), None).await;
        let (_, v) = h.call("POST", "/api/keyholder/timer/add", Some(&kh), Some(json!({ "duration_secs": 3600 }))).await;
        assert_eq!((v["timer"]["kind"].as_str(), v["timer"]["remaining_ms"].as_i64()), (Some("paused"), Some(150 * MIN)));
    }

    #[tokio::test]
    async fn a_random_extension_is_in_range_hidden_from_the_wearer_and_logged() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 7200 }))).await;

        let (s, v) = h.call("POST", "/api/keyholder/timer/add-roll", Some(&kh), Some(json!({ "min_secs": 600, "max_secs": 1200 }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let rolled = v["rolled_secs"].as_i64().unwrap();
        assert!((600..=1200).contains(&rolled));
        assert_eq!(v["timer"]["remaining_ms"].as_i64().unwrap(), 7_200_000 + rolled * 1000);

        let (_, ws) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert!(ws.get("rolled_secs").is_none());
        let (_, act) = h.call("GET", "/api/wearer/activity", Some(&w), None).await;
        let text = act.to_string();
        assert!(text.contains("timer_extension_rolled"), "the wearer should see that time was added");
        assert!(!text.contains("chosen_ms") && !text.contains(&rolled.to_string()), "but not how much: {text}");

        let (_, a) = h.call("GET", "/api/keyholder/audit?limit=50", Some(&kh), None).await;
        let entry = a["entries"].as_array().unwrap().iter().find(|e| e["kind"] == "timer_extension_rolled").unwrap();
        assert_eq!((entry["detail"]["min_ms"].as_i64(), entry["detail"]["max_ms"].as_i64()), (Some(600_000), Some(1_200_000)));
        assert_eq!(entry["detail"]["chosen_ms"].as_i64().unwrap(), rolled * 1000);
    }

    #[tokio::test]
    async fn adding_time_validates_its_input_and_the_wearer_cannot_do_it() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 3600 }))).await;
        for body in [json!({ "duration_secs": 0 }), json!({ "duration_secs": -5 }), json!({ "duration_secs": 400 * 86400 })] {
            let (s, _) = h.call("POST", "/api/keyholder/timer/add", Some(&kh), Some(body)).await;
            assert_eq!(s, StatusCode::BAD_REQUEST);
        }
        // The total may not pass a year.
        let (s, _) = h.call("POST", "/api/keyholder/timer/add", Some(&kh), Some(json!({ "duration_secs": 365 * 86400 }))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = h.call("POST", "/api/keyholder/timer/add-roll", Some(&kh), Some(json!({ "min_secs": 10, "max_secs": 5 }))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        let (s, _) = h.call("POST", "/api/keyholder/timer/add", Some(&w), Some(json!({ "duration_secs": 60 }))).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (_, v) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert_eq!(v["timer"]["remaining_ms"].as_i64().unwrap(), 3_600_000, "nothing above may have changed the timer");
    }

    #[tokio::test]
    async fn adding_time_when_the_timer_has_ended_starts_a_new_one_and_the_wearer_is_told() {
        let h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        h.call("POST", "/api/wearer/push/subscribe", Some(&w), Some(good_subscription())).await;
        let sender = FakeSender::default();
        crate::push::notify_once(&h.state, &sender).await;

        h.call("POST", "/api/keyholder/timer", Some(&kh), Some(json!({ "duration_secs": 60 }))).await;
        h.advance(2 * MIN);
        h.call("POST", "/api/wearer/request-unlock", Some(&w), None).await;
        let (s, v) = h.call("POST", "/api/keyholder/timer/add", Some(&kh), Some(json!({ "duration_secs": 3600 }))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!((v["timer"]["kind"].as_str(), v["lock"].as_str()), (Some("running"), Some("locked")), "the pending request is cancelled");

        h.call("POST", "/api/keyholder/timer/add", Some(&kh), Some(json!({ "duration_secs": 600 }))).await;
        crate::push::notify_once(&h.state, &sender).await;
        let titles: Vec<String> = sender.sent().iter().map(|n| n["title"].as_str().unwrap().to_string()).collect();
        assert!(titles.contains(&"Timer extended".to_string()), "{titles:?}");
    }

    // ---------- encrypted QIUI credentials ----------

    struct VaultHarness {
        h: Harness,
        vault: Arc<LazyCloud>,
        dir: std::path::PathBuf,
    }

    /// A server whose QIUI credentials are sealed under the keyholder's password, as after `config set-client-id`.
    fn vault_harness(name: &str) -> VaultHarness {
        use crate::secrets::Secrets;
        let dir = std::env::temp_dir().join(format!("qiui-vault-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let auth = Auth::for_tests(b"api test pepper");
        let mut cfg = crate::datadir::Config::default();
        cfg.seal_secrets(&auth, PW, &Secrets { client_id: Some("Client_VAULT_TEST".into()), api_key: None }).unwrap();
        crate::datadir::save_config(&dir, &cfg).unwrap();

        let store = Store::open_in_memory().unwrap();
        accounts::init_keyholder(store.connection(), &auth, PW, PIN).unwrap();
        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let pod = Arc::new(FakePod::default());
        let vault = Arc::new(LazyCloud::sealed(cfg.secrets.clone().unwrap(), "AA:BB:CC:DD:EE:FF", false));
        let mut state = AppState::new(store, auth, Hardware::new(vault.clone(), pod.clone())).with_vault(vault.clone(), dir.clone());
        state.clock = Arc::new(move || clock.load(Ordering::SeqCst));
        let h = Harness { app: router(state.clone()), now, pod, cloud: Arc::new(FakeCloud::default()), state };
        VaultHarness { h, vault, dir }
    }

    impl VaultHarness {
        /// The server restarts: same database, credentials sealed and locked again.
        fn restart(&self) -> (Harness, Arc<LazyCloud>) {
            let sealed = crate::datadir::load_config(&self.dir).unwrap().secrets.unwrap();
            let vault = Arc::new(LazyCloud::sealed(sealed, "AA:BB:CC:DD:EE:FF", false));
            let mut state = self.h.state.clone();
            state.hardware = Arc::new(Hardware::new(vault.clone(), self.h.pod.clone()));
            state.vault = Some(vault.clone());
            (Harness { app: router(state.clone()), now: self.h.now.clone(), pod: self.h.pod.clone(), cloud: self.h.cloud.clone(), state }, vault)
        }
    }

    #[tokio::test]
    async fn the_credentials_stay_locked_until_the_keyholder_signs_in_with_the_right_password() {
        let v = vault_harness("unlock");
        assert!(!v.vault.is_unlocked());

        let (s, _) = v.h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "not the password" }))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert!(!v.vault.is_unlocked(), "a wrong password must not unlock anything");

        let kh = v.h.keyholder().await;
        assert!(v.vault.is_unlocked());
        assert!(v.h.audit_kinds(&kh).await.contains(&"credentials_unlocked".to_string()));
    }

    #[tokio::test]
    async fn after_a_restart_pod_control_fails_fast_without_touching_bluetooth_until_the_keyholder_signs_in() {
        let v = vault_harness("restart");
        let kh = v.h.keyholder().await;
        let w = v.h.wearer(&kh).await;
        v.h.approved(&kh, &w).await;

        let (after, vault) = v.restart();
        assert!(!vault.is_unlocked());

        // The wearer's session survives the restart, but pod control does not, and says why.
        let (s, body) = after.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        assert_eq!((s, body["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("credentials_locked")));
        let (s, body) = after.call("POST", "/api/wearer/relay/start", Some(&w), Some(json!({ "intent": "unlock" }))).await;
        assert_eq!((s, body["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("credentials_locked")));
        assert!(after.pod.ops().is_empty(), "a locked server must not even scan for the pod");

        // Accounts, timers and messages still work while locked.
        let (s, _) = after.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(s, StatusCode::OK);

        // The keyholder signs in: decrypted in memory, and the wearer's approved unlock now goes through.
        let (s, body) = after.call("POST", "/api/keyholder/login", None, Some(json!({ "password": PW }))).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        assert!(vault.is_unlocked());
        let (s, body) = after.call("POST", "/api/wearer/unlock", Some(&w), None).await;
        assert_eq!((s, body["lock"].as_str()), (StatusCode::OK, Some("unlocked")));
    }

    #[tokio::test]
    async fn changing_the_password_moves_the_sealed_credentials_to_the_new_one() {
        let v = vault_harness("change");
        let kh = v.h.keyholder().await;
        let (s, body) = v
            .h
            .call("POST", "/api/keyholder/password", Some(&kh), Some(json!({ "current_password": PW, "new_password": "a brand new password" })))
            .await;
        assert_eq!((s, body["credentials"].as_str()), (StatusCode::OK, Some("resealed")), "{body}");

        let sealed = crate::datadir::load_config(&v.dir).unwrap();
        let auth = Auth::for_tests(b"api test pepper");
        assert!(sealed.secrets(&auth, PW).is_err(), "the old password must no longer open the credentials");
        assert_eq!(sealed.secrets(&auth, "a brand new password").unwrap().client_id.as_deref(), Some("Client_VAULT_TEST"));

        // And the next start unlocks with the new password only.
        let (after, vault) = v.restart();
        after.call("POST", "/api/keyholder/login", None, Some(json!({ "password": PW }))).await;
        assert!(!vault.is_unlocked());
        after.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "a brand new password" }))).await;
        assert!(vault.is_unlocked());
        let _ = std::fs::remove_dir_all(&v.dir);
    }

    #[tokio::test]
    async fn if_the_credentials_cannot_be_resealed_the_keyholder_is_told_and_it_is_logged() {
        let v = vault_harness("reseal-fail");
        // The file was sealed under some other password than the keyholder's current one.
        let auth = Auth::for_tests(b"api test pepper");
        let mut cfg = crate::datadir::load_config(&v.dir).unwrap();
        cfg.seal_secrets(&auth, "some other password", &crate::secrets::Secrets { client_id: Some("Client_X".into()), api_key: None }).unwrap();
        crate::datadir::save_config(&v.dir, &cfg).unwrap();

        let kh = v.h.keyholder().await;
        let (s, body) = v
            .h
            .call("POST", "/api/keyholder/password", Some(&kh), Some(json!({ "current_password": PW, "new_password": "a brand new password" })))
            .await;
        assert_eq!((s, body["credentials"].as_str()), (StatusCode::OK, Some("failed")));
        assert!(body["note"].as_str().unwrap().contains("config set-client-id"));
        let kh2 = v.h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "a brand new password" }))).await.1["token"].as_str().unwrap().to_string();
        assert!(v.h.audit_kinds(&kh2).await.contains(&"credentials_reseal_failed".to_string()));
        let _ = std::fs::remove_dir_all(&v.dir);
    }

    // ---------- two paired devices ----------

    #[tokio::test]
    async fn one_phone_can_be_paired_on_two_addresses_and_a_third_device_is_refused() {
        let h = harness();
        let kh = h.keyholder().await;
        let lan = h.wearer(&kh).await; // e.g. http://<lan-ip>:8443
        let tailscale = h.wearer(&kh).await; // e.g. https://<name>.ts.net

        // Both work, and they see the same lock.
        h.call("POST", "/api/wearer/request-unlock", Some(&lan), None).await;
        let (s, v) = h.call("GET", "/api/wearer/state", Some(&tailscale), None).await;
        assert_eq!((s, v["lock"].as_str()), (StatusCode::OK, Some("requested")));

        // The keyholder sees both.
        let (_, st) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert_eq!(st["paired_devices"].as_array().unwrap().len(), 2);

        // A third needs one revoked first.
        let (_, code) = h.call("POST", "/api/keyholder/pairing-code", Some(&kh), None).await;
        let (s, v) = h.call("POST", "/api/wearer/pair", None, Some(json!({ "code": code["code"], "device_name": "third" }))).await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        let (_, d) = h.call("GET", "/api/keyholder/devices", Some(&kh), None).await;
        let first = d["devices"][0]["id"].as_i64().unwrap();
        h.call("POST", &format!("/api/keyholder/devices/{first}/revoke"), Some(&kh), None).await;
        let (s, _) = h.call("GET", "/api/wearer/state", Some(&lan), None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "the revoked device is out");
        let (s, _) = h.call("GET", "/api/wearer/state", Some(&tailscale), None).await;
        assert_eq!(s, StatusCode::OK, "the other is untouched");
        let (s, _) = h.call("POST", "/api/wearer/pair", None, Some(json!({ "code": code["code"], "device_name": "third" }))).await;
        assert_eq!(s, StatusCode::OK, "now there is room");
    }

    #[tokio::test]
    async fn every_subscribed_device_is_notified_and_only_active_ones() {
        let h = harness();
        let kh = h.keyholder().await;
        let a = h.wearer(&kh).await;
        let b = h.wearer(&kh).await;
        h.call("POST", "/api/wearer/push/subscribe", Some(&a), Some(good_subscription())).await;
        h.call("POST", "/api/wearer/push/subscribe", Some(&b), Some(good_subscription())).await;
        let sender = FakeSender::default();
        crate::push::notify_once(&h.state, &sender).await; // sets the cursor

        h.call("POST", "/api/keyholder/messages", Some(&kh), Some(json!({ "body": "hello both" }))).await;
        assert_eq!(crate::push::notify_once(&h.state, &sender).await, 2);
        let mut to = sender.sent_to();
        to.sort();
        assert_eq!(to.len(), 2);
        assert_ne!(to[0], to[1], "one push per device, not two to the same one");

        // Revoke one: the next message reaches only the other.
        let (_, d) = h.call("GET", "/api/keyholder/devices", Some(&kh), None).await;
        let revoked = d["devices"][0]["id"].as_i64().unwrap();
        h.call("POST", &format!("/api/keyholder/devices/{revoked}/revoke"), Some(&kh), None).await;
        h.call("POST", "/api/keyholder/messages", Some(&kh), Some(json!({ "body": "hello one" }))).await;
        assert_eq!(crate::push::notify_once(&h.state, &sender).await, 1);
        assert!(!sender.sent_to()[2..].contains(&revoked));
    }

    #[tokio::test]
    async fn a_device_that_stopped_listening_is_dropped_without_affecting_the_others() {
        let h = harness();
        let kh = h.keyholder().await;
        let a = h.wearer(&kh).await;
        let b = h.wearer(&kh).await;
        h.call("POST", "/api/wearer/push/subscribe", Some(&a), Some(good_subscription())).await;
        h.call("POST", "/api/wearer/push/subscribe", Some(&b), Some(good_subscription())).await;
        let sender = FakeSender::default();
        crate::push::notify_once(&h.state, &sender).await;

        sender.set_gone(); // the push service says every subscription is gone
        h.call("POST", "/api/keyholder/messages", Some(&kh), Some(json!({ "body": "anyone?" }))).await;
        assert_eq!(crate::push::notify_once(&h.state, &sender).await, 0);
        assert!(crate::push::active_subscriptions(h.state.store.lock().unwrap().connection()).unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_device_limit_is_the_keyholders_to_change() {
        let h = harness();
        let kh = h.keyholder().await;
        h.state.store.lock().unwrap().connection().execute("INSERT INTO settings (key, value) VALUES ('max_devices', '1') ON CONFLICT(key) DO UPDATE SET value='1'", []).unwrap();
        let _only = h.wearer(&kh).await;
        let (_, code) = h.call("POST", "/api/keyholder/pairing-code", Some(&kh), None).await;
        let (s, _) = h.call("POST", "/api/wearer/pair", None, Some(json!({ "code": code["code"], "device_name": "second" }))).await;
        assert_eq!(s, StatusCode::CONFLICT);
    }

    // ---------- password-check cost ----------

    fn weak_then_strong() -> (Auth, Auth) {
        (
            Auth::for_tests(b"api test pepper"),
            Auth::with_params(b"api test pepper".to_vec(), accounts::KdfParams { m: 16, t: 2, p: 1 }),
        )
    }

    /// A server whose stored hash was made under weaker settings than it now uses.
    fn upgraded_harness() -> Harness {
        let (weak, strong) = weak_then_strong();
        let store = Store::open_in_memory().unwrap();
        accounts::init_keyholder(store.connection(), &weak, PW, PIN).unwrap();
        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let pod = Arc::new(FakePod::default());
        let cloud = Arc::new(FakeCloud::default());
        let mut state = AppState::new(store, strong, Hardware::new(cloud.clone(), pod.clone()));
        state.clock = Arc::new(move || clock.load(Ordering::SeqCst));
        Harness { app: router(state.clone()), now, pod, cloud, state }
    }

    #[tokio::test]
    async fn signing_in_strengthens_an_older_password_hash_once_and_logs_it() {
        let h = upgraded_harness();
        let stored = |h: &Harness| accounts::stored_password_hash(h.state.store.lock().unwrap().connection()).unwrap();
        assert_eq!(accounts::KdfParams::from_phc(&stored(&h)).unwrap().m, 8);

        let (s, _) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "not the password!!" }))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(accounts::KdfParams::from_phc(&stored(&h)).unwrap().m, 8, "a wrong password upgrades nothing");

        let kh = h.keyholder().await;
        assert_eq!(accounts::KdfParams::from_phc(&stored(&h)).unwrap().m, 16);
        h.keyholder().await; // a second sign-in finds it up to date
        let upgrades = h.audit_kinds(&kh).await.iter().filter(|k| *k == "kdf_upgraded").count();
        assert_eq!(upgrades, 1);
    }

    #[tokio::test]
    async fn signing_in_re_seals_credentials_that_were_sealed_under_older_settings() {
        use crate::secrets::Secrets;
        let (weak, strong) = weak_then_strong();
        let dir = std::env::temp_dir().join(format!("qiui-upgrade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = crate::datadir::Config::default();
        cfg.seal_secrets(&weak, PW, &Secrets { client_id: Some("Client_UPGRADE".into()), api_key: None }).unwrap();
        crate::datadir::save_config(&dir, &cfg).unwrap();
        assert_eq!(cfg.secrets.as_ref().unwrap().m, Some(8));

        let store = Store::open_in_memory().unwrap();
        accounts::init_keyholder(store.connection(), &strong, PW, PIN).unwrap();
        let vault = Arc::new(LazyCloud::sealed(cfg.secrets.clone().unwrap(), "AA:BB", false));
        let state = AppState::new(store, strong, Hardware::new(vault.clone(), Arc::new(FakePod::default()))).with_vault(vault.clone(), dir.clone());
        let h = Harness { app: router(state.clone()), now: Arc::new(AtomicI64::new(1_000_000)), pod: Arc::new(FakePod::default()), cloud: Arc::new(FakeCloud::default()), state };

        let kh = h.keyholder().await;
        assert!(vault.is_unlocked());
        let on_disk = crate::datadir::load_config(&dir).unwrap().secrets.unwrap();
        assert_eq!((on_disk.v, on_disk.m, on_disk.t), (2, Some(16), Some(2)), "now sealed under the current settings");
        assert_eq!(crate::datadir::load_config(&dir).unwrap().secrets(&Auth::with_params(b"api test pepper".to_vec(), accounts::KdfParams { m: 16, t: 2, p: 1 }), PW).unwrap().client_id.as_deref(), Some("Client_UPGRADE"));
        assert!(h.audit_kinds(&kh).await.contains(&"kdf_upgraded".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_flood_of_guesses_is_turned_away_when_the_gate_is_full_and_everything_else_keeps_answering() {
        let mut h = harness();
        let kh = h.keyholder().await;
        let w = h.wearer(&kh).await;
        // A gate with one slot and no queue, and that slot busy with (pretend) password checks.
        h.state.hash_gate = Arc::new(HashGate::new(1, 0));
        h.app = router(h.state.clone());
        let gate = h.state.hash_gate.clone();
        let hog = tokio::spawn(async move { gate.run(|| std::thread::sleep(std::time::Duration::from_millis(600))).await });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;

        // A guess now is told the server is busy, rather than queued forever or locking anyone out...
        let (s, v) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "a guess" }))).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("busy")));
        let (s, v) = h.call("POST", "/api/keyholder/password", Some(&kh), Some(json!({ "current_password": PW, "new_password": "a brand new password" }))).await;
        assert_eq!((s, v["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("busy")));

        // ...while the wearer's app and the keyholder's other requests are not held up at all.
        let (s, _) = h.call("GET", "/api/wearer/state", Some(&w), None).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(!hog.is_finished(), "those answers came back while the password checks were still running");

        // Once there is room, the right password works straight away: nothing was locked.
        hog.await.unwrap().unwrap();
        let (s, _) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": PW }))).await;
        assert_eq!(s, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_new_password_shorter_than_sixteen_characters_is_refused_before_any_hashing() {
        let h = harness();
        let kh = h.keyholder().await;
        let (s, v) = h.call("POST", "/api/keyholder/password", Some(&kh), Some(json!({ "current_password": PW, "new_password": "only 15 chars!!" }))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert!(v["error"].as_str().unwrap().contains("16"));
        let (s, _) = h.call("GET", "/api/keyholder/state", Some(&kh), None).await;
        assert_eq!(s, StatusCode::OK, "nothing changed, and the session is still good");
    }

    #[tokio::test]
    async fn a_burst_of_wrong_passwords_is_shown_to_the_keyholder_at_once_and_recorded_when_the_window_closes() {
        let h = harness();
        let kh = h.keyholder().await;
        for _ in 0..12 {
            h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "wrong wrong wrong" }))).await;
        }
        // At once: the first is its own row, and the other eleven are shown as pending, not hidden.
        let (_, a) = h.call("GET", "/api/keyholder/audit?limit=100", Some(&kh), None).await;
        let rows: Vec<&Value> = a["entries"].as_array().unwrap().iter().filter(|e| e["kind"] == "login_failed").collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["detail"]["suppressed"], 0);
        assert_eq!(a["pending_failures"][0]["count"], 11);
        assert_eq!((a["pending_failures"][0]["kind"].as_str(), a["pending_failures"][0]["actor"].as_str()), (Some("login_failed"), Some("system")));

        // Too early for a summary row; then the window closes and the worker writes it, with no further failure.
        assert_eq!(flush_failure_summaries(&h.state).await, 0);
        h.advance(31_000);
        assert_eq!(flush_failure_summaries(&h.state).await, 1);
        let (_, a) = h.call("GET", "/api/keyholder/audit?limit=100", Some(&kh), None).await;
        let rows: Vec<&Value> = a["entries"].as_array().unwrap().iter().filter(|e| e["kind"] == "login_failed").collect();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0]["detail"]["suppressed"].as_i64(), rows[0]["detail"]["summary"].as_bool()), (Some(11), Some(true)));
        assert!(a["pending_failures"].as_array().unwrap().is_empty());
        assert_eq!(a["chain_intact"], true);
    }

    #[tokio::test]
    async fn every_route_counts_its_own_failures_so_a_flood_on_one_cannot_hide_another() {
        let h = harness();
        let kh = h.keyholder().await;
        // Hammer the keyholder login.
        for _ in 0..15 {
            h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "wrong wrong wrong" }))).await;
        }
        // Then one bad pairing code and one bad "current password" on the change-password route.
        h.call("POST", "/api/wearer/pair", None, Some(json!({ "code": "AAAA-AAAA", "device_name": "x" }))).await;
        h.call("POST", "/api/keyholder/password", Some(&kh), Some(json!({ "current_password": "not the password!!", "new_password": "a brand new password" }))).await;

        let (_, a) = h.call("GET", "/api/keyholder/audit?limit=200", Some(&kh), None).await;
        let count = |kind: &str| a["entries"].as_array().unwrap().iter().filter(|e| e["kind"] == kind).count();
        assert_eq!(count("login_failed"), 1, "the login flood is one row plus a pending count");
        assert_eq!(count("pairing_failed"), 1, "the first bad pairing code still got its own row");
        assert_eq!(count("password_change_failed"), 1, "and so did the first bad change-password attempt");
        let pending = a["pending_failures"].as_array().unwrap();
        assert_eq!(pending.len(), 1, "only the flooded route has anything pending: {pending:?}");
        assert_eq!((pending[0]["kind"].as_str(), pending[0]["count"].as_i64()), (Some("login_failed"), Some(14)));
    }

    #[tokio::test]
    async fn attempts_the_gate_turns_away_are_counted_per_route_and_shown_at_once() {
        let mut h = harness();
        let kh = h.keyholder().await;
        h.state.hash_gate = Arc::new(HashGate::new(1, 0));
        h.app = router(h.state.clone());
        let gate = h.state.hash_gate.clone();
        let hog = tokio::spawn(async move { gate.run(|| std::thread::sleep(std::time::Duration::from_millis(500))).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Twelve login guesses and two change-password guesses all turned away, none of them checked.
        for _ in 0..12 {
            let (s, v) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "a guess" }))).await;
            assert_eq!((s, v["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("busy")));
        }
        for _ in 0..2 {
            h.call("POST", "/api/keyholder/password", Some(&kh), Some(json!({ "current_password": "a guess at it!!", "new_password": "a brand new password" }))).await;
        }
        let (_, a) = h.call("GET", "/api/keyholder/audit?limit=100", Some(&kh), None).await;
        let rows = |kind: &str| a["entries"].as_array().unwrap().iter().filter(|e| e["kind"] == kind).count();
        assert_eq!((rows("login_busy"), rows("password_change_busy")), (1, 1), "each route's first turned-away attempt has its own row at once");
        let pending: std::collections::HashMap<String, i64> =
            a["pending_failures"].as_array().unwrap().iter().map(|p| (p["kind"].as_str().unwrap().to_string(), p["count"].as_i64().unwrap())).collect();
        assert_eq!(pending["login_busy"], 11, "the other eleven are visible immediately, before any flush");
        assert_eq!(pending["password_change_busy"], 1);

        // The worker folds them in, and when the window closes writes the summary rows.
        hog.await.unwrap().unwrap();
        flush_failure_summaries(&h.state).await;
        h.advance(31_000);
        assert_eq!(flush_failure_summaries(&h.state).await, 2);
        let (_, a) = h.call("GET", "/api/keyholder/audit?limit=100", Some(&kh), None).await;
        let summary = a["entries"].as_array().unwrap().iter().find(|e| e["kind"] == "login_busy" && e["detail"]["summary"] == true).unwrap();
        assert_eq!(summary["detail"]["suppressed"], 11);
        assert!(a["pending_failures"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected() {
        let h = harness();
        let (s, _) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "x".repeat(20_000) }))).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
