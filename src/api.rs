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
use crate::cloud::CloudError;
use crate::hardware::{Hardware, Intent, Stage};
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
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl AppState {
    pub fn new(store: Store, auth: Auth, hardware: Hardware) -> Self {
        Self { store: Arc::new(Mutex::new(store)), auth: Arc::new(auth), hardware: Arc::new(hardware), clock: Arc::new(system_now_ms) }
    }

    fn now(&self) -> i64 {
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
    retry_after_secs: Option<i64>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into(), code: None, retry_after_secs: None }
    }

    fn coded(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, message: message.into(), code: Some(code), retry_after_secs: None }
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
        if let Some(secs) = self.retry_after_secs {
            body["retry_after_secs"] = secs.into();
        }
        let mut resp = (self.status, Json(body)).into_response();
        if let Some(secs) = self.retry_after_secs {
            resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(secs.max(0) as u64));
        }
        resp
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Invalid => Self::new(StatusCode::UNAUTHORIZED, "That did not match."),
            AuthError::Locked { retry_after_ms } => Self {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: e.to_string(),
                code: None,
                retry_after_secs: Some(retry_after_ms / 1000 + 1),
            },
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
            machine::Error::InvalidDuration => StatusCode::BAD_REQUEST,
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

fn pod_error(e: PodError) -> ApiError {
    match e {
        PodError::NotInRange => ApiError::coded(StatusCode::CONFLICT, "out_of_range", e.to_string()),
        PodError::ControlLost => control_lost(),
        PodError::Timeout => ApiError::coded(StatusCode::GATEWAY_TIMEOUT, "pod_timeout", e.to_string()),
        other => ApiError::coded(StatusCode::BAD_GATEWAY, "pod_error", other.to_string()),
    }
}

fn cloud_error(e: CloudError) -> ApiError {
    match e {
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

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        Self::internal(e)
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

/// Run database work off the async threads: Argon2 is deliberately slow.
async fn db<T, F>(st: &AppState, f: F) -> Result<T, ApiError>
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
    let device = accounts::list_devices(store.connection())?.into_iter().find(|d| d.revoked_ms.is_none());
    view["paired_device"] = match device {
        Some(d) => json!({ "id": d.id, "name": d.name, "paired_ms": d.paired_ms, "last_seen_ms": d.last_seen_ms }),
        None => Value::Null,
    };
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
    db(&st, move |store, auth, now| match accounts::login(store.connection(), auth, &req.password, now) {
        Ok(token) => {
            store.log(now, "keyholder", "login", &json!({}))?;
            Ok(Json(json!({ "token": token, "expires_in_secs": accounts::KEYHOLDER_SESSION_MS / 1000 })))
        }
        Err(AuthError::Invalid) => {
            store.log(now, "system", "login_failed", &json!({}))?;
            Err(AuthError::Invalid.into())
        }
        Err(e) => Err(e.into()),
    })
    .await
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
            store.log(now, "system", "pairing_failed", &json!({}))?;
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
        Ok(Json(json!({ "chain_intact": intact, "entries": entries })))
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
    db(&st, move |store, auth, now| {
        accounts::change_password(store.connection(), auth, &req.current_password, &req.new_password, now)?;
        store.log(now, "keyholder", "password_changed", &json!({}))?;
        Ok(Json(json!({ "changed": true, "note": "All sessions were signed out. Sign in again." })))
    })
    .await
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

// ---------- router ----------

pub fn router(state: AppState) -> Router {
    let keyholder = Router::new()
        .route("/api/keyholder/state", get(kh_state))
        .route("/api/keyholder/approve", post(kh_approve))
        .route("/api/keyholder/deny", post(kh_deny))
        .route("/api/keyholder/timer", post(kh_timer_set))
        .route("/api/keyholder/timer/roll", post(kh_timer_roll))
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
        .layer(middleware::from_fn_with_state(state.clone(), require_wearer));

    Router::new()
        .route("/api/keyholder/login", post(keyholder_login))
        .route("/api/wearer/pair", post(wearer_pair))
        .merge(keyholder)
        .merge(wearer)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::map_response(|mut r: Response| async move {
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::fakes::{FakeCloud, FakePod};

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
    async fn bad_logins_are_throttled_with_retry_after() {
        let h = harness();
        for _ in 0..5 {
            let (s, _) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "not the password" }))).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED);
        }
        let (s, v) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": PW }))).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert!(v["retry_after_secs"].as_i64().unwrap() > 0);
        h.advance(2 * MIN);
        let (s, _) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": PW }))).await;
        assert_eq!(s, StatusCode::OK);
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

    #[tokio::test]
    async fn oversized_bodies_are_rejected() {
        let h = harness();
        let (s, _) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "x".repeat(20_000) }))).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
