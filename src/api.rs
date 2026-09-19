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
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::accounts::{self, Auth, AuthError, Role};
use crate::audit;
use crate::machine::{self, Actor, Machine};
use crate::store::{ApplyError, Store};
use crate::timer::Timer;

const MAX_TIMER_SECS: i64 = 365 * 24 * 60 * 60;
const DEFAULT_APPROVAL_MINUTES: i64 = 15;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub auth: Arc<Auth>,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl AppState {
    pub fn new(store: Store, auth: Auth) -> Self {
        Self { store: Arc::new(Mutex::new(store)), auth: Arc::new(auth), clock: Arc::new(system_now_ms) }
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
    retry_after_secs: Option<i64>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into(), retry_after_secs: None }
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

/// `server_time_ms` lets the app count down from the server's clock, not the phone's.
fn state_view(m: &Machine, unread: i64, now: i64) -> Value {
    json!({
        "server_time_ms": now,
        "lock": m.state.as_str(),
        "approval_expires_ms": m.approval_expires_ms,
        "timer": timer_view(&m.timer, now),
        "unread_messages": unread,
    })
}

/// Apply time first (ending timers, expiring approvals) so a read never shows stale state.
fn current(store: &mut Store, now: i64) -> Result<Machine, ApiError> {
    store.apply(now, |_| Ok(Vec::new()))?;
    Ok(store.machine()?)
}

fn wearer_state(store: &mut Store, now: i64) -> ApiResult {
    let m = current(store, now)?;
    Ok(Json(state_view(&m, accounts::unread_count(store.connection())?, now)))
}

fn keyholder_state(store: &mut Store, now: i64) -> ApiResult {
    let m = current(store, now)?;
    let mut view = state_view(&m, accounts::unread_count(store.connection())?, now);
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
        .layer(middleware::from_fn_with_state(state.clone(), require_keyholder));

    let wearer = Router::new()
        .route("/api/wearer/state", get(wearer_get_state))
        .route("/api/wearer/request-unlock", post(wearer_request_unlock))
        .route("/api/wearer/cancel-request", post(wearer_cancel_request))
        .route("/api/wearer/messages", get(wearer_messages))
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

    const PW: &str = "correct horse battery";
    const PIN: &str = "482913";
    const MIN: i64 = 60_000;
    const HOUR: i64 = 60 * MIN;

    struct Harness {
        app: Router,
        now: Arc<AtomicI64>,
    }

    fn harness() -> Harness {
        let store = Store::open_in_memory().unwrap();
        let auth = Auth::for_tests(b"api test pepper");
        accounts::init_keyholder(store.connection(), &auth, PW, PIN).unwrap();
        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let mut state = AppState::new(store, auth);
        state.clock = Arc::new(move || clock.load(Ordering::SeqCst));
        Harness { app: router(state), now }
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
        ];
        for (method, path) in keyholder_routes {
            let (s, _) = h.call(method, path, Some(&w), Some(json!({}))).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "wearer token on {method} {path}");
            let (s, _) = h.call(method, path, None, Some(json!({}))).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "no token on {method} {path}");
            let (s, _) = h.call(method, path, Some("0000"), Some(json!({}))).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "junk token on {method} {path}");
        }
        // And the keyholder token is not a wearer token.
        let (s, _) = h.call("GET", "/api/wearer/state", Some(&kh), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);

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

    #[tokio::test]
    async fn oversized_bodies_are_rejected() {
        let h = harness();
        let (s, _) = h.call("POST", "/api/keyholder/login", None, Some(json!({ "password": "x".repeat(20_000) }))).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
