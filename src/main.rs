use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{Local, TimeZone};
use clap::{Args, Parser, Subcommand};
use reqwest::Method;
use serde_json::{Value, json};

use qiui_server::accounts::{self, AuthError};
use qiui_server::api::{self, AppState, system_now_ms};
use qiui_server::ble::{self, KNOWN_MAC, MAC_PREFIX};
use qiui_server::client::{ENV_FILE, load_env};
use qiui_server::cloud::{Cloud, QiuiCloud, SimulatedCloud, UnconfiguredCloud};
use qiui_server::datadir::{self, Config};
use qiui_server::hardware::Hardware;
use qiui_server::machine::Actor;
use qiui_server::pod::{BlePod, PodError, PodLink, PodOp, SimulatedPod};
use qiui_server::push::{self, DEFAULT_CONTACT, HttpPushSender, Vapid};
use qiui_server::store::{ApplyError, Store};

#[derive(Parser)]
#[command(about = "QIUI KeyPod keyholder server and command-line client", version)]
struct Cli {
    /// Print every raw HTTP response and BLE payload
    #[arg(long, global = true)]
    debug: bool,
    /// KeyPod Bluetooth MAC address (default: from `config set-mac`)
    #[arg(long, global = true)]
    mac: Option<String>,
    /// Where the database, pepper key and config live (default: $QIUI_DATA_DIR or ~/.local/share/qiui-server)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Address of the running server, for the keyholder commands
    #[arg(long, global = true, env = "QIUI_SERVER", default_value = "http://127.0.0.1:8443")]
    server: String,
    #[command(subcommand)]
    action: Action,
}

/// Keyholder password for commands that need it. Omit it to be prompted.
#[derive(Args, Clone)]
struct PasswordArg {
    /// Keyholder password. Visible in `ps` and shell history; prefer QIUI_KEYHOLDER_PASSWORD.
    #[arg(long, env = "QIUI_KEYHOLDER_PASSWORD", hide_env_values = true)]
    password: Option<String>,
}

#[derive(Subcommand)]
enum Action {
    // ----- keyholder commands (talk to the running server) -----
    /// Show the lock, timer, pending requests, queued command and pod info
    Status(PasswordArg),
    /// Approve the wearer's unlock request
    Approve {
        /// How long the approval stays usable
        #[arg(long, default_value_t = 15)]
        minutes: i64,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// Deny a request, or revoke an approval that has not been used
    Deny(PasswordArg),
    /// Lock the pod (server's Bluetooth; works without the server running too)
    Lock(PasswordArg),
    /// Unlock the pod (refused while a timer is running or paused)
    Unlock(PasswordArg),
    /// Refresh what is known about the pod over Bluetooth
    Sync(PasswordArg),
    /// Set, roll, pause, resume or clear the timer
    Timer {
        #[command(subcommand)]
        cmd: TimerCmd,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// Send the wearer a message
    Message {
        text: String,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// Show the audit log, newest first
    Audit {
        #[arg(long, default_value_t = 30)]
        limit: u32,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// Queue a lock or unlock for the next time the pod can be reached, or cancel it
    Queue {
        #[command(subcommand)]
        cmd: QueueCmd,
        #[command(flatten)]
        auth: PasswordArg,
    },

    // ----- server and account administration (local shell) -----
    /// Run the HTTP API
    Serve {
        #[arg(long, default_value = "127.0.0.1:8443")]
        bind: SocketAddr,
        /// Allow binding a non-loopback address. The server speaks plain HTTP; put it behind TLS (e.g. `tailscale serve`).
        #[arg(long)]
        allow_remote: bool,
        /// DEMO ONLY: pretend the pod is always in range and obeys. No QIUI account or hardware is used.
        #[arg(long)]
        simulate_pod: bool,
        /// With --simulate-pod: the pod is never in the server's range, so the phone's Bluetooth is used
        #[arg(long, requires = "simulate_pod")]
        simulate_out_of_range: bool,
    },
    /// Create the keyholder account (password and recovery PIN)
    Init {
        /// New keyholder password (prefer the QIUI_KEYHOLDER_PASSWORD environment variable)
        #[arg(long, env = "QIUI_KEYHOLDER_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// New recovery PIN (prefer the QIUI_RECOVERY_PIN environment variable)
        #[arg(long, env = "QIUI_RECOVERY_PIN", hide_env_values = true)]
        pin: Option<String>,
    },
    /// Reset the keyholder password using the recovery PIN
    ResetPassword {
        /// Recovery PIN (prefer the QIUI_RECOVERY_PIN environment variable)
        #[arg(long, env = "QIUI_RECOVERY_PIN", hide_env_values = true)]
        pin: Option<String>,
        /// The new password (prefer the QIUI_NEW_PASSWORD environment variable)
        #[arg(long, env = "QIUI_NEW_PASSWORD", hide_env_values = true)]
        new_password: Option<String>,
    },
    /// Print a one-time code to pair the wearer's device
    PairingCode,
    /// List paired wearer devices
    Devices,
    /// Sign a wearer device out and forbid it from reconnecting
    RevokeDevice { id: i64 },
    /// QIUI credentials and the pod's address
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Scan Bluetooth and report which devices are KeyPods (no cloud calls)
    Identify,
}

#[derive(Subcommand)]
enum TimerCmd {
    /// Start a timer of an exact length, e.g. 14d, 36h, 2d12h30m
    Set { duration: String },
    /// Start a timer of a random length between MIN and MAX (the wearer never sees the roll)
    Roll { min: String, max: String },
    Pause,
    Resume,
    Clear,
}

#[derive(Subcommand)]
enum QueueCmd {
    Lock,
    Unlock,
    Cancel,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Show what is configured (secrets masked)
    Show,
    /// Set the QIUI client id
    SetClientId {
        #[arg(env = "QIUI_CLIENT_ID", hide_env_values = true)]
        value: Option<String>,
    },
    /// Set the QIUI API key
    SetApiKey {
        #[arg(env = "QIUI_API_KEY", hide_env_values = true)]
        value: Option<String>,
    },
    /// Set the pod's Bluetooth address
    SetMac { mac: String },
    /// Set the contact address push services can use (mailto:you@example.com)
    SetPushContact { contact: String },
    /// Import QIUI_CLIENT_ID / QIUI_PROD_API_KEY from an old .qiui_pod_env file
    ImportEnv { path: Option<PathBuf> },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    warn_if_secret_on_command_line();
    match &cli.action {
        Action::Status(a) => status(&cli, a).await,
        Action::Approve { minutes, auth } => {
            show_state(&kh(&cli, auth, Method::POST, "/api/keyholder/approve", Some(json!({ "ttl_minutes": minutes }))).await?)
        }
        Action::Deny(a) => show_state(&kh(&cli, a, Method::POST, "/api/keyholder/deny", None).await?),
        Action::Lock(a) => pod_action(&cli, a, "lock").await,
        Action::Unlock(a) => pod_action(&cli, a, "unlock").await,
        Action::Sync(a) => pod_action(&cli, a, "sync").await,
        Action::Timer { cmd, auth } => timer(&cli, auth, cmd).await,
        Action::Message { text, auth } => {
            kh(&cli, auth, Method::POST, "/api/keyholder/messages", Some(json!({ "body": text }))).await?;
            println!("Message sent.");
            Ok(())
        }
        Action::Audit { limit, auth } => audit(&cli, auth, *limit).await,
        Action::Queue { cmd, auth } => queue(&cli, auth, cmd).await,
        Action::Serve { bind, allow_remote, simulate_pod, simulate_out_of_range } => {
            serve(&cli, *bind, *allow_remote, *simulate_pod, !*simulate_out_of_range).await
        }
        Action::Init { password, pin } => init(&cli, password.clone(), pin.clone()),
        Action::ResetPassword { pin, new_password } => reset_password(&cli, pin.clone(), new_password.clone()),
        Action::PairingCode => pairing_code(&cli),
        Action::Devices => devices(&cli),
        Action::RevokeDevice { id } => revoke_device(&cli, *id),
        Action::Config { cmd } => config(&cli, cmd),
        Action::Identify => identify().await,
    }
}

// ---------- secrets on the command line ----------

/// A secret given up front (flag or environment variable) is used as is; otherwise ask, hidden.
fn secret(given: Option<String>, prompt: &str) -> Result<String> {
    match given {
        Some(s) => Ok(s),
        None => Ok(rpassword::prompt_password(prompt)?),
    }
}

fn new_secret(given: Option<String>, what: &str) -> Result<String> {
    match given {
        Some(s) => Ok(s),
        None => prompt_twice(what),
    }
}

/// Flags put secrets in the process list and shell history. Say so, once.
fn warn_if_secret_on_command_line() {
    let inline = std::env::args().any(|a| ["--password", "--pin", "--new-password"].iter().any(|f| a == *f || a.starts_with(&format!("{f}="))));
    if inline {
        eprintln!("Warning: a secret on the command line is visible to other users (ps) and saved in shell history. Prefer the QIUI_* environment variables.");
    }
}

fn prompt_twice(what: &str) -> Result<String> {
    let first = rpassword::prompt_password(format!("New {what}: "))?;
    let second = rpassword::prompt_password(format!("Repeat {what}: "))?;
    if first != second {
        bail!("the two entries did not match");
    }
    Ok(first)
}

// ---------- talking to the running server ----------

struct Server {
    base: String,
    http: reqwest::Client,
    token: String,
}

impl Server {
    /// Sign in. `Ok(None)` means nothing is listening, so callers can fall back where that makes sense.
    async fn connect(cli: &Cli, password: &PasswordArg) -> Result<Option<Server>> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(90)).build()?;
        let base = cli.server.trim_end_matches('/').to_string();
        // Only ask for the password once we know there is a server to give it to.
        let probe = http.get(format!("{base}/api/wearer/state")).send().await;
        if let Err(e) = &probe {
            if e.is_connect() {
                return Ok(None);
            }
        }
        let password = secret(password.password.clone(), "Keyholder password: ")?;
        let resp = http.post(format!("{base}/api/keyholder/login")).json(&json!({ "password": password })).send().await?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("{}", body["error"].as_str().unwrap_or("sign-in failed"));
        }
        let token = body["token"].as_str().context("the server returned no token")?.to_string();
        Ok(Some(Server { base, http, token }))
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let mut req = self.http.request(method, format!("{}{path}", self.base)).bearer_auth(&self.token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("{}", v["error"].as_str().unwrap_or("the server refused"));
        }
        Ok(v)
    }
}

/// One keyholder call to the server, signing in first and out afterwards.
async fn kh(cli: &Cli, auth: &PasswordArg, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
    let srv = Server::connect(cli, auth)
        .await?
        .ok_or_else(|| anyhow!("the server is not running at {}. Start it with `qiui-server serve`.", cli.server))?;
    let out = srv.call(method, path, body).await;
    let _ = srv.call(Method::POST, "/api/keyholder/logout", None).await;
    out
}

// ---------- output helpers ----------

fn fmt_span(ms: i64) -> String {
    let s = ms.max(0) / 1000;
    let (d, h, m, sec) = (s / 86400, s % 86400 / 3600, s % 3600 / 60, s % 60);
    if d > 0 { format!("{d}d {h:02}:{m:02}:{sec:02}") } else { format!("{h:02}:{m:02}:{sec:02}") }
}

fn fmt_local(ms: i64) -> String {
    Local.timestamp_millis_opt(ms).single().map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_else(|| ms.to_string())
}

fn ago(now: i64, then: i64) -> String {
    let s = (now - then).max(0) / 1000;
    match s {
        0..=59 => format!("{s}s ago"),
        60..=3599 => format!("{}m ago", s / 60),
        3600..=86399 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86400),
    }
}

fn show_state(v: &Value) -> Result<()> {
    let now = v["server_time_ms"].as_i64().unwrap_or(0);
    println!("Lock      {}", v["lock"].as_str().unwrap_or("?"));
    if let Some(t) = v["approval_expires_ms"].as_i64() {
        println!("Approval  expires in {}", fmt_span(t - now));
    }
    let timer = &v["timer"];
    match timer["kind"].as_str() {
        Some("running") => println!("Timer     running, {} left (ends {})", fmt_span(timer["remaining_ms"].as_i64().unwrap_or(0)), fmt_local(timer["ends_at_ms"].as_i64().unwrap_or(0))),
        Some("paused") => println!("Timer     paused with {} left", fmt_span(timer["remaining_ms"].as_i64().unwrap_or(0))),
        Some("ended") => println!("Timer     ended; the wearer may ask to be unlocked"),
        _ => println!("Timer     none"),
    }
    if let Some(c) = v["queued_command"]["command"].as_str() {
        println!("Queued    {c} (waiting for the pod to be reachable)");
    }
    match v["pod"]["checked_ms"].as_i64() {
        Some(t) => println!("Pod       last reached {} via {}", ago(now, t), v["pod"]["via"].as_str().unwrap_or("?")),
        None => println!("Pod       not reached yet; run `qiui-server sync`"),
    }
    if let Some(d) = v.get("paired_device").filter(|d| !d.is_null()) {
        let seen = d["last_seen_ms"].as_i64().map(|t| ago(now, t)).unwrap_or_else(|| "never".into());
        println!("Wearer    {} (last seen {seen})", d["name"].as_str().unwrap_or("?"));
    }
    if let Some(n) = v["rolled_secs"].as_i64() {
        println!("Rolled    {}", fmt_span(n * 1000));
    }
    Ok(())
}

/// "2d12h30m", "36h", "90m", "45s" or a bare number of seconds.
fn parse_duration_secs(input: &str) -> Result<i64> {
    let s = input.trim().to_ascii_lowercase();
    if let Ok(n) = s.parse::<i64>() {
        if n <= 0 {
            bail!("a duration must be more than zero");
        }
        return Ok(n);
    }
    let (mut total, mut digits) = (0i64, String::new());
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let n: i64 = digits.parse().map_err(|_| anyhow!("cannot read a duration from {input:?}; try 2d12h30m"))?;
        digits.clear();
        total += n * match c {
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => bail!("unknown unit {c:?} in {input:?}; use d, h, m or s"),
        };
    }
    if !digits.is_empty() || total == 0 {
        bail!("cannot read a duration from {input:?}; try 2d12h30m");
    }
    Ok(total)
}

// ---------- keyholder commands ----------

async fn status(cli: &Cli, auth: &PasswordArg) -> Result<()> {
    show_state(&kh(cli, auth, Method::GET, "/api/keyholder/state", None).await?)
}

async fn timer(cli: &Cli, auth: &PasswordArg, cmd: &TimerCmd) -> Result<()> {
    let (path, body) = match cmd {
        TimerCmd::Set { duration } => ("/api/keyholder/timer", Some(json!({ "duration_secs": parse_duration_secs(duration)? }))),
        TimerCmd::Roll { min, max } => {
            ("/api/keyholder/timer/roll", Some(json!({ "min_secs": parse_duration_secs(min)?, "max_secs": parse_duration_secs(max)? })))
        }
        TimerCmd::Pause => ("/api/keyholder/timer/pause", None),
        TimerCmd::Resume => ("/api/keyholder/timer/resume", None),
        TimerCmd::Clear => ("/api/keyholder/timer/clear", None),
    };
    show_state(&kh(cli, auth, Method::POST, path, body).await?)
}

async fn queue(cli: &Cli, auth: &PasswordArg, cmd: &QueueCmd) -> Result<()> {
    let (path, body) = match cmd {
        QueueCmd::Lock => ("/api/keyholder/queue", Some(json!({ "command": "lock" }))),
        QueueCmd::Unlock => ("/api/keyholder/queue", Some(json!({ "command": "unlock" }))),
        QueueCmd::Cancel => ("/api/keyholder/queue/cancel", None),
    };
    show_state(&kh(cli, auth, Method::POST, path, body).await?)
}

async fn audit(cli: &Cli, auth: &PasswordArg, limit: u32) -> Result<()> {
    let v = kh(cli, auth, Method::GET, &format!("/api/keyholder/audit?limit={limit}"), None).await?;
    if v["chain_intact"] != true {
        println!("WARNING: the audit log's hash chain is broken: it has been altered.\n");
    }
    for e in v["entries"].as_array().into_iter().flatten() {
        let detail = if e["detail"].as_object().is_some_and(|o| !o.is_empty()) { e["detail"].to_string() } else { String::new() };
        println!("{}  {:<10} {:<24} {detail}", fmt_local(e["ts_ms"].as_i64().unwrap_or(0)), e["actor"].as_str().unwrap_or("?"), e["kind"].as_str().unwrap_or("?"));
    }
    Ok(())
}

/// lock / unlock / sync: through the server if it is running, else directly over Bluetooth.
async fn pod_action(cli: &Cli, auth: &PasswordArg, what: &str) -> Result<()> {
    if let Some(srv) = Server::connect(cli, auth).await? {
        let out = srv.call(Method::POST, &format!("/api/keyholder/{what}"), None).await;
        let _ = srv.call(Method::POST, "/api/keyholder/logout", None).await;
        let v = out?;
        if what == "sync" && v["in_range"] == false {
            println!("The pod is not within range of the server.");
        }
        return show_state(&v);
    }
    eprintln!("(server not running at {}; talking to the pod directly)", cli.server);
    direct(cli, auth, what).await
}

// ---------- direct pod control, with the same rules as the API ----------

fn resolve_config(cli: &Cli) -> Result<(PathBuf, Config)> {
    let root = datadir::resolve(cli.data_dir.clone())?;
    let cfg = datadir::load_config(&root)?;
    Ok((root, cfg))
}

/// Client id from the config file, else QIUI_CLIENT_ID, else an old `.qiui_pod_env`.
fn credentials(cli: &Cli, cfg: &Config) -> Option<(String, String)> {
    let client_id = cfg
        .client_id
        .clone()
        .or_else(|| std::env::var("QIUI_CLIENT_ID").ok())
        .or_else(|| load_env(ENV_FILE).ok().and_then(|e| e.get("QIUI_CLIENT_ID").cloned()))?;
    let mac = cli.mac.clone().or_else(|| cfg.mac.clone()).unwrap_or_else(|| KNOWN_MAC.to_string());
    Some((client_id, mac))
}

async fn direct(cli: &Cli, auth: &PasswordArg, what: &str) -> Result<()> {
    let (_, cfg) = resolve_config(cli)?;
    let (client_id, mac) = credentials(cli, &cfg).ok_or_else(|| anyhow!("no QIUI client id configured. Run `qiui-server config set-client-id`."))?;
    let cloud = QiuiCloud::new(&client_id, &mac, cli.debug);
    let pod = BlePod { mac, debug: cli.debug };

    if what == "sync" {
        let status = pod.run(&cloud, PodOp::Status).await.map_err(|e| anyhow!("{e}"))?;
        println!("Reached the pod. Reply type {}, unlocking flag {}.", status.comment_type, status.is_unlocking);
        return Ok(());
    }

    let (mut store, args_auth) = open_store(cli)?;
    let now = system_now_ms();
    let password = secret(auth.password.clone(), "Keyholder password: ")?;
    match accounts::verify_password_throttled(store.connection(), &args_auth, &password, now) {
        Ok(()) => {}
        Err(AuthError::Invalid) => {
            store.log(now, "local-cli", "login_failed", &json!({}))?;
            bail!("wrong password");
        }
        Err(e) => return Err(e.into()),
    }
    let op = if what == "unlock" { PodOp::Unlock } else { PodOp::Lock };
    // Also applies time (a finished timer, a lapsed approval) before checking the rules.
    store
        .apply(now, |m| {
            if op == PodOp::Unlock { m.check_unlock(Actor::Keyholder, now) } else { m.check_lock(Actor::Keyholder) }.map(|()| Vec::new())
        })
        .map_err(rule_error)?;

    match pod.run(&cloud, op).await {
        Ok(_) => {}
        Err(PodError::ControlLost) => {
            store.log(system_now_ms(), "system", "control_lost", &json!({}))?;
            bail!("{}", PodError::ControlLost);
        }
        Err(e) => bail!("{e}"),
    }
    let now = system_now_ms();
    store.apply(now, |m| Ok(if op == PodOp::Unlock { m.record_unlocked(Actor::Keyholder, "direct") } else { m.record_locked(Actor::Keyholder, "direct") }))?;
    store.save_pod_status(now, "direct", None)?;
    println!("Done: the pod is {}.", if op == PodOp::Unlock { "unlocked" } else { "locked" });
    Ok(())
}

fn rule_error(e: ApplyError) -> anyhow::Error {
    match e {
        ApplyError::Rule(r) => anyhow!("refused: {r}"),
        ApplyError::Db(d) => anyhow!(d),
    }
}

// ---------- account administration (local shell only) ----------

fn open_store(cli: &Cli) -> Result<(Store, accounts::Auth)> {
    datadir::open(&datadir::resolve(cli.data_dir.clone())?)
}

fn init(cli: &Cli, password: Option<String>, pin: Option<String>) -> Result<()> {
    let (store, auth) = open_store(cli)?;
    if accounts::is_initialised(store.connection())? {
        bail!("a keyholder account already exists. Use `reset-password` if you have forgotten the password.");
    }
    if password.is_none() {
        println!("Choose a keyholder password (at least 10 characters). It is never stored; only a keyed hash is.");
    }
    let password = new_secret(password, "password")?;
    if pin.is_none() {
        println!("Choose a recovery PIN (6 to 12 digits). It is the only way to reset the password, and only from this machine.");
    }
    let pin = new_secret(pin, "recovery PIN")?;
    accounts::init_keyholder(store.connection(), &auth, &password, &pin)?;
    store.log(system_now_ms(), "local-cli", "keyholder_initialised", &json!({}))?;
    println!("Keyholder account created.");
    Ok(())
}

fn reset_password(cli: &Cli, pin: Option<String>, new_password: Option<String>) -> Result<()> {
    let (store, auth) = open_store(cli)?;
    let now = system_now_ms();
    let pin = secret(pin, "Recovery PIN: ")?;
    let new = new_secret(new_password, "password")?;
    match accounts::reset_password_with_pin(store.connection(), &auth, &pin, &new, now) {
        Ok(()) => {
            store.log(now, "local-cli", "password_reset", &json!({}))?;
            println!("Password reset. Every keyholder session was signed out.");
            Ok(())
        }
        Err(AuthError::Invalid) => {
            store.log(now, "local-cli", "password_reset_failed", &json!({}))?;
            bail!("that recovery PIN is not correct")
        }
        Err(e) => Err(e.into()),
    }
}

fn pairing_code(cli: &Cli) -> Result<()> {
    let (store, _) = open_store(cli)?;
    let now = system_now_ms();
    let code = accounts::create_pairing_code(store.connection(), now)?;
    store.log(now, "local-cli", "pairing_code_created", &json!({}))?;
    println!("Pairing code: {code}");
    println!("Valid for {} minutes, one use. A new code replaces this one.", accounts::PAIRING_CODE_TTL_MS / 60_000);
    Ok(())
}

fn devices(cli: &Cli) -> Result<()> {
    let (store, _) = open_store(cli)?;
    let list = accounts::list_devices(store.connection())?;
    if list.is_empty() {
        println!("No devices paired.");
    }
    for d in list {
        let state = if d.revoked_ms.is_some() { "revoked" } else { "active" };
        let seen = d.last_seen_ms.map(fmt_local).unwrap_or_else(|| "never".into());
        println!("{:>3}  {:<8} {:<20} paired {}  last seen {seen}", d.id, state, d.name, fmt_local(d.paired_ms));
    }
    Ok(())
}

fn revoke_device(cli: &Cli, id: i64) -> Result<()> {
    let (store, _) = open_store(cli)?;
    let now = system_now_ms();
    if !accounts::revoke_device(store.connection(), id, now)? {
        bail!("no active device with id {id}");
    }
    store.log(now, "local-cli", "device_revoked", &json!({ "id": id }))?;
    println!("Device {id} revoked.");
    Ok(())
}

// ---------- configuration ----------

fn mask(s: &str) -> String {
    if s.len() <= 6 { "*".repeat(s.len()) } else { format!("{}…{} ({} chars)", &s[..4], &s[s.len() - 2..], s.len()) }
}

fn config(cli: &Cli, cmd: &ConfigCmd) -> Result<()> {
    let (root, mut cfg) = resolve_config(cli)?;
    match cmd {
        ConfigCmd::Show => {
            println!("Data directory  {}", root.display());
            println!("Client id       {}", cfg.client_id.as_deref().map(mask).unwrap_or_else(|| "not set".into()));
            println!("API key         {}", cfg.api_key.as_deref().map(mask).unwrap_or_else(|| "not set".into()));
            println!("Pod address     {}", cfg.mac.as_deref().unwrap_or("not set (using the built-in default)"));
            println!("Push contact    {}", cfg.push_contact.as_deref().unwrap_or("not set (using a placeholder)"));
            return Ok(());
        }
        ConfigCmd::SetClientId { value } => cfg.client_id = Some(secret(value.clone(), "QIUI client id: ")?.trim().to_string()),
        ConfigCmd::SetApiKey { value } => cfg.api_key = Some(secret(value.clone(), "QIUI API key: ")?.trim().to_string()),
        ConfigCmd::SetMac { mac } => cfg.mac = Some(mac.trim().to_ascii_uppercase()),
        ConfigCmd::SetPushContact { contact } => cfg.push_contact = Some(contact.trim().to_string()),
        ConfigCmd::ImportEnv { path } => {
            let env = load_env(path.clone().unwrap_or_else(|| PathBuf::from(ENV_FILE)))?;
            cfg.client_id = env.get("QIUI_CLIENT_ID").cloned().or(cfg.client_id);
            cfg.api_key = env.get("QIUI_PROD_API_KEY").cloned().or(cfg.api_key);
        }
    }
    datadir::save_config(&root, &cfg)?;
    println!("Saved. Restart a running server for the change to take effect.");
    Ok(())
}

// ---------- server ----------

async fn serve(cli: &Cli, bind: SocketAddr, allow_remote: bool, simulate: bool, sim_in_range: bool) -> Result<()> {
    if !bind.ip().is_loopback() && !allow_remote {
        bail!("{bind} is not a loopback address and this server speaks plain HTTP. Bind 127.0.0.1 behind TLS (e.g. `tailscale serve`), or pass --allow-remote if you know what you are doing.");
    }
    let (store, auth) = open_store(cli)?;
    if !accounts::is_initialised(store.connection())? {
        eprintln!("Note: no keyholder account yet. Run `qiui-server init` first.");
    }
    let (root, cfg) = resolve_config(cli)?;
    let (cloud, pod, real_cloud, mac): (Arc<dyn Cloud>, Arc<dyn PodLink>, Option<Arc<QiuiCloud>>, String) = if simulate {
        eprintln!("\n*** DEMO MODE: the pod is simulated. Nothing here touches a real pod or QIUI. ***\n");
        (Arc::new(SimulatedCloud), Arc::new(SimulatedPod { in_range: sim_in_range }), None, "simulated".to_string())
    } else {
        match credentials(cli, &cfg) {
            Some((client_id, mac)) => {
                let c = Arc::new(QiuiCloud::new(&client_id, &mac, cli.debug));
                (c.clone(), Arc::new(BlePod { mac: mac.clone(), debug: cli.debug }), Some(c), mac)
            }
            None => {
                eprintln!("Note: no QIUI client id configured, so the pod cannot be controlled yet. Run `qiui-server config set-client-id`.");
                let mac = cli.mac.clone().unwrap_or_else(|| KNOWN_MAC.to_string());
                (Arc::new(UnconfiguredCloud), Arc::new(BlePod { mac: mac.clone(), debug: cli.debug }), None, mac)
            }
        }
    };

    // Push notifications: the server's VAPID identity, and a worker that turns audit events into pushes.
    let vapid = Arc::new(Vapid::load_or_create(&root)?);
    let state = AppState::new(store, auth, Hardware::new(cloud, pod)).with_push_key(vapid.public_key().to_string());
    let sender = HttpPushSender::new(vapid, cfg.push_contact.as_deref().unwrap_or(DEFAULT_CONTACT));
    let push_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            push::notify_once(&push_state, &sender).await;
        }
    });

    // Carry out the keyholder's queued command as soon as the pod is in range.
    let queue_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(45)).await;
            if api::run_queue_once(&queue_state).await {
                println!("Queued command carried out.");
            }
        }
    });

    // Keep QIUI's 12-hour platform token fresh, and tell the audit log if that ever stops working.
    if let Some(qiui) = real_cloud {
        let token_state = state.clone();
        tokio::spawn(async move {
            let mut healthy = true;
            loop {
                match qiui.refresh_token_if_needed().await {
                    Ok(_) if !healthy => {
                        healthy = true;
                        api::audit_event(&token_state, "system", "platform_token_recovered", json!({})).await;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("QIUI platform token: {e}");
                        if healthy {
                            healthy = false;
                            api::audit_event(&token_state, "system", "platform_token_failed", json!({ "error": e.to_string() })).await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(10 * 60)).await;
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("binding {bind}"))?;
    println!("Listening on http://{bind} for pod {mac}  (Ctrl-C to stop)");
    println!("The wearer's app is served at the same address.");
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

// ---------- discovery ----------

async fn identify() -> Result<()> {
    println!("Scanning for BLE devices...");
    let devices = ble::scan().await?;
    let matches: Vec<_> = devices.iter().filter(|(a, _)| a.starts_with(MAC_PREFIX)).collect();
    println!("Found {} device(s), {} matching prefix {MAC_PREFIX}", devices.len(), matches.len());
    let candidates: Vec<_> = if matches.is_empty() { devices.iter().collect() } else { matches };
    for (addr, p) in candidates {
        if let Err(e) = ble::identify(addr, p).await {
            println!("  Error: {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_in_the_forms_people_type() {
        assert_eq!(parse_duration_secs("14d").unwrap(), 14 * 86_400);
        assert_eq!(parse_duration_secs("2d12h30m").unwrap(), 2 * 86_400 + 12 * 3_600 + 30 * 60);
        assert_eq!(parse_duration_secs("90m").unwrap(), 5_400);
        assert_eq!(parse_duration_secs(" 45S ").unwrap(), 45);
        assert_eq!(parse_duration_secs("3600").unwrap(), 3_600);
    }

    #[test]
    fn nonsense_durations_are_rejected() {
        for bad in ["", "abc", "5x", "d", "10m5", "0", "0h", "-5"] {
            assert!(parse_duration_secs(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn spans_are_readable() {
        assert_eq!(fmt_span(13 * 86_400_000 + 51 * 60_000 + 12_000), "13d 00:51:12");
        assert_eq!(fmt_span(90_000), "00:01:30");
        assert_eq!(fmt_span(-5), "00:00:00");
    }

    #[test]
    fn secrets_are_masked() {
        assert_eq!(mask("abc"), "***");
        assert_eq!(mask("Client_35115347524B"), "Clie…4B (19 chars)");
    }
}
