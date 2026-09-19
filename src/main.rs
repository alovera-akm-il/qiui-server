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
use qiui_server::cloud::{Cloud, LazyCloud, QiuiCloud, SimulatedCloud, UnconfiguredCloud};
use qiui_server::datadir::{self, Config};
use qiui_server::hardware::Hardware;
use qiui_server::machine::Actor;
use qiui_server::pod::{BlePod, PodError, PodLink, PodOp, SimulatedPod};
use qiui_server::secrets::SealedSecrets;
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
    /// Accepted anywhere on the line, so `timer set 1h --password …` works as well as `timer --password … set 1h`.
    #[arg(long, env = "QIUI_KEYHOLDER_PASSWORD", hide_env_values = true, global = true)]
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
    /// Run the HTTP API and the wearer's app. Listens on every network interface by default, in plain HTTP.
    Serve {
        #[arg(long, default_value = "0.0.0.0:8443")]
        bind: SocketAddr,
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
    /// Print a one-time code to pair the wearer's device (needs the keyholder password)
    PairingCode(PasswordArg),
    /// List paired wearer devices (needs the keyholder password)
    Devices(PasswordArg),
    /// Sign a wearer device out and forbid it from reconnecting (needs the keyholder password)
    RevokeDevice {
        id: i64,
        #[command(flatten)]
        auth: PasswordArg,
    },
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
    /// Add time to the running or paused timer, e.g. 2h. With no timer running it starts one.
    Add { duration: String },
    /// Add a random amount between MIN and MAX to the timer (the wearer never sees how much)
    AddRoll { min: String, max: String },
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
    /// Show what is configured (nothing secret is displayed)
    Show(PasswordArg),
    /// Set the QIUI client id. It is stored encrypted, under your keyholder password.
    SetClientId {
        #[arg(env = "QIUI_CLIENT_ID", hide_env_values = true)]
        value: Option<String>,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// Set the QIUI API key. It is stored encrypted, under your keyholder password.
    SetApiKey {
        #[arg(env = "QIUI_API_KEY", hide_env_values = true)]
        value: Option<String>,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// Set the pod's Bluetooth address
    SetMac {
        mac: String,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// Set the contact address push services can use (mailto:you@example.com)
    SetPushContact {
        contact: String,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// How many wearer devices may be paired at once (1 to 5; the default is 2)
    SetMaxDevices {
        count: i64,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// Import QIUI_CLIENT_ID / QIUI_PROD_API_KEY from an old .qiui_pod_env file (stored encrypted)
    ImportEnv {
        path: Option<PathBuf>,
        #[command(flatten)]
        auth: PasswordArg,
    },
    /// Encrypt credentials that an older version left in config.json as plain text
    Encrypt(PasswordArg),
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
        Action::Serve { bind, simulate_pod, simulate_out_of_range } => serve(&cli, *bind, *simulate_pod, !*simulate_out_of_range).await,
        Action::Init { password, pin } => init(&cli, password.clone(), pin.clone()),
        Action::ResetPassword { pin, new_password } => reset_password(&cli, pin.clone(), new_password.clone()),
        Action::PairingCode(a) => pairing_code(&cli, a),
        Action::Devices(a) => devices(&cli, a),
        Action::RevokeDevice { id, auth } => revoke_device(&cli, auth, *id),
        Action::Config { cmd } => config(&cli, cmd),
        Action::Identify => identify().await,
    }
}

// ---------- secrets on the command line ----------

/// A secret given up front (flag or environment variable) is used as is; otherwise ask, hidden.
fn secret(given: Option<String>, prompt: &str) -> Result<String> {
    match given {
        Some(s) => Ok(s),
        None => ask_hidden(prompt),
    }
}

/// A hidden prompt. When there is no terminal (a script, a service) say what to do instead.
fn ask_hidden(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt)
        .map_err(|e| anyhow!("cannot ask for that here ({e}). Run this in a terminal, or supply it with the QIUI_* environment variable or its flag."))
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
    let first = ask_hidden(&format!("New {what}: "))?;
    let second = ask_hidden(&format!("Repeat {what}: "))?;
    if first != second {
        bail!("the two entries did not match");
    }
    Ok(first)
}

// ---------- talking to the running server ----------

/// The server answered, but is too busy checking passwords to take another sign-in right now.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct ServerBusy(String);

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
            let message = body["error"].as_str().unwrap_or("sign-in failed").to_string();
            if body["code"] == "busy" {
                return Err(ServerBusy(message).into());
            }
            bail!("{message}");
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
    for d in v["paired_devices"].as_array().into_iter().flatten() {
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
        TimerCmd::Add { duration } => ("/api/keyholder/timer/add", Some(json!({ "duration_secs": parse_duration_secs(duration)? }))),
        TimerCmd::AddRoll { min, max } => {
            ("/api/keyholder/timer/add-roll", Some(json!({ "min_secs": parse_duration_secs(min)?, "max_secs": parse_duration_secs(max)? })))
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
    // Failed attempts folded into the next row: shown here at once, so a burst is never hidden.
    for p in v["pending_failures"].as_array().into_iter().flatten() {
        let since = p["since_ms"].as_i64().map(fmt_local).unwrap_or_default();
        println!(
            "        pending  {:<10} {:<24} +{} more since {since} (summary row follows within about 35 s)",
            p["actor"].as_str().unwrap_or("?"),
            p["kind"].as_str().unwrap_or("?"),
            p["count"]
        );
    }
    for e in v["entries"].as_array().into_iter().flatten() {
        let detail = if e["detail"].as_object().is_some_and(|o| !o.is_empty()) { e["detail"].to_string() } else { String::new() };
        println!("{}  {:<10} {:<24} {detail}", fmt_local(e["ts_ms"].as_i64().unwrap_or(0)), e["actor"].as_str().unwrap_or("?"), e["kind"].as_str().unwrap_or("?"));
    }
    Ok(())
}

/// lock / unlock / sync: through the server if it is running, else directly over Bluetooth.
async fn pod_action(cli: &Cli, auth: &PasswordArg, what: &str) -> Result<()> {
    match Server::connect(cli, auth).await {
        Ok(Some(srv)) => {
            let out = srv.call(Method::POST, &format!("/api/keyholder/{what}"), None).await;
            let _ = srv.call(Method::POST, "/api/keyholder/logout", None).await;
            let v = out?;
            if what == "sync" && v["in_range"] == false {
                println!("The pod is not within range of the server.");
            }
            show_state(&v)
        }
        Ok(None) => {
            eprintln!("(server not running at {}; talking to the pod directly)", cli.server);
            direct(cli, auth, what).await
        }
        // A flood of guesses can crowd out sign-ins over the network. Lock, unlock and sync must still work
        // from this machine, so go to the pod directly (with the same password check and the same rules).
        Err(e) if e.downcast_ref::<ServerBusy>().is_some() => {
            eprintln!("(the server is busy checking passwords; talking to the pod directly)");
            direct(cli, auth, what).await
        }
        Err(e) => Err(e),
    }
}

// ---------- direct pod control, with the same rules as the API ----------

fn resolve_config(cli: &Cli) -> Result<(PathBuf, Config)> {
    let root = datadir::resolve(cli.data_dir.clone())?;
    let cfg = datadir::load_config(&root)?;
    Ok((root, cfg))
}

/// Where the QIUI client id comes from.
enum CredentialSource {
    /// Encrypted in config.json: needs the keyholder's password to open.
    Sealed(SealedSecrets),
    /// Plain text: an old config.json, QIUI_CLIENT_ID, or an old `.qiui_pod_env`.
    Plain(String),
    None,
}

fn credential_source(cfg: &Config) -> CredentialSource {
    if let Some(sealed) = &cfg.secrets {
        return CredentialSource::Sealed(sealed.clone());
    }
    cfg.client_id
        .clone()
        .or_else(|| std::env::var("QIUI_CLIENT_ID").ok())
        .or_else(|| load_env(ENV_FILE).ok().and_then(|e| e.get("QIUI_CLIENT_ID").cloned()))
        .map_or(CredentialSource::None, CredentialSource::Plain)
}

fn pod_mac(cli: &Cli, cfg: &Config) -> String {
    cli.mac.clone().or_else(|| cfg.mac.clone()).unwrap_or_else(|| KNOWN_MAC.to_string())
}

/// Ask for (or take) the keyholder password and check it, counting failures toward the lockout.
fn verify_keyholder(store: &Store, auth: &accounts::Auth, given: Option<String>) -> Result<String> {
    let now = system_now_ms();
    let password = secret(given, "Keyholder password: ")?;
    match accounts::verify_password(store.connection(), auth, &password) {
        Ok(()) => Ok(password),
        Err(AuthError::Invalid) => {
            store.log_failure(now, "local-cli", "login_failed")?;
            bail!("wrong password")
        }
        Err(e) => Err(e.into()),
    }
}

async fn direct(cli: &Cli, auth: &PasswordArg, what: &str) -> Result<()> {
    let (_, cfg) = resolve_config(cli)?;
    let (mut store, auth_obj) = open_store(cli)?;
    let mac = pod_mac(cli, &cfg);

    // Lock and unlock always need the password. `sync` needs it only to open encrypted credentials.
    let source = credential_source(&cfg);
    let password = if what != "sync" || matches!(source, CredentialSource::Sealed(_)) {
        Some(verify_keyholder(&store, &auth_obj, auth.password.clone())?)
    } else {
        None
    };
    let client_id = match source {
        CredentialSource::Sealed(sealed) => {
            let opened = qiui_server::secrets::open(&auth_obj, password.as_deref().unwrap_or_default(), &sealed)
                .map_err(|e| anyhow!("{e}. If you reset the password with the recovery PIN, run `qiui-server config set-client-id` again."))?;
            opened.client_id.clone().ok_or_else(|| anyhow!("no QIUI client id stored. Run `qiui-server config set-client-id`."))?
        }
        CredentialSource::Plain(id) => id,
        CredentialSource::None => bail!("no QIUI client id configured. Run `qiui-server config set-client-id`."),
    };
    let cloud = QiuiCloud::new(&client_id, &mac, cli.debug);
    let pod = BlePod { mac, debug: cli.debug };

    if what == "sync" {
        let status = pod.run(&cloud, PodOp::Status).await.map_err(|e| anyhow!("{e}"))?;
        println!("Reached the pod. Reply type {}, unlocking flag {}.", status.comment_type, status.is_unlocking);
        return Ok(());
    }

    let now = system_now_ms();
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
            // The QIUI credentials are encrypted under the old password, and a recovery PIN is far too weak
            // to protect them, so they cannot be carried over.
            if datadir::clear_sealed(&datadir::resolve(cli.data_dir.clone())?)? {
                store.log(now, "local-cli", "credentials_cleared", &json!({}))?;
                println!("The encrypted QIUI credentials could not be carried over to the new password and were removed.");
                println!("Enter them again: qiui-server config set-client-id");
            }
            Ok(())
        }
        Err(AuthError::Invalid) => {
            store.log_failure(now, "local-cli", "password_reset_failed")?;
            bail!("that recovery PIN is not correct")
        }
        Err(e) => Err(e.into()),
    }
}

/// Everything that touches the account or its settings needs the keyholder password. The exceptions
/// are `init` (no account exists yet), `reset-password` (the recovery route), `serve` and `identify`.
fn require_keyholder(cli: &Cli, auth: &PasswordArg) -> Result<(Store, accounts::Auth)> {
    let (store, auth_obj) = open_store(cli)?;
    verify_keyholder(&store, &auth_obj, auth.password.clone())?;
    Ok((store, auth_obj))
}

fn pairing_code(cli: &Cli, auth: &PasswordArg) -> Result<()> {
    let (store, _) = require_keyholder(cli, auth)?;
    let now = system_now_ms();
    let code = accounts::create_pairing_code(store.connection(), now)?;
    store.log(now, "local-cli", "pairing_code_created", &json!({}))?;
    println!("Pairing code: {code}");
    println!("Valid for {} minutes, one use. A new code replaces this one.", accounts::PAIRING_CODE_TTL_MS / 60_000);
    Ok(())
}

fn devices(cli: &Cli, auth: &PasswordArg) -> Result<()> {
    let (store, _) = require_keyholder(cli, auth)?;
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

fn revoke_device(cli: &Cli, auth: &PasswordArg, id: i64) -> Result<()> {
    let (store, _) = require_keyholder(cli, auth)?;
    let now = system_now_ms();
    if !accounts::revoke_device(store.connection(), id, now)? {
        bail!("no active device with id {id}");
    }
    store.log(now, "local-cli", "device_revoked", &json!({ "id": id }))?;
    println!("Device {id} revoked.");
    Ok(())
}

// ---------- configuration ----------

fn config(cli: &Cli, cmd: &ConfigCmd) -> Result<()> {
    let (root, mut cfg) = resolve_config(cli)?;
    match cmd {
        ConfigCmd::Show(auth) => {
            require_keyholder(cli, auth)?;
            println!("Data directory    {}", root.display());
            let credentials = if cfg.secrets.is_some() {
                "encrypted (opened in memory when the keyholder signs in)"
            } else if cfg.has_plain_secrets() {
                "STORED IN PLAIN TEXT. Run `qiui-server config encrypt`."
            } else {
                "not set"
            };
            println!("QIUI credentials  {credentials}");
            println!("Pod address       {}", cfg.mac.as_deref().unwrap_or("not set (using the built-in default)"));
            println!("Push contact      {}", cfg.push_contact.as_deref().unwrap_or("not set (using a placeholder)"));
            let (store, _) = open_store(cli)?;
            println!("Paired devices    up to {}", accounts::max_devices(store.connection())?);
            Ok(())
        }
        ConfigCmd::SetMac { mac, auth } => {
            require_keyholder(cli, auth)?;
            cfg.mac = Some(mac.trim().to_ascii_uppercase());
            save_plain(&root, &cfg)
        }
        ConfigCmd::SetPushContact { contact, auth } => {
            require_keyholder(cli, auth)?;
            cfg.push_contact = Some(contact.trim().to_string());
            save_plain(&root, &cfg)
        }
        ConfigCmd::SetMaxDevices { count, auth } => {
            let (store, _) = require_keyholder(cli, auth)?;
            accounts::set_max_devices(store.connection(), *count)?;
            store.log(system_now_ms(), "local-cli", "max_devices_changed", &json!({ "max": count }))?;
            println!("Up to {count} wearer device(s) may now be paired. Takes effect immediately.");
            Ok(())
        }
        ConfigCmd::SetClientId { value, auth } => {
            let id = secret(value.clone(), "QIUI client id: ")?.trim().to_string();
            seal_credentials(cli, &root, &mut cfg, auth, |s| s.client_id = Some(id))
        }
        ConfigCmd::SetApiKey { value, auth } => {
            let key = secret(value.clone(), "QIUI API key: ")?.trim().to_string();
            seal_credentials(cli, &root, &mut cfg, auth, |s| s.api_key = Some(key))
        }
        ConfigCmd::ImportEnv { path, auth } => {
            let env = load_env(path.clone().unwrap_or_else(|| PathBuf::from(ENV_FILE)))?;
            let (id, key) = (env.get("QIUI_CLIENT_ID").cloned(), env.get("QIUI_PROD_API_KEY").cloned());
            seal_credentials(cli, &root, &mut cfg, auth, |s| {
                s.client_id = id.or(s.client_id.take());
                s.api_key = key.or(s.api_key.take());
            })
        }
        ConfigCmd::Encrypt(auth) => {
            if !cfg.has_plain_secrets() {
                require_keyholder(cli, auth)?;
                println!("Nothing to encrypt: no credentials are stored in plain text.");
                return Ok(());
            }
            seal_credentials(cli, &root, &mut cfg, auth, |_| {})
        }
    }
}

fn save_plain(root: &std::path::Path, cfg: &Config) -> Result<()> {
    datadir::save_config(root, cfg)?;
    println!("Saved. Restart a running server for the change to take effect.");
    Ok(())
}

/// Change the stored QIUI credentials. They are always written encrypted, under the keyholder's
/// password, and any plain-text copy left by an older version is removed in the same write.
fn seal_credentials(cli: &Cli, root: &std::path::Path, cfg: &mut Config, auth: &PasswordArg, edit: impl FnOnce(&mut qiui_server::secrets::Secrets)) -> Result<()> {
    let (store, auth_obj) = open_store(cli)?;
    if !accounts::is_initialised(store.connection())? {
        bail!("create the keyholder account first (`qiui-server init`): the credentials are encrypted under its password.");
    }
    let password = verify_keyholder(&store, &auth_obj, auth.password.clone())?;
    let mut secrets = cfg.secrets(&auth_obj, &password).map_err(|e| anyhow!("{e}"))?;
    edit(&mut secrets);
    cfg.seal_secrets(&auth_obj, &password, &secrets).map_err(|e| anyhow!("{e}"))?;
    datadir::save_config(root, cfg)?;
    store.log(system_now_ms(), "local-cli", "credentials_sealed", &json!({}))?;
    println!("Saved, encrypted under your keyholder password. Restart a running server for the change to take effect.");
    Ok(())
}

// ---------- server ----------

async fn serve(cli: &Cli, bind: SocketAddr, simulate: bool, sim_in_range: bool) -> Result<()> {
    let (store, auth) = open_store(cli)?;
    if !accounts::is_initialised(store.connection())? {
        eprintln!("Note: no keyholder account yet. Run `qiui-server init` first.");
    }
    let (root, cfg) = resolve_config(cli)?;
    let (cloud, pod, vault, mac): (Arc<dyn Cloud>, Arc<dyn PodLink>, Option<Arc<LazyCloud>>, String) = if simulate {
        eprintln!("\n*** DEMO MODE: the pod is simulated. Nothing here touches a real pod or QIUI. ***\n");
        (Arc::new(SimulatedCloud), Arc::new(SimulatedPod { in_range: sim_in_range }), None, "simulated".to_string())
    } else {
        let mac = pod_mac(cli, &cfg);
        let pod: Arc<dyn PodLink> = Arc::new(BlePod { mac: mac.clone(), debug: cli.debug });
        match credential_source(&cfg) {
            CredentialSource::Sealed(sealed) => {
                eprintln!("The QIUI credentials are encrypted. Pod control unlocks the first time the keyholder signs in (any keyholder command does it).");
                let v = Arc::new(LazyCloud::sealed(sealed, &mac, cli.debug));
                (v.clone(), pod, Some(v), mac)
            }
            CredentialSource::Plain(id) => {
                if cfg.has_plain_secrets() {
                    eprintln!("Warning: the QIUI credentials are stored in plain text. Run `qiui-server config encrypt`.");
                }
                let v = Arc::new(LazyCloud::unlocked(Arc::new(QiuiCloud::new(&id, &mac, cli.debug))));
                (v.clone(), pod, Some(v), mac)
            }
            CredentialSource::None => {
                eprintln!("Note: no QIUI client id configured, so the pod cannot be controlled yet. Run `qiui-server config set-client-id`.");
                (Arc::new(UnconfiguredCloud), pod, None, mac)
            }
        }
    };

    // Push notifications: the server's VAPID identity, and a worker that turns audit events into pushes.
    let vapid = Arc::new(Vapid::load_or_create(&root)?);
    let mut state = AppState::new(store, auth, Hardware::new(cloud, pod)).with_push_key(vapid.public_key().to_string());
    if let Some(v) = &vault {
        state = state.with_vault(v.clone(), root.clone());
    }
    let sender = HttpPushSender::new(vapid, cfg.push_contact.as_deref().unwrap_or(DEFAULT_CONTACT));
    let push_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            push::notify_once(&push_state, &sender).await;
        }
    });

    // Write the summary row for a burst of failed attempts as soon as its window closes.
    let failure_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            api::flush_failure_summaries(&failure_state).await;
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
    if let Some(qiui) = vault {
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
    if !bind.ip().is_loopback() {
        // Plain HTTP on more than this machine: say so, once, where it will be seen.
        eprintln!(
            "Note: {bind} is plain HTTP, reachable from {}. Passwords and tokens are not encrypted on that path; use an HTTPS front (your Tailscale address) for anything remote.",
            if bind.ip().is_unspecified() { "every network interface (LAN and Tailscale)" } else { "that address" }
        );
    }
    println!("The wearer's app is served at the same address.");
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Resolves on Ctrl-C or, under a service manager, SIGTERM, so a stop lets requests finish and the database close.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
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

    /// The password given by flag, wherever it is placed, for every command that takes one.
    #[test]
    fn the_password_flag_works_before_or_after_the_subcommand_on_every_keyholder_command() {
        fn password_of(args: &[&str]) -> Option<String> {
            let cli = Cli::try_parse_from(std::iter::once("qiui-server").chain(args.iter().copied())).unwrap_or_else(|e| panic!("{args:?}: {e}"));
            match cli.action {
                Action::Status(a) | Action::Deny(a) | Action::Lock(a) | Action::Unlock(a) | Action::Sync(a) | Action::PairingCode(a) | Action::Devices(a) => a.password,
                Action::Approve { auth, .. } | Action::Message { auth, .. } | Action::Audit { auth, .. } | Action::RevokeDevice { auth, .. } => auth.password,
                Action::Timer { auth, .. } | Action::Queue { auth, .. } => auth.password,
                Action::Config { cmd } => match cmd {
                    ConfigCmd::SetClientId { auth, .. } | ConfigCmd::SetApiKey { auth, .. } | ConfigCmd::ImportEnv { auth, .. } | ConfigCmd::Encrypt(auth) => auth.password,
                    ConfigCmd::Show(auth) | ConfigCmd::SetMac { auth, .. } | ConfigCmd::SetPushContact { auth, .. } | ConfigCmd::SetMaxDevices { auth, .. } => auth.password,
                },
                _ => panic!("{args:?}: not a command with a password"),
            }
        }
        let with_flag: &[&[&str]] = &[
            &["status"], &["approve"], &["approve", "--minutes", "5"], &["deny"], &["lock"], &["unlock"], &["sync"],
            &["timer", "set", "1h"], &["timer", "roll", "1h", "2h"], &["timer", "add", "1h"], &["timer", "add-roll", "1h", "2h"],
            &["timer", "pause"], &["timer", "resume"], &["timer", "clear"],
            &["message", "hello"], &["audit"], &["audit", "--limit", "5"],
            &["queue", "lock"], &["queue", "unlock"], &["queue", "cancel"],
            &["pairing-code"], &["devices"], &["revoke-device", "3"],
            &["config", "show"], &["config", "set-mac", "AA:BB"], &["config", "set-push-contact", "mailto:a@b.c"], &["config", "set-max-devices", "2"],
            &["config", "set-client-id", "Client_x"], &["config", "set-api-key", "key"], &["config", "import-env"], &["config", "encrypt"],
        ];
        for base in with_flag {
            // After the whole command...
            let mut after: Vec<&str> = base.to_vec();
            after.extend(["--password", "pw"]);
            assert_eq!(password_of(&after).as_deref(), Some("pw"), "{after:?}");
            // ...and, for commands with subcommands, right after the command word (`config`'s
            // subcommands each own their flag, so only "after" applies there).
            if base[0] != "config" {
                let mut before: Vec<&str> = vec![base[0], "--password", "pw"];
                before.extend(&base[1..]);
                assert_eq!(password_of(&before).as_deref(), Some("pw"), "{before:?}");
            }
        }
    }

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
}
