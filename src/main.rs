use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::json;

use qiui_server::accounts::{self, AuthError};
use qiui_server::api::{self, AppState, system_now_ms};
use qiui_server::ble::{self, KNOWN_MAC, KeyPod, MAC_PREFIX};
use qiui_server::client::{self, ENV_FILE, QiuiClient, load_env};
use qiui_server::datadir;
use qiui_server::machine::Actor;
use qiui_server::store::{ApplyError, Store};

#[derive(Parser)]
#[command(about = "QIUI KeyPod keyholder server")]
struct Cli {
    /// Print every raw HTTP response and BLE payload
    #[arg(long, global = true)]
    debug: bool,
    /// KeyPod Bluetooth MAC address
    #[arg(long, global = true, default_value = KNOWN_MAC)]
    mac: String,
    /// Where the database and pepper key live (default: $QIUI_DATA_DIR or ~/.local/share/qiui-server)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Scan BLE and report which devices are KeyPods (no cloud calls)
    Identify,
    /// Connect and report the pod's state
    Status,
    /// Lock the pod (needs the keyholder password)
    Lock(PasswordArg),
    /// Unlock the pod (needs the keyholder password; refused while a timer is running or paused)
    Unlock(PasswordArg),
    /// Run the HTTP API
    Serve {
        #[arg(long, default_value = "127.0.0.1:8443")]
        bind: SocketAddr,
        /// Allow binding a non-loopback address. The server speaks plain HTTP; put it behind TLS (e.g. `tailscale serve`).
        #[arg(long)]
        allow_remote: bool,
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
}

/// Keyholder password for commands that act on the pod. Omit it to be prompted.
#[derive(Args)]
struct PasswordArg {
    /// Keyholder password. Visible in `ps` and shell history; prefer QIUI_KEYHOLDER_PASSWORD.
    #[arg(long, env = "QIUI_KEYHOLDER_PASSWORD", hide_env_values = true)]
    password: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Hardware {
    Status,
    Lock,
    Unlock,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    warn_if_secret_on_command_line();
    match &cli.action {
        Action::Identify => identify().await,
        Action::Status => hardware(&cli, Hardware::Status, None).await,
        Action::Lock(a) => hardware(&cli, Hardware::Lock, a.password.clone()).await,
        Action::Unlock(a) => hardware(&cli, Hardware::Unlock, a.password.clone()).await,
        Action::Serve { bind, allow_remote } => serve(&cli, *bind, *allow_remote).await,
        Action::Init { password, pin } => init(&cli, password.clone(), pin.clone()),
        Action::ResetPassword { pin, new_password } => reset_password(&cli, pin.clone(), new_password.clone()),
        Action::PairingCode => pairing_code(&cli),
        Action::Devices => devices(&cli),
        Action::RevokeDevice { id } => revoke_device(&cli, *id),
    }
}

// ---------- account administration (local shell only) ----------

fn open_store(cli: &Cli) -> Result<(Store, accounts::Auth)> {
    datadir::open(&datadir::resolve(cli.data_dir.clone())?)
}

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
        println!("{:>3}  {:<8} {}  paired_ms={} last_seen_ms={:?}", d.id, state, d.name, d.paired_ms, d.last_seen_ms);
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

// ---------- server ----------

async fn serve(cli: &Cli, bind: SocketAddr, allow_remote: bool) -> Result<()> {
    if !bind.ip().is_loopback() && !allow_remote {
        bail!("{bind} is not a loopback address and this server speaks plain HTTP. Bind 127.0.0.1 behind TLS (e.g. `tailscale serve`), or pass --allow-remote if you know what you are doing.");
    }
    let (store, auth) = open_store(cli)?;
    if !accounts::is_initialised(store.connection())? {
        eprintln!("Note: no keyholder account yet. Run `qiui-server init` first.");
    }
    let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("binding {bind}"))?;
    println!("Listening on http://{bind}  (Ctrl-C to stop)");
    axum::serve(listener, api::router(AppState::new(store, auth)))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

// ---------- hardware ----------

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

/// Lock and unlock need the keyholder password, obey the same rules as the API
/// (no unlocking under a timer), and are written to the audit log.
async fn hardware(cli: &Cli, action: Hardware, password: Option<String>) -> Result<()> {
    if action == Hardware::Status {
        return control(cli, action).await;
    }
    let (mut store, auth) = open_store(cli)?;
    let now = system_now_ms();
    let password = secret(password, "Keyholder password: ")?;
    match accounts::verify_password_throttled(store.connection(), &auth, &password, now) {
        Ok(()) => {}
        Err(AuthError::Invalid) => {
            store.log(now, "local-cli", "login_failed", &json!({}))?;
            bail!("wrong password");
        }
        Err(e) => return Err(e.into()),
    }

    if action == Hardware::Unlock {
        // Also applies time (a finished timer or lapsed approval) before checking the rules.
        store.apply(now, |m| m.check_unlock(Actor::Keyholder, now).map(|()| Vec::new())).map_err(rule_error)?;
    }

    control(cli, action).await?;

    let now = system_now_ms();
    store.apply(now, |m| {
        Ok(if action == Hardware::Unlock { m.record_unlocked(Actor::Keyholder) } else { m.record_locked(Actor::Keyholder) })
    })?;
    Ok(())
}

fn rule_error(e: ApplyError) -> anyhow::Error {
    match e {
        ApplyError::Rule(r) => anyhow::anyhow!("refused: {r}"),
        ApplyError::Db(d) => anyhow::anyhow!(d),
    }
}

async fn control(cli: &Cli, action: Hardware) -> Result<()> {
    let env = load_env(ENV_FILE)?;
    let client_id = env.get("QIUI_CLIENT_ID").ok_or_else(|| anyhow::anyhow!("QIUI_CLIENT_ID missing in {ENV_FILE}"))?;
    let mut client = QiuiClient::new(client_id, cli.debug);

    println!("Getting platform API token...");
    client.get_platform_token().await?;

    println!("Binding/looking up device {}...", cli.mac);
    let dev = client.ensure_bound(&cli.mac).await?;
    println!("  serialNumber={} typeId={}", dev.serial_number, dev.type_id);

    println!("Connecting over BLE...");
    let mut pod = KeyPod::connect(&cli.mac, cli.debug).await?;
    let result = run(&client, &mut pod, &cli.mac, &dev, action).await;
    pod.disconnect().await.ok();
    result
}

async fn run(client: &QiuiClient, pod: &mut KeyPod, mac: &str, dev: &client::DeviceInfo, action: Hardware) -> Result<()> {
    println!("Performing device-token handshake...");
    let reply = pod.write_hex(&client.device_token_cmd(mac, dev).await?).await?;
    let status = client.decrypt_reply(&reply, dev).await?;
    println!("  Device status: {status:?}");

    let cmd = match action {
        Hardware::Unlock => client.unlock_cmd(mac, dev).await?,
        Hardware::Lock => client.lock_cmd(mac, dev).await?,
        Hardware::Status => return Ok(()),
    };
    let reply = pod.write_hex(&cmd).await?;
    println!("  Post-command status: {:?}", client.decrypt_reply(&reply, dev).await?);
    Ok(())
}
