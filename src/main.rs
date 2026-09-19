use anyhow::Result;
use clap::{Parser, Subcommand};

use qiui_server::ble::{self, KNOWN_MAC, KeyPod, MAC_PREFIX};
use qiui_server::client::{self, ENV_FILE, QiuiClient, load_env};

#[derive(Parser)]
#[command(about = "QIUI KeyPod local controller")]
struct Cli {
    /// Print every raw HTTP response and BLE payload
    #[arg(long, global = true)]
    debug: bool,
    /// KeyPod Bluetooth MAC address
    #[arg(long, global = true, default_value = KNOWN_MAC)]
    mac: String,
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Clone, Copy, PartialEq)]
enum Action {
    /// Scan BLE and report which devices are KeyPods (no cloud calls)
    Identify,
    /// Connect and report battery / lock state
    Status,
    Lock,
    Unlock,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.action {
        Action::Identify => identify().await,
        action => control(&cli, action).await,
    }
}

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

async fn control(cli: &Cli, action: Action) -> Result<()> {
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

async fn run(client: &QiuiClient, pod: &mut KeyPod, mac: &str, dev: &client::DeviceInfo, action: Action) -> Result<()> {
    println!("Performing device-token handshake...");
    let reply = pod.write_hex(&client.device_token_cmd(mac, dev).await?).await?;
    let status = client.decrypt_reply(&reply, dev).await?;
    println!("  Device status: {status:?}");

    let cmd = match action {
        Action::Unlock => client.unlock_cmd(mac, dev).await?,
        Action::Lock => client.lock_cmd(mac, dev).await?,
        _ => return Ok(()),
    };
    let reply = pod.write_hex(&cmd).await?;
    println!("  Post-command status: {:?}", client.decrypt_reply(&reply, dev).await?);
    Ok(())
}
