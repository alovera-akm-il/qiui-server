//! BLE transport for a QIUI KeyPod (gen 1, typeId 6) via btleplug.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use btleplug::api::{
    Central, CharPropFlags, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures::{FutureExt, StreamExt};
use uuid::{Uuid, uuid};

pub const SERVICE_UUID: Uuid = uuid!("0000fff0-0000-1000-8000-00805f9b34fb");
pub const WRITE_UUID: Uuid = uuid!("0000fff1-0000-1000-8000-00805f9b34fb");
pub const NOTIFY_UUID: Uuid = uuid!("0000fff2-0000-1000-8000-00805f9b34fb");

/// Known KeyPod MAC and vendor prefix (tail bytes may rotate).
pub const KNOWN_MAC: &str = "E5:26:D6:6E:B6:8A";
pub const MAC_PREFIX: &str = "E5:26:D6";

const SCAN_TIME: Duration = Duration::from_secs(8);
/// How long a session waits for the pod to show up before calling it out of range.
const FIND_TIMEOUT: Duration = Duration::from_secs(8);
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(10);

async fn adapter() -> Result<Adapter> {
    let manager = Manager::new().await?;
    manager.adapters().await?.into_iter().next().context("no Bluetooth adapter found")
}

/// Scan and return every peripheral seen, with its (upper-case) address.
pub async fn scan() -> Result<Vec<(String, Peripheral)>> {
    let adapter = adapter().await?;
    adapter.start_scan(ScanFilter::default()).await?;
    tokio::time::sleep(SCAN_TIME).await;
    adapter.stop_scan().await.ok();
    Ok(adapter
        .peripherals()
        .await?
        .into_iter()
        .map(|p| (p.address().to_string().to_uppercase(), p))
        .collect())
}

/// The pod did not appear while scanning.
#[derive(Debug, thiserror::Error)]
#[error("{0} was not seen while scanning (is it awake and in range?)")]
pub struct NotFound(pub String);

/// Scan until the pod shows up, then stop at once, or give up after `within`.
pub async fn find(mac: &str, within: Duration) -> Result<Peripheral> {
    let adapter = adapter().await?;
    adapter.start_scan(ScanFilter::default()).await?;
    let deadline = tokio::time::Instant::now() + within;
    let found = loop {
        let hit = adapter.peripherals().await?.into_iter().find(|p| p.address().to_string().eq_ignore_ascii_case(mac));
        if hit.is_some() || tokio::time::Instant::now() >= deadline {
            break hit;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    adapter.stop_scan().await.ok();
    found.ok_or_else(|| anyhow::Error::new(NotFound(mac.to_string())))
}

pub struct KeyPod {
    peripheral: Peripheral,
    write: Characteristic,
    notifications: std::pin::Pin<Box<dyn futures::Stream<Item = btleplug::api::ValueNotification> + Send>>,
    debug: bool,
}

impl KeyPod {
    pub async fn connect(mac: &str, debug: bool) -> Result<Self> {
        let peripheral = find(mac, FIND_TIMEOUT).await?;
        peripheral.connect().await?;
        peripheral.discover_services().await?;
        let chars = peripheral.characteristics();
        let write = chars.iter().find(|c| c.uuid == WRITE_UUID).cloned().context("write characteristic fff1 missing")?;
        let notify = chars
            .iter()
            .find(|c| c.uuid == NOTIFY_UUID && c.properties.contains(CharPropFlags::NOTIFY))
            .cloned()
            .context("notify characteristic fff2 missing")?;
        peripheral.subscribe(&notify).await?;
        let notifications = peripheral.notifications().await?;
        if debug {
            eprintln!("  BLE connected + subscribed to notify");
        }
        Ok(Self { peripheral, write, notifications, debug })
    }

    /// Write a hex command and return the hex-encoded notify reply.
    pub async fn write_hex(&mut self, hex_cmd: &str) -> Result<String> {
        let payload = hex::decode(hex_cmd).context("server returned non-hex command")?;
        if self.debug {
            eprintln!("  [BLE write] {hex_cmd}");
        }
        // Drop anything left over from an earlier command so a
        // stale or repeated notification is never mistaken for this command's reply.
        while self.notifications.next().now_or_never().flatten().is_some() {}
        self.peripheral.write(&self.write, &payload, WriteType::WithoutResponse).await?;
        loop {
            let n = tokio::time::timeout(NOTIFY_TIMEOUT, self.notifications.next())
                .await
                .context("timed out waiting for BLE notify")?
                .context("BLE notification stream closed")?;
            if n.uuid != NOTIFY_UUID {
                continue;
            }
            let reply = hex::encode(&n.value);
            if self.debug {
                eprintln!("  [BLE notify] {reply}");
            }
            return Ok(reply);
        }
    }

    pub async fn disconnect(self) -> Result<()> {
        if self.peripheral.is_connected().await? {
            self.peripheral.disconnect().await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::pod::Transport for KeyPod {
    async fn exchange(&mut self, cmd_hex: &str) -> Result<String, crate::pod::PodError> {
        use crate::pod::PodError;
        self.write_hex(cmd_hex).await.map_err(|e| {
            if e.to_string().contains("timed out") { PodError::Timeout } else { PodError::Ble(format!("{e:#}")) }
        })
    }
}

/// Print the GATT tree of a peripheral and report whether it is a KeyPod.
pub async fn identify(addr: &str, p: &Peripheral) -> Result<()> {
    println!("\n--- Connecting to [{addr}] ---");
    p.connect().await?;
    p.discover_services().await?;
    let services = p.services();
    println!("  Services found:");
    for s in &services {
        println!("    {}", s.uuid);
        for c in &s.characteristics {
            println!("      char {}  props={:?}", c.uuid, c.properties);
        }
    }
    if services.iter().any(|s| s.uuid == SERVICE_UUID) {
        let has = |u| services.iter().flat_map(|s| &s.characteristics).any(|c| c.uuid == u);
        println!(
            "\n  >>> MATCH: QIUI KeyPod (write char: {}, notify char: {})",
            has(WRITE_UUID),
            has(NOTIFY_UUID)
        );
        println!("  >>> MAC to use for the cloud API's bluetoothAddress: {addr}");
    } else {
        println!("  Not a KeyPod (service UUID not present).");
    }
    p.disconnect().await.ok();
    if !services.is_empty() {
        return Ok(());
    }
    bail!("no services discovered")
}
