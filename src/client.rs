//! REST client for the QIUI Open Platform cloud API.
//!
//! Only handles the HTTP side: auth token, device binding, and asking the
//! server to generate the hex BLE command strings. Bluetooth lives in `ble.rs`.

use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

pub const BASE_URL: &str = "https://openapi.qiuitoy.com";
pub const ENV_FILE: &str = ".qiui_pod_env";

/// Parse a simple `KEY=value` env file (comments and quotes tolerated).
pub fn load_env(path: impl AsRef<Path>) -> Result<HashMap<String, String>> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches(['"', '\'']).to_string()))
        .collect())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub serial_number: String,
    pub type_id: u32,
}

/// Decoded BLE reply from `decryBluetoothCommand`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceStatus {
    pub battery: Option<i64>,
    pub comment_type: Option<String>,
    pub is_unlocking: Option<bool>,
}

pub struct QiuiClient {
    http: reqwest::Client,
    client_id: String,
    base_url: String,
    token: Option<String>,
    debug: bool,
}

impl QiuiClient {
    pub fn new(client_id: impl Into<String>, debug: bool) -> Self {
        Self {
            http: reqwest::Client::new(),
            client_id: client_id.into(),
            base_url: BASE_URL.to_string(),
            token: None,
            debug,
        }
    }

    async fn post(&self, path: &str, body: Value, auth: bool) -> Result<Value> {
        let mut req = self
            .http
            .post(format!("{}{path}", self.base_url))
            .header("Environment", "TEST")
            .json(&body);
        if auth {
            let token = self.token.as_deref().context("call get_platform_token() first")?;
            req = req.header("Authorization", token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if self.debug {
            eprintln!("  POST {path} -> HTTP {status}: {text}");
        }
        if !status.is_success() {
            bail!("POST {path} failed: HTTP {status}: {text}");
        }
        let value: Value = serde_json::from_str(&text)?;
        if let Some(code) = value.get("code").and_then(Value::as_i64)
            && code != 200
        {
            bail!("POST {path} rejected: code {code}: {}", value["message"]);
        }
        Ok(value)
    }

    async fn post_data<T: for<'de> Deserialize<'de>>(&self, path: &str, body: Value) -> Result<T> {
        let mut value = self.post(path, body, true).await?;
        Ok(serde_json::from_value(value["data"].take())?)
    }

    fn grant_body(&self) -> Value {
        // Per the docs only clientId + grantType are sent; there is no clientSecret.
        json!({ "clientId": self.client_id, "grantType": "client_credentials" })
    }

    pub async fn get_platform_token(&mut self) -> Result<()> {
        let v = self
            .post("/system/api/device/common/getPlatformApiToken", self.grant_body(), false)
            .await?;
        self.token = Some(v["data"]["platformApiToken"].as_str().context("no platformApiToken")?.into());
        Ok(())
    }

    pub async fn refresh_platform_token(&mut self) -> Result<()> {
        let v = self
            .post("/system/api/device/common/refreshPlatformApiToken", self.grant_body(), true)
            .await?;
        self.token = Some(v["data"]["platformApiToken"].as_str().context("no platformApiToken")?.into());
        Ok(())
    }

    pub async fn query_device_info(&self, mac: &str) -> Result<Option<DeviceInfo>> {
        self.post_data(
            "/system/api/platform/device/queryDeviceInfo",
            json!({ "bluetoothAddress": mac }),
        )
        .await
    }

    pub async fn ensure_bound(&self, mac: &str) -> Result<DeviceInfo> {
        if let Some(info) = self.query_device_info(mac).await? {
            return Ok(info);
        }
        self.post(
            "/system/api/platform/device/addDeviceInfo",
            json!({ "bluetoothAddress": mac }),
            true,
        )
        .await?;
        self.query_device_info(mac).await?.context("device still unbound after addDeviceInfo")
    }

    fn device_body(mac: &str, dev: &DeviceInfo) -> Value {
        json!({ "bluetoothAddress": mac, "serialNumber": dev.serial_number, "typeId": dev.type_id })
    }

    pub async fn device_token_cmd(&self, mac: &str, dev: &DeviceInfo) -> Result<String> {
        self.post_data("/system/api/device/common/getDeviceToken", Self::device_body(mac, dev)).await
    }

    pub async fn unlock_cmd(&self, mac: &str, dev: &DeviceInfo) -> Result<String> {
        self.post_data("/system/api/device/keyPod/getKeyPodUnlockCmd", Self::device_body(mac, dev)).await
    }

    pub async fn lock_cmd(&self, mac: &str, dev: &DeviceInfo) -> Result<String> {
        self.post_data("/system/api/device/keyPod/getKeyPodLockCmd", Self::device_body(mac, dev)).await
    }

    pub async fn decrypt_reply(&self, hex_payload: &str, dev: &DeviceInfo) -> Result<DeviceStatus> {
        self.post_data(
            "/system/api/device/keyPod/decryBluetoothCommand",
            json!({ "lockCommand": hex_payload, "serialNumber": dev.serial_number }),
        )
        .await
    }
}
