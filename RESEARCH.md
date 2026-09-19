# QIUI Open Platform API — Research & Architecture Notes

Compiled from: QIUI's official Android/iOS sample apps (`ZouZLong/QIUI-API`, `GZguanshiwei/QIUIAPI`), QIUI's official Developer API Documentation Center (`developers.qiuitoy.com`), and live testing against a real KeyPod (gen 1) device. Supersedes earlier notes built from 2020-era third-party security research, which covered a now-decommissioned v1 API.

Physical device under test: QIUI KeyPod (gen 1), MAC `E5:26:D6:6E:B6:8A`.

---

## 1. Architecture

The cloud REST API never talks to the lock directly. Every device is a BLE peripheral; the API's role is:

1. **Auth** — issue a short-lived bearer token (`platformApiToken`) for your registered `clientId`.
2. **Device bookkeeping** — bind a Bluetooth MAC address to your account and look up its `serialNumber`/`typeId`.
3. **Command generation** — given the device's identity and a per-connection device token, the server returns a hex-encoded byte string. The client writes those bytes to the lock's BLE "write" characteristic. The lock's own reply comes back over BLE "notify," gets hex-encoded, and is POSTed back to the server (`decryBluetoothCommand`) to be decoded into human-readable status.

So a full client needs both an HTTPS client (token/command generation) and a BLE client (talking to the physical lock). Cellular-equipped product lines (Cellmate Gen3 and others) additionally expose a parallel `.../4g/send...` path per command, letting a *different* phone/account control the device over the internet via MQTT (`tcp://openmq.qiuitoy.com:1883`) instead of local BLE — same command names, no Bluetooth proximity required. The plain KeyPod (our device) has no cellular module and no `4g/` endpoints — BLE proximity is mandatory.

**Key implication:** there is no "offline" unlock in the vendor's design by default — command bytes are minted per-request by the cloud, not generated locally. See §7 for what this means for a reboot-/internet-resilient timer.

---

## 2. Base URLs

| Purpose | Value |
|---|---|
| Production REST API | `https://openapi.qiuitoy.com` |
| MQTT broker (cellular-equipped devices only) | `tcp://openmq.qiuitoy.com:1883` |
| Official developer portal (account/API-key registration) | `https://developers.qiuitoy.com` |

Every REST call is `POST`, JSON body, headers `Environment: TEST|PRODUCT` and (after auth) `Authorization: <platformApiToken>`.

An AES/CBC/PKCS5Padding request/response encryption layer exists in the sample SDK (`EncryptUtil`, key `C8BE5C77E0104378ABBEF7DA6FBF7408`, IV `0123456789abcdef`) but is short-circuited to a no-op in the shipped sample. Not needed against production as tested so far.

---

## 3. Auth

```
POST /system/api/device/common/getPlatformApiToken
Header: Environment: TEST
Body:   { "clientId": "<your client id>", "grantType": "client_credentials" }
→ { "code": 200, "data": { "platformApiToken": "<JWT>", "expiresTime": 43200 } }
```
Confirmed live: this exact call succeeds immediately with a registered `clientId`. Token is valid 12 hours (`expiresTime` in seconds), and per the docs, a token obtained in TEST and PRODUCT environments is the same value.

**No `clientSecret`/API-key field is part of this call** — confirmed directly from the official docs. The separately-issued "API key" is not consumed here; its actual use is still unconfirmed (possibly `Environment: PRODUCT` gating, or unused by this device tier).

Refresh before expiry:
```
POST /system/api/device/common/refreshPlatformApiToken
Header: Authorization: <old token>, Environment: TEST
Body:   { "clientId": "...", "grantType": "client_credentials" }
→ same shape as above, new platformApiToken
```

A working test `clientId` ships hardcoded in the official Android sample (`Client_35115347524B4D1CA9A20BF2F660EF49`) for prototyping without registering your own.

---

## 4. Device binding — hard architectural constraint

```
POST /system/api/platform/device/queryDeviceInfo
Body: { "bluetoothAddress": "<MAC>" }
→ data: null                     (not bound to this platform account)
→ data: { id, userId, bluetoothAddress, serialNumber, typeId, environmentType, iccid, ... }
```
```
POST /system/api/platform/device/addDeviceInfo
Body: { "bluetoothAddress": "<MAC>" }
→ data: { id, userId, bluetoothAddress, serialNumber, typeId, environmentType }
```

**Confirmed from the official docs' own "Important Notice" on this endpoint, and reproduced live against our device:**

> Bound devices must be unbound from the QiUI app before they can be used normally on other platforms. To operate a device under your API, the device must not be bound to the QiUI app in order to be bound to your API platform.

Live test result while the KeyPod was still bound in the consumer QiUi app:
```
addDeviceInfo → { "code": 500059, "message": "设备已经在[QiUi]App中绑定，请在[QiUi]中解除绑定后再使用开放平台Api" }
```
("This device is already bound in the [QiUi] App — please unbind it there before using the Open Platform API.")

**A device can only be claimed by the consumer app OR the Open Platform API at any one time, never both.** This is a one-time setup step per device, not a per-session issue — unbind once in the app, then the Open Platform owns it going forward (until unbound the other direction). As of this writing, our test device is still app-bound and this is the only remaining blocker to a live end-to-end test.

---

## 5. BLE identity (confirmed live for KeyPod)

Live-scanned via `bleak` against `E5:26:D6:6E:B6:8A`:

| Role | UUID | Properties (observed) |
|---|---|---|
| Service | `0000fff0-0000-1000-8000-00805f9b34fb` | — |
| Write | `0000fff1-0000-1000-8000-00805f9b34fb` | `write-without-response` (not plain `write`) |
| Notify | `0000fff2-0000-1000-8000-00805f9b34fb` | `notify` |

A second, undocumented service (`5833ff01-9b8b-5191-6142-22a4536ef123`, with `write`/`notify` characteristics `5833ff02`/`5833ff03`) is also present on the physical device — not referenced anywhere in QIUI's sample code or docs. Likely OTA/DFU or a manufacturing-test interface; not used by the documented protocol and not touched by our client.

Other product lines' UUIDs (from the sample SDK source, not live-tested):

| typeId | Product | Service | Notify | Write |
|---|---|---|---|---|
| 6 | KeyPod gen1 (ours) | `fff0` | `fff2` | `fff1` |
| 10 | Cellmate Gen3 | `fee7` | `36f6` | `36f5` |
| 13 | Metal lock | `fee5` | `3ff6` | `3ff5` |
| 15 | Vibrating metal lock | `fee5` | `3ff6` | `3ff5` |
| 18 | Anal plug gen2 | `ac3a` | `ac3c` | `ac3b` |
| 19 | Sissy lock | `fee5` | `3ff6` | `3ff5` |
| 20 | Metal KeyPod | `0b30` | `0b31` | `0b32` |

(All share the Bluetooth SIG base `-0000-1000-8000-00805f9b34fb`.)

---

## 6. KeyPod (typeId 6) full endpoint set — every field cross-checked against official docs

All `POST`, header `Authorization: <platformApiToken>` + `Environment: TEST|PRODUCT`, base `https://openapi.qiuitoy.com`.

| Purpose | Path | Body | Response `data` |
|---|---|---|---|
| Device token | `/system/api/device/common/getDeviceToken` | `{bluetoothAddress, serialNumber, typeId}` | Docs say `boolean`; QIUI's own Android sample class (`GetDeviceTokenBean.java`) types it as a hex `String` (e.g. `"6612C16C7D600088AC8ACA4BA5350281"`) — **unresolved discrepancy**, doc's example response is an empty placeholder so likely a doc-tool type-inference bug. Treating as hex string per the sample code until verified live. |
| Decrypt BLE reply | `/system/api/device/keyPod/decryBluetoothCommand` | `{lockCommand: "<hex from BLE notify>", serialNumber}` | `{battery: int, commentType: string, isUnlocking: bool}` |
| Unlock | `/system/api/device/keyPod/getKeyPodUnlockCmd` | `{bluetoothAddress, serialNumber, typeId}` | hex command string to write over BLE |
| Lock | `/system/api/device/keyPod/getKeyPodLockCmd` | `{bluetoothAddress, serialNumber, typeId}` | hex command string to write over BLE |
| Query binding | `/system/api/platform/device/queryDeviceInfo` | `{bluetoothAddress}` | device record or `null` |
| Bind | `/system/api/platform/device/addDeviceInfo` | `{bluetoothAddress}` | device record |

**No timing/scheduled-lock endpoint exists for KeyPod.** Unlike Cellmate Gen3, the metal locks, and the sissy lock — all of which expose `.../TimingLockCmd` / `.../TimingUnlock` variants — the KeyPod namespace only has immediate lock/unlock. Any "unlock at time X" behavior has to be implemented client-side.

### Session flow (BLE)
1. Connect to the MAC; discover GATT services.
2. Subscribe (`notify`) on `fff2`.
3. Once subscribed, call `getDeviceToken` → write the returned command to `fff1` (`write-without-response`).
4. Device replies asynchronously over `fff2`. Hex-encode the raw bytes, POST to `decryBluetoothCommand` → get back `{battery, commentType, isUnlocking}` plus (implicitly) whatever session token the device just issued.
5. For lock/unlock: call the matching `get...Cmd` endpoint, write the returned hex to `fff1`, read the notify reply, decrypt via `decryBluetoothCommand` again to confirm the new state.

Per the docs: "the token changes every time [the device] is connected... each time a Bluetooth command is obtained, the Token must be carried for authentication" — meaning step 3-4 must be repeated after every fresh BLE connection (e.g., after a power cycle or reconnect), not just once ever.

---

## 7. Open question that gates offline/reboot-resilient timers

The user's goal: set an unlock time now, have it fire later even across a reboot or with no internet at fire-time.

This hits a real constraint: unlock command bytes are minted by the cloud (§1, §6), not computed locally, and the device issues a **new token per BLE connection** per the docs. Whether the resulting unlock command hex is:
- **(a) deterministic/static** per device regardless of session → a hex fetched once while online can be cached and replayed offline later, or
- **(b) session-bound/nonced** → a stale cached command will be rejected by the device when replayed against a different (later) connection session

...is not yet determined; it requires a live A/B test (fetch `getKeyPodUnlockCmd` twice across two separate BLE connect/disconnect cycles and diff the hex). This is the single most important unresolved question for the offline-timer design and should be the first thing tested once the device is unbound from the app.

**Design if (a) holds** — fully offline once scheduled:
1. Persist `{unlock_at: <UTC epoch>, cached_unlock_hex}` to disk (SQLite/JSON) at schedule-time, while online.
2. Run a long-lived local service (systemd unit, `Restart=always`) that reloads this state on boot.
3. Drive the wait with a periodic poll against wall-clock time (not one long sleep, to tolerate NTP/clock jumps — see §timer-design below), and connect over BLE + write the cached hex directly when due. No network call needed at fire-time.
4. `lock` has no timing concern — it's always an immediate, online, cloud-round-trip call.

**Design if (b) holds** — offline unlock is not achievable through this API at all; the only way to get a "survives no internet" unlock would be a feature on the device's own firmware (KeyPod does not expose one via this API — see §6), or accepting that connectivity must be available at the scheduled moment.

### General timer design principle (independent of (a)/(b))
Store the target as an **absolute UTC epoch** (survives restarts, unambiguous to log), but drive the actual wait loop off a **monotonic clock** and periodic rechecks of wall-clock time rather than a single `sleep(duration)` — a wall-clock-only sleep can fire early/late if the system clock is corrected (NTP, manual change, DST) mid-wait.

### Trusted local time source: TerraMaster F4-424 Pro NAS (available on this network)

For the epoch timestamp above to be trustworthy across a reboot with no internet, the controller device needs a clock that (a) doesn't reset on power loss and (b) can be corrected without WAN access. The user's NAS covers both:

- **RTC survives power loss**: the F4-424 Pro has a genuine battery-backed CMOS RTC on its motherboard (CR2032 coin cell, standard PC-style setup — it's built on an Intel N-series platform, not a bare SoC without a clock battery). Rated ~5 years lifespan powered-on, ~2.5–3 years unpowered. So its clock is meaningful even after a full cold power event, unlike e.g. a bare Raspberry Pi with no RTC that resets to an arbitrary time with no internet to re-sync.
- **LAN-only NTP server**: TerraMaster's TOS can act as an NTP server for other devices on the same network (Control Panel → General Settings → Time and Language → enable NTP service). Other LAN devices then point their NTP client at the NAS's IP instead of a public pool, giving a trusted time source even during a WAN outage.

Recommended setup for whatever box runs the persisted-timer service:
1. On the F4-424 Pro: enable its NTP server option in TOS; let it sync from public NTP whenever WAN is up (keeps long-term drift in check).
2. On the controller box: configure `chrony` (or `systemd-timesyncd`) with the NAS's LAN IP as the primary time source and a public NTP pool as fallback — e.g. in `/etc/chrony/chrony.conf`:
   ```
   server <nas-lan-ip> iburst prefer
   pool pool.ntp.org iburst
   ```
This makes the `unlock_at` epoch timestamp (§ design above) resolvable to a correct wall-clock time even through a reboot with no WAN connectivity, as long as the controller and NAS share a LAN and the NAS itself stays powered (UPS-backed, per the user's setup).

---

## 8. Code produced so far (in this folder)

- `qiui_keypod_identify.py` — pure BLE discovery/identification, no cloud dependency. Confirmed working against the real device.
- `qiui_client.py` — REST client (`QiuiClient`): token, refresh, bind/query, device-token cmd, decrypt, lock/unlock cmd. Every endpoint's field names now match the official docs.
- `qiui_keypod_control.py` — full lock/unlock/status CLI combining `qiui_client.py` + `bleak`. Blocked on the app-binding conflict (§4); not yet run end-to-end successfully.
- `.qiui_pod_env` — holds `QIUI_CLIENT_ID` / `QIUI_PROD_API_KEY` (not committed/shared).

## 9. Next steps

1. Unbind the KeyPod from the QiUi phone app.
2. Re-run `qiui_keypod_control.py status --debug` — confirms `addDeviceInfo` succeeds and settles the `getDeviceToken` response-type question (§6) with a real payload.
3. Run the two-connection A/B test described in §7 to determine whether offline replay is viable at all.
4. Depending on that result, either build the persisted-timer service (Python or a Rust `axum`/`btleplug` rewrite) or document that offline unlock isn't supported and design around always-online scheduling instead.

---

## 10. Live findings against the real KeyPod (2026-09-19)

Device bound to our platform account; tests run with `qiui_replay_test.py` and a Web Bluetooth probe (Chrome on a Mac). Battery was possibly low during some runs (see last bullet).

**Protocol behaviour**
- `getDeviceToken` returns a fresh random 16-byte hex string every call (a string, not a boolean).
- The server refuses to mint unlock/lock commands (`500032`/`500033`) until a handshake reply has been decrypted. If the decrypt is skipped the server still returns bytes, but the pod ignores them. **Order per connection: connect, write token, wait for reply, `decryBluetoothCommand`, then mint unlock/lock, write, decrypt the reply.**
- Reply types (`commentType`): `01` handshake, `02` unlock, `03` lock. `isUnlocking` stays `true` after a lock reply, so it is not a reliable lock state. Read state from the handshake (`01`) reply.
- `battery` has read `0` in every reply. Either the KeyPod does not report a level or the battery was empty. Recheck with a fresh battery.
- Repeated notifications seen in the Web Bluetooth probe were a probe bug: one extra listener was added per reconnect, so a reply was logged once per connection made in that page (1, 2, 3 ... up to 30 in the sampling run). The Python/BlueZ runs show exactly one notify per reply. Draining pending notifications before a write is still sensible hygiene.
- Platform token: repeat calls return the same token until it expires (12 h); `expiresTime` counts down.

**Unlock bytes depend on a hidden per-connection state, and that state can repeat (OPEN RISK)**
- Same bytes worked repeatedly on the same connection, across several handshakes, up to 15.6 min old (pod kept awake).
- Old bytes were ignored on new connections in every test but one class of case: the server mints different bytes for different connections, and a 5 s disconnect/reconnect (pod awake) made a 16 s-old unlock ignored.
- BUT the exact same unlock bytes (`CF2FBA95...`) and lock bytes (`8A139F21...`) were minted for two unrelated connections 1 h 50 min apart (10:46 and 12:37). The first copy was rejected on a later connection at 11:02; the second copy was accepted at 12:37. So a stale byte string works whenever a new connection happens to be in the same hidden state.
- 11 mints so far gave 10 distinct values (one repeat). Handshake replies also repeat (`c9859021...`, `cde9259e...`, `d0142496...`). Server-direct unlock is unaffected (bytes never leave the server).
- Sampling run (30 rounds of reconnect + handshake + mint, nothing written to the pod): 30 distinct values, 0 repeats within the run. One value (`A8569B9F...`) matched an earlier mint from 10:29. Across all 41 mints there are 2 repeated values among 820 pairs, so the number of possible states is roughly a few hundred (plausibly 100 to 3000; small sample). For someone holding one captured unlock byte string, each fresh connection then has roughly a 1-in-few-hundred chance of matching. Multiple captured strings raise it proportionally.
- Practical exposure: needs (1) capturing the bytes (browser dev tools, or an Android Bluetooth HCI log analysed on a computer) and (2) hundreds of reconnect-and-write attempts (a generic BLE app such as nRF Connect could do this by hand). Accepted risk for phone-relay; server-direct unlock is unaffected.

**Pod behaviour**
- Advertises as `QIUI-KeyPod`; write characteristic is write-without-response only.
- Powers off after about 10 min without writes, even with a connection open.
- The first connection after a wake often drops after about 2 s; the second works. Retry once.
- After an unlock that is not followed by a lock command, the pod locks itself and drops the connection 3 to 44 s later.

**Cloud authorisation**
- Another client id can read the device record (including the serial number) with `queryDeviceInfo`, but is refused (`500025`, "bound on another platform") for token, unlock and lock commands.

**Web Bluetooth**
- Works from desktop Chrome via `requestDevice` (service filter `fff0` works); reconnecting to the same device object needs no chooser. iOS Safari and Chrome have no Web Bluetooth; a Web Bluetooth browser app such as Bluetooth Browser is a possible route, untested.
