# qiui-server usage guide

A local server that lets a **keyholder** control a QIUI KeyPod worn by a **wearer**, with the rules enforced on the
server rather than on the wearer's phone.

> **What exists today.** Everything described here is built and tested: the server, the keyholder command line, the
> HTTP API, Bluetooth control (through the server or relayed by the wearer's phone), the audit log, the wearer's
> installable web app and push notifications. Two things have not yet been run for real: the Rust Bluetooth path
> against the actual pod (it is covered by tests with a fake pod), and push delivery through a real push service to a
> real phone. The wearer screenshots below are taken from the running app against a **simulated** pod
> (`--simulate-pod`), driven by an automated browser test.

Contents: [How it works](#how-it-works) · [Setup](#setup) · [Keyholder guide](#keyholder-guide) ·
[Wearer guide](#wearer-guide) · [Security model and limits](#security-model-and-limits) ·
[Troubleshooting](#troubleshooting) · [API reference](#api-reference) · [Files and settings](#files-and-settings)

---

## How it works

```
 wearer's phone (web app)                        keyholder (CLI or API)
        │  HTTPS                                        │  HTTP on the server machine
        ▼                                               ▼
   ┌───────────────────────────  qiui-server  ───────────────────────────┐
   │  rules · timer · approvals · queue · audit log · accounts · SQLite  │
   └───────────────┬─────────────────────────────────────┬───────────────┘
                   │ Bluetooth (server's adapter)        │ HTTPS
                   ▼                                     ▼
                KeyPod  ◄── Bluetooth (phone relay) ── phone      QIUI cloud (mints command bytes)
```

- **The server decides everything.** The wearer's phone only ever asks; it never holds a rule.
- **QIUI's cloud mints the command bytes** for every lock, unlock and handshake. The server calls it; the wearer's
  app never talks to it and never sees your QIUI credentials.
- **Bluetooth is used in short sessions**: connect, handshake, one command, disconnect. Nothing stays connected.

### What each side can do

| | Wearer | Keyholder |
|---|---|---|
| See lock state, timer countdown, messages | ✔ | ✔ |
| Ask to be unlocked | ✔, unless a timer is running or paused | – |
| Approve or deny a request | ✘ | ✔ |
| Unlock | only after a live approval | ✔, unless a timer is running or paused |
| Lock | ✔ after unlocking | ✔ any time |
| Set, roll, pause, resume, clear the timer | ✘ | ✔ |
| Queue a lock or unlock for later | ✘ | ✔ |
| Send messages | ✘ | ✔ |
| Read the audit log | ✘ | ✔ |

A timer that finishes only **reopens requests**. Nothing ever unlocks by itself, and the wearer can never unlock
without approval.

---

## Setup

### 1. Prerequisites

- A Linux machine with a Bluetooth adapter that stays near the pod (about 10 m). A laptop works if it never sleeps.
- Rust (edition 2024), plus the BlueZ and D-Bus development headers (`libdbus-1-dev` on Debian/Ubuntu).
- A QIUI Open Platform **client id** (from developers.qiuitoy.com).
- The KeyPod **unbound from the QiUi phone app**. A pod can belong to the app or to the Open Platform, never both.
  If it is still in the app you will see QIUI error `500059`.

```
cargo build --release          # binary: target/release/qiui-server
```

### Run it as a service (systemd)

For a machine that stays on, install it as a service that starts at boot and restarts if it fails:

```
scripts/deploy.sh                       # build, install, enable and start
scripts/deploy.sh --bind 192.168.1.20:8443   # listen on one address instead of every interface
```

It is safe to run again: `git pull && scripts/deploy.sh` updates the program in place and keeps your data and settings.
It does not touch Tailscale, other web servers or firewalls.

| What | Where |
|---|---|
| Program | `/usr/local/bin/qiui-server` |
| Keyholder command line | `/usr/local/bin/qiui-ctl` (same program, run as the service user on the service's data) |
| Service | `/etc/systemd/system/qiui-server.service` (from `deploy/qiui-server.service`) |
| Data (database, keys, sealed credentials) | `/var/lib/qiui-server`, owned by the `qiui` user, mode 0700 |
| Settings | `/etc/qiui-server/service.env` (`QIUI_BIND` only; never put a password here) |

The service runs as a dedicated `qiui` user with no login, in the `bluetooth` group, with a locked-down sandbox
(read-only system, no home directory, no extra privileges, network limited to IP and local sockets).

Use `qiui-ctl` in place of `qiui-server` for everything, since only the service user can read the data. It runs through `sudo`, which drops environment variables, so give the password with `--password` or type it at the prompt (`QIUI_KEYHOLDER_PASSWORD` does not get through):

```
qiui-ctl init                     # first time only
qiui-ctl config set-client-id     # first time only
qiui-ctl config set-mac E5:26:D6:6E:B6:8A
qiui-ctl status                   # the first keyholder sign-in after each start unlocks pod control
```

Day to day:

```
journalctl -u qiui-server -f      # logs
sudo systemctl restart qiui-server
sudo systemctl stop qiui-server
scripts/deploy.sh --uninstall           # remove the service and program, keep the data
scripts/deploy.sh --uninstall --purge   # ...and delete the data and the service user
```

After a reboot or restart the QIUI credentials are sealed again until you sign in as keyholder once
(any keyholder command does it), so the pod cannot be controlled until then. That is by design.

### 2. Create the keyholder account

```
qiui-server init
```

You choose a **password** (at least **16 characters**; a long passphrase is easiest) and a **recovery PIN** (6 to 12 digits). Neither is stored: only
keyed hashes are. The PIN is the only way to reset a forgotten password, and only from this machine. It is one-time:
using it to reset the password retires it and issues a new one — see [Forgotten password](#forgotten-password).

### 3. Tell it about QIUI and the pod

```
qiui-server config set-client-id        # prompts, hidden; asks for your keyholder password
qiui-server config set-mac E5:26:D6:6E:B6:8A
qiui-server config show                 # nothing secret is ever displayed
```

**The QIUI client id and API key are stored encrypted.** They are sealed in `config.json` with a key derived from
your keyholder password (and the server's `pepper.key`), so a copy of the file or the disk is useless without the
password. The server keeps them in memory only, and never writes anything decrypted back to disk.

- **After the server starts,** pod control is locked. Accounts, timers, messages and the wearer's app all work, but
  Bluetooth commands are refused with "the keyholder needs to sign in once". The first keyholder sign-in decrypts the
  credentials in memory (any keyholder command signs in, so `qiui-server status` is enough). The audit log records
  `credentials_unlocked`.
- **Changing your password** (through the API) re-encrypts them under the new one.
- **Resetting it with the recovery PIN** cannot: a 6 to 12 digit PIN is far too weak to protect them. The reset
  removes the sealed credentials, and you enter them again with `config set-client-id`.
- **An older `config.json` with plain-text credentials** keeps working, with a warning. `qiui-server config encrypt`
  migrates it and removes the plain-text copy.

Coming from the old Python scripts? `qiui-server config import-env ~/qiui-keypod/.qiui_pod_env` copies the client id
and API key across, encrypted.

Check the pod is reachable (wake it first by pressing its button; it sleeps after about 10 minutes). With the server
not running this asks for your keyholder password, which it needs to decrypt the credentials:

```
qiui-server sync
```

### 4. Run the server

```
qiui-server serve                       # listens on http://0.0.0.0:8443: every network interface
```

By default the server listens on **every network interface, in plain HTTP** (`--bind` changes that). It prints a note
saying so when it starts. That suits reaching it two ways:

- **On your LAN:** `http://<this machine's LAN address>:8443`, straight to the server.
- **From anywhere else:** your Tailscale address, through whatever already serves HTTPS on your tailnet, pointed at
  `127.0.0.1:8443` (or any address the server can be reached on). A Cloudflare Tunnel would also work.

**Know what each address gives the wearer.** The browser only allows service workers, installing the app, notifications
and Web Bluetooth on a secure address (HTTPS, or `localhost`). I measured this: on a plain `http://` address the app
pairs, requests, unlocks through the server and shows the countdown, but **cannot install, start offline, send
notifications or use the phone's Bluetooth**. So the LAN address gets the core flow, and the HTTPS address gets
everything. The wearer can use the HTTPS address at home too, if Tailscale is on: it connects directly over your
LAN. Each address is a separate app to the browser (its own stored login), so the phone pairs once per address, which is
why up to two devices may be paired by default (see below).

**Plain HTTP on the LAN is not encrypted.** The keyholder password and the wearer's token cross your home network in the
clear on that path, readable by anything else on it. Keyholder work is safest done with the CLI on the server itself
or through the HTTPS address.

**Trying it without a pod.** `qiui-server serve --simulate-pod` runs the whole thing against a pretend pod that is
always in range and always obeys (add `--simulate-out-of-range` to make the phone's Bluetooth the only way in). It
prints a warning and touches neither QIUI nor any hardware. It is what the screenshots in this guide were taken with.

A typical always-on setup (not tested here): a systemd user service running `qiui-server serve`, `loginctl
enable-linger $USER`, and the laptop configured not to suspend when the lid closes (`HandleLidSwitch=ignore` in
`/etc/systemd/logind.conf`).

### 5. Open the wearer's app

The app is served at the same address as the API. On the wearer's phone open the server's HTTPS address in the
browser and choose **Add to Home Screen**. It then opens like an app, works offline for the countdown, and can
receive notifications.

### 6. Pair the wearer's device

```
qiui-server pairing-code
```

(It asks for your password.) Read the code to the wearer. It works once, for 10 minutes, and a new code replaces it.

**Up to two devices can be paired at once by default**, so one phone can be paired on the LAN address and on the
Tailscale address (each is a separate app to the browser). Change the limit, 1 to 5, with
`qiui-server config set-max-devices N`; it takes effect immediately. A pairing beyond the limit is refused until you
`qiui-server devices` and `qiui-server revoke-device <id>` one. Every pairing still needs a code from you.

---

## Keyholder guide

Every command below signs in for you. Give the password with `QIUI_KEYHOLDER_PASSWORD` (best for scripts) or
`--password` (visible in `ps` and shell history, so the tool warns you), or type it when asked.

### Which commands take the password

**Everything needs the keyholder password except the recovery route.** `--password` (or `QIUI_KEYHOLDER_PASSWORD`,
which is safer) works anywhere on the line, so `timer set 1h --password …` is as good as `timer --password … set 1h`.
A wrong password is refused and recorded in the audit log. **There is no lockout and no delay**: the right password
works immediately, however many wrong ones came before it.

| Commands | Password |
|---|---|
| `status`, `approve`, `deny`, `lock`, `unlock`, `sync`, `timer …`, `queue …`, `message`, `audit` | `--password` |
| `pairing-code`, `devices`, `revoke-device` | `--password` |
| every `config …` command (`show`, `set-client-id`, `set-api-key`, `set-mac`, `set-push-contact`, `set-max-devices`, `import-env`, `encrypt`) | `--password`; the credentials are also encrypted under it |
| `reset-password` | The recovery route: `--pin` and `--new-password`, no password. Also rotates the PIN — see [Forgotten password](#forgotten-password) |
| `init` | Only works before an account exists, so there is no password yet: `--password` is the **new** one, and `--pin` the new recovery PIN |
| `serve`, `identify` | none. `serve` only starts the process (pod control stays locked until you sign in), and `identify` just scans Bluetooth and touches nothing |

With no terminal and no `QIUI_KEYHOLDER_PASSWORD` set, a command that needs the password says so instead of hanging.

![A keyholder session in the terminal](images/cli-keyholder.gif)

*This session is real output from the built binary against a test server with no pod attached.*

### Commands

| Command | What it does |
|---|---|
| `status` | Lock state, timer, approval, queued command, when the pod was last reached, the paired device |
| `approve [--minutes N]` | Approve the wearer's request (default 15 minutes, one use) |
| `deny` | Deny a request, or revoke an approval that has not been used |
| `unlock` / `lock` | Do it now over the server's Bluetooth. `unlock` is refused under a timer |
| `sync` | Reach the pod over Bluetooth and refresh "last reached" |
| `timer set <duration>` | Start a timer of an exact length: `14d`, `36h`, `2d12h30m`, `90m` |
| `timer roll <min> <max>` | Start a timer of random length in that range. The wearer never sees the range or the roll |
| `timer add <duration>` | Add time to the running or paused timer, e.g. `2h`. With no active timer it starts one |
| `timer add-roll <min> <max>` | Add a random amount in that range. The wearer never sees how much |
| `timer pause` / `resume` / `clear` | Freeze, restart or remove the timer |
| `queue lock` / `queue unlock` / `queue cancel` | Have a command carried out the next time the pod can be reached |
| `message "text"` | Send the wearer a message (up to 1000 characters) |
| `audit [--limit N]` | The audit log, newest first, with any failed attempts still pending a summary row shown at the top |
| `pairing-code`, `devices`, `revoke-device <id>` | Manage the wearer's device |
| `reset-password` | Reset the password with the recovery PIN, and rotate the PIN |
| `config …` | `show`, `set-client-id`, `set-api-key`, `set-mac`, `set-push-contact`, `set-max-devices`, `import-env`, `encrypt` |

`lock`, `unlock` and `sync` also work with the server **stopped**: the CLI then talks to the pod directly, applying
the same rules. That is your fallback if the server is down. Because the QIUI credentials are encrypted, this
direct mode always asks for your password (`sync` too), which it uses to decrypt them. The other commands need the
server running.

### Timers

- A timer counts down on the **server's clock**, so changing the phone's clock does nothing.
- **While a timer is running or paused, nobody unlocks**, you included. Pausing is not enough: to unlock you must
  `timer clear` first.
- **Adding time** (`timer add`, `timer add-roll`) makes a running timer end later, or gives a paused timer more time
  while leaving it paused. A timer cannot be made longer than 365 days in total. If there is no active timer (none,
  or one that has ended), `add` simply starts a new one, exactly like `timer set`.
- Starting a timer **cancels a pending request or approval**, because they were granted under different rules.
  You can see this in the demo above (`approval_revoked`).
- When the timer ends, the wearer's **Request unlock** button reopens. They still need your approval.

### Approvals

An approval lasts a set time (15 minutes by default) and can be used once. If it lapses, or a timer starts, it is
gone and the wearer must ask again. An unlock attempt that fails (for example the pod is out of range) does **not**
use the approval up.

### When the pod is out of range: the queue

If you want the pod locked (or unlocked) and it is not near the server, `queue lock` holds the command. It runs:

1. **Automatically**, within about 45 seconds of the pod coming into the server's range, or
2. **From the wearer's phone**, the next time they open the app and connect over Bluetooth.

The rules are checked again when it runs, so a queued unlock is **dropped** if a timer has started since. One
command can be queued at a time.

### The audit log

Every change is recorded: who did it (`keyholder`, `wearer`, `system`, `local-cli`), what, and when. Rolled timers
store both the range and the result. Unlocks and locks record `"via"`: `server`, `phone` or `direct`.

Each row includes a hash of the row before it, so editing or deleting a row is detected: `audit` warns you if the
chain is broken. This catches casual tampering. It cannot stop someone who can rewrite the whole database.

Two events deserve attention:

- `relay_unlock_issued`: unlock bytes were handed to the wearer's phone (see [limits](#security-model-and-limits)).
- `control_lost`: QIUI says the pod is now bound outside this server, for example the wearer re-paired it to the
  QiUi app. The server cannot prevent that; it can only tell you.

**Every event the log can contain** (`actor` is who did it; `system` means the server itself):

| Event | Actor | Meaning |
|---|---|---|
| `unlock_requested`, `request_cancelled` | wearer | The wearer asked to be unlocked, or withdrew the request |
| `unlock_approved`, `request_denied` | keyholder | You approved (with its expiry) or turned down a request |
| `approval_revoked` | keyholder | An unused approval was withdrawn, or a timer started and cancelled it |
| `approval_expired` | system | An approval ran out unused |
| `unlocked`, `locked` | wearer or keyholder | The pod was unlocked or locked; `via` is `server`, `phone` or `direct` |
| `timer_set`, `timer_rolled` | keyholder | A timer started, with its length or its range and the rolled result |
| `timer_extended`, `timer_extension_rolled` | keyholder | Time was added, or a random amount (range and result recorded) |
| `timer_paused`, `timer_resumed`, `timer_cleared` | keyholder | |
| `timer_ended` | system | A timer reached zero. This reopens requests; it unlocks nothing |
| `command_queued`, `command_cancelled` | keyholder | A lock or unlock was queued for later, or the queue was cancelled |
| `queued_command_done`, `queued_command_dropped` | system | A queued command ran (`via` says how), or was dropped because the rules no longer allowed it |
| `relay_unlock_issued` | system | Unlock bytes were handed to the wearer's phone |
| `control_lost` | system | QIUI says the pod is now bound outside this server |
| `message_sent` | keyholder | You sent a message (its id, not its text) |
| `login`, `password_changed` | keyholder | Sign-ins and password changes |
| `login_failed`, `pairing_failed`, `password_change_failed`, `password_reset_failed`, `login_busy`, `password_change_busy` | system or local-cli | A wrong password, pairing code, current password on a password change, or recovery PIN; and (`…_busy`) attempts the server was too busy to even check. **Each route counts on its own**: the command line's password, the API's login, pairing codes, password changes and the PIN, so a flood on one never hides another. **The first failure in a 30-second window gets its own row at once** (`suppressed: 0`). The rest of that window are counted, shown in `audit` immediately as *pending*, and written as one summary row (`summary: true`, with the count) within about 35 seconds, even if nothing else fails afterwards |
| `keyholder_initialised`, `password_reset`, `pin_rotated` | local-cli | Account setup, recovery-PIN resets, and the PIN rotation that follows every successful one |
| `pairing_code_created`, `device_revoked` | keyholder or local-cli | Managing the wearer's devices |
| `max_devices_changed` | local-cli | The paired-device limit was changed |
| `device_paired` | wearer | The wearer paired a device |
| `push_subscribed`, `push_unsubscribed` | wearer | Notifications turned on or off |
| `credentials_sealed`, `credentials_cleared` | local-cli | The QIUI credentials were stored encrypted, or removed after a PIN reset |
| `credentials_unlocked`, `credentials_unlock_failed` | system | They were decrypted at sign-in, or could not be |
| `kdf_upgraded` | system | A password hash, or the sealed QIUI credentials, was re-made under stronger settings at sign-in |
| `credentials_reseal_failed` | system | A password change could not re-encrypt them; re-enter them with `config set-client-id` |
| `platform_token_failed`, `platform_token_recovered` | system | QIUI's 12-hour token could not be renewed, or renewal works again |

### Forgotten password

```
qiui-server reset-password        # asks for the recovery PIN, then a new password
```

Run it on the server machine. Wrong PINs are refused and logged (there is no lockout), and a successful reset signs out every
keyholder session, and the reset is recorded in the audit log as `local-cli`.

**The recovery PIN is one-time.** A successful reset retires the PIN it just verified and issues a new one, so a
PIN that has been used (or seen) once cannot be replayed:

```
qiui-server reset-password --pin ... --new-password ...

Password reset. Every keyholder session was signed out.

The recovery PIN you just used is now retired. New recovery PIN: 9148281112
Write it down now; it will not be shown again.
```

- **`--new-pin <PIN>`** sets the next recovery PIN yourself (6 to 12 digits, same rule as `init`) instead of getting
  a generated one. On success it just confirms `Recovery PIN updated.` — there is nothing new to write down, since
  you chose it.
- **`--quiet` / `-q`** drops the prose for scripting: on success stdout carries only the new PIN (nothing at all if
  `--new-pin` was given), while errors still go to stderr and the exit code is still 0/1 as usual:
  ```sh
  new_pin=$(QIUI_RECOVERY_PIN="$old_pin" QIUI_NEW_PASSWORD="$(openssl rand -base64 24)" \
    qiui-server reset-password --quiet) || { echo "reset failed" >&2; exit 1; }
  ```
- **`--env-file FILE`** writes the new password and new PIN to `FILE` as `QIUI_KEYHOLDER_PASSWORD=...` /
  `QIUI_RECOVERY_PIN=...` lines (the same shape `.qiui_pod_env` uses), creating or overwriting it with mode `600`,
  instead of printing them. Combine with `--quiet` for a fully silent run:
  ```sh
  qiui-server reset-password --quiet --env-file ~/new_pass.env
  ```

Each rotation is also logged to the audit trail as `pin_rotated`.

---

## Wearer guide

![One unlock cycle in the wearer's app](images/app-flow.gif)

*Locked, a timer running, the timer ending, a request, its approval, unlocked. Real screens from the app.*

### Installing and pairing

Open the server's HTTPS address in the phone's browser, choose **Add to Home Screen**, then enter the pairing code
the keyholder gives you. A wrong code is refused with a message, and never blocks the real one.

<img src="images/app-pair.png" alt="Pairing screen" width="260">

### The button

The main button always says what is possible right now:

| State | Button | Why |
|---|---|---|
| Locked, no timer | **Request unlock** | You may ask at any time |
| Locked, timer running or paused | *Unlock requests closed* (greyed out) | Only the keyholder can change the timer |
| Timer ended | **Request unlock** | Asking is allowed again |
| Request sent | *Waiting for approval* (**Cancel request** below it) | The keyholder decides |
| Approved | **Unlock** | Single use, and it times out |
| Unlocked | **Lock** | Ends the unlock; the pod also locks itself soon after opening |

<p>
<img src="images/app-locked.png" alt="Locked, no timer" width="200">
<img src="images/app-timer-running.png" alt="Locked, timer running" width="200">
<img src="images/app-request-sent.png" alt="Request sent" width="200">
<img src="images/app-approved.png" alt="Approved" width="200">
</p>

### The timer and the sync button

The countdown shows days, hours, minutes and seconds, whether the keyholder set an exact time or rolled a random
one. It is drawn from the **server's clock**, so changing the phone's clock does nothing. The circular arrows at the
top right refresh the app from the server and ask it to check the pod; "Pod checked … ago" says when the pod itself
was last reached, because the pod can only be read over Bluetooth.

If the phone goes offline the countdown keeps running from the last reading, and if it reaches zero it is marked
**Ended · unconfirmed**: the keyholder may have changed it since. You can still tap **Request unlock**; the request
is held and sent when you reconnect, and the server checks the timer itself, so it is only accepted if the timer
really ended.

<p>
<img src="images/app-timer-paused.png" alt="Timer paused" width="200">
<img src="images/app-timer-ended.png" alt="Timer ended" width="200">
<img src="images/app-offline.png" alt="Offline, timer unconfirmed" width="200">
</p>

### Unlocking: server or phone

- **Pod within range of the server:** tapping **Unlock** opens it directly. Nothing to connect.
- **Pod out of range:** the app says so and offers **Connect over Bluetooth**, which uses **this phone's Bluetooth**.
  Hold the phone within a metre or two of the pod and keep the screen open. (It asks for a second tap because the
  browser only allows a Bluetooth connection straight after a tap.) The phone disconnects as soon as the command is done.

<p>
<img src="images/app-relay-offer.png" alt="Offered the phone's Bluetooth" width="200">
<img src="images/app-relay-progress.png" alt="Unlocking over the phone's Bluetooth" width="200">
<img src="images/app-unlocked.png" alt="Unlocked" width="200">
</p>

| Phone | Unlock away from the server |
|---|---|
| Android, Chrome | ✔ |
| iPhone, Safari or Chrome | ✘. Apple gives every iOS browser an engine without Web Bluetooth |
| iPhone, a Web Bluetooth browser app (for example *Bluetooth Browser*) | Probably; **not tested** |

On a phone that cannot use Bluetooth the app says so, and you can still unlock whenever the pod is within range of
the server.

<img src="images/app-no-bluetooth.png" alt="A browser without Bluetooth" width="200">

### Messages, activity and queued commands

The **Messages** tab shows what the keyholder has sent. **Activity** tells the story of your lock: requests,
approvals, timer changes (including time being added), unlocks and locks, and who did each. It never shows how a random timer was rolled, or how much time was added. If the
keyholder queued a lock or unlock while you were out of range, a card offers **Connect and apply**.

<p>
<img src="images/app-messages.png" alt="Messages" width="200">
<img src="images/app-activity.png" alt="Activity" width="200">
<img src="images/app-queued.png" alt="A queued command" width="200">
</p>

### Notifications

When the server has notifications set up, the app offers **Turn on notifications** (on the HTTPS address only: the browser
does not allow them on plain HTTP). You are then told when your
keyholder approves or turns down a request, sends a message (the text is shown, so it can appear on your lock
screen), starts, extends, pauses or clears a timer, or queues a command, and when a timer finishes. Things you did yourself
are never notified.

<img src="images/app-notifications.png" alt="The notifications offer" width="200">

- **Android, Chrome:** works from the browser or the installed app.
- **iPhone (iOS 16.4 or later):** only from the app **added to the Home Screen** from Safari.
- The server signs pushes with its own key (`vapid.key`) and encrypts each one for your phone, so the push service
  (Google, Mozilla, Apple) cannot read them. Give push services a contact address with
  `qiui-server config set-push-contact mailto:you@example.com`; Apple in particular can refuse pushes without one.
- Delivery through a real push service has not been tried yet. If nothing arrives, the audit log and
  `qiui-server serve`'s output are the places to look.

---

## Security model and limits

This is what the design does and does not protect against. Read it before relying on it.

**Held by the server, not the phone.** Timer, approvals, and every unlock decision are enforced server-side. A
wearer token is refused on every keyholder route (a test tries each one).

**Secrets.** Passwords and the recovery PIN are Argon2id hashes keyed with a *pepper* stored outside the database;
session tokens and pairing codes are stored only as SHA-256 hashes. A copied database reveals none of them. Back
up `pepper.key` together with the database, or every stored hash becomes unverifiable. Failed logins, PIN guesses
and pairing guesses are never locked out. What slows a guesser is the cost of each check, tuned for that (next paragraph). Failures are still logged: the first in each 30-second window gets its own row at once, and the rest are counted (visible in `audit` immediately, then written as one summary row), so guessing cannot flood the log but is never hidden.

**Password-check cost.** Every password, PIN and encryption key is derived with Argon2id at **128 MiB of memory, 3 passes,
1 lane**: about 230 ms per check on an 8-core laptop. Because there is no lockout, this cost is the brake on guessing, so
the server also protects itself and everyone else while someone guesses:

- At most **two checks run at a time**, with a queue of 32 behind them. Anything beyond that gets "the server is busy,
  try again", never a lockout. That caps a guesser at roughly **10 guesses a second** in total, however many connections
  they open, and bounds memory at about 256 MiB.
- Checks run **away from the database lock**, so a flood of guesses cannot slow the wearer's app or anything else
  (measured: a wearer request took 1 ms with or without 40 connections guessing; with the older single check under the
  lock it took 181 ms).
- **Older hashes are upgraded automatically.** Hashes and sealed credentials record the settings they were made with, so
  changing the cost never breaks anything: a right password re-hashes an older hash, and re-seals older credentials, at
  the next sign-in (both are noted in the audit log as `kdf_upgraded`).

To retune for other hardware, run `cargo run --release --example argon_bench`. It times several settings on the
machine, and the constants are in `KdfParams` in `src/accounts.rs`.

**The web app.** It is served with a strict Content-Security-Policy (no inline scripts or styles, and it may only talk to
this server), and the device token lives in the browser's local storage. Push notification URLs come from the
wearer's device, so the server only sends to https addresses on the known push services (Google, Mozilla, Apple,
Microsoft) and never follows redirects; otherwise a wearer could aim the server at something inside your network.

**The QIUI credentials.** They are the most valuable thing on the machine: the client id lets anyone ask QIUI for
commands for your pod. They are encrypted at rest (XChaCha20-Poly1305, key from your password through Argon2id, mixed
with the pepper) and decrypted only in memory. The limits: a process with access to the running server's memory, or
root on the machine, can still read them; and until the keyholder signs in after a restart, the pod cannot be
controlled at all. The API key is stored the same way, though nothing currently uses it.

**Not protected:**

- **Anyone with a shell on the server machine** cannot pair a device, revoke one, change a setting or touch the pod
  without your password, and cannot read the QIUI client id from disk. They can reset the keyholder password if they
  know the recovery PIN (which wipes the encrypted QIUI credentials, so the pod stays uncontrollable until you
  re-enter them). Root, or anything that can read the server's memory while it runs, can still see decrypted
  values. Treat the machine as keyholder-only.
- **The server listens in plain HTTP on every interface.** Anything on your LAN or tailnet can reach the keyholder login
  and the API, and on the plain-HTTP paths passwords and tokens are readable by anyone else on that network. Use the
  HTTPS address, or the CLI on the server, for keyholder work.
- **Nothing locks guessing out, so the password's strength is the protection.** By your choice there is no lockout, so
  anyone who can reach the API (the wearer, or any device on your LAN or tailnet) can keep trying passwords at about 10 a
  second. That is far too slow for a long passphrase (16 or more characters is now required) and far too fast for a
  short or common one: a list of the million most common passwords would take about 28 hours. Failures are logged, so a
  guessing run is visible in `audit`. The recovery PIN is weaker still, but using it needs a shell on the server.
- **A flood of guesses can crowd out your sign-in over the network.** While more than about 34 connections are guessing at
  once, extra attempts, including yours, are answered "busy". It never locks you out and never slows anything else, and it
  clears the moment the guessing stops. `lock`, `unlock` and `sync` run on the server machine fall back to talking to the
  pod directly when this happens.
- **Phone relay leaks unlock bytes to the wearer's phone.** Testing showed the bytes only work on the connection
  they were made for, and rarely on another (a few hundred possible states, so roughly a 1-in-several-hundred
  chance per reconnect for someone holding captured bytes). Exploiting that needs the wearer to extract the bytes
  (browser developer tools, or an Android Bluetooth log analysed on a computer) and then reconnect many times. It
  is an accepted risk for this design; every issue of unlock bytes is logged as `relay_unlock_issued`. Unlocks over
  the **server's** Bluetooth never expose the bytes.
- **The wearer can take the pod away from the server** by binding it to another platform or app. This cannot be
  prevented, only detected (`control_lost`).
- **Physical access.** This is software protecting a latch. It does not make the pod tamper-proof, and it cannot
  release a pod whose battery has died or whose server is down; keep a plan for getting out (the CLI works without
  the server, and the pod battery level is not reported by this model).
- **The audit chain** detects edits, not a complete rewrite by someone with database write access.

The evidence behind these statements is in [`RESEARCH.md`](../RESEARCH.md) §10.

---

## Troubleshooting

| You see | Meaning and fix |
|---|---|
| "the pod is not within Bluetooth range of the server" | The pod is asleep (press its button; it sleeps after about 10 minutes idle) or too far from the server's adapter |
| First connect after waking fails, second works | Normal for this pod; the server retries once automatically |
| `control_lost` / "bound outside this server" | QIUI codes `500025` or `500059`: the pod is bound to another platform or the QiUi app. Unbind it there, then it can be used again |
| "The keyholder needs to sign in once after the server starts" (`credentials_locked`) | Normal after a restart: the QIUI credentials are encrypted until you sign in. Run any keyholder command, such as `qiui-server status` |
| After a PIN reset: "no QIUI client id stored" | The reset had to remove the encrypted credentials. Run `qiui-server config set-client-id` again |
| "QIUI credentials are not configured" | Run `qiui-server config set-client-id` and restart `serve` |
| QIUI error `500032` / `500033` (no command returned) | QIUI has no session state for the pod yet: a handshake reply must be decrypted first. The server always does this; if you see it, retry after a fresh `sync` |
| A timer blocks `unlock` | Working as designed: `timer clear` first |
| `unlock` refused, "wrong state" | The wearer has not asked, or the approval lapsed |
| Lock state looks wrong after the pod locked itself | The pod re-locks itself soon after opening. `lock` (keyholder) or the wearer's **Lock** button brings the record back in line |
| `audit` warns the chain is broken | Rows were edited or deleted. Treat the log as untrustworthy from the first bad row |
| No notifications | Check the app shows *notifications on* (not the offer), the browser allows them, and on iPhone that the app is on the Home Screen. Push has not been verified against a real push service yet |
| "The server is busy checking passwords" (`busy`) | Something is guessing passwords faster than the server will check them. Wait a moment and try again; `lock`, `unlock` and `sync` on the server fall back to the direct route by themselves. Look for a run of `login_failed` in `audit` |
| "The limit of paired devices has been reached" | Two devices are already paired. `qiui-server devices`, then `revoke-device <id>`, or raise the limit with `qiui-server config set-max-devices` |
| The app works on the LAN address but cannot install or send notifications | That address is plain HTTP, and browsers only allow those features on HTTPS. Use the HTTPS address |
| The app shows old data | It refreshes every 20 seconds and when opened. The circular arrows refresh it now. Offline, it shows what it last saw and says so |
| Battery never shows | The KeyPod API reports 0, which we treat as "not reported" |

---

## API reference

All bodies are JSON. Errors look like `{"error": "…", "code": "…"}` (`code` appears for cases a client may want to
branch on: `out_of_range`, `control_lost`, `pod_timeout`, `pod_error`, `cloud_error`, `relay_expired`, `push_unavailable`, `credentials_locked`, `busy`). Every
response carries `Cache-Control: no-store`. Authenticate with `Authorization: Bearer <token>`.

### Sign-in

| Method and path | Body | Result |
|---|---|---|
| `POST /api/keyholder/login` | `{"password"}` | `{"token", "expires_in_secs"}` (8 hours). A wrong password gets `401`; there is no lockout |
| `POST /api/wearer/pair` | `{"code", "device_name"}` | `{"token"}` for that device (about 400 days, until revoked) |

### Keyholder routes (`/api/keyholder/…`)

| Path | Method | Body | Purpose |
|---|---|---|---|
| `state` | GET | | Lock, timer, approval, queue, pod info, and `paired_devices` (each with last-seen) |
| `approve` | POST | `{"ttl_minutes"?}` (1 to 240) | Approve the request |
| `deny` | POST | | Deny or revoke |
| `unlock`, `lock` | POST | | Do it over the server's Bluetooth |
| `sync` | POST | | Refresh pod info over Bluetooth (`in_range` false is a normal answer) |
| `timer` | POST | `{"duration_secs"}` | Exact timer |
| `timer/roll` | POST | `{"min_secs","max_secs"}` | Random timer; the response adds `rolled_secs` |
| `timer/add` | POST | `{"duration_secs"}` | Add time; starts a timer if none is active. Refused past 365 days in total |
| `timer/add-roll` | POST | `{"min_secs","max_secs"}` | Add a random amount; the response adds `rolled_secs` |
| `timer/pause`, `timer/resume`, `timer/clear` | POST | | |
| `queue` | POST | `{"command": "lock"\|"unlock"}` | Queue a command |
| `queue/cancel` | POST | | |
| `messages` | POST | `{"body"}` | Message the wearer |
| `audit?limit=N` | GET | | `{"chain_intact", "entries", "pending_failures"}`. `pending_failures` lists failed attempts counted but not yet written as a summary row (`actor`, `kind`, `count`, `since_ms`) |
| `pairing-code` | POST | | `{"code", "expires_ms"}` |
| `devices` | GET | | Paired devices |
| `devices/{id}/revoke` | POST | | Sign a device out |
| `password` | POST | `{"current_password","new_password"}` | Change password; signs everyone out |
| `logout` | POST | | |

### Wearer routes (`/api/wearer/…`)

| Path | Method | Purpose |
|---|---|---|
| `state` | GET | `server_time_ms`, `lock`, `approval_expires_ms`, `timer`, `unread_messages`, `queued_command`, `pod`. The rolled value and range are never included |
| `request-unlock`, `cancel-request` | POST | Ask, or withdraw |
| `unlock`, `lock` | POST | Over the server's Bluetooth. `409` with `code: out_of_range` means use the phone relay |
| `sync` | POST | Refresh pod info; rate-limited (`cooldown: true`) |
| `messages` | GET | Messages, marked read |
| `relay/start`, `relay/reply` | POST | Phone-relayed Bluetooth (below) |
| `activity` | GET | The wearer's own story: requests, approvals, timer changes, unlocks, locks. Actor and route only, never details |
| `push/key` | GET | The server's VAPID public key (`404 push_unavailable` if notifications are not set up) |
| `push/subscribe` | POST | `{"endpoint","keys":{"p256dh","auth"}}`. Endpoint must be https on a known push service |
| `push/unsubscribe` | POST | |

### Phone relay

The phone only carries bytes; the server drives the sequence and decides when a command may be minted.

1. `POST /api/wearer/relay/start {"intent": "unlock"|"lock"|"status"|"queued"}` → `{"session_id", "cmd"}`.
   The rules for the intent are checked first, so an unapproved unlock never gets as far as a handshake.
2. Connect to the pod over Bluetooth and write `cmd` to characteristic `0000fff1-…`. The pod answers on `0000fff2-…`.
3. `POST /api/wearer/relay/reply {"session_id", "hex": "<pod reply>"}`.
   - `{"done": false, "cmd": "…"}`: write this next (the unlock or lock bytes), then `reply` again with the pod's answer.
   - `{"done": true, …state}`: finished. **Disconnect now.**
4. A session belongs to one device, lasts two minutes, and each device has at most one at a time.

### A complete wearer flow with curl

```
# keyholder: sign in and make a pairing code
KH=$(curl -s -X POST $S/api/keyholder/login -H 'content-type: application/json' -d '{"password":"…"}' | jq -r .token)
CODE=$(curl -s -X POST $S/api/keyholder/pairing-code -H "authorization: Bearer $KH" | jq -r .code)

# wearer: pair, ask
W=$(curl -s -X POST $S/api/wearer/pair -H 'content-type: application/json' -d "{\"code\":\"$CODE\",\"device_name\":\"phone\"}" | jq -r .token)
curl -s -X POST $S/api/wearer/request-unlock -H "authorization: Bearer $W"

# keyholder: approve; wearer: unlock (server's Bluetooth)
curl -s -X POST $S/api/keyholder/approve -H "authorization: Bearer $KH" -H 'content-type: application/json' -d '{}'
curl -s -X POST $S/api/wearer/unlock -H "authorization: Bearer $W"
```

---

## Files and settings

Everything lives in the **data directory**: `--data-dir`, else `$QIUI_DATA_DIR`, else `~/.local/share/qiui-server`.
The directory is mode 0700 and the files 0600; the server refuses to start if they are looser.

| File | Contents |
|---|---|
| `qiui.db` | SQLite: lock state, accounts, sessions, queue, messages, audit log (WAL mode) |
| `pepper.key` | 32 random bytes that key the password hashes. Back it up with the database |
| `config.json` | Pod address, push contact, and the QIUI client id and API key **encrypted** under your keyholder password |
| `vapid.key` | The server's push-signing key, created on first run |

QIUI's 12-hour platform token is kept **in memory only** and renewed about 30 minutes before it expires (checked every
10 minutes). QIUI returns the same token until it expires, so fetching again after a restart is equivalent, and no
live credential ever sits in the database. If renewal fails, `platform_token_failed` is written to the audit log.

| Variable | Used by |
|---|---|
| `QIUI_KEYHOLDER_PASSWORD` | `init` (the new password), every keyholder command, and `config set-client-id`, `set-api-key`, `import-env`, `encrypt` |
| `QIUI_RECOVERY_PIN`, `QIUI_NEW_PASSWORD` | `init`, `reset-password` |
| `QIUI_NEW_PIN` | `reset-password` — choose the next recovery PIN yourself instead of getting a generated one |
| `QIUI_CLIENT_ID`, `QIUI_API_KEY` | `config set-client-id`, `config set-api-key` |
| `QIUI_DATA_DIR` | Where the state lives |
| `QIUI_SERVER` | Address the keyholder commands talk to (default `http://127.0.0.1:8443`) |

---

## Development

```
cargo test                          # the server: state machine, accounts, API, push, Bluetooth sessions (with fakes)
node --test web/test                # the app's logic: countdown, button rules, the phone-relay loop
```

`scripts/e2e.mjs` runs the real server binary in demo mode and drives the real app in a real browser: pairing,
requesting, approving, unlocking, the offline countdown, the phone-relay flow (with a fake Bluetooth radio), a
browser without Bluetooth, and the notifications offer. It asserts what it sees and takes the screenshots in this
guide.

```
cargo build
npm i playwright-core
CHROME=/path/to/chrome node scripts/e2e.mjs        # SHOTS_DIR=… to keep the screenshots
```

The wearer's app is plain JavaScript with no build step, in `web/`. It is compiled into the binary, so changing it
means rebuilding.
