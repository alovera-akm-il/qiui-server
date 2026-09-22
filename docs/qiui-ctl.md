# `qiui-ctl` — the keyholder command line

`qiui-ctl` is installed by `scripts/deploy.sh` alongside the `qiui-server` systemd service. It is a **one-line
wrapper**, not a different program:

```sh
#!/bin/sh
exec sudo -u qiui --preserve-env=QIUI_KEYHOLDER_PASSWORD,QIUI_RECOVERY_PIN,QIUI_NEW_PASSWORD,QIUI_NEW_PIN \
  env QIUI_DATA_DIR=/var/lib/qiui-server QIUI_SERVER=… /usr/local/bin/qiui-server "$@"
```

It runs the same `qiui-server` binary, as the `qiui` service user, pointed at the service's own data directory
(`/var/lib/qiui-server`). Use it for **every** keyholder command on a machine where the service is installed.

## Why this matters — use `qiui-ctl`, never plain `qiui-server`, on a deployed machine

The plain `qiui-server` binary is also on `PATH` (`/usr/local/bin/qiui-server`) and looks like a perfectly normal way
to run the same commands. It isn't, on a machine with the service installed: run as your own login user, with no
`--data-dir`/`QIUI_DATA_DIR`, it silently defaults to `~/.local/share/qiui-server` — a directory the running service
never reads. Commands report success (`Saved to …`), but nothing changes for the actual service, and pod control
later fails with something like:

```
Error: QIUI's cloud refused: QIUI credentials are not configured. Run `qiui-server config set-client-id`.
```

or, after a restart with no sign-in yet, `credentials_locked`. Both look like a credentials bug; the real cause is
two separate, unrelated data directories that happen to share a binary name. As of this build, running plain
`qiui-server` on a machine with the service installed prints a loud warning naming the mismatch and pointing back
here — but the simplest fix is to just always use `qiui-ctl` and never invoke `qiui-server` directly once the
service is installed.

| | `qiui-ctl` | plain `qiui-server` |
|---|---|---|
| Runs as | the `qiui` service user (via `sudo -u qiui`) | whoever is logged in |
| Data directory | always `/var/lib/qiui-server` (the real service's data) | `~/.local/share/qiui-server` by default — **not** the service's data, unless you pass `--data-dir`/`QIUI_DATA_DIR` yourself |
| Right tool for | every keyholder command, on the machine running the service | development only: `cargo run`, `serve --simulate-pod`, or a machine with no service installed |

`sudo` resets the environment by default, but `scripts/deploy.sh` also installs a scoped sudoers drop-in,
`/etc/sudoers.d/qiui-ctl-env`:

```
Defaults!/usr/local/bin/qiui-server env_keep += "QIUI_KEYHOLDER_PASSWORD QIUI_RECOVERY_PIN QIUI_NEW_PASSWORD QIUI_NEW_PIN"
```

That's what lets the wrapper's `--preserve-env=…` above actually work: those four variables, and only those, pass
through from your shell into the `qiui-server` process — **as environment, never as an argument**, so they never
appear in `ps` output or shell history. A `.env` file works exactly like it would running `qiui-server` directly:

```sh
source ~/old_pass.env      # sets QIUI_KEYHOLDER_PASSWORD (and/or QIUI_RECOVERY_PIN)
qiui-ctl status             # picks it up silently
```

`--password`/`--pin` on the command line still work too, but are visible in `ps` and shell history for as long as
they're there — the CLI warns you about that when it detects a secret flag on the line. If you ever need a variable
that isn't in that list to reach the sudo'd process, either add it to the sudoers drop-in and the wrapper's
`--preserve-env=…` list (rebuild by re-running `scripts/deploy.sh`), or fall back to
`sudo -u qiui env QIUI_DATA_DIR=/var/lib/qiui-server SOME_VAR=… /usr/local/bin/qiui-server …` directly — but then
that value *is* visible in `ps` for the duration of the call.

---

## Quick reference

```sh
qiui-ctl status                              # lock state, timer, approval, queue, pod
qiui-ctl approve --minutes 15
qiui-ctl deny
qiui-ctl unlock                              # over the server's Bluetooth
qiui-ctl lock
qiui-ctl sync                                # refresh "pod last reached"

qiui-ctl timer set 14d
qiui-ctl timer roll 6h 48h
qiui-ctl timer add 2h
qiui-ctl timer add-roll 30m 4h
qiui-ctl timer pause
qiui-ctl timer resume
qiui-ctl timer clear

qiui-ctl queue lock                          # or: queue unlock, queue cancel

qiui-ctl message "back in an hour"
qiui-ctl audit --limit 50

qiui-ctl pairing-code
qiui-ctl devices
qiui-ctl revoke-device 3

qiui-ctl config show
qiui-ctl config set-client-id
qiui-ctl config set-api-key
qiui-ctl config set-mac E5:26:D6:6E:B6:8A
qiui-ctl config set-push-contact mailto:you@example.com
qiui-ctl config set-max-devices 2
qiui-ctl config import-env ~/qiui-keypod/.qiui_pod_env
qiui-ctl config encrypt

qiui-ctl init                                # first time only
qiui-ctl reset-password                      # forgotten password, via the recovery PIN
qiui-ctl identify                            # scan Bluetooth for KeyPods, no cloud calls
```

---

## Authentication

Almost every command needs the keyholder password. Give it with `--password` (works anywhere on the command line —
`qiui-ctl timer set 1h --password …` and `qiui-ctl timer --password … set 1h` are equivalent) or answer the
interactive prompt. `--password` is visible in `ps` and shell history, so `qiui-ctl` warns you when you use it.

There is **no lockout and no delay**: a wrong password is refused and logged, but the right one always works
immediately, however many wrong attempts came before it.

| Commands | Password needed |
|---|---|
| `status`, `approve`, `deny`, `lock`, `unlock`, `sync`, `timer …`, `queue …`, `message`, `audit` | ✔ |
| `pairing-code`, `devices`, `revoke-device` | ✔ |
| every `config …` subcommand (`show`, `set-client-id`, `set-api-key`, `set-mac`, `set-push-contact`, `set-max-devices`, `import-env`, `encrypt`) | ✔ — the QIUI credentials are also (re-)encrypted under it |
| `reset-password` | Not the password: `--pin` (recovery PIN) and `--new-password` |
| `init` | Only runs before an account exists. `--password`/`--pin` are the ones you're **creating** |
| `identify` | none — a local Bluetooth scan only, no cloud, no data-dir access |

With no terminal to prompt and no password supplied, a command that needs one fails immediately with a clear error
instead of hanging.

---

## Command reference

### Status and control

| Command | What it does |
|---|---|
| `status` | Lock state, timer, pending approval, queued command, when the pod was last reached, the paired device(s) |
| `approve [--minutes N]` | Approve the wearer's pending unlock request. Default 15 minutes, single use |
| `deny` | Deny a pending request, or revoke an approval that hasn't been used yet |
| `unlock` | Unlock now, over the server's Bluetooth. Refused while a timer is running or paused |
| `lock` | Lock now. Always allowed, any state |
| `sync` | Reach the pod over Bluetooth and refresh "last reached"/battery info |

`lock`, `unlock` and `sync` also work with the systemd service **stopped** — the CLI then talks to the pod directly,
applying the same rules the server would. That's your fallback if the service is down. Because the QIUI credentials
are encrypted, this direct path always asks for your password, which it needs to decrypt them on the spot.

### Timers

| Command | What it does |
|---|---|
| `timer set <duration>` | Start a timer of an exact length: `14d`, `36h`, `2d12h30m`, `90m` |
| `timer roll <min> <max>` | Start a timer of random length in that range. The wearer never sees the range or the result |
| `timer add <duration>` | Add time to a running or paused timer. With none active, starts one (same as `set`) |
| `timer add-roll <min> <max>` | Add a random amount in that range. The wearer never sees how much |
| `timer pause` | Freeze the running timer |
| `timer resume` | Resume a paused timer |
| `timer clear` | Remove the timer entirely |

While a timer is running or paused, **nobody unlocks**, keyholder included — `timer clear` first. A timer cannot
exceed 365 days total. Starting a timer cancels any pending request or unused approval. When a timer ends, it only
reopens the wearer's **Request unlock** button; nothing unlocks by itself.

### Queue (for when the pod is out of range)

| Command | What it does |
|---|---|
| `queue lock` | Have the pod locked the next time it's reachable |
| `queue unlock` | Same, for unlock |
| `queue cancel` | Cancel the pending queued command |

Runs automatically within ~45 seconds of the pod coming into the server's range, or from the wearer's phone the next
time it connects. Rules are re-checked when it actually runs, so a queued unlock is dropped if a timer started since
it was queued. One command can be queued at a time.

### Messages and audit

| Command | What it does |
|---|---|
| `message "text"` | Send the wearer a message (up to 1000 characters) |
| `audit [--limit N]` | Audit log, newest first, including failed-attempt summaries still pending a row |

### Pairing and devices

| Command | What it does |
|---|---|
| `pairing-code` | Print a one-time code, valid 10 minutes, for the wearer's phone to pair |
| `devices` | List paired wearer devices |
| `revoke-device <id>` | Sign a device out permanently |

Up to 2 devices may be paired by default (`config set-max-devices` to change, 1–5).

### `config` — QIUI credentials and pod settings

| Command | What it does |
|---|---|
| `config show` | What's configured. Never displays a secret |
| `config set-client-id [value]` | Set the QIUI client id, sealed under your keyholder password. Prompts (hidden input) if omitted |
| `config set-api-key [value]` | Set the QIUI API key, sealed the same way. **Currently unused by any cloud call** (QIUI's auth only needs the client id — confirmed against the live API; see `RESEARCH.md` §3) — stored for completeness/future use, not required for unlock to work |
| `config set-mac <address>` | The pod's Bluetooth MAC address |
| `config set-push-contact <mailto:… or https:…>` | Contact address given to push services (some, e.g. Apple, may refuse pushes without one) |
| `config set-max-devices <1-5>` | How many wearer devices may be paired at once; takes effect immediately |
| `config import-env [path]` | Import `QIUI_CLIENT_ID`/`QIUI_PROD_API_KEY` from an old `.qiui_pod_env` file (default `./.qiui_pod_env`), sealed on import. **Strip any surrounding quotes** if the file quotes its values — the importer expects the raw value after `=` |
| `config encrypt` | Migrate an old plain-text `config.json` to sealed storage |

Every `config` write prints the directory it saved to (`Saved to /var/lib/qiui-server, …`) — check that line reads
`/var/lib/qiui-server`, not somewhere under a home directory, before assuming a change took effect.

**After any `config` change, restart the service** (`sudo systemctl restart qiui-server`) so it re-reads
`config.json`, then sign in once (`qiui-ctl status` is enough) to decrypt the credentials into memory. Sealed
credentials **do not survive a restart in decrypted form** by design — see [Files and settings](#files-and-settings).

### Account administration

| Command | What it does |
|---|---|
| `init` | Create the keyholder account: a password (16+ characters) and a 6–12 digit recovery PIN. First time only |
| `reset-password` | Reset the password using the recovery PIN (`--pin`, `--new-password`). The PIN is one-time: on success it is retired and a new one is generated and printed (or set with `--new-pin`, to choose your own). `--quiet`/`-q` prints nothing but the new PIN (or nothing at all with `--new-pin`), for scripting. `--env-file FILE` writes the new password and PIN to FILE as `KEY=value` lines (mode 600) instead of printing them. Signs out every session. **Removes the sealed QIUI credentials** (a PIN is too weak to protect them) — re-enter them afterwards with `config set-client-id`/`set-api-key` |
| `identify` | Scan Bluetooth and report which nearby devices look like KeyPods. No QIUI/cloud calls, no data-dir access |

---

## Typical workflows

### First-time setup on a freshly deployed service

```sh
qiui-ctl init                                        # choose password + recovery PIN
qiui-ctl config set-client-id                         # prompts, hidden
qiui-ctl config set-api-key                           # prompts, hidden (see note above: currently unused)
qiui-ctl config set-mac E5:26:D6:6E:B6:8A
sudo systemctl restart qiui-server                    # pick up config.json
qiui-ctl status                                       # first sign-in decrypts credentials into memory
```

### Day to day

```sh
qiui-ctl status
qiui-ctl approve --minutes 20
qiui-ctl timer set 3d
journalctl -u qiui-server -f                          # service logs
```

### Changing the QIUI credentials later

```sh
qiui-ctl config set-client-id
sudo systemctl restart qiui-server
qiui-ctl status                                       # sign in again to decrypt the new credentials
```

### Forgotten keyholder password

```sh
qiui-ctl reset-password --pin ...
# a new recovery PIN is printed once — write it down now, it replaces the one you just used
# (pass --new-pin ... instead to choose your own)
# then, since the sealed credentials were just removed:
qiui-ctl config set-client-id
qiui-ctl config set-api-key
sudo systemctl restart qiui-server
qiui-ctl status
```

### Scripted rotation

`--quiet` (`-q`) strips the prose so stdout carries only the value a script needs; errors and the
exit code (0/1) are unaffected, so this composes with normal shell error handling:

```sh
new_pin=$(QIUI_RECOVERY_PIN="$old_pin" QIUI_NEW_PASSWORD="$(openssl rand -base64 24)" \
  qiui-ctl reset-password --quiet) || { echo "reset failed" >&2; exit 1; }
# $new_pin now holds the freshly generated recovery PIN — store it somewhere safe
```

Or skip stdout entirely and have the new password and PIN written straight to a credentials file,
in the same `KEY=value` shape as `.qiui_pod_env` — handy for chaining into the next scripted reset:

```sh
old_pass=$(cut -d= -f2 <(grep QIUI_KEYHOLDER_PASSWORD ~/old_pass.env))
old_pin=$(cut -d= -f2 <(grep QIUI_RECOVERY_PIN ~/old_pass.env))

QIUI_RECOVERY_PIN="$old_pin" QIUI_NEW_PASSWORD="$(openssl rand -base64 24)" \
  qiui-ctl reset-password --quiet --env-file ~/new_pass.env
mv ~/new_pass.env ~/old_pass.env   # ready for the next rotation
```

`--env-file` writes `QIUI_KEYHOLDER_PASSWORD=...` and `QIUI_RECOVERY_PIN=...` to the given path,
creating it (or overwriting it) with permissions `600`. Combine it with `--quiet` for a fully
silent run, or drop `--quiet` to also get the usual status line on stdout.

---

## Troubleshooting

| You see | Cause and fix |
|---|---|
| `Error: QIUI's cloud refused: QIUI credentials are not configured. Run \`qiui-server config set-client-id\`.` | No `config.json` (or no `client_id`/sealed secrets in it) at `/var/lib/qiui-server`. Confirm with `qiui-ctl config show`, then `qiui-ctl config set-client-id` and restart the service |
| `Error: QIUI's cloud refused: ... QIUI code 500037: 平台ClientId无效` ("invalid ClientId") | The stored client id is not one QIUI recognizes. Common cause: it was sealed with stray characters — e.g. surrounding quotes copied in from a `KEY="value"`-style `.env` file. Re-run `config set-client-id` with the bare value (no quotes) and restart |
| `credentials_locked` / "the keyholder needs to sign in once" | Normal right after a restart: sealed credentials are locked until a keyholder sign-in. Run `qiui-ctl status` |
| A `config` command reports success but nothing changes for the running service | You ran plain `qiui-server` instead of `qiui-ctl` (or `qiui-ctl` without going through `sudo -u qiui`), and it wrote to the wrong data directory. Re-run through `qiui-ctl`, and check the `Saved to …` line names `/var/lib/qiui-server` |
| `QIUI_KEYHOLDER_PASSWORD` set in the shell is ignored by `qiui-ctl` | Check `/etc/sudoers.d/qiui-ctl-env` exists (`scripts/deploy.sh` installs it) — without it, `sudo` resets the environment and you need `--password` or the interactive prompt instead |
| "the pod is not within Bluetooth range of the server" | Pod asleep (press its button; sleeps after ~10 min idle) or out of range |
| `control_lost` / "bound outside this server" | QIUI codes `500025`/`500059`: the pod is bound to the consumer app or another platform. Unbind it there |
| A timer blocks `unlock` | Working as designed — `qiui-ctl timer clear` first |
| "The server is busy checking passwords" | Something is guessing passwords faster than the server will check them (no lockout, so a guesser is throttled instead). Wait and retry; `lock`/`unlock`/`sync` fall back to the direct route automatically |

For everything else (the wearer's app, the HTTP API, security model, the full audit event list), see
[`usage.md`](usage.md).

---

## Files and settings

`qiui-ctl` always points at `/var/lib/qiui-server` (mode `0700`, owned by the `qiui` user):

| File | Contents |
|---|---|
| `qiui.db` | SQLite: lock state, accounts, sessions, queue, messages, audit log |
| `pepper.key` | 32 random bytes that key the password hashes. Back it up with the database |
| `config.json` | Pod MAC, push contact, and the QIUI client id/API key **encrypted** under the keyholder password |
| `vapid.key` | The push-signing key, created on first run |

The QIUI credentials are sealed with a key derived from your keyholder password (plus `pepper.key`) and are **never
written to disk decrypted**. The running service keeps a decrypted copy in memory only after a successful sign-in,
which is why a restart re-locks pod control until you run any keyholder command again.

| Variable | Used by |
|---|---|
| `QIUI_KEYHOLDER_PASSWORD` | Any keyholder command, including through `qiui-ctl` (preserved through `sudo` via `/etc/sudoers.d/qiui-ctl-env`) |
| `QIUI_RECOVERY_PIN`, `QIUI_NEW_PASSWORD` | `init`, `reset-password` |
| `QIUI_NEW_PIN` | `reset-password` — choose the next recovery PIN yourself instead of getting a generated one |
| `QIUI_CLIENT_ID`, `QIUI_API_KEY` | `config set-client-id`, `config set-api-key` |
| `QIUI_DATA_DIR` | Already fixed to `/var/lib/qiui-server` inside `qiui-ctl` — you shouldn't need to set this yourself |
| `QIUI_SERVER` | Address the keyholder commands talk to (default `http://127.0.0.1:8443`; `qiui-ctl` runs on the same host as the service) |
