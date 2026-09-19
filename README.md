# qiui-server
A QiUi local server for cages.

Rust port of the Python KeyPod scripts (cloud command generation via the QIUI
Open Platform API + local BLE via btleplug). See RESEARCH notes for protocol details.

```
# .qiui_pod_env (gitignored) must contain QIUI_CLIENT_ID=...
cargo run -- identify
cargo run -- status --debug
cargo run -- unlock
cargo run -- lock
```
Needs BlueZ + libdbus dev headers on Linux.

## Running the server

```
qiui-server init                      # keyholder password + recovery PIN (prompted, hidden)
qiui-server serve                     # http://127.0.0.1:8443, loopback only
tailscale serve --bg https / http://127.0.0.1:8443   # TLS for phones; the PWA needs HTTPS
qiui-server pairing-code              # one-time code for the wearer's device
qiui-server devices / revoke-device <id>
qiui-server reset-password            # needs the recovery PIN; local shell only
```

State lives in `~/.local/share/qiui-server` (or `--data-dir` / `$QIUI_DATA_DIR`): `qiui.db` and `pepper.key`,
both mode 0600. The pepper is what makes a copied database useless for guessing passwords; back it up with the
database or every stored hash becomes unverifiable.

`lock` and `unlock` ask for the keyholder password and refuse to unlock while a timer is running or paused.

### Scripting

Anything that prompts can be given its secret up front. Prefer environment variables: a `--password` flag is
visible in `ps` and saved in shell history (the tool warns if you use one).

| Command | Environment variables | Flags |
|---|---|---|
| `init` | `QIUI_KEYHOLDER_PASSWORD`, `QIUI_RECOVERY_PIN` | `--password`, `--pin` |
| `reset-password` | `QIUI_RECOVERY_PIN`, `QIUI_NEW_PASSWORD` | `--pin`, `--new-password` |
| `lock`, `unlock` | `QIUI_KEYHOLDER_PASSWORD` | `--password` |

```
QIUI_KEYHOLDER_PASSWORD=... qiui-server unlock
```

## API

`POST /api/keyholder/login` returns a bearer token (8 h). `POST /api/wearer/pair` trades a pairing code for a
device token. Keyholder routes live under `/api/keyholder/*` (state, approve, deny, timer, timer/roll,
timer/pause, timer/resume, timer/clear, messages, audit, pairing-code, devices, password, logout); wearer routes
under `/api/wearer/*` (state, request-unlock, cancel-request, messages). A wearer token is refused on every
keyholder route.
