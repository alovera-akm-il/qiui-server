#!/usr/bin/env bash
# Install, update or remove qiui-server as a systemd service.
#
#   scripts/deploy.sh                 build, install and (re)start the service
#   scripts/deploy.sh --no-start      install but do not start it
#   scripts/deploy.sh --bind ADDR     listen on ADDR (default 0.0.0.0:8443), saved in /etc/qiui-server/service.env
#   scripts/deploy.sh --uninstall     stop and remove the service and program; keeps the data
#   scripts/deploy.sh --uninstall --purge   ...and delete the data (database, keys) and the service user
#
# Safe to run again: it updates in place and keeps the data and your settings.
# It does not touch Tailscale, other web servers or firewalls.
set -euo pipefail

SERVICE=qiui-server
USER_NAME=qiui
BIN=/usr/local/bin/qiui-server
CTL=/usr/local/bin/qiui-ctl
ETC=/etc/qiui-server
DATA=/var/lib/qiui-server
DOCS=/usr/local/share/doc/qiui-server
UNIT=/etc/systemd/system/${SERVICE}.service
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

start=1 uninstall=0 purge=0 bind=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-start) start=0 ;;
    --uninstall) uninstall=1 ;;
    --purge) purge=1 ;;
    --bind) bind="${2:?--bind needs an address like 0.0.0.0:8443}"; shift ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done
[ "$purge" = 0 ] || [ "$uninstall" = 1 ] || { echo "--purge only makes sense with --uninstall" >&2; exit 2; }

say() { printf '==> %s\n' "$*"; }
# Run as yourself: it asks for sudo only where it must. As root, cargo would build the project as root
# (often with no cargo on root's PATH) and leave root-owned files in target/.
if [ "$(id -u)" -eq 0 ]; then
  echo "run this as your normal user, not root or with sudo; it uses sudo itself where needed" >&2
  exit 1
fi
SUDO=sudo
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }

if [ "$uninstall" = 1 ]; then
  say "stopping and removing the service"
  $SUDO systemctl disable --now "$SERVICE" 2>/dev/null || true
  $SUDO rm -f "$UNIT" "$BIN" "$CTL" /etc/sudoers.d/qiui-ctl-env
  $SUDO rm -rf "$DOCS"
  $SUDO systemctl daemon-reload
  if [ "$purge" = 1 ]; then
    say "deleting the data, settings and the service user"
    $SUDO rm -rf "$DATA" "$ETC"
    id "$USER_NAME" >/dev/null 2>&1 && $SUDO userdel "$USER_NAME" || true
  else
    say "kept $DATA and $ETC (use --purge to delete them)"
  fi
  exit 0
fi

# ---- build as the invoking user, never as root ----
say "building (release)"
( cd "$HERE" && cargo build --release --locked )
NEW="$HERE/target/release/qiui-server"
[ -x "$NEW" ] || { echo "build produced no binary" >&2; exit 1; }

# ---- service user: no login, no home, in the bluetooth group ----
if ! id "$USER_NAME" >/dev/null 2>&1; then
  say "creating the $USER_NAME service user"
  $SUDO useradd --system --no-create-home --home-dir "$DATA" --shell /usr/sbin/nologin "$USER_NAME"
fi
if getent group bluetooth >/dev/null; then
  $SUDO usermod -aG bluetooth "$USER_NAME"
else
  echo "warning: no 'bluetooth' group; install and enable BlueZ or the pod cannot be reached" >&2
fi

# ---- program, docs, unit ----
say "installing the program"
$SUDO install -m 0755 "$NEW" "$BIN"
$SUDO install -d -m 0755 "$DOCS"
$SUDO install -m 0644 "$HERE/docs/usage.md" "$DOCS/usage.md"
$SUDO install -m 0644 "$HERE/deploy/qiui-server.service" "$UNIT"

# ---- settings (kept across updates unless --bind is given) ----
$SUDO install -d -m 0755 "$ETC"
if [ -n "$bind" ]; then
  say "saving the listen address $bind"
  printf 'QIUI_BIND=%s\n' "$bind" | $SUDO tee "$ETC/service.env" >/dev/null
  $SUDO chmod 0644 "$ETC/service.env"
fi

# ---- qiui-ctl: run the CLI as the service user, on the service's data ----
say "installing qiui-ctl (the keyholder command line for this service)"
$SUDO tee "$CTL" >/dev/null <<CTLEOF
#!/bin/sh
# Runs qiui-server as the service user against the installed service's data,
# and talks to the port the service actually listens on (from QIUI_BIND in
# $ETC/service.env, default 8443) rather than a hardcoded guess — so this
# still works after \`qiui-server config set-...\` or a manual --bind change.
PORT=\$(sed -n 's/^QIUI_BIND=.*:\([0-9]*\)\$/\1/p' $ETC/service.env 2>/dev/null | tail -n1)
# --preserve-env carries these from your shell into the sudo'd process without ever putting the
# value in argv (so it never shows in \`ps\` or shell history) — allowed only for this exact binary,
# via /etc/sudoers.d/qiui-ctl-env.
exec sudo -u $USER_NAME --preserve-env=QIUI_KEYHOLDER_PASSWORD,QIUI_RECOVERY_PIN,QIUI_NEW_PASSWORD,QIUI_NEW_PIN \\
  env QIUI_DATA_DIR=$DATA QIUI_SERVER="http://127.0.0.1:\${PORT:-8443}" $BIN "\$@"
CTLEOF
$SUDO chmod 0755 "$CTL"

# Let qiui-ctl's `sudo --preserve-env=...` (above) actually carry the QIUI_* secrets through: sudo
# refuses to preserve any variable that isn't explicitly allowed, and only for this one binary.
say "allowing qiui-ctl to pass QIUI_* secrets through sudo without exposing them in argv"
SUDOERS_D=/etc/sudoers.d/qiui-ctl-env
TMP_SUDOERS="$(mktemp)"
printf 'Defaults!%s env_keep += "QIUI_KEYHOLDER_PASSWORD QIUI_RECOVERY_PIN QIUI_NEW_PASSWORD QIUI_NEW_PIN"\n' "$BIN" > "$TMP_SUDOERS"
$SUDO visudo -c -f "$TMP_SUDOERS" >/dev/null
$SUDO install -m 0440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_D"
rm -f "$TMP_SUDOERS"

say "loading the service"
$SUDO systemctl daemon-reload
$SUDO systemctl enable "$SERVICE" >/dev/null
if [ "$start" = 1 ]; then
  $SUDO systemctl restart "$SERVICE"
  sleep 1
  if $SUDO systemctl is-active --quiet "$SERVICE"; then
    say "running"
  else
    echo "the service did not start; see: journalctl -u $SERVICE -n 50" >&2
    exit 1
  fi
else
  say "installed, not started (start it with: sudo systemctl start $SERVICE)"
fi

cat <<MSG

Next:
  qiui-ctl init                 first time only: create the keyholder account
  qiui-ctl config encrypt       first time only: store the QIUI client id and API key (sealed)
  qiui-ctl status --password ...   the first keyholder sign-in after each start unlocks pod control

Logs:     journalctl -u $SERVICE -f
Stop:     sudo systemctl stop $SERVICE
Update:   git pull && scripts/deploy.sh
Remove:   scripts/deploy.sh --uninstall
MSG
