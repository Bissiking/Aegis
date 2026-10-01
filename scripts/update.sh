#!/usr/bin/env bash
#
# Updates an installed Aegis from a checkout of this repository:
#   * rebuilds the frontend and both binaries
#   * replaces /usr/local/bin/aegis{,-agent} and /usr/share/aegis/web
#   * restarts the services (migrations run automatically on startup)
#
# Usage:
#   sudo ./scripts/update.sh
#
# A database backup is taken first; see scripts/backup.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '\033[1;34m[aegis]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[aegis]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
command -v go >/dev/null 2>&1 || die "go toolchain not found"
command -v npm >/dev/null 2>&1 || die "node/npm not found"

log "creating a backup first"
"${ROOT}/scripts/backup.sh" || die "backup failed, aborting update"

log "building frontend"
( cd "${ROOT}/web" && npm ci --silent && npm run build )

log "building binaries"
BIN="${ROOT}/build"
mkdir -p "$BIN"
( cd "$ROOT" \
  && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BIN/aegis" ./cmd/aegis \
  && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BIN/aegis-agent" ./cmd/aegis-agent )

log "stopping services"
systemctl stop aegis.service 2>/dev/null || true
systemctl stop aegis-agent.service 2>/dev/null || true

log "installing new binaries and frontend"
install -m 0755 -o root -g root "$BIN/aegis" /usr/local/bin/aegis
install -m 0755 -o root -g root "$BIN/aegis-agent" /usr/local/bin/aegis-agent
rm -rf /usr/share/aegis/web
install -d -m 0755 -o root -g root /usr/share/aegis/web
cp -r "${ROOT}/web/dist/." /usr/share/aegis/web/

if [ -d /run/systemd/system ]; then
  install -m 0644 -o root -g root "${ROOT}/deploy/aegis.service" /etc/systemd/system/aegis.service
  install -m 0644 -o root -g root "${ROOT}/deploy/aegis-agent.service" /etc/systemd/system/aegis-agent.service
  systemctl daemon-reload
  log "starting services"
  systemctl start aegis-agent.service
  systemctl start aegis.service
fi

log "update complete"
systemctl --no-pager --full status aegis.service 2>/dev/null | head -n 5 || true
