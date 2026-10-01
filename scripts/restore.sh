#!/usr/bin/env bash
#
# Restores an archive produced by scripts/backup.sh.
#
# Usage:
#   sudo ./scripts/restore.sh /var/backups/aegis/aegis-YYYYmmdd-HHMMSS.tar.gz
#
# The services are stopped before anything is written and started again at the
# end. WireGuard peers present in the archive are re-synced by the panel.
set -euo pipefail

ARCHIVE="${1:-}"
DB="${AEGIS_DATABASE_PATH:-/var/lib/aegis/aegis.db}"
ENV_FILE="${AEGIS_CONFIG:-/etc/aegis/aegis.env}"
WG_DIR="${AEGIS_WG_CONF_DIR:-/etc/wireguard}"

log() { printf '[aegis] %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
[ -n "$ARCHIVE" ] || { echo "usage: $0 <archive.tar.gz>" >&2; exit 2; }
[ -f "$ARCHIVE" ] || { echo "not found: $ARCHIVE" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log "extracting $ARCHIVE"
tar -C "$WORK" -xzf "$ARCHIVE"
[ -f "$WORK/aegis.db" ] || { echo "archive does not contain a database" >&2; exit 1; }
command -v sqlite3 >/dev/null 2>&1 && {
  sqlite3 "$WORK/aegis.db" "PRAGMA integrity_check;" | grep -qi '^ok$' || {
    echo "snapshot failed its integrity check" >&2; exit 1;
  }
}

log "stopping services"
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop aegis.service 2>/dev/null || true
  systemctl stop aegis-agent.service 2>/dev/null || true
fi

log "restoring database -> $DB"
install -d -m 0750 -o aegis -g aegis "$(dirname "$DB")"
cp -a "$WORK/aegis.db" "$DB"
rm -f "${DB}-wal" "${DB}-shm"
chown aegis:aegis "$DB"
chmod 0600 "$DB"

if [ -f "$WORK/aegis.env" ]; then
  log "restoring configuration -> $ENV_FILE"
  cp -a "$WORK/aegis.env" "$ENV_FILE"
  chown root:aegis "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
fi

if [ -d "$WORK/wireguard" ]; then
  log "restoring $WG_DIR"
  mkdir -p "$WG_DIR"
  cp -a "$WORK/wireguard/." "$WG_DIR/"
  chmod 0700 "$WG_DIR"
fi

log "starting services"
if command -v systemctl >/dev/null 2>&1; then
  systemctl start aegis-agent.service 2>/dev/null || true
  systemctl start aegis.service 2>/dev/null || true
fi

log "restore complete"
