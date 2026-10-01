#!/usr/bin/env bash
#
# Creates a consistent snapshot of an Aegis installation:
#   * the SQLite database (online, via sqlite3 .backup when available)
#   * /etc/aegis/aegis.env  (secrets: keep the result safe)
#   * /etc/wireguard        (persistent peer configuration)
#
# Usage:
#   sudo ./scripts/backup.sh [output-dir]
#
# Environment:
#   AEGIS_DATABASE_PATH  (default /var/lib/aegis/aegis.db)
#   AEGIS_CONFIG         (default /etc/aegis/aegis.env)
#   AEGIS_KEEP           number of archives to keep (default 14)
set -euo pipefail

DB="${AEGIS_DATABASE_PATH:-/var/lib/aegis/aegis.db}"
ENV_FILE="${AEGIS_CONFIG:-/etc/aegis/aegis.env}"
WG_DIR="${AEGIS_WG_CONF_DIR:-/etc/wireguard}"
KEEP="${AEGIS_KEEP:-14}"
OUT_DIR="${1:-/var/backups/aegis}"
STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { printf '[aegis] %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
command -v sqlite3 >/dev/null 2>&1 || { echo "sqlite3 is required" >&2; exit 1; }

mkdir -p "$OUT_DIR"
chmod 0700 "$OUT_DIR"

log "snapshotting database $DB"
sqlite3 "file:${DB}?mode=ro" ".backup '${WORK}/aegis.db'"
sqlite3 "${WORK}/aegis.db" "PRAGMA integrity_check;" | grep -qi '^ok$' || {
  echo "integrity check failed on the snapshot" >&2
  exit 1
}

if [ -f "$ENV_FILE" ]; then
  log "copying configuration $ENV_FILE"
  cp -a "$ENV_FILE" "$WORK/aegis.env"
fi

if [ -d "$WG_DIR" ]; then
  log "copying $WG_DIR"
  cp -a "$WG_DIR" "$WORK/wireguard"
fi

ARCHIVE="${OUT_DIR}/aegis-${STAMP}.tar.gz"
tar -C "$WORK" -czf "$ARCHIVE" .
chmod 0600 "$ARCHIVE"
log "wrote $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

# Retention.
ls -1t "${OUT_DIR}"/aegis-*.tar.gz 2>/dev/null | tail -n "+$((KEEP + 1))" | while read -r old; do
  log "pruning $old"
  rm -f "$old"
done
