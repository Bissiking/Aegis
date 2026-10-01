#!/usr/bin/env bash
#
# Aegis installer for Debian/Ubuntu.
#
#   sudo ./deploy/install.sh            # build from source and install
#   sudo ./deploy/install.sh --no-build # install binaries from ./build
#
# It installs:
#   /usr/local/bin/aegis            unprivileged web panel
#   /usr/local/bin/aegis-agent      privileged WireGuard agent (root, CAP_NET_ADMIN)
#   /usr/share/aegis/web            built frontend
#   /etc/aegis/aegis.env            configuration (0600)
#   /etc/sysctl.d/90-aegis.conf     ip forwarding
#   /etc/systemd/system/aegis*.service
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="${ROOT}/build"
DO_BUILD=1

for arg in "$@"; do
  case "$arg" in
    --no-build) DO_BUILD=0 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\033[1;34m[aegis]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[aegis]\033[0m %s\n' "$*" >&2; exit 1; }

rand_b64() { # $1 = number of bytes
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$1" | tr -d '\n'
  else
    head -c "$1" /dev/urandom | base64 | tr -d '\n'
  fi
}
rand_hex() { # $1 = number of bytes
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    od -An -tx1 -N "$1" /dev/urandom | tr -d ' \n'
  fi
}

[ "$(id -u)" -eq 0 ] || die "this installer must run as root"

if [ ! -f /etc/debian_version ]; then
  die "only Debian/Ubuntu are supported by this installer"
fi

# ------------------------------------------------------------------ build
if [ "$DO_BUILD" -eq 1 ]; then
  command -v go >/dev/null 2>&1 || die "go toolchain not found (or pass --no-build)"
  command -v npm >/dev/null 2>&1 || die "node/npm not found (or pass --no-build)"
  log "building frontend"
  ( cd "${ROOT}/web" && npm ci --silent && npm run build )
  mkdir -p "${BIN_SRC}"
  log "building binaries"
  ( cd "${ROOT}" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${BIN_SRC}/aegis" ./cmd/aegis \
      && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${BIN_SRC}/aegis-agent" ./cmd/aegis-agent )
fi

[ -x "${BIN_SRC}/aegis" ] || die "missing ${BIN_SRC}/aegis (build it or pass --no-build)"
[ -x "${BIN_SRC}/aegis-agent" ] || die "missing ${BIN_SRC}/aegis-agent"
[ -f "${ROOT}/web/dist/index.html" ] || die "missing web/dist (run npm run build first)"

# -------------------------------------------------------------- packages
if ! command -v wg >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
  log "installing wireguard-tools and iptables"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard wireguard-tools iptables
fi
command -v wg >/dev/null 2>&1 || die "wg not available after installation"

# ---------------------------------------------------------------- users
if ! getent group aegis >/dev/null; then
  log "creating group aegis"
  groupadd --system aegis
fi
if ! getent passwd aegis >/dev/null; then
  log "creating system user aegis"
  useradd --system --gid aegis --home-dir /var/lib/aegis --shell /usr/sbin/nologin aegis
fi

# ------------------------------------------------------------- filesystem
log "installing files"
install -d -m 0755 -o root -g root /usr/local/bin /usr/share/aegis/web
install -m 0755 -o root -g root "${BIN_SRC}/aegis" /usr/local/bin/aegis
install -m 0755 -o root -g root "${BIN_SRC}/aegis-agent" /usr/local/bin/aegis-agent
cp -r "${ROOT}/web/dist/." /usr/share/aegis/web/

install -d -m 0750 -o root -g aegis /etc/aegis
install -d -m 0750 -o aegis -g aegis /var/lib/aegis

if [ ! -f /etc/aegis/aegis.env ]; then
  log "creating /etc/aegis/aegis.env"
  install -m 0600 -o root -g aegis "${ROOT}/.env.example" /etc/aegis/aegis.env
  SESSION_SECRET="$(rand_b64 48)"
  AGENT_TOKEN="$(rand_hex 32)"
  sed -i "s|^AEGIS_SESSION_SECRET=.*|AEGIS_SESSION_SECRET=${SESSION_SECRET}|" /etc/aegis/aegis.env
  sed -i "s|^AEGIS_AGENT_TOKEN=.*|AEGIS_AGENT_TOKEN=${AGENT_TOKEN}|" /etc/aegis/aegis.env
  # Development convenience: no TLS in front yet, cookies must not be Secure.
  sed -i 's|^AEGIS_COOKIE_SECURE=.*|AEGIS_COOKIE_SECURE=false|' /etc/aegis/aegis.env
  log "generated AEGIS_SESSION_SECRET and AEGIS_AGENT_TOKEN"
else
  log "keeping existing /etc/aegis/aegis.env"
fi
chmod 0600 /etc/aegis/aegis.env

install -m 0644 -o root -g root "${ROOT}/deploy/90-aegis.conf" /etc/sysctl.d/90-aegis.conf
sysctl --system >/dev/null || log "warning: could not reload sysctl (run: sysctl --system)"

# ----------------------------------------------------------------- systemd
if [ -d /run/systemd/system ]; then
  log "installing systemd units"
  install -m 0644 -o root -g root "${ROOT}/deploy/aegis.service" /etc/systemd/system/aegis.service
  install -m 0644 -o root -g root "${ROOT}/deploy/aegis-agent.service" /etc/systemd/system/aegis-agent.service
  systemctl daemon-reload
  systemctl enable --now aegis-agent.service
  systemctl enable --now aegis.service
  systemctl --no-pager --full status aegis-agent.service | head -n 5 || true
else
  log "systemd not detected: start the agent and the panel manually"
fi

cat <<EOF

Aegis is installed.

  panel    : systemctl status aegis
  agent    : systemctl status aegis-agent
  config   : /etc/aegis/aegis.env   (0600, root:aegis)

Next steps
  1. Set AEGIS_PUBLIC_URL and AEGIS_WG_ENDPOINT in /etc/aegis/aegis.env.
  2. Set AEGIS_BOOTSTRAP_USER / AEGIS_BOOTSTRAP_PASSWORD for the first run,
     restart the panel, log in, then clear AEGIS_BOOTSTRAP_PASSWORD.
  3. Put a TLS reverse proxy in front of 127.0.0.1:8443 and set
     AEGIS_COOKIE_SECURE=true and AEGIS_TRUST_PROXY=true.
  4. Read docs/deployment.md and docs/security.md.
EOF
