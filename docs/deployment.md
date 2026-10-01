# Deployment

Target: Debian 12 / Ubuntu 22.04+, systemd, WireGuard kernel module, one
public IPv4 address, TLS terminated by a reverse proxy.

## 1. Install

```bash
git clone <repo> && cd aegis
chmod +x deploy/install.sh scripts/*.sh
sudo ./deploy/install.sh
```

The installer:

1. builds `web/dist` and both binaries (or use `--no-build` with prebuilt
   binaries in `./build`);
2. installs `wireguard-tools` + `iptables` if missing;
3. creates the system group/user `aegis`;
4. writes `/usr/local/bin/aegis{,-agent}`, `/usr/share/aegis/web`;
5. creates `/etc/aegis/aegis.env` (0600) with a freshly generated
   `AEGIS_SESSION_SECRET` and `AEGIS_AGENT_TOKEN`;
6. installs `/etc/sysctl.d/90-aegis.conf` (IPv4 forwarding);
7. installs and enables `aegis-agent.service` then `aegis.service`.

## 2. Configure

Edit `/etc/aegis/aegis.env` (see `.env.example` for every variable):

```ini
AEGIS_ENV=production
AEGIS_PUBLIC_URL=https://vpn.example.com
AEGIS_LISTEN=127.0.0.1:8443
AEGIS_COOKIE_SECURE=true
AEGIS_TRUST_PROXY=true          # only if the proxy sets X-Forwarded-For

AEGIS_WG_ENDPOINT=vpn.example.com:51820
AEGIS_WG_EGRESS_IFACE=ens3      # or leave empty to auto-detect
AEGIS_WG_DNS=1.1.1.1,1.0.0.1

AEGIS_BOOTSTRAP_USER=admin@example.org
AEGIS_BOOTSTRAP_PASSWORD=<one-time password>
```

```bash
sudo systemctl restart aegis
```

Log in once, create your accounts, then **delete
`AEGIS_BOOTSTRAP_PASSWORD`** from the environment file: the bootstrap user is
only created while the database has no users.

## 3. Reverse proxy

The panel must not be exposed directly. Example with nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name vpn.example.com;

    ssl_certificate     /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8443;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
        client_max_body_size 1m;
    }
}

server {
    listen 80;
    server_name vpn.example.com;
    return 301 https://$host$request_uri;
}
```

`proxy_set_header X-Forwarded-For` is what makes `AEGIS_TRUST_PROXY=true`
correct; without it the client address seen by the rate limiter is the proxy.

Redirect the WireGuard UDP port through your firewall as well:

```bash
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

## 4. Services

| Unit              | User   | Notes                                             |
| ----------------- | ------ | ------------------------------------------------- |
| `aegis-agent`     | root   | only `CAP_NET_ADMIN`, `CAP_NET_RAW`; socket `0770 root:aegis` |
| `aegis`           | aegis  | no capabilities; reads `/run/aegis/agent.sock`    |

```bash
systemctl status aegis aegis-agent
journalctl -u aegis -u aegis-agent -f
```

Health check:

```bash
curl -s http://127.0.0.1:8443/api/v1/health
```

## 5. Upgrades

```bash
sudo ./scripts/update.sh
```

It takes a backup first, rebuilds, replaces the binaries and the SPA, then
restarts. Migrations run automatically at startup (forward-only).

Rollback: restore the previous archive with `scripts/restore.sh` (see
`docs/backup-restore.md`) and reinstall the previous binaries from your build
artifacts or previous release tag.

## 6. Manual installation (no systemd)

```bash
# panel
AEGIS_CONFIG=/etc/aegis/aegis.env /usr/local/bin/aegis

# agent (root)
AEGIS_AGENT_LISTEN=unix:///run/aegis/agent.sock AEGIS_AGENT_TOKEN=... \
  /usr/local/bin/aegis-agent
```

For development the agent can listen on a loopback TCP port; the token is then
mandatory:

```bash
sudo AEGIS_AGENT_LISTEN=tcp://127.0.0.1:51821 AEGIS_AGENT_TOKEN=$(openssl rand -hex 32) \
  ./build/aegis-agent
AEGIS_AGENT_SOCKET=tcp://127.0.0.1:51821 AEGIS_AGENT_TOKEN=... ./build/aegis
```

## 7. Uninstall

```bash
sudo systemctl disable --now aegis aegis-agent
sudo rm -f /etc/systemd/system/aegis{,-agent}.service /etc/sysctl.d/90-aegis.conf
sudo rm -rf /usr/local/bin/aegis /usr/local/bin/aegis-agent /usr/share/aegis
# keep your data until you are sure:
sudo tar -C / -czf /root/aegis-data.tgz var/lib/aegis etc/aegis etc/wireguard
sudo rm -rf /var/lib/aegis /etc/aegis /etc/wireguard/*.conf
sudo userdel aegis; sudo groupdel aegis
```
