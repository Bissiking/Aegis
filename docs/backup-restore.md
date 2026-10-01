# Backup and restore

## What to back up

| Path                       | Contents                                      | Sensitivity |
| -------------------------- | --------------------------------------------- | ----------- |
| `/var/lib/aegis/aegis.db`  | users, devices, peers, usage, audit, sessions | **secret** (Argon2id hashes, session hashes) |
| `/etc/aegis/aegis.env`     | session secret, agent token, Kyros secret     | **secret**  |
| `/etc/wireguard/*.conf`    | persistent peer configuration                 | **secret** (peer public keys only, but still private infrastructure) |

Nothing else is state: the SPA and binaries are rebuildable, and the private
keys of clients are **never stored anywhere**, so a backup can never leak them.

## Creating a backup

```bash
sudo ./scripts/backup.sh                 # -> /var/backups/aegis/aegis-<stamp>.tar.gz
sudo ./scripts/backup.sh /mnt/nas/aegis  # custom destination
AEGIS_KEEP=30 sudo ./scripts/backup.sh   # keep 30 archives instead of 14
```

The database is snapshotted **online** with `sqlite3 .backup`, so the panel
does not need to be stopped. The snapshot is then checked with
`PRAGMA integrity_check` before the archive is written. The archive is
created with mode `0600`.

Requires the `sqlite3` CLI (`apt-get install sqlite3`).

## Restoring

```bash
sudo ./scripts/restore.sh /var/backups/aegis/aegis-20260101-120000.tar.gz
```

The script:

1. extracts to a temporary directory and verifies the integrity check;
2. stops `aegis` and `aegis-agent`;
3. restores the database (owner `aegis:aegis`, mode `0600`) and removes any
   stale `-wal`/`-shm` files from the previous run;
4. restores `/etc/aegis/aegis.env` (mode `0600`, group `aegis`);
5. restores `/etc/wireguard`;
6. restarts both services.

Migrations run on startup, so restoring an older database into a newer binary
is supported (forward-only migrations).

## What is *not* in a backup

* **Client private keys.** They are generated once at device creation/rotation
  and never persisted. After a restore, every device keeps working because the
  peer configuration is restored from the database and `/etc/wireguard`; the
  end user still holds their own `.conf` file.
* **The browser's one-time profile view.** That lives in the SPA's memory.

## Disaster recovery

1. Install Aegis on the new host (`deploy/install.sh`).
2. Stop the services.
3. Restore the archive.
4. Set `AEGIS_PUBLIC_URL`, `AEGIS_WG_ENDPOINT` and `AEGIS_WG_EGRESS_IFACE` if
   the host changed.
5. Start `aegis-agent` then `aegis`, check `/api/v1/health`.
6. Re-sync the tunnels: any device operation (or the first collector pass)
   calls `sync_config`, rewriting `/etc/wireguard/*.conf` from the database.

## Scheduling

```cron
17 3 * * * root /opt/aegis/scripts/backup.sh >/dev/null 2>&1
```

Copy the archives off the host as well: a backup next to the database does not
protect against disk loss or a compromised root account.

## Verifying a backup

```bash
tar -tzf /var/backups/aegis/aegis-*.tar.gz        # should list aegis.db [+ aegis.env]
mkdir /tmp/check && tar -xzf <archive> -C /tmp/check
sqlite3 /tmp/check/aegis.db 'PRAGMA integrity_check; SELECT COUNT(*) FROM users;'
```
