# Operations

## Deploy

Requirements: a Linux host with Docker Compose and the admin network (VPN, Tailscale or your LAN) able to reach it.

- **Production:** a public DNS name for the console, and ports 80 and 443 reachable from the internet (agents and Let's Encrypt).
- **Test VM:** the VM's IP address (or a local name such as `buoy.internal`) is enough. Caddy then issues the certificate from its internal CA, and the agent install commands pin that CA (see [docs/install-agent.md](install-agent.md#console-with-a-private-ca)).

### With the setup script

On an Ubuntu server (`sudo apt install docker.io docker-compose-v2 git openssl curl`, and add yourself to the `docker` group):

```sh
git clone https://github.com/Soup9x/Lake-Effect-Buoy.git
Lake-Effect-Buoy/deploy/setup.sh
```

It asks for the console hostname or IP and the admin networks (defaults: this host's IP and local network), writes `deploy/.env` with fresh random secrets (mode 0600), builds and starts the stack, publishes Caddy's internal CA when it is used, and creates the first admin (you choose the password). For unattended use: `setup.sh --hostname 192.168.1.50 --admin-cidr 192.168.1.0/24 --yes`, then create the admin as below. Run it again at any time to upgrade; it keeps `.env`, the data and the admins.

Then publish an agent release (below), sign in, create a tenant and an enrollment token, and paste the install command the console shows on each endpoint.

### By hand

```sh
cd deploy
cp ../.env.example .env        # then edit every value; .env is gitignored
openssl rand -base64 32        # -> TOKEN_HASH_KEY
openssl rand -hex 24           # -> POSTGRES_PASSWORD, and again for CAV_APP_DB_PASSWORD
mkdir -p downloads             # signed agent release files go here (see "Publish an agent release")
docker compose up -d --build
```

If Caddy uses its internal CA (an IP address or local name in `CAV_HOSTNAME`), publish it for the install commands:

```sh
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./root.crt
openssl x509 -in root.crt -out downloads/console-ca.pem && chmod 644 downloads/console-ca.pem
```

Services:

| Service | Purpose | Network exposure |
|---|---|---|
| `caddy` | TLS (Let's Encrypt), path and IP filtering | publishes 80/443 |
| `server` | console server, runs as `cav_app` DB role | internal only |
| `migrate` | one-shot, applies migrations as `cav_owner`, then exits | internal only |
| `postgres` | database, named volume `pgdata` | internal only |

The server never holds the owner DB password. `cav_app` can read and write normal tables but can only INSERT and SELECT on `audit_log`, and a trigger blocks UPDATE, DELETE and TRUNCATE on `audit_log` for every role.

### Create the first admin

There are no default credentials. Create the first user from the host:

```sh
docker compose run --rm -it server admin create-user --email you@example.com --name "Your Name"
```

The password is read from the terminal (or one line of stdin), never from arguments. If an admin is locked out or forgets their password:

```sh
docker compose run --rm -it server admin reset-password --email you@example.com
```

Both commands are written to the audit log with actor `cli`.

## Network exposure (Caddy)

Only these paths are reachable from any source: `/agent/v1/*`, `/downloads/*`, `/healthz`. Everything else (the web UI, `/readyz`) only answers clients whose IP is in `ADMIN_ALLOWED_CIDRS` (space-separated), and returns 404 to everyone else. The server enforces the same list again, using the client IP Caddy forwards.

- Tailscale: `100.64.0.0/10` (or narrower). A site-to-site VPN: its client subnet.
- Caddy matches on the direct peer address. If you put another proxy or load balancer in front of Caddy, configure Caddy's `trusted_proxies` and use `client_ip` instead of `remote_ip`, or the allowlist will see the proxy's address.
- After changing `ADMIN_ALLOWED_CIDRS`: `docker compose up -d caddy server`.

## Backups

Back up two things, separately:

1. **The database.** `docker compose exec postgres pg_dump -U cav_owner -Fc cav > cav-$(date +%F).dump`. Restore with `pg_restore` into an empty database before starting the server.
2. **`TOKEN_HASH_KEY`** (and `TOKEN_HASH_KEY_PREVIOUS` during a rotation). Store it in your password manager or secrets vault, not next to the database dumps. A database backup is not usable to restore agent connectivity without the key that was active when it was taken.

`deploy/.env` holds all secrets; keep a copy in your vault so the host can be rebuilt.

## TOKEN_HASH_KEY

`TOKEN_HASH_KEY` is the HMAC key the server uses to hash every bearer secret before storing it: enrollment tokens, agent credentials and web session tokens. The database only ever holds these HMACs.

### What happens if it is lost

The secrets themselves still exist (on endpoints, in browsers) but the server can no longer verify them:

- **Every agent stops being accepted.** Agents receive a generic `401 unauthorized` (not `agent_revoked`), so they keep running, log errors, and retry every 30 to 60 minutes. They will never recover on their own. Each endpoint must be re-enrolled: create a new enrollment token and re-run the installer with `--reinstall` (Linux) or `-Reinstall` (Windows). Re-enrollment replaces the old agent record for that machine.
- **All unused enrollment tokens stop working.** Revoke them in the UI and issue new ones.
- **All web sessions end.** Users sign in again. Passwords are unaffected (they are argon2id hashes and do not depend on this key).
- The audit log, tenants, users and agent history are unaffected.

To recover: set a new `TOKEN_HASH_KEY`, restart (`docker compose up -d server`), then re-enroll endpoints as above.

### Rotating it

Rotate on a schedule you choose, and immediately if the key may have leaked. The server accepts hashes under the previous key during the rotation and transparently re-hashes each secret under the new key the next time it is used.

1. Generate a new key: `openssl rand -base64 32`. Store it in your vault.
2. In `deploy/.env`: set `TOKEN_HASH_KEY_PREVIOUS` to the current key and `TOKEN_HASH_KEY` to the new key.
3. `docker compose up -d server`. Note the time.
4. Wait until every agent you care about has heartbeated since step 3. Online agents do this within a minute. Check from the host:
   ```sh
   docker compose exec postgres psql -U cav_owner cav -c \
     "SELECT t.name, a.hostname, a.last_heartbeat_at FROM agents a JOIN tenants t ON t.id = a.tenant_id
      WHERE a.revoked_at IS NULL AND (a.last_heartbeat_at IS NULL OR a.last_heartbeat_at < '<time from step 3>')
      ORDER BY 1, 2;"
   ```
   Agents still listed have not been re-hashed. Offline machines (laptops on holiday) stay on the old hash until they next connect.
5. When the list is empty, or you accept re-enrolling whatever is left, remove `TOKEN_HASH_KEY_PREVIOUS` from `.env` and run `docker compose up -d server` again. Unused enrollment tokens created before step 3 stop working at this point; issue new ones. Sessions re-hash on use, so active users are not signed out.
6. Destroy the old key in your vault once you no longer need to restore pre-rotation backups. (A backup taken before step 3 needs the old key.)

If the key leaked, also consider rotating every agent credential from the UI (each agent's page, "Rotate credential"), since the leak combined with a database copy is the threat this key protects against.

## Publish an agent release

Agent binaries and install scripts are signed offline with the release minisign key, which never touches this server (see `docs/release-signing.md`). On the release workstation:

```sh
make dist      # builds dist/downloads/*
make sign      # signs every file with the offline key -> *.minisig
```

Copy the contents of `dist/downloads/` (files and their `.minisig`) into the server's downloads directory (`CAV_DOWNLOADS_PATH`, default `deploy/downloads`). The server serves them read-only at `/downloads/<name>`. No restart is needed. The install scripts refuse anything whose signature doesn't verify against the public key embedded in them.

## Health and logs

- `GET /healthz`: liveness, public.
- `GET /readyz`: database reachable, admin networks only.
- Server logs are JSON on stdout: `docker compose logs -f server`.
- An agent counts as offline after `AGENT_OFFLINE_AFTER_SECONDS` (default 180) without a heartbeat. The server records `went_offline` and `went_online` events on each agent's page.

## Agent actions

Admins can queue a fixed set of ClamAV actions (check clamd, reload signatures, clamd stats, scan a folder) on one endpoint or a batch, from the endpoint page or a tenant's **Run action…** button; **Actions** in the top bar lists recent runs. See docs/install-agent.md, "Actions from the console", for what each does and how endpoints allow folder scans. Undelivered actions expire after 24 hours, and the server deletes runs older than 90 days.

## Upgrades

```sh
git pull
cd deploy && docker compose up -d --build
```

The `migrate` service applies new migrations before the server starts. Migrations are forward-only.
