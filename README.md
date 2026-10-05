# Lake-Effect-Buoy

A multi-tenant management console for ClamAV, built for an MSP managing ClamAV across client endpoints.

- **Agent** (Go): runs as a systemd unit on Linux and a Windows service. Talks to the local clamd (Unix socket on Linux, loopback TCP on Windows), and connects outbound-only to the console over HTTPS. It never listens on a network port.
- **Server** (Go): agent API, server-rendered web UI (htmx), Postgres. Deployed with Docker Compose behind Caddy.

## Phase 1 features

- Tenants, with optional `source` + `external_id` for a future PSA/documentation sync.
- Per-tenant enrollment tokens (expiry, max uses, revoke). Agents enroll with a token and receive their own credential, which can be rotated or revoked.
- Agent heartbeat every 60 s: hostname, OS, agent version, ClamAV engine version, signature version and date, clamd status.
- Web UI: sign in, tenants, endpoints per tenant with online/offline state and last heartbeat (auto-refreshing), enrollment tokens with copy-paste install commands, endpoint detail and events, audit log, users.
- Signed agent releases and install scripts for Linux and Windows.

## Security model

The permanent project rules are in [CLAUDE.md](CLAUDE.md). In short: the agent only runs a fixed allowlist of ClamAV actions (check, reload, stats, and scans of folders allowed on the endpoint itself); every admin action is audited in an append-only log enforced by the database; the UI requires authentication and is designed for MFA; secrets only come from environment variables; agent releases are signed with an offline key; agents only stop on an explicit `agent_revoked` response.

## Layout

```
cmd/server, internal/server   console server
cmd/agent, internal/agent     endpoint agent
internal/protocol             agent <-> server wire types and action allowlist
internal/release              embedded release public key + signature verification
cmd/release-sign              offline signing tool
db/migrations                 SQL migrations (goose)
deploy/                       Docker Compose, Caddyfile, Dockerfile
packaging/                    agent install/uninstall scripts and systemd unit
scripts/                      release build and signing scripts
docs/                         design, operations, agent install, release signing
```

## Quick start

On an Ubuntu server with Docker (`sudo apt install docker.io docker-compose-v2 git openssl curl`):

```sh
git clone https://github.com/Soup9x/Lake-Effect-Buoy.git
Lake-Effect-Buoy/deploy/setup.sh     # asks for the hostname/IP and admin network, starts everything, creates the first admin
```

Publish a signed agent release ([docs/operations.md](docs/operations.md#publish-an-agent-release)), then create an enrollment token in the console and paste the one-line install command it shows on each Linux or Windows endpoint ([docs/install-agent.md](docs/install-agent.md)). A test VM reached by IP address works too: the commands pin the console's private CA.

## Docs

- [Phase 1 design](docs/design/phase1.md)
- [Operations](docs/operations.md): deploy, first admin, backups, `TOKEN_HASH_KEY` rotation, publishing agent releases
- [Installing the agent](docs/install-agent.md)
- [Release signing](docs/release-signing.md)

## Development

```sh
make test                      # unit tests
TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres make test-integration
make lint
make build                     # bin/clamav-console, bin/clamav-agent
```

Run the server locally against a dev database:

```sh
export MIGRATE_DATABASE_URL=postgres://owner@127.0.0.1/cav DATABASE_URL=postgres://owner@127.0.0.1/cav
export PUBLIC_URL=http://127.0.0.1:8080 INSECURE_COOKIES_FOR_DEV=true LISTEN_ADDR=127.0.0.1:8080
export TOKEN_HASH_KEY=$(openssl rand -base64 32) ADMIN_ALLOWED_CIDRS=127.0.0.1/32
go run ./cmd/server admin create-user --email you@example.com
go run ./cmd/server serve
```
